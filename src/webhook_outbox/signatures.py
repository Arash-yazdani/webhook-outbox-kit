"""Webhook signature verification for three common vendor schemes.

Every verifier here fails closed: an unverifiable request raises, it does not
return a warning and let the caller decide. The whole point of signature
verification is that the "maybe" branch does not exist.

The three schemes below are the ones you actually hit in production, and they
are deliberately different from each other:

    SharedSecretHeader   a fixed secret echoed in a header      (Vapi style)
    TwilioHmacSha1       HMAC-SHA1 over URL + sorted form body  (Twilio style)
    StripeHmacSha256     HMAC-SHA256 over "timestamp.body"      (Stripe style)

Only the third one is replay-resistant on its own, because only the third one
signs a timestamp. That asymmetry is the interesting part and it is why a
single generic `verify_hmac()` helper is not good enough.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from abc import ABC, abstractmethod
from typing import Mapping
from urllib.parse import urlencode

__all__ = [
    "SignatureError",
    "MissingSignature",
    "InvalidSignature",
    "StaleSignature",
    "SignatureVerifier",
    "SharedSecretHeader",
    "TwilioHmacSha1",
    "StripeHmacSha256",
]


class SignatureError(Exception):
    """Base class. Callers should reject the request on any subclass."""


class MissingSignature(SignatureError):
    """The signature header was absent or empty."""


class InvalidSignature(SignatureError):
    """The signature was present but did not match."""


class StaleSignature(SignatureError):
    """The signature was valid but the timestamp fell outside tolerance."""


class SignatureVerifier(ABC):
    """Common interface so a router can hold a dict of {route: verifier}."""

    @abstractmethod
    def verify(self, *, headers: Mapping[str, str], body: bytes, **kwargs) -> None:
        """Return None if authentic, raise a SignatureError subclass otherwise."""

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> str:
        # HTTP headers are case-insensitive; most frameworks hand you a dict
        # that is not. Normalise rather than trusting the caller.
        lowered = {k.lower(): v for k, v in headers.items()}
        value = lowered.get(name.lower())
        if not value:
            raise MissingSignature(f"missing header: {name}")
        return value


class SharedSecretHeader(SignatureVerifier):
    """Constant-time comparison of a static secret sent in a header.

    The weakest of the three: the secret is replayable and is transmitted on
    every request, so it is only acceptable over TLS. Included because plenty
    of vendors ship exactly this, and because doing the comparison with `==`
    instead of `compare_digest` leaks the secret one byte at a time to anyone
    willing to measure.
    """

    def __init__(self, secret: str, header_name: str = "x-webhook-secret") -> None:
        if not secret:
            raise ValueError("secret must be non-empty")
        self._secret = secret.encode()
        self._header_name = header_name

    def verify(self, *, headers: Mapping[str, str], body: bytes = b"", **kwargs) -> None:
        provided = self._header(headers, self._header_name).encode()
        if not hmac.compare_digest(provided, self._secret):
            raise InvalidSignature("shared secret mismatch")


class TwilioHmacSha1(SignatureVerifier):
    """HMAC-SHA1 over the full request URL plus sorted form parameters.

    Twilio's scheme, reimplemented rather than imported so the mechanics are
    visible. Two details that bite people:

    1. The signed string is the exact URL Twilio requested, including query
       string and port. If you sit behind a proxy that rewrites http->https,
       you must reconstruct the *original* URL or every signature fails.
    2. Form params are appended as sorted key+value pairs with no separators
       at all. Not urlencoded, not comma-joined. Just concatenated.

    JSON bodies are not covered by this scheme, which is why `params` is
    separate from `body`.
    """

    def __init__(self, auth_token: str) -> None:
        if not auth_token:
            raise ValueError("auth_token must be non-empty")
        self._token = auth_token.encode()

    def expected(self, url: str, params: Mapping[str, str] | None = None) -> str:
        payload = url
        for key in sorted((params or {}).keys()):
            payload += key + str(params[key])
        digest = hmac.new(self._token, payload.encode("utf-8"), hashlib.sha1).digest()
        return base64.b64encode(digest).decode()

    def verify(
        self,
        *,
        headers: Mapping[str, str],
        body: bytes = b"",
        url: str = "",
        params: Mapping[str, str] | None = None,
        **kwargs,
    ) -> None:
        if not url:
            raise ValueError("url is required to verify a Twilio-style signature")
        provided = self._header(headers, "x-twilio-signature")
        if not hmac.compare_digest(provided, self.expected(url, params)):
            raise InvalidSignature("twilio signature mismatch")


class StripeHmacSha256(SignatureVerifier):
    """HMAC-SHA256 over "{timestamp}.{raw_body}" with a replay window.

    Stripe's scheme. Three things make it stronger than the other two:

    1. The timestamp is inside the signed payload, so an attacker cannot
       replay yesterday's captured request past the tolerance window.
    2. The header can carry several `v1=` values at once, which is how key
       rotation works without downtime. Check all of them.
    3. The signature covers the *raw* body bytes. If your framework parsed
       the JSON and you re-serialise it before verifying, key ordering and
       whitespace will differ and every signature will fail. Capture the raw
       body first.
    """

    def __init__(self, signing_secret: str, tolerance_seconds: int = 300) -> None:
        if not signing_secret:
            raise ValueError("signing_secret must be non-empty")
        self._secret = signing_secret.encode()
        self._tolerance = tolerance_seconds

    @staticmethod
    def _parse_header(raw: str) -> tuple[str | None, list[str]]:
        timestamp: str | None = None
        signatures: list[str] = []
        for part in raw.split(","):
            if "=" not in part:
                continue
            key, _, value = part.strip().partition("=")
            if key == "t":
                timestamp = value
            elif key == "v1":
                signatures.append(value)
        return timestamp, signatures

    def expected(self, timestamp: str, body: bytes) -> str:
        signed_payload = timestamp.encode() + b"." + body
        return hmac.new(self._secret, signed_payload, hashlib.sha256).hexdigest()

    def verify(
        self,
        *,
        headers: Mapping[str, str],
        body: bytes,
        now: float | None = None,
        **kwargs,
    ) -> None:
        raw = self._header(headers, "stripe-signature")
        timestamp, signatures = self._parse_header(raw)
        if timestamp is None or not signatures:
            raise MissingSignature("malformed stripe-signature header")

        expected = self.expected(timestamp, body)
        # Compare against every v1 value so key rotation does not cause an outage.
        if not any(hmac.compare_digest(candidate, expected) for candidate in signatures):
            raise InvalidSignature("stripe signature mismatch")

        # Only check freshness *after* the signature is known good. Checking it
        # first would let an attacker probe the tolerance window for free.
        try:
            sent_at = int(timestamp)
        except ValueError as exc:
            raise MissingSignature("non-numeric timestamp") from exc

        current = time.time() if now is None else now
        if abs(current - sent_at) > self._tolerance:
            raise StaleSignature(
                f"timestamp outside {self._tolerance}s tolerance "
                f"(drift {abs(current - sent_at):.0f}s)"
            )


def twilio_form_payload(params: Mapping[str, str]) -> str:
    """Helper for tests and debugging: the urlencoded form Twilio would POST."""
    return urlencode(sorted(params.items()))
