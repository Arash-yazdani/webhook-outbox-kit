import base64
import hashlib
import hmac
import time

import pytest

from webhook_outbox import (
    InvalidSignature,
    MissingSignature,
    SharedSecretHeader,
    StaleSignature,
    StripeHmacSha256,
    TwilioHmacSha1,
)


# ------------------------------------------------------------ shared secret


def test_shared_secret_accepts_match():
    v = SharedSecretHeader("s3cr3t")
    v.verify(headers={"X-Webhook-Secret": "s3cr3t"}, body=b"")


def test_shared_secret_header_lookup_is_case_insensitive():
    v = SharedSecretHeader("s3cr3t")
    v.verify(headers={"x-WEBHOOK-secret": "s3cr3t"}, body=b"")


def test_shared_secret_rejects_mismatch():
    v = SharedSecretHeader("s3cr3t")
    with pytest.raises(InvalidSignature):
        v.verify(headers={"X-Webhook-Secret": "wrong"}, body=b"")


def test_shared_secret_rejects_missing_header():
    v = SharedSecretHeader("s3cr3t")
    with pytest.raises(MissingSignature):
        v.verify(headers={}, body=b"")


def test_shared_secret_rejects_empty_secret_at_construction():
    with pytest.raises(ValueError):
        SharedSecretHeader("")


# -------------------------------------------------------------------- twilio


def _twilio_sign(token: str, url: str, params: dict[str, str]) -> str:
    payload = url
    for key in sorted(params):
        payload += key + params[key]
    return base64.b64encode(
        hmac.new(token.encode(), payload.encode(), hashlib.sha1).digest()
    ).decode()


def test_twilio_accepts_valid_signature():
    token, url = "auth-token", "https://example.com/hooks/voice"
    params = {"CallSid": "CA123", "From": "+15551234567", "CallStatus": "completed"}
    v = TwilioHmacSha1(token)
    v.verify(
        headers={"X-Twilio-Signature": _twilio_sign(token, url, params)},
        body=b"",
        url=url,
        params=params,
    )


def test_twilio_params_are_sorted_not_insertion_ordered():
    """Two dicts with the same pairs in different order must sign identically."""
    v = TwilioHmacSha1("auth-token")
    url = "https://example.com/hooks/voice"
    a = v.expected(url, {"b": "2", "a": "1"})
    b = v.expected(url, {"a": "1", "b": "2"})
    assert a == b


def test_twilio_rejects_url_tampering():
    """The URL is inside the signed payload; a proxy rewriting it breaks auth."""
    token = "auth-token"
    params = {"CallSid": "CA123"}
    signed_url = "https://example.com/hooks/voice"
    v = TwilioHmacSha1(token)
    with pytest.raises(InvalidSignature):
        v.verify(
            headers={"X-Twilio-Signature": _twilio_sign(token, signed_url, params)},
            body=b"",
            url="http://example.com/hooks/voice",  # scheme changed by a proxy
            params=params,
        )


def test_twilio_rejects_param_tampering():
    token, url = "auth-token", "https://example.com/hooks/voice"
    v = TwilioHmacSha1(token)
    sig = _twilio_sign(token, url, {"From": "+15551234567"})
    with pytest.raises(InvalidSignature):
        v.verify(
            headers={"X-Twilio-Signature": sig},
            body=b"",
            url=url,
            params={"From": "+15559999999"},
        )


def test_twilio_requires_url():
    v = TwilioHmacSha1("auth-token")
    with pytest.raises(ValueError):
        v.verify(headers={"X-Twilio-Signature": "x"}, body=b"", params={})


# -------------------------------------------------------------------- stripe


def _stripe_header(secret: str, body: bytes, ts: int, *, extra_v1: str | None = None) -> str:
    sig = hmac.new(
        secret.encode(), f"{ts}".encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    header = f"t={ts},v1={sig}"
    if extra_v1:
        header += f",v1={extra_v1}"
    return header


def test_stripe_accepts_valid_signature():
    secret, body = "whsec_test", b'{"id":"evt_1","type":"invoice.paid"}'
    now = int(time.time())
    v = StripeHmacSha256(secret)
    v.verify(headers={"Stripe-Signature": _stripe_header(secret, body, now)}, body=body, now=now)


def test_stripe_accepts_during_key_rotation_with_multiple_v1_values():
    """During rotation the header carries several v1 values; any match is fine."""
    secret, body = "whsec_new", b'{"id":"evt_2"}'
    now = int(time.time())
    header = _stripe_header(secret, body, now, extra_v1="deadbeef" * 8)
    StripeHmacSha256(secret).verify(headers={"Stripe-Signature": header}, body=body, now=now)


def test_stripe_rejects_body_tampering():
    secret, body = "whsec_test", b'{"amount":100}'
    now = int(time.time())
    header = _stripe_header(secret, body, now)
    with pytest.raises(InvalidSignature):
        StripeHmacSha256(secret).verify(
            headers={"Stripe-Signature": header}, body=b'{"amount":1000000}', now=now
        )


def test_stripe_rejects_replay_outside_tolerance():
    """The timestamp is signed, so a captured request cannot be replayed later."""
    secret, body = "whsec_test", b'{"id":"evt_3"}'
    signed_at = int(time.time())
    header = _stripe_header(secret, body, signed_at)
    with pytest.raises(StaleSignature):
        StripeHmacSha256(secret, tolerance_seconds=300).verify(
            headers={"Stripe-Signature": header}, body=body, now=signed_at + 3600
        )


def test_stripe_checks_signature_before_freshness():
    """A bad signature on a stale request must report Invalid, not Stale.

    Reporting staleness first would let an attacker with no valid secret probe
    the tolerance window by watching which error comes back.
    """
    body = b'{"id":"evt_4"}'
    signed_at = int(time.time()) - 99999
    header = _stripe_header("wrong-secret", body, signed_at)
    with pytest.raises(InvalidSignature):
        StripeHmacSha256("whsec_real").verify(
            headers={"Stripe-Signature": header}, body=body
        )


def test_stripe_rejects_malformed_header():
    v = StripeHmacSha256("whsec_test")
    with pytest.raises(MissingSignature):
        v.verify(headers={"Stripe-Signature": "garbage"}, body=b"{}")


def test_stripe_rejects_missing_header():
    v = StripeHmacSha256("whsec_test")
    with pytest.raises(MissingSignature):
        v.verify(headers={}, body=b"{}")


# ------------------------------------------------------- cross-scheme sanity


def test_schemes_are_not_interchangeable():
    """A Stripe-signed request must not validate against the Twilio verifier."""
    body = b'{"id":"evt_5"}'
    now = int(time.time())
    stripe_header = _stripe_header("shared", body, now)
    with pytest.raises(MissingSignature):
        TwilioHmacSha1("shared").verify(
            headers={"Stripe-Signature": stripe_header},
            body=body,
            url="https://example.com/hook",
            params={},
        )
