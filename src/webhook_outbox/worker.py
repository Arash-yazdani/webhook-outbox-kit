"""The drain worker: takes claimed messages and actually sends them.

Deliberately boring. It claims a batch, calls a sender, and records the result.
All the interesting behaviour (backoff schedule, quarantine threshold) lives in
the Outbox so that the worker stays trivial enough to reason about at 3am.

Senders are plain callables so the worker has no opinion about your transport:

    def send_sms(message: Message) -> None:
        resp = twilio.messages.create(
            to=message.payload["to"],
            body=message.payload["body"],
            # Pass the dedupe key through so the vendor collapses retries too.
            # This is what turns at-least-once delivery into one visible SMS.
            idempotency_key=message.dedupe_key,
        )
        if resp.status == "failed":
            raise TransientError(resp.error_message)

Raise to signal failure. Return None to signal success. That is the contract.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping

from .outbox import Message, Outbox, Status

__all__ = ["DrainResult", "Worker", "PermanentError", "TransientError"]

log = logging.getLogger("webhook_outbox.worker")

Sender = Callable[[Message], None]


class TransientError(Exception):
    """Retry me. Network blip, 429, upstream 503."""


class PermanentError(Exception):
    """Do not retry me. Malformed payload, unsubscribed recipient, 400.

    Quarantined immediately rather than burning five attempts on something
    that will never succeed. Getting this classification wrong in the other
    direction is worse: a permanent error retried forever will silently eat
    your worker throughput, which is how a dead letter queue turns into an
    outage nobody notices.
    """


@dataclass
class DrainResult:
    claimed: int = 0
    sent: int = 0
    retried: int = 0
    quarantined: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.quarantined == 0


class Worker:
    def __init__(
        self,
        outbox: Outbox,
        senders: Mapping[str, Sender],
        *,
        batch_size: int = 10,
    ) -> None:
        self._outbox = outbox
        self._senders = dict(senders)
        self._batch_size = batch_size

    def drain_once(self, *, now: float | None = None) -> DrainResult:
        """Claim and process one batch. Call this on a loop or a cron."""
        ts = time.time() if now is None else now
        result = DrainResult()

        for message in self._outbox.claim(self._batch_size, now=ts):
            result.claimed += 1
            sender = self._senders.get(message.topic)

            if sender is None:
                # An unroutable topic is a deployment bug, not a network blip.
                # Quarantine immediately so it surfaces instead of spinning.
                self._quarantine(message, f"no sender registered for topic {message.topic!r}", ts, result)
                continue

            try:
                sender(message)
            except PermanentError as exc:
                self._quarantine(message, f"permanent: {exc}", ts, result)
            except Exception as exc:  # noqa: BLE001 - transport errors are open-ended
                outcome = self._outbox.mark_failed(message, f"transient: {exc}", now=ts)
                result.errors.append(str(exc))
                if outcome is Status.DEAD:
                    result.quarantined += 1
                    log.error(
                        "outbox message quarantined after max attempts",
                        extra={"dedupe_key": message.dedupe_key, "topic": message.topic},
                    )
                else:
                    result.retried += 1
            else:
                self._outbox.mark_sent(message.id, now=ts)
                result.sent += 1

        return result

    def run_forever(self, interval_seconds: float = 1.0) -> None:  # pragma: no cover
        while True:
            result = self.drain_once()
            if result.claimed == 0:
                time.sleep(interval_seconds)

    def _quarantine(
        self, message: Message, reason: str, ts: float, result: DrainResult
    ) -> None:
        # Force the attempt counter past the threshold so mark_failed kills it now.
        forced = Message(
            id=message.id,
            dedupe_key=message.dedupe_key,
            topic=message.topic,
            payload=message.payload,
            status=message.status,
            attempts=self._outbox._max_attempts - 1,  # noqa: SLF001
            next_attempt_at=message.next_attempt_at,
            created_at=message.created_at,
        )
        self._outbox.mark_failed(forced, reason, now=ts)
        result.quarantined += 1
        result.errors.append(reason)
        log.error(
            "outbox message quarantined immediately",
            extra={"dedupe_key": message.dedupe_key, "reason": reason},
        )
