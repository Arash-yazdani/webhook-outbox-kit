import sqlite3

import pytest

from webhook_outbox import Outbox, PermanentError, Status, Worker


@pytest.fixture()
def outbox() -> Outbox:
    return Outbox(sqlite3.connect(":memory:"), max_attempts=3, base_backoff_seconds=2.0)


def test_successful_send_marks_message_sent(outbox: Outbox):
    seen = []
    worker = Worker(outbox, {"sms.alert": seen.append})
    outbox.enqueue("sms.alert", {"body": "hi"}, dedupe_key="k1", now=100.0)

    result = worker.drain_once(now=100.0)

    assert (result.claimed, result.sent, result.quarantined) == (1, 1, 0)
    assert result.ok
    assert len(seen) == 1
    assert outbox.get("k1").status is Status.SENT


def test_transient_failure_retries_then_succeeds(outbox: Outbox):
    """The whole reason the outbox exists: a blip must not lose the message."""
    calls = {"n": 0}

    def flaky(_message):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("carrier timeout")

    worker = Worker(outbox, {"sms.alert": flaky})
    outbox.enqueue("sms.alert", {}, dedupe_key="k2", now=100.0)

    first = worker.drain_once(now=100.0)
    assert (first.sent, first.retried) == (0, 1)
    assert outbox.get("k2").status is Status.PENDING

    second = worker.drain_once(now=103.0)  # after the 2s backoff
    assert second.sent == 1
    assert outbox.get("k2").status is Status.SENT
    assert calls["n"] == 2


def test_permanent_error_quarantines_immediately(outbox: Outbox):
    """No point burning five attempts on a payload that will never be accepted."""

    def rejects(_message):
        raise PermanentError("recipient unsubscribed")

    worker = Worker(outbox, {"sms.alert": rejects})
    outbox.enqueue("sms.alert", {}, dedupe_key="k3", now=100.0)

    result = worker.drain_once(now=100.0)

    assert result.quarantined == 1
    assert not result.ok
    assert outbox.get("k3").status is Status.DEAD
    assert "permanent" in outbox.get("k3").last_error


def test_unroutable_topic_quarantines_instead_of_spinning(outbox: Outbox):
    """A missing sender is a deploy bug. Surface it, do not retry it forever."""
    worker = Worker(outbox, {"sms.alert": lambda m: None})
    outbox.enqueue("email.digest", {}, dedupe_key="k4", now=100.0)

    result = worker.drain_once(now=100.0)

    assert result.quarantined == 1
    assert outbox.get("k4").status is Status.DEAD
    assert "no sender registered" in outbox.get("k4").last_error


def test_persistent_transient_failure_eventually_quarantines(outbox: Outbox):
    def always_fails(_message):
        raise ConnectionError("carrier down")

    worker = Worker(outbox, {"sms.alert": always_fails})
    outbox.enqueue("sms.alert", {}, dedupe_key="k5", now=100.0)

    worker.drain_once(now=100.0)   # attempt 1
    worker.drain_once(now=103.0)   # attempt 2
    result = worker.drain_once(now=110.0)  # attempt 3 -> dead

    assert result.quarantined == 1
    assert outbox.get("k5").status is Status.DEAD
    assert outbox.claim(now=1_000_000.0) == []


def test_one_bad_message_does_not_block_the_batch(outbox: Outbox):
    """Head-of-line blocking is how a single poison message becomes an outage."""

    def selective(message):
        if message.payload.get("poison"):
            raise PermanentError("nope")

    worker = Worker(outbox, {"sms.alert": selective})
    outbox.enqueue("sms.alert", {"poison": True}, dedupe_key="bad", now=100.0)
    outbox.enqueue("sms.alert", {"poison": False}, dedupe_key="good1", now=101.0)
    outbox.enqueue("sms.alert", {"poison": False}, dedupe_key="good2", now=102.0)

    result = worker.drain_once(now=110.0)

    assert result.sent == 2
    assert result.quarantined == 1
    assert outbox.get("good1").status is Status.SENT
    assert outbox.get("good2").status is Status.SENT


def test_dedupe_key_is_available_to_the_sender(outbox: Outbox):
    """Passing it to the vendor as an idempotency key is what collapses
    at-least-once delivery into one visible side effect."""
    captured = []
    worker = Worker(outbox, {"sms.alert": lambda m: captured.append(m.dedupe_key)})
    outbox.enqueue("sms.alert", {}, dedupe_key="dose-4821-missed", now=100.0)

    worker.drain_once(now=100.0)

    assert captured == ["dose-4821-missed"]


def test_empty_queue_is_a_noop(outbox: Outbox):
    worker = Worker(outbox, {"sms.alert": lambda m: None})
    result = worker.drain_once(now=100.0)
    assert (result.claimed, result.sent, result.quarantined) == (0, 0, 0)
    assert result.ok


def test_batch_size_is_respected(outbox: Outbox):
    sent = []
    worker = Worker(outbox, {"sms.alert": sent.append}, batch_size=2)
    for i in range(5):
        outbox.enqueue("sms.alert", {}, dedupe_key=f"b{i}", now=100.0 + i)

    result = worker.drain_once(now=200.0)

    assert result.claimed == 2
    assert len(sent) == 2
