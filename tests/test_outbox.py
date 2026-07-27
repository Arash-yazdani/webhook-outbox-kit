import sqlite3

import pytest

from webhook_outbox import DuplicateMessage, Outbox, Status, transaction


@pytest.fixture()
def outbox() -> Outbox:
    conn = sqlite3.connect(":memory:")
    return Outbox(conn, max_attempts=3, base_backoff_seconds=2.0)


def test_enqueue_then_claim(outbox: Outbox):
    outbox.enqueue("sms.alert", {"to": "+1555", "body": "hi"}, dedupe_key="dose-1", now=100.0)
    claimed = outbox.claim(now=100.0)
    assert len(claimed) == 1
    assert claimed[0].topic == "sms.alert"
    assert claimed[0].payload == {"to": "+1555", "body": "hi"}
    assert claimed[0].status is Status.PENDING


def test_dedupe_key_is_enforced_by_the_database(outbox: Outbox):
    """The uniqueness guarantee has to live in the schema, not in app code.

    Two racing workers both checking "does this exist yet" and then inserting
    will both see 'no'. Only a UNIQUE constraint actually prevents the double.
    """
    outbox.enqueue("sms.alert", {"n": 1}, dedupe_key="dose-1", now=100.0)
    with pytest.raises(DuplicateMessage):
        outbox.enqueue("sms.alert", {"n": 2}, dedupe_key="dose-1", now=100.0)
    assert outbox.counts() == {"pending": 1}


def test_enqueue_requires_a_dedupe_key(outbox: Outbox):
    with pytest.raises(ValueError):
        outbox.enqueue("sms.alert", {}, dedupe_key="", now=100.0)


def test_business_write_and_enqueue_share_one_commit(outbox: Outbox):
    """The entire point: if the business write rolls back, so does the alert."""
    conn = outbox._conn  # noqa: SLF001
    conn.execute("CREATE TABLE doses (id TEXT PRIMARY KEY, state TEXT)")

    with pytest.raises(RuntimeError):
        with transaction(conn):
            conn.execute("INSERT INTO doses VALUES ('d1', 'missed')")
            outbox.enqueue("sms.alert", {"dose": "d1"}, dedupe_key="dose-d1", now=100.0)
            raise RuntimeError("handler blew up after both writes")

    assert conn.execute("SELECT COUNT(*) FROM doses").fetchone()[0] == 0
    assert outbox.get("dose-d1") is None


def test_committed_transaction_persists_both(outbox: Outbox):
    conn = outbox._conn  # noqa: SLF001
    conn.execute("CREATE TABLE doses (id TEXT PRIMARY KEY, state TEXT)")
    with transaction(conn):
        conn.execute("INSERT INTO doses VALUES ('d2', 'missed')")
        outbox.enqueue("sms.alert", {"dose": "d2"}, dedupe_key="dose-d2", now=100.0)

    assert conn.execute("SELECT COUNT(*) FROM doses").fetchone()[0] == 1
    assert outbox.get("dose-d2") is not None


def test_mark_sent_removes_from_claimable_set(outbox: Outbox):
    m = outbox.enqueue("sms.alert", {}, dedupe_key="dose-2", now=100.0)
    outbox.mark_sent(m.id, now=101.0)
    assert outbox.claim(now=200.0) == []
    assert outbox.get("dose-2").status is Status.SENT


def test_failure_schedules_exponential_backoff(outbox: Outbox):
    m = outbox.enqueue("sms.alert", {}, dedupe_key="dose-3", now=100.0)

    outbox.mark_failed(m, "503 from carrier", now=100.0)
    after_first = outbox.get("dose-3")
    assert after_first.attempts == 1
    assert after_first.next_attempt_at == pytest.approx(102.0)  # 2 * 2^0

    outbox.mark_failed(after_first, "503 again", now=102.0)
    after_second = outbox.get("dose-3")
    assert after_second.attempts == 2
    assert after_second.next_attempt_at == pytest.approx(106.0)  # 2 * 2^1


def test_message_is_not_claimable_until_backoff_elapses(outbox: Outbox):
    m = outbox.enqueue("sms.alert", {}, dedupe_key="dose-4", now=100.0)
    outbox.mark_failed(m, "boom", now=100.0)
    assert outbox.claim(now=101.0) == []      # still backing off
    assert len(outbox.claim(now=103.0)) == 1  # window has passed


def test_exhausted_retries_quarantine_rather_than_loop(outbox: Outbox):
    """A message that can never send must stop consuming worker throughput."""
    m = outbox.enqueue("sms.alert", {}, dedupe_key="dose-5", now=100.0)
    outcome = None
    current = m
    for _ in range(3):
        outcome = outbox.mark_failed(current, "permanent upstream failure", now=100.0)
        current = outbox.get("dose-5")

    assert outcome is Status.DEAD
    assert current.status is Status.DEAD
    assert outbox.claim(now=1_000_000.0) == []
    assert [d.dedupe_key for d in outbox.dead_letters()] == ["dose-5"]


def test_requeue_returns_a_dead_letter_to_the_queue(outbox: Outbox):
    m = outbox.enqueue("sms.alert", {}, dedupe_key="dose-6", now=100.0)
    current = m
    for _ in range(3):
        outbox.mark_failed(current, "boom", now=100.0)
        current = outbox.get("dose-6")
    assert current.status is Status.DEAD

    assert outbox.requeue("dose-6", now=200.0) is True
    revived = outbox.get("dose-6")
    assert revived.status is Status.PENDING
    assert revived.attempts == 0
    assert len(outbox.claim(now=200.0)) == 1


def test_requeue_is_a_noop_for_a_healthy_message(outbox: Outbox):
    outbox.enqueue("sms.alert", {}, dedupe_key="dose-7", now=100.0)
    assert outbox.requeue("dose-7", now=200.0) is False


def test_claim_is_fifo_by_creation_time(outbox: Outbox):
    outbox.enqueue("sms.alert", {}, dedupe_key="a", now=100.0)
    outbox.enqueue("sms.alert", {}, dedupe_key="b", now=101.0)
    outbox.enqueue("sms.alert", {}, dedupe_key="c", now=102.0)
    assert [m.dedupe_key for m in outbox.claim(now=200.0)] == ["a", "b", "c"]


def test_claim_respects_limit(outbox: Outbox):
    for i in range(5):
        outbox.enqueue("sms.alert", {}, dedupe_key=f"k{i}", now=100.0 + i)
    assert len(outbox.claim(limit=2, now=200.0)) == 2


def test_backoff_is_capped(outbox: Outbox):
    conn = sqlite3.connect(":memory:")
    ob = Outbox(conn, max_attempts=50, base_backoff_seconds=2.0, max_backoff_seconds=60.0)
    m = ob.enqueue("sms.alert", {}, dedupe_key="capped", now=0.0)
    current = m
    for _ in range(20):
        ob.mark_failed(current, "boom", now=0.0)
        current = ob.get("capped")
    assert current.next_attempt_at <= 60.0
