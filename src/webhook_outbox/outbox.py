"""A transactional outbox with exactly-once delivery semantics.

The problem this solves
----------------------
Your handler needs to do two things when something happens: write a row, and
tell the outside world. If you do them as two separate operations there is a
window where one succeeds and the other does not:

    db.record_missed_dose(...)      # committed
    sms.send("Dad missed his 8am")  # process dies here
                                    # -> nobody is ever told

Retrying the send does not fix it, because the process that would retry is the
one that died. Sending first does not fix it either, you just flip which half
is lost.

The fix is to stop having two systems. Write the intent to send into your own
database, in the same transaction as the business fact:

    with db.transaction():
        db.record_missed_dose(...)
        outbox.enqueue("sms.alert", payload, dedupe_key="dose-4821-missed")

Now there is exactly one commit. Either both landed or neither did. A separate
worker drains the outbox and does the actual sending, retrying until it works.

"Exactly-once" in practice
--------------------------
True exactly-once delivery across a network boundary is not achievable; the
receiver can always ack and then crash. What is achievable, and what this does,
is exactly-once *enqueue* plus at-least-once *delivery* with a stable dedupe
key, which the receiver (or the vendor API's own idempotency key) collapses
back to one visible effect. Anyone who claims more than that is not counting
the failure modes.

Storage
-------
Backed by stdlib sqlite3 so the tests run anywhere with no dependencies. The
schema and the claim query are written to port cleanly to Postgres; see
`_claim_sql()` for the one line that changes.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterator, Sequence

__all__ = ["Status", "Message", "Outbox", "DuplicateMessage"]


class Status(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    DEAD = "dead"  # exhausted retries, quarantined for a human


class DuplicateMessage(Exception):
    """Raised when a dedupe_key is enqueued twice. Usually safe to swallow."""


@dataclass(frozen=True)
class Message:
    id: str
    dedupe_key: str
    topic: str
    payload: dict[str, Any]
    status: Status
    attempts: int
    next_attempt_at: float
    created_at: float
    last_error: str | None = None


SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id              TEXT PRIMARY KEY,
    dedupe_key      TEXT NOT NULL UNIQUE,
    topic           TEXT NOT NULL,
    payload         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    created_at      REAL NOT NULL,
    sent_at         REAL,
    last_error      TEXT
);
CREATE INDEX IF NOT EXISTS ix_outbox_claimable
    ON outbox (status, next_attempt_at);
"""


class Outbox:
    """Append-only queue table living inside your application database.

    It must be the *same* database your business writes go to. An outbox in a
    separate database is just a message broker with extra steps, and it
    reintroduces the two-commit problem it was meant to remove.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        max_attempts: int = 5,
        base_backoff_seconds: float = 2.0,
        max_backoff_seconds: float = 3600.0,
    ) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._max_attempts = max_attempts
        self._base_backoff = base_backoff_seconds
        self._max_backoff = max_backoff_seconds
        self._conn.executescript(SCHEMA)

    # ---------------------------------------------------------------- write

    def enqueue(
        self,
        topic: str,
        payload: dict[str, Any],
        *,
        dedupe_key: str,
        now: float | None = None,
    ) -> Message:
        """Insert one message. Call this inside your business transaction.

        `dedupe_key` must be derived from the business fact, not from the
        clock or a random value. "dose-4821-missed" is correct. A uuid4 is
        not: retrying the handler would enqueue a second copy.
        """
        if not dedupe_key:
            raise ValueError("dedupe_key is required; it is the whole mechanism")

        ts = time.time() if now is None else now
        message = Message(
            id=str(uuid.uuid4()),
            dedupe_key=dedupe_key,
            topic=topic,
            payload=payload,
            status=Status.PENDING,
            attempts=0,
            next_attempt_at=ts,
            created_at=ts,
        )
        try:
            self._conn.execute(
                "INSERT INTO outbox (id, dedupe_key, topic, payload, status,"
                " attempts, next_attempt_at, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    message.id,
                    message.dedupe_key,
                    message.topic,
                    json.dumps(payload, sort_keys=True),
                    Status.PENDING.value,
                    0,
                    ts,
                    ts,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateMessage(dedupe_key) from exc
        return message

    # ----------------------------------------------------------------- read

    @staticmethod
    def _claim_sql() -> str:
        # On Postgres this becomes:
        #   SELECT ... FOR UPDATE SKIP LOCKED
        # which lets N workers drain the same table without stepping on each
        # other. SQLite serialises writers anyway, so the plain SELECT is
        # equivalent here.
        return (
            "SELECT * FROM outbox"
            " WHERE status = ? AND next_attempt_at <= ?"
            " ORDER BY created_at LIMIT ?"
        )

    def claim(self, limit: int = 10, *, now: float | None = None) -> list[Message]:
        ts = time.time() if now is None else now
        rows = self._conn.execute(
            self._claim_sql(), (Status.PENDING.value, ts, limit)
        ).fetchall()
        return [self._row_to_message(r) for r in rows]

    def get(self, dedupe_key: str) -> Message | None:
        row = self._conn.execute(
            "SELECT * FROM outbox WHERE dedupe_key = ?", (dedupe_key,)
        ).fetchone()
        return self._row_to_message(row) if row else None

    def counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT status, COUNT(*) AS n FROM outbox GROUP BY status"
        ).fetchall()
        return {r["status"]: r["n"] for r in rows}

    def dead_letters(self) -> list[Message]:
        """Everything that exhausted its retries. Page a human on len() > 0."""
        rows = self._conn.execute(
            "SELECT * FROM outbox WHERE status = ? ORDER BY created_at",
            (Status.DEAD.value,),
        ).fetchall()
        return [self._row_to_message(r) for r in rows]

    # --------------------------------------------------------------- update

    def mark_sent(self, message_id: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else now
        self._conn.execute(
            "UPDATE outbox SET status = ?, sent_at = ?, last_error = NULL"
            " WHERE id = ?",
            (Status.SENT.value, ts, message_id),
        )

    def mark_failed(
        self, message: Message, error: str, *, now: float | None = None
    ) -> Status:
        """Record a failed attempt and decide whether to retry or quarantine."""
        ts = time.time() if now is None else now
        attempts = message.attempts + 1

        if attempts >= self._max_attempts:
            self._conn.execute(
                "UPDATE outbox SET status = ?, attempts = ?, last_error = ?"
                " WHERE id = ?",
                (Status.DEAD.value, attempts, error[:2000], message.id),
            )
            return Status.DEAD

        delay = min(self._base_backoff * (2 ** (attempts - 1)), self._max_backoff)
        self._conn.execute(
            "UPDATE outbox SET attempts = ?, next_attempt_at = ?, last_error = ?"
            " WHERE id = ?",
            (attempts, ts + delay, error[:2000], message.id),
        )
        return Status.PENDING

    def requeue(self, dedupe_key: str, *, now: float | None = None) -> bool:
        """Pull a message back out of the dead-letter queue after a fix."""
        ts = time.time() if now is None else now
        cur = self._conn.execute(
            "UPDATE outbox SET status = ?, attempts = 0, next_attempt_at = ?,"
            " last_error = NULL WHERE dedupe_key = ? AND status = ?",
            (Status.PENDING.value, ts, dedupe_key, Status.DEAD.value),
        )
        return cur.rowcount > 0

    # --------------------------------------------------------------- helper

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> Message:
        return Message(
            id=row["id"],
            dedupe_key=row["dedupe_key"],
            topic=row["topic"],
            payload=json.loads(row["payload"]),
            status=Status(row["status"]),
            attempts=row["attempts"],
            next_attempt_at=row["next_attempt_at"],
            created_at=row["created_at"],
            last_error=row["last_error"],
        )


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Business write and outbox enqueue must share one commit. This is it."""
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
