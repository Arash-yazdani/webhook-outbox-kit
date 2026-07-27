# webhook-outbox-kit

Fail-closed webhook signature verification and a transactional outbox, in about
600 lines with **no dependencies outside the Python standard library**.

Two patterns that cover both edges of a webhook-driven system:

- **Inbound** — you only act on requests you can prove came from the vendor.
- **Outbound** — an alert you promised to send survives the process dying.

Extracted from a production voice-AI system where a dropped message meant a
family did not learn their parent missed a dose. The IP stayed private; the
patterns did not need to.

```
pip install -e ".[dev]" && pytest -q
41 passed in 0.05s
```

---

## The problem the outbox solves

Your handler has to do two things: write a row, and tell the outside world.
If those are two separate operations, there is a window where one succeeds and
the other does not.

```python
db.record_missed_dose(dose_id)     # committed
sms.send("Dad missed his 8am")     # process dies here
                                   # -> nobody is ever told
```

Retrying does not help: the process that would retry is the one that died.
Sending first does not help either, you just choose which half to lose.

The fix is to stop having two systems. Write the *intent to send* into your own
database, in the same transaction as the business fact:

```python
from webhook_outbox import Outbox, transaction

outbox = Outbox(conn)

with transaction(conn):
    conn.execute("INSERT INTO dose_events VALUES (?, 'missed', ?)", (dose_id, ts))
    outbox.enqueue(
        "sms.caregiver_alert",
        {"to": caregiver, "dose_id": dose_id},
        dedupe_key=f"dose-{dose_id}-missed",   # derived from the fact, not the clock
    )
```

One commit. Either both landed or neither did. A separate worker drains the
outbox and does the sending, retrying until it works.

```python
from webhook_outbox import Worker

worker = Worker(outbox, {"sms.caregiver_alert": send_sms})
worker.run_forever()
```

### On the phrase "exactly-once"

True exactly-once delivery across a network boundary is not achievable. The
receiver can always ack and then crash. What *is* achievable, and what this
does:

- **exactly-once enqueue** — enforced by a `UNIQUE` constraint on `dedupe_key`,
  in the schema rather than in application code. Two racing workers that both
  check "does this exist yet" will both see *no*. Only the database can
  actually prevent the double.
- **at-least-once delivery** with a stable dedupe key, which the receiver or
  the vendor's own idempotency key collapses back into one visible effect.

Anyone claiming more than that is not counting the failure modes.

**The dedupe key must be derived from the business fact.** `dose-4821-missed`
is correct. A `uuid4()` is not — retrying the handler would enqueue a second
copy, which is the exact bug the outbox exists to prevent.

### Failure handling

| Situation | Behaviour |
|---|---|
| Transient error (timeout, 429, 503) | Exponential backoff, capped, retried |
| `PermanentError` (bad number, 400) | Quarantined immediately, no retries burned |
| No sender registered for the topic | Quarantined immediately — it's a deploy bug |
| Retries exhausted | Moved to `dead`, stops consuming worker throughput |

A poison message never blocks the batch behind it. Head-of-line blocking is how
one bad payload becomes an outage.

Alert on `len(outbox.dead_letters()) > 0`. A growing dead-letter queue is the
earliest signal something downstream broke, and it's the metric people forget.
`outbox.requeue(dedupe_key)` puts a message back after you ship the fix.

---

## Inbound: three signature schemes, and why one verifier isn't enough

| Class | Scheme | Signs | Replay-resistant |
|---|---|---|---|
| `SharedSecretHeader` | static secret in a header | nothing | ❌ |
| `TwilioHmacSha1` | HMAC-SHA1 | URL + sorted form params | ❌ |
| `StripeHmacSha256` | HMAC-SHA256 | `timestamp` + raw body | ✅ |

```python
from webhook_outbox import StripeHmacSha256, SignatureError

verifier = StripeHmacSha256(os.environ["STRIPE_WEBHOOK_SECRET"])

body = await request.body()          # RAW bytes, before any parsing
try:
    verifier.verify(headers=dict(request.headers), body=body)
except SignatureError:
    return Response(status_code=401)  # fail closed, always
```

Every verifier raises rather than returning a boolean. The "maybe" branch is
the whole vulnerability, so the API does not offer one.

### Details that actually bite people

**Constant-time comparison.** Comparing signatures with `==` leaks the secret
one byte at a time to anyone willing to measure. Every comparison here uses
`hmac.compare_digest`.

**Twilio signs the URL.** Including scheme, port, and query string. If you sit
behind a proxy that terminates TLS and rewrites `https` to `http`, every
signature fails until you reconstruct the original URL from
`X-Forwarded-Proto`/`X-Forwarded-Host`.

**Twilio concatenates params with no separator.** Sorted `key + value` pairs,
joined by nothing. Not urlencoded, not comma-delimited. Just concatenated.

**Stripe signs the raw body.** If your framework parsed the JSON and you
re-serialise it before verifying, key ordering and whitespace differ and every
signature fails. Capture the raw bytes first.

**Stripe's header can carry multiple `v1=` values.** That is how key rotation
happens without downtime. Check all of them or you take an outage mid-rotation.

**Check the signature before the timestamp.** Validating freshness first lets
an attacker with no valid secret probe your tolerance window by watching which
error comes back. `StripeHmacSha256` verifies the HMAC, *then* the clock.

---

## Install

```bash
pip install -e ".[dev]"
pytest -q
```

Python 3.10+. No runtime dependencies. FastAPI is needed only for
`examples/fastapi_app.py`.

## Storage

Backed by stdlib `sqlite3` so the tests run anywhere. The schema and claim
query port cleanly to Postgres — one line changes, in `Outbox._claim_sql()`:

```sql
SELECT * FROM outbox
 WHERE status = 'pending' AND next_attempt_at <= now()
 ORDER BY created_at LIMIT $1
 FOR UPDATE SKIP LOCKED          -- lets N workers drain without collisions
```

The outbox table **must live in the same database as your business writes**.
An outbox in a separate database is a message broker with extra steps, and it
reintroduces the two-commit problem it was meant to remove.

## Layout

```
src/webhook_outbox/
  signatures.py   three verifiers, fail-closed, constant-time
  outbox.py       schema, enqueue, claim, backoff, dead-letter, requeue
  worker.py       drain loop, transient vs permanent classification
tests/            41 tests, no network, no fixtures beyond an in-memory DB
examples/         FastAPI app wiring all three verifiers + a real sender
```

## What the tests actually assert

Not "does the happy path work." The failure modes:

- a rolled-back business transaction leaves **no** queued alert
- a duplicate `dedupe_key` is rejected by the database, not by app code
- a message is not claimable until its backoff window elapses
- exhausted retries quarantine instead of looping forever
- a permanent error quarantines on attempt one
- one poison message does not block the batch behind it
- a Stripe-signed request does not validate against the Twilio verifier
- a bad signature on a stale request reports `Invalid`, not `Stale`
- Twilio params sort deterministically regardless of dict insertion order

## License

MIT.
