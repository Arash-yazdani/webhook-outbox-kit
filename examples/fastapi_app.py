"""End-to-end example: verify inbound webhooks, enqueue outbound alerts safely.

Run it:

    pip install fastapi uvicorn
    uvicorn examples.fastapi_app:app --reload

FastAPI is only needed for this file. The library itself has no dependencies.

The shape below is the one that matters. Read the `/webhooks/voice` handler:
the business write and the outbox enqueue happen inside one transaction, and
the SMS is never sent from the request path. If this process is killed on the
line after the commit, the alert still goes out, because the intent to send is
already durable.
"""

from __future__ import annotations

import os
import sqlite3

from fastapi import FastAPI, Request, Response

from webhook_outbox import (
    DuplicateMessage,
    Message,
    Outbox,
    PermanentError,
    SharedSecretHeader,
    SignatureError,
    StripeHmacSha256,
    TwilioHmacSha1,
    Worker,
    transaction,
)

app = FastAPI(title="webhook-outbox-kit example")

conn = sqlite3.connect("example.db", check_same_thread=False)
conn.execute(
    "CREATE TABLE IF NOT EXISTS dose_events ("
    " id TEXT PRIMARY KEY, outcome TEXT NOT NULL, received_at REAL NOT NULL)"
)
outbox = Outbox(conn)

# One verifier per inbound integration. Each vendor signs differently; there is
# no single generic verifier that covers all three correctly.
verifiers = {
    "voice": SharedSecretHeader(os.environ.get("VOICE_WEBHOOK_SECRET", "dev-secret")),
    "telephony": TwilioHmacSha1(os.environ.get("TWILIO_AUTH_TOKEN", "dev-token")),
    "billing": StripeHmacSha256(os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_dev")),
}


@app.post("/webhooks/voice")
async def voice_webhook(request: Request) -> Response:
    """Vendor: shared-secret header (Vapi style)."""
    body = await request.body()  # raw bytes, before any parsing
    try:
        verifiers["voice"].verify(headers=dict(request.headers), body=body)
    except SignatureError:
        # Fail closed. No logging of the payload: it is unauthenticated input.
        return Response(status_code=401)

    event = await request.json()
    dose_id = event["dose_id"]
    outcome = event["outcome"]  # confirmed | deferred | denied | concern | unclear

    with transaction(conn):
        conn.execute(
            "INSERT OR REPLACE INTO dose_events VALUES (?, ?, ?)",
            (dose_id, outcome, event.get("ts", 0.0)),
        )
        if outcome in {"denied", "concern", "unclear"}:
            try:
                outbox.enqueue(
                    "sms.caregiver_alert",
                    {"to": event["caregiver_phone"], "dose_id": dose_id, "outcome": outcome},
                    # Derived from the business fact, never from the clock.
                    # A vendor retry of this same webhook enqueues nothing new.
                    dedupe_key=f"dose-{dose_id}-{outcome}",
                )
            except DuplicateMessage:
                pass  # already queued by an earlier delivery of this webhook

    return Response(status_code=204)


@app.post("/webhooks/telephony")
async def telephony_webhook(request: Request) -> Response:
    """Vendor: HMAC-SHA1 over URL + sorted form params (Twilio style)."""
    form = dict(await request.form())
    try:
        verifiers["telephony"].verify(
            headers=dict(request.headers),
            body=b"",
            # Must be the URL the vendor actually called. Behind a TLS-
            # terminating proxy, reconstruct it from X-Forwarded-Proto/Host
            # or every signature will fail.
            url=str(request.url),
            params={k: str(v) for k, v in form.items()},
        )
    except SignatureError:
        return Response(status_code=401)
    return Response(status_code=204)


@app.post("/webhooks/billing")
async def billing_webhook(request: Request) -> Response:
    """Vendor: HMAC-SHA256 over "timestamp.body" with replay window (Stripe style)."""
    body = await request.body()  # raw bytes; re-serialising the JSON breaks this
    try:
        verifiers["billing"].verify(headers=dict(request.headers), body=body)
    except SignatureError:
        return Response(status_code=401)
    return Response(status_code=204)


# --------------------------------------------------------------- the sender


def send_caregiver_sms(message: Message) -> None:
    """Runs in the worker, never in the request path."""
    to = message.payload["to"]
    if not to.startswith("+"):
        # Will never succeed no matter how many times we try it.
        raise PermanentError(f"unroutable number {to!r}")

    # twilio.messages.create(
    #     to=to,
    #     body=f"Alert: dose {message.payload['dose_id']} -> {message.payload['outcome']}",
    #     idempotency_key=message.dedupe_key,   # <- collapses our retries vendor-side
    # )
    print(f"[sms] -> {to}: {message.payload}")


worker = Worker(outbox, {"sms.caregiver_alert": send_caregiver_sms})


@app.post("/internal/drain")
def drain() -> dict:
    """Trigger a drain. In production run `worker.run_forever()` in its own
    process, or call this from a scheduler every few seconds."""
    result = worker.drain_once()
    return {
        "claimed": result.claimed,
        "sent": result.sent,
        "retried": result.retried,
        "quarantined": result.quarantined,
    }


@app.get("/internal/health")
def health() -> dict:
    """Page on dead_letters > 0. A growing dead-letter queue is the earliest
    signal that something downstream broke, and it is the one metric people
    forget to alert on."""
    dead = outbox.dead_letters()
    return {"counts": outbox.counts(), "dead_letters": len(dead), "healthy": not dead}
