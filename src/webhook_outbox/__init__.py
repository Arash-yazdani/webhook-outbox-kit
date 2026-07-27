"""webhook-outbox-kit

Two production patterns that belong together, implemented with no dependencies
outside the standard library:

    Inbound   fail-closed webhook signature verification across three schemes
    Outbound  a transactional outbox so a queued alert cannot be silently lost

Together they cover both edges of a webhook-driven system: you only act on
requests you can prove came from the vendor, and every action you promised to
take survives a process dying mid-flight.
"""

from .outbox import DuplicateMessage, Message, Outbox, Status, transaction
from .signatures import (
    InvalidSignature,
    MissingSignature,
    SharedSecretHeader,
    SignatureError,
    SignatureVerifier,
    StaleSignature,
    StripeHmacSha256,
    TwilioHmacSha1,
)
from .worker import DrainResult, PermanentError, TransientError, Worker

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # signatures
    "SignatureVerifier",
    "SharedSecretHeader",
    "TwilioHmacSha1",
    "StripeHmacSha256",
    "SignatureError",
    "MissingSignature",
    "InvalidSignature",
    "StaleSignature",
    # outbox
    "Outbox",
    "Message",
    "Status",
    "DuplicateMessage",
    "transaction",
    # worker
    "Worker",
    "DrainResult",
    "TransientError",
    "PermanentError",
]
