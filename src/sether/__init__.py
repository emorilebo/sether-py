"""Sether -- streaming PII redaction for AI applications.

Hide personal data from your AI before it reaches any LLM provider. Sether
detects sensitive data, swaps each match for a stable token before the request
leaves your boundary, then restores the originals transparently in the response.

    from sether import Sether

    sether = Sether()
    safe = sether.redact_sync("my email is alice@example.com")
    # -> "my email is <EMAIL_...>"
    back = sether.restore_sync(safe)
    # -> "my email is alice@example.com"

Named for the Hebrew *sether* -- *the hiding place*. Psalm 32:7.
"""

from __future__ import annotations

__version__ = "0.2.0"

from .audit import (
    DEFAULT_REGULATION_MAPPINGS,
    AuditEvent,
    AuditSink,
    ConsoleAuditSink,
    MemoryAuditSink,
    RegulationMapping,
)
from .core import Sether
from .detectors import (
    Detector,
    DetectorMatch,
    address_detector,
    anthropic_key_detector,
    aws_access_key_detector,
    basic_detectors,
    create_phone_detector,
    credit_card_detector,
    dob_detector,
    email_detector,
    github_pat_detector,
    high_entropy_detector,
    iban_detector,
    identity_detectors,
    ipv4_detector,
    ipv6_detector,
    jwt_detector,
    name_detector,
    openai_key_detector,
    passport_detector,
    phone_detector,
    secrets_detectors,
    slack_token_detector,
    ssn_detector,
    stripe_key_detector,
)
from .middleware import (
    SetherASGIMiddleware,
    SetherWSGIMiddleware,
    wrap_anthropic,
    wrap_httpx,
    wrap_openai,
)
from .stream import (
    RedactStream,
    RestoreStream,
    SSEStream,
    aredact_iter,
    arestore_iter,
    asse_redact_iter,
    asse_restore_iter,
    create_redact_stream,
    create_restore_stream,
    create_sse_redact_stream,
    create_sse_restore_stream,
    redact_iter,
    redact_sync,
    restore_iter,
    restore_sync,
    sse_redact_iter,
    sse_restore_iter,
)
from .vault import MemoryVault, Vault

__all__ = [
    "__version__",
    # core
    "Sether",
    "MemoryVault",
    "Vault",
    # one-shot + streaming
    "redact_sync",
    "restore_sync",
    "RedactStream",
    "RestoreStream",
    "create_redact_stream",
    "create_restore_stream",
    "redact_iter",
    "aredact_iter",
    "restore_iter",
    "arestore_iter",
    # detectors
    "Detector",
    "DetectorMatch",
    "basic_detectors",
    "email_detector",
    "credit_card_detector",
    "ssn_detector",
    "ipv4_detector",
    "ipv6_detector",
    "iban_detector",
    "phone_detector",
    "create_phone_detector",
    "secrets_detectors",
    "aws_access_key_detector",
    "openai_key_detector",
    "anthropic_key_detector",
    "github_pat_detector",
    "slack_token_detector",
    "stripe_key_detector",
    "jwt_detector",
    "high_entropy_detector",
    "identity_detectors",
    "name_detector",
    "dob_detector",
    "passport_detector",
    "address_detector",
    # SSE
    "SSEStream",
    "create_sse_redact_stream",
    "create_sse_restore_stream",
    "sse_redact_iter",
    "sse_restore_iter",
    "asse_redact_iter",
    "asse_restore_iter",
    # audit
    "AuditEvent",
    "AuditSink",
    "RegulationMapping",
    "DEFAULT_REGULATION_MAPPINGS",
    "ConsoleAuditSink",
    "MemoryAuditSink",
    # middleware
    "wrap_openai",
    "wrap_anthropic",
    "wrap_httpx",
    "SetherASGIMiddleware",
    "SetherWSGIMiddleware",
]
