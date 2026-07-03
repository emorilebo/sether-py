"""Audit event schema.

Direct port of ``src/audit/types.ts``. Every redaction can emit one
:class:`AuditEvent`. The OSS package provides the type contract and reference
sinks; the hosted tier ingests these events for retention, compliance
reporting, and SIEM export. The JSON wire shape is the same on both sides
(camelCase keys), so a deployment can promote from local-only to hosted without
reshaping events.

**The original value is never carried in an event -- only its length.**
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol, Tuple, runtime_checkable

# Allowed compliance frameworks (informational -- not enforced at runtime).
FRAMEWORKS = (
    "GDPR", "SOC2", "HIPAA", "EU_AI_ACT", "NDPA", "CCPA",
    "PCI_DSS", "ISO_27001", "OWASP_LLM", "OWASP_AGENTIC",
)


@dataclass(frozen=True)
class RegulationMapping:
    framework: str  # one of FRAMEWORKS
    reference: str  # e.g. "Art. 28", "CC6.7", "164.312"

    def to_dict(self) -> Dict[str, str]:
        return {"framework": self.framework, "reference": self.reference}


@dataclass
class AuditEvent:
    """One redaction (or restoration) event."""

    timestamp: str  # ISO-8601 UTC
    detector: str  # e.g. "EMAIL" or "OPENAI_KEY"
    value_length: int  # length of the original value (never the value itself)
    token: str  # the token that replaced the value
    action: str = "REDACTED"  # "REDACTED" | "RESTORED"
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    destination: Optional[str] = None
    regulation_mappings: Optional[List[RegulationMapping]] = None

    def to_dict(self) -> Dict[str, object]:
        """Serialise to the camelCase JSON wire shape, omitting unset optionals."""
        out: Dict[str, object] = {
            "timestamp": self.timestamp,
            "detector": self.detector,
            "valueLength": self.value_length,
            "token": self.token,
            "action": self.action,
        }
        if self.tenant_id is not None:
            out["tenantId"] = self.tenant_id
        if self.request_id is not None:
            out["requestId"] = self.request_id
        if self.destination is not None:
            out["destination"] = self.destination
        if self.regulation_mappings is not None:
            out["regulationMappings"] = [m.to_dict() for m in self.regulation_mappings]
        return out


@runtime_checkable
class AuditSink(Protocol):
    def write(self, event: AuditEvent) -> None: ...


def _m(*pairs: Tuple[str, str]) -> List[RegulationMapping]:
    return [RegulationMapping(framework, reference) for framework, reference in pairs]


# Default regulation mappings per detector type. Each entry is defensible
# against the actual regulation text.
DEFAULT_REGULATION_MAPPINGS: Dict[str, List[RegulationMapping]] = {
    "EMAIL": _m(("GDPR", "Art. 28"), ("SOC2", "CC6.7")),
    "PHONE": _m(("GDPR", "Art. 28"), ("SOC2", "CC6.7")),
    "CC": _m(("PCI_DSS", "Req. 3.4"), ("SOC2", "CC6.7")),
    "SSN": _m(("GDPR", "Art. 9"), ("HIPAA", "164.514")),
    "IPV4": _m(("GDPR", "Recital 30")),
    "IPV6": _m(("GDPR", "Recital 30")),
    "IBAN": _m(("PCI_DSS", "Req. 3.4"), ("GDPR", "Art. 28")),
    "AWS_KEY": _m(("SOC2", "CC6.1"), ("ISO_27001", "A.9.4.3")),
    "OPENAI_KEY": _m(("SOC2", "CC6.1")),
    "ANTHROPIC_KEY": _m(("SOC2", "CC6.1")),
    "GITHUB_PAT": _m(("SOC2", "CC6.1")),
    "SLACK_TOKEN": _m(("SOC2", "CC6.1")),
    "STRIPE_KEY": _m(("PCI_DSS", "Req. 3.5"), ("SOC2", "CC6.1")),
    "JWT": _m(("SOC2", "CC6.1")),
    "HIGH_ENTROPY": _m(("SOC2", "CC6.1")),
}


__all__ = [
    "FRAMEWORKS",
    "RegulationMapping",
    "AuditEvent",
    "AuditSink",
    "DEFAULT_REGULATION_MAPPINGS",
]
