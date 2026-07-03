from __future__ import annotations

import json

from sether.audit.sinks import ConsoleAuditSink, MemoryAuditSink
from sether.audit.types import (
    DEFAULT_REGULATION_MAPPINGS,
    AuditEvent,
    RegulationMapping,
)


def test_event_to_dict_camelcase_and_omits_optionals():
    ev = AuditEvent(
        timestamp="2026-06-25T00:00:00.000Z",
        detector="EMAIL",
        value_length=17,
        token="<EMAIL_x>",
    )
    d = ev.to_dict()
    assert d == {
        "timestamp": "2026-06-25T00:00:00.000Z",
        "detector": "EMAIL",
        "valueLength": 17,
        "token": "<EMAIL_x>",
        "action": "REDACTED",
    }
    # Optionals omitted entirely.
    assert "tenantId" not in d and "requestId" not in d and "destination" not in d


def test_event_to_dict_includes_set_optionals_and_mappings():
    ev = AuditEvent(
        timestamp="t",
        detector="CC",
        value_length=16,
        token="<CC_x>",
        tenant_id="acme",
        request_id="req-1",
        destination="openai",
        regulation_mappings=[RegulationMapping("PCI_DSS", "Req. 3.4")],
    )
    d = ev.to_dict()
    assert d["tenantId"] == "acme"
    assert d["requestId"] == "req-1"
    assert d["destination"] == "openai"
    assert d["regulationMappings"] == [{"framework": "PCI_DSS", "reference": "Req. 3.4"}]


def test_never_carries_the_value():
    ev = AuditEvent(timestamp="t", detector="EMAIL", value_length=17, token="<EMAIL_x>")
    assert "value" not in ev.to_dict()


def test_console_sink_writes_jsonl():
    lines = []
    sink = ConsoleAuditSink(write=lines.append)
    sink.write(AuditEvent(timestamp="t", detector="EMAIL", value_length=3, token="<EMAIL_x>"))
    assert len(lines) == 1
    assert lines[0].endswith("\n")
    parsed = json.loads(lines[0])
    assert parsed["detector"] == "EMAIL" and parsed["valueLength"] == 3


def test_memory_sink_accumulates_and_clears():
    sink = MemoryAuditSink()
    sink.write(AuditEvent(timestamp="t", detector="EMAIL", value_length=1, token="<x>"))
    sink.write(AuditEvent(timestamp="t", detector="CC", value_length=2, token="<y>"))
    assert len(sink.events) == 2
    sink.clear()
    assert sink.events == []


def test_default_mappings_present():
    assert DEFAULT_REGULATION_MAPPINGS["EMAIL"][0].framework == "GDPR"
    assert any(m.framework == "PCI_DSS" for m in DEFAULT_REGULATION_MAPPINGS["CC"])
