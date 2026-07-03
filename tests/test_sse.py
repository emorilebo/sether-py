from __future__ import annotations

from sether.detectors.basic import basic_detectors
from sether.stream.sse import sse_redact_iter, sse_restore_iter
from sether.vault.memory import MemoryVault


def _chunk(text, size):
    return [text[i:i + size] for i in range(0, len(text), size)]


SSE_INPUT = (
    "event: message\n"
    "id: 42\n"
    "data: hello alice@example.com\n"
    "data: second line\n"
    "\n"
    "retry: 3000\n"
)


def test_sse_redacts_only_data_lines_and_preserves_framing():
    vault = MemoryVault()
    out = "".join(sse_redact_iter([SSE_INPUT], basic_detectors, vault))
    # Field labels and separators preserved verbatim.
    assert "event: message\n" in out
    assert "id: 42\n" in out
    assert "retry: 3000\n" in out
    assert "\n\n" in out  # blank-line event separator preserved
    # The email inside the data line is gone.
    assert "alice@example.com" not in out
    assert "data: hello <EMAIL_" in out


def test_sse_round_trip_across_chunks():
    vault = MemoryVault()
    redacted = "".join(sse_redact_iter(_chunk(SSE_INPUT, 6), basic_detectors, vault))
    restored = "".join(sse_restore_iter(_chunk(redacted, 4), vault))
    assert restored == SSE_INPUT


def test_sse_preserves_data_prefix_without_space():
    vault = MemoryVault()
    out = "".join(sse_redact_iter(["data:nospace@example.com\n"], basic_detectors, vault))
    assert out.startswith("data:<EMAIL_")
