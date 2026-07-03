"""Reference audit sinks.

Direct port of ``src/audit/console.ts``. Sinks are intentionally simple -- one
method. Anything more complex (batching, retries, structured forwarding) lives
in your own adapter.
"""

from __future__ import annotations

import json
import sys
from typing import Callable, List, Optional

from .types import AuditEvent


class ConsoleAuditSink:
    """Writes one JSON line per event to stderr by default. A template for
    production sinks (Datadog, Splunk, Logpush, R2, ...)."""

    def __init__(
        self,
        write: Optional[Callable[[str], object]] = None,
        pretty: bool = False,
    ) -> None:
        self._write: Callable[[str], object] = write or (lambda line: sys.stderr.write(line))
        self._pretty = pretty

    def write(self, event: AuditEvent) -> None:
        data = event.to_dict()
        text = json.dumps(data, indent=2, ensure_ascii=False) if self._pretty else json.dumps(data, ensure_ascii=False)
        self._write(text + "\n")


class MemoryAuditSink:
    """Accumulates events in memory. Used by tests and the in-browser sandbox."""

    def __init__(self) -> None:
        self.events: List[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()


__all__ = ["ConsoleAuditSink", "MemoryAuditSink"]
