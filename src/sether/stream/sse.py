"""SSE / JSON-stream mode.

Direct port of ``src/stream/sse.ts``. Server-Sent Events frame text as
``data:`` / ``event:`` / ``id:`` / ``retry:`` lines separated by blank lines.
This module redacts only the payload inside ``data:`` lines and preserves the
field labels, event metadata, and blank-line separators verbatim.

Each SSE line is a complete unit by design, so per-line one-shot redaction is
correct -- the chunk-boundary safe-distance buffering of the plain redact stream
is not needed here. (For PII that spans multiple SSE lines, concatenate first
and use the plain redact stream.)
"""

from __future__ import annotations

from typing import AsyncIterable, AsyncIterator, Callable, Iterable, Iterator, Sequence

from ..detectors.types import Detector
from ..vault.types import Vault
from .redact import redact_sync
from .restore import restore_sync


class SSEStream:
    """Stateful, line-oriented SSE transformer."""

    def __init__(self, process_payload: Callable[[str], str]) -> None:
        self._line_buffer = ""
        self._process = process_payload

    def _process_line(self, line: str) -> str:
        if not line.startswith("data:"):
            return line
        after_colon = line[5:]
        has_space = after_colon.startswith(" ")
        prefix = "data: " if has_space else "data:"
        payload = after_colon[1:] if has_space else after_colon
        return prefix + self._process(payload)

    def feed(self, chunk: str) -> str:
        self._line_buffer += chunk
        out: list = []
        while True:
            nl = self._line_buffer.find("\n")
            if nl == -1:
                break
            line = self._line_buffer[:nl]
            self._line_buffer = self._line_buffer[nl + 1:]
            out.append(self._process_line(line) + "\n")
        return "".join(out)

    def finish(self) -> str:
        if self._line_buffer:
            line = self._line_buffer
            self._line_buffer = ""
            return self._process_line(line)
        return ""


def create_sse_redact_stream(detectors: Sequence[Detector], vault: Vault) -> SSEStream:
    return SSEStream(lambda payload: redact_sync(payload, detectors, vault))


def create_sse_restore_stream(vault: Vault) -> SSEStream:
    return SSEStream(lambda payload: restore_sync(payload, vault))


def _run_sync(stream: SSEStream, chunks: Iterable[str]) -> Iterator[str]:
    for chunk in chunks:
        out = stream.feed(chunk)
        if out:
            yield out
    out = stream.finish()
    if out:
        yield out


async def _run_async(stream: SSEStream, chunks: AsyncIterable[str]) -> AsyncIterator[str]:
    async for chunk in chunks:
        out = stream.feed(chunk)
        if out:
            yield out
    out = stream.finish()
    if out:
        yield out


def sse_redact_iter(chunks: Iterable[str], detectors: Sequence[Detector], vault: Vault) -> Iterator[str]:
    return _run_sync(create_sse_redact_stream(detectors, vault), chunks)


def sse_restore_iter(chunks: Iterable[str], vault: Vault) -> Iterator[str]:
    return _run_sync(create_sse_restore_stream(vault), chunks)


def asse_redact_iter(chunks: AsyncIterable[str], detectors: Sequence[Detector], vault: Vault) -> AsyncIterator[str]:
    return _run_async(create_sse_redact_stream(detectors, vault), chunks)


def asse_restore_iter(chunks: AsyncIterable[str], vault: Vault) -> AsyncIterator[str]:
    return _run_async(create_sse_restore_stream(vault), chunks)


__all__ = [
    "SSEStream",
    "create_sse_redact_stream",
    "create_sse_restore_stream",
    "sse_redact_iter",
    "sse_restore_iter",
    "asse_redact_iter",
    "asse_restore_iter",
]
