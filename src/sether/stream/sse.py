"""SSE / JSON-stream mode.

Direct port of ``src/stream/sse.ts``. Server-Sent Events frame text as
``data:`` / ``event:`` / ``id:`` / ``retry:`` lines separated by blank lines.
This module redacts only the payload inside ``data:`` lines and preserves the
field labels, event metadata, and blank-line separators verbatim.

Each SSE line is a complete unit by design, so per-line one-shot redaction is
correct -- the chunk-boundary safe-distance buffering of the plain redact stream
is not needed here. (For PII that spans multiple SSE lines, concatenate first
and use the plain redact stream.)

On restore, a ``data:`` payload that parses as JSON (the OpenAI / Anthropic
chunk format) is restored value by value: only the string values holding a
token are re-encoded, so an original containing ``"``, ``\\`` or a line break can
neither change the JSON nor break the SSE framing, and every other byte is kept.
Object keys are not restored. Any other payload is restored as text, and a line
break in an original continues it on a new ``data: `` line, so it cannot end
the line and inject ``event:`` / ``id:`` / ``data:`` fields or a blank line. The
client joins the data lines with ``\\n``, so CR and CRLF in an original arrive
as ``\\n``. Each ``data:`` line is handled on its own, so a JSON payload split
across several ``data:`` lines is restored as text.
"""

from __future__ import annotations

import re
from typing import AsyncIterable, AsyncIterator, Callable, Iterable, Iterator, Sequence

from ..detectors.types import Detector
from ..vault.types import Vault
from ._tokens import TOKEN_RE
from .redact import redact_sync
from .restore import RestoreString, restore_json_document, restore_sync


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
    return _sse_restore_stream(lambda text: restore_sync(text, vault))


def restore_sse_text(text: str, restore_string: RestoreString) -> str:
    """Restore a complete, already-buffered SSE text the way the SSE restore
    stream does, with ``restore_string`` restoring each decoded value (and, in a
    text payload, each token). Used for buffered ``text/event-stream`` response
    bodies."""
    stream = _sse_restore_stream(restore_string)
    return stream.feed(text) + stream.finish()


def _sse_restore_stream(restore_string: RestoreString) -> SSEStream:
    return SSEStream(lambda payload: _restore_sse_payload(payload, restore_string))


_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")


def _restore_sse_payload(payload: str, restore_string: RestoreString) -> str:
    """A JSON payload is restored value by value, which escapes line breaks. A
    text payload is restored token by token, and each line break in an original
    starts a new data line in the line ending of the stream (a CRLF-framed line
    keeps its trailing ``\\r`` in the payload). Continuation lines always use
    ``data: ``, so a leading space in the next part of the original is kept.
    Without a line break in an original, the output equals restoring the
    payload as text."""
    document = restore_json_document(payload, restore_string)
    if document is not None:
        return document
    new_data_line = "\r\ndata: " if payload.endswith("\r") else "\ndata: "

    def _sub(m: "re.Match[str]") -> str:
        return _LINE_BREAK_RE.sub(lambda _: new_data_line, restore_string(m.group(0)))

    return TOKEN_RE.sub(_sub, payload)


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
