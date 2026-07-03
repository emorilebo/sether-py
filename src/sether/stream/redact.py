"""Chunk-boundary-safe streaming redaction.

Direct port of ``src/stream/redact.ts``. The redactor holds back
``safe_distance_bytes`` (default 256) at the tail of each chunk so a PII pattern
crossing a chunk boundary is still detected when the next chunk arrives, plus a
long-value guard that holds back an in-progress whitespace-free run (a JWT, an
API key) up to ``max(safe_distance_bytes * 4, 8192)`` bytes.

The same stateful :class:`RedactStream` backs both the synchronous and the
asynchronous iteration helpers, so there is exactly one copy of the boundary
logic.
"""

from __future__ import annotations

from typing import AsyncIterable, AsyncIterator, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..detectors.types import Detector, DetectorMatch
from ..vault.types import Vault
from ._tokens import UuidFn, random_uuid

_DEFAULT_SAFE_DISTANCE = 256
_WHITESPACE = frozenset(" \t\n\r\f\v")


class _DetectedMatch:
    __slots__ = ("start", "end", "value", "detector_type")

    def __init__(self, start: int, end: int, value: str, detector_type: str) -> None:
        self.start = start
        self.end = end
        self.value = value
        self.detector_type = detector_type


def _detect_all(text: str, detectors: Sequence[Detector]) -> List[_DetectedMatch]:
    all_matches: List[_DetectedMatch] = []
    for detector in detectors:
        for match in detector.detect(text):
            all_matches.append(_DetectedMatch(match.start, match.end, match.value, detector.type))
    # Sort by start, then by length descending so the longest match wins on overlap.
    all_matches.sort(key=lambda m: (m.start, -m.end))
    resolved: List[_DetectedMatch] = []
    last_end = -1
    for m in all_matches:
        if m.start >= last_end:
            resolved.append(m)
            last_end = m.end
    return resolved


def _is_whitespace(ch: Optional[str]) -> bool:
    # An out-of-range index (None) counts as non-whitespace, matching the TS guard.
    return ch is not None and ch in _WHITESPACE


def _char_at(text: str, idx: int) -> Optional[str]:
    if 0 <= idx < len(text):
        return text[idx]
    return None


def _redact_range(
    text: str,
    matches: Sequence[_DetectedMatch],
    range_start: int,
    range_end: int,
    vault: Vault,
    uuid: UuidFn,
) -> str:
    in_range = [m for m in matches if m.start >= range_start and m.end <= range_end]
    if not in_range:
        return text[range_start:range_end]

    out: List[str] = []
    pos = range_start
    for m in in_range:
        out.append(text[pos:m.start])
        token = "<{0}_{1}>".format(m.detector_type, uuid())
        vault.set(token, m.value)
        out.append(token)
        pos = m.end
    out.append(text[pos:range_end])
    return "".join(out)


def _process_chunk(
    text: str,
    detectors: Sequence[Detector],
    vault: Vault,
    uuid: UuidFn,
    safe_distance: int,
    is_final: bool,
) -> Tuple[str, str]:
    """Return ``(emitted, kept)``."""
    if is_final:
        matches = _detect_all(text, detectors)
        return _redact_range(text, matches, 0, len(text), vault, uuid), ""

    if len(text) <= safe_distance:
        return "", text

    matches = _detect_all(text, detectors)
    cut = len(text) - safe_distance

    # Long-value guard. A value longer than safe_distance that is still
    # streaming in produces no detector match yet. Every long secret/email is
    # whitespace-free, so if `cut` lands inside a run of non-whitespace bytes,
    # pull back to that run's start and re-examine once the rest arrives.
    # Bounded by max_buffered so a long blob can't grow the buffer without limit.
    if 0 < cut < len(text) and not _is_whitespace(_char_at(text, cut - 1)) and not _is_whitespace(_char_at(text, cut)):
        max_buffered = max(safe_distance * 4, 8192)
        run_start = cut
        while run_start > 0 and not _is_whitespace(_char_at(text, run_start - 1)):
            run_start -= 1
        if len(text) - run_start <= max_buffered:
            cut = run_start

    # Straddle guard. Never split a detected match across the cut.
    for m in matches:
        if m.start < cut < m.end:
            cut = min(cut, m.start)

    if cut <= 0:
        return "", text

    emitted = _redact_range(text, matches, 0, cut, vault, uuid)
    return emitted, text[cut:]


class RedactStream:
    """Stateful redactor. Feed it chunks with :meth:`feed`; drain the buffer
    with :meth:`finish`. The TypeScript analog is the ``Transform`` returned by
    ``createRedactStream``."""

    def __init__(
        self,
        detectors: Sequence[Detector],
        vault: Vault,
        safe_distance_bytes: int = _DEFAULT_SAFE_DISTANCE,
        uuid: Optional[UuidFn] = None,
    ) -> None:
        self._detectors = detectors
        self._vault = vault
        self._safe_distance = safe_distance_bytes
        self._uuid: UuidFn = uuid or random_uuid
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        """Push a chunk; return whatever is safe to emit now (possibly empty)."""
        self._buffer += chunk
        emitted, kept = _process_chunk(
            self._buffer, self._detectors, self._vault, self._uuid, self._safe_distance, False
        )
        self._buffer = kept
        return emitted

    def finish(self) -> str:
        """Flush the held-back buffer at end of stream."""
        if not self._buffer:
            return ""
        emitted, _ = _process_chunk(
            self._buffer, self._detectors, self._vault, self._uuid, self._safe_distance, True
        )
        self._buffer = ""
        return emitted


def create_redact_stream(
    detectors: Sequence[Detector],
    vault: Vault,
    safe_distance_bytes: int = _DEFAULT_SAFE_DISTANCE,
    uuid: Optional[UuidFn] = None,
) -> RedactStream:
    return RedactStream(detectors, vault, safe_distance_bytes, uuid)


def redact_iter(
    chunks: Iterable[str],
    detectors: Sequence[Detector],
    vault: Vault,
    safe_distance_bytes: int = _DEFAULT_SAFE_DISTANCE,
    uuid: Optional[UuidFn] = None,
) -> Iterator[str]:
    """Synchronously redact an iterable of text chunks."""
    stream = RedactStream(detectors, vault, safe_distance_bytes, uuid)
    for chunk in chunks:
        out = stream.feed(chunk)
        if out:
            yield out
    out = stream.finish()
    if out:
        yield out


async def aredact_iter(
    chunks: AsyncIterable[str],
    detectors: Sequence[Detector],
    vault: Vault,
    safe_distance_bytes: int = _DEFAULT_SAFE_DISTANCE,
    uuid: Optional[UuidFn] = None,
) -> AsyncIterator[str]:
    """Asynchronously redact an async iterable of text chunks."""
    stream = RedactStream(detectors, vault, safe_distance_bytes, uuid)
    async for chunk in chunks:
        out = stream.feed(chunk)
        if out:
            yield out
    out = stream.finish()
    if out:
        yield out


def redact_sync(
    text: str,
    detectors: Sequence[Detector],
    vault: Vault,
    uuid: Optional[UuidFn] = None,
) -> str:
    """One-shot redaction of a complete text fragment. Identical to the
    ``is_final`` path of the streaming redactor: detect all matches, resolve
    overlaps (longest wins), substitute tokens, write to the vault."""
    uuid_fn: UuidFn = uuid or random_uuid
    matches = _detect_all(text, detectors)
    return _redact_range(text, matches, 0, len(text), vault, uuid_fn)


__all__ = [
    "RedactStream",
    "create_redact_stream",
    "redact_iter",
    "aredact_iter",
    "redact_sync",
]
