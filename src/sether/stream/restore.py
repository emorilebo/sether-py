"""Chunk-boundary-safe streaming restoration.

Direct port of ``src/stream/restore.ts``. Swaps every ``<TYPE_uuid>`` token
back to its original value via the vault. The stream holds back a trailing
partial token (a ``<`` with no closing ``>`` yet) until the rest arrives, up to
``max_token_length`` characters.
"""

from __future__ import annotations

from typing import AsyncIterable, AsyncIterator, Iterable, Iterator, Tuple

from ..vault.types import Vault
from ._tokens import replace_tokens

_DEFAULT_MAX_TOKEN = 128


def _process(text: str, vault: Vault, max_token_length: int, is_final: bool) -> Tuple[str, str]:
    """Return ``(emitted, kept)``."""
    if is_final:
        return replace_tokens(text, vault), ""

    last_open = text.rfind("<")
    if last_open == -1:
        return text, ""

    tail = text[last_open:]
    if ">" in tail:
        return replace_tokens(text, vault), ""

    if len(tail) >= max_token_length:
        return replace_tokens(text, vault), ""

    safe = text[:last_open]
    return replace_tokens(safe, vault), tail


class RestoreStream:
    """Stateful restorer. The TypeScript analog is the ``Transform`` returned by
    ``createRestoreStream``."""

    def __init__(self, vault: Vault, max_token_length: int = _DEFAULT_MAX_TOKEN) -> None:
        self._vault = vault
        self._max_token = max_token_length
        self._buffer = ""

    def feed(self, chunk: str) -> str:
        self._buffer += chunk
        emitted, kept = _process(self._buffer, self._vault, self._max_token, False)
        self._buffer = kept
        return emitted

    def finish(self) -> str:
        if not self._buffer:
            return ""
        emitted, _ = _process(self._buffer, self._vault, self._max_token, True)
        self._buffer = ""
        return emitted


def create_restore_stream(vault: Vault, max_token_length: int = _DEFAULT_MAX_TOKEN) -> RestoreStream:
    return RestoreStream(vault, max_token_length)


def restore_iter(
    chunks: Iterable[str],
    vault: Vault,
    max_token_length: int = _DEFAULT_MAX_TOKEN,
) -> Iterator[str]:
    stream = RestoreStream(vault, max_token_length)
    for chunk in chunks:
        out = stream.feed(chunk)
        if out:
            yield out
    out = stream.finish()
    if out:
        yield out


async def arestore_iter(
    chunks: AsyncIterable[str],
    vault: Vault,
    max_token_length: int = _DEFAULT_MAX_TOKEN,
) -> AsyncIterator[str]:
    stream = RestoreStream(vault, max_token_length)
    async for chunk in chunks:
        out = stream.feed(chunk)
        if out:
            yield out
    out = stream.finish()
    if out:
        yield out


def restore_sync(text: str, vault: Vault) -> str:
    """One-shot restoration of a complete text fragment -- the mirror of
    :func:`redact_sync`. A token with no vault entry (expired, evicted, or from
    a different vault) is left untouched."""
    return replace_tokens(text, vault)


__all__ = [
    "RestoreStream",
    "create_restore_stream",
    "restore_iter",
    "arestore_iter",
    "restore_sync",
]
