"""Chunk-boundary-safe streaming restoration.

Direct port of ``src/stream/restore.ts``. Swaps every ``<TYPE_uuid>`` token
back to its original value via the vault. The stream holds back a trailing
partial token (a ``<`` with no closing ``>`` yet) until the rest arrives, up to
``max_token_length`` characters.
"""

from __future__ import annotations

import json
import re
from typing import (
    AsyncIterable,
    AsyncIterator,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from ..vault.types import Vault
from ._tokens import TOKEN_RE, replace_tokens

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


def restore_sync(text: str, vault: Vault, *, strict: bool = False) -> str:
    """One-shot restoration of a complete text fragment -- the mirror of
    :func:`redact_sync`. A token with no vault entry (expired, evicted, or from
    a different vault) is left untouched, unless ``strict`` is true, in which
    case :class:`UnresolvedTokenError` is raised instead.

    Never call it on SERIALIZED JSON (e.g. tool-call arguments): originals are
    inserted unescaped, so a ``"`` or ``\\`` in one can add keys or break the
    document. Use :func:`restore_json` / :func:`restore_json_value` for JSON."""
    unresolved: Optional[List[str]] = [] if strict else None
    restored = _restore_text(text, vault, unresolved)
    _raise_if_unresolved(unresolved)
    return restored


JsonValue = Union[None, bool, int, float, str, List["JsonValue"], Dict[str, "JsonValue"]]
"""A value as produced by :func:`json.loads`."""


def restore_json(text: str, vault: Vault, *, strict: bool = False) -> str:
    """Restore tokens inside a SERIALIZED JSON document -- e.g. LLM tool-call
    arguments -- without letting an original value change its structure.

    Parses ``text``, restores every string value individually (object keys are
    left as-is) and re-serializes, so :func:`json.dumps` escapes any ``"`` or
    ``\\`` in an original instead of splicing it into the document.

    Raises :class:`json.JSONDecodeError` if ``text`` is not valid JSON (and
    ``TypeError`` if it is not a string); it never falls back to string
    replacement. The output is compact -- input formatting is not kept. A
    string value that itself holds serialized JSON is restored as plain text:
    parse and restore it separately."""
    restored = restore_json_value(json.loads(text), vault, strict=strict)
    return json.dumps(restored, ensure_ascii=False, separators=(",", ":"))


def restore_json_value(value: JsonValue, vault: Vault, *, strict: bool = False) -> JsonValue:
    """Restore tokens in every string value of an already-parsed JSON value.
    Object keys are not restored. Returns a new value; the input is not
    mutated."""
    unresolved: Optional[List[str]] = [] if strict else None
    restored = _restore_node(value, vault, unresolved)
    _raise_if_unresolved(unresolved)
    return restored


class UnresolvedTokenError(ValueError):
    """Raised by a strict restore when token-shaped text would be left in the
    output: a well-formed token the vault cannot resolve (invented, expired, or
    from another vault), a case-altered copy such as ``<email_...>``, or a token
    in an object key. Carries the tokens only -- never restored originals."""

    def __init__(self, tokens: Sequence[str]) -> None:
        self.tokens: Tuple[str, ...] = tuple(tokens)
        super().__init__(
            f"Sether could not restore {len(self.tokens)} token(s): {', '.join(self.tokens)}"
        )


# Case-insensitive twin of TOKEN_RE: also matches copies like ``<email_...>``,
# which TOKEN_RE (and so restoration) skips. Both match the same ``<``...``>``
# span, so a candidate is restorable exactly when it is canonical and in the
# vault. re.ASCII keeps case folding to A-Z, matching the TypeScript port.
_TOKEN_LIKE_RE = re.compile(TOKEN_RE.pattern, re.IGNORECASE | re.ASCII)


def _restore_text(text: str, vault: Vault, unresolved: Optional[List[str]]) -> str:
    """Without a collector this is plain ``replace_tokens``. With one (strict
    mode) it restores and records in a single pass, so what is reported is
    exactly what is left in the output."""
    if unresolved is None:
        return replace_tokens(text, vault)

    def _sub(m: "re.Match[str]") -> str:
        candidate = m.group(0)
        value: Optional[object] = vault.get(candidate) if TOKEN_RE.fullmatch(candidate) else None
        if isinstance(value, str):
            return value
        unresolved.append(candidate)
        return candidate

    return _TOKEN_LIKE_RE.sub(_sub, text)


def _restore_node(value: JsonValue, vault: Vault, unresolved: Optional[List[str]]) -> JsonValue:
    if isinstance(value, str):
        return _restore_text(value, vault, unresolved)
    if isinstance(value, list):
        return [_restore_node(item, vault, unresolved) for item in value]
    if isinstance(value, dict):
        if unresolved is not None:
            # Keys are never restored, so any token shape in a key is left behind.
            for key in value:
                if isinstance(key, str):
                    unresolved.extend(m.group(0) for m in _TOKEN_LIKE_RE.finditer(key))
        return {key: _restore_node(item, vault, unresolved) for key, item in value.items()}
    return value


def _raise_if_unresolved(unresolved: Optional[List[str]]) -> None:
    if unresolved:
        raise UnresolvedTokenError(tuple(dict.fromkeys(unresolved)))


# --- In-place JSON restore for Sether's own restore paths (SSE payloads,
# response bodies, JSON-mode SDK replies). Not exported from the package root.
#
# Unlike restore_json, which re-serializes the whole parsed value, this only
# re-encodes the string values that actually change and keeps every other
# byte: formatting, key order, escapes and numbers.

RestoreString = Callable[[str], str]
"""Restores one decoded string value, e.g. ``lambda s: restore_sync(s, vault)``."""

# In valid JSON, every match is exactly one string literal (``"`` cannot occur
# outside one), and the unrolled form never backtracks.
_STRING_LITERAL_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"')
_KEY_COLON_RE = re.compile(r"[ \t\n\r]*:")
# A token can only reach a decoded JSON string through a raw ``<`` or the
# ``<`` escape (the only two encodings of ``<``).
_ESCAPED_LT_RE = re.compile(r"\\u003c", re.IGNORECASE)


def _may_hold_token(text: str) -> bool:
    return "<" in text or _ESCAPED_LT_RE.search(text) is not None


def restore_json_document(text: str, restore_string: RestoreString) -> Optional[str]:
    """Restore the string values of the JSON document ``text`` in place: each
    value holding a token is decoded, restored with ``restore_string`` and
    re-encoded by :func:`json.dumps`, so an original can never change the
    document's structure. Object keys are never restored.

    Returns ``None`` when ``text`` is not valid JSON. Text with nothing
    token-shaped in it is returned as-is without being parsed."""
    if not _may_hold_token(text):
        return text
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return None

    def _sub(m: "re.Match[str]") -> str:
        literal = m.group(0)
        if _KEY_COLON_RE.match(text, m.end()) or not _may_hold_token(literal):
            return literal
        value = json.loads(literal)
        restored = restore_string(value)
        return literal if restored == value else json.dumps(restored, ensure_ascii=False)

    return _STRING_LITERAL_RE.sub(_sub, text)


__all__ = [
    "RestoreStream",
    "create_restore_stream",
    "restore_iter",
    "arestore_iter",
    "restore_sync",
    "restore_json",
    "restore_json_value",
    "JsonValue",
    "UnresolvedTokenError",
]
