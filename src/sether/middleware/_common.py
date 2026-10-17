"""Shared middleware helpers."""

from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..stream._tokens import replace_tokens
from ..stream.restore import restore_json_document
from ..stream.sse import restore_sse_text
from ..vault.types import Vault


def is_textual_content_type(content_type: Optional[str]) -> bool:
    """Mirror of the TS check: redact/restore only text, JSON, and SSE bodies."""
    ct = content_type or ""
    return ct.startswith("text/") or "json" in ct or "event-stream" in ct


def restore_in_text(text: str, vault: Vault) -> str:
    return replace_tokens(text, vault)


def restore_json_text(text: str, vault: Vault) -> str:
    """Serialized JSON: restored value by value, or left tokenized if it is
    not valid JSON (never restored as text)."""
    restored = restore_json_document(text, lambda value: replace_tokens(value, vault))
    return text if restored is None else restored


def restore_body(body: str, content_type: Optional[str], vault: Vault) -> str:
    """Restore a complete textual body without splicing an original unescaped
    into JSON: an event-stream body per ``data:`` payload, a body that parses as
    JSON value by value, a JSON-typed body that doesn't (NDJSON / JSON Lines)
    line by line, and any other text as text. A line of a JSON-typed body that
    is not valid JSON stays tokenized rather than being restored as text, so an
    original cannot complete a truncated document into a different one."""
    ct = content_type or ""

    def restore_string(text: str) -> str:
        return replace_tokens(text, vault)

    if "event-stream" in ct:
        return restore_sse_text(body, restore_string)
    document = restore_json_document(body, restore_string)
    if document is not None:
        return document
    if "json" not in ct:
        return restore_string(body)
    return "\n".join(restore_json_text(line, vault) for line in body.split("\n"))


def get_field(obj: object, name: str) -> object:
    """Read ``name`` from a dict key or an object attribute (duck-typed)."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def set_field(obj: object, name: str, value: object) -> None:
    """Write ``name`` as a dict key or an object attribute (duck-typed)."""
    if isinstance(obj, dict):
        obj[name] = value  # type: ignore[index]
    else:
        setattr(obj, name, value)


def asgi_header(headers: Iterable[Tuple[bytes, bytes]], name: str) -> str:
    """Look up an ASGI header (case-insensitive). Returns '' if absent."""
    target = name.lower().encode("latin-1")
    for key, value in headers:
        if key.lower() == target:
            return value.decode("latin-1")
    return ""


def strip_asgi_headers(
    headers: Iterable[Tuple[bytes, bytes]],
    drop: Iterable[str],
) -> List[Tuple[bytes, bytes]]:
    drop_set = {d.lower().encode("latin-1") for d in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_set]


__all__ = [
    "is_textual_content_type",
    "restore_in_text",
    "restore_json_text",
    "restore_body",
    "get_field",
    "set_field",
    "asgi_header",
    "strip_asgi_headers",
]
