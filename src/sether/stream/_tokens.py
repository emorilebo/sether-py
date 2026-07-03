"""Shared token format -- one source of truth for redact and restore.

A token looks like ``<TYPE_uuid>`` where TYPE is the detector type and uuid is a
v4 UUID (hex with dashes). The restore pattern is deliberately a touch broader
than the emit format (it also accepts a leading underscore in the type) so it
restores any well-formed token regardless of which code path produced it.
"""

from __future__ import annotations

import re
import uuid as _uuid
from typing import Callable, Optional

from ..vault.types import Vault

# Matches every token the redact path emits.
TOKEN_RE = re.compile(r"<([A-Z_][A-Z0-9_]*)_([0-9a-fA-F-]{8,})>")


def random_uuid() -> str:
    return str(_uuid.uuid4())


def replace_tokens(text: str, vault: Vault) -> str:
    """Swap every token back to its original value via the vault. A token with
    no (string) vault entry is left untouched."""

    def _sub(m: "re.Match[str]") -> str:
        value: Optional[object] = vault.get(m.group(0))
        # Substitute only when the vault returns a string. A non-string return
        # (e.g. a mistakenly async get() yielding a coroutine) leaves the token
        # in place rather than inserting a repr.
        return value if isinstance(value, str) else m.group(0)

    return TOKEN_RE.sub(_sub, text)


UuidFn = Callable[[], str]

__all__ = ["TOKEN_RE", "random_uuid", "replace_tokens", "UuidFn"]
