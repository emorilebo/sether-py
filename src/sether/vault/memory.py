"""In-memory LRU vault with per-entry TTL.

Faithful port of the TypeScript ``MemoryVault``: 10 000 entries and a 1-hour
TTL by default, least-recently-used eviction, lazy expiry on read.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Optional

_DEFAULT_MAX_ENTRIES = 10_000
_DEFAULT_TTL_MS = 60 * 60 * 1000  # 1 hour


class _Entry:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: str, expires_at: float) -> None:
        self.value = value
        self.expires_at = expires_at  # epoch seconds


def _now() -> float:
    return time.time()


class MemoryVault:
    """LRU + TTL token store.

    :param max_entries: maximum entries before LRU eviction (default 10 000).
    :param ttl_ms: time-to-live in milliseconds per entry (default 1 hour).
    """

    def __init__(self, max_entries: int = _DEFAULT_MAX_ENTRIES, ttl_ms: int = _DEFAULT_TTL_MS) -> None:
        self._max_entries = max_entries
        self._ttl_seconds = ttl_ms / 1000.0
        self._store: "OrderedDict[str, _Entry]" = OrderedDict()

    def set(self, token: str, value: str) -> None:
        # Delete-then-insert so the key moves to the most-recent end.
        if token in self._store:
            del self._store[token]
        self._store[token] = _Entry(value, _now() + self._ttl_seconds)
        while len(self._store) > self._max_entries:
            # popitem(last=False) removes the oldest (LRU) entry.
            self._store.popitem(last=False)

    def get(self, token: str) -> Optional[str]:
        entry = self._store.get(token)
        if entry is None:
            return None
        if entry.expires_at < _now():
            del self._store[token]
            return None
        # Mark as most-recently-used.
        self._store.move_to_end(token)
        return entry.value

    def has(self, token: str) -> bool:
        return self.get(token) is not None

    def delete(self, token: str) -> bool:
        if token in self._store:
            del self._store[token]
            return True
        return False

    def size(self) -> int:
        now = _now()
        expired = [k for k, e in self._store.items() if e.expires_at < now]
        for k in expired:
            del self._store[k]
        return len(self._store)

    def clear(self) -> None:
        self._store.clear()


__all__ = ["MemoryVault"]
