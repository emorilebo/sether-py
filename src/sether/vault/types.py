"""Token vault contract.

Tokens map back to their original values through a vault. The interface is
**synchronous** by design: ``restore`` substitutes tokens as bytes flow through
a stream and cannot ``await`` a lookup per token. A store reached over async
I/O (Redis, Postgres) therefore can't be dropped straight into the restore
path -- front it with a synchronous in-process cache you hydrate before the
restore pass, or keep the vault in-process.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class Vault(Protocol):
    """Synchronous token store. Implement this to change eviction, encrypt at
    rest, or namespace tokens per tenant."""

    def set(self, token: str, value: str) -> None: ...

    def get(self, token: str) -> Optional[str]: ...

    def has(self, token: str) -> bool: ...

    def delete(self, token: str) -> bool: ...

    def size(self) -> int: ...

    def clear(self) -> None: ...


__all__ = ["Vault"]
