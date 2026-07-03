"""The :class:`Sether` facade -- a shared vault wiring redact and restore."""

from __future__ import annotations

from typing import AsyncIterable, AsyncIterator, Iterable, Iterator, Optional, Sequence

from .detectors.basic import basic_detectors
from .detectors.types import Detector
from .stream.redact import (
    RedactStream,
    aredact_iter,
    redact_iter,
    redact_sync,
)
from .stream.restore import (
    RestoreStream,
    arestore_iter,
    restore_iter,
    restore_sync,
)
from .vault.memory import MemoryVault
from .vault.types import Vault

_DEFAULT_SAFE_DISTANCE = 256


class Sether:
    """Streaming PII redaction layer.

    The same instance shares its vault between redaction and restoration, which
    is how the redact->restore round-trip identity is preserved across streaming
    chunks.

    :param detectors: detectors to run. Defaults to ``basic_detectors``.
    :param vault: token vault. Defaults to a fresh :class:`MemoryVault`.
    :param safe_distance_bytes: bytes held back at each chunk tail so a pattern
        crossing a chunk boundary is still detected (default 256).
    """

    def __init__(
        self,
        detectors: Optional[Sequence[Detector]] = None,
        vault: Optional[Vault] = None,
        safe_distance_bytes: int = _DEFAULT_SAFE_DISTANCE,
    ) -> None:
        self._detectors: Sequence[Detector] = tuple(detectors) if detectors is not None else basic_detectors
        self._vault: Vault = vault if vault is not None else MemoryVault()
        self._safe_distance = safe_distance_bytes

    # --- one-shot ---------------------------------------------------------

    def redact_sync(self, text: str) -> str:
        return redact_sync(text, self._detectors, self._vault)

    def restore_sync(self, text: str) -> str:
        return restore_sync(text, self._vault)

    # --- synchronous streaming -------------------------------------------

    def redact_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        return redact_iter(chunks, self._detectors, self._vault, self._safe_distance)

    def restore_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        return restore_iter(chunks, self._vault)

    # --- asynchronous streaming ------------------------------------------

    def aredact_stream(self, chunks: AsyncIterable[str]) -> AsyncIterator[str]:
        return aredact_iter(chunks, self._detectors, self._vault, self._safe_distance)

    def arestore_stream(self, chunks: AsyncIterable[str]) -> AsyncIterator[str]:
        return arestore_iter(chunks, self._vault)

    # --- low-level stateful transforms -----------------------------------

    def new_redact_stream(self) -> RedactStream:
        return RedactStream(self._detectors, self._vault, self._safe_distance)

    def new_restore_stream(self) -> RestoreStream:
        return RestoreStream(self._vault)

    # --- accessors --------------------------------------------------------

    @property
    def vault(self) -> Vault:
        return self._vault

    @property
    def detectors(self) -> Sequence[Detector]:
        return self._detectors

    @property
    def safe_distance_bytes(self) -> int:
        return self._safe_distance


__all__ = ["Sether"]
