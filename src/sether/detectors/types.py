"""Detector contract.

A detector finds sensitive substrings in a piece of text and reports their
absolute offsets. The same shape backs every built-in detector and any custom
one you write -- anything with a ``type`` string and a ``detect(text)`` method
that returns a list of :class:`DetectorMatch` satisfies the protocol.

Example of a custom detector::

    import re
    from sether import DetectorMatch

    class OrderIdDetector:
        type = "ORDER_ID"
        _re = re.compile(r"\\bORD-\\d{8}\\b")

        def detect(self, text):
            return [
                DetectorMatch(m.start(), m.end(), m.group(0))
                for m in self._re.finditer(text)
            ]
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol, runtime_checkable


@dataclass(frozen=True)
class DetectorMatch:
    """A single match. ``start``/``end`` are absolute offsets into the input."""

    start: int
    end: int
    value: str


@runtime_checkable
class Detector(Protocol):
    """Anything with a ``type`` label and a ``detect`` method."""

    type: str

    def detect(self, text: str) -> List[DetectorMatch]:  # pragma: no cover - protocol
        ...


__all__ = ["Detector", "DetectorMatch"]
