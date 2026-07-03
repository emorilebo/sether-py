"""Basic detector pack: email, credit card, SSN, IPv4, IPv6, IBAN, phone.

Direct port of ``src/detectors/basic.ts``. Every regex is a single bounded
character class -- no nested quantifiers, no catastrophic-backtracking surface.
Shape-only matches (CC, SSN, IBAN, IPv6) are confirmed in plain code afterward
(Luhn, SSA prefix rules, mod-97, structural IPv6 validation).
"""

from __future__ import annotations

import re
from typing import List, Optional

from .types import DetectorMatch

# ---------------------------------------------------------------------------
# In-tree IPv6 validator -- equivalent to Node's net.isIPv6 for the
# hex+colon-only candidates produced by the candidate regex below. The
# IPv4-in-IPv6 mixed form (which contains '.') is intentionally not handled.
# ---------------------------------------------------------------------------


def is_ipv6_address(value: str) -> bool:
    length = len(value)
    if length == 0 or length > 45:
        return False

    # Only hex digits and ':' permitted.
    for ch in value:
        c = ord(ch)
        is_hex = (48 <= c <= 57) or (65 <= c <= 70) or (97 <= c <= 102)
        if not is_hex and c != 58:  # ':'
            return False

    # At most one '::' allowed.
    first_double = value.find("::")
    if first_double != -1 and value.find("::", first_double + 1) != -1:
        return False

    if first_double != -1:
        left = value[:first_double]
        right = value[first_double + 2:]
        left_groups = [] if left == "" else left.split(":")
        right_groups = [] if right == "" else right.split(":")
        for g in left_groups:
            if len(g) < 1 or len(g) > 4:
                return False
        for g in right_groups:
            if len(g) < 1 or len(g) > 4:
                return False
        return len(left_groups) + len(right_groups) < 8

    groups = value.split(":")
    if len(groups) != 8:
        return False
    for g in groups:
        if len(g) < 1 or len(g) > 4:
            return False
    return True


def _match_all(text: str, pattern: "re.Pattern[str]") -> List[DetectorMatch]:
    return [DetectorMatch(m.start(), m.end(), m.group(0)) for m in pattern.finditer(text)]


class _RegexDetector:
    """A detector whose every match is reported verbatim."""

    def __init__(self, type_: str, pattern: "re.Pattern[str]") -> None:
        self.type = type_
        self._re = pattern

    def detect(self, text: str) -> List[DetectorMatch]:
        return _match_all(text, self._re)


# --- EMAIL -----------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.ASCII)
email_detector = _RegexDetector("EMAIL", _EMAIL_RE)


# --- CREDIT CARD -----------------------------------------------------------

# First char a digit, then 12-22 of digit/space/dash. Validated by Luhn.
_CC_RE = re.compile(r"\b\d[\d -]{12,22}", re.ASCII)
_CC_TRAILING_RE = re.compile(r"[\s-]+$")
_NON_DIGIT_RE = re.compile(r"\D")


def _luhn(digits: str) -> bool:
    total = 0
    alt = False
    for i in range(len(digits) - 1, -1, -1):
        c = ord(digits[i]) - 48
        if c < 0 or c > 9:
            return False
        n = c
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


class _CreditCardDetector:
    type = "CC"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        for m in _CC_RE.finditer(text):
            trimmed = _CC_TRAILING_RE.sub("", m.group(0))
            digits = _NON_DIGIT_RE.sub("", trimmed)
            if len(digits) < 13 or len(digits) > 19:
                continue
            if not _luhn(digits):
                continue
            matches.append(DetectorMatch(m.start(), m.start() + len(trimmed), trimmed))
        return matches


credit_card_detector = _CreditCardDetector()


# --- SSN --------------------------------------------------------------------

_SSN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b", re.ASCII)
_SSN_INVALID_AREAS = frozenset({"000", "666"})


class _SsnDetector:
    type = "SSN"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        for m in _SSN_RE.finditer(text):
            area, group, serial = m.group(1), m.group(2), m.group(3)
            if area in _SSN_INVALID_AREAS:
                continue
            if int(area) >= 900:
                continue
            if group == "00":
                continue
            if serial == "0000":
                continue
            matches.append(DetectorMatch(m.start(), m.end(), m.group(0)))
        return matches


ssn_detector = _SsnDetector()


# --- IPV4 -------------------------------------------------------------------

_IPV4_OCTET = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(
    r"\b" + _IPV4_OCTET + r"\." + _IPV4_OCTET + r"\." + _IPV4_OCTET + r"\." + _IPV4_OCTET + r"\b",
    re.ASCII,
)
ipv4_detector = _RegexDetector("IPV4", _IPV4_RE)


# --- IPV6 -------------------------------------------------------------------

_IPV6_CANDIDATE = re.compile(r"\b[0-9A-Fa-f:]{4,39}\b", re.ASCII)


class _Ipv6Detector:
    type = "IPV6"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        for m in _IPV6_CANDIDATE.finditer(text):
            candidate = m.group(0)
            if ":" not in candidate:
                continue
            if not is_ipv6_address(candidate):
                continue
            matches.append(DetectorMatch(m.start(), m.start() + len(candidate), candidate))
        return matches


ipv6_detector = _Ipv6Detector()


# --- IBAN -------------------------------------------------------------------

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{11,40}", re.ASCII)
_IBAN_TRAILING_RE = re.compile(r"\s+$")
_WS_RE = re.compile(r"\s")


def _iban_mod97(iban: str) -> bool:
    rearranged = iban[4:] + iban[:4]
    numeric_parts: List[str] = []
    for ch in rearranged:
        code = ord(ch)
        if 65 <= code <= 90:  # A-Z -> 10..35
            numeric_parts.append(str(code - 55))
        elif 48 <= code <= 57:
            numeric_parts.append(ch)
        else:
            return False
    numeric = "".join(numeric_parts)
    remainder = 0
    for i in range(0, len(numeric), 7):
        chunk = str(remainder) + numeric[i:i + 7]
        remainder = int(chunk) % 97
    return remainder == 1


class _IbanDetector:
    type = "IBAN"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        for m in _IBAN_RE.finditer(text):
            trimmed = _IBAN_TRAILING_RE.sub("", m.group(0))
            cleaned = _WS_RE.sub("", trimmed)
            if len(cleaned) < 15 or len(cleaned) > 34:
                continue
            if not _iban_mod97(cleaned):
                continue
            matches.append(DetectorMatch(m.start(), m.start() + len(trimmed), trimmed))
        return matches


iban_detector = _IbanDetector()


# --- PHONE ------------------------------------------------------------------

_phonenumbers: Optional[object]
try:  # pragma: no cover - import guard
    import phonenumbers as _phonenumbers  # type: ignore
except ImportError:  # pragma: no cover - import guard
    _phonenumbers = None


class _PhoneDetector:
    type = "PHONE"

    def __init__(self, default_country: Optional[str] = None) -> None:
        self._default_country = default_country

    def detect(self, text: str) -> List[DetectorMatch]:
        if _phonenumbers is None:  # pragma: no cover - import guard
            raise ImportError(
                "sether phone detection requires the 'phonenumbers' package. "
                "Install it with: pip install phonenumbers"
            )
        matches: List[DetectorMatch] = []
        # region=None matches only international-format numbers (a leading '+') --
        # the conservative analog of libphonenumber-js's findPhoneNumbersInText
        # with no default country. A default_country (e.g. 'US', 'NG', 'GB') also
        # catches NATIONAL-format numbers -- "(415) 555-2671", "0803 123 4567" --
        # for that region.
        for found in _phonenumbers.PhoneNumberMatcher(text, self._default_country):  # type: ignore[attr-defined]
            start = found.start
            end = start + len(found.raw_string)
            matches.append(DetectorMatch(start, end, text[start:end]))
        return matches


def create_phone_detector(default_country: Optional[str] = None) -> _PhoneDetector:
    """Build a PHONE detector.

    ``create_phone_detector()`` with no argument behaves exactly like the default
    ``phone_detector`` export (international-format numbers only). Pass
    ``default_country`` (ISO 3166-1 alpha-2, e.g. 'US', 'NG', 'GB') when your
    traffic contains national-format numbers for a known region::

        detectors = [
            *(d for d in basic_detectors if d.type != "PHONE"),
            create_phone_detector(default_country="US"),
        ]
    """
    return _PhoneDetector(default_country)


phone_detector = create_phone_detector()


basic_detectors = (
    email_detector,
    credit_card_detector,
    ssn_detector,
    ipv4_detector,
    ipv6_detector,
    iban_detector,
    phone_detector,
)


__all__ = [
    "is_ipv6_address",
    "email_detector",
    "credit_card_detector",
    "ssn_detector",
    "ipv4_detector",
    "ipv6_detector",
    "iban_detector",
    "phone_detector",
    "create_phone_detector",
    "basic_detectors",
]
