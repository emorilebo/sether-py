"""Identity detector pack (opt-in -- NOT part of ``basic_detectors``).

Direct port of ``src/detectors/identity.ts``. Names, dates of birth, passport
numbers, and postal addresses have no self-validating shape, so this pack uses
LABEL-ANCHORED detection: a value is redacted only when it appears next to the
label that introduces it ("Name:", "DOB:", "Passport No:", "Address:"), or, for
the few distinctive standalone shapes (a street line with a house number, a UK
postcode), a structural pattern strong enough to keep false positives low.

Multilingual: each class is anchored on labels in many languages. Latin-script
labels use ASCII word boundaries; non-Latin labels (CJK, Cyrillic, Arabic) are
anchored on a trailing colon instead. Value capture is Unicode-aware throughout
-- "Nom: Jose Muller", the Japanese / Cyrillic forms, and accented names all
redact.

The Python port replaces the TypeScript ``\\p{L}`` / ``\\p{M}`` Unicode property
escapes (unsupported by the stdlib ``re`` module) with ``unicodedata`` major
category checks, which are exactly equivalent.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date
from typing import Callable, List, Optional, Sequence

from .types import DetectorMatch

_MAX_VALUE_LEN = 60
_MAX_ADDRESS_LEN = 120


def _is_cased_letter(ch: str) -> bool:
    """True for a letter with distinct upper/lower case (Latin, Greek, Cyrillic...)."""
    return ch.lower() != ch.upper()


def _is_letter(ch: str) -> bool:
    """Equivalent to ``/[\\p{L}\\p{M}]/u`` -- any letter or combining mark."""
    return unicodedata.category(ch)[0] in ("L", "M")


def _each_label_match(
    text: str,
    regexes: Sequence["re.Pattern[str]"],
    cb: Callable[[int], None],
) -> None:
    """Call ``cb`` with the offset immediately after every label match (where the
    value begins)."""
    for regex in regexes:
        for m in regex.finditer(text):
            cb(m.end())


# ---------------------------------------------------------------------------
# NAME
# ---------------------------------------------------------------------------

_NAME_LABEL_RE = re.compile(
    r"\b(?:full[\s_-]?name|first[\s_-]?name|last[\s_-]?name|name|nom|nombre|nome|naam|"
    r"navn|patient|customer|client|contact|cardholder|account[\s_-]?holder|beneficiary|"
    r"attn|attention|dear|mr|mrs|ms|mx|dr|prof)\b[\s:.=_-]{0,3}",
    re.IGNORECASE,
)

# Non-Latin labels -- anchored on a trailing colon (ASCII or fullwidth).
_NAME_LABEL_INTL_RE = re.compile(
    r"(?:名前|氏名|姓名|이름|성명|имя|"
    r"الاسم)\s*[:：]\s*",
    re.IGNORECASE,
)

_NAME_LABELS = (_NAME_LABEL_RE, _NAME_LABEL_INTL_RE)

_NAME_COMMON_WORDS = frozenset({
    "the", "and", "is", "of", "a", "an", "our", "your", "my", "their", "unknown",
    "none", "null", "na", "anonymous", "redacted", "test", "sir", "madam",
    "madame", "team", "service", "support", "customer", "client", "user",
    "admin", "everyone", "all", "hello", "hi", "dear", "valued", "account",
    "holder", "name", "please", "thanks", "regards", "mr", "mrs", "ms", "dr",
    "prof", "staff", "department", "desk", "president",
})

_TRAILING_WS_RE = re.compile(r"\s+$")
_SPLIT_WS_RE = re.compile(r"\s+")


def _capture_name(text: str, pos: int) -> Optional[str]:
    """Capture a person name starting at ``pos``: up to 4 capitalised words for
    cased scripts, or a single run of letters for uncased scripts."""
    n = len(text)
    i = pos
    while i < n and text[i].isspace():
        i += 1
    start = i
    words = 0
    while i < n and words < 4 and i - start < _MAX_VALUE_LEN:
        first = text[i]
        if not _is_letter(first):
            break
        # For cased scripts a name word must start uppercase.
        if _is_cased_letter(first) and first != first.upper():
            break
        j = i + 1
        while j < n:
            c = text[j]
            if _is_letter(c):
                j += 1
                continue
            if (c == "'" or c == "’" or c == "-") and j + 1 < n and _is_letter(text[j + 1]):
                j += 1
                continue
            break
        words += 1
        i = j
        # Allow one or more spaces/tabs (not newlines) before the next word.
        k = i
        while k < n and (text[k] == " " or text[k] == "\t"):
            k += 1
        if k > i and k < n and _is_letter(text[k]):
            i = k
        else:
            break
    value = _TRAILING_WS_RE.sub("", text[start:i])
    if len(value) < 2 or words == 0:
        return None
    parts = _SPLIT_WS_RE.split(value.lower())
    if all(w in _NAME_COMMON_WORDS for w in parts):
        return None
    return value


class _NameDetector:
    type = "NAME"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []

        def cb(value_start: int) -> None:
            value = _capture_name(text, value_start)
            if not value:
                return
            start = text.find(value, value_start)
            if start == -1:
                return
            matches.append(DetectorMatch(start, start + len(value), value))

        _each_label_match(text, _NAME_LABELS, cb)
        return matches


name_detector = _NameDetector()


# ---------------------------------------------------------------------------
# DOB
# ---------------------------------------------------------------------------

_DOB_LABEL_RE = re.compile(
    r"\b(?:date\s+of\s+birth|date\s+de\s+naissance|fecha\s+de\s+nacimiento|"
    r"data\s+de\s+nascimento|geburtsdatum|geboortedatum|d\.?o\.?b\.?|birth\s?date|born)"
    r"\b[\s:=-]{0,3}",
    re.IGNORECASE,
)

_DOB_LABEL_INTL_RE = re.compile(
    r"(?:生年月日|出生日期|出生日|"
    r"생년월일|дата\s+рождения)"
    r"\s*[:：]\s*",
    re.IGNORECASE,
)

_DOB_LABELS = (_DOB_LABEL_RE, _DOB_LABEL_INTL_RE)

_MONTHS = (
    "jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|"
    "aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
)
_MONTH_INDEX = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Trailing (?!\d) stops a valid date being carved out of a longer number.
_DATE_ISO_RE = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?!\d)", re.ASCII)
_DATE_NUM_RE = re.compile(r"^(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})(?!\d)", re.ASCII)
_DATE_DMY_RE = re.compile(r"^(\d{1,2})\s+(" + _MONTHS + r")\.?\s*,?\s*(\d{4})(?!\d)", re.IGNORECASE | re.ASCII)
_DATE_MDY_RE = re.compile(r"^(" + _MONTHS + r")\.?\s+(\d{1,2})\s*,?\s*(\d{4})(?!\d)", re.IGNORECASE | re.ASCII)


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)) else 28
    if month in (4, 6, 9, 11):
        return 30
    return 31


def _is_plausible_birth_date(year: int, month: int, day: int) -> bool:
    current_year = date.today().year
    if year < 1900 or year > current_year:
        return False
    if month < 1 or month > 12:
        return False
    if day < 1 or day > _days_in_month(year, month):
        return False
    return True


def _match_date_at(text: str, pos: int) -> Optional[str]:
    sliced = text[pos:pos + 32]

    iso = _DATE_ISO_RE.match(sliced)
    if iso and _is_plausible_birth_date(int(iso.group(1)), int(iso.group(2)), int(iso.group(3))):
        return iso.group(0)

    num = _DATE_NUM_RE.match(sliced)
    if num:
        a = int(num.group(1))
        b = int(num.group(2))
        year = int(num.group(3))
        if year < 100:
            year += 2000 if year < 30 else 1900
        if _is_plausible_birth_date(year, b, a) or _is_plausible_birth_date(year, a, b):
            return num.group(0)

    dmy = _DATE_DMY_RE.match(sliced)
    if dmy:
        month = _MONTH_INDEX.get(dmy.group(2)[:3].lower())
        if month and _is_plausible_birth_date(int(dmy.group(3)), month, int(dmy.group(1))):
            return dmy.group(0)

    mdy = _DATE_MDY_RE.match(sliced)
    if mdy:
        month = _MONTH_INDEX.get(mdy.group(1)[:3].lower())
        if month and _is_plausible_birth_date(int(mdy.group(3)), month, int(mdy.group(2))):
            return mdy.group(0)

    return None


class _DobDetector:
    type = "DOB"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        n = len(text)

        def cb(vs: int) -> None:
            value_start = vs
            while value_start < n and text[value_start].isspace():
                value_start += 1
            date_str = _match_date_at(text, value_start)
            if not date_str:
                return
            matches.append(DetectorMatch(value_start, value_start + len(date_str), date_str))

        _each_label_match(text, _DOB_LABELS, cb)
        return matches


dob_detector = _DobDetector()


# ---------------------------------------------------------------------------
# PASSPORT
# ---------------------------------------------------------------------------

_PASSPORT_LABEL_RE = re.compile(
    r"\b(?:passport|passeport|pasaporte|reisepass|passaporto|paspoort|passaporte)"
    r"(?:\s(?:no|number|num|#))?\b[\s:.#=-]{0,3}",
    re.IGNORECASE,
)

_PASSPORT_LABEL_INTL_RE = re.compile(
    r"(?:パスポート|护照|여권|паспорт)"
    r"\s*[:：#]?\s*",
    re.IGNORECASE,
)

_PASSPORT_LABELS = (_PASSPORT_LABEL_RE, _PASSPORT_LABEL_INTL_RE)

_PASSPORT_VALUE_RE = re.compile(r"^[A-Za-z0-9]{6,9}\b", re.ASCII)
_HAS_DIGIT_RE = re.compile(r"\d", re.ASCII)


class _PassportDetector:
    type = "PASSPORT"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        n = len(text)

        def cb(vs: int) -> None:
            value_start = vs
            while value_start < n and text[value_start].isspace():
                value_start += 1
            m = _PASSPORT_VALUE_RE.match(text[value_start:value_start + 12])
            if not m:
                return
            value = m.group(0)
            # Require at least one digit -- pure-letter words are not passport numbers.
            if not _HAS_DIGIT_RE.search(value):
                return
            matches.append(DetectorMatch(value_start, value_start + len(value), value))

        _each_label_match(text, _PASSPORT_LABELS, cb)
        return matches


passport_detector = _PassportDetector()


# ---------------------------------------------------------------------------
# ADDRESS
# ---------------------------------------------------------------------------

_ADDRESS_LABEL_RE = re.compile(
    r"\b(?:(?:shipping|billing|mailing|home|residential)\s)?"
    r"(?:address|adresse|adres|direccion|indirizzo|endereco)(?:es)?\b[\s:.=-]{0,3}",
    re.IGNORECASE,
)

_ADDRESS_LABEL_INTL_RE = re.compile(
    r"(?:住所|地址|주소|адрес|"
    r"dirección|endereço)\s*[:：]\s*",
    re.IGNORECASE,
)

_ADDRESS_LABELS = (_ADDRESS_LABEL_RE, _ADDRESS_LABEL_INTL_RE)

_STREET_SUFFIX_RE = re.compile(
    r"\b(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|"
    r"way|place|pl|terrace|ter|square|sq|highway|hwy|parkway|pkwy)\b\.?",
    re.IGNORECASE,
)

# A street line ending at the suffix: house number + up to ~40 chars of words.
_STREET_HEAD_RE = re.compile(r"\d{1,6}\s+[A-Za-z0-9.' -]{0,40}$", re.ASCII)

_UK_POSTCODE_RE = re.compile(r"\b[A-Za-z]{1,2}\d[A-Za-z\d]?\s*\d[A-Za-z]{2}\b", re.ASCII)

_HAS_DIGIT_OR_COMMA_RE = re.compile(r"[\d,]", re.ASCII)


class _AddressDetector:
    type = "ADDRESS"

    def detect(self, text: str) -> List[DetectorMatch]:
        matches: List[DetectorMatch] = []
        n = len(text)

        # (a) Labelled address line -- capture to end of line, bounded.
        def cb(vs: int) -> None:
            start = vs
            while start < n and (text[start] == " " or text[start] == "\t"):
                start += 1
            end = start
            while end < n and text[end] != "\n" and end - start < _MAX_ADDRESS_LEN:
                end += 1
            value = _TRAILING_WS_RE.sub("", text[start:end])
            if len(value) >= 5 and _HAS_DIGIT_OR_COMMA_RE.search(value):
                matches.append(DetectorMatch(start, start + len(value), value))

        _each_label_match(text, _ADDRESS_LABELS, cb)

        # (b) Standalone street line: street suffix preceded by a house number.
        for s in _STREET_SUFFIX_RE.finditer(text):
            suffix_end = s.end()
            window_start = max(0, s.start() - 50)
            head = _STREET_HEAD_RE.search(text[window_start:s.start()])
            if not head:
                continue
            start = window_start + head.start()
            matches.append(DetectorMatch(start, suffix_end, text[start:suffix_end]))

        # (c) UK postcode -- distinctive enough to stand alone.
        for p in _UK_POSTCODE_RE.finditer(text):
            matches.append(DetectorMatch(p.start(), p.end(), p.group(0)))

        return matches


address_detector = _AddressDetector()


identity_detectors = (
    name_detector,
    dob_detector,
    passport_detector,
    address_detector,
)


__all__ = [
    "name_detector",
    "dob_detector",
    "passport_detector",
    "address_detector",
    "identity_detectors",
]
