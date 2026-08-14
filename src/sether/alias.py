"""Alias engine (new in 0.3.0) -- direct port of TS ``src/alias.ts`` (0.7.0).

Redaction hides a value (``<EMAIL_...>``, ``j***@***.com``). ALIASING replaces
it with a realistic decoy -- "Godfrey Lebo" becomes "John Doe", a real phone
number becomes a fictional-but-well-formed one -- so the prompt still reads
naturally to an LLM, leaks nothing, and can be reversed later via the
``AliasVault``.

Decoys use officially-reserved fictional ranges wherever one exists, so a
generated decoy can never collide with a real person's data:

* US phones     -- NNN-555-01XX  (reserved for fiction, NANPA)
* UK phones     -- 07700 900XXX  (Ofcom drama ranges)
* IPv4          -- 192.0.2/24, 198.51.100/24, 203.0.113/24  (RFC 5737)
* IPv6          -- 2001:db8::/32  (RFC 3849)
* SSN           -- 987-65-43XX   (SSA advertising range; deliberately NOT
  re-detectable by sether's own SSN detector -- never-issued beats
  re-detectable)
* Email domains -- example.com / example.org / example.net  (RFC 2606)
* Cards         -- Luhn-valid numbers with a test-style BIN

Types with no reserved range fall back to shape-preserving randomisation:
every digit/letter is replaced with a random one of the same class,
punctuation and known vendor prefixes (sk-proj-, AKIA, ghp_, ...) are kept so
the decoy still *looks* like the real thing.

Randomness is injectable (``rng``: a callable returning floats in [0, 1)) so
tests are deterministic.
"""

from __future__ import annotations

import random as _random
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

try:  # pragma: no cover - import guard mirrors basic.py
    import phonenumbers as _phonenumbers
except ImportError:  # pragma: no cover
    _phonenumbers = None  # type: ignore[assignment]

Rng = Callable[[], float]


def _pick(seq, rng: Rng):
    return seq[int(rng() * len(seq))]


def _rand_int(lo: int, hi: int, rng: Rng) -> int:
    return lo + int(rng() * (hi - lo + 1))


def _rand_digits(n: int, rng: Rng) -> str:
    return "".join(str(_rand_int(0, 9, rng)) for _ in range(n))


# ---------------------------------------------------------------------------
# Name pools -- deliberately diverse. "John"/"Jane" lead so the classic
# John Doe / Jane Doe decoys surface first in suggestions.
# ---------------------------------------------------------------------------

_FIRST_NAMES = (
    "John", "Jane", "Alex", "Maria", "David", "Sarah", "Michael", "Amina",
    "Kwame", "Chen", "Yuki", "Omar", "Priya", "Lucas", "Emma", "Noah",
    "Sofia", "Liam", "Aisha", "Diego", "Ingrid", "Tunde", "Mei", "Ivan",
)

_LAST_NAMES = (
    "Doe", "Smith", "Johnson", "Brown", "Garcia", "Miller", "Davis",
    "Martinez", "Lopez", "Wilson", "Anderson", "Taylor", "Thomas", "Moore",
    "Jackson", "Martin", "Lee", "Walker", "Hall", "Young", "Wright",
    "Adeyemi", "Okoro", "Tanaka",
)

_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")

_STREET_NAMES = (
    "Cedar", "Maple", "Oakwood", "Riverside", "Hillcrest", "Sunset", "Willow",
    "Juniper", "Lakeview", "Meadow", "Rosewood", "Elmwood",
)
_STREET_SUFFIXES = ("Street", "Avenue", "Road", "Lane", "Drive", "Crescent", "Court")
_CITIES = ("Springfield", "Fairview", "Riverton", "Lakeside", "Greenfield", "Brookhaven")

# ---------------------------------------------------------------------------
# Shape-preserving fallback
# ---------------------------------------------------------------------------

# Known vendor prefixes to keep intact so the decoy stays type-detectable.
_KNOWN_PREFIXES: Tuple["re.Pattern[str]", ...] = (
    re.compile(r"^sk-ant-(?:api|admin)\d{2}-"),
    re.compile(r"^sk-(?:proj-|svcacct-|admin-)"),
    re.compile(r"^sk-"),
    re.compile(r"^(?:AKIA|ASIA|AROA|AIDA)"),
    re.compile(r"^gh[pousr]_"),
    re.compile(r"^github_pat_"),
    re.compile(r"^xox[baprs]-"),
    re.compile(r"^(?:sk|rk|pk)_(?:live|test)_"),
    re.compile(r"^whsec_"),
)

_LOWER = "abcdefghijklmnopqrstuvwxyz"
_UPPER = _LOWER.upper()


def shape_alias(value: str, rng: Optional[Rng] = None) -> str:
    """Replace every letter/digit with a random character of the same class.

    Punctuation, whitespace, and any known vendor prefix are preserved -- the
    result has the exact shape of the original but none of its content.
    """
    r = rng or _random.random
    prefix_len = 0
    for pat in _KNOWN_PREFIXES:
        m = pat.match(value)
        if m:
            prefix_len = m.end()
            break
    out = [value[:prefix_len]]
    for ch in value[prefix_len:]:
        if "0" <= ch <= "9":
            out.append(str(_rand_int(0, 9, r)))
        elif "a" <= ch <= "z":
            out.append(_LOWER[_rand_int(0, 25, r)])
        elif "A" <= ch <= "Z":
            out.append(_UPPER[_rand_int(0, 25, r)])
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# Per-type generators
# ---------------------------------------------------------------------------


def _alias_name(value: str, rng: Rng) -> str:
    words = len(value.strip().split())
    first = _pick(_FIRST_NAMES, rng)
    if words <= 1:
        return first
    return f"{first} {_pick(_LAST_NAMES, rng)}"


def _alias_email(rng: Rng) -> str:
    first = _pick(_FIRST_NAMES, rng).lower()
    last = _pick(_LAST_NAMES, rng).lower()
    styles = (
        f"{first}.{last}",
        f"{first}{last}{_rand_int(1, 99, rng)}",
        f"{first}_{last}",
        f"{first}{_rand_int(10, 999, rng)}",
    )
    return f"{_pick(styles, rng)}@{_pick(_EMAIL_DOMAINS, rng)}"


_US_AREAS = ("212", "310", "415", "617", "702", "808", "904")

_NG_NATIONAL_RE = re.compile(r"^0(70|80|81|90|91)")


def _alias_phone(value: str, rng: Rng) -> str:
    intl = value.strip().startswith("+")
    parsed = None
    country = None
    cc = None
    if _phonenumbers is not None:
        try:
            parsed = _phonenumbers.parse(value, None)
            country = _phonenumbers.region_code_for_number(parsed)
            cc = str(parsed.country_code)
        except Exception:  # noqa: BLE001 - unparseable national format
            parsed = None

    digits = re.sub(r"\D", "", value)
    us_national = parsed is None and len(digits) == 10 and digits[0] in "23456789"
    ng_national = parsed is None and len(digits) == 11 and _NG_NATIONAL_RE.match(digits)
    gb_national = (
        parsed is None and not ng_national and len(digits) == 11 and digits.startswith("07")
    )

    if country == "US" or cc == "1" or us_national:
        area = _pick(_US_AREAS, rng)
        tail = f"01{_rand_digits(2, rng)}"
        return f"+1 {area} 555 {tail}" if intl else f"({area}) 555-{tail}"
    if country == "GB" or cc == "44" or gb_national:
        tail = _rand_digits(3, rng)
        return f"+44 7700 900{tail}" if intl else f"07700 900{tail}"
    if country == "NG" or cc == "234" or ng_national:
        tail = _rand_digits(4, rng)
        return f"+234 803 555 {tail}" if intl else f"0803 555 {tail}"
    if parsed is not None and cc is not None:
        national_len = len(str(parsed.national_number))
        return f"+{cc} {_rand_digits(min(national_len, 12), rng)}"
    # National format, unknown region: keep the first two digits (trunk prefix)
    # and all punctuation, randomise the rest. NOTE: not guaranteed fictional.
    kept = 0
    out = []
    for ch in value:
        if "0" <= ch <= "9":
            out.append(ch if kept < 2 else str(_rand_int(0, 9, rng)))
            kept += 1
        else:
            out.append(ch)
    return "".join(out)


def _luhn_check_digit(digits: str) -> str:
    total = 0
    alt = True
    for ch in reversed(digits):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return str((10 - (total % 10)) % 10)


def _alias_card(value: str, rng: Rng) -> str:
    digits = "4" + _rand_digits(14, rng)
    digits += _luhn_check_digit(digits)
    sep = " " if " " in value else "-" if "-" in value else ""
    if not sep:
        return digits
    return sep.join(digits[i:i + 4] for i in range(0, 16, 4))


def _alias_ssn(value: str, rng: Rng) -> str:
    ssn = f"987-65-43{_rand_digits(2, rng)}"
    return ssn if "-" in value else ssn.replace("-", "")


def _alias_ipv4(rng: Rng) -> str:
    block = _pick(("192.0.2", "198.51.100", "203.0.113"), rng)
    return f"{block}.{_rand_int(1, 254, rng)}"


def _alias_ipv6(rng: Rng) -> str:
    def group() -> str:
        return format(_rand_int(0, 0xFFFF, rng), "x")

    return f"2001:db8:{group()}:{group()}:{group()}:{group()}::1"


def _iban_check_digits(country: str, body: str) -> str:
    rearranged = body + country + "00"
    numeric = []
    for ch in rearranged:
        code = ord(ch)
        if 65 <= code <= 90:
            numeric.append(str(code - 55))
        else:
            numeric.append(ch)
    remainder = int("".join(numeric)) % 97
    check = 98 - remainder
    return f"0{check}" if check < 10 else str(check)


def _alias_iban(value: str, rng: Rng) -> str:
    body = f"SETH{_rand_digits(6, rng)}{_rand_digits(8, rng)}"
    iban = f"GB{_iban_check_digits('GB', body)}{body}"
    if not re.search(r"\s", value):
        return iban
    return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))


_MONTH_NAMES = (
    "January", "February", "March", "April", "May", "June", "July",
    "August", "September", "October", "November", "December",
)


def _alias_dob(value: str, rng: Rng) -> str:
    year = _rand_int(1955, 2005, rng)
    month = _rand_int(1, 12, rng)
    day = _rand_int(1, 12, rng)  # <=12 so it is valid as either D/M or M/D
    if re.match(r"^\d{4}-", value):
        return f"{year}-{month:02d}-{day:02d}"
    if re.match(r"^[A-Za-z]", value):
        return f"{_MONTH_NAMES[month - 1]} {day}, {year}"
    if re.search(r"\d\s+[A-Za-z]", value):
        return f"{day} {_MONTH_NAMES[month - 1]} {year}"
    sep = "/" if "/" in value else "." if "." in value else "-"
    return f"{day:02d}{sep}{month:02d}{sep}{year}"


def _alias_address(rng: Rng) -> str:
    return (
        f"{_rand_int(2, 199, rng)} {_pick(_STREET_NAMES, rng)} "
        f"{_pick(_STREET_SUFFIXES, rng)}, {_pick(_CITIES, rng)}"
    )


def _alias_passport(rng: Rng) -> str:
    return _UPPER[_rand_int(0, 25, rng)] + _rand_digits(8, rng)


_B64URL = _UPPER + _LOWER + "0123456789-_"


def _rand_b64(n: int, rng: Rng) -> str:
    return "".join(_B64URL[_rand_int(0, len(_B64URL) - 1, rng)] for _ in range(n))


def _alias_jwt(rng: Rng) -> str:
    # Dummy header {"alg":"HS256","typ":"JWT"} + decoy payload/signature. Both
    # payload and header start "eyJ" so the decoy is still detector-visible.
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        f"eyJzdWIiOiI{_rand_b64(16, rng)}.{_rand_b64(32, rng)}"
    )


def _alias_db_uri(value: str, rng: Optional[Rng]) -> str:
    idx = value.find("://")
    if idx == -1:
        return shape_alias(value, rng)
    return value[: idx + 3] + shape_alias(value[idx + 3:], rng)


def _alias_credential(value: str, rng: Rng) -> str:
    eq = value.find("=")
    colon = value.find(":")
    sep = eq if eq >= 0 else colon
    if sep < 0:
        return shape_alias(value, rng)
    head = value[: sep + 1]
    secret = value[sep + 1:].strip()
    spacer = value[sep + 1: len(value) - len(secret)] if secret else value[sep + 1:]
    decoy = shape_alias(secret, rng) if secret else _rand_b64(24, rng)
    return head + spacer + decoy


def _alias_password(rng: Rng) -> str:
    lower = "abcdefghjkmnpqrstuvwxyz"
    upper = "ABCDEFGHJKMNPQRSTUVWXYZ"
    digit_chars = "23456789"
    out = []
    for _ in range(4):
        out.append(upper[_rand_int(0, len(upper) - 1, rng)])
        out.append(lower[_rand_int(0, len(lower) - 1, rng)])
        out.append(digit_chars[_rand_int(0, len(digit_chars) - 1, rng)])
    return "".join(out)


def alias_value(type_: str, value: str, rng: Optional[Rng] = None) -> str:
    """Generate ONE realistic decoy for a detected value.

    ``type_`` is the detector type ("EMAIL", "NAME", "PHONE", ...). Unknown
    types fall back to shape-preserving randomisation, so custom detectors
    work too.
    """
    r = rng or _random.random
    if type_ == "NAME":
        return _alias_name(value, r)
    if type_ == "EMAIL":
        return _alias_email(r)
    if type_ == "PHONE":
        return _alias_phone(value, r)
    if type_ == "CC":
        return _alias_card(value, r)
    if type_ == "SSN":
        return _alias_ssn(value, r)
    if type_ == "IPV4":
        return _alias_ipv4(r)
    if type_ == "IPV6":
        return _alias_ipv6(r)
    if type_ == "IBAN":
        return _alias_iban(value, r)
    if type_ == "DOB":
        return _alias_dob(value, r)
    if type_ == "ADDRESS":
        return _alias_address(r)
    if type_ == "PASSPORT":
        return _alias_passport(r)
    if type_ == "JWT":
        return _alias_jwt(r)
    if type_ == "DB_URI":
        return _alias_db_uri(value, r)
    if type_ == "CREDENTIAL":
        return _alias_credential(value, r)
    if type_ == "PASSWORD":
        return _alias_password(r)
    # AWS_KEY, OPENAI_KEY, ANTHROPIC_KEY, GITHUB_PAT, SLACK_TOKEN, STRIPE_KEY,
    # API_KEY, HIGH_ENTROPY, NATIONAL_ID, PRIVATE_KEY, custom types --
    # shape-preserving with vendor prefix kept.
    return shape_alias(value, r)


def suggest_aliases(
    type_: str,
    value: str,
    count: int = 3,
    rng: Optional[Rng] = None,
) -> List[str]:
    """Generate ``count`` DISTINCT decoy suggestions (none equal the original).

    This is what a suggestion UI renders as choices::

        suggest_aliases("NAME", "Godfrey Lebo")   # ['John Doe', 'Aisha Tanaka', ...]
    """
    out: List[str] = []
    seen = {value}
    # A few generators have small output spaces; cap attempts defensively.
    for _ in range(count * 20):
        if len(out) >= count:
            break
        candidate = alias_value(type_, value, rng)
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


# ---------------------------------------------------------------------------
# Alias vault
# ---------------------------------------------------------------------------


@dataclass
class AliasEntry:
    """One original <-> alias mapping. Keep originals in ephemeral memory only."""

    original: str
    alias: str
    type: str


class AliasVault:
    """Bidirectional original <-> alias map with stable assignment.

    The same original always gets the same alias within a vault, so a value
    mentioned three times in a prompt reads consistently. ``apply()`` swaps
    originals for aliases in a text; ``restore()`` swaps back. Aliases are
    unique within the vault BY CONSTRUCTION (``set()`` refuses collisions,
    ``alias_for()`` regenerates), which is what makes ``restore()`` a pure
    string substitution with no ambiguity.
    """

    def __init__(self) -> None:
        self._by_original: Dict[str, AliasEntry] = {}
        self._by_alias: Dict[str, AliasEntry] = {}

    def set(self, original: str, alias: str, type_: str) -> bool:
        """Record a chosen alias. Returns False (storing nothing) if the alias
        is already in use for a DIFFERENT original."""
        if original == alias:
            return False
        clash = self._by_alias.get(alias)
        if clash is not None and clash.original != original:
            return False
        existing = self._by_original.get(original)
        if existing is not None:
            self._by_alias.pop(existing.alias, None)
        entry = AliasEntry(original, alias, type_)
        self._by_original[original] = entry
        self._by_alias[alias] = entry
        return True

    def alias_for(self, type_: str, original: str, rng: Optional[Rng] = None) -> str:
        """Return the stable alias for ``original``, generating one if needed.
        Generated aliases are guaranteed unique within this vault."""
        existing = self._by_original.get(original)
        if existing is not None:
            return existing.alias
        for _ in range(40):
            candidate = alias_value(type_, original, rng)
            if candidate != original and candidate not in self._by_alias:
                self.set(original, candidate, type_)
                return candidate
        fallback = shape_alias(original, rng)
        self.set(original, fallback, type_)
        return fallback

    def alias_of(self, original: str) -> Optional[str]:
        entry = self._by_original.get(original)
        return entry.alias if entry else None

    def original_of(self, alias: str) -> Optional[str]:
        entry = self._by_alias.get(alias)
        return entry.original if entry else None

    def entries(self) -> List[AliasEntry]:
        return list(self._by_original.values())

    def __len__(self) -> int:
        return len(self._by_original)

    def clear(self) -> None:
        self._by_original.clear()
        self._by_alias.clear()

    def delete(self, original: str) -> bool:
        entry = self._by_original.pop(original, None)
        if entry is None:
            return False
        self._by_alias.pop(entry.alias, None)
        return True

    def apply(self, text: str) -> str:
        """Replace every known original with its alias (longest-first)."""
        return _substitute(text, [(e.original, e.alias) for e in self.entries()])

    def restore(self, text: str) -> str:
        """Replace every known alias back with its original -- the restore path."""
        return _substitute(text, [(e.alias, e.original) for e in self.entries()])


def _substitute(text: str, pairs: List[Tuple[str, str]]) -> str:
    out = text
    for src, dst in sorted(pairs, key=lambda p: -len(p[0])):
        if src:
            out = out.replace(src, dst)
    return out


__all__ = [
    "AliasEntry",
    "AliasVault",
    "alias_value",
    "suggest_aliases",
    "shape_alias",
]
