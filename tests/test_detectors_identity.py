from __future__ import annotations

from sether.detectors.identity import (
    address_detector,
    dob_detector,
    name_detector,
    passport_detector,
)


def _values(detector, text):
    return [m.value for m in detector.detect(text)]


def test_name_labelled_latin():
    assert _values(name_detector, "Name: Amara Okafor") == ["Amara Okafor"]


def test_name_salutation():
    assert "John Smith" in _values(name_detector, "Dear John Smith,")


def test_name_rejects_common_words():
    # "Dear Customer" -> every captured word is a common non-name word.
    assert _values(name_detector, "Dear Customer,") == []


def test_name_multilingual_cjk():
    # Japanese label + uncased-script name. The capture (faithful to the TS
    # algorithm) runs to the newline, which it correctly treats as a boundary.
    out = _values(name_detector, "名前：田中太郎\n")
    assert out == ["田中太郎"]


def test_name_multilingual_cyrillic():
    out = _values(name_detector, "Имя: Иван Петров")
    assert "Иван Петров" in out


def test_name_not_in_filename():
    # \b keeps "name" from matching inside "filename".
    assert _values(name_detector, "the filename Foo Bar is set") == []


def test_dob_iso():
    assert _values(dob_detector, "DOB: 1990-04-12") == ["1990-04-12"]


def test_dob_written():
    assert _values(dob_detector, "Date of birth: 12 January 1985") == ["12 January 1985"]


def test_dob_rejects_implausible():
    # Year out of plausible birth range.
    assert _values(dob_detector, "DOB: 1850-01-01") == []


def test_dob_rejects_invalid_calendar():
    assert _values(dob_detector, "DOB: 1990-02-31") == []


def test_passport_labelled():
    out = _values(passport_detector, "Passport No: X1234567")
    assert out == ["X1234567"]


def test_passport_requires_digit():
    # Pure-letter word after the label is not a passport number.
    assert _values(passport_detector, "Passport: ABCDEFG") == []


def test_address_labelled():
    out = _values(address_detector, "Address: 221B Baker Street, London")
    assert out and "221B Baker Street" in out[0]


def test_address_standalone_street():
    out = _values(address_detector, "Ship to 350 Fifth Avenue please")
    assert any("350 Fifth Avenue" in v for v in out)


def test_address_uk_postcode():
    assert "SW1A 1AA" in _values(address_detector, "postcode SW1A 1AA here")
