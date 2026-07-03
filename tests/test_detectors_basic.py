from __future__ import annotations

import pytest

from sether.detectors.basic import (
    credit_card_detector,
    email_detector,
    iban_detector,
    ipv4_detector,
    ipv6_detector,
    is_ipv6_address,
    ssn_detector,
)


def _values(detector, text):
    return [m.value for m in detector.detect(text)]


def test_email_basic():
    assert _values(email_detector, "ping alice@example.com now") == ["alice@example.com"]


def test_email_multiple_and_embedded():
    out = _values(email_detector, "to a@b.io, cc c.d+x@sub.example.co.uk!")
    assert out == ["a@b.io", "c.d+x@sub.example.co.uk"]


def test_ascii_digits_only():
    # JS \d is ASCII-only; the port matches that. Arabic-Indic digits in an
    # SSN-shaped string must NOT be treated as a digit-bearing SSN.
    assert _values(ssn_detector, "ssn ١٢٣-٤٥-٦٧٨٩ x") == []


def test_credit_card_luhn_pass():
    assert _values(credit_card_detector, "card 4242 4242 4242 4242 ok") == ["4242 4242 4242 4242"]


def test_credit_card_luhn_fail():
    assert _values(credit_card_detector, "num 4242 4242 4242 4243") == []


def test_credit_card_trims_trailing_separators():
    out = credit_card_detector.detect("4242424242424242 - done")
    assert out and out[0].value == "4242424242424242"


def test_ssn_valid():
    assert _values(ssn_detector, "ssn 123-45-6789 end") == ["123-45-6789"]


@pytest.mark.parametrize("bad", ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-6789", "123-45-0000"])
def test_ssn_invalid_prefixes(bad):
    assert _values(ssn_detector, f"ssn {bad} end") == []


def test_ipv4_valid_and_bounds():
    assert _values(ipv4_detector, "host 192.168.0.1 up") == ["192.168.0.1"]
    assert _values(ipv4_detector, "not 256.1.1.1 here") == []


def test_ipv6_valid_uncompressed():
    v = "2001:0db8:0000:0000:0000:ff00:0042:8329"
    assert _values(ipv6_detector, f"addr {v} ok") == [v]


def test_ipv6_compressed():
    v = "2001:db8::ff00:42:8329"
    assert _values(ipv6_detector, f"addr {v} ok") == [v]


def test_ipv6_loopback_known_limitation():
    # Documented: '::1' is intentionally not matched (candidate requires 4+ chars).
    assert _values(ipv6_detector, "addr ::1 ok") == []


def test_is_ipv6_address_helper():
    assert is_ipv6_address("2001:db8::1") is True
    assert is_ipv6_address("nothex::1") is False
    assert is_ipv6_address("2001:db8::ff00::1") is False  # two '::'


def test_iban_valid_mod97():
    assert _values(iban_detector, "iban GB82 WEST 1234 5698 7654 32 end") == ["GB82 WEST 1234 5698 7654 32"]


def test_iban_invalid_checksum():
    assert _values(iban_detector, "iban GB00 WEST 1234 5698 7654 32 end") == []


def test_phone_detector():
    phonenumbers = pytest.importorskip("phonenumbers")  # noqa: F841
    from sether.detectors.basic import phone_detector

    out = phone_detector.detect("call me at +1 415 555 2671 today")
    assert out and "415" in out[0].value


def test_create_phone_detector_national_format():
    pytest.importorskip("phonenumbers")
    from sether.detectors.basic import create_phone_detector, phone_detector

    national = "call the office at (202) 456-1111 today"
    # The default detector (international-format only) does not catch this.
    assert phone_detector.detect(national) == []
    # With a default country, the national-format number is redacted.
    us = create_phone_detector(default_country="US")
    out = us.detect(national)
    assert out and "202" in out[0].value
