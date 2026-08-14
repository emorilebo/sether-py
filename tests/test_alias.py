"""Alias engine tests -- mirrors TS ``test/alias.test.ts``."""

from __future__ import annotations

import random

import pytest

from sether import (
    AliasVault,
    alias_value,
    shape_alias,
    suggest_aliases,
)
from sether.detectors import (
    credit_card_detector,
    email_detector,
    iban_detector,
    ipv4_detector,
    ipv6_detector,
    jwt_detector,
    openai_key_detector,
    phone_detector,
)


@pytest.fixture()
def rng():
    return random.Random(42).random


class TestAliasValue:
    def test_name_keeps_word_count(self, rng):
        assert len(alias_value("NAME", "Godfrey", rng).split()) == 1
        two = alias_value("NAME", "Godfrey Lebo", rng)
        assert len(two.split()) == 2
        assert two != "Godfrey Lebo"

    def test_email_reserved_domain_and_redetectable(self, rng):
        alias = alias_value("EMAIL", "emory@gmail.com", rng)
        assert alias.split("@")[1] in ("example.com", "example.org", "example.net")
        assert len(email_detector.detect(alias)) == 1

    def test_us_phone_fictional_block(self, rng):
        national = alias_value("PHONE", "(415) 555-2671", rng)
        assert national.startswith("(") and " 555-01" in national
        intl = alias_value("PHONE", "+14155552671", rng)
        assert intl.startswith("+1") and "555 01" in intl

    def test_gb_phone_ofcom_range(self, rng):
        assert alias_value("PHONE", "+447911123456", rng).startswith("+44 7700 900")

    def test_ng_phone_stays_ng_shaped(self, rng):
        alias = alias_value("PHONE", "+2348065786535", rng)
        assert alias.startswith("+234 803 555 ")
        assert len(phone_detector.detect(alias)) == 1

    def test_national_unknown_region_keeps_trunk_prefix(self, rng):
        alias = alias_value("PHONE", "0806 578 6535", rng)
        assert alias.startswith("08")
        assert alias != "0806 578 6535"

    def test_cc_luhn_valid_and_grouped(self, rng):
        alias = alias_value("CC", "4242 4242 4242 4242", rng)
        assert len(alias.split()) == 4
        assert len(credit_card_detector.detect(alias)) == 1  # Luhn passes
        plain = alias_value("CC", "4242424242424242", rng)
        assert plain.isdigit() and len(plain) == 16

    def test_ssn_advertising_range(self, rng):
        assert alias_value("SSN", "123-45-6789", rng).startswith("987-65-43")
        assert alias_value("SSN", "123456789", rng).startswith("9876543")

    def test_ipv4_test_net(self, rng):
        alias = alias_value("IPV4", "10.1.2.3", rng)
        assert alias.rsplit(".", 1)[0] in ("192.0.2", "198.51.100", "203.0.113")
        assert len(ipv4_detector.detect(alias)) == 1

    def test_ipv6_documentation_prefix(self, rng):
        alias = alias_value("IPV6", "fe80::1", rng)
        assert alias.startswith("2001:db8:")
        assert len(ipv6_detector.detect(alias)) == 1

    def test_iban_mod97_valid(self, rng):
        alias = alias_value("IBAN", "GB82 WEST 1234 5698 7654 32", rng)
        assert len(iban_detector.detect(alias)) == 1

    def test_dob_mirrors_format(self, rng):
        import re

        assert re.match(r"^\d{4}-\d{2}-\d{2}$", alias_value("DOB", "1995-03-14", rng))
        assert re.match(r"^\d{2}/\d{2}/\d{4}$", alias_value("DOB", "14/03/1995", rng))
        assert re.match(r"^[A-Z][a-z]+ \d{1,2}, \d{4}$", alias_value("DOB", "March 14, 1995", rng))

    def test_openai_key_keeps_prefix_and_redetects(self, rng):
        real = "sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"
        alias = alias_value("OPENAI_KEY", real, rng)
        assert alias.startswith("sk-proj-")
        assert alias != real and len(alias) == len(real)
        assert len(openai_key_detector.detect(alias)) == 1

    def test_jwt_detector_visible(self, rng):
        assert len(jwt_detector.detect(alias_value("JWT", "eyJx.eyJy.z", rng))) == 1

    def test_credential_keeps_key_name(self, rng):
        alias = alias_value("CREDENTIAL", "DB_PASSWORD=hunter2secret", rng)
        assert alias.startswith("DB_PASSWORD=")
        assert "hunter2secret" not in alias

    def test_db_uri_keeps_scheme(self, rng):
        alias = alias_value("DB_URI", "mongodb+srv://user:pass@cluster0.mongodb.net/db", rng)
        assert alias.startswith("mongodb+srv://")
        assert "cluster0" not in alias

    def test_unknown_type_shape_preserves(self, rng):
        import re

        alias = alias_value("CUSTOM:emp-id", "EMP-12345-ab", rng)
        assert re.match(r"^[A-Z]{3}-\d{5}-[a-z]{2}$", alias)
        assert alias != "EMP-12345-ab"


class TestSuggestAliases:
    def test_distinct_and_never_original(self, rng):
        s = suggest_aliases("NAME", "Godfrey Lebo", 4, rng)
        assert len(s) == 4
        assert len(set(s)) == 4
        assert "Godfrey Lebo" not in s

    def test_every_builtin_type(self, rng):
        samples = [
            ("EMAIL", "a@b.com"), ("PHONE", "+2348065786535"), ("CC", "4242424242424242"),
            ("SSN", "123-45-6789"), ("IPV4", "1.2.3.4"), ("IPV6", "2001:db8::1"),
            ("IBAN", "GB82WEST12345698765432"), ("NAME", "Ada Obi"), ("DOB", "01/02/1990"),
            ("ADDRESS", "12 Marina Rd, Lagos"), ("PASSPORT", "A1234567"),
            ("JWT", "eyJa.eyJb.c"), ("DB_URI", "redis://u:p@h:6379"),
            ("CREDENTIAL", "TOKEN=abc123"), ("PASSWORD", "hunter2"),
            ("HIGH_ENTROPY", "a1B2c3D4e5F6g7H8a1B2c3D4e5F6g7H8"),
        ]
        for type_, value in samples:
            assert len(suggest_aliases(type_, value, 3, rng)) >= 2, type_


class TestShapeAlias:
    def test_preserves_classes(self, rng):
        import re

        assert re.match(r"^[A-Z][a-z]\d-[A-Z][a-z]\d_[a-z]\d$", shape_alias("Ab1-Cd2_e3", rng))


class TestAliasVault:
    def test_stable_alias_per_original(self, rng):
        vault = AliasVault()
        assert vault.alias_for("NAME", "Godfrey Lebo", rng) == vault.alias_for(
            "NAME", "Godfrey Lebo", rng
        )

    def test_generated_aliases_unique(self):
        vault = AliasVault()
        seen = set()
        for i in range(20):
            alias = vault.alias_for("NAME", f"Person Number{i}")
            assert alias not in seen
            seen.add(alias)

    def test_set_refuses_claimed_alias(self):
        vault = AliasVault()
        assert vault.set("godfrey@gmail.com", "jane.doe@example.com", "EMAIL") is True
        assert vault.set("emory@gmail.com", "jane.doe@example.com", "EMAIL") is False
        assert vault.set("emory@gmail.com", "john.smith@example.org", "EMAIL") is True

    def test_set_repoint_replaces_alias(self):
        vault = AliasVault()
        vault.set("X", "A", "NAME")
        vault.set("X", "B", "NAME")
        assert vault.alias_of("X") == "B"
        assert vault.original_of("A") is None
        assert vault.original_of("B") == "X"

    def test_apply_restore_round_trip(self):
        vault = AliasVault()
        vault.set("Godfrey Lebo", "John Doe", "NAME")
        vault.set("emory@gmail.com", "jane.doe@example.org", "EMAIL")
        vault.set("+2348065786535", "+234 803 555 1234", "PHONE")
        original = (
            "My name is Godfrey Lebo, my email address is emory@gmail.com, "
            "call me on +2348065786535. Sign off as Godfrey Lebo."
        )
        applied = vault.apply(original)
        assert "Godfrey Lebo" not in applied
        assert "emory@gmail.com" not in applied
        assert applied.count("John Doe") == 2
        assert vault.restore(applied) == original

    def test_restore_on_ai_reply(self):
        vault = AliasVault()
        vault.set("Godfrey Lebo", "John Doe", "NAME")
        reply = "Dear John Doe,\n\nThanks! Best,\nJohn Doe's assistant"
        assert vault.restore(reply) == "Dear Godfrey Lebo,\n\nThanks! Best,\nGodfrey Lebo's assistant"

    def test_longest_first_substitution(self):
        vault = AliasVault()
        vault.set("Ann", "Mei", "NAME")
        vault.set("Annabel Lee", "Ingrid Hall", "NAME")
        applied = vault.apply("Annabel Lee met Ann.")
        assert applied == "Ingrid Hall met Mei."
        assert vault.restore(applied) == "Annabel Lee met Ann."

    def test_delete_and_clear(self):
        vault = AliasVault()
        vault.set("X", "A", "NAME")
        assert vault.delete("X") is True
        assert vault.alias_of("X") is None
        vault.set("Y", "B", "NAME")
        vault.clear()
        assert len(vault) == 0
