"""Regression tests for the 0.3.0 detection-gap fixes -- mirrors TS
``test/detectors.gaps.test.ts`` (0.7.0): multi-region national phones,
label-anchored API keys/passwords, "born on" DOB, prose/Commonwealth
addresses, and the non-postal "address" compound false positive."""

from __future__ import annotations

from sether.detectors import (
    address_detector,
    create_multi_region_phone_detector,
    dob_detector,
    labeled_api_key_detector,
    labeled_password_detector,
)


class TestMultiRegionPhone:
    detector = create_multi_region_phone_detector(["US", "NG", "GB"])

    def test_national_formats(self):
        assert len(self.detector.detect("call me on 08065786535")) == 1
        assert len(self.detector.detect("my number is 0806 578 6535")) == 1
        assert len(self.detector.detect("call me at (415) 555-2671")) == 1
        assert len(self.detector.detect("my number is 415-555-2671")) == 1
        assert len(self.detector.detect("ring 07911 123456 today")) == 1

    def test_international_still_works(self):
        assert len(self.detector.detect("reach me on +2348065786535")) == 1

    def test_deduplicates_across_passes(self):
        assert len(self.detector.detect("call +1 415 555 2671 now")) == 1

    def test_no_fire_on_prose(self):
        assert self.detector.detect("the meeting is at 3pm on tuesday") == []


class TestLabeledApiKey:
    def test_prose_labelled_keys(self):
        m = labeled_api_key_detector.detect("use apikey AbC123xYz789QwE456")
        assert len(m) == 1 and m[0].value == "AbC123xYz789QwE456"
        assert len(labeled_api_key_detector.detect("my api key is Zx9Yw8Vu7Tt6Ss5R")) == 1
        assert len(labeled_api_key_detector.detect("access_token: 9f8e7d6c5b4a3928")) == 1
        assert len(labeled_api_key_detector.detect("client secret = qT4xP0mN8kL2jH6g")) == 1

    def test_no_fire_on_prose(self):
        assert labeled_api_key_detector.detect("api key management is important") == []
        assert labeled_api_key_detector.detect("rotate your api keys regularly please") == []


class TestLabeledPassword:
    def test_catches_prose_password(self):
        m = labeled_password_detector.detect("my password is hunter2butlonger, keep it safe")
        assert len(m) == 1 and m[0].value == "hunter2butlonger"

    def test_strips_trailing_punctuation(self):
        m = labeled_password_detector.detect("password: S3cr3t!pass.")
        assert m[0].value == "S3cr3t!pass"

    def test_rejects_non_secrets(self):
        assert labeled_password_detector.detect("the password is required here") == []
        assert labeled_password_detector.detect("my password is wrong again") == []

    def test_requires_separator(self):
        assert labeled_password_detector.detect("password hunter2") == []


class TestDobBornOn:
    def test_born_on(self):
        m = dob_detector.detect("I was born on 14/03/1995")
        assert len(m) == 1 and m[0].value == "14/03/1995"

    def test_bare_born_still_works(self):
        assert len(dob_detector.detect("born 1990-05-12")) == 1


class TestAddressGaps:
    def test_live_at_crescent(self):
        m = address_detector.detect("I live at 24 Adetokunbo Ademola Crescent, Wuse 2, Abuja")
        assert any("Adetokunbo Ademola Crescent" in x.value for x in m)

    def test_standalone_crescent(self):
        assert len(address_detector.detect("send it to 15 Freedom Crescent tomorrow")) >= 1

    def test_verb_suffixes_excluded(self):
        assert address_detector.detect("the 3 stores close at 5pm") == []

    def test_non_postal_compounds_do_not_fire(self):
        assert (
            address_detector.detect(
                "my email address is emory@gmail.com, call me on 08065786535. Regards, Godfrey"
            )
            == []
        )
        assert address_detector.detect("IP address: 10.0.0.1 is unreachable") == []
        assert address_detector.detect("wallet address: 0x12a4 5bc backup, ok") == []
        assert address_detector.detect("the server address is 192.168.0.1, port 8080") == []

    def test_real_labelled_addresses_still_fire(self):
        assert len(address_detector.detect("Address: 12 Marina Road, Lagos")) >= 1
        assert len(address_detector.detect("shipping address: 4 Elm Street, Springfield")) >= 1
