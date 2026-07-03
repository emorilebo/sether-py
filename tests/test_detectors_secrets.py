from __future__ import annotations

from sether.detectors.secrets import (
    anthropic_key_detector,
    aws_access_key_detector,
    github_pat_detector,
    high_entropy_detector,
    jwt_detector,
    openai_key_detector,
    slack_token_detector,
    stripe_key_detector,
)


def _values(detector, text):
    return [m.value for m in detector.detect(text)]


def test_aws_access_key():
    key = "AKIAIOSFODNN7EXAMPLE"
    assert _values(aws_access_key_detector, f"key={key}") == [key]


def test_openai_key():
    key = "sk-proj-" + "a" * 30
    assert _values(openai_key_detector, f"OPENAI={key}") == [key]


def test_anthropic_key():
    key = "sk-ant-api03-" + "B" * 50
    assert _values(anthropic_key_detector, f"k={key}") == [key]


def test_github_classic_and_finegrained():
    classic = "ghp_" + "a" * 36
    fine = "github_pat_" + "A" * 22 + "_" + "b" * 59
    assert _values(github_pat_detector, f"{classic} {fine}") == [classic, fine]


def test_slack_token():
    tok = "xoxb-1234567890-1234567890123-" + "a" * 24
    assert _values(slack_token_detector, f"t={tok}") == [tok]


def test_stripe_keys():
    live = "sk_live_" + "a" * 24
    whsec = "whsec_" + "b" * 32
    out = _values(stripe_key_detector, f"{live} {whsec}")
    assert live in out and whsec in out


def test_jwt():
    jwt = "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12
    assert _values(jwt_detector, f"auth {jwt}") == [jwt]


def test_high_entropy_requires_letter_digit_and_entropy():
    # All same char -> low entropy -> rejected.
    assert _values(high_entropy_detector, "a" * 40) == []
    # No digit -> rejected.
    assert _values(high_entropy_detector, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ") == []
    # Mixed high-entropy token -> detected.
    token = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
    assert token in _values(high_entropy_detector, f"secret {token} end")
