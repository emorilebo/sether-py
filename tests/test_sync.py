from __future__ import annotations

from sether.detectors.basic import basic_detectors
from sether.stream.redact import redact_sync
from sether.stream.restore import restore_sync
from sether.vault.memory import MemoryVault


def test_redact_restore_sync_round_trip():
    vault = MemoryVault()
    text = "email alice@example.com card 4242 4242 4242 4242"
    redacted = redact_sync(text, basic_detectors, vault)
    assert "alice@example.com" not in redacted
    assert restore_sync(redacted, vault) == text


def test_restore_leaves_unknown_token_intact():
    vault = MemoryVault()
    # A token with no vault entry is passed through untouched.
    text = "ref <EMAIL_deadbeef-dead-beef-dead-beefdeadbeef> end"
    assert restore_sync(text, vault) == text


def test_token_format():
    vault = MemoryVault()
    out = redact_sync("alice@example.com", basic_detectors, vault)
    assert out.startswith("<EMAIL_") and out.endswith(">")
    # The vault maps the token back to the original.
    assert vault.get(out) == "alice@example.com"
