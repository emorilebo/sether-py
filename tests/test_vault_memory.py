from __future__ import annotations

import time

from sether.vault.memory import MemoryVault


def test_set_get_has_delete_size_clear():
    v = MemoryVault()
    v.set("<EMAIL_1>", "a@b.com")
    assert v.get("<EMAIL_1>") == "a@b.com"
    assert v.has("<EMAIL_1>") is True
    assert v.size() == 1
    assert v.delete("<EMAIL_1>") is True
    assert v.get("<EMAIL_1>") is None
    assert v.delete("<EMAIL_1>") is False
    v.set("<X_1>", "y")
    v.clear()
    assert v.size() == 0


def test_ttl_expiry():
    v = MemoryVault(ttl_ms=10)
    v.set("<T_1>", "secret")
    assert v.get("<T_1>") == "secret"
    time.sleep(0.03)
    assert v.get("<T_1>") is None
    assert v.has("<T_1>") is False


def test_lru_eviction():
    v = MemoryVault(max_entries=2)
    v.set("a", "1")
    v.set("b", "2")
    # Touch 'a' so 'b' is now least-recently-used.
    assert v.get("a") == "1"
    v.set("c", "3")  # evicts the LRU entry ('b')
    assert v.get("b") is None
    assert v.get("a") == "1"
    assert v.get("c") == "3"


def test_size_prunes_expired():
    v = MemoryVault(ttl_ms=10)
    v.set("a", "1")
    v.set("b", "2")
    time.sleep(0.03)
    assert v.size() == 0
