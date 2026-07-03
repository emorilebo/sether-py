from __future__ import annotations

import asyncio
import random

from sether import Sether
from sether.detectors.basic import basic_detectors
from sether.detectors.secrets import secrets_detectors
from sether.stream.redact import redact_iter
from sether.stream.restore import restore_iter
from sether.vault.memory import MemoryVault

SAMPLE = (
    "Contact alice@example.com or bob@work.co.uk. "
    "IBAN GB82 WEST 1234 5698 7654 32. "
    "Card 4242 4242 4242 4242. SSN 123-45-6789. "
    "Token sk-proj-" + "a" * 40 + " stays hidden."
)


def _chunk(text, size):
    return [text[i:i + size] for i in range(0, len(text), size)]


def test_sync_stream_round_trip_identity():
    detectors = (*basic_detectors, *secrets_detectors)
    for size in (1, 2, 3, 5, 7, 13, 64, 256, 4096):
        vault = MemoryVault()
        redacted = "".join(redact_iter(_chunk(SAMPLE, size), detectors, vault))
        assert "alice@example.com" not in redacted
        assert "4242 4242 4242 4242" not in redacted
        restored = "".join(restore_iter(_chunk(redacted, size), vault))
        assert restored == SAMPLE


def test_async_stream_round_trip_identity():
    async def run():
        s = Sether(detectors=(*basic_detectors, *secrets_detectors))

        async def agen(chunks):
            for c in chunks:
                yield c

        redacted_parts = [p async for p in s.aredact_stream(agen(_chunk(SAMPLE, 5)))]
        redacted = "".join(redacted_parts)
        assert "alice@example.com" not in redacted
        restored_parts = [p async for p in s.arestore_stream(agen(_chunk(redacted, 9)))]
        return "".join(restored_parts)

    assert asyncio.run(run()) == SAMPLE


def test_property_random_partitions():
    detectors = (*basic_detectors, *secrets_detectors)
    rng = random.Random(1337)
    for _ in range(60):
        # Random partition of SAMPLE into chunks.
        cuts = sorted(rng.sample(range(1, len(SAMPLE)), rng.randint(1, 12)))
        chunks = []
        prev = 0
        for c in cuts:
            chunks.append(SAMPLE[prev:c])
            prev = c
        chunks.append(SAMPLE[prev:])

        vault = MemoryVault()
        redacted = "".join(redact_iter(chunks, detectors, vault))
        assert "alice@example.com" not in redacted

        # Re-partition the redacted text differently for restore.
        rcuts = sorted(rng.sample(range(1, len(redacted)), rng.randint(1, 12)))
        rchunks = []
        prev = 0
        for c in rcuts:
            rchunks.append(redacted[prev:c])
            prev = c
        rchunks.append(redacted[prev:])
        restored = "".join(restore_iter(rchunks, vault))
        assert restored == SAMPLE


def test_long_whitespace_free_value_guard():
    # A long JWT split awkwardly across chunks must never be emitted partially.
    jwt = "eyJ" + "a" * 80 + ".eyJ" + "b" * 80 + "." + "c" * 80
    text = "header " + jwt + " trailer"
    vault = MemoryVault()
    redacted = "".join(redact_iter(_chunk(text, 11), (*secrets_detectors,), vault))
    assert jwt not in redacted
    assert "<JWT_" in redacted
    restored = "".join(restore_iter([redacted], vault))
    assert restored == text


def test_restore_buffers_partial_token():
    # A token split mid-way should not be emitted until complete.
    s = Sether()
    redacted = s.redact_sync("email alice@example.com")
    token = redacted[redacted.index("<"):redacted.index(">") + 1]
    # Feed the token one character at a time through the restore stream.
    out = "".join(s.restore_stream(list(redacted)))
    assert out == "email alice@example.com"
    assert token  # sanity


def test_overlap_resolution_longest_wins():
    # Build a custom detector that overlaps email; the longer match should win.
    from sether.detectors.types import DetectorMatch

    class WholeLineDetector:
        type = "LINE"

        def detect(self, text):
            return [DetectorMatch(0, len(text), text)]

    vault = MemoryVault()
    from sether.detectors.basic import email_detector
    from sether.stream.redact import redact_sync

    text = "alice@example.com"
    out = redact_sync(text, (WholeLineDetector(), email_detector), vault)
    # The whole-line match (longer) wins; one token, type LINE.
    assert out.startswith("<LINE_") and out.endswith(">")
