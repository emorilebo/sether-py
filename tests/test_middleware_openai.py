from __future__ import annotations

import asyncio

from sether.detectors.basic import basic_detectors
from sether.middleware.openai import wrap_openai
from sether.vault.memory import MemoryVault


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _make_sync_client(sink):
    class Completions:
        def create(self, **kwargs):
            sink["request"] = kwargs
            # Echo the (already-redacted) content back as the model output.
            content = kwargs["messages"][-1]["content"]
            return _Obj(choices=[_Obj(message=_Obj(content=content))])

    class Chat:
        completions = Completions()

    return _Obj(chat=Chat())


def test_wrap_openai_sync_round_trip():
    sink = {}
    vault = MemoryVault()
    client = wrap_openai(_make_sync_client(sink), detectors=basic_detectors, vault=vault)

    resp = client.chat.completions.create(
        model="gpt-x",
        messages=[{"role": "user", "content": "hi alice@example.com"}],
    )
    # Request that left the process was redacted.
    assert "alice@example.com" not in sink["request"]["messages"][-1]["content"]
    assert "<EMAIL_" in sink["request"]["messages"][-1]["content"]
    # Response tokens were restored.
    assert resp.choices[0].message.content == "hi alice@example.com"


def test_wrap_openai_redacts_content_parts():
    sink = {}
    vault = MemoryVault()
    client = wrap_openai(_make_sync_client(sink), detectors=basic_detectors, vault=vault)
    client.chat.completions.create(
        model="gpt-x",
        messages=[{"role": "user", "content": [{"type": "text", "text": "ssn 123-45-6789"}]}],
    )
    part = sink["request"]["messages"][-1]["content"][0]
    assert "123-45-6789" not in part["text"]
    assert part["type"] == "text"


def test_wrap_openai_async_round_trip():
    sink = {}
    vault = MemoryVault()

    class Completions:
        async def create(self, **kwargs):
            sink["request"] = kwargs
            content = kwargs["messages"][-1]["content"]
            return _Obj(choices=[_Obj(message=_Obj(content=content))])

    class Chat:
        completions = Completions()

    client = wrap_openai(_Obj(chat=Chat()), detectors=basic_detectors, vault=vault)

    async def run():
        return await client.chat.completions.create(
            model="gpt-x",
            messages=[{"role": "user", "content": "hi alice@example.com"}],
        )

    resp = asyncio.run(run())
    assert "alice@example.com" not in sink["request"]["messages"][-1]["content"]
    assert resp.choices[0].message.content == "hi alice@example.com"
