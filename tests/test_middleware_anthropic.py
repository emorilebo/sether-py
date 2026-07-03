from __future__ import annotations

from sether.detectors.basic import basic_detectors
from sether.middleware.anthropic import wrap_anthropic
from sether.vault.memory import MemoryVault


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _make_client(sink):
    class Messages:
        def create(self, **kwargs):
            sink["request"] = kwargs
            text = kwargs["messages"][-1]["content"]
            return _Obj(content=[_Obj(type="text", text=text)])

    return _Obj(messages=Messages())


def test_wrap_anthropic_round_trip():
    sink = {}
    vault = MemoryVault()
    client = wrap_anthropic(_make_client(sink), detectors=basic_detectors, vault=vault)

    resp = client.messages.create(
        model="claude-x",
        max_tokens=64,
        messages=[{"role": "user", "content": "email alice@example.com please"}],
    )
    assert "alice@example.com" not in sink["request"]["messages"][-1]["content"]
    assert resp.content[0].text == "email alice@example.com please"


def test_wrap_anthropic_redacts_system_string():
    sink = {}
    vault = MemoryVault()
    client = wrap_anthropic(_make_client(sink), detectors=basic_detectors, vault=vault)
    client.messages.create(
        model="claude-x",
        max_tokens=64,
        system="operator bob@work.co.uk",
        messages=[{"role": "user", "content": "hello"}],
    )
    assert "bob@work.co.uk" not in sink["request"]["system"]
    assert "<EMAIL_" in sink["request"]["system"]
