from __future__ import annotations

import asyncio

import pytest

from sether.detectors.basic import basic_detectors
from sether.middleware.httpx_client import wrap_httpx
from sether.vault.memory import MemoryVault

httpx = pytest.importorskip("httpx")


def test_wrap_httpx_sync_round_trip():
    captured = {}

    def handler(request):
        captured["content"] = request.content
        # Echo the redacted request body back as the response.
        return httpx.Response(200, headers={"content-type": "application/json"}, content=request.content)

    vault = MemoryVault()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    wrap_httpx(client, detectors=basic_detectors, vault=vault)

    body = '{"q":"email alice@example.com"}'
    r = client.post("http://test/v1", content=body, headers={"content-type": "application/json"})

    # Outgoing request body was redacted.
    assert b"alice@example.com" not in captured["content"]
    assert b"<EMAIL_" in captured["content"]
    # Response body was restored.
    assert r.text == body


def test_wrap_httpx_passes_binary_through():
    captured = {}

    def handler(request):
        captured["content"] = request.content
        return httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=b"\x00\x01")

    vault = MemoryVault()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    wrap_httpx(client, detectors=basic_detectors, vault=vault)

    r = client.post("http://test/v1", content=b"\x00alice@example.com", headers={"content-type": "application/octet-stream"})
    # Non-textual content-type: request passed through untouched.
    assert captured["content"] == b"\x00alice@example.com"
    assert r.content == b"\x00\x01"


def test_wrap_httpx_async_round_trip():
    captured = {}

    async def handler(request):
        captured["content"] = request.content
        return httpx.Response(200, headers={"content-type": "application/json"}, content=request.content)

    async def run():
        vault = MemoryVault()
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        wrap_httpx(client, detectors=basic_detectors, vault=vault)
        body = '{"q":"ssn 123-45-6789"}'
        r = await client.post("http://test/v1", content=body, headers={"content-type": "application/json"})
        await client.aclose()
        return r.text, body

    text, body = asyncio.run(run())
    assert b"123-45-6789" not in captured["content"]
    assert text == body
