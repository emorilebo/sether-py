from __future__ import annotations

import asyncio

from sether.detectors.basic import basic_detectors
from sether.middleware.asgi import SetherASGIMiddleware
from sether.vault.memory import MemoryVault


def _echo_app(seen):
    """Inner ASGI app: reads the (redacted) request body, records it, and echoes
    it straight back as a JSON response."""

    async def app(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        seen["request_body"] = body
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})

    return app


async def _drive(app, body):
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-type", b"application/json")],
    }
    incoming = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return incoming.pop(0) if incoming else {"type": "http.request", "body": b"", "more_body": False}

    sent = []

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


def test_asgi_redacts_request_and_restores_response():
    seen = {}
    vault = MemoryVault()
    app = SetherASGIMiddleware(_echo_app(seen), detectors=basic_detectors, vault=vault)

    original = '{"q":"email alice@example.com"}'.encode()
    sent = asyncio.run(_drive(app, original))

    # Inner app saw a redacted body.
    assert b"alice@example.com" not in seen["request_body"]
    assert b"<EMAIL_" in seen["request_body"]

    # Outgoing response was restored.
    body = b"".join(m["body"] for m in sent if m["type"] == "http.response.body")
    assert body == original

    # content-length was recomputed to the restored length.
    start = next(m for m in sent if m["type"] == "http.response.start")
    headers = {k.lower(): v for k, v in start["headers"]}
    assert headers[b"content-length"] == str(len(original)).encode()


def test_asgi_passes_non_http_scope_through():
    vault = MemoryVault()

    async def inner(scope, receive, send):
        await send({"type": "lifespan.startup.complete"})

    app = SetherASGIMiddleware(inner, detectors=basic_detectors, vault=vault)

    async def run():
        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "lifespan.startup"}

        await app({"type": "lifespan"}, receive, send)
        return sent

    sent = asyncio.run(run())
    assert sent and sent[0]["type"] == "lifespan.startup.complete"
