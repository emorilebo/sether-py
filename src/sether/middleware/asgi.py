"""ASGI middleware (FastAPI / Starlette) -- the closest analog of the TS Express
middleware.

Redacts incoming textual request bodies and restores outgoing textual response
bodies, so route handlers never have to think about redaction. Both directions
buffer the full body (as ``express.json()`` does on the TS side), then redact /
restore in one pass. Response bodies are restored like ``wrap_httpx`` restores
them, so JSON is never restored as text.

    from fastapi import FastAPI
    from sether import Sether, SetherASGIMiddleware

    sether = Sether()
    app = FastAPI()
    app.add_middleware(SetherASGIMiddleware, detectors=sether.detectors, vault=sether.vault)
"""

from __future__ import annotations

from typing import Sequence

from ..detectors.types import Detector
from ..stream.redact import redact_sync
from ..vault.types import Vault
from ._common import asgi_header, is_textual_content_type, restore_body, strip_asgi_headers


class SetherASGIMiddleware:
    def __init__(
        self,
        app,
        *,
        detectors: Sequence[Detector],
        vault: Vault,
        safe_distance_bytes: int = 256,
    ) -> None:
        self.app = app
        self.detectors = detectors
        self.vault = vault
        self.safe_distance_bytes = safe_distance_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request_ct = asgi_header(scope.get("headers", []), "content-type")
        wrapped_receive = receive
        if is_textual_content_type(request_ct):
            wrapped_receive = self._redacting_receive(receive)

        wrapped_send = self._restoring_send(send)
        await self.app(scope, wrapped_receive, wrapped_send)

    def _redacting_receive(self, receive):
        state = {"consumed": False}

        async def wrapped():
            if state["consumed"]:
                return {"type": "http.request", "body": b"", "more_body": False}
            chunks = []
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    return message  # e.g. http.disconnect
                chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            try:
                redacted = redact_sync(body.decode("utf-8"), self.detectors, self.vault).encode("utf-8")
            except UnicodeDecodeError:
                redacted = body
            state["consumed"] = True
            return {"type": "http.request", "body": redacted, "more_body": False}

        return wrapped

    def _restoring_send(self, send):
        state = {"restore": False, "start": None, "content_type": "", "body": b""}

        async def wrapped(message):
            mtype = message["type"]

            if mtype == "http.response.start":
                ct = asgi_header(message.get("headers", []), "content-type")
                if is_textual_content_type(ct):
                    state["restore"] = True
                    state["start"] = message
                    state["content_type"] = ct
                    return  # defer until the full body is restored
                await send(message)
                return

            if mtype == "http.response.body":
                if not state["restore"]:
                    await send(message)
                    return
                state["body"] += message.get("body", b"")
                if message.get("more_body", False):
                    return
                try:
                    text = state["body"].decode("utf-8")
                    restored = restore_body(text, state["content_type"], self.vault).encode("utf-8")
                except UnicodeDecodeError:
                    restored = state["body"]
                start = state["start"]
                headers = strip_asgi_headers(start.get("headers", []), ("content-length", "content-encoding"))
                headers.append((b"content-length", str(len(restored)).encode("latin-1")))
                await send({"type": "http.response.start", "status": start["status"], "headers": headers})
                await send({"type": "http.response.body", "body": restored, "more_body": False})
                return

            await send(message)

        return wrapped


__all__ = ["SetherASGIMiddleware"]
