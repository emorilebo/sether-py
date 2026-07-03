"""httpx client wrapper -- the Python analog of the TS ``wrapFetch``.

Patches a ``httpx.Client`` or ``httpx.AsyncClient`` so outgoing textual request
bodies are redacted before they leave the process and textual response bodies
are restored on the way back. Binary bodies pass through untouched.

    import httpx
    from sether import Sether, wrap_httpx

    sether = Sether()
    client = wrap_httpx(httpx.Client(), detectors=sether.detectors, vault=sether.vault)
    r = client.post("https://api.example.com/v1/chat", json={"q": "email alice@example.com"})
    # The request carried <EMAIL_...>; r.text has tokens the server echoed back restored.

Note: for true server-sent streaming, use ``client.stream(...)`` (left
untouched) together with the SSE restore stream, or restore manually -- this
wrapper buffers non-streaming responses to restore them, mirroring ``wrapFetch``
reading ``response.text()``.
"""

from __future__ import annotations

from typing import Sequence

from ..detectors.types import Detector
from ..stream.redact import redact_sync
from ..stream.restore import restore_sync
from ..vault.types import Vault
from ._common import is_textual_content_type


def _redact_request(request, detectors: Sequence[Detector], vault: Vault, httpx):
    content_type = request.headers.get("content-type", "")
    if not is_textual_content_type(content_type):
        return request
    body = request.content
    if not body:
        return request
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return request
    redacted = redact_sync(text, detectors, vault).encode("utf-8")
    headers = httpx.Headers(request.headers)
    if "content-length" in headers:
        del headers["content-length"]
    return httpx.Request(
        request.method,
        request.url,
        headers=headers,
        content=redacted,
        extensions=request.extensions,
    )


def _restore_response(response, vault: Vault, httpx):
    content_type = response.headers.get("content-type", "")
    if not is_textual_content_type(content_type):
        return response
    try:
        text = response.content.decode("utf-8")
    except UnicodeDecodeError:
        return response
    restored = restore_sync(text, vault).encode("utf-8")
    headers = httpx.Headers(response.headers)
    # The restored body has a new length and is already decoded; carrying the
    # upstream content-length / content-encoding forward would describe the old
    # bytes. Drop both so the rebuilt response stays self-consistent.
    for name in ("content-length", "content-encoding"):
        if name in headers:
            del headers[name]
    return httpx.Response(
        response.status_code,
        headers=headers,
        content=restored,
        request=response.request,
        extensions=response.extensions,
    )


def wrap_httpx(
    client,
    *,
    detectors: Sequence[Detector],
    vault: Vault,
    safe_distance_bytes: int = 256,
):
    """Wrap ``client`` in place and return it."""
    import httpx

    is_async = isinstance(client, httpx.AsyncClient)
    original_send = client.send

    if is_async:
        async def send(request, **kwargs):
            request = _redact_request(request, detectors, vault, httpx)
            response = await original_send(request, **kwargs)
            if kwargs.get("stream"):
                return response  # preserve streaming; restore manually if needed
            await response.aread()
            return _restore_response(response, vault, httpx)
    else:
        def send(request, **kwargs):
            request = _redact_request(request, detectors, vault, httpx)
            response = original_send(request, **kwargs)
            if kwargs.get("stream"):
                return response
            response.read()
            return _restore_response(response, vault, httpx)

    client.send = send
    return client


__all__ = ["wrap_httpx"]
