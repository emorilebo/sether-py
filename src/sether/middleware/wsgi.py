"""WSGI middleware (Flask / classic sync stack).

Redacts incoming textual request bodies and restores outgoing textual response
bodies. The request body and the response body are each buffered fully, then
redacted / restored in one pass.

    from flask import Flask
    from sether import Sether, SetherWSGIMiddleware

    sether = Sether()
    app = Flask(__name__)
    app.wsgi_app = SetherWSGIMiddleware(app.wsgi_app, detectors=sether.detectors, vault=sether.vault)
"""

from __future__ import annotations

import io
from typing import Sequence

from ..detectors.types import Detector
from ..stream.redact import redact_sync
from ..stream.restore import restore_sync
from ..vault.types import Vault
from ._common import is_textual_content_type


def _header_value(headers, name: str) -> str:
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return ""


class SetherWSGIMiddleware:
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

    def __call__(self, environ, start_response):
        environ = self._redact_request(environ)

        captured: dict = {}

        def capture_start(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = list(headers)
            captured["exc_info"] = exc_info
            return lambda data: None  # legacy write() callable -- unused by buffered apps

        result = self.app(environ, capture_start)
        try:
            body = b"".join(result)
        finally:
            close = getattr(result, "close", None)
            if callable(close):
                close()

        headers = captured["headers"]
        if is_textual_content_type(_header_value(headers, "content-type")):
            try:
                body = restore_sync(body.decode("utf-8"), self.vault).encode("utf-8")
            except UnicodeDecodeError:
                pass

        out_headers = [
            (k, v) for k, v in headers if k.lower() not in ("content-length", "content-encoding")
        ]
        out_headers.append(("Content-Length", str(len(body))))
        start_response(captured["status"], out_headers, captured.get("exc_info"))
        return [body]

    def _redact_request(self, environ):
        content_type = environ.get("CONTENT_TYPE", "")
        if not is_textual_content_type(content_type):
            return environ
        stream = environ.get("wsgi.input")
        if stream is None:
            return environ
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except (TypeError, ValueError):
            length = 0
        body = stream.read(length) if length > 0 else stream.read()
        if not body:
            return environ
        try:
            redacted = redact_sync(body.decode("utf-8"), self.detectors, self.vault).encode("utf-8")
        except UnicodeDecodeError:
            redacted = body
        environ = dict(environ)
        environ["wsgi.input"] = io.BytesIO(redacted)
        environ["CONTENT_LENGTH"] = str(len(redacted))
        return environ


__all__ = ["SetherWSGIMiddleware"]
