from __future__ import annotations

import io

from sether.detectors.basic import basic_detectors
from sether.middleware.wsgi import SetherWSGIMiddleware
from sether.vault.memory import MemoryVault


def _echo_app(seen):
    """Inner WSGI app: reads the (redacted) request body, records it, and echoes
    it back as a JSON response."""

    def app(environ, start_response):
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        body = environ["wsgi.input"].read(length)
        seen["request_body"] = body
        start_response(
            "200 OK",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]

    return app


def _drive(app, body):
    environ = {
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    result = app(environ, start_response)
    return b"".join(result), captured


def test_wsgi_redacts_request_and_restores_response():
    seen = {}
    vault = MemoryVault()
    app = SetherWSGIMiddleware(_echo_app(seen), detectors=basic_detectors, vault=vault)

    original = b'{"q":"email alice@example.com"}'
    body, captured = _drive(app, original)

    assert b"alice@example.com" not in seen["request_body"]
    assert b"<EMAIL_" in seen["request_body"]
    assert body == original

    headers = {k.lower(): v for k, v in captured["headers"]}
    assert headers["content-length"] == str(len(original))
