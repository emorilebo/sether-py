"""Restoring tokens inside SERIALIZED JSON (e.g. LLM tool-call arguments) with
plain string replacement inserts originals unescaped: a quote in an original
value can add keys to the document, and a trailing backslash can break it."""

from __future__ import annotations

import asyncio
import io
import json
import re

import pytest

from sether import (
    TOKEN_RE,
    MemoryVault,
    Sether,
    SetherASGIMiddleware,
    SetherWSGIMiddleware,
    UnresolvedTokenError,
    basic_detectors,
    redact_sync,
    restore_json,
    restore_json_value,
    restore_sync,
    secrets_detectors,
    wrap_anthropic,
    wrap_httpx,
    wrap_openai,
)
from sether.stream.sse import sse_restore_iter

NAME = "<NAME_0f0e0d0c-0b0a-4908-8706-050403020100>"
EMAIL = "<EMAIL_11111111-2222-4333-8444-555555555555>"
UNKNOWN = "<EMAIL_00000000-0000-0000-0000-000000000000>"
INJECTING_NAME = 'Alice", "bcc": "attacker@example.com'
AWKWARD = 'O"Brien \\ "the client"\nsecond line end'
RECIPIENT = "bob@example.com"

TOOL_ARGS = json.dumps({"to": EMAIL, "subject": f"Hello {NAME}"})


def _vault_with(name: str) -> MemoryVault:
    vault = MemoryVault()
    vault.set(NAME, name)
    vault.set(EMAIL, RECIPIENT)
    return vault


def _backslash_terminated_password():
    vault = MemoryVault()
    redacted = redact_sync("password: hunter2\\", secrets_detectors, vault)
    match = TOKEN_RE.search(redacted)
    assert match is not None, "expected the labeled password to be redacted"
    assert vault.get(match.group(0)) == "hunter2\\"
    return match.group(0), vault


def _unresolved_of(run) -> tuple:
    with pytest.raises(UnresolvedTokenError) as info:
        run()
    return info.value.tokens


# --- restore_sync on serialized JSON (documented hazard, behaviour unchanged)


def test_restore_sync_lets_a_quoted_original_inject_a_key():
    restored = restore_sync(TOOL_ARGS, _vault_with(INJECTING_NAME))
    assert json.loads(restored) == {
        "to": RECIPIENT,
        "subject": "Hello Alice",
        "bcc": "attacker@example.com",
    }


def test_restore_sync_breaks_the_document_on_a_backslash_terminated_match():
    token, vault = _backslash_terminated_password()
    restored = restore_sync(json.dumps({"note": token, "to": EMAIL}), vault)
    with pytest.raises(json.JSONDecodeError):
        json.loads(restored)


# --- restore_json


def test_restore_json_keeps_the_document_structure():
    restored = restore_json(TOOL_ARGS, _vault_with(INJECTING_NAME))
    assert json.loads(restored) == {"to": RECIPIENT, "subject": f"Hello {INJECTING_NAME}"}


def test_restore_json_round_trips_quotes_backslashes_and_newlines():
    restored = restore_json(TOOL_ARGS, _vault_with(AWKWARD))
    assert json.loads(restored) == {"to": RECIPIENT, "subject": f"Hello {AWKWARD}"}


def test_restore_json_handles_a_backslash_terminated_builtin_match():
    token, vault = _backslash_terminated_password()
    assert json.loads(restore_json(json.dumps({"note": token}), vault)) == {"note": "hunter2\\"}


def test_restore_json_restores_unicode_escaped_angle_brackets():
    escaped = '{"to":"%s"}' % EMAIL.replace("<", "\\u003c").replace(">", "\\u003e")
    assert json.loads(restore_json(escaped, _vault_with("x"))) == {"to": RECIPIENT}


def test_restore_json_keeps_numbers_booleans_null_and_nesting():
    doc = {"a": [1, 2.5, True, None, {"b": EMAIL}], "c": {"d": False}, "big": 2**64 + 1}
    assert json.loads(restore_json(json.dumps(doc), _vault_with("x"))) == {
        "a": [1, 2.5, True, None, {"b": RECIPIENT}],
        "c": {"d": False},
        "big": 2**64 + 1,
    }


def test_restore_json_does_not_restore_keys():
    restored = restore_json(json.dumps({EMAIL: EMAIL}), _vault_with("x"))
    assert json.loads(restored) == {EMAIL: RECIPIENT}


def test_restore_json_rejects_text_that_is_not_json():
    with pytest.raises(json.JSONDecodeError):
        restore_json(f"Hello {NAME}", _vault_with("x"))


def test_restore_json_rejects_an_already_parsed_value():
    with pytest.raises(TypeError):
        restore_json({"to": EMAIL}, _vault_with("x"))  # type: ignore[arg-type]


def test_facade_restore_json_uses_the_shared_vault():
    sether = Sether()
    safe = sether.redact_sync("mail bob@example.com")
    assert json.loads(sether.restore_json(json.dumps({"body": safe}))) == {
        "body": "mail bob@example.com"
    }


# --- restore_json_value


def test_restore_json_value_restores_leaves_without_mutating_input():
    value = {"to": [EMAIL], "subject": f"Hello {NAME}"}
    snapshot = json.dumps(value)

    out = restore_json_value(value, _vault_with(INJECTING_NAME))

    assert out == {"to": [RECIPIENT], "subject": f"Hello {INJECTING_NAME}"}
    assert json.dumps(value) == snapshot


def test_restore_json_value_restores_a_top_level_string_as_text():
    assert restore_json_value(f"Hi {EMAIL}", _vault_with("x")) == f"Hi {RECIPIENT}"


# --- strict mode


def test_strict_reports_tokens_the_vault_cannot_resolve():
    doc = json.dumps({"to": UNKNOWN, "cc": EMAIL, "again": UNKNOWN})
    vault = _vault_with("Alice")
    assert _unresolved_of(lambda: restore_json(doc, vault, strict=True)) == (UNKNOWN,)


def test_strict_reports_case_altered_tokens():
    lowered = EMAIL.lower()
    doc = json.dumps({"to": lowered})
    vault = _vault_with("Alice")
    assert _unresolved_of(lambda: restore_json(doc, vault, strict=True)) == (lowered,)


def test_strict_reports_tokens_in_keys():
    doc = json.dumps({EMAIL: "x"})
    vault = _vault_with("Alice")
    assert _unresolved_of(lambda: restore_json(doc, vault, strict=True)) == (EMAIL,)


def test_strict_applies_to_restore_sync_and_restore_json_value():
    vault = _vault_with("Alice")
    assert _unresolved_of(lambda: restore_sync(f"cc {UNKNOWN}", vault, strict=True)) == (UNKNOWN,)
    assert _unresolved_of(lambda: restore_json_value([UNKNOWN], vault, strict=True)) == (UNKNOWN,)


def test_strict_error_never_contains_restored_originals():
    doc = json.dumps({"to": EMAIL, "cc": UNKNOWN})
    with pytest.raises(UnresolvedTokenError) as info:
        restore_json(doc, _vault_with("Alice"), strict=True)
    assert RECIPIENT not in str(info.value)


def test_strict_returns_the_restored_value_when_everything_resolves():
    vault = _vault_with("Alice")
    assert restore_sync(f"to {EMAIL}", vault, strict=True) == f"to {RECIPIENT}"
    assert json.loads(restore_json(TOOL_ARGS, vault, strict=True)) == {
        "to": RECIPIENT,
        "subject": "Hello Alice",
    }


def test_strict_is_off_by_default():
    vault = _vault_with("Alice")
    assert restore_sync(f"cc {UNKNOWN}", vault) == f"cc {UNKNOWN}"
    assert json.loads(restore_json(json.dumps({"cc": UNKNOWN}), vault)) == {"cc": UNKNOWN}


# --- TOKEN_RE export


def test_token_re_matches_exactly_the_tokens_redact_issues():
    vault = MemoryVault()
    redacted = redact_sync("mail bob@example.com or 10.0.0.1", basic_detectors, vault)
    tokens = [m.group(0) for m in TOKEN_RE.finditer(redacted)]
    assert len(tokens) == 2
    assert all(vault.has(token) for token in tokens)


# --- SDK wrappers leave tool-call arguments tokenized


class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_wrap_openai_does_not_restore_tool_call_arguments():
    class Completions:
        def create(self, **kwargs):
            call = _Obj(function=_Obj(arguments=TOOL_ARGS))
            return _Obj(choices=[_Obj(message=_Obj(content=None, tool_calls=[call]))])

    class Chat:
        completions = Completions()

    client = wrap_openai(_Obj(chat=Chat()), detectors=basic_detectors, vault=_vault_with("Alice"))
    resp = client.chat.completions.create(messages=[])
    assert resp.choices[0].message.tool_calls[0].function.arguments == TOOL_ARGS


def test_wrap_anthropic_does_not_restore_tool_use_input():
    class Messages:
        def create(self, **kwargs):
            block = {"type": "tool_use", "id": "toolu_1", "name": "send_email", "input": {"to": EMAIL}}
            return {"content": [block]}

    client = wrap_anthropic(_Obj(messages=Messages()), detectors=basic_detectors, vault=_vault_with("Alice"))
    resp = client.messages.create(messages=[])
    assert resp["content"][0]["input"] == {"to": EMAIL}


# --- Sether's own restore paths: JSON is restored value by value

INJECTED = {"to": RECIPIENT, "subject": f"Hello {INJECTING_NAME}"}
STREAMED_JSON = ['{"to": "', EMAIL, '", "subject": "Hello ', NAME, '"}']


def _restore_sse(chunks, vault) -> str:
    return "".join(sse_restore_iter(chunks, vault))


def test_sse_restore_keeps_json_data_payloads_intact():
    sse = "data: %s\n\n" % json.dumps({"choices": [{"delta": {"content": f"Hi {NAME}"}}]})
    out = _restore_sse([sse], _vault_with(INJECTING_NAME))
    payload = json.loads(out[len("data: "):])
    assert payload == {"choices": [{"delta": {"content": f"Hi {INJECTING_NAME}"}}]}


def test_sse_restore_keeps_the_payload_valid_on_a_backslash_terminated_match():
    token, vault = _backslash_terminated_password()
    out = _restore_sse(["data: %s\n\n" % json.dumps({"note": token})], vault)
    assert json.loads(out[len("data: "):]) == {"note": "hunter2\\"}


def test_sse_restore_keeps_line_breaks_of_an_original_inside_its_data_line():
    original = "Alice\n\nevent: injected\ndata: {}"
    out = _restore_sse(["data: %s\n\n" % json.dumps({"c": NAME})], _vault_with(original))
    assert out.split("\n") == ["data: %s" % json.dumps({"c": original}), "", ""]


def test_sse_restore_changes_only_the_restored_string_values():
    payload = '{ "id": 12345678901234567890, "n": 1.0, "s": "caf\\u00e9 \\/", "c": "Hi %s" }' % NAME
    out = _restore_sse(["data:%s\r\n\r\n" % payload], _vault_with(INJECTING_NAME))
    restored = payload.replace('"Hi %s"' % NAME, json.dumps(f"Hi {INJECTING_NAME}"))
    assert out == "data:%s\r\n\r\n" % restored


def test_sse_restore_restores_escaped_and_chunk_split_tokens_but_never_keys():
    escaped = EMAIL.replace("<", "\\u003c").replace(">", "\\u003e")
    sse = 'data: {"%s":"%s","b":"%s"}\n\n' % (EMAIL, escaped, NAME)
    out = _restore_sse([sse[:20], sse[20:70], sse[70:]], _vault_with(INJECTING_NAME))
    assert json.loads(out[len("data: "):]) == {EMAIL: RECIPIENT, "b": INJECTING_NAME}


def test_sse_restore_still_restores_text_payloads_and_passes_done_through():
    out = _restore_sse([f"data: Hi {NAME}\n\ndata: [DONE]\n\n"], _vault_with("Alice"))
    assert out == "data: Hi Alice\n\ndata: [DONE]\n\n"


# A non-JSON ``data:`` payload is restored as text, so a line break in an
# original must not end the line: the rest would be read as new SSE fields.

BREAKING = "Alice\n\nevent: injected\nid: 7\ndata: {}"


def _parse_sse(text: str) -> list:
    """Parse SSE text the way a browser EventSource does (WHATWG HTML,
    "Interpreting an event stream") into ``(type, data, last_event_id)``."""
    events = []
    data, event_type, last_event_id = "", "", ""
    for line in re.split(r"\r\n|\r|\n", text):
        if line == "":
            if data:
                events.append((event_type or "message", data[:-1], last_event_id))
            data, event_type = "", ""
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            data += value + "\n"
        elif field == "event":
            event_type = value
        elif field == "id":
            last_event_id = value
    return events


def test_sse_restore_continues_a_multi_line_original_on_new_data_lines():
    out = _restore_sse([f"data: Hi {NAME}!\n\n"], _vault_with(BREAKING))
    assert _parse_sse(out) == [("message", f"Hi {BREAKING}!", "")]
    assert out == "data: Hi Alice\ndata: \ndata: event: injected\ndata: id: 7\ndata: data: {}!\n\n"


def test_sse_restore_turns_cr_lf_and_crlf_into_data_lines_in_the_stream_line_ending():
    out = _restore_sse([f"data:{NAME}\r\n\r\n"], _vault_with("a\rb\r\nc\n d"))
    assert out == "data:a\r\ndata: b\r\ndata: c\r\ndata:  d\r\n\r\n"
    assert _parse_sse(out) == [("message", "a\nb\nc\n d", "")]


def test_sse_restore_restores_chunk_split_tokens_in_a_payload_that_is_not_json():
    sse = 'data: {"c":"%s"\n\n' % NAME
    out = _restore_sse([sse[:20], sse[20:]], _vault_with(BREAKING))
    assert _parse_sse(out) == [("message", '{"c":"%s"' % BREAKING, "")]


def test_sse_restore_keeps_every_byte_when_no_original_has_a_line_break():
    sse = f"data:Hi {NAME}\r\n\r\nevent: x\nid: 1\ndata: {NAME} {EMAIL} {UNKNOWN}\n\n"
    out = _restore_sse([sse], _vault_with("Alice"))
    assert out == f"data:Hi Alice\r\n\r\nevent: x\nid: 1\ndata: Alice {RECIPIENT} {UNKNOWN}\n\n"


def _httpx_get(body: str, content_type: str) -> str:
    httpx = pytest.importorskip("httpx")

    def handler(request):
        return httpx.Response(200, headers={"content-type": content_type}, content=body.encode("utf-8"))

    client = httpx.Client(transport=httpx.MockTransport(handler))
    wrap_httpx(client, detectors=basic_detectors, vault=_vault_with(INJECTING_NAME))
    return client.get("http://test/").text


def test_wrap_httpx_keeps_a_json_body_intact():
    assert json.loads(_httpx_get(TOOL_ARGS, "application/json; charset=utf-8")) == INJECTED


def test_wrap_httpx_changes_only_the_restored_string_values_of_a_json_body():
    body = '{\n  "id": 12345678901234567890,\n  "to": "%s"\n}' % EMAIL
    assert _httpx_get(body, "application/json") == body.replace(EMAIL, RECIPIENT)


def test_wrap_httpx_restores_each_ndjson_line_on_its_own():
    body = "%s\n%s\n" % (TOOL_ARGS, json.dumps({"done": True, "by": NAME}))
    lines = _httpx_get(body, "application/x-ndjson").split("\n")
    assert len(lines) == 3
    assert json.loads(lines[0]) == INJECTED
    assert json.loads(lines[1]) == {"done": True, "by": INJECTING_NAME}


def test_wrap_httpx_restores_event_stream_data_payloads():
    text = _httpx_get(f"data: {TOOL_ARGS}\n\ndata: [DONE]\n\n", "text/event-stream")
    first, rest = text.split("\n", 1)
    assert json.loads(first[len("data: "):]) == INJECTED
    assert rest == "\ndata: [DONE]\n\n"


def _asgi_body(body: str, content_type: str, name: str = INJECTING_NAME) -> str:
    async def app(scope, receive, send):
        headers = [(b"content-type", content_type.encode("latin-1"))]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body.encode("utf-8"), "more_body": False})

    middleware = SetherASGIMiddleware(app, detectors=basic_detectors, vault=_vault_with(name))
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(middleware({"type": "http", "headers": []}, receive, send))
    return b"".join(m["body"] for m in sent if m["type"] == "http.response.body").decode("utf-8")


def test_asgi_keeps_a_json_body_intact():
    assert json.loads(_asgi_body(TOOL_ARGS, "application/json")) == INJECTED


def test_asgi_restores_event_stream_data_payloads():
    text = _asgi_body(f"data: {TOOL_ARGS}\n\n", "text/event-stream")
    assert json.loads(text[len("data: "):]) == INJECTED


def test_asgi_keeps_a_multi_line_original_inside_an_event_stream_text_payload():
    text = _asgi_body(f"data: Hi {NAME}\n\ndata: [DONE]\n\n", "text/event-stream", BREAKING)
    assert _parse_sse(text) == [("message", f"Hi {BREAKING}", ""), ("message", "[DONE]", "")]


def _wsgi_body(body: str, content_type: str, name: str = INJECTING_NAME) -> str:
    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", content_type)])
        return [body.encode("utf-8")]

    middleware = SetherWSGIMiddleware(app, detectors=basic_detectors, vault=_vault_with(name))
    environ = {"REQUEST_METHOD": "GET", "wsgi.input": io.BytesIO(b"")}
    return b"".join(middleware(environ, lambda status, headers, exc_info=None: None)).decode("utf-8")


def test_wsgi_keeps_a_json_body_intact():
    assert json.loads(_wsgi_body(TOOL_ARGS, "application/json")) == INJECTED


def test_wsgi_leaves_a_json_typed_body_that_is_not_valid_json_tokenized():
    # Truncated upstream JSON: restored as text, this original would complete
    # it into a valid document with an extra key.
    truncated = '{"to":"%s","note":"%s' % (RECIPIENT, NAME)
    body = _wsgi_body(truncated, "application/json", name='x", "bcc": "attacker@example.com"}')
    assert body == truncated


def test_wsgi_restores_each_ndjson_line_on_its_own():
    lines = _wsgi_body(f"{TOOL_ARGS}\n{TOOL_ARGS}", "application/x-ndjson").split("\n")
    assert [json.loads(line) for line in lines] == [INJECTED, INJECTED]


def _openai_returning(*items, stream: bool = False):
    class Completions:
        def create(self, **kwargs):
            if stream:
                return iter([_Obj(choices=[_Obj(delta=_Obj(content=item))]) for item in items])
            return _Obj(choices=[_Obj(message=items[0])])

    class Chat:
        completions = Completions()

    return _Obj(chat=Chat())


@pytest.mark.parametrize("kind", ["json_object", "json_schema"])
def test_wrap_openai_restores_json_mode_content_value_by_value(kind):
    client = wrap_openai(
        _openai_returning(_Obj(content=TOOL_ARGS)),
        detectors=basic_detectors,
        vault=_vault_with(INJECTING_NAME),
    )
    resp = client.chat.completions.create(messages=[], response_format={"type": kind})
    assert json.loads(resp.choices[0].message.content) == INJECTED


def test_wrap_openai_async_restores_json_mode_content_value_by_value():
    class Completions:
        async def create(self, **kwargs):
            return _Obj(choices=[_Obj(message=_Obj(content=TOOL_ARGS))])

    class Chat:
        completions = Completions()

    client = wrap_openai(_Obj(chat=Chat()), detectors=basic_detectors, vault=_vault_with(INJECTING_NAME))

    async def run():
        return await client.chat.completions.create(messages=[], response_format={"type": "json_object"})

    assert json.loads(asyncio.run(run()).choices[0].message.content) == INJECTED


def test_wrap_openai_leaves_json_mode_content_that_is_not_valid_json_tokenized():
    truncated = TOOL_ARGS[:-2]
    client = wrap_openai(
        _openai_returning(_Obj(content=truncated)),
        detectors=basic_detectors,
        vault=_vault_with(INJECTING_NAME),
    )
    resp = client.chat.completions.create(messages=[], response_format={"type": "json_object"})
    assert resp.choices[0].message.content == truncated


def test_wrap_openai_leaves_streamed_json_mode_deltas_tokenized():
    client = wrap_openai(
        _openai_returning(*STREAMED_JSON, stream=True),
        detectors=basic_detectors,
        vault=_vault_with(INJECTING_NAME),
    )
    chunks = client.chat.completions.create(messages=[], stream=True, response_format={"type": "json_object"})
    assert "".join(chunk.choices[0].delta.content for chunk in chunks) == "".join(STREAMED_JSON)


def test_wrap_openai_still_restores_streamed_text_deltas():
    client = wrap_openai(
        _openai_returning("Hi ", NAME, stream=True),
        detectors=basic_detectors,
        vault=_vault_with("Alice"),
    )
    chunks = client.chat.completions.create(messages=[], stream=True)
    assert "".join(chunk.choices[0].delta.content for chunk in chunks) == "Hi Alice"


def test_wrap_openai_restores_tool_call_arguments_when_opted_in():
    invalid = '{"to":"%s"' % EMAIL
    calls = [
        _Obj(id="call_1", type="function", function=_Obj(name="send_email", arguments=TOOL_ARGS)),
        _Obj(id="call_2", type="function", function=_Obj(name="send_email", arguments=invalid)),
    ]
    client = wrap_openai(
        _openai_returning(_Obj(content=None, tool_calls=calls)),
        detectors=basic_detectors,
        vault=_vault_with(INJECTING_NAME),
        restore_tool_arguments=True,
    )
    out = client.chat.completions.create(messages=[]).choices[0].message.tool_calls
    assert [(call.id, call.function.name) for call in out] == [("call_1", "send_email"), ("call_2", "send_email")]
    assert json.loads(out[0].function.arguments) == INJECTED
    assert out[1].function.arguments == invalid


def _anthropic_returning(*items, stream: bool = False):
    class Messages:
        def create(self, **kwargs):
            if stream:
                return iter([_Obj(type="content_block_delta", delta=_Obj(type="text_delta", text=t)) for t in items])
            return {"content": list(items)}

    return _Obj(messages=Messages())


@pytest.mark.parametrize(
    "option",
    [
        {"output_config": {"format": {"type": "json_schema", "schema": {}}}},
        {"output_format": {"type": "json_schema", "schema": {}}},
    ],
)
def test_wrap_anthropic_restores_json_mode_text_value_by_value(option):
    client = wrap_anthropic(
        _anthropic_returning({"type": "text", "text": TOOL_ARGS}),
        detectors=basic_detectors,
        vault=_vault_with(INJECTING_NAME),
    )
    resp = client.messages.create(messages=[], **option)
    assert json.loads(resp["content"][0]["text"]) == INJECTED


def test_wrap_anthropic_leaves_streamed_json_mode_text_deltas_tokenized():
    client = wrap_anthropic(
        _anthropic_returning(*STREAMED_JSON, stream=True),
        detectors=basic_detectors,
        vault=_vault_with(INJECTING_NAME),
    )
    events = client.messages.create(
        messages=[], stream=True, output_config={"format": {"type": "json_schema", "schema": {}}}
    )
    assert "".join(event.delta.text for event in events) == "".join(STREAMED_JSON)


def test_wrap_anthropic_restores_tool_use_input_when_opted_in():
    tool_input = {"to": EMAIL, "subject": f"Hello {NAME}"}
    client = wrap_anthropic(
        _anthropic_returning({"type": "tool_use", "id": "toolu_1", "name": "send", "input": tool_input}),
        detectors=basic_detectors,
        vault=_vault_with(INJECTING_NAME),
        restore_tool_arguments=True,
    )
    resp = client.messages.create(messages=[])
    assert resp["content"][0]["input"] == INJECTED
    assert tool_input == {"to": EMAIL, "subject": f"Hello {NAME}"}
