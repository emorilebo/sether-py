"""OpenAI SDK wrapper.

Direct port of ``src/middleware/openai.ts``. Wraps an OpenAI client so every
``chat.completions.create`` call redacts message contents before they go out and
restores response choices on the way back. Structurally typed -- Sether never
imports ``openai``; anything with ``chat.completions.create`` works, sync or
async, streaming or not.

    from openai import OpenAI
    from sether import Sether, wrap_openai

    sether = Sether()
    client = wrap_openai(OpenAI(api_key=key), detectors=sether.detectors, vault=sether.vault)

When the request asks for JSON output (``response_format`` ``json_object`` /
``json_schema``), ``message.content`` is restored value by value instead of as
text, and left tokenized if it is not valid JSON; streamed JSON-mode deltas are
fragments of a document and stay tokenized. Tool-call arguments stay tokenized
unless ``restore_tool_arguments`` is set.
"""

from __future__ import annotations

import inspect
from typing import List, Optional, Sequence

from ..detectors.types import Detector
from ..stream.redact import redact_sync
from ..vault.types import Vault
from ._common import get_field, restore_in_text, restore_json_text, set_field


def _redact_message(msg: object, detectors: Sequence[Detector], vault: Vault) -> object:
    if not isinstance(msg, dict):
        return msg
    content = msg.get("content")
    if isinstance(content, str):
        return {**msg, "content": redact_sync(content, detectors, vault)}
    if isinstance(content, list):
        new_parts: List[object] = []
        for part in content:
            if (
                isinstance(part, dict)
                and part.get("type") == "text"
                and isinstance(part.get("text"), str)
            ):
                new_parts.append({**part, "text": redact_sync(part["text"], detectors, vault)})
            else:
                new_parts.append(part)
        return {**msg, "content": new_parts}
    return msg


def _redact_call(args: tuple, kwargs: dict, detectors: Sequence[Detector], vault: Vault) -> tuple:
    messages = kwargs.get("messages")
    if isinstance(messages, list):
        kwargs = dict(kwargs)
        kwargs["messages"] = [_redact_message(m, detectors, vault) for m in messages]
        return args, kwargs
    # Defensive: a single positional request dict (uncommon in the Python SDK).
    if args and isinstance(args[0], dict) and isinstance(args[0].get("messages"), list):
        req = dict(args[0])
        req["messages"] = [_redact_message(m, detectors, vault) for m in req["messages"]]
        return (req,) + tuple(args[1:]), kwargs
    return args, kwargs


def _requests_json_output(args: tuple, kwargs: dict) -> bool:
    response_format = kwargs.get("response_format")
    if response_format is None and args and isinstance(args[0], dict):
        response_format = args[0].get("response_format")
    return get_field(response_format, "type") in ("json_object", "json_schema")


def _restore_choice(choice: object, vault: Vault, json_content: bool, tool_arguments: bool) -> None:
    for key in ("message", "delta"):
        # A JSON-mode delta is a fragment of a document: it cannot be restored
        # safely on its own, so it stays tokenized.
        if key == "delta" and json_content:
            continue
        inner = get_field(choice, key)
        if inner is None:
            continue
        content = get_field(inner, "content")
        if isinstance(content, str):
            restored = restore_json_text(content, vault) if json_content else restore_in_text(content, vault)
            set_field(inner, "content", restored)
    if tool_arguments:
        tool_calls = get_field(get_field(choice, "message"), "tool_calls")
        for call in tool_calls if isinstance(tool_calls, list) else ():
            function = get_field(call, "function")
            arguments = get_field(function, "arguments")
            if isinstance(arguments, str):
                set_field(function, "arguments", restore_json_text(arguments, vault))


def _restore_response(response: object, vault: Vault, json_content: bool, tool_arguments: bool) -> object:
    choices = get_field(response, "choices")
    if isinstance(choices, list):
        for choice in choices:
            _restore_choice(choice, vault, json_content, tool_arguments)
    return response


def _restore_sync_stream(response: object, vault: Vault, json_content: bool):
    def gen():
        for chunk in response:  # type: ignore[union-attr]
            yield _restore_response(chunk, vault, json_content, False)
    return gen()


def _restore_async_stream(response: object, vault: Vault, json_content: bool):
    async def agen():
        async for chunk in response:  # type: ignore[union-attr]
            yield _restore_response(chunk, vault, json_content, False)
    return agen()


def wrap_openai(
    client,
    *,
    detectors: Sequence[Detector],
    vault: Vault,
    restore_responses: bool = True,
    restore_tool_arguments: bool = False,
):
    """Wrap ``client`` in place and return it. Works on sync ``OpenAI`` and
    async ``AsyncOpenAI`` clients.

    ``restore_tool_arguments`` (default ``False``) also restores
    ``choices[].message.tool_calls[].function.arguments`` in non-streaming
    responses, value by value so an original cannot change the arguments' JSON
    structure; arguments that are not valid JSON are left tokenized. Restored
    arguments carry real PII into your tool code, and a model can still put a
    real token in the wrong field, so validate them before acting on them."""
    completions = client.chat.completions
    original_create = completions.create
    is_async = inspect.iscoroutinefunction(original_create)

    if is_async:
        async def create(*args, **kwargs):
            json_content = _requests_json_output(args, kwargs)
            args, kwargs = _redact_call(args, kwargs, detectors, vault)
            streaming = bool(kwargs.get("stream"))
            response = await original_create(*args, **kwargs)
            if not restore_responses:
                return response
            if streaming:
                return _restore_async_stream(response, vault, json_content)
            return _restore_response(response, vault, json_content, restore_tool_arguments)
    else:
        def create(*args, **kwargs):
            json_content = _requests_json_output(args, kwargs)
            args, kwargs = _redact_call(args, kwargs, detectors, vault)
            streaming = bool(kwargs.get("stream"))
            response = original_create(*args, **kwargs)
            if not restore_responses:
                return response
            if streaming:
                return _restore_sync_stream(response, vault, json_content)
            return _restore_response(response, vault, json_content, restore_tool_arguments)

    completions.create = create
    return client


__all__ = ["wrap_openai"]
