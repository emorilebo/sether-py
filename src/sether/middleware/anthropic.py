"""Anthropic SDK wrapper.

Direct port of ``src/middleware/anthropic.ts``. Wraps an Anthropic client so
every ``messages.create`` call redacts user/system message contents before the
request goes out and restores response content blocks on the way back.
Structurally typed -- Sether never imports ``anthropic``.

    import anthropic
    from sether import Sether, wrap_anthropic

    sether = Sether()
    client = wrap_anthropic(anthropic.Anthropic(), detectors=sether.detectors, vault=sether.vault)

When the request asks for JSON output (``output_config.format`` or the
deprecated ``output_format``, type ``json_schema``), text blocks are restored
value by value instead of as text, and left tokenized if they are not valid
JSON; streamed JSON-mode text deltas are fragments of a document and stay
tokenized. ``tool_use`` input stays tokenized unless ``restore_tool_arguments``
is set.
"""

from __future__ import annotations

import inspect
from typing import List, Sequence

from ..detectors.types import Detector
from ..stream.redact import redact_sync
from ..stream.restore import restore_json_value
from ..vault.types import Vault
from ._common import get_field, restore_in_text, restore_json_text, set_field


def _redact_block(block: object, detectors: Sequence[Detector], vault: Vault) -> object:
    if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
        return {**block, "text": redact_sync(block["text"], detectors, vault)}
    return block


def _redact_call(args: tuple, kwargs: dict, detectors: Sequence[Detector], vault: Vault) -> tuple:
    kwargs = dict(kwargs)

    system = kwargs.get("system")
    if isinstance(system, str):
        kwargs["system"] = redact_sync(system, detectors, vault)
    elif isinstance(system, list):
        kwargs["system"] = [_redact_block(b, detectors, vault) for b in system]

    messages = kwargs.get("messages")
    if isinstance(messages, list):
        new_messages: List[object] = []
        for msg in messages:
            if not isinstance(msg, dict):
                new_messages.append(msg)
                continue
            content = msg.get("content")
            if isinstance(content, str):
                new_messages.append({**msg, "content": redact_sync(content, detectors, vault)})
            elif isinstance(content, list):
                new_messages.append({**msg, "content": [_redact_block(b, detectors, vault) for b in content]})
            else:
                new_messages.append(msg)
        kwargs["messages"] = new_messages

    return args, kwargs


def _requests_json_output(kwargs: dict) -> bool:
    output_format = get_field(kwargs.get("output_config"), "format")
    return any(
        get_field(fmt, "type") == "json_schema" for fmt in (output_format, kwargs.get("output_format"))
    )


def _restore_response(response: object, vault: Vault, json_content: bool, tool_arguments: bool) -> object:
    content = get_field(response, "content")
    if isinstance(content, list):
        for block in content:
            block_type = get_field(block, "type")
            if block_type == "text":
                text = get_field(block, "text")
                if isinstance(text, str):
                    restored = restore_json_text(text, vault) if json_content else restore_in_text(text, vault)
                    set_field(block, "text", restored)
            elif block_type == "tool_use" and tool_arguments:
                tool_input = get_field(block, "input")
                if isinstance(tool_input, dict):
                    set_field(block, "input", restore_json_value(tool_input, vault))
    return response


def _restore_event(event: object, vault: Vault, json_content: bool) -> object:
    # A JSON-mode text delta is a fragment of a document: it cannot be
    # restored safely on its own, so it stays tokenized.
    if json_content:
        return event
    # Restore any text that streaming events carry, across the common shapes.
    for container in ("delta", "content_block"):
        inner = get_field(event, container)
        if inner is not None:
            text = get_field(inner, "text")
            if isinstance(text, str):
                set_field(inner, "text", restore_in_text(text, vault))
    top_text = get_field(event, "text")
    if isinstance(top_text, str):
        set_field(event, "text", restore_in_text(top_text, vault))
    return event


def _restore_sync_stream(response: object, vault: Vault, json_content: bool):
    def gen():
        for event in response:  # type: ignore[union-attr]
            yield _restore_event(event, vault, json_content)
    return gen()


def _restore_async_stream(response: object, vault: Vault, json_content: bool):
    async def agen():
        async for event in response:  # type: ignore[union-attr]
            yield _restore_event(event, vault, json_content)
    return agen()


def wrap_anthropic(
    client,
    *,
    detectors: Sequence[Detector],
    vault: Vault,
    restore_responses: bool = True,
    restore_tool_arguments: bool = False,
):
    """Wrap ``client`` in place and return it. Works on sync ``Anthropic`` and
    async ``AsyncAnthropic`` clients.

    ``restore_tool_arguments`` (default ``False``) also restores the ``input``
    of ``tool_use`` blocks in non-streaming responses, value by value
    (:func:`restore_json_value`; keys are not restored). Restored input carries
    real PII into your tool code, and a model can still put a real token in the
    wrong field, so validate it before acting on it."""
    messages_resource = client.messages
    original_create = messages_resource.create
    is_async = inspect.iscoroutinefunction(original_create)

    if is_async:
        async def create(*args, **kwargs):
            json_content = _requests_json_output(kwargs)
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
            json_content = _requests_json_output(kwargs)
            args, kwargs = _redact_call(args, kwargs, detectors, vault)
            streaming = bool(kwargs.get("stream"))
            response = original_create(*args, **kwargs)
            if not restore_responses:
                return response
            if streaming:
                return _restore_sync_stream(response, vault, json_content)
            return _restore_response(response, vault, json_content, restore_tool_arguments)

    messages_resource.create = create
    return client


__all__ = ["wrap_anthropic"]
