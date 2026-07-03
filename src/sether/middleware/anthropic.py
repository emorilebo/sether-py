"""Anthropic SDK wrapper.

Direct port of ``src/middleware/anthropic.ts``. Wraps an Anthropic client so
every ``messages.create`` call redacts user/system message contents before the
request goes out and restores response content blocks on the way back.
Structurally typed -- Sether never imports ``anthropic``.

    import anthropic
    from sether import Sether, wrap_anthropic

    sether = Sether()
    client = wrap_anthropic(anthropic.Anthropic(), detectors=sether.detectors, vault=sether.vault)
"""

from __future__ import annotations

import inspect
from typing import List, Sequence

from ..detectors.types import Detector
from ..stream.redact import redact_sync
from ..vault.types import Vault
from ._common import get_field, restore_in_text, set_field


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


def _restore_response(response: object, vault: Vault) -> object:
    content = get_field(response, "content")
    if isinstance(content, list):
        for block in content:
            if get_field(block, "type") == "text":
                text = get_field(block, "text")
                if isinstance(text, str):
                    set_field(block, "text", restore_in_text(text, vault))
    return response


def _restore_event(event: object, vault: Vault) -> object:
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


def _restore_sync_stream(response: object, vault: Vault):
    def gen():
        for event in response:  # type: ignore[union-attr]
            yield _restore_event(event, vault)
    return gen()


def _restore_async_stream(response: object, vault: Vault):
    async def agen():
        async for event in response:  # type: ignore[union-attr]
            yield _restore_event(event, vault)
    return agen()


def wrap_anthropic(
    client,
    *,
    detectors: Sequence[Detector],
    vault: Vault,
    restore_responses: bool = True,
):
    """Wrap ``client`` in place and return it. Works on sync ``Anthropic`` and
    async ``AsyncAnthropic`` clients."""
    messages_resource = client.messages
    original_create = messages_resource.create
    is_async = inspect.iscoroutinefunction(original_create)

    if is_async:
        async def create(*args, **kwargs):
            args, kwargs = _redact_call(args, kwargs, detectors, vault)
            streaming = bool(kwargs.get("stream"))
            response = await original_create(*args, **kwargs)
            if not restore_responses:
                return response
            if streaming:
                return _restore_async_stream(response, vault)
            return _restore_response(response, vault)
    else:
        def create(*args, **kwargs):
            args, kwargs = _redact_call(args, kwargs, detectors, vault)
            streaming = bool(kwargs.get("stream"))
            response = original_create(*args, **kwargs)
            if not restore_responses:
                return response
            if streaming:
                return _restore_sync_stream(response, vault)
            return _restore_response(response, vault)

    messages_resource.create = create
    return client


__all__ = ["wrap_anthropic"]
