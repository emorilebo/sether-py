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
"""

from __future__ import annotations

import inspect
from typing import List, Optional, Sequence

from ..detectors.types import Detector
from ..stream.redact import redact_sync
from ..vault.types import Vault
from ._common import get_field, restore_in_text, set_field


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


def _restore_choice(choice: object, vault: Vault) -> None:
    for key in ("message", "delta"):
        inner = get_field(choice, key)
        if inner is None:
            continue
        content = get_field(inner, "content")
        if isinstance(content, str):
            set_field(inner, "content", restore_in_text(content, vault))


def _restore_response(response: object, vault: Vault) -> object:
    choices = get_field(response, "choices")
    if isinstance(choices, list):
        for choice in choices:
            _restore_choice(choice, vault)
    return response


def _restore_sync_stream(response: object, vault: Vault):
    def gen():
        for chunk in response:  # type: ignore[union-attr]
            yield _restore_response(chunk, vault)
    return gen()


def _restore_async_stream(response: object, vault: Vault):
    async def agen():
        async for chunk in response:  # type: ignore[union-attr]
            yield _restore_response(chunk, vault)
    return agen()


def wrap_openai(
    client,
    *,
    detectors: Sequence[Detector],
    vault: Vault,
    restore_responses: bool = True,
):
    """Wrap ``client`` in place and return it. Works on sync ``OpenAI`` and
    async ``AsyncOpenAI`` clients."""
    completions = client.chat.completions
    original_create = completions.create
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

    completions.create = create
    return client


__all__ = ["wrap_openai"]
