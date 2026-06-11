"""The single choke point for talking to a model.

Every model call in gauntlet goes through an ``LLMClient``. ``AnthropicClient``
wraps the real Messages API with retries and a timeout; ``StubLLMClient`` serves
recorded responses so the test suite and CI run with no network access.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from .types import LLMRequest, LLMResponse, ToolCall


class LLMClient(Protocol):
    """Anything that can answer an :class:`LLMRequest`."""

    def complete(self, request: LLMRequest) -> LLMResponse: ...


def fingerprint(request: LLMRequest) -> str:
    """A stable hash of the request, used to key recorded stub responses.

    Captures the inputs that determine the model's reply: model id, system
    prompt, the full message history, and the advertised tool names.
    """
    payload = {
        "model": request.model,
        "system": request.system,
        "messages": request.messages,
        "tools": sorted(t.name for t in request.tools),
        "max_tokens": request.max_tokens,
    }
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


class StubMiss(KeyError):
    """Raised when the stub has no recorded response for a request.

    Failing loudly keeps tests honest: an unmatched request means the fixtures
    drifted from the code, never a silent live call.
    """


class StubLLMClient:
    """Serves recorded responses. The default client for tests and CI.

    Provide ``by_fingerprint`` for content-addressed lookup, or ``responses``
    for a simple in-order queue, or both (fingerprint wins, queue is the
    fallback). Every request is recorded on ``calls`` for assertions.
    """

    def __init__(
        self,
        responses: Sequence[LLMResponse] | None = None,
        by_fingerprint: Mapping[str, LLMResponse] | None = None,
    ) -> None:
        self._queue: list[LLMResponse] = list(responses or [])
        self._by_fingerprint: dict[str, LLMResponse] = dict(by_fingerprint or {})
        self.calls: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        fp = fingerprint(request)
        if fp in self._by_fingerprint:
            return self._by_fingerprint[fp]
        if self._queue:
            return self._queue.pop(0)
        raise StubMiss(
            f"no recorded response for request fingerprint {fp} "
            f"(model={request.model}, {len(request.messages)} messages)"
        )


class AnthropicClient:
    """Wraps the Anthropic Messages API with retries and a timeout.

    The SDK is imported lazily so the package (and the offline test suite) does
    not require ``anthropic`` to be installed. Retries on 429/5xx and backoff
    are handled by the SDK via ``max_retries``.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 4,
    ) -> None:
        import anthropic  # noqa: PLC0415  (lazy: keep the SDK optional)

        base = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self._client = base.with_options(timeout=timeout, max_retries=max_retries)

    def complete(self, request: LLMRequest) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": request.messages,
        }
        if request.system is not None:
            kwargs["system"] = request.system
        if request.tools:
            kwargs["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                }
                for t in request.tools
            ]
        message = self._client.messages.create(**kwargs)
        return _to_response(message)


def _to_response(message: Any) -> LLMResponse:
    """Map an Anthropic ``Message`` onto an :class:`LLMResponse`."""
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    content_blocks: list[dict[str, Any]] = []
    for block in message.content:
        block_type = getattr(block, "type", None)
        if block_type == "text":
            text_parts.append(block.text)
            content_blocks.append({"type": "text", "text": block.text})
        elif block_type == "tool_use":
            arguments = dict(block.input) if block.input else {}
            tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=arguments))
            content_blocks.append(
                {
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": arguments,
                }
            )
    return LLMResponse(
        stop_reason=message.stop_reason or "end_turn",
        text="".join(text_parts),
        tool_calls=tuple(tool_calls),
        content_blocks=tuple(content_blocks),
    )
