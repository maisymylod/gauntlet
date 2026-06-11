"""Request and response types for the LLM client.

These are deliberately small and provider-neutral. The Anthropic client maps
the Messages API onto them; the stub client fabricates them from recorded data.
Nothing outside this package should depend on the Anthropic SDK directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolDef:
    """A tool advertised to the model."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMRequest:
    """One call to the model."""

    model: str
    messages: list[dict[str, Any]]
    system: str | None = None
    tools: tuple[ToolDef, ...] = ()
    max_tokens: int = 4096


@dataclass(frozen=True)
class LLMResponse:
    """The model's reply for one call.

    ``content_blocks`` holds the raw assistant content (text and tool_use
    blocks) so the agent loop can echo it back verbatim on the next turn, as
    the Messages API requires.
    """

    stop_reason: str
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    content_blocks: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def make(
        cls,
        *,
        stop_reason: str,
        text: str = "",
        tool_calls: tuple[ToolCall, ...] = (),
    ) -> LLMResponse:
        """Build a response, synthesizing content blocks from text and tool calls.

        Convenience for tests and the stub client.
        """
        blocks: list[dict[str, Any]] = []
        if text:
            blocks.append({"type": "text", "text": text})
        for call in tool_calls:
            blocks.append(
                {
                    "type": "tool_use",
                    "id": call.id,
                    "name": call.name,
                    "input": call.arguments,
                }
            )
        return cls(
            stop_reason=stop_reason,
            text=text,
            tool_calls=tuple(tool_calls),
            content_blocks=tuple(blocks),
        )

    def assistant_message(self) -> dict[str, Any]:
        """The assistant turn to append to the running message history."""
        return {"role": "assistant", "content": list(self.content_blocks)}
