"""The target interface and the defense seam.

A :class:`Target` is anything the harness can drive one user turn at a time.
The reference Claude agent and the HTTP adapter both implement it.

The :class:`Defense` protocol is the seam the defense stack plugs into. Phase 1
ships only :class:`NullDefense` (everything allowed); Phase 3 supplies a real
stack. Wiring the seam now keeps the agent loop stable across phases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from gauntlet.llm.types import ToolCall


@dataclass(frozen=True)
class GuardDecision:
    """A guard's verdict on one input, tool call, or output."""

    allowed: bool
    verdict: str  # "clean" | "flagged" | "blocked"
    reason: str = ""


@dataclass(frozen=True)
class TargetContext:
    """The secrets and cross-tenant data the oracles probe for.

    Held by the reference agent (in its system prompt and fake filesystem) so
    exfiltration and tenant-isolation oracles have a concrete string to match.
    """

    system_prompt: str
    fake_secret: str
    other_tenant_record: str


@dataclass(frozen=True)
class TargetResult:
    """The outcome of one user turn."""

    output_text: str
    tool_calls: list[ToolCall]
    system_prompt: str | None
    raw: dict[str, Any] = field(default_factory=dict)


class Target(Protocol):
    """A drivable agent."""

    name: str

    def reset(self) -> None:
        """Clear per-session state before a new attack case."""
        ...

    def send(self, user_text: str) -> TargetResult:
        """Run one user turn and return the result."""
        ...


class Defense(Protocol):
    """The guard seam wrapped around a target's turn."""

    def on_user_input(self, text: str) -> GuardDecision: ...

    def on_tool_call(self, call: ToolCall) -> GuardDecision: ...

    def on_output(self, text: str) -> tuple[str, GuardDecision]:
        """Return possibly-redacted output text and the guard decision."""
        ...


class NullDefense:
    """No defenses. Everything is allowed and unmodified."""

    def on_user_input(self, text: str) -> GuardDecision:
        return GuardDecision(allowed=True, verdict="clean")

    def on_tool_call(self, call: ToolCall) -> GuardDecision:
        return GuardDecision(allowed=True, verdict="clean")

    def on_output(self, text: str) -> tuple[str, GuardDecision]:
        return text, GuardDecision(allowed=True, verdict="clean")
