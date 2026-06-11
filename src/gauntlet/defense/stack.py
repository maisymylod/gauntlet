"""The composed defense stack.

Implements the :class:`Defense` seam by routing each hook to the guards enabled
in a :class:`DefenseConfig`. Each guard is independent, so the harness can turn
one on at a time and measure its contribution.
"""

from __future__ import annotations

from gauntlet.config import DefenseConfig
from gauntlet.llm.types import ToolCall
from gauntlet.target.base import GuardDecision, TargetContext

from . import prompt_hardening
from .input_guard import InputGuard
from .output_guard import OutputGuard
from .policy_engine import PolicyConfig, PolicyEngine

_CLEAN = GuardDecision(allowed=True, verdict="clean")


class DefenseStack:
    """Routes the guard seam to the enabled guards.

    Built fresh per case so the policy engine's rate and repetition counters
    start clean.
    """

    def __init__(
        self,
        *,
        config: DefenseConfig,
        context: TargetContext,
        policy: PolicyConfig | None = None,
    ) -> None:
        self.config = config
        self._input_guard = InputGuard()
        self._output_guard = OutputGuard(context)
        self._policy = PolicyEngine(policy or PolicyConfig())

    def harden_system_prompt(self, system: str) -> str:
        if self.config.prompt_hardening:
            return prompt_hardening.harden(system)
        return system

    def on_user_input(self, text: str) -> GuardDecision:
        if self.config.input_guard:
            return self._input_guard.scan(text)
        return _CLEAN

    def on_tool_call(self, call: ToolCall) -> GuardDecision:
        if self.config.policy_engine:
            return self._policy.check(call)
        return _CLEAN

    def on_tool_result(self, tool_name: str, content: str) -> tuple[str, GuardDecision]:
        if self.config.input_guard:
            return content, self._input_guard.scan(content)
        return content, _CLEAN

    def on_output(self, text: str) -> tuple[str, GuardDecision]:
        if self.config.output_guard:
            return self._output_guard.redact(text)
        return text, _CLEAN
