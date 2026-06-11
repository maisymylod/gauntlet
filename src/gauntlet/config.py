"""Run configuration and defense toggles."""

from __future__ import annotations

from dataclasses import dataclass, field

# Model used by the reference agent. Opus for a realistic, capable target.
AGENT_MODEL = "claude-opus-4-8"
# Cheaper, faster tier for the LLM judge and the optional input-guard classifier.
JUDGE_MODEL = "claude-haiku-4-5"


@dataclass(frozen=True)
class DefenseConfig:
    """Independent toggles so each defense's effect can be measured alone."""

    input_guard: bool = False
    output_guard: bool = False
    policy_engine: bool = False
    prompt_hardening: bool = False

    @classmethod
    def all_on(cls) -> DefenseConfig:
        return cls(
            input_guard=True,
            output_guard=True,
            policy_engine=True,
            prompt_hardening=True,
        )

    @classmethod
    def all_off(cls) -> DefenseConfig:
        return cls()

    def enabled_names(self) -> list[str]:
        names = []
        if self.input_guard:
            names.append("input_guard")
        if self.output_guard:
            names.append("output_guard")
        if self.policy_engine:
            names.append("policy_engine")
        if self.prompt_hardening:
            names.append("prompt_hardening")
        return names


@dataclass(frozen=True)
class RunConfig:
    """Top-level configuration for a single ``gauntlet run``."""

    run_id: str
    agent_model: str = AGENT_MODEL
    judge_model: str = JUDGE_MODEL
    defenses: DefenseConfig = field(default_factory=DefenseConfig)
    output_dir: str = "runs"
