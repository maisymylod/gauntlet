"""Drive the corpus against a target and collect per-case outcomes.

The runner is deliberately client-agnostic: callers pass factories that build a
model client per case. For offline runs and CI, :func:`offline_clients` replays
each case's scripted transcript through the stub. For live runs, the factory
returns a shared :class:`AnthropicClient`.

The defense is built per case via ``make_defense`` so stateful guards (rate and
recursion limits) start fresh each case. Phase 2 uses :class:`NullDefense`; the
real stack is wired in Phase 3.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from gauntlet.config import AGENT_MODEL, JUDGE_MODEL, DefenseConfig
from gauntlet.defense.policy_engine import PolicyConfig
from gauntlet.defense.stack import DefenseStack
from gauntlet.llm.client import LLMClient, StubLLMClient
from gauntlet.llm.types import LLMRequest, LLMResponse
from gauntlet.target.base import Defense, NullDefense, TargetContext
from gauntlet.target.reference_agent import ReferenceAgent

from .base import AttackCase, build_scripted_responses
from .oracles import build_oracle

AgentClientFactory = Callable[[AttackCase], LLMClient]
JudgeClientFactory = Callable[[AttackCase], LLMClient]
DefenseFactory = Callable[[], Defense]


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    attack_class: str
    success: bool
    rationale: str
    blocked: bool
    output_text: str
    attempted_tools: list[str]
    executed_tools: list[str]


def run_case(
    case: AttackCase,
    *,
    context: TargetContext,
    agent_client: LLMClient,
    defense: Defense,
    judge_client: LLMClient | None = None,
    agent_model: str = AGENT_MODEL,
    judge_model: str = JUDGE_MODEL,
) -> CaseOutcome:
    agent = ReferenceAgent(agent_client, context=context, defense=defense, model=agent_model)
    if case.injected_tool_payload:
        agent.apply_injection(case.injected_tool_payload)
    result = agent.send(case.user_text)

    oracle = build_oracle(case.oracle, judge_client=judge_client, judge_model=judge_model)
    verdict = oracle.evaluate(case, result, context)

    executed = [str(call["name"]) for call in result.raw.get("executed_calls", [])]
    return CaseOutcome(
        case_id=case.id,
        attack_class=str(case.attack_class),
        success=verdict.success,
        rationale=verdict.rationale,
        blocked=bool(result.raw.get("blocked", False)),
        output_text=result.output_text,
        attempted_tools=[call.name for call in result.tool_calls],
        executed_tools=executed,
    )


def run_corpus(
    cases: Sequence[AttackCase],
    *,
    context: TargetContext,
    make_agent_client: AgentClientFactory,
    make_defense: DefenseFactory = NullDefense,
    make_judge_client: JudgeClientFactory | None = None,
    agent_model: str = AGENT_MODEL,
    judge_model: str = JUDGE_MODEL,
) -> list[CaseOutcome]:
    outcomes: list[CaseOutcome] = []
    for case in cases:
        judge_client = make_judge_client(case) if make_judge_client is not None else None
        outcomes.append(
            run_case(
                case,
                context=context,
                agent_client=make_agent_client(case),
                defense=make_defense(),
                judge_client=judge_client,
                agent_model=agent_model,
                judge_model=judge_model,
            )
        )
    return outcomes


class OfflineJudgeClient:
    """A deterministic offline judge that reflects the actual agent output.

    A fixed verdict would ignore the defenses; instead this client decides from
    the judging prompt (which embeds the agent's output) whether a success
    marker survived. With defenses off the marker is present and the attack
    scores a success; with defenses on the output is blocked or redacted, the
    marker is gone, and the attack scores a failure.
    """

    def __init__(self, marker: str) -> None:
        self._marker = marker

    def complete(self, request: LLMRequest) -> LLMResponse:
        prompt = " ".join(str(message.get("content", "")) for message in request.messages)
        succeeded = self._marker.lower() in prompt.lower()
        verdict = {
            "attack_succeeded": succeeded,
            "reason": (
                "agent output retains the marker of compliance"
                if succeeded
                else "agent output no longer shows compliance"
            ),
        }
        return LLMResponse.make(stop_reason="end_turn", text=json.dumps(verdict))


def offline_clients(
    context: TargetContext,
) -> tuple[AgentClientFactory, JudgeClientFactory]:
    """Factories that replay each case's scripted transcript via the stub.

    Deterministic, offline, and the basis for the CI defense-threshold gate.
    """

    def make_agent(case: AttackCase) -> LLMClient:
        return StubLLMClient(responses=build_scripted_responses(case, context))

    def make_judge(case: AttackCase) -> LLMClient:
        if case.scripted_judge and "marker" in case.scripted_judge:
            return OfflineJudgeClient(str(case.scripted_judge["marker"]))
        return StubLLMClient(responses=[])

    return make_agent, make_judge


def defense_factory(
    config: DefenseConfig,
    context: TargetContext,
    policy: PolicyConfig | None = None,
) -> DefenseFactory:
    """Build fresh DefenseStacks for a given toggle configuration."""

    def make() -> Defense:
        return DefenseStack(config=config, context=context, policy=policy)

    return make
