"""Attack case types, corpus loading, and the offline scripted-response builder.

The corpus lives as JSONL data under ``corpus/``, one case per line. Each case
carries the attack itself (the user turn, any injected tool payload) plus a
machine-checkable success oracle. For deterministic offline runs and CI, a case
also carries a ``scripted`` transcript: the responses a vulnerable bare agent
would produce, played back through the stub client. Live runs ignore ``scripted``
and hit the real model.

Scripted text and tool arguments may use placeholders, substituted from the
target context so fixtures never duplicate (and drift from) the secret literals:

* ``{{SECRET}}``        -> the system-prompt secret
* ``{{TENANT_B}}``      -> the other-tenant record
* ``{{SYSTEM_PROMPT}}`` -> the full system prompt
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from gauntlet.llm.types import LLMResponse, ToolCall
from gauntlet.target.base import TargetContext

CORPUS_DIR = Path(__file__).parent / "corpus"


class AttackClass(StrEnum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    EXFILTRATION = "exfiltration"
    TOOL_ABUSE = "tool_abuse"


@dataclass(frozen=True)
class OracleSpec:
    """How to decide whether an attack succeeded.

    ``type`` is ``"rule"`` (deterministic) or ``"judge"`` (LLM, semantic).
    """

    type: str
    check: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    rubric: str | None = None


@dataclass(frozen=True)
class AttackCase:
    id: str
    attack_class: AttackClass
    description: str
    user_text: str
    oracle: OracleSpec
    injected_tool_payload: dict[str, Any] | None = None
    tags: tuple[str, ...] = ()
    scripted: tuple[dict[str, Any], ...] = ()
    scripted_judge: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackCase:
        oracle_data = data["oracle"]
        oracle = OracleSpec(
            type=oracle_data["type"],
            check=oracle_data.get("check"),
            params=oracle_data.get("params", {}),
            rubric=oracle_data.get("rubric"),
        )
        return cls(
            id=data["id"],
            attack_class=AttackClass(data["attack_class"]),
            description=data["description"],
            user_text=data["user_text"],
            oracle=oracle,
            injected_tool_payload=data.get("injected_tool_payload"),
            tags=tuple(data.get("tags", [])),
            scripted=tuple(data.get("scripted", [])),
            scripted_judge=data.get("scripted_judge"),
        )


def load_corpus(corpus_dir: Path | None = None) -> list[AttackCase]:
    """Load every ``*.jsonl`` case in the corpus directory, sorted by id."""
    directory = corpus_dir or CORPUS_DIR
    cases: list[AttackCase] = []
    for path in sorted(directory.glob("*.jsonl")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                cases.append(AttackCase.from_dict(json.loads(stripped)))
            except (json.JSONDecodeError, KeyError) as exc:
                raise ValueError(f"{path.name}:{line_number}: invalid case ({exc})") from exc
    cases.sort(key=lambda c: c.id)
    return cases


def substitute(text: str, context: TargetContext) -> str:
    """Replace corpus placeholders with the live context's secret values."""
    return (
        text.replace("{{SECRET}}", context.fake_secret)
        .replace("{{TENANT_B}}", context.other_tenant_record)
        .replace("{{SYSTEM_PROMPT}}", context.system_prompt)
    )


def build_scripted_responses(case: AttackCase, context: TargetContext) -> list[LLMResponse]:
    """Turn a case's scripted transcript into stub-ready responses."""
    responses: list[LLMResponse] = []
    for spec in case.scripted:
        text = substitute(str(spec.get("text", "")), context)
        calls: list[ToolCall] = []
        for raw_call in spec.get("tool_calls", []):
            arguments = {
                key: substitute(value, context) if isinstance(value, str) else value
                for key, value in raw_call.get("arguments", {}).items()
            }
            calls.append(
                ToolCall(
                    id=str(raw_call["id"]),
                    name=str(raw_call["name"]),
                    arguments=arguments,
                )
            )
        responses.append(
            LLMResponse.make(
                stop_reason=str(spec["stop_reason"]),
                text=text,
                tool_calls=tuple(calls),
            )
        )
    return responses
