"""Structured security events and a JSONL emitter.

Each case-session produces one :class:`SecurityEvent`: a flat, serializable
record of what the guards saw and how the case resolved. Events are the input to
the adversary-detection pass and the audit trail an operator would keep.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from gauntlet.attacks.runner import CaseOutcome

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    allowed: bool


@dataclass(frozen=True)
class SecurityEvent:
    run_id: str
    session_id: str
    seq: int
    attack_id: str | None
    attack_class: str | None
    defenses_enabled: list[str]
    input_verdict: str
    output_verdict: str
    tool_calls: list[ToolCallRecord]
    tool_result_verdicts: list[str]
    blocked: bool
    oracle_success: bool
    oracle_rationale: str
    output_excerpt: str
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _verdict_for(guard_log: list[dict[str, Any]], stage: str) -> str:
    for entry in guard_log:
        if entry.get("stage") == stage:
            decision = entry.get("decision", {})
            return str(decision.get("verdict", "clean"))
    return "clean"


def event_from_outcome(run_id: str, outcome: CaseOutcome) -> SecurityEvent:
    guard_log = outcome.guard_log
    tool_calls = [
        ToolCallRecord(
            name=str(entry.get("tool", "")),
            arguments=dict(entry.get("arguments", {})),
            allowed=bool(entry.get("decision", {}).get("allowed", True)),
        )
        for entry in guard_log
        if entry.get("stage") == "tool"
    ]
    tool_result_verdicts = [
        str(entry.get("decision", {}).get("verdict", "clean"))
        for entry in guard_log
        if entry.get("stage") == "tool_result"
    ]
    return SecurityEvent(
        run_id=run_id,
        session_id=outcome.session_id,
        seq=0,
        attack_id=outcome.case_id,
        attack_class=outcome.attack_class,
        defenses_enabled=list(outcome.defenses_enabled),
        input_verdict=_verdict_for(guard_log, "input"),
        output_verdict=_verdict_for(guard_log, "output"),
        tool_calls=tool_calls,
        tool_result_verdicts=tool_result_verdicts,
        blocked=outcome.blocked,
        oracle_success=outcome.success,
        oracle_rationale=outcome.rationale,
        output_excerpt=outcome.output_text[:200],
    )


def events_from_outcomes(run_id: str, outcomes: Sequence[CaseOutcome]) -> list[SecurityEvent]:
    return [event_from_outcome(run_id, outcome) for outcome in outcomes]


@dataclass
class JsonlEmitter:
    """Append-only JSONL writer for security events."""

    path: Path
    _lines: list[str] = field(default_factory=list)

    def emit(self, event: SecurityEvent) -> None:
        self._lines.append(json.dumps(event.to_dict(), sort_keys=True))

    def flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(self._lines) + ("\n" if self._lines else ""), "utf-8")


def write_events(path: Path, events: Sequence[SecurityEvent]) -> None:
    emitter = JsonlEmitter(path)
    for event in events:
        emitter.emit(event)
    emitter.flush()
