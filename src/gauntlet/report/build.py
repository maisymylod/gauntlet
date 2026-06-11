"""Orchestrate a full run: off, on, per-defense, detection, and artifacts.

Deterministic and offline. Produces the report data and, on request, writes the
Markdown report, the JSON summary, the security-event logs, and one incident
report per flagged defended session under ``runs/<run_id>/``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from gauntlet.attacks.base import load_corpus
from gauntlet.attacks.runner import (
    CaseOutcome,
    defense_factory,
    offline_clients,
    run_corpus,
)
from gauntlet.config import DefenseConfig
from gauntlet.detect.detector import detect_run, flagged_sessions
from gauntlet.detect.events import SecurityEvent, events_from_outcomes, write_events
from gauntlet.detect.incident import render_incident
from gauntlet.report.render import ReportData, build_report_data, render_markdown, report_json
from gauntlet.target.base import TargetContext
from gauntlet.target.reference_agent import default_context

SINGLE_DEFENSES = {
    "input_guard": DefenseConfig(input_guard=True),
    "output_guard": DefenseConfig(output_guard=True),
    "policy_engine": DefenseConfig(policy_engine=True),
    "prompt_hardening": DefenseConfig(prompt_hardening=True),
}


@dataclass(frozen=True)
class BuiltReport:
    data: ReportData
    off_events: list[SecurityEvent]
    on_events: list[SecurityEvent]


def build(run_id: str = "local", context: TargetContext | None = None) -> BuiltReport:
    context = context or default_context()
    cases = load_corpus()
    make_agent, make_judge = offline_clients(context)

    def run(config: DefenseConfig) -> list[CaseOutcome]:
        return run_corpus(
            cases,
            context=context,
            make_agent_client=make_agent,
            make_judge_client=make_judge,
            make_defense=defense_factory(config, context),
            run_id=run_id,
            defenses_enabled=config.enabled_names(),
        )

    off = run(DefenseConfig.all_off())
    on = run(DefenseConfig.all_on())
    per_defense = {name: run(config) for name, config in SINGLE_DEFENSES.items()}

    off_events = events_from_outcomes(run_id, off)
    on_events = events_from_outcomes(run_id, on)
    data = build_report_data(
        run_id,
        off=off,
        on=on,
        per_defense_outcomes=per_defense,
        detection_off=detect_run(off_events),
        detection_on=detect_run(on_events),
    )
    return BuiltReport(data=data, off_events=off_events, on_events=on_events)


def write_artifacts(report: BuiltReport, out_dir: Path) -> Path:
    base = out_dir / report.data.run_id
    base.mkdir(parents=True, exist_ok=True)

    (base / "report.md").write_text(render_markdown(report.data), encoding="utf-8")
    (base / "summary.json").write_text(
        json.dumps(report_json(report.data), indent=2, sort_keys=True), encoding="utf-8"
    )
    write_events(base / "events_off.jsonl", report.off_events)
    write_events(base / "events_on.jsonl", report.on_events)

    incidents = base / "incidents"
    incidents.mkdir(exist_ok=True)
    events_by_session = {event.session_id: event for event in report.on_events}
    for verdict in flagged_sessions(detect_run(report.on_events)):
        event = events_by_session.get(verdict.session_id)
        if event is None:
            continue
        name = verdict.session_id.replace(":", "_")
        (incidents / f"{name}.md").write_text(render_incident(verdict, event), encoding="utf-8")

    return base


def gate_block_rate(context: TargetContext | None = None) -> float:
    """The fraction of the corpus blocked with all defenses on. Drives CI."""
    report = build(run_id="gate", context=context)
    return report.data.on.block_rate
