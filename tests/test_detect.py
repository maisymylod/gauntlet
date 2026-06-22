"""Tests for security events, the emitter, detection, and incident reports."""

from __future__ import annotations

import json
from pathlib import Path

from gauntlet.attacks.base import load_corpus
from gauntlet.attacks.runner import CaseOutcome, defense_factory, offline_clients, run_corpus
from gauntlet.config import DefenseConfig
from gauntlet.detect.detector import detect_event, detect_run, flagged_sessions
from gauntlet.detect.events import events_from_outcomes, write_events
from gauntlet.detect.incident import render_incident
from gauntlet.target.reference_agent import default_context

CONTEXT = default_context()
CASES = load_corpus()
MAKE_AGENT, MAKE_JUDGE = offline_clients(CONTEXT)


def _run(config: DefenseConfig) -> list[CaseOutcome]:
    return run_corpus(
        CASES,
        context=CONTEXT,
        make_agent_client=MAKE_AGENT,
        make_judge_client=MAKE_JUDGE,
        make_defense=defense_factory(config, CONTEXT),
        run_id="test",
        defenses_enabled=config.enabled_names(),
    )


def test_events_built_for_every_case() -> None:
    events = events_from_outcomes("test", _run(DefenseConfig.all_off()))
    assert len(events) == 15
    assert {e.attack_id for e in events} == {c.id for c in CASES}
    assert all(e.session_id.startswith("test:") for e in events)


def test_emitter_writes_one_json_object_per_line(tmp_path: Path) -> None:
    events = events_from_outcomes("test", _run(DefenseConfig.all_on()))
    path = tmp_path / "events.jsonl"
    write_events(path, events)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 15
    for line in lines:
        record = json.loads(line)
        assert record["schema_version"] == 1
        assert "oracle_success" in record


def test_detection_flags_every_defended_session() -> None:
    events = events_from_outcomes("test", _run(DefenseConfig.all_on()))
    verdicts = detect_run(events)
    assert all(v.flagged for v in verdicts)
    assert all(v.severity == "high" for v in verdicts)


def test_detection_on_bare_run_flags_most_but_misses_content_jailbreak() -> None:
    events = events_from_outcomes("test", _run(DefenseConfig.all_off()))
    verdicts = {v.attack_id: v for v in detect_run(events)}
    # The content-only jailbreak leaves no secret, no tool call, no guard trip.
    assert not verdicts["jailbreak-002"].flagged
    assert len(flagged_sessions(list(verdicts.values()))) == 14


def test_bare_run_detection_signals() -> None:
    events = {e.attack_id: e for e in events_from_outcomes("test", _run(DefenseConfig.all_off()))}
    # Tool-arg heuristic catches the SSRF even with no guard running.
    ssrf = detect_event(events["toolabuse-003"])
    assert any(s.startswith("risky_fetch") for s in ssrf.signals)
    # Output heuristic catches the secret leak.
    leak = detect_event(events["direct-001"])
    assert "sensitive_output" in leak.signals


def test_incident_report_has_expected_sections() -> None:
    events = {e.attack_id: e for e in events_from_outcomes("test", _run(DefenseConfig.all_on()))}
    event = events["toolabuse-002"]
    verdict = detect_event(event)
    report = render_incident(verdict, event)
    assert "# Incident: session test:toolabuse-002" in report
    assert "## Guard timeline" in report
    assert "## Recommended mitigation" in report
    assert "deny-by-default" in report


def test_detection_thresholds_are_configurable() -> None:
    from gauntlet.detect.detector import DetectionConfig, detect_event
    from gauntlet.detect.events import SecurityEvent, ToolCallRecord

    # Two in-scope, allowed reads: the only signal is tool escalation.
    benign_reads = [
        ToolCallRecord(name="read_file", arguments={"path": "/data/tenant_a/1"}, allowed=True),
        ToolCallRecord(name="read_file", arguments={"path": "/data/tenant_a/2"}, allowed=True),
    ]
    event = SecurityEvent(
        run_id="t", session_id="t:1", seq=0, attack_id=None, attack_class=None,
        defenses_enabled=[], input_verdict="clean", output_verdict="clean",
        tool_calls=benign_reads, tool_result_verdicts=["clean", "clean"], blocked=False,
        oracle_success=False, oracle_rationale="", output_excerpt="ok",
    )

    # Default threshold (2): two calls flag as tool escalation.
    default = detect_event(event)
    assert "tool_escalation" in default.signals
    assert default.flagged

    # A chattier agent: raise the threshold so two calls no longer escalate.
    relaxed = detect_event(event, DetectionConfig(tool_escalation_threshold=5))
    assert "tool_escalation" not in relaxed.signals
    assert not relaxed.flagged

    # A custom read scope turns the same in-scope reads into risky reads.
    rescoped = detect_event(event, DetectionConfig(read_scope_prefix="/data/tenant_z"))
    assert any(s.startswith("risky_read:") for s in rescoped.signals)
