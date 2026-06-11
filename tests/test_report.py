"""Tests for the report build, renderers, artifacts, and the gate."""

from __future__ import annotations

import json
from pathlib import Path

from gauntlet.report.build import build, gate_block_rate, write_artifacts
from gauntlet.report.render import render_markdown, report_json


def test_build_shows_full_drop() -> None:
    data = build("test").data
    assert data.off.success_rate == 1.0
    assert data.on.success_rate == 0.0
    assert data.on_residual == []
    assert set(data.per_defense) == {
        "input_guard",
        "output_guard",
        "policy_engine",
        "prompt_hardening",
    }


def test_detection_summary_in_report() -> None:
    data = build("test").data
    assert data.detection_on_flagged == data.detection_total == 15
    assert "jailbreak-002" in data.detection_off_missed


def test_render_markdown_has_sections() -> None:
    md = render_markdown(build("test").data)
    assert "# Attack-surface report: test" in md
    assert "## Per-class success" in md
    assert "## Per-defense contribution" in md
    assert "## In-flight detection" in md
    assert "## Residual risk" in md


def test_report_json_structure() -> None:
    payload = report_json(build("test").data)
    assert payload["reduction"] == 1.0
    assert payload["on"]["block_rate"] == 1.0
    assert payload["off"]["success_rate"] == 1.0
    assert set(payload["per_defense"]) == {
        "input_guard",
        "output_guard",
        "policy_engine",
        "prompt_hardening",
    }
    # The JSON summary must round-trip.
    assert json.loads(json.dumps(payload))["run_id"] == "test"


def test_gate_block_rate_is_full() -> None:
    assert gate_block_rate() == 1.0


def test_write_artifacts(tmp_path: Path) -> None:
    report = build("arttest")
    base = write_artifacts(report, tmp_path)
    assert (base / "report.md").exists()
    assert (base / "summary.json").exists()
    assert (base / "events_off.jsonl").exists()
    assert (base / "events_on.jsonl").exists()
    # Every defended session is flagged, so every session gets an incident report.
    incidents = list((base / "incidents").glob("*.md"))
    assert len(incidents) == 15
    summary = json.loads((base / "summary.json").read_text(encoding="utf-8"))
    assert summary["on"]["succeeded"] == 0
