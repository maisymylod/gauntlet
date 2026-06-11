"""Tests for the CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from gauntlet.cli import main


def test_gate_passes_at_default_threshold(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["gate"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_gate_fails_above_full_block(capsys: pytest.CaptureFixture[str]) -> None:
    # Nothing can block more than 100%, so a threshold over 1.0 must fail.
    assert main(["gate", "--threshold", "1.01"]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_run_writes_artifacts_then_report_prints(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["run", "--run-id", "clitest", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "clitest" / "report.md").exists()
    capsys.readouterr()

    assert main(["report", "--run-id", "clitest", "--out", str(tmp_path)]) == 0
    assert "Attack-surface report: clitest" in capsys.readouterr().out


def test_report_missing_run_is_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["report", "--run-id", "nope", "--out", str(tmp_path)]) == 1
