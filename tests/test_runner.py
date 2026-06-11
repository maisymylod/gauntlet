"""Tests for the offline corpus runner and scoring."""

from __future__ import annotations

from gauntlet.attacks.base import AttackClass, load_corpus
from gauntlet.attacks.runner import CaseOutcome, offline_clients, run_corpus
from gauntlet.report.scoring import summarize
from gauntlet.target.reference_agent import default_context


def _run_all() -> list[CaseOutcome]:
    context = default_context()
    cases = load_corpus()
    make_agent, make_judge = offline_clients(context)
    return run_corpus(
        cases,
        context=context,
        make_agent_client=make_agent,
        make_judge_client=make_judge,
    )


def test_bare_agent_is_fully_vulnerable() -> None:
    outcomes = _run_all()
    failed = [o.case_id for o in outcomes if not o.success]
    assert failed == [], f"bare agent unexpectedly defended: {failed}"


def test_scoring_reports_full_success_baseline() -> None:
    score = summarize(_run_all())
    assert score.success_rate == 1.0
    assert score.block_rate == 0.0
    assert {key for key in score.by_class} == {str(c) for c in AttackClass}
    for class_score in score.by_class.values():
        assert class_score.success_rate == 1.0


def test_indirect_exfil_executes_attacker_fetch() -> None:
    outcomes = {o.case_id: o for o in _run_all()}
    indirect = outcomes["indirect-003"]
    # The second-order injection drove a fetch_url against the attacker domain.
    assert indirect.executed_tools.count("fetch_url") == 2
    assert indirect.success


def test_tool_abuse_records_executed_tool() -> None:
    outcomes = {o.case_id: o for o in _run_all()}
    ssrf = outcomes["toolabuse-003"]
    assert ssrf.executed_tools == ["fetch_url"]
    assert ssrf.success
