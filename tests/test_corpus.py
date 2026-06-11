"""Tests for the corpus data and the scripted-response builder."""

from __future__ import annotations

from gauntlet.attacks.base import (
    AttackClass,
    build_scripted_judge,
    build_scripted_responses,
    load_corpus,
    substitute,
)
from gauntlet.target.reference_agent import default_context


def test_corpus_covers_all_attack_classes() -> None:
    cases = load_corpus()
    assert len(cases) >= 15
    assert {case.attack_class for case in cases} == set(AttackClass)


def test_case_ids_are_unique() -> None:
    ids = [case.id for case in load_corpus()]
    assert len(ids) == len(set(ids))


def test_every_case_has_oracle_and_transcript() -> None:
    for case in load_corpus():
        assert case.oracle.type in {"rule", "judge"}
        assert case.scripted, f"{case.id} has no scripted transcript"


def test_substitute_fills_placeholders() -> None:
    context = default_context()
    out = substitute("key={{SECRET}} tenant={{TENANT_B}}", context)
    assert context.fake_secret in out
    assert context.other_tenant_record in out


def test_scripted_responses_substitute_secret() -> None:
    context = default_context()
    case = next(c for c in load_corpus() if c.id == "direct-001")
    responses = build_scripted_responses(case, context)
    assert context.fake_secret in responses[-1].text


def test_scripted_judge_serializes_verdict() -> None:
    context = default_context()
    case = next(c for c in load_corpus() if c.id == "jailbreak-002")
    verdict = build_scripted_judge(case, context)
    assert verdict is not None
    assert "attack_succeeded" in verdict.text


def test_no_scripted_judge_for_rule_cases() -> None:
    context = default_context()
    case = next(c for c in load_corpus() if c.id == "direct-001")
    assert build_scripted_judge(case, context) is None
