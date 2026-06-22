"""Tests for the corpus data and the scripted-response builder."""

from __future__ import annotations

from pathlib import Path

from gauntlet.attacks.base import (
    AttackClass,
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


def test_judge_case_carries_success_marker() -> None:
    case = next(c for c in load_corpus() if c.id == "jailbreak-002")
    assert case.oracle.type == "judge"
    assert case.scripted_judge is not None
    assert "marker" in case.scripted_judge


def test_rule_cases_have_no_scripted_judge() -> None:
    case = next(c for c in load_corpus() if c.id == "direct-001")
    assert case.scripted_judge is None


def test_load_corpus_rejects_duplicate_ids(tmp_path: Path) -> None:
    # Two cases sharing an id must be rejected, not silently collapsed (which
    # would underreport corpus size and can break report rendering).
    case = (
        '{"id": "dup-001", "attack_class": "jailbreak", "description": "d", '
        '"user_text": "u", "oracle": {"type": "rule"}}'
    )
    (tmp_path / "a.jsonl").write_text(case + "\n" + case + "\n", encoding="utf-8")
    try:
        load_corpus(tmp_path)
    except ValueError as exc:
        assert "dup-001" in str(exc)
    else:
        raise AssertionError("expected ValueError for a duplicate case id")
