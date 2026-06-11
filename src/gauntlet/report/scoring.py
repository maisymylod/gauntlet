"""Aggregate per-case outcomes into per-class and overall success rates.

A run's "success rate" is the fraction of attacks that succeeded, so lower is
better. Phase 5 compares two runs (defenses off vs on) to show the drop and to
drive the CI gate.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from gauntlet.attacks.runner import CaseOutcome


@dataclass(frozen=True)
class ClassScore:
    attack_class: str
    total: int
    succeeded: int

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.total if self.total else 0.0


@dataclass(frozen=True)
class RunScore:
    total: int
    succeeded: int
    by_class: dict[str, ClassScore]

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.total if self.total else 0.0

    @property
    def block_rate(self) -> float:
        """Fraction of attacks that did not succeed (defended or ineffective)."""
        return 1.0 - self.success_rate


def summarize(outcomes: Sequence[CaseOutcome]) -> RunScore:
    by_class: dict[str, ClassScore] = {}
    classes = sorted({outcome.attack_class for outcome in outcomes})
    for attack_class in classes:
        rows = [o for o in outcomes if o.attack_class == attack_class]
        succeeded = sum(1 for o in rows if o.success)
        by_class[attack_class] = ClassScore(attack_class, len(rows), succeeded)
    total = len(outcomes)
    succeeded = sum(1 for o in outcomes if o.success)
    return RunScore(total=total, succeeded=succeeded, by_class=by_class)


def format_summary(label: str, score: RunScore) -> str:
    lines = [f"{label}: {score.succeeded}/{score.total} attacks succeeded "
             f"({score.success_rate:.0%} success, {score.block_rate:.0%} blocked)"]
    for attack_class, class_score in score.by_class.items():
        lines.append(
            f"  {attack_class:<20} {class_score.succeeded}/{class_score.total} "
            f"({class_score.success_rate:.0%})"
        )
    return "\n".join(lines)
