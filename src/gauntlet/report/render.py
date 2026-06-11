"""The attack-surface report data model and renderers (Markdown and JSON).

A report compares the corpus run with defenses off versus on, shows each
defense's individual contribution, summarizes in-flight detection on both runs,
and lists residual risk (anything still succeeding with all defenses on).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from gauntlet.attacks.runner import CaseOutcome
from gauntlet.detect.detector import AdversaryVerdict
from gauntlet.report.scoring import RunScore, summarize

MITIGATIONS = {
    "direct_injection": "Instruction hierarchy + input guard + output redaction.",
    "indirect_injection": "Treat tool output as untrusted; screen tool results; constrain egress.",
    "jailbreak": "Screen role-play and obfuscation framing on input.",
    "exfiltration": "Redact secrets, cross-tenant data, and PII; scope file reads.",
    "tool_abuse": "Deny-by-default tool policy with arg validation, allowlists, and limits.",
}


@dataclass(frozen=True)
class ReportData:
    run_id: str
    off: RunScore
    on: RunScore
    per_defense: dict[str, RunScore]
    off_residual: list[str]
    on_residual: list[str]
    detection_off_flagged: int
    detection_on_flagged: int
    detection_total: int
    detection_off_missed: list[str]
    detection_on_missed: list[str]


def build_report_data(
    run_id: str,
    *,
    off: Sequence[CaseOutcome],
    on: Sequence[CaseOutcome],
    per_defense_outcomes: Mapping[str, Sequence[CaseOutcome]],
    detection_off: Sequence[AdversaryVerdict],
    detection_on: Sequence[AdversaryVerdict],
) -> ReportData:
    return ReportData(
        run_id=run_id,
        off=summarize(off),
        on=summarize(on),
        per_defense={name: summarize(rows) for name, rows in per_defense_outcomes.items()},
        off_residual=[o.case_id for o in off if o.success],
        on_residual=[o.case_id for o in on if o.success],
        detection_off_flagged=sum(1 for v in detection_off if v.flagged),
        detection_on_flagged=sum(1 for v in detection_on if v.flagged),
        detection_total=len(detection_on),
        detection_off_missed=[v.attack_id or "?" for v in detection_off if not v.flagged],
        detection_on_missed=[v.attack_id or "?" for v in detection_on if not v.flagged],
    )


def render_markdown(data: ReportData) -> str:
    lines: list[str] = [
        f"# Attack-surface report: {data.run_id}",
        "",
        "Defensive evaluation of an agent we own. The corpus contains standard, "
        "publicly documented attack classes used to measure and harden the agent.",
        "",
        "## Headline",
        "",
        f"- Defenses off: {_rate(data.off)} of attacks succeed.",
        f"- Defenses on: {_rate(data.on)} of attacks succeed.",
        f"- Reduction: {data.off.success_rate - data.on.success_rate:.0%} fewer successful "
        "attacks with defenses on.",
        "",
        "## Per-class success (off vs on)",
        "",
        "| Attack class | Off | On |",
        "| --- | --- | --- |",
    ]
    for attack_class in sorted(data.off.by_class):
        off_class = data.off.by_class[attack_class]
        on_class = data.on.by_class.get(attack_class)
        on_rate = f"{on_class.success_rate:.0%}" if on_class else "n/a"
        lines.append(
            f"| {attack_class} | {off_class.success_rate:.0%} "
            f"({off_class.succeeded}/{off_class.total}) | {on_rate} |"
        )

    lines += [
        "",
        "## Per-defense contribution",
        "",
        "Each defense enabled alone, against the full corpus. Blocked = attacks "
        "that no longer succeed versus the bare baseline.",
        "",
        "| Defense | Blocked | Residual success |",
        "| --- | --- | --- |",
    ]
    baseline = data.off.succeeded
    for name in sorted(data.per_defense):
        score = data.per_defense[name]
        blocked = baseline - score.succeeded
        lines.append(f"| {name} | {blocked}/{baseline} | {score.success_rate:.0%} |")

    lines += [
        "",
        "## In-flight detection",
        "",
        f"- Defended run: flagged {data.detection_on_flagged}/{data.detection_total} sessions.",
        f"- Bare run: flagged {data.detection_off_flagged}/{data.detection_total} sessions.",
        f"- Bare-run misses: {', '.join(data.detection_off_missed) or 'none'}.",
        "",
        "Detection reasons only from observable signals (guard trips, risky tool "
        "arguments, sensitive output), not the success oracle, so it runs the same "
        "way in production.",
        "",
        "## Residual risk",
        "",
        f"- With all defenses on: {', '.join(data.on_residual) or 'no attacks succeed'}.",
        "",
        "## Recommended mitigations",
        "",
    ]
    for attack_class in sorted(MITIGATIONS):
        lines.append(f"- **{attack_class}**: {MITIGATIONS[attack_class]}")

    lines += ["", "## Scope", "", _SCOPE, ""]
    return "\n".join(lines)


def report_json(data: ReportData) -> dict[str, Any]:
    return {
        "run_id": data.run_id,
        "off": _score_json(data.off),
        "on": _score_json(data.on),
        "reduction": round(data.off.success_rate - data.on.success_rate, 4),
        "per_defense": {name: _score_json(score) for name, score in data.per_defense.items()},
        "residual_on": data.on_residual,
        "detection": {
            "total": data.detection_total,
            "flagged_on": data.detection_on_flagged,
            "flagged_off": data.detection_off_flagged,
            "missed_off": data.detection_off_missed,
            "missed_on": data.detection_on_missed,
        },
    }


def _score_json(score: RunScore) -> dict[str, Any]:
    return {
        "total": score.total,
        "succeeded": score.succeeded,
        "success_rate": round(score.success_rate, 4),
        "block_rate": round(score.block_rate, 4),
        "by_class": {
            name: {"total": cs.total, "succeeded": cs.succeeded}
            for name, cs in score.by_class.items()
        },
    }


def _rate(score: RunScore) -> str:
    return f"{score.success_rate:.0%} ({score.succeeded}/{score.total})"


_SCOPE = (
    "The corpus evaluates the robustness of an agent the operator owns. It uses "
    "standard, publicly documented attack classes for defensive evaluation, does "
    "not target third-party systems, and includes no novel exploit weaponization."
)
