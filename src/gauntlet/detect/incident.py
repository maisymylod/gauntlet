"""Render a human-readable incident report for a flagged session."""

from __future__ import annotations

from .detector import AdversaryVerdict
from .events import SecurityEvent

MITIGATIONS = {
    "direct_injection": (
        "Enforce instruction hierarchy (operator over user), screen user turns "
        "with the input guard, and redact secrets on output."
    ),
    "indirect_injection": (
        "Treat tool results and fetched content as untrusted data; screen tool "
        "results before they reach the model and constrain tool egress."
    ),
    "jailbreak": (
        "Screen for role-play and obfuscation framing on input; do not rely on "
        "the model refusing on its own."
    ),
    "exfiltration": (
        "Redact secrets, cross-tenant data, and PII on output; scope file reads "
        "to the current tenant."
    ),
    "tool_abuse": (
        "Apply deny-by-default tool policy with per-argument validation, host "
        "allowlisting, and rate and recursion limits."
    ),
}


def render_incident(verdict: AdversaryVerdict, event: SecurityEvent) -> str:
    label = verdict.attack_class or "unknown"
    lines = [
        f"# Incident: session {verdict.session_id}",
        "",
        f"- Severity: {verdict.severity}",
        f"- Suspected attack class: {label}",
        f"- Case id: {verdict.attack_id or 'n/a'}",
        f"- Defenses enabled: {', '.join(event.defenses_enabled) or 'none'}",
        f"- Signals: {', '.join(verdict.signals) or 'none'}",
        "",
        "## Guard timeline",
        f"- input guard: {event.input_verdict}",
    ]
    for call in event.tool_calls:
        status = "allowed" if call.allowed else "blocked"
        lines.append(f"- tool call {call.name}({_fmt_args(call.arguments)}): {status}")
    for index, verdict_value in enumerate(event.tool_result_verdicts):
        lines.append(f"- tool result #{index}: {verdict_value}")
    lines.append(f"- output guard: {event.output_verdict}")
    lines.append(f"- turn blocked: {event.blocked}")
    lines += [
        "",
        "## Outcome",
        f"- attack succeeded: {event.oracle_success}",
        f"- oracle note: {event.oracle_rationale or 'n/a'}",
        f"- output excerpt: {event.output_excerpt!r}",
        "",
        "## Recommended mitigation",
        MITIGATIONS.get(label, "Review the session manually."),
    ]
    return "\n".join(lines)


def _fmt_args(arguments: dict[str, object]) -> str:
    return ", ".join(f"{key}={value!r}" for key, value in arguments.items())
