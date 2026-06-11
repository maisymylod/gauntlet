"""Output guard: redact secrets, cross-tenant data, and PII before output leaves.

It knows the operator's own sensitive strings (the system-prompt secret, the
other-tenant record, the full system prompt) and redacts any occurrence in the
agent's outgoing text, plus a generic PII pass for emails and long digit runs.
It does not block; it redacts, so a leak attempt returns a scrubbed reply.
"""

from __future__ import annotations

import re

from gauntlet.target.base import GuardDecision, TargetContext

REDACTION = "[REDACTED]"

PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email
    re.compile(r"\b\d{13,19}\b"),  # long digit run (card-like)
)


class OutputGuard:
    """Redacts known sensitive strings and PII from outgoing text."""

    def __init__(self, context: TargetContext) -> None:
        # Redact the longest known secrets first so substrings do not leak.
        self._secrets = sorted(
            (context.system_prompt, context.other_tenant_record, context.fake_secret),
            key=len,
            reverse=True,
        )

    def redact(self, text: str) -> tuple[str, GuardDecision]:
        redacted = text
        for secret in self._secrets:
            if secret and secret in redacted:
                redacted = redacted.replace(secret, REDACTION)
        for pattern in PII_PATTERNS:
            redacted = pattern.sub(REDACTION, redacted)
        if redacted != text:
            return redacted, GuardDecision(
                allowed=True, verdict="flagged", reason="redacted sensitive content"
            )
        return text, GuardDecision(allowed=True, verdict="clean")
