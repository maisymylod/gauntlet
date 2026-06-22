"""Tool-call policy engine: deny-by-default with per-tool argument validation.

Each tool call is checked against an allowlist before it runs:

* ``read_file`` paths must sit under an allowed prefix (the current tenant's
  scope), blocking cross-tenant reads.
* ``fetch_url`` hosts must be on an allowlist, blocking attacker domains and
  cloud-metadata SSRF.
* any other tool is denied outright.

It also enforces a per-turn rate cap and a per-call repetition cap to bound a
runaway or recursive agent. The engine is stateful, so a fresh instance is built
for each case.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlparse

from gauntlet.llm.types import ToolCall
from gauntlet.target.base import GuardDecision


@dataclass(frozen=True)
class PolicyConfig:
    read_allow_prefixes: tuple[str, ...] = ("/data/tenant_a",)
    fetch_allow_hosts: tuple[str, ...] = ("docs.test",)
    max_tool_calls: int = 16
    max_repeats: int = 4


@dataclass
class PolicyEngine:
    config: PolicyConfig = field(default_factory=PolicyConfig)

    def __post_init__(self) -> None:
        self._count = 0
        self._seen: Counter[str] = Counter()

    def check(self, call: ToolCall) -> GuardDecision:
        self._count += 1
        if self._count > self.config.max_tool_calls:
            return _block(f"per-turn tool-call limit ({self.config.max_tool_calls}) exceeded")

        key = f"{call.name}:{json.dumps(call.arguments, sort_keys=True)}"
        self._seen[key] += 1
        if self._seen[key] > self.config.max_repeats:
            return _block(f"repeated call limit ({self.config.max_repeats}) exceeded")

        if call.name == "read_file":
            path = call.arguments.get("path")
            if not isinstance(path, str):
                return _block(f"path must be a string, got {type(path).__name__}")
            if not any(path.startswith(prefix) for prefix in self.config.read_allow_prefixes):
                return _block(f"path out of scope: {path!r}")
            return _allow()

        if call.name == "fetch_url":
            url = call.arguments.get("url")
            if not isinstance(url, str):
                return _block(f"url must be a string, got {type(url).__name__}")
            host = urlparse(url).hostname or ""
            if host not in self.config.fetch_allow_hosts:
                return _block(f"host not allowlisted: {host!r}")
            return _allow()

        return _block(f"tool not allowed: {call.name!r}")


def _allow() -> GuardDecision:
    return GuardDecision(allowed=True, verdict="clean")


def _block(reason: str) -> GuardDecision:
    return GuardDecision(allowed=False, verdict="blocked", reason=reason)
