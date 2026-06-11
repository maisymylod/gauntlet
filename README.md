# gauntlet

Adversarial test and defense harness for LLM agents. gauntlet puts an agent you
own through a battery of publicly documented attack classes, applies a
configurable defense stack, detects attacks in flight, and emits an
attack-surface report.

This is defensive security tooling. Everything here probes and hardens an agent
the operator controls. See [Defensive scope](#defensive-scope).

> Status: in development. Phase 1 (scaffold, LLM client, target adapters, CLI
> skeleton) is in place. Phases 2 to 5 add the attack library, defense stack,
> in-flight detection, and the scoring report.

## What it does

Five components, built in phases:

1. **Target adapter** (`gauntlet/target/`): wraps any agent so the harness can
   drive it. Ships a deliberately under-defended Claude reference agent (two
   tools, a fake secret, a fake other-tenant record) and an HTTP adapter that
   points the harness at an existing agent over a local endpoint.
2. **Attack library** (`gauntlet/attacks/`): direct injection, indirect
   injection, jailbreak, data exfiltration, and tool abuse, as a data corpus
   with a machine-checkable success oracle per case.
3. **Defense stack** (`gauntlet/defense/`): input guard, output guard, tool-call
   policy engine, and a system-prompt hardening helper. Each is independently
   toggleable so its effect can be measured alone.
4. **Detection and incident response** (`gauntlet/detect/`): a structured
   security event per turn, an adversary-detection pass over a session, and a
   human-readable incident report.
5. **Scoring and report** (`gauntlet/report/`): runs the corpus with defenses
   off, then on, and produces a Markdown report plus a JSON summary.

## Why this exists (gap mapping)

This project extends genuine agent-engineering experience into agent security:
attacking agents, defending them, and detecting attacks in flight.

| JD signal | Already have | What this repo adds |
| --- | --- | --- |
| Solutions with LLMs / LLM-based agents | yes (production agent stack) | the security layer on top |
| Software engineering, ownership | yes (sole engineer on full stack) | a clean, tested security library |
| Security solutions for systems/infra | partial (authN, CORS, tenant isolation, auth debugging) | formalized into a policy + detection engine |
| Agent engineering and security | gap | core of the project |
| LLM attack surfaces | gap | structured attack-surface model + corpus |
| Red-teaming: prompt injection, jailbreak, exfil | gap | the attack library + success oracles |
| Securing long-running autonomous agents | gap | tool-call policy engine + guards |
| Incident response / adversary detection | gap | session security events + detection + reports |
| Deploying/managing LLMs reliably | partial | LLM judge + guard models wired with retries/limits |

## Defensive scope

The attack corpus exists to evaluate the robustness of an agent the operator
owns. It contains standard, publicly documented attack classes used for
defensive evaluation. It does not target third-party systems and does not
include novel exploit weaponization. Use it on your own agents.

## Install

gauntlet runs offline for development and CI. The Anthropic SDK is only needed
for live runs against the reference agent.

```bash
pip install -e ".[dev]"        # tests, lint, type-check (no network)
pip install -e ".[dev,live]"   # also install the Anthropic SDK for live runs
```

## Develop

```bash
ruff check .
mypy
pytest
```

The full test suite runs with no network access: every model call goes through
a stub client that serves recorded responses and raises on any unmatched
request.

## Architecture notes

- All model access goes through one `LLMClient` (`gauntlet/llm/`). The real
  client wraps the Anthropic Messages API with a timeout and retries; the stub
  client serves recorded responses for offline tests.
- A `Target` is anything the harness can drive one user turn at a time. Defenses
  plug in through a `Defense` seam wrapped around each turn, so the agent loop is
  stable across phases.
