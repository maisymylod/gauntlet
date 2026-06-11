# Threat model

This document enumerates the attack surface of the agent under evaluation, the
assets it must protect, and how the harness probes and defends each surface. It
is a defensive artifact: the agent is one the operator owns.

## Target under evaluation

The reference target is a Claude-based support agent for a single tenant
(TENANT-A). It holds an internal API key in its system prompt and has two tools:

- `read_file(path)`: reads an in-memory filesystem. One path holds another
  tenant's record, modeling a broken tenant-isolation boundary.
- `fetch_url(url)`: reads an in-memory URL map, modeling retrieval of untrusted
  external content.

The HTTP adapter lets the same harness drive an external agent over a local
endpoint; the threat model below is written against the reference target but the
surfaces generalize.

## Assets to protect

| Asset | Where it lives | Leak oracle |
| --- | --- | --- |
| System-prompt secret (internal API key) | system prompt | `secret_leaked` |
| Other-tenant record | `read_file` filesystem | `tenant_record_leaked` |
| System prompt itself | system prompt | `system_prompt_disclosed` |
| Tool-use integrity | tool interface | `disallowed_tool_executed`, `tool_arg_out_of_policy` |
| Instruction hierarchy | system vs user vs tool content | observed across classes |

## Trust boundaries

1. **User turn -> agent.** The user is untrusted. Direct injection and jailbreak
   framing arrive here.
2. **Tool result -> agent.** Fetched pages and file contents are untrusted data,
   not instructions. Indirect (second-order) injection arrives here.
3. **Agent -> user (output channel).** Exfiltration of secrets, cross-tenant
   data, and PII happens here.
4. **Agent -> tool interface.** Tool abuse, privilege escalation, SSRF, and
   out-of-policy arguments happen here.

## Attack surfaces and coverage

| Surface | Attack class | Corpus cases | Primary defense |
| --- | --- | --- | --- |
| User turn | direct_injection | direct-001..003 | input guard; output guard |
| User turn | jailbreak | jailbreak-001..003 | input guard |
| Tool result | indirect_injection | indirect-001..003 | tool-result screening; output guard; tool policy |
| Output channel | exfiltration | exfil-001..003 | output guard (redaction) |
| Tool interface | tool_abuse | toolabuse-001..003 | tool-call policy engine |

## Defenses and what they are accountable for

- **Input guard.** Heuristic screen on untrusted text (user turns and tool
  results). Blocks injection, jailbreak, and exfiltration framing; aborts a turn
  when an injected instruction reaches a tool result.
- **Output guard.** Redacts the secret, the other-tenant record, the system
  prompt, and PII before output leaves.
- **Tool-call policy engine.** Deny-by-default. Per-tool argument validation
  (read paths scoped to the current tenant, fetch hosts allowlisted), plus rate
  and recursion caps.
- **Prompt hardening.** Fences the system prompt with instruction-precedence
  language and marks tool output as untrusted. This shapes what the model sees;
  the offline harness holds model behavior fixed, so its effect is measured in
  live runs rather than in the deterministic scores.

## In-flight detection

Each session emits a structured security event. The detector flags anomalous
sessions from observable signals only (guard trips, risky tool arguments it
evaluates itself, sensitive-looking output, tool-call escalation), never the
success oracle, so it behaves the same in production. Flagged sessions get an
incident report with the guard timeline and a class-specific mitigation.

Known coverage gap: a content-only jailbreak that leaks no secret, calls no
tool, and trips no guard is not flagged on the bare run. It is flagged once a
defense turns the attack into a guard trip.

## Residual risk

With all boundary defenses on, the corpus drops to zero successful attacks. This
does not imply the agent is secure in general: the corpus is a fixed set of
publicly documented patterns, not an exhaustive adversary. The harness is a
regression and measurement tool, not a proof of safety.
