# How It Works

Every tool call your agent makes passes through Edictum's pipeline before it executes. The pipeline evaluates YAML contracts against the call's arguments, principal, and session state. If any contract fails, the call is denied and never reaches the tool. This is a hard boundary -- the LLM cannot reason its way past it.

```
Agent decides to call tool
        |
  +--------------+
  |   Edictum    |
  |   Pipeline   |
  +--------------+
  | Preconditions | <-- YAML contracts checked BEFORE execution
  | Session limits|
  | Principal     |
  +------+-------+
         | ALLOW / DENY
         v
    Tool executes (only if allowed)
         |
  +--------------+
  |Postconditions| <-- Output checked AFTER execution
  | Audit event  | --> OTel / stdout
  +--------------+
```

## When to use this

Read this page when you need to understand why a tool call was denied or allowed. It walks through the full pipeline evaluation order -- attempt limits, hooks, preconditions, session contracts, execution limits, tool execution, postconditions -- so you can trace exactly where a decision was made. This is also the starting point for explaining Edictum to a new team member: every tool call passes through the pipeline, contracts are checked deterministically in Python (not in the LLM), and the call is either allowed or denied before the tool runs.

## A Denied Call: Step by Step

An agent tries to read `.env` using the `read_file` tool. Here is what happens:

**1. Agent decides to call `read_file` with `{"path": ".env"}`.**

The framework adapter intercepts the call and builds a `ToolEnvelope` -- a frozen snapshot of the tool name, arguments, and principal.

**2. Edictum evaluates preconditions.**

The pipeline checks the contract bundle. This contract matches:

```yaml
- id: block-dotenv
  type: pre
  tool: read_file
  when:
    args.path: { contains: ".env" }
  then:
    effect: deny
    message: "Read of sensitive file denied: {args.path}"
```

The `args.path` value is `".env"`. The `contains` operator finds `".env"` in the string. The contract fires.

**3. The call is denied.**

The pipeline returns a `PreDecision` with `action: "deny"`. The tool function never executes. The agent receives the denial message: `"Read of sensitive file denied: .env"`.

**4. An audit event is emitted.**

An `AuditEvent` with `action: CALL_DENIED` is written to all configured sinks (stdout, file, OpenTelemetry). The event records the tool name, arguments, principal, which contract fired, and the policy version hash.

The `.env` file was never read. The agent sees the denial and can try a different approach.

## An Approval Gate: Step by Step

An agent calls `delete_records` with `{"table": "users", "query": "WHERE inactive = true"}`. A precondition with `effect: approve` is configured.

**1. Agent decides to call `delete_records`.**

The adapter intercepts the call and builds a `ToolEnvelope`.

**2. Edictum evaluates preconditions.**

The pipeline finds a matching contract with `effect: approve`. Instead of denying immediately, it returns `PreDecision` with `action: "pending_approval"`.

**3. The pipeline requests human approval.**

The `approval_backend.request_approval()` method is called. A `CALL_APPROVAL_REQUESTED` audit event is emitted. The pipeline then calls `approval_backend.wait_for_decision()` and blocks until a decision arrives or the timeout expires.

**4a. If approved:** The tool executes normally. A `CALL_APPROVAL_GRANTED` audit event is emitted and `on_allow` fires.

**4b. If denied:** `EdictumDenied` is raised. A `CALL_APPROVAL_DENIED` audit event is emitted and `on_deny` fires.

**4c. If timeout:** The `timeout_effect` determines the outcome. Default is `deny` (raises `EdictumDenied`). A `CALL_APPROVAL_TIMEOUT` audit event is emitted.

## An Allowed Call: Step by Step

The same agent calls `read_file` with `{"path": "config.txt"}`.

**1. Agent decides to call `read_file` with `{"path": "config.txt"}`.**

The adapter intercepts and builds the envelope.

**2. Edictum evaluates preconditions.**

The `block-dotenv` contract checks `args.path` for `".env"`. The value is `"config.txt"` -- no match. All other preconditions pass. Session limits are within bounds.

**3. The call is allowed.**

The pipeline returns `PreDecision` with `action: "allow"`. The tool function executes and returns the file contents.

**4. Edictum evaluates postconditions.**

The pipeline checks the tool's output against postcondition contracts. For example, a PII detection contract scans the output for SSN patterns. If a pattern matches, the contract produces a [finding](../findings.md). For READ/PURE tools, postconditions with `effect: redact` replace matched patterns in the output with `[REDACTED]`, and `effect: deny` suppresses the output entirely. For WRITE/IRREVERSIBLE tools, effects fall back to `warn` because the action already happened. See [postcondition effects](../contracts/yaml-reference.md#postcondition-effects).

**5. An audit event is emitted.**

An `AuditEvent` with `action: CALL_EXECUTED` is written. It includes the tool name, arguments, whether postconditions passed, any findings, and the policy version hash.

## Why This Is Deterministic

Contracts are code evaluated against arguments. The expression grammar supports string matching, regex, numeric comparisons, and membership checks -- all evaluated by Python at runtime, outside the LLM.

A precondition like `args.path: { contains: ".env" }` will always deny when the path contains `.env`. It does not matter what the LLM was told in its system prompt, how long the conversation has been, or how creatively the agent argues. The check runs in Python, not in the model.

This is the difference between a prompt instruction ("do not read .env files") and a contract. The prompt is a suggestion. The contract is enforcement.

## Shadow Contracts (Dual-Mode Evaluation)

When bundles are composed with [`observe_alongside: true`](../contracts/yaml-reference.md#observe-alongside), the pipeline evaluates shadow contracts alongside real contracts. Shadow contracts produce audit events but never affect allow/deny decisions.

After all real checks pass, the pipeline evaluates shadow preconditions and session contracts. Each shadow result emits a separate audit event with `mode: "observe"` -- either `CALL_WOULD_DENY` or `CALL_ALLOWED`. This lets you compare the behavior of a candidate contract version against the currently enforced version. See [observe mode](observe-mode.md#dual-mode-evaluation-with-observe_alongside) for the full workflow.

## What Happens at Each Stage

| Stage | When | Can Deny? | Output |
|-------|------|-----------|--------|
| Preconditions | Before tool executes | Yes | `CALL_DENIED` or pass |
| Approval gate | When precondition has `effect: approve` | Yes (on denial/timeout) | `CALL_APPROVAL_REQUESTED`, then `GRANTED`/`DENIED`/`TIMEOUT` |
| Session limits | Before tool executes | Yes | `CALL_DENIED` if limit exceeded |
| Shadow contracts | After real checks pass | Never | Audit events with `mode: "observe"` |
| Tool execution | Only if all preconditions pass | -- | Tool's return value |
| Postconditions | After tool executes | `warn`: findings only. `redact`/`deny`: enforced for READ/PURE tools | `CALL_EXECUTED` with warnings |
| Audit | After every evaluation | -- | Structured event to all sinks |

## Next Steps

- [Contracts](contracts.md) -- the three contract types and how to write them
- [Principals](principals.md) -- attaching identity context to tool calls
- [Observe mode](observe-mode.md) -- shadow-testing contracts before enforcement
- [YAML reference](../contracts/yaml-reference.md) -- full contract syntax and bundle composition
