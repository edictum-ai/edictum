# Architecture

Edictum is a single pipeline that every adapter calls. Contracts written in YAML compile to the same runtime objects as Python-defined contracts. The pipeline is deterministic -- same input, same decision, every time.

---

## Pipeline Overview

Every tool call passes through one pipeline, regardless of which framework adapter triggers it.

```
Agent decides to call tool
        |
  +-----+---------+
  |    Edictum     |
  |    Pipeline    |
  +----------------+
  | Preconditions  | <-- YAML contracts checked BEFORE execution
  | Session limits |
  | Principal      |
  +-------+--------+
          | ALLOW / DENY
          v
    Tool executes (only if allowed)
          v
  +----------------+
  | Postconditions | <-- Output checked AFTER execution
  | Audit event    | --> OTel / stdout
  +----------------+
```

In enforce mode, if any precondition fails, the tool call is denied. The tool never executes. There is no "soft deny" -- either every check passes or the call does not happen. (In [observe mode](concepts/observe-mode.md), failures are logged as `CALL_WOULD_DENY` but the call proceeds.)

---

## Pre-Execution Detail

`GovernancePipeline.pre_execute()` runs six checks in order. The first failure in steps 1-5 short-circuits -- remaining checks are skipped. Step 6 (shadow evaluation) always runs when the decision is "allow."

```
ToolEnvelope --> pre_execute(envelope, session)
                    |
                    +-- 1. Check attempt limit (max_attempts)
                    |      Counts ALL attempts, including denied ones.
                    |      Catches retry loops before they waste resources.
                    |
                    +-- 2. Run before-hooks
                    |      Each hook returns allow or deny.
                    |      First denial short-circuits.
                    |      Hooks have optional `when` predicates for filtering.
                    |
                    +-- 3. Evaluate preconditions
                    |      Each returns Verdict.pass_() or .fail(msg).
                    |      In observe mode, failures are recorded but do not deny.
                    |      In enforce mode, first failure short-circuits.
                    |      Contracts with effect=approve return "pending_approval"
                    |      instead of deny, delegating to approval_backend.
                    |
                    +-- 4. Evaluate session contracts
                    |      Session contracts receive the Session object.
                    |      Used for cross-turn limits and stateful contracts.
                    |      First failure short-circuits.
                    |
                    +-- 5. Check execution limits
                    |      max_tool_calls: total executions across all tools.
                    |      max_calls_per_tool: per-tool execution cap.
                    |      Counts only successful past executions, not attempts.
                    |
                    +-- 6. Evaluate shadow contracts
                           Shadow preconditions and session contracts from
                           observe_alongside composition. Never affect the
                           real decision. Results emitted as audit events
                           with mode: "observe".

                    --> PreDecision(action="allow"|"deny"|"pending_approval", shadow_results=[...], ...)
```

If the `PreDecision.action` is `"allow"`, the adapter lets the tool execute.

---

## Post-Execution Detail

Once a tool has executed, Edictum checks its output. Postcondition behavior depends on the declared `effect` and the tool's side-effect classification.

```
(tool_response, tool_success) --> post_execute(envelope, response, success)
                                      |
                                      +-- 1. Evaluate postconditions
                                      |      Each returns Verdict.pass_() or .fail(msg).
                                      |      Effect determines action on failure:
                                      |        warn:   produce a finding (all tools)
                                      |        redact: replace matched patterns (READ/PURE only)
                                      |        deny:   suppress entire output (READ/PURE only)
                                      |      WRITE/IRREVERSIBLE tools: all effects fall back to warn.
                                      |      Observe mode: all effects fall back to warn.
                                      |
                                      +-- 2. Run after-hooks
                                             Fire-and-forget observation hooks.
                                             Cannot modify the result.

                                      --> PostDecision(tool_success, postconditions_passed, warnings,
                                                       redacted_response, output_suppressed)
```

For `warn`, the pipeline warns the agent and lets it decide how to proceed. For `redact` and `deny` on READ/PURE tools, the pipeline modifies the response before it reaches the agent. WRITE/IRREVERSIBLE tools always get `warn` because the action already happened -- hiding the result only removes context the agent needs.

---

## YAML Compilation

YAML contract bundles go through a multi-stage pipeline that produces the same runtime objects as hand-written Python contracts. When multiple files are passed to `from_yaml()`, a composition step merges them before compilation.

```
YAML file(s)
  |
  +-- loader.py (per file)
  |     Parse YAML text
  |     Validate against JSON Schema (edictum-v1.schema.json)
  |     Compute SHA-256 hash (becomes policy_version in audit events)
  |     Return structured contract definitions
  |
  +-- composer.py (when multiple files)
  |     Merge bundles left-to-right with deterministic semantics
  |     Same-ID contracts: later layer replaces earlier
  |     Tools/metadata: deep merge; defaults/limits/observability: later wins
  |     observe_alongside bundles: contracts become shadow copies
  |     Return ComposedBundle with merged dict + CompositionReport
  |
  +-- compiler.py
  |     Convert each definition into @precondition / @postcondition /
  |       @session_contract decorated callables
  |     Stamp _edictum_shadow on shadow contracts (from observe_alongside)
  |     Compile regex match patterns
  |     Build OperationLimits from session limits section
  |     Extract tool classifications from optional tools: section
  |     Return list of contract objects + OperationLimits + tool registry
  |
  +-- Result: identical objects to Python-defined contracts
        Regular contracts registered in standard evaluation lists
        Shadow contracts registered in separate lists (never block calls)
        Both executed by the same pipeline
```

There is no separate "YAML execution path." A precondition compiled from YAML and a precondition written as a Python function are indistinguishable to the pipeline. They produce the same `Verdict` objects, appear in the same `contracts_evaluated` audit records, and are subject to the same observe-mode behavior.

---

## Adapter Pattern

Adapters are thin translation layers between framework-specific hook APIs and the pipeline. Each adapter:

1. Intercepts the framework's tool-call lifecycle event
2. Builds a `ToolEnvelope` via `create_envelope()`
3. Calls `pipeline.pre_execute()` and translates the `PreDecision` into the framework's expected format
4. If allowed, lets the tool execute
5. Calls `pipeline.post_execute()` and forwards any findings

| Adapter | Framework | Integration Method |
|---------|-----------|-------------------|
| `LangChainAdapter` | LangChain | `as_middleware()`, `as_tool_wrapper()` |
| `CrewAIAdapter` | CrewAI | `register()` -- global hooks |
| `AgnoAdapter` | Agno | `as_tool_hook()` -- wrap-around hook |
| `SemanticKernelAdapter` | Semantic Kernel | `register(kernel)` -- auto-invocation filter |
| `OpenAIAgentsAdapter` | OpenAI Agents | `as_guardrails()` -- input/output guardrails |
| `ClaudeAgentSDKAdapter` | Claude Agent SDK | `to_hook_callables()` -- pre/post tool use hooks |
| `NanobotAdapter` | Nanobot | `wrap_registry()` -- governed ToolRegistry |

Adapters never contain enforcement logic. They translate formats. If you need to add a new contract, add it as a contract or hook -- not adapter code.

---

## Design Decisions

### Envelope Immutability

`ToolEnvelope` is a frozen dataclass. Once created, no field can be modified.

This is enforced at two levels: `@dataclass(frozen=True)` raises `FrozenInstanceError` on assignment, and `create_envelope()` deep-copies `args` and `metadata` via `json.loads(json.dumps(...))` so the caller cannot mutate the original dicts.

Always create envelopes through `create_envelope()`, never by constructing `ToolEnvelope(...)` directly. The `Principal` dataclass is also frozen.

### Session and Storage Model

Sessions track execution state across multiple tool calls within an agent run.

| Counter | Semantics |
|---------|-----------|
| `attempts` | Incremented on every `pre_execute` call, including denials |
| `execs` | Incremented only when a tool actually executes |
| `tool:{name}` | Per-tool execution count |
| `consec_fail` | Consecutive failures; resets on success |

All counter operations go through the `StorageBackend` protocol:

```python
class StorageBackend(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def increment(self, key: str, amount: float = 1) -> float: ...
```

`increment()` must be atomic. This is the fundamental requirement for correctness under concurrent access.

`MemoryBackend` stores counters in a Python dict -- one process, one agent. This covers the vast majority of use cases: a single agent process enforcing session limits on its own tool calls. For multi-agent coordination across processes, the Edictum Server (planned) handles centralized session tracking. See the [roadmap](roadmap.md).

### Operation Limits

`OperationLimits` defines three cap types:

| Limit | Default | Counts |
|-------|---------|--------|
| `max_attempts` | 500 | All `pre_execute` calls (including denials) |
| `max_tool_calls` | 200 | Successful executions only |
| `max_calls_per_tool` | `{}` | Per-tool execution count |

`max_attempts` fires first because it counts denied calls too. An agent stuck in a denial loop hits the attempt cap without ever incrementing the execution counter. The denial message tells the agent to stop and reassess rather than keep retrying.

### Claude Agent SDK: Intentional Decoupling

`to_hook_callables()` returns callables using Edictum's own calling convention
(snake_case keys, `(tool_name, tool_input, tool_use_id)` signature) rather than
the SDK-native `HookCallback` signature (`(input_data, tool_use_id, context)`
with PascalCase event keys and `HookMatcher` wrappers).

This is intentional. The `claude-agent-sdk` package is pre-1.0 and its types
(`HookMatcher`, `HookContext`, `HookCallback`) may change. Importing them would
add a runtime dependency to Edictum's zero-dep core and couple releases to SDK
breaking changes. The ~10-line bridge recipe in the
[Claude SDK adapter docs](adapters/claude-sdk.md#using-with-claudesdkclient-bridge-recipe)
lives in user-land where the `claude-agent-sdk` coupling already exists.

If the SDK stabilizes at 1.0, a `to_native_hooks()` convenience method that
returns `dict[HookEvent, list[HookMatcher]]` directly could be added without
breaking `to_hook_callables()`.

### Error Handling: Fail-Closed

Edictum follows a fail-closed default with explicit opt-in to permissive behavior:

- **Unregistered tools** default to `SideEffect.IRREVERSIBLE` (most restrictive classification)
- **Contract evaluation errors** deny the tool call rather than silently allowing it
- **Observe mode** is opt-in per-contract or per-pipeline, never the default
- **Postconditions** default to warn; `redact` and `deny` effects are enforced for READ/PURE tools but fall back to warn for WRITE/IRREVERSIBLE tools

Audit events record `policy_error: true` when contract loading fails, ensuring that broken contract bundles are visible in monitoring even when the system falls back to a safe default.

---

## Where It's Heading

Edictum is currently an in-process library -- contracts are loaded and enforced within the same process as the agent. This covers single-agent deployments and most production use cases today.

The **server SDK** (`pip install edictum[server]`) provides the client-side connectivity for agents to talk to the edictum-server control plane. It implements the core protocols (`ApprovalBackend`, `AuditSink`, `StorageBackend`) over HTTP, letting agents use server-managed approvals, centralized audit ingestion, distributed session state, and SSE-pushed contract updates. The server itself is a separate deployment. See the [roadmap](roadmap.md) for details.

### The Boundary Principle

The split between OSS core and enterprise follows one principle: **evaluation pipeline = OSS, infrastructure = enterprise.**

- The pipeline that takes a tool call and returns allow/deny/warn is OSS
- Anything that requires persistence beyond local files, networking, or coordination is enterprise
- Stdout + File (.jsonl) sinks ship in OSS for dev and local audit. Network destinations (Webhook, Splunk, Datadog) are enterprise
- OTel instrumentation (emitting spans) is OSS. Dashboards and alerting are enterprise
- Session (MemoryBackend) is OSS for single-process. Server SDK client (`edictum[server]`) connects to the Edictum Server for multi-process coordination

---

<details>
<summary>Source Layout</summary>

```
src/edictum/
  __init__.py              Edictum facade (registers contracts, hooks, sinks)

  envelope.py              ToolEnvelope, Principal, ToolRegistry, BashClassifier
  contracts.py             @precondition, @postcondition, @session_contract, Verdict
  pipeline.py              GovernancePipeline -- PreDecision, PostDecision
  hooks.py                 HookResult, HookDecision (allow/deny)
  session.py               Session (atomic counters via StorageBackend)
  storage.py               StorageBackend protocol, MemoryBackend
  limits.py                OperationLimits (max_attempts, max_tool_calls, per-tool)
  audit.py                 AuditEvent, AuditAction, AuditSink, RedactionPolicy
  telemetry.py             GovernanceTelemetry (OTel spans + metrics, no-op fallback)
  builtins.py              deny_sensitive_reads() built-in precondition

  yaml_engine/
    loader.py              Parse YAML, validate against JSON Schema, SHA-256 hash
    evaluator.py           Condition evaluation (match, principal checks, etc.)
    compiler.py            YAML contracts -> @precondition/@postcondition objects
    composer.py            Bundle composition (compose_bundles, observe_alongside)

  otel.py                  configure_otel(), has_otel(), get_tracer() (OTel spans)

  cli/
    main.py                Click CLI entry point (validate, check, diff, replay, test)

  adapters/
    langchain.py           LangChain tool-calling middleware
    crewai.py              CrewAI before/after hooks
    agno.py                Agno async hook wrapper
    semantic_kernel.py     Semantic Kernel filter pattern
    openai_agents.py       OpenAI Agents guardrails
    claude_agent_sdk.py    Anthropic Claude Agent SDK hooks
    nanobot.py             Nanobot governed ToolRegistry

  server/                  pip install edictum[server]
    client.py              EdictumServerClient (async HTTP, auth, retries)
    approval_backend.py    ServerApprovalBackend (ApprovalBackend via HTTP)
    audit_sink.py          ServerAuditSink (batched event ingestion)
    backend.py             ServerBackend (StorageBackend via HTTP)
    contract_source.py     ServerContractSource (SSE contract bundle updates)
```

</details>
