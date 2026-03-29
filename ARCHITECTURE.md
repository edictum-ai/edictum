# Edictum Architecture

> Runtime safety for AI agents. Stop agents before they break things.

## What It Does

Edictum sits between an agent's decision to call a tool and actual execution. It enforces rules, hooks, audit trails, and operation limits. When a rule is violated, it tells the agent **why** so it can self-correct.

## Package Structure

```
src/edictum/
├── __init__.py          # Edictum class, guard.run(), exceptions, re-exports
├── envelope.py          # ToolCall (frozen), SideEffect, ToolRegistry, BashClassifier
├── hooks.py             # HookDecision (ALLOW/DENY)
├── rules.py         # Decision, @precondition, @postcondition, @session_contract
├── limits.py            # OperationLimits (attempt + execution + per-tool caps)
├── pipeline.py          # CheckPipeline — single source of governance logic
├── session.py           # Session (atomic counters via StorageBackend)
├── storage.py           # StorageBackend protocol + MemoryBackend
├── audit.py             # AuditEvent, RedactionPolicy, Stdout/File sinks
├── telemetry.py         # OpenTelemetry (graceful no-op if absent)
├── builtins.py          # deny_sensitive_reads()
├── types.py             # Internal types (HookRegistration, ToolConfig)
└── adapters/
    ├── langchain.py         # LangChain adapter (pre/post tool call hooks)
    ├── crewai.py            # CrewAI adapter (before/after hooks)
    ├── agno.py              # Agno adapter (wrap-around hook)
    ├── semantic_kernel.py   # Semantic Kernel adapter (filter pattern)
    ├── openai_agents.py     # OpenAI Agents SDK adapter (guardrails)
    └── claude_agent_sdk.py  # Claude Agent SDK adapter (hook dict)
```

## The Flow

Every tool call passes through:

```
Agent decides to call tool
    │
    ▼
Adapter creates ToolCall (deep-copied, classified)
Increments attempt_count (BEFORE governance)
    │
    ▼
Pipeline.pre_execute() — 5 steps:
    1. Attempt limit (>= max_attempts?)
    2. Before hooks (user-defined, can DENY)
    3. Checks (rule checks, can BLOCK)
    4. Session rules (cross-turn state, can BLOCK)
    5. Execution limits (>= max_tool_calls? per-tool?)
    │
    ├── BLOCK → audit event → tell agent why → agent self-corrects
    │
    └── ALLOW → tool executes
                    │
                    ▼
            Pipeline.post_execute():
                1. Postconditions (observe-only, warnings)
                2. After hooks
                3. Session record (exec count, consecutive failures)
                    │
                    ▼
                Audit event (CALL_EXECUTED or CALL_FAILED)
```

## Key Design Decisions

**Pipeline owns ALL governance logic.** Adapters are thin translation layers. Adding a second adapter doesn't fork governance behavior.

**Two counter types:**
- `max_attempts` — caps ALL PreToolUse events (including blocked). Catches block loops.
- `max_tool_calls` — caps executions only (PostToolUse). Caps total work done.

**Postconditions are observe-only.** They emit warnings, never block. For pure/read tools: suggest retry. For write/irreversible: warn only.

**Observe mode** (`mode="observe"`): full pipeline runs, audit emits `CALL_WOULD_DENY`, but tool executes anyway.

**Zero runtime deps.** OpenTelemetry via optional `edictum[otel]`.

**Redaction at write time.** Destructive by design — no recovery. Sensitive keys, secret value patterns (OpenAI/AWS/JWT/GitHub/Slack), 32KB payload cap.

**BashClassifier is a heuristic, not a security boundary.** Conservative READ allowlist + shell operator detection. Defense in depth with `deny_sensitive_reads()`.

## Usage Modes

**1. Framework-agnostic (`guard.run()`):**
```python
guard = Edictum(rules=[deny_sensitive_reads()])
result = await guard.run("Bash", {"command": "ls"}, my_bash_fn)
```

**2. Framework adapters (6 supported):**

All adapters are thin translation layers — governance logic stays in the pipeline.

```python
from edictum.adapters.langchain import LangChainAdapter
from edictum.adapters.crewai import CrewAIAdapter
from edictum.adapters.agno import AgnoAdapter
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

adapter = LangChainAdapter(guard, session_id="session-1")
```

## What This Is NOT

- Not prompt injection defense
- Not content safety filtering
- Not network egress control
- Not a security boundary for Bash
- Not concurrency-safe across workers (MemoryBackend is single-process)
