# Edictum

Edictum enforces contracts on AI agent tool calls. Before your agent reads a file, queries a database, or calls an API -- Edictum checks the call against YAML contracts and denies it if it violates policy. The agent cannot bypass it.

## The Problem

AI agents call tools with real-world side effects. An agent with `run_command` can delete files. An agent with `send_email` can impersonate your organization. An agent with `query_database` can exfiltrate every row in your customer table.

The standard defense is prompt engineering: "Do not read .env files." But prompts are suggestions the LLM can ignore. A long conversation, a creative jailbreak, or a model update can bypass any instruction embedded in a system prompt.

There is no hard boundary between "the agent decides to act" and "the action executes." Until you add one.

## The Solution

Edictum sits at the decision-to-action seam. The agent decides to call a tool. Before that call executes, Edictum checks it against contracts. This is a hard boundary, not a suggestion.

**Without Edictum** -- the agent reads your secrets:

```python
# Agent decides to read .env
result = await read_file(".env")
# => "OPENAI_API_KEY=sk-abc123..."
```

**With Edictum** -- the call is denied before it executes:

```python
from edictum import Edictum, EdictumDenied

guard = Edictum.from_yaml("contracts.yaml")

try:
    result = await guard.run("read_file", {"path": ".env"}, read_file)
except EdictumDenied as e:
    print(e.reason)
    # => "Sensitive file '.env' denied."
```

**The contract that makes it happen** -- `contracts.yaml`:

```yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: file-safety
defaults:
  mode: enforce
contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied."
```

**Postconditions catch what preconditions can't** -- scan tool output after execution:

```yaml
contracts:
  - id: redact-ssn-in-output
    type: post
    tool: query_database
    when:
      output.text:
        matches: '\b\d{3}-\d{2}-\d{4}\b'
    then:
      effect: redact
      message: "SSN pattern detected and redacted from query result."
```

With `effect: redact`, the matching content is stripped from the tool's return value before the agent sees it. With `effect: deny`, the entire output is suppressed.

Contracts are YAML. Enforcement is deterministic. The LLM cannot talk its way past a contract.

## How It Works

1. **Write contracts in YAML.** Preconditions deny dangerous calls before execution. Postconditions check tool output after -- warn, redact, or deny. Session contracts cap total calls and retries. Sandbox contracts define allowlists for file paths, commands, and domains.

2. **Attach to your agent framework.** One adapter line. Same contracts across all seven supported frameworks -- LangChain, OpenAI Agents, CrewAI, Agno, Semantic Kernel, Claude SDK, and Nanobot.

3. **Compose and layer bundles.** Split contracts across files by concern. `from_yaml()` accepts multiple paths with deterministic merge semantics. Shadow-test contract updates with [`observe_alongside`](contracts/yaml-reference.md#observe-alongside) before promoting them.

4. **Every tool call passes through the pipeline.** Agent decides to call a tool. Edictum evaluates preconditions, session limits, and principal context. If any contract fails, the call is denied and never executes.

5. **Full audit trail.** Every evaluation -- allowed, denied, or observed -- produces a structured audit event with automatic secret redaction. Route to stdout, file, OpenTelemetry, or your existing observability stack.

## Pick Your Path

- **I want to try it now** -- [Quickstart](quickstart.md). Install, write a contract, deny a dangerous call in five minutes.
- **I want to see real scenarios** -- [Use Cases](use-cases.md). Six domains with complete YAML bundles and wiring code.
- **I want to understand the system** -- [How It Works](concepts/how-it-works.md). The pipeline, adapters, and what happens on every tool call.
- **I have a specific framework** -- [Adapters](adapters/overview.md). Integration guides for LangChain, OpenAI, CrewAI, Agno, Semantic Kernel, Claude SDK, and Nanobot.

## What You Can Do

- Preconditions deny dangerous calls before execution
- Postconditions scan output -- warn, redact PII, or deny entirely
- Session contracts cap total calls, per-tool calls, and retries
- Sandbox contracts define file path, command, and domain allowlists
- Deny-list + allowlist composition for defense in depth
- Role-gate tools with `principal` claims and `env.*` context
- `edictum validate` catches schema errors at load time
- `edictum test` runs YAML test cases with expected verdicts
- `guard.evaluate()` dry-runs contracts without executing the tool
- Observe mode logs what would be denied so you can tune before enforcing
- `observe_alongside` shadow-tests new contracts next to production
- `edictum diff` and `edictum replay` detect contract drift
- Multi-file composition with deterministic merge
- Secrets auto-redacted in audit events and denial messages
- OpenTelemetry spans and policy version hash on every event

## Install

```bash
pip install edictum[yaml]           # YAML contract parsing
pip install edictum[server]         # server SDK (approval, audit, session via HTTP)
pip install edictum[all]            # everything
```

Requires Python 3.11+. Current version: **v0.11.3**. See the [quickstart](quickstart.md) to write your first contract and deny a dangerous call in five minutes.

## Framework Support

Edictum integrates with seven agent frameworks. Same YAML contracts, same enforcement, different adapter patterns:

| Framework | Adapter | Integration |
|-----------|---------|-------------|
| LangChain | `LangChainAdapter` | `as_tool_wrapper()` / `as_middleware()` |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `as_guardrails()` |
| CrewAI | `CrewAIAdapter` | `register()` |
| Agno | `AgnoAdapter` | `as_tool_hook()` |
| Semantic Kernel | `SemanticKernelAdapter` | `register(kernel)` |
| Claude Agent SDK | `ClaudeAgentSDKAdapter` | `to_hook_callables()` |
| Nanobot | `NanobotAdapter` | `wrap_registry()` |

See the [adapter overview](adapters/overview.md) for setup guides and known limitations.

## What's Coming

- **Server SDK** (shipped) -- `pip install edictum[server]` connects agents to edictum-server for centralized approvals, audit ingestion, distributed sessions, and SSE contract updates
- **edictum-server** (coming soon) -- open-source server for production approval workflows, governance dashboard, distributed sessions, hot-reload contracts, and RBAC
- **PII detection** -- pluggable detectors for postcondition contracts (regex built-in, Presidio as optional dependency)
- **Production audit sinks** -- Webhook, Splunk HEC, and Datadog as core sinks or via server-managed ingestion

See the [roadmap](roadmap.md) for the full plan.

## Next Steps

- [Quickstart](quickstart.md) -- Install, write a contract, and deny your first dangerous call
- [Use Cases](use-cases.md) -- Six domains with complete YAML bundles
- [How It Works](concepts/how-it-works.md) -- The pipeline, adapters, and what happens on every tool call
- [Contracts](concepts/contracts.md) -- Preconditions, postconditions, sandbox allowlists, session limits, and observe mode
- [YAML Reference](contracts/yaml-reference.md) -- Full schema for `edictum/v1` contract bundles
- [Adapters](adapters/overview.md) -- Integration guides for all seven frameworks
