# Edictum

[![PyPI](https://img.shields.io/pypi/v/edictum?cacheSeconds=3600)](https://pypi.org/project/edictum/)
[![License](https://img.shields.io/pypi/l/edictum?cacheSeconds=86400)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/edictum?cacheSeconds=86400)](https://pypi.org/project/edictum/)

Runtime contract enforcement for AI agent tool calls.

Prompts are suggestions. Contracts are enforcement.
The LLM cannot talk its way past a contract.

## The Problem

An agent says "I won't read sensitive files" -- then calls `read_file(".env")` and leaks your API keys.

A DevOps agent recognizes a jailbreak attempt, writes "I should NOT comply" in its reasoning -- then reads four production database credentials in the next tool call.

Prompt engineering doesn't fix this. You need enforcement at the tool-call layer.

## Without Edictum / With Edictum

**Without** -- the agent reads your secrets:

```python
# Agent decides to read .env
result = await read_file(".env")
# => "OPENAI_API_KEY=sk-abc123..."
```

**With** -- the call is denied before it executes:

```python
from edictum import Edictum, EdictumDenied

guard = Edictum.from_yaml("contracts.yaml")

try:
    result = await guard.run("read_file", {"path": ".env"}, read_file)
except EdictumDenied as e:
    print(e.reason)
    # => "Sensitive file '.env' denied."
```

**The contract** -- `contracts.yaml`:

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

Contracts are YAML. Enforcement is deterministic -- no LLM in the evaluation path, just pattern matching against tool names and arguments. The agent cannot bypass a matched contract. Contract errors, type mismatches, and missing fields all fail closed (deny). Tool calls with no matching contracts are allowed by default -- add a catch-all `tool: "*"` contract for deny-by-default.

## Works With Your Framework

```python
# LangChain — wrap your tools
from edictum.adapters import LangChainAdapter
adapter = LangChainAdapter(guard)
tool = adapter.as_tool_wrapper(tool)

# OpenAI Agents SDK — input/output guardrails
from edictum.adapters import OpenAIAgentsAdapter
adapter = OpenAIAgentsAdapter(guard)
input_gr, output_gr = adapter.as_guardrails()

# Claude Agent SDK — hook callables
from edictum.adapters import ClaudeSDKAdapter
adapter = ClaudeSDKAdapter(guard)
hooks = adapter.to_hook_callables()
```

Edictum plugs into your existing agent code. You don't restructure your tools -- you wrap them. See [Adapter docs](https://docs.edictum.ai/docs/adapters) for all 8 frameworks.

## Install

Requires Python 3.11+.

```bash
pip install edictum              # core (zero deps)
pip install edictum[yaml]        # + YAML contract parsing
pip install edictum[otel]        # + OpenTelemetry span emission
pip install edictum[cli]         # + validate/check/diff/replay CLI
pip install edictum[gate]        # + coding assistant governance
pip install edictum[server]      # + server SDK (connect to Edictum Console)
pip install edictum[all]         # everything
```

## What You Can Do

**Contracts** -- four types covering the full tool call lifecycle:

- **Preconditions** deny dangerous calls before execution
- **Postconditions** scan tool output -- warn, redact PII, or deny
- **Session contracts** cap total calls, per-tool calls, and retry attempts
- **Sandbox contracts** allowlist file paths, commands, and domains

**Principal-aware enforcement** -- role-gate tools with claims and `env.*` context. `set_principal()` for mid-session role changes.

**Callbacks** -- `on_deny` / `on_allow` for logging, alerting, or approval workflows.

**Test and validate:**

- `edictum validate` -- catch schema errors at load time
- `edictum test` -- YAML test cases with expected verdicts
- `guard.evaluate()` -- dry-run without executing the tool

**Ship safely:**

- Observe mode -- log what would be denied, then enforce
- Multi-file composition with deterministic merge
- Custom YAML operators and selectors
- `edictum diff` and `edictum replay` for contract drift detection

**Audit and observability:**

- Structured audit events on every evaluation
- OpenTelemetry spans and metrics
- Secret values auto-redacted in audit events
- File, stdout, and composite sinks

## Edictum Gate

Pre-execution governance for coding assistants. Sits between the assistant and the OS, evaluating every tool call against contracts.

```bash
pip install edictum[gate]
edictum gate init
```

Supports Claude Code, Cursor, Copilot CLI, Gemini CLI, and OpenCode. Self-protection contracts prevent the assistant from disabling governance. Optional sync to [Edictum Console](https://github.com/acartag7/edictum-console) for centralized audit.

See the [Gate guide](https://docs.edictum.ai/docs/guides/gate) for setup.

## Framework Adapters

| Framework | Integration | Complexity |
|-----------|------------|------------|
| LangChain + LangGraph | `as_tool_wrapper()` | Low |
| OpenAI Agents SDK | `as_guardrails()` | Medium |
| Agno | `as_tool_hook()` | Low |
| Semantic Kernel | `register()` | Medium-High |
| CrewAI | `register()` | High |
| Claude Agent SDK | `to_hook_callables()` | Low |
| Nanobot | `wrap_registry()` | Low |
| Google ADK | `as_plugin()`, `as_agent_callbacks()` | Low |

See [Adapter docs](https://docs.edictum.ai/docs/adapters) for setup and limitations.

## Built-in Templates

```python
guard = Edictum.from_template("file-agent")
# Blocks .env, .pem, credentials, id_rsa reads. Denies rm -rf, chmod 777, destructive shell commands.

guard = Edictum.from_template("research-agent")
# Postcondition PII scanning on tool output. Session limits (100 calls, 20 per tool).

guard = Edictum.from_template("devops-agent")
# Role gates (only ops principal can deploy). Ticket ID required. Bash command safety.

guard = Edictum.from_template("nanobot-agent")
# Approval gates for exec/spawn/cron/MCP. Workspace path restrictions. Session limits.
```

## Edictum Console

Optional self-hostable operations console for governed agents. Contract management, live hot-reload via SSE, human-in-the-loop approvals, audit event feeds, and fleet monitoring.

```python
guard = await Edictum.from_server(
    url="http://localhost:8000",
    api_key="edk_production_...",
    agent_id="my-agent",
)
```

See [edictum-console](https://github.com/acartag7/edictum-console) for deployment.

## How It Compares

| Approach | Scope | Runtime enforcement | Audit trail |
|---|---|---|---|
| Prompt/output guardrails | Input/output text | No -- advisory only | No |
| API gateways / MCP proxies | Network transport | Yes -- at the proxy | Partial |
| Security scanners | Post-hoc analysis | No -- detection only | Yes |
| Manual if-statements | Per-tool, ad hoc | Yes -- scattered logic | No |
| **Edictum** | **Tool call contracts** | **Yes -- deterministic pipeline** | **Yes -- structured + redacted** |

## Use Cases

| Domain | What Edictum enforces |
|--------|----------------------|
| Coding agents | Secret protection, destructive command denial, write scope ([Gate guide](https://docs.edictum.ai/docs/guides/gate)) |
| Healthcare | Patient data access control, role-gated queries |
| Finance | PII redaction in query results, transaction limits |
| DevOps | Production deploy gates, ticket requirements, bash safety |
| Education | Student data protection, session limits per assignment |
| Legal | Privileged document access, audit trail for compliance |

## Research

Edictum was evaluated across six regulated domains in the GAP benchmark.

[Paper](https://arxiv.org/abs/2602.16943) -- [Benchmark](https://github.com/acartag7/gap-benchmark)

## Demos & Examples

- [edictum-demo](https://github.com/acartag7/edictum-demo) -- Full scenario demos, adversarial tests, benchmarks, and Grafana observability
- [Contract Patterns](https://docs.edictum.ai/docs/contracts/patterns) -- Real-world contract recipes by concern

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Links

- [Documentation](https://docs.edictum.ai)
- [Edictum Console](https://github.com/acartag7/edictum-console)
- [GitHub](https://github.com/acartag7/edictum)
- [PyPI](https://pypi.org/project/edictum/)
- [Changelog](CHANGELOG.md)
- [License](LICENSE) (MIT)
