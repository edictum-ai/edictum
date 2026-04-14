<!-- logo placeholder: center Edictum logo here -->
# Edictum

[![PyPI](https://img.shields.io/pypi/v/edictum?cacheSeconds=3600)](https://pypi.org/project/edictum/)
[![License](https://img.shields.io/pypi/l/edictum?cacheSeconds=86400)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/edictum?cacheSeconds=86400)](https://pypi.org/project/edictum/)
[![CI](https://github.com/edictum-ai/edictum/actions/workflows/ci.yml/badge.svg)](https://github.com/edictum-ai/edictum/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/pypi/dm/edictum)](https://pypi.org/project/edictum/)
[![arXiv](https://img.shields.io/badge/arXiv-2602.16943-b31b1b.svg)](https://arxiv.org/abs/2602.16943)

Runtime rule enforcement for AI agent tool calls.

**Prompts are suggestions. Rules are enforcement.** The LLM cannot talk its way past a rule.

**55us overhead** · **Python, TypeScript, and Go SDKs** · **Zero runtime deps** · **Fail-closed by default**

```bash
pip install edictum[yaml]
```

## Quick Start

Deny first -- see enforcement before writing YAML:

```python
from edictum import Edictum, EdictumDenied

guard = Edictum.from_template("file-agent")
result = guard.evaluate("read_file", {"path": ".env"})
print(result.decision)         # "block"
print(result.block_reasons[0])  # "Sensitive file '.env' blocked."
```

Full path -- your rule, your enforcement:

```python
guard = Edictum.from_yaml("rules.yaml")

try:
    result = await guard.run("read_file", {"path": ".env"}, read_file)
except EdictumDenied as e:
    print(e.reason)  # "Sensitive file '.env' blocked."
```

`rules.yaml`:

```yaml
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: file-safety
defaults:
  mode: enforce
rules:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa"]
    then:
      action: block
      message: "Sensitive file '{args.path}' blocked."
```

Rules are YAML. Enforcement is deterministic -- no LLM in the evaluation path, just pattern matching against tool names and arguments. The agent cannot bypass a matched rule. Rule errors, type mismatches, and missing fields all fail closed (block). Tool calls with no matching rules are allowed by default -- add a catch-all `tool: "*"` rule for block-by-default.

## The Problem

An agent says "I won't read sensitive files" -- then calls `read_file(".env")` and leaks your API keys.

A DevOps agent recognizes a jailbreak attempt, writes "I should NOT comply" in its reasoning -- then reads four production database credentials in the next tool call.

Prompt engineering doesn't fix this. You need enforcement at the tool-call layer.

## Works With Your Framework

| Framework | Adapter | Integration |
|-----------|---------|-------------|
| LangChain + LangGraph | `LangChainAdapter` | `as_tool_wrapper()` / `as_middleware()` |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `as_guardrails()` |
| Claude Agent SDK | `ClaudeAgentSDKAdapter` | `to_hook_callables()` |
| CrewAI | `CrewAIAdapter` | `register()` |
| Agno | `AgnoAdapter` | `as_tool_hook()` |
| Semantic Kernel | `SemanticKernelAdapter` | `register()` |
| Google ADK | `GoogleADKAdapter` | `as_plugin()` / `as_agent_callbacks()` |
| Nanobot | `NanobotAdapter` | `wrap_registry()` |

```python
# LangChain
from edictum.adapters.langchain import LangChainAdapter
adapter = LangChainAdapter(guard)
tool = adapter.as_tool_wrapper(tool)

# OpenAI Agents SDK
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
adapter = OpenAIAgentsAdapter(guard)
input_gr, output_gr = adapter.as_guardrails()

# Claude Agent SDK
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
adapter = ClaudeAgentSDKAdapter(guard)
hooks = adapter.to_hook_callables()

# Google ADK
from edictum.adapters.google_adk import GoogleADKAdapter
adapter = GoogleADKAdapter(guard)
plugin = adapter.as_plugin()
```

See [Adapter docs](https://docs.edictum.ai/docs/adapters/overview) for all 8 frameworks.

## What You Can Do

**Rules** -- four types covering the full tool call lifecycle:

- **Preconditions** block dangerous calls before execution
- **Postconditions** scan tool output -- warn, redact PII, or block
- **Session rules** cap total calls, per-tool calls, and retry attempts
- **Sandbox rules** allowlist file paths, commands, and domains

**Principal-aware enforcement** -- role-gate tools with claims and `env.*` context. `set_principal()` for mid-session role changes.

**Callbacks** -- block/allow lifecycle callbacks for logging, alerting, or approval workflows.

**Test and validate:**

- `guard.evaluate()` -- dry-run without executing the tool
- Load rules in tests and assert decisions directly from Python
- For CLI workflows, use the Go binary in [edictum-go](https://github.com/edictum-ai/edictum-go) -- that is the canonical Edictum CLI

**Ship safely:**

- Observe mode -- log what would be blocked, then enforce
- Multi-file composition with deterministic merge
- Custom YAML operators and selectors
- For CLI-based diff/replay workflows, use the Go binary in [edictum-go](https://github.com/edictum-ai/edictum-go)

**Audit and observability:**

- Structured audit events on every evaluation
- OpenTelemetry spans and metrics
- Secret values auto-redacted in audit events
- File, stdout, and composite sinks

## Built-in Templates

```python
guard = Edictum.from_template("file-agent")
# Blocks .env, .pem, credentials, id_rsa reads. Blocks rm -rf, chmod 777, destructive shell commands.

guard = Edictum.from_template("research-agent")
# Postcondition PII scanning on tool output. Session limits (100 calls, 20 per tool).

guard = Edictum.from_template("devops-agent")
# Role gates (only ops principal can deploy). Ticket ID required. Bash command safety.

guard = Edictum.from_template("nanobot-agent")
# Approval gates for exec/spawn/cron/MCP. Workspace path restrictions. Session limits.
```

## Edictum Gate

Pre-execution governance for coding assistants. Sits between the assistant and the OS, evaluating every tool call against rules.

```bash
pip install edictum[gate]
```

The Python package ships the Gate library and integrations. For command-line workflows, use the Go binary in [edictum-go](https://github.com/edictum-ai/edictum-go) -- that is the canonical Edictum CLI.

Supports Claude Code, Cursor, Copilot CLI, Gemini CLI, and OpenCode. Self-protection rules prevent the assistant from disabling governance. Optional sync to the hosted control plane for centralized audit.

See the [Gate guide](https://docs.edictum.ai/docs/guides/gate) for setup.

## Edictum Console

Optional self-hostable operations console for governed agents. Rule management, live hot-reload via SSE, human-in-the-loop approvals, audit event feeds, and fleet monitoring.

```python
guard = await Edictum.from_server(
    url="http://localhost:8000",
    api_key="edk_production_...",
    agent_id="my-agent",
)
```

See the [console docs](https://docs.edictum.ai/docs/console) for the current control-plane surface.

## Research & Real-World Impact

Edictum was evaluated across six regulated domains in the GAP benchmark (6 LLMs, 17,420 datapoints).

[Paper (arXiv:2602.16943)](https://arxiv.org/abs/2602.16943)

Used to audit [OpenClaw](https://github.com/OpenClaw)'s 36,000-skill registry -- found live C2 malware on first scan.

For CLI-based scanning and other command-line workflows, use the Go binary in [edictum-go](https://github.com/edictum-ai/edictum-go).

## Install

Requires Python 3.11+.

```bash
pip install edictum              # core (zero deps)
pip install edictum[yaml]        # + YAML rule parsing
pip install edictum[otel]        # + OpenTelemetry span emission
pip install edictum[gate]        # + coding assistant governance library
pip install edictum[verified]    # + Ed25519 bundle signature verification
pip install edictum[server]      # + server SDK (connect to Edictum Console)
pip install edictum[all]         # everything in this Python package
```

For CLI workflows, use the Go binary in [edictum-go](https://github.com/edictum-ai/edictum-go).

## How It Compares

| Approach | Scope | Runtime enforcement | Audit trail |
|---|---|---|---|
| Prompt/output guardrails | Input/output text | No -- advisory only | No |
| API gateways / MCP proxies | Network transport | Yes -- at the proxy | Partial |
| Security scanners | Post-hoc analysis | No -- detection only | Yes |
| Manual if-statements | Per-tool, ad hoc | Yes -- scattered logic | No |
| **Edictum** | **Tool call rules** | **Yes -- deterministic pipeline** | **Yes -- structured + redacted** |

## Use Cases

| Domain | What Edictum enforces |
|--------|----------------------|
| Coding agents | Secret protection, destructive command denial, write scope ([Gate guide](https://docs.edictum.ai/docs/guides/gate)) |
| Healthcare | Patient data access control, role-gated queries |
| Finance | PII redaction in query results, transaction limits |
| DevOps | Production deploy gates, ticket requirements, bash safety |
| Education | Student data protection, session limits per assignment |
| Legal | Privileged document access, audit trail for compliance |

## Ecosystem

| Repo | Language | What it does |
|------|----------|-------------|
| [edictum](https://github.com/edictum-ai/edictum) | Python | Core library -- this repo |
| [edictum-ts](https://github.com/edictum-ai/edictum-ts) | TypeScript | Core + adapters (Claude SDK, LangChain, OpenAI Agents, Vercel AI) |
| [edictum-go](https://github.com/edictum-ai/edictum-go) | Go | Core + adapters (ADK Go, Anthropic, Eino, Genkit, LangChain Go) |
| [edictum-api](https://github.com/edictum-ai/edictum-api) | Go | Hosted control-plane API: runs, approvals, notifications, audit |
| [edictum-app](https://github.com/edictum-ai/edictum-app) | React | Hosted control-plane UI: runs, approvals, policies, settings |
| [edictum-schemas](https://github.com/edictum-ai/edictum-schemas) | JSON Schema | Rule bundle schema + cross-SDK conformance fixtures |
| [edictum-demo](https://github.com/edictum-ai/edictum-demo) | Python | Scenario demos, adversarial tests, benchmarks, Grafana observability |
| [Documentation](https://docs.edictum.ai) | MDX | Full docs site |
| [edictum.ai](https://edictum.ai) | -- | Official website |

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE)
