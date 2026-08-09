<!-- logo placeholder: center Edictum logo here -->
# Edictum

[![PyPI](https://img.shields.io/pypi/v/edictum?cacheSeconds=3600)](https://pypi.org/project/edictum/)
[![License](https://img.shields.io/pypi/l/edictum?cacheSeconds=86400)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/edictum?cacheSeconds=86400)](https://pypi.org/project/edictum/)
[![CI](https://github.com/edictum-ai/edictum/actions/workflows/ci.yml/badge.svg)](https://github.com/edictum-ai/edictum/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/pypi/dm/edictum)](https://pypi.org/project/edictum/)
[![arXiv](https://img.shields.io/badge/arXiv-2602.16943-b31b1b.svg)](https://arxiv.org/abs/2602.16943)

Edictum is the runtime control layer for AI agent behavior.

It turns an agent's declared profile into executable boundaries: what tools it can call, what data it can touch, what workflow stage it is in, what evidence is required, and when human approval is needed.

For production teams, Edictum is the agency control layer for production AI agents.

**Agent frameworks build the agent. Edictum bounds the agency.**

**55us overhead** · **18 adapters across Python, TypeScript, Go** · **Zero runtime deps** · **Fail-closed by default**

```bash
pip install edictum[yaml]
```

## Quick Start

Start with the first primitive: a single tool-call boundary.

Block first -- see enforcement before writing YAML:

```python
from edictum import Edictum

guard = Edictum.from_template("file-agent")
result = guard.evaluate("read_file", {"path": ".env"})
print(result.decision)         # "block"
print(result.block_reasons[0])  # "Sensitive file '.env' blocked."
```

Full path -- your rule, your boundary:

```python
guard = Edictum.from_yaml("rules.yaml")

result = guard.evaluate("read_file", {"path": ".env"})
print(result.decision)         # "block"
print(result.block_reasons[0])  # "Sensitive file '.env' blocked."
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

Rules are YAML. Enforcement is deterministic -- no LLM in the evaluation path, just pattern matching against tool names and arguments. The agent cannot bypass a matched rule. Rule errors, type mismatches, and missing fields all fail closed with a block decision. Tool calls with no matching rules are allowed by default -- add a catch-all `tool: "*"` rule for block-by-default.

## The Problem

An agent says "I won't read sensitive files" -- then calls `read_file(".env")` and leaks your API keys.

A DevOps agent recognizes a jailbreak attempt, writes "I should NOT comply" in its reasoning -- then reads four production database credentials in the next tool call.

Prompt engineering doesn't fix this. Production agents need executable agency boundaries at runtime.

## Bound Agency, Not Frameworks

Agent frameworks build the agent. Edictum bounds the agency.

Use your existing framework as the composition layer, then attach Edictum where tool calls, outputs, workflow evidence, and approvals cross the runtime boundary. Edictum works with LangChain, LangGraph, OpenAI Agents, CrewAI, Claude SDK, Google ADK, Semantic Kernel, Agno, and Nanobot.

| Framework | Adapter | Integration point |
|-----------|---------|-------------------|
| LangChain + LangGraph | `LangChainAdapter` | Tool wrappers and middleware |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | SDK boundary hooks |
| Claude Agent SDK | `ClaudeAgentSDKAdapter` | Agent hook callables |
| CrewAI | `CrewAIAdapter` | Tool registration |
| Agno | `AgnoAdapter` | Tool hook |
| Semantic Kernel | `SemanticKernelAdapter` | Kernel filter |
| Google ADK | `GoogleADKAdapter` | Plugin and agent callbacks |
| Nanobot | `NanobotAdapter` | Tool registry wrapper |

```python
# LangChain
from edictum.adapters.langchain import LangChainAdapter
adapter = LangChainAdapter(guard)
tool = adapter.as_tool_wrapper(tool)

# Claude Agent SDK
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
adapter = ClaudeAgentSDKAdapter(guard)
hooks = adapter.to_hook_callables()

# Google ADK
from edictum.adapters.google_adk import GoogleADKAdapter
adapter = GoogleADKAdapter(guard)
plugin = adapter.as_plugin()
```

See [Adapter docs](https://docs.edictum.ai/docs/adapters/overview) for all 8 Python framework adapters.

## Enterprise Agent Profiles

Enterprises do not just need "more autonomous" or "less autonomous" agents. They need declared profiles that can survive review:

- **Low agency** -- read-only tools, narrow data scope, no external side effects
- **Medium agency** -- scoped writes, ticket-bound actions, workflow stages, evidence, and approval on higher-risk transitions
- **High agency** -- broader write authority, production actions, stricter runtime evidence, approval, audit, and rollback requirements

Every profile has a read scope, a write scope, tool authority, approval requirements, and process obligations. Edictum makes that declared profile executable.

Edictum turns documented agent profiles into executable runtime boundaries.

Medium Agency is the common enterprise starting point right now because it maps to practical internal assistants: agents that can read, draft, edit, file tickets, open PRs, or prepare changes, but need boundaries before production-impacting action. That is the demand center, not the product boundary. Edictum makes any agency level defensible.

## Workflow Gates

Rulesets are one primitive. Workflow Gates enforce ordered process with evidence and approvals: which stage the agent is in, which tools are allowed there, what evidence must exist before moving forward, and when a human must approve the next action.

```yaml
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: read-before-edit
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: Read the spec before editing
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
    approval:
      message: Human approval required before implementation
```

Attach a workflow alongside rules:

```python
guard = Edictum.from_yaml("rules.yaml", workflow_path="workflow.yaml")
```

Now an `Edit` call is blocked until the agent has successfully read `spec.md`, moved into the `implement` stage, and satisfied the configured approval.

## What You Can Do

**Rulesets** -- four rule types covering tool calls, outputs, sessions, and sandbox scope:

- **Preconditions** block dangerous calls before execution
- **Postconditions** scan tool output -- warn, redact PII, or block
- **Session rules** cap total calls, per-tool calls, and retry attempts
- **Sandbox rules** allowlist file paths, commands, and domains

**Workflow Gates** -- ordered runtime stages with allowed tools, entry conditions, exit conditions, recorded evidence, terminal stages, and human approval.

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

## Measurement Boundary

Edictum measures behavioral conformance to a declared agent profile. It tells you whether the agent stayed inside runtime boundaries:

- Blocked actions
- Approval rate
- Workflow completion
- Stuck stages
- Missing evidence
- Profile drift

Edictum does not replace output-quality evals. It does not grade answer accuracy, relevance, coherence, writing quality, or whether the final response is correct. Use output-quality evals for that. Use Edictum to prove what the agent was allowed to do, what it tried to do, what was blocked, what was approved, and which workflow evidence existed at runtime.

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

The Edictum Gate watches every tool call a coding assistant makes and blocks the ones your rules forbid. It sits between the assistant and the operating system.

Use the Go binary in [edictum-go](https://github.com/edictum-ai/edictum-go) -- that is the canonical Edictum CLI. It supports Claude Code, Cursor, Copilot CLI, Gemini CLI, and OpenCode, with optional sync to the [Edictum Control Plane](https://docs.edictum.ai/docs/control-plane) for centralized audit. See the [Gate guide](https://docs.edictum.ai/docs/guides/gate) for setup.

> **The Python `gate` extra was removed in v0.19.0.** Its Claude Code output used a decision value the host rejects, so it did not actually block tools. If you wired `edictum[gate]` into a Claude Code `PreToolUse` hook, switch to the Go CLI. Details in the [v0.19.0 release notes](https://github.com/edictum-ai/edictum/releases).

## Edictum Control Plane

Optional hosted control plane for production agents. Ruleset management, live hot-reload via SSE, human-in-the-loop approvals, audit event feeds, and fleet monitoring.

```python
guard = await Edictum.from_server(
    url="http://localhost:8000",
    api_key="edk_production_...",
    agent_id="my-agent",
)
```

See the [control-plane docs](https://docs.edictum.ai/docs/control-plane) for the current control-plane surface.

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
pip install edictum[verified]    # + Ed25519 bundle signature verification
pip install edictum[server]      # + server SDK (connect to the Edictum Control Plane)
pip install edictum[all]         # everything in this Python package
```

For CLI workflows, use the Go binary in [edictum-go](https://github.com/edictum-ai/edictum-go).

## How It Compares

| Approach | Scope | Runtime enforcement | Audit trail |
|---|---|---|---|
| Prompt/output filters | Input/output text | No -- advisory only | No |
| API gateways / MCP proxies | Network transport | Yes -- at the proxy | Partial |
| Security scanners | Post-hoc analysis | No -- detection only | Yes |
| Manual if-statements | Per-tool, ad hoc | Yes -- scattered logic | No |
| **Edictum** | **Agency boundaries: tools, data, stages, evidence, approvals** | **Yes -- deterministic pipeline** | **Yes -- structured + redacted** |

## Use Cases

| Domain | What Edictum enforces |
|--------|----------------------|
| Coding agents | Secret protection, destructive command blocking, write scope ([Gate guide](https://docs.edictum.ai/docs/guides/gate)) |
| Healthcare | Patient data access control, role-gated queries |
| Finance | PII redaction in query results, transaction limits |
| DevOps | Production deploy gates, ticket requirements, bash safety |
| Education | Student data protection, session limits per assignment |
| Legal | Privileged document access, audit trail for compliance |

## Ecosystem

| Repo | Language | What it does |
|------|----------|-------------|
| [edictum](https://github.com/edictum-ai/edictum) | Python | Core library -- this repo |
| [edictum-ts](https://github.com/edictum-ai/edictum-ts) | TypeScript | Core + adapters (Claude SDK, LangChain, OpenAI Agents, OpenClaw, Vercel AI) |
| [edictum-go](https://github.com/edictum-ai/edictum-go) | Go | Core + adapters (ADK Go, Anthropic, Eino, Genkit, LangChain Go) |
| [Control-plane docs](https://docs.edictum.ai/docs/control-plane) | Docs | Hosted control plane: approvals, audit, rules, fleet monitoring |
| [edictum-schemas](https://github.com/edictum-ai/edictum-schemas) | JSON Schema | Rule bundle schema + cross-SDK conformance fixtures |
| [edictum-demo](https://github.com/edictum-ai/edictum-demo) | Python | Scenario demos, adversarial tests, benchmarks, Grafana observability |
| [Documentation](https://docs.edictum.ai) | MDX | Full docs site |
| [edictum.ai](https://edictum.ai) | -- | Official website |

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[MIT](LICENSE)
