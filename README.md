# Edictum

[![PyPI](https://img.shields.io/pypi/v/edictum?cacheSeconds=3600)](https://pypi.org/project/edictum/)
[![License](https://img.shields.io/pypi/l/edictum?cacheSeconds=86400)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/edictum?cacheSeconds=86400)](https://pypi.org/project/edictum/)

Runtime contract enforcement for AI agent tool calls.

Prompts are suggestions. Contracts are enforcement.
The LLM cannot talk its way past a contract.

## Why This Exists

An agent says "I won't read sensitive files" -- then calls `read_file(".env")` and leaks your API keys.

A DevOps agent recognizes a jailbreak attempt, writes "I should NOT comply" in its reasoning -- then reads four production database credentials in the next tool call.

A medical assistant promises to respect patient privacy -- then dumps an entire clinical record into a chat response because nothing actually stops it.

Prompt engineering doesn't fix this. You need enforcement at the tool-call layer.

## Without Edictum / With Edictum

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

Contracts are YAML. Enforcement is deterministic. The agent cannot bypass it.

## How It Compares

| Approach | Scope | Runtime enforcement | Audit trail |
|---|---|---|---|
| Prompt/output guardrails | Input/output text | No -- advisory only | No |
| API gateways / MCP proxies | Network transport | Yes -- at the proxy | Partial |
| Security scanners | Post-hoc analysis | No -- detection only | Yes |
| Manual if-statements | Per-tool, ad hoc | Yes -- scattered logic | No |
| **Edictum** | **Tool call contracts** | **Yes -- deterministic pipeline** | **Yes -- structured + redacted** |

## Quick Start

One line with a built-in template:

```python
guard = Edictum.from_template("file-agent")  # secret protection, destructive command denial
```

Or write your own contracts in YAML:

```python
guard = Edictum.from_yaml("contracts.yaml")
```

See the [quickstart guide](https://docs.edictum.dev/quickstart/) to write your first contract and deny a dangerous call in five minutes.

## What You Can Do

**Write and enforce contracts**

- Preconditions deny dangerous calls before execution
- Postconditions scan tool output -- warn, redact PII, or deny entirely
- Session contracts cap total calls, per-tool calls, and retry attempts
- Role-gate tools with `principal` claims and `env.*` environment context
- `on_deny` / `on_allow` callbacks for deny logging, alerting, or approval workflows
- `set_principal()` for mid-session role changes (analyst -> operator escalation)

**Test and validate**

- `edictum validate` -- catch schema errors at load time, not runtime
- `edictum test` -- YAML test cases with expected verdicts
- `guard.evaluate()` -- dry-run contracts without executing the tool
- CI/CD exit codes for pipeline gating

**Ship safely**

- Observe mode -- log what would be denied, tune contracts, then enforce
- `observe_alongside` -- shadow-test new contracts next to production
- `edictum diff` -- see what changed between contract bundle versions
- `edictum replay` -- replay audit logs against updated contracts to predict drift
- Multi-file composition with `from_yaml()` and deterministic merge
- Custom YAML operators and selectors for domain-specific contract logic

**Automatic security (zero config)**

- Secret values auto-redacted in audit events and denial messages
- Bash commands sanitized (passwords, tokens, connection strings)
- Regex inputs capped to prevent ReDoS
- Audit payloads capped at 32KB
- All contract errors fail closed -- never silently pass

**Observe everything**

- Structured audit events on every evaluation
- OpenTelemetry spans and metrics
- Policy version hash on every event
- File and stdout sinks included; `CompositeSink` fans out to multiple destinations
- `--json` CLI output for CI/CD pipeline integration

**Works with 7 frameworks**

| Framework | Integration | PII Redaction | Complexity |
|-----------|------------|---------------|------------|
| LangChain + LangGraph | `as_tool_wrapper()` | Full interception | Low |
| OpenAI Agents SDK | `as_guardrails()` | Logged only | Medium |
| Agno | `as_tool_hook()` | Full interception | Low |
| Semantic Kernel | `register()` | Full interception | Medium-High |
| CrewAI | `register()` | Partial | High |
| Claude Agent SDK | `to_hook_callables()` | Logged only | Low |
| Nanobot | `wrap_registry()` | Full interception | Low |

See [Adapter Docs](https://docs.edictum.dev/adapters/overview/) for setup, known limitations, and recommendations.

## Use Cases

| Domain | What Edictum enforces |
|--------|----------------------|
| Coding agents | Secret protection, destructive command denial, write scope |
| Healthcare | Patient data access control, role-gated queries |
| Finance | PII redaction in query results, transaction limits |
| DevOps | Production deploy gates, ticket requirements, bash safety |
| Education | Student data protection, session limits per assignment |
| Legal | Privileged document access, audit trail for compliance |

See [Use Cases](https://docs.edictum.dev/use-cases/) for complete YAML bundles and wiring code.

## Install

Requires Python 3.11+. Current version: **v0.9.0**.

```bash
pip install edictum              # core (zero deps)
pip install edictum[yaml]        # + YAML contract parsing
pip install edictum[otel]        # + OpenTelemetry span emission
pip install edictum[cli]         # + validate/check/diff/replay CLI
pip install edictum[server]      # + server SDK (approvals, audit, sessions via HTTP)
pip install edictum[all]         # everything
```

## Built-in Templates

```python
guard = Edictum.from_template("file-agent")      # secret file protection, destructive cmd denial
guard = Edictum.from_template("research-agent")   # output PII detection, session limits
guard = Edictum.from_template("devops-agent")     # role gates, ticket requirements, bash safety
guard = Edictum.from_template("nanobot-agent")    # approval gates, path restrictions, session limits
```

## Demos & Examples

- **[edictum-demo](https://github.com/acartag7/edictum-demo)** -- Full scenario demos, adversarial tests, benchmarks, and Grafana observability
- **[Contract Patterns](https://docs.edictum.dev/contracts/patterns/)** -- Real-world contract recipes by concern
- **[Framework Adapters](https://docs.edictum.dev/adapters/overview/)** -- Integration guides for six frameworks

## Research

Edictum was evaluated across six regulated domains in the GAP benchmark.

[Paper](https://arxiv.org/abs/2602.16943) · [Benchmark](https://github.com/acartag7/gap-benchmark)

## Links

- [Documentation](https://docs.edictum.dev/)
- [GitHub](https://github.com/acartag7/edictum)
- [PyPI](https://pypi.org/project/edictum/)
- [Changelog](CHANGELOG.md)
- [License](LICENSE) (MIT)
