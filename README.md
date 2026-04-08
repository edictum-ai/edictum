# edictum

> Declarative behavior rules for AI agents. Write rules in YAML. Enforce them at runtime.

[![PyPI](https://img.shields.io/pypi/v/edictum?cacheSeconds=3600)](https://pypi.org/project/edictum/)
[![Tests](https://github.com/edictum-ai/edictum/actions/workflows/ci.yml/badge.svg)](https://github.com/edictum-ai/edictum/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/edictum?cacheSeconds=86400)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/edictum?cacheSeconds=86400)](https://pypi.org/project/edictum/)

## The Problem

`CLAUDE.md` is a wish list. The GAP benchmark found a 55-79% gap between what frontier agents refuse in text and what they still do through tool calls. Your agent says "I won't do that" and then does it anyway.

Edictum intercepts the tool call, not the model's explanation. You write the rule once in YAML, then enforce it at runtime across frameworks.

## Quick Start

Install YAML support:

```bash
pip install edictum[yaml]
```

Requires Python 3.11+.

Core-only install stays zero-dependency:

```bash
pip install edictum
```

1. Write a ruleset.

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
    tool: Read
    when:
      args.file_path:
        contains_any: [".env", ".pem", "id_rsa", "credentials"]
    then:
      action: block
      message: "Sensitive file '{args.file_path}' is blocked."
```

2. Load it.

```python
from edictum import Edictum

guard = Edictum.from_yaml("rules.yaml")
```

3. Wrap the tool call.

```python
from edictum import EdictumDenied


async def read_file(file_path: str) -> str:
    with open(file_path) as f:
        return f.read()


try:
    result = await guard.run(
        "Read",
        {"file_path": ".env"},
        read_file,
    )
except EdictumDenied as exc:
    print(exc.reason)
```

## Workflow Gates

Rules block one tool call at a time. Workflow gates enforce process across a session: what has been read, which stage is active, which commands are allowed, and where human approval is required.

```yaml
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: ship-feature
  description: "Read, implement, verify, review"
  version: "1.0"

stages:
  - id: read-context
    description: "Read the spec"
    tools: [Read]
    exit:
      - condition: file_read("specs/feature.md")
        message: "Read the spec first"

  - id: implement
    description: "Make the change"
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit, Write]

  - id: local-verify
    description: "Run tests"
    entry:
      - condition: stage_complete("implement")
    tools: [Bash]
    checks:
      - command_matches: "^pytest tests/ -q$"
        message: "Only the test command is allowed here"
    exit:
      - condition: command_matches("^pytest tests/ -q$")
        message: "Run the test command before moving on"

  - id: review
    description: "Pause for approval"
    entry:
      - condition: stage_complete("local-verify")
    approval:
      message: "Human approval required before push"
```

## Rules Engine

The rules engine is deterministic, model-agnostic, and cheap enough to sit on every tool call.

```yaml
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: command-rules
defaults:
  mode: enforce
rules:
  - id: block-force-push
    type: pre
    tool: Bash
    when:
      args.command:
        matches_any:
          - 'git\\s+push\\s+.*--force'
          - 'git\\s+push\\s+-f\\b'
    then:
      action: block
      message: "Force push is blocked."

  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII pattern detected in output. Redact before using."
```

Edictum supports pre rules, post rules, session rules, sandbox rules, workflow gates, and `action: ask` approvals.

## Adapters

| Framework | Python adapter | Integration |
| --- | --- | --- |
| LangChain / LangGraph | `LangChainAdapter` | `as_middleware()`, `as_tool_wrapper()` |
| CrewAI | `CrewAIAdapter` | `register()` |
| Agno | `AgnoAdapter` | `as_tool_hook()` |
| Semantic Kernel | `SemanticKernelAdapter` | `register()` |
| OpenAI Agents SDK | `OpenAIAgentsAdapter` | `as_guardrails()` |
| Claude Agent SDK | `ClaudeAgentSDKAdapter` | `to_hook_callables()` |
| Google ADK | `GoogleADKAdapter` | `as_plugin()`, `as_agent_callbacks()` |
| Nanobot | `NanobotAdapter` | `wrap_registry()` |

## How It Works

Edictum sits at the tool-call boundary. Adapters translate framework-specific tool events into a shared `ToolCall`, the pipeline evaluates rules and workflow state with deterministic checks, and the decision is applied before or after execution. No LLM is involved in enforcement, and the same ruleset can follow the agent across frameworks.

## Research

Edictum is built on the GAP benchmark: 17,420 datapoints across 6 frontier models showing a 55-79% gap between text refusal and tool-call execution. Existing guardrails mostly inspect what the model says. Edictum focuses on what the agent does.

- Paper: [arXiv:2602.16943](https://arxiv.org/abs/2602.16943)
- Docs: [docs.edictum.ai](https://docs.edictum.ai)
- Package: [PyPI](https://pypi.org/project/edictum/)

## License

[MIT](LICENSE)
