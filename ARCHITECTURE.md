# Edictum Architecture

> Developer agent behavior platform for Python. Rulesets, workflow gates, adapters, and decision logs around one deterministic pipeline.

## Shape Of The Repo

Edictum has two Python layers:

- `src/edictum/` is the standalone core library. It loads rulesets, evaluates tool calls, tracks local session state, runs workflow gates, and emits decision logs.
- `src/edictum/server/` is the server SDK. It implements the same core protocols over HTTP so a Python agent can use a remote approval backend, remote rule source, remote session store, and remote log destination.

The server itself is a separate deployment. This repo ships the core library and the Python server client.

## Package Layout

```text
src/edictum/
├── __init__.py
├── _guard.py              # Edictum class and public construction paths
├── _runner.py             # guard.run() execution path
├── _factory.py            # from_yaml(), from_template(), from_multiple()
├── rules.py               # Python rule decorators
├── pipeline.py            # Deterministic pre/post evaluation pipeline
├── envelope.py            # ToolCall model, tool registry, bash classifier
├── session.py             # Local session counters and state helpers
├── approval.py            # Human approval backends
├── audit.py               # Decision log event model and log destinations
├── evaluation.py          # Dry-run evaluation results
├── findings.py            # Structured post-rule violations
├── workflow/              # WorkflowDefinition, WorkflowRuntime, loaders, evaluators
├── yaml_engine/           # Ruleset schema, loader, composer, compiler, templates
├── adapters/
│   ├── langchain.py
│   ├── crewai.py
│   ├── agno.py
│   ├── semantic_kernel.py
│   ├── openai_agents.py
│   ├── claude_agent_sdk.py
│   ├── google_adk.py
│   └── nanobot.py
├── gate/                  # Coding assistant hook runtime
├── server/                # HTTP-backed SDK implementations
├── skill/                 # Skill scanning and risk analysis
└── telemetry.py / otel.py # Optional OpenTelemetry integration
```

## Runtime Flow

1. A framework adapter, Gate hook, or direct `guard.run()` call creates a `ToolCall`.
2. `CheckPipeline.pre_execute()` evaluates before-hooks, pre rules, sandbox rules, session rules, approvals, and workflow stage rules.
3. If the decision is `block`, execution stops and a decision log event is emitted. If the decision is `ask`, execution pauses for approval. If the decision is `allow`, the tool runs.
4. `CheckPipeline.post_execute()` evaluates post rules, records workflow evidence, updates session counters, and emits the final decision log event.

The pipeline is the single source of truth. Adapters are translation layers. They should not contain separate rule logic.

## Workflow Module

The workflow runtime is separate from one-shot rules because it tracks process across calls:

- `workflow/definition.py` validates `kind: Workflow` documents.
- `workflow/load.py` parses workflow YAML from files or strings.
- `workflow/runtime.py` manages stage state, entry gates, exit gates, command checks, and approvals.
- `workflow/runtime_eval.py` evaluates a live `ToolCall` against the active workflow stage.
- `workflow/evaluator_exec.py` provides the opt-in trusted `exec(...)` evaluator for stage conditions.

Workflow state is attached to the same session model the rules pipeline uses, so stage moves, approvals, evidence, and tool-call decisions stay aligned.

## Adapters

The Python SDK ships eight adapters:

- `LangChainAdapter`
- `CrewAIAdapter`
- `AgnoAdapter`
- `SemanticKernelAdapter`
- `OpenAIAgentsAdapter`
- `ClaudeAgentSDKAdapter`
- `GoogleADKAdapter`
- `NanobotAdapter`

Each adapter maps its framework's tool-call lifecycle onto the same core pipeline. The adapter owns translation. The pipeline owns decisions.

## Design Notes

- Core stays standalone. No runtime network dependency is required for local enforcement.
- YAML rulesets and Python decorators both compile to the same runtime model.
- Workflow gates are explicit opt-in stateful process enforcement on top of per-call rules.
- Decision logs are structured and redact sensitive values before emission.
- OpenTelemetry is optional. If the dependency is missing, tracing is a no-op.
- The `gate/` package is the coding-assistant runtime layer, not a separate rules engine.
