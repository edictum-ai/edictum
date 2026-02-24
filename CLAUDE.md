# CLAUDE.md

## What is Edictum

Runtime contract enforcement for AI agent tool calls. Deterministic pipeline: preconditions, postconditions, session contracts, principal-aware enforcement. Seven framework adapters (LangChain, CrewAI, Agno, Semantic Kernel, OpenAI Agents SDK, Claude Agent SDK, Nanobot). Zero runtime deps in core.

Current version: 0.11.0 (PyPI: `edictum`)

## Architecture: Core + Server

Two deployment units. One library, one server.

- `src/edictum/` -- MIT core. All contract types (pre, post, session, sandbox), pipeline, 7 adapters, CLI, audit to stdout/file/OTel, local approval backend, single-process session tracking.
- `src/edictum/server/` -- Server SDK client (`pip install edictum[server]`). Implements core protocols (`ApprovalBackend`, `AuditSink`, `StorageBackend`) over HTTP to connect agents to the server.
- `edictum-server` -- A separate deployment (coming soon, open source). Centralized approval workflows, audit dashboards, distributed sessions, hot-reload contracts, RBAC.

## THE ONE RULE

**Core code (src/edictum/) runs fully standalone. The server SDK (src/edictum/server/) imports from core. The server itself is a separate deployment.**

Core provides protocols and interfaces. The server SDK provides HTTP-backed implementations. The server provides the coordination infrastructure.

## Core (MIT)

- GovernancePipeline (evaluation engine)
- ToolEnvelope, Principal model, Session (MemoryBackend)
- YAML contract parsing + validation + templates + composition
- All 7 framework adapters
- Sandbox contracts (`type: sandbox`) — allowlist-based governance for file paths, commands, and domains
- Observe mode (shadow deploy)
- on_postcondition_warn callbacks
- edictum check + edictum test CLI
- AuditEvent dataclass + StdoutAuditSink + FileAuditSink (.jsonl) + RedactionPolicy
- OTel span instrumentation + GovernanceTelemetry
- Finding classification (findings.py) with pii_detected, secret_detected, policy_violation types

## Server (edictum-server)

The server is a separate deployment, coming soon as open source. It provides:

- Production approval workflows (ServerApprovalBackend connects to webhooks, Slack/Teams, review dashboard)
- Centralized audit ingestion and governance dashboard (denial rates, contract drift, sandbox violations)
- Distributed session state for multi-agent tracking across processes
- Hot-reload contracts via SSE push (ServerContractSource) without restarting agents
- RBAC for contract management (who can create/modify/deploy contracts)
- Cross-agent session tracking (correlate tool calls across agents)
- SSO integration (Okta, Azure AD) and JWT/OIDC principal verification

## Boundary Principle

The split follows one rule: **evaluation = core library, coordination = server.**

- Pipeline that takes a tool call and returns allow/deny/warn -- core
- Persistence beyond local files, networking, coordination across processes -- server
- Stdout + File (.jsonl) sinks for dev/local audit -- core. Centralized audit dashboards and alerting -- server
- OTel instrumentation (emitting spans) -- core. Governance dashboards -- server
- Session (MemoryBackend) for single-process -- core. Multi-process session state via edictum-server -- server
- LocalApprovalBackend for development approval -- core. Production approval workflows (webhooks, Slack, review UI) -- server

## Dropped Features (do NOT implement)

- `reset_session()` — new run_id handles this naturally
- Redis StorageBackend — not our problem, application layer concern
- DB StorageBackend — OTel already covers queryable audit data

## What's Shipped

- v0.5.0: Core library — pipeline, 6 adapters, YAML contracts, CLI check, OTel, observe mode
- v0.5.1: Adapter bug fixes (CrewAI, Agno, SK)
- v0.5.2: Adapter bug fixes (LangChain, OpenAI)
- v0.5.3: Claude SDK on_postcondition_warn callback, edictum test CLI
- v0.5.4: Dry-run evaluation API (evaluate, evaluate_batch), edictum test --calls
- v0.6.0: Postcondition enforcement effects (redact/deny), SideEffect classification
- v0.6.1: YAML tools: section for side-effect classifications
- v0.6.2: Renamed to_sdk_hooks() → to_hook_callables()
- v0.7.0: env.* selector, Edictum.from_multiple() guard merging, Claude Code GitHub Actions
- v0.8.0: Bundle composition (compose_bundles, from_yaml multi-file), dual-mode evaluation
- v0.8.1: RuleResult → ContractResult rename, terminology enforcement
- v0.9.0: YAML extensibility (custom_operators, custom_selectors, metadata.* selector, template_dirs, from_yaml_string), adapter lifecycle (on_deny, on_allow, success_check, set_principal, principal_resolver), CompositeSink, CLI --json/--environment, OTel TLS
- Docs overhaul: homepage, quickstart, concepts section, patterns, 7 guides
- edictum-demo repo: github.com/acartag7/edictum-demo
- v0.10.0: HITL approval workflows (ApprovalBackend, effect: approve, timeout/timeout_effect), wildcard tool matching (fnmatch), Nanobot adapter, Server SDK package (edictum[server])
- v0.11.0: Sandbox contracts (type: sandbox) — allowlist-based governance for file paths, commands, and domains. Pipeline stage between preconditions and session.

## Session Model

MemoryBackend stores counters in a Python dict -- one process, one agent. This covers the vast majority of use cases. For multi-agent coordination across processes, edictum-server handles centralized session tracking. There is no DIY Redis/DynamoDB path.

## Build & Test

```bash
pytest tests/ -v              # full test suite
ruff check src/ tests/        # lint
python -m mkdocs build --strict  # docs build
edictum validate contracts.yaml  # validate YAML contracts
```

## Code Conventions

- Python 3.11+
- `from __future__ import annotations` in every file
- Frozen dataclasses for immutable data
- Type hints everywhere
- Async: all pipeline, session, and audit sink methods are async
- Testing: pytest + pytest-asyncio, maintain 97%+ coverage
- Commits: conventional commits (feat/fix/docs/test/refactor/chore), no Co-Authored-By
- PRs: small and focused, Linear ticket in PR description not title

## Terminology Enforcement

The binding glossary is `.docs-style-guide.md`. ALL code, comments, docstrings, CLI output, docs, release notes, and CHANGELOG entries MUST use these canonical terms:

| Wrong | Correct |
|-------|---------|
| rule / rules (in prose) | contract / contracts |
| blocked | denied |
| engine (for runtime) | pipeline |
| shadow mode | observe mode |
| alert | finding |

**Exception**: None. There are no exceptions. The class was renamed from `RuleResult` to `ContractResult` in v0.8.1 to eliminate the last holdout.

Before writing ANY user-facing string, comment, docstring, or documentation, check it against the glossary.

## API Design Checklist

Before adding any new public API (function, method, parameter, class), verify ALL of these:

- **Every accepted parameter has an observable effect.** If the parameter is in the signature, there must be a test proving it changes behavior. If unimplemented, raise `NotImplementedError` — never silently ignore.
- **Collection parameters have documented merge semantics.** If a parameter accepts a set/list/dict, document and test whether it EXTENDS defaults or REPLACES them. Use `merged = defaults | custom` for union.
- **Deny decisions propagate end-to-end.** If the pipeline returns deny, trace the path through every adapter. Never return a generic "allow" after processing a deny.
- **Callbacks fire exactly once.** If a callback is invoked in an inner method AND an outer wrapper, one must be removed. Assert `callback.call_count == 1` in tests.
- **All adapters handle the new feature.** Run `pytest tests/test_adapter_parity.py -v` after any adapter change.
- **No ghost features.** If you add it to CLAUDE.md, architecture.md, or any doc page, the code must exist. Run `pytest tests/test_docs_sync.py -v`.

## Behavior Test Requirement

Every public API parameter MUST have a behavior test in `tests/test_behavior/`.

A behavior test answers: "What observable effect does this parameter have?"

- Tests the parameter's effect through the public API (not internal state)
- Asserts a concrete difference between passing and not passing the parameter
- Lives in `tests/test_behavior/test_{module}_behavior.py`
- Keep test files focused: one file per module, under 200 lines

## Pre-Merge Verification

Every change MUST pass these checks before committing:

```bash
pytest tests/ -v                    # full test suite
ruff check src/ tests/              # lint
pytest tests/test_docs_sync.py -v   # docs-code sync
python -m mkdocs build --strict     # docs build
# If touching adapters:
pytest tests/test_adapter_parity.py -v
```

## Pre-Release Checklist

Before tagging a release:

1. `grep -rn` for banned terms (rule/rules in prose, blocked, engine, shadow mode, alert) in src/, docs/, CHANGELOG.md
2. Verify CLI output strings match .docs-style-guide.md terminology
3. Verify YAML examples in release notes use correct schema (`then:` block with `effect:` and `message:`, not `action:`)
4. Verify release notes prose uses canonical terms
5. Run: `pytest tests/ -v && ruff check src/ tests/ && python -m mkdocs build --strict`

## YAML Schema (locked)

- `apiVersion: edictum/v1`, `kind: ContractBundle`
- Contract types: `type: pre` (deny/approve), `type: post` (warn/redact/deny), `type: session` (deny only), `type: sandbox` (allowlist-based, outside: deny/approve)
- Conditions: `when:` with boolean AST (`all/any/not`) and leaves (`selector: {operator: value}`)
- 15 operators: exists, equals, not_equals, in, not_in, contains, contains_any, starts_with, ends_with, matches, matches_any, gt, gte, lt, lte
- Missing fields evaluate to `false`. Type mismatches yield deny/warn + `policy_error: true`
- Regex: Python `re` module, single-quoted in YAML docs (`'\b'` not `"\b"`)
- Bundle hash: SHA256 of raw YAML bytes -> `policy_version` on every audit event
