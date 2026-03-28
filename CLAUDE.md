# CLAUDE.md

## What is Edictum

Runtime rule enforcement for AI agent tool calls. Deterministic pipeline: checks, output checks, session rules, principal-aware enforcement. Eight framework adapters (LangChain, CrewAI, Agno, Semantic Kernel, OpenAI Agents SDK, Claude Agent SDK, Nanobot, Google ADK). Zero runtime deps in core.

Current version: 0.16.0 (PyPI: `edictum`)

## Architecture: Core + Server

Two deployment units. One library, one server.

- `src/edictum/` -- MIT core. All rule types (pre, post, session, sandbox), pipeline, 8 adapters, audit to stdout/file/OTel, local approval backend, single-process session tracking.
- `src/edictum/server/` -- Server SDK client (`pip install edictum[server]`). Implements core protocols (`ApprovalBackend`, `AuditSink`, `StorageBackend`) over HTTP to connect agents to the server.
- `edictum-server` -- A separate deployment (coming soon, open source). Centralized approval workflows, audit dashboards, distributed sessions, hot-reload rules, RBAC.

## THE ONE RULE

**Core code (src/edictum/) runs fully standalone. The server SDK (src/edictum/server/) imports from core. The server itself is a separate deployment.**

Core provides protocols and interfaces. The server SDK provides HTTP-backed implementations. The server provides the coordination infrastructure.

## Core (MIT)

- CheckPipeline (evaluation engine)
- ToolCall, Principal model, Session (MemoryBackend)
- YAML rule parsing + validation + templates + composition
- All 8 framework adapters
- Sandbox rules (`type: sandbox`) — allowlist-based governance for file paths, commands, and domains
- Observe mode
- on_postcondition_warn callbacks
- AuditEvent dataclass + StdoutAuditSink + FileAuditSink (.jsonl) + RedactionPolicy
- OTel span instrumentation + GovernanceTelemetry
- Violation classification (`findings.py`, `Finding`) with pii_detected, secret_detected, policy_violation types

## Server (edictum-server)

The server is a separate deployment, coming soon as open source. It provides:

- Production approval workflows (ServerApprovalBackend connects to webhooks, Slack/Teams, review dashboard)
- Centralized audit ingestion and governance dashboard (block rates, rule drift, sandbox violations)
- Distributed session state for multi-agent tracking across processes
- Hot-reload rules via SSE push (ServerContractSource) without restarting agents
- RBAC for rule management (who can create/modify/deploy rules)
- Cross-agent session tracking (correlate tool calls across agents)
- SSO integration (Okta, Azure AD) and JWT/OIDC principal verification

## Boundary Principle

The split follows one rule: **evaluation = core library, coordination = server.**

- Pipeline that takes a tool call and returns allow/block/warn -- core
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

- v0.5.0: Core library — pipeline, 6 adapters, YAML rules, OTel, observe mode
- v0.5.1: Adapter bug fixes (CrewAI, Agno, SK)
- v0.5.2: Adapter bug fixes (LangChain, OpenAI)
- v0.5.3: Claude SDK on_postcondition_warn callback, edictum test (removed — use Go CLI)
- v0.5.4: Dry-run evaluation API (evaluate, evaluate_batch), edictum test --calls
- v0.6.0: Postcondition enforcement effects (redact/block), SideEffect classification
- v0.6.1: YAML tools: section for side-action classifications
- v0.6.2: Renamed to_sdk_hooks() → to_hook_callables()
- v0.7.0: env.* selector, Edictum.from_multiple() guard merging, Claude Code GitHub Actions
- v0.8.0: Bundle composition (compose_bundles, from_yaml multi-file), dual-mode evaluation
- v0.8.1: ContractResult → RuleResult rename, terminology enforcement
- v0.9.0: YAML extensibility (custom_operators, custom_selectors, metadata.* selector, template_dirs, from_yaml_string), adapter lifecycle (on_deny, on_allow, success_check, set_principal, principal_resolver), CompositeSink, --json/--environment flags (removed — use Go CLI), OTel TLS
- Docs overhaul: homepage, quickstart, concepts section, patterns, 7 guides
- edictum-demo repo: github.com/edictum-ai/edictum-demo
- v0.10.0: HITL approval workflows (ApprovalBackend, action: ask, timeout/timeout_action), wildcard tool matching (fnmatch), Nanobot adapter, Server SDK package (edictum[server])
- v0.11.0: Sandbox rules (type: sandbox) — allowlist-based governance for file paths, commands, and domains. Pipeline stage between checks and session rules.
- v0.11.1: Fix path traversal bypass in sandbox within/not_within checks (os.path.normpath normalization)
- v0.11.2: Security hardening — ServerBackend fail-closed, BashClassifier operator coverage, symlink resolution in sandbox, approval timeout audit accuracy, tool_name validation, MemoryBackend atomicity
- v0.11.3: Adversarial test suite, CI hardening (bandit + security test step), code-reviewer security criteria, architecture.md refresh
- v0.14.0: Google ADK adapter — plugin and agent callback integration for Google Agent Development Kit (8th framework adapter)
- v0.15.0: Edictum Gate (coding assistant governance), `CollectingAuditSink`, `Edictum.from_server()`, `Edictum.reload()`, `Edictum.close()`, SSE watcher, server rule source revision tracking, `ServerAuditSink` multi-bundle support. Default audit sink changed from `StdoutAuditSink` to `CollectingAuditSink` only.
- v0.16.0: `edictum skill scan` CLI for skill security analysis. Ed25519 bundle signature verification (`edictum[verified]`). Server HTTPS enforcement. Batch session counter reads. Cross-SDK conformance runner. Terminology rename `shadow_*` → `observe_*` completed. Removed `ShadowContract` deprecation alias and `"shadows"` backward-compat JSON key. 14 security fixes including session injection, shell separator bypass, and redaction gaps.

## Session Model

MemoryBackend stores counters in a Python dict -- one process, one agent. This covers the vast majority of use cases. For multi-agent coordination across processes, edictum-server handles centralized session tracking. There is no DIY Redis/DynamoDB path.

## Build & Test

```bash
pytest tests/ -v              # full test suite
ruff check src/ tests/        # lint
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
| contract / contracts | rule / rules |
| denied | blocked |
| finding | violation |
| engine (for runtime) | pipeline |
| shadow mode | observe mode |

**Exception**: None. There are no exceptions. The class was renamed from `ContractResult` to `RuleResult` in v0.8.1 to eliminate the last holdout.

Before writing ANY user-facing string, comment, docstring, or documentation, check it against the glossary.

## API Design Checklist

Before adding any new public API (function, method, parameter, class), verify ALL of these:

- **Every accepted parameter has an observable action.** If the parameter is in the signature, there must be a test proving it changes behavior. If unimplemented, raise `NotImplementedError` — never silently ignore.
- **Collection parameters have documented merge semantics.** If a parameter accepts a set/list/dict, document and test whether it EXTENDS defaults or REPLACES them. Use `merged = defaults | custom` for union.
- **Block decisions propagate end-to-end.** If the pipeline returns block, trace the path through every adapter. Never return a generic "allow" after processing a block.
- **Callbacks fire exactly once.** If a callback is invoked in an inner method AND an outer wrapper, one must be removed. Assert `callback.call_count == 1` in tests.
- **All adapters handle the new feature.** Run `pytest tests/test_adapter_parity.py -v` after any adapter change.
- **No ghost features.** If you add it to CLAUDE.md, architecture.md, or any doc page, the code must exist. Run `pytest tests/test_docs_sync.py -v`.

## Security Review Checklist

Before merging ANY code that touches these areas, verify:

- **Path handling**: Uses `os.path.realpath()` not just `normpath()`. Test with symlinks.
- **Shell command classification**: All shell metacharacters enumerated. Test with: \n, \r, |, ;, &&, ||, $(), \`\`, ${}, <(), <<, >, >>
- **Error handling in backends**: `get()` and `increment()` fail-closed. Network errors propagate, only 404 returns None.
- **Audit action accuracy**: Audit events reflect what actually happened, not just the final decision. Timeouts emit TIMEOUT, not GRANTED.
- **Input validation**: tool_name, session_id, any string used in storage keys or log messages validated for control characters.
- **Concurrency**: Read-modify-write operations use `asyncio.Lock`. Single dict operations are safe without locks.

## Behavior Test Requirement

Every public API parameter MUST have a behavior test in `tests/test_behavior/`.

A behavior test answers: "What observable action does this parameter have?"

- Tests the parameter's action through the public API (not internal state)
- Asserts a concrete difference between passing and not passing the parameter
- Lives in `tests/test_behavior/test_{module}_behavior.py`
- Keep test files focused: one file per module, under 200 lines

## Negative Security Test Requirement

Every security boundary MUST have bypass tests — tests that attempt to circumvent the boundary and verify the attempt is caught. These go in `tests/test_behavior/` alongside the positive tests, marked with `@pytest.mark.security`.

Examples:
- Sandbox: symlink escape, double-encoding, null byte injection
- BashClassifier: every shell metacharacter individually
- Session limits: concurrent access, counter reset on backend failure
- Approval: timeout edge cases, status/action combinations
- Input validation: null bytes, control characters, path separators in tool_name

## Pre-Merge Verification

Every change MUST pass these checks before committing:

```bash
pytest tests/ -v                    # full test suite
ruff check src/ tests/              # lint
pytest tests/test_docs_sync.py -v   # docs-code sync
# If touching adapters:
pytest tests/test_adapter_parity.py -v
```

## Pre-Release Checklist

Before tagging a release:

1. `grep -rn` for banned terms (contract/contracts, denied, engine, shadow mode) in src/, docs/, CHANGELOG.md
2. Verify CLI output strings match .docs-style-guide.md terminology
3. Verify YAML examples in release notes use correct schema (`then:` block with `action:` and `message:`, not `effect:`)
4. Verify release notes prose uses canonical terms
5. Run: `pytest tests/ -v && ruff check src/ tests/`

## YAML Schema (locked)

- `apiVersion: edictum/v1`, `kind: Ruleset`
- Rule types: `type: pre` (block/ask), `type: post` (warn/redact/block), `type: session` (block only), `type: sandbox` (allowlist-based, outside: block/ask)
- Conditions: `when:` with boolean AST (`all/any/not`) and leaves (`selector: {operator: value}`)
- 15 operators: exists, equals, not_equals, in, not_in, contains, contains_any, starts_with, ends_with, matches, matches_any, gt, gte, lt, lte
- Missing fields evaluate to `false`. Type mismatches yield block/warn + `policy_error: true`
- Regex: Python `re` module, single-quoted in YAML docs (`'\b'` not `"\b"`)
- Bundle hash: SHA256 of raw YAML bytes -> `policy_version` on every audit event

## Cross-SDK Conformance Workflow

When a change affects shared semantics, YAML validation, fixture behavior, audit/tool_call wire format, or policy evaluation behavior, you MUST follow this workflow before merging:

1. **Update shared fixtures** in `edictum-schemas` — add or modify `fixtures/rejection/*.rejection.yaml` files as needed
2. **Update canonical Python behavior** in this repo if the change originates here
3. **Ensure all three SDKs pass** — Python, Go (`edictum-go`), and TypeScript (`edictum-ts`) shared-fixture runners must all pass with `EDICTUM_CONFORMANCE_REQUIRED=1`
4. **Do not merge** parity-affecting behavior without the Parity Check workflow passing in all affected repos

The conformance runner in this repo lives at `tests/test_conformance/test_rejection.py` and is executed in CI by:

```bash
EDICTUM_SCHEMAS_DIR=edictum-schemas EDICTUM_CONFORMANCE_REQUIRED=1 \
  pytest tests/test_conformance/ -v
```

The `Parity Check` workflow (`.github/workflows/parity-check.yml`) runs on PRs to main, pushes to main, and weekly. It is intended to be a required status check.
