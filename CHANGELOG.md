# Changelog

## 0.18.0

### Added
- **v0.18 workflow shared semantics** — workflow definitions now support wildcard stage tools, terminal stages, MCP evidence checks, and ruleset inheritance via `extends` (#199)
- **Python server client parity** — the Python SDK now exposes the hosted/server capabilities needed to stay aligned with the control-plane surface (#189)
- **Non-destructive stage moves and lineage state** — workflow state now carries session lineage and supports explicit non-destructive stage transitions (#187, #188)

### Fixed
- **Workflow stage enforcement correctness** — adapter conformance, stage transitions, and current-stage check failures now block and advance consistently (#190, #193, #195)

### Changed
- Refreshed docs and repository wording to use the current control-plane naming consistently (#202, #203)

## 0.17.0

### Added
- **Workflow runtime enforcement** — `WorkflowRuntime`, `WorkflowDefinition`, `WorkflowStage`, `WorkflowGate`, `WorkflowApproval`, `WorkflowCheck`, `WorkflowMetadata`, `WorkflowEvaluation`, `WorkflowEvidence`, `WorkflowState`, `load_workflow()`, and `load_workflow_string()` add explicit workflow loading, runtime stage gating, workflow approvals, and opt-in `exec(...)` workflow conditions (#181)
- **Workflow adapter validation coverage** — adapter integration tests now validate workflow evidence recording for CrewAI, Google ADK, LangChain, and OpenAI Agents SDK flows (#182)

### Changed
- Updated governance and repository markdown to use the M1 terminology consistently: rules/rulesets, ToolCall, Decision, CheckPipeline, blocked, and violations (#178)
- Refreshed YAML examples and reviewer guidance to use `kind: Ruleset`, `rules:`, and `action:` (#178)
- Bumped `langchain-core` from 1.2.17 to 1.2.22 (#177)
- Bumped `pygments` from 2.19.2 to 2.20.0 (#183)
- **Workflow final-stage completion** — final workflow stages without an explicit `exit:` gate or `approval:` remain the active stage after a successful tool call. Add an `exit:` gate or `approval:` to emit `workflow_completed` for the final stage. (#190)

### Removed
- **Python CLI removed.** The `edictum` CLI commands (validate, check, test, diff, replay, gate, skill) are no longer part of the Python package. Use the Go binary (`edictum-go`) for all CLI workflows. The Python package is now library-only. (#180)

### Security
- Bumped `cryptography` from 46.0.5 to 46.0.6 (#179)

## 0.16.0

### Added
- **`edictum skill scan`** — deterministic security analysis for AI agent skill files (SKILL.md). Pattern matching for dangerous commands, credential access, exfiltration domains, obfuscation signals, and base64 payloads. Risk tiering: CRITICAL/HIGH/MEDIUM/CLEAN. JSON output, `--threshold` filtering, `--structural-only` mode, optional `--server` upload (#169)
- **Ed25519 bundle signature verification** — `verify_signatures` and `signing_public_key` parameters on `from_server()`, `verify_bundle_signature()` and `BundleVerificationError` in `edictum.server`, `edictum[verified]` extra installs PyNaCl (#116)
- **Server HTTPS enforcement** — `EdictumServerClient` enforces HTTPS by default; plaintext HTTP requires explicit `allow_http=True` (#114)
- **Batch session counter reads** — `ServerSessionBackend.batch_get()` reduces HTTP round trips for session counter checks, with 405 fallback to sequential reads (#115, #120)
- **Cross-SDK conformance runner** — shared rejection fixtures from `edictum-schemas` validate evaluation parity across Python, Go, and TypeScript SDKs (#168)
- **Parity check workflow** — CI workflow validates cross-SDK fixture conformance on PRs and pushes to main (#156, #170)
- **pdoc API reference generation** — auto-generated API docs from source docstrings (#153)

### Fixed
- **7 verified security bugs** — session injection via crafted session IDs, approval redaction leaking secrets in audit, sensitive key matching bypassed by substrings, observe-mode postconditions silently dropped, audit auth action misclassified, SSE reconnect timeout drift, Ed25519 key length validation (#138)
- **Shell separators in command allowlist** — sandbox command allowlist checks now reject shell separators (`;`, `&&`, `||`, `|`) preventing command chaining bypasses (#167)
- **Bash redaction on string values** — `redact_args` now applies bash-pattern redaction (API keys, tokens) to string values, not just command strings (#151)
- **Word-boundary matching in `_is_sensitive_key`** — prevents false positives on substrings like "password_reset_url" matching "password" (#157)
- **Shell-aware tokenization** — sandbox path and URL extraction uses proper shell tokenization instead of naive splitting (#112)
- **`ToolCall.__post_init__` validation** — prevents bypass via direct construction with invalid fields (#106)
- **`CompositeSink` fault isolation** — emits to all sinks even when one fails, preventing audit loss (#108)
- **Bare `$VAR` detection in `BashClassifier`** — catches unquoted variable expansions as potential injection vectors (#107)
- **`reload()` atomicity** — rule replacement uses frozen state to prevent partial updates during in-flight evaluations (#117)
- **`reload()` observe-mode reset** — reloading rules now correctly resets observe-mode rule lists (#109)
- **`from_multiple()` observe-mode merge** — guard merging now includes observe-mode rules from all bundles (#110)
- **Gate CLI resilience** — transitive import failures surface a warning instead of silently hiding the `gate` subcommand (#164)
- **5 review violations** from PRs #136, #138, #140 — additional edge cases in security boundaries (#143)

### Changed
- **Terminology rename: `shadow_*` → `observe_*`** — all code identifiers, comments, docstrings, and CLI output now use "observe" terminology consistently (#118, #140)

### Removed
- **`ShadowContract` deprecation alias** — import `ObserveContract` from `edictum.yaml_engine` instead (deprecated since v0.15.0)
- **`"shadows"` key in `edictum diff --json`** — use `"observe_contracts"` instead (deprecated since v0.15.0)

### Security
- **GitHub Actions supply chain hardening** — SHA-pinned actions, restricted permissions, injection-resistant review workflow (#94, #97)
- **semantic-kernel bumped ≥1.39.4** — addresses CVE-2026-26030 and CVE-2026-25592 (#95)
- **PyJWT bumped to 2.12.0** (#122)
- **PyOpenSSL bumped to 26.0.0** (#131)

### Infrastructure
- Migrated to Blacksmith ARM runners (#158, #159)
- Standardized CI workflows across all repos (#161)
- Added Sigstore signing and SBOM generation to release workflow (#111)
- Added format and typecheck steps to CI (#111)
- Migrated GitHub URLs from `acartag7` to `edictum-ai` org (#96)
- Updated development status to Beta

## 0.15.0

### Added
- **Edictum Gate** — pre-execution hook system for coding assistant governance. Sits between assistants and the OS, evaluating every tool call against YAML rules with a local audit trail (`pip install edictum[gate]`)
- **Gate: 5 assistant formats** — Claude Code, Cursor, Copilot CLI, Gemini CLI, OpenCode with format-specific stdin parsing and output
- **Gate: `edictum gate init`** — interactive setup wizard with rule deployment, assistant hook registration, and optional control-plane connection verification
- **Gate: control-plane sync** — auto-flush audit events to the Edictum Control Plane every 30 seconds via background fork; manual flush with `edictum gate sync`
- **Gate: self-protection rules** — always-enforced rules preventing the governed assistant from reading, writing, or disabling Gate configuration
- **Gate: scope enforcement** — programmatic check preventing Write/Edit outside the project directory, respects observe/enforce mode from ruleset
- **Gate: secret redaction** — secrets redacted before WAL write; API keys, SSH keys, tokens never hit disk or wire
- **Gate: Cursor auto-detection** — when Cursor fires a Claude Code hook, Gate detects `cursor_version`/`workspace_roots` in stdin and uses the correct format handler
- **Gate: control-plane onboarding** — `gate init --server URL` verifies connection, validates API key, shows auto-flush guidance
- **`CollectingAuditSink`** — in-memory audit sink with bounded ring buffer and mark-based windowed queries for programmatic inspection of governance decisions
- **`MarkEvictedError`** exception — raised when `since_mark()` references events evicted from the buffer
- **`Edictum.local_sink`** property — always-present `CollectingAuditSink` on every `Edictum` instance, regardless of construction method
- **`Edictum.from_server(url, api_key, agent_id)`** — one-line wiring of all server SDK components (client, audit sink, approval backend, session backend, rule source) from a single URL and API key
- **`Edictum.reload(rules_yaml)`** — atomically replace all rules from a new YAML bundle; fail-closed on parse errors; in-flight evaluations unaffected
- **`Edictum.close()`** — graceful shutdown of SSE watcher, rule source, HTTP client, and audit sink
- **SSE watcher** — background asyncio task subscribing to `ServerRuleSource.watch()` that auto-reloads rules on `rule_update` events; controlled via `auto_watch` parameter on `from_server()`
- **`env` and `bundle_name` on `EdictumServerClient`** — SSE connections pass `env`, `bundle_name`, and `policy_version` as query params for server-side filtering and drift detection
- **`ServerRuleSource` revision tracking** — `_current_revision` updated on each received bundle, passed as `policy_version` on reconnect for server-side drift detection
- **`ServerAuditSink` multi-bundle support** — `bundle_name` included in every event payload; `environment` falls back to `client.env` when not set on the event

### Changed
- `Edictum.__init__` no longer adds `StdoutAuditSink` by default. When `audit_sink=None`, only the `CollectingAuditSink` is used. Stdout output is now controlled via YAML `observability.stdout: true` or by explicitly passing `StdoutAuditSink()`.
- When `audit_sink` is provided (single sink or list), it is wrapped in a `CompositeSink` with the `CollectingAuditSink` first.
- `from_server()` audit tee: local `CollectingAuditSink` is always composed alongside the server sink (or user-provided sink), enabling local inspection in server mode.

### Migration
- Code relying on `Edictum()` printing JSON to stdout by default should explicitly pass `audit_sink=StdoutAuditSink()` or set `observability.stdout: true` in YAML.
- Code using `guard.audit_sink is my_sink` should use `my_sink in guard.audit_sink.sinks` instead (when a user sink is provided, `audit_sink` is a `CompositeSink`).

### Fixed
- Fixed `reload()` docstring incorrectly claiming `CONTRACTS_RELOADED` audit event emission

## 0.11.3

### Added
- Adversarial test suite (`tests/test_adversarial/`) covering shell metacharacter bypasses, sandbox symlink escapes, input injection, backend failure modes, and session concurrency
- Protocol compliance tests verifying StorageBackend and AuditSink protocol rules
- `CapturingAuditSink` test fixture for asserting audit event fidelity
- `@pytest.mark.security` marker on 114 security boundary tests
- bandit static security analysis in CI
- Dedicated `pytest -m security` step in CI
- Security review criteria in code-reviewer.md: fail-open/fail-closed, audit fidelity, path security, input validation

### Changed
- Updated architecture.md with missing source files and v0.11.2 security hardening details

## 0.11.2

### Fixed
- Fixed ServerBackend error handling to fail-closed on network errors
- Fixed BashClassifier to detect additional shell metacharacters
- Fixed sandbox path resolution to resolve symlinks
- Fixed approval timeout audit event classification
- Added tool_name validation in create_envelope
- Added atomicity lock to MemoryBackend

## 0.11.1

### Fixed
- **Sandbox path traversal bypass** — path traversal sequences (`..`, `.`, `//`) in tool call arguments now normalized with `os.path.normpath()` before `within`/`not_within` evaluation. Previously, paths like `/tmp/../etc/shadow` bypassed `within: [/tmp]` because matching used raw string prefix comparison. Both extracted paths and rule boundaries are normalized.

## 0.11.0

### Added
- **Sandbox rules** (`type: sandbox`) — allowlist-based governance that defines what agents CAN do, replacing open-ended deny-lists. Sandbox rules check file paths (`within`/`not_within`), command allowlists (`allows.commands`), and domain allowlists (`allows.domains`/`not_allows.domains`). The `outside` field controls the effect when a tool call falls outside the sandbox (`block` or `ask` for HITL approval).
- **Multi-tool matching for sandbox** — `tools: [read_file, write_file, edit_file]` applies one sandbox rule to multiple tools
- **Pipeline sandbox stage** — sandbox evaluates after preconditions (deny) and before session rules, creating a block-then-allowlist evaluation order
- **Sandbox in CLI** — `edictum check` and `edictum test` evaluate sandbox rules alongside checks
- **Sandbox in dry-run evaluation** — `evaluate()` and `evaluate_batch()` include sandbox `RuleResult` entries with `rule_type="sandbox"`
- **Sandbox composition** — `from_multiple()` merges sandbox rules across bundles with duplicate ID detection
- **Sandbox observe mode** — per-rule `mode: observe` logs sandbox blocks without enforcing them
- **Loader validation** — `not_within` requires `within`, `not_allows` requires `allows` (caught at load time)
- JSON Schema: `SandboxContract`, `SandboxAllows`, `SandboxNotAllows` definitions in `edictum-v1.schema.json`

## 0.10.0

### Added
- **Human-in-the-loop approval workflows** — `ApprovalBackend` protocol, `ApprovalRequest`/`ApprovalDecision` frozen dataclasses, `ApprovalStatus` enum, and `LocalApprovalBackend` for CLI-based approval during development
- **Pipeline approval gates** — preconditions with `effect: approve` pause the pipeline, request human approval via the configured `ApprovalBackend`, and emit HITL audit actions (`CALL_APPROVAL_REQUESTED`, `CALL_APPROVAL_GRANTED`, `CALL_APPROVAL_DENIED`, `CALL_APPROVAL_TIMEOUT`)
- **Wildcard tool matching** — tool selectors upgraded from exact-match to glob patterns via `fnmatch`, enabling `tool: "mcp_*"` in YAML rules
- **Nanobot adapter** — 7th framework adapter with `GovernedToolRegistry` drop-in replacement for nanobot's `ToolRegistry`, including approval workflows, observe mode, sub-agent propagation (`for_subagent()`), and `principal_from_message()` for multi-channel identity
- **`nanobot-agent` rule template** — approval gates for high-risk operations (exec, spawn, cron, MCP), workspace path restrictions, sensitive file protection, and session limits
- **Server SDK package** (`edictum[server]`) — 5 async client components for the edictum-server control plane: `EdictumServerClient`, `ServerApprovalBackend`, `ServerAuditSink`, `ServerBackend`, `ServerContractSource`
- 4 new HITL audit actions: `CALL_APPROVAL_REQUESTED`, `CALL_APPROVAL_GRANTED`, `CALL_APPROVAL_DENIED`, `CALL_APPROVAL_TIMEOUT`
- `approval_backend` parameter on `Edictum()`, `from_yaml()`, and `from_yaml_string()`
- YAML schema: `effect: approve`, `timeout`, and `timeout_effect` on preconditions

## 0.9.0

### Added
- `custom_operators` parameter on `from_yaml()`, `from_yaml_string()`, and `from_template()` — register custom YAML condition operators
- `custom_selectors` parameter on `from_yaml()`, `from_yaml_string()`, and `from_template()` — register custom YAML value selectors
- `metadata.*` selector — rules can reference bundle metadata fields
- `template_dirs` parameter on `from_template()` and `list_templates()` — load templates from custom directories
- `from_yaml_string()` and `load_bundle_string()` — load rules from string/bytes input
- `on_block` and `on_allow` lifecycle callbacks on `Edictum` — fire on every block or allow decision
- `success_check` parameter on `Edictum` — custom tool success detection for postconditions
- `set_principal()` and `principal_resolver` on all 6 adapters — mutable principal for mid-session role changes
- `CompositeSink` — fan-out audit events to multiple sinks
- `--json` flag on CLI `check`, `validate`, and `diff` commands — machine-readable output
- `--environment` flag on CLI `test` command — pass environment variables to test cases
- `insecure` parameter on `configure_otel()` — disable TLS verification for development OTel collectors
- `terminate_on_block` parameter on Semantic Kernel adapter

### Fixed
- OpenAI adapter `on_postcondition_warn` callback now fires from `_post()` (was only in `as_guardrails()` closure)
- CrewAI adapter double callback invocation removed; `_deny()` returns reason string
- OpenAI output guardrail now enforces postcondition `effect: deny`
- Removed dead `ttl` parameter from `StorageBackend` protocol
- Removed ghost `PIIDetector`/`pii.py` references from docs

### Changed
- CI safety-nets job removed; all tests (parity, behavior, docs-sync) now run in the main test job
- Review workflow now has Python + test execution capability (pytest, ruff, python)

## 0.8.1

### Changed
- Renamed `ContractResult` → `RuleResult` (`contract_id` → `rule_id`, `contract_type` → `rule_type`, `contracts` → `rules`, `contracts_evaluated` → `rules_evaluated`)
- CLI output now uses "rule" instead of "contract" in all user-facing strings

### Fixed
- Fixed terminology violations in comments, docstrings, and CLI output per .docs-style-guide.md
- Fixed GitHub release notes for v0.5.4, v0.7.0, and v0.8.0 (terminology and YAML schema corrections)

### Added
- Added terminology enforcement guardrails and pre-release checklist to CLAUDE.md

## 0.8.0

### Added
- `compose_bundles()` — multi-file YAML composition with deterministic left-to-right merge
- `from_yaml()` now accepts multiple file paths with automatic composition
- `observe_alongside: true` — dual-mode evaluation (observe-mode rules run without affecting decisions)
- `CompositionReport` with override and observe-mode tracking
- `edictum validate` and `edictum diff` support multi-file arguments
- CLI composition report output for overrides and observe-mode rules

## 0.7.0

### Added
- `env.*` selector — rules can reference environment variables with automatic type coercion
- `Edictum.from_multiple()` — merge rules from multiple guard instances
- Claude Code GitHub Actions workflow

## 0.6.2

### Changed
- Renamed `to_sdk_hooks()` → `to_hook_callables()` on Claude Agent SDK adapter

## 0.6.1

### Added
- YAML `tools:` section for declaring tool side-effect classifications
- `from_yaml(tools=)` parameter for programmatic tool classification

## 0.6.0

### Added
- Postcondition enforcement effects: `redact` and `deny` (in addition to existing `warn`)
- `SideEffect` classification (PURE, READ, WRITE, IRREVERSIBLE) controls which effects apply
- Postcondition regex-based pattern redaction
- Output suppression for `deny` effect on READ/PURE tools

## 0.5.4

### Added
- `guard.evaluate()` and `evaluate_batch()` — dry-run evaluation API
- `edictum test --calls` mode for JSON tool call evaluation

## 0.5.3

### Added
- `edictum test` CLI command — validate rules against YAML test cases
  without spinning up an agent. Supports precondition testing with principal
  claims, expected verdicts, and rule ID matching.
- Tests for `on_postcondition_warn` callback in Claude SDK adapter — all 6
  adapters now have test coverage for postcondition callbacks.

### Notes
- `edictum test` evaluates preconditions only. Postcondition testing requires
  tool output and is not supported in dry-run mode.

## 0.5.2

### Fixed
- **OpenAI Agents SDK:** `as_guardrails()` now returns correctly typed
  `ToolInputGuardrail` / `ToolOutputGuardrail` with 1-arg functions matching
  the SDK's calling convention. Previously unusable due to signature mismatch.
- **CrewAI:** `register()` now uses `register_before_tool_call_hook()` /
  `register_after_tool_call_hook()` internally instead of decorators, fixing
  `setattr` failure on bound methods.
- **Semantic Kernel:** Tool call denial and postcondition remediation now wrap
  values in `FunctionResult` for SK 1.39+ pydantic compatibility.

### Added
- CrewAI adapter: automatic tool name normalization
  ("Search Documents" → "search_documents")
- Comprehensive framework comparison documentation in `docs/adapters/overview.md`
  covering integration patterns, PII redaction capabilities, token costs,
  and known limitations for all 6 frameworks
- Framework-specific `on_postcondition_warn` callback behavior documented
  in `docs/violations.md`

### Documentation
- `docs/adapters/overview.md`: Full rewrite with real-world integration patterns,
  cross-framework comparison table, choosing-a-framework guide, and
  per-adapter known limitations
- `docs/violations.md`: Added framework-specific callback behavior table
- SK adapter: Documented chat history TOOL role filtering requirement
- CrewAI adapter: Documented global hooks, generic denial messages,
  token cost (~3x), and tracing prompt suppression

## 0.5.1

### Added
- `Finding` dataclass -- structured postcondition detection results
- `PostCallResult` dataclass -- tool call result with violations attached
- `on_postcondition_warn` callback parameter on all 6 adapters
- `classify_finding()` helper for standard finding type classification
- `docs/violations.md` -- full documentation with remediation examples

### Changed
- All 6 adapters support optional postcondition remediation callbacks

### Breaking (internal)
- Adapter internal `_post*` methods now return `PostCallResult` instead of
  `None`/`{}`. Code that subclasses adapters or calls `_post_tool_call` /
  `_post` / `_after_hook` directly must handle `PostCallResult` instead of
  the previous return type. Public wrapper APIs (`as_tool_wrapper`,
  `as_middleware`, `as_tool_hook`, etc.) are unchanged — they still return
  the tool result directly.

### Fixed
- Postcondition violations no longer depend on audit sink state (eliminates race condition
  with parallel tool calls when using `tracking_sink.last_event` pattern)

## 0.5.0

- OTel-native observability
- Custom sinks removed in favor of OpenTelemetry spans
- `configure_otel()` helper for quick setup
