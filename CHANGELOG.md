# Changelog

## 0.15.0

### Added
- **Edictum Gate** — pre-execution hook system for coding assistant governance. Sits between assistants and the OS, evaluating every tool call against YAML contracts with a local audit trail (`pip install edictum[gate]`)
- **Gate: 5 assistant formats** — Claude Code, Cursor, Copilot CLI, Gemini CLI, OpenCode with format-specific stdin parsing and output
- **Gate: `edictum gate init`** — interactive setup wizard with contract deployment, assistant hook registration, and optional Console connection verification
- **Gate: Console sync** — auto-flush audit events to Edictum Console every 30 seconds via background fork; manual flush with `edictum gate sync`
- **Gate: self-protection contracts** — always-enforced contracts preventing the governed assistant from reading, writing, or disabling Gate configuration
- **Gate: scope enforcement** — programmatic check preventing Write/Edit outside the project directory, respects observe/enforce mode from contract bundle
- **Gate: secret redaction** — secrets redacted before WAL write; API keys, SSH keys, tokens never hit disk or wire
- **Gate: Cursor auto-detection** — when Cursor fires a Claude Code hook, Gate detects `cursor_version`/`workspace_roots` in stdin and uses the correct format handler
- **Gate: console onboarding** — `gate init --server URL` verifies connection, validates API key, shows auto-flush guidance
- **`CollectingAuditSink`** — in-memory audit sink with bounded ring buffer and mark-based windowed queries for programmatic inspection of governance decisions
- **`MarkEvictedError`** exception — raised when `since_mark()` references events evicted from the buffer
- **`Edictum.local_sink`** property — always-present `CollectingAuditSink` on every `Edictum` instance, regardless of construction method
- **`Edictum.from_server(url, api_key, agent_id)`** — one-line wiring of all server SDK components (client, audit sink, approval backend, session backend, contract source) from a single URL and API key
- **`Edictum.reload(contracts_yaml)`** — atomically replace all contracts from a new YAML bundle; fail-closed on parse errors; in-flight evaluations unaffected
- **`Edictum.close()`** — graceful shutdown of SSE watcher, contract source, HTTP client, and audit sink
- **SSE watcher** — background asyncio task subscribing to `ServerContractSource.watch()` that auto-reloads contracts on `contract_update` events; controlled via `auto_watch` parameter on `from_server()`
- **`env` and `bundle_name` on `EdictumServerClient`** — SSE connections pass `env`, `bundle_name`, and `policy_version` as query params for server-side filtering and drift detection
- **`ServerContractSource` revision tracking** — `_current_revision` updated on each received bundle, passed as `policy_version` on reconnect for server-side drift detection
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
- Protocol compliance tests verifying StorageBackend and AuditSink protocol contracts
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
- **Sandbox path traversal bypass** — path traversal sequences (`..`, `.`, `//`) in tool call arguments now normalized with `os.path.normpath()` before `within`/`not_within` evaluation. Previously, paths like `/tmp/../etc/shadow` bypassed `within: [/tmp]` because matching used raw string prefix comparison. Both extracted paths and contract boundaries are normalized.

## 0.11.0

### Added
- **Sandbox contracts** (`type: sandbox`) — allowlist-based governance that defines what agents CAN do, replacing open-ended deny-lists. Sandbox contracts check file paths (`within`/`not_within`), command allowlists (`allows.commands`), and domain allowlists (`allows.domains`/`not_allows.domains`). The `outside` field controls the effect when a tool call falls outside the sandbox (`deny` or `approve` for HITL approval).
- **Multi-tool matching for sandbox** — `tools: [read_file, write_file, edit_file]` applies one sandbox contract to multiple tools
- **Pipeline sandbox stage** — sandbox evaluates after preconditions (deny) and before session contracts, creating a deny-then-allowlist evaluation order
- **Sandbox in CLI** — `edictum check` and `edictum test` evaluate sandbox contracts alongside preconditions
- **Sandbox in dry-run evaluation** — `evaluate()` and `evaluate_batch()` include sandbox `ContractResult` entries with `contract_type="sandbox"`
- **Sandbox composition** — `from_multiple()` merges sandbox contracts across bundles with duplicate ID detection
- **Sandbox observe mode** — per-contract `mode: observe` logs sandbox denials without enforcing them
- **Loader validation** — `not_within` requires `within`, `not_allows` requires `allows` (caught at load time)
- JSON Schema: `SandboxContract`, `SandboxAllows`, `SandboxNotAllows` definitions in `edictum-v1.schema.json`

## 0.10.0

### Added
- **Human-in-the-loop approval workflows** — `ApprovalBackend` protocol, `ApprovalRequest`/`ApprovalDecision` frozen dataclasses, `ApprovalStatus` enum, and `LocalApprovalBackend` for CLI-based approval during development
- **Pipeline approval gates** — preconditions with `effect: approve` pause the pipeline, request human approval via the configured `ApprovalBackend`, and emit HITL audit actions (`CALL_APPROVAL_REQUESTED`, `CALL_APPROVAL_GRANTED`, `CALL_APPROVAL_DENIED`, `CALL_APPROVAL_TIMEOUT`)
- **Wildcard tool matching** — tool selectors upgraded from exact-match to glob patterns via `fnmatch`, enabling `tool: "mcp_*"` in YAML contracts
- **Nanobot adapter** — 7th framework adapter with `GovernedToolRegistry` drop-in replacement for nanobot's `ToolRegistry`, including approval workflows, observe mode, sub-agent propagation (`for_subagent()`), and `principal_from_message()` for multi-channel identity
- **`nanobot-agent` contract template** — approval gates for high-risk operations (exec, spawn, cron, MCP), workspace path restrictions, sensitive file protection, and session limits
- **Server SDK package** (`edictum[server]`) — 5 async client components for the edictum-server control plane: `EdictumServerClient`, `ServerApprovalBackend`, `ServerAuditSink`, `ServerBackend`, `ServerContractSource`
- 4 new HITL audit actions: `CALL_APPROVAL_REQUESTED`, `CALL_APPROVAL_GRANTED`, `CALL_APPROVAL_DENIED`, `CALL_APPROVAL_TIMEOUT`
- `approval_backend` parameter on `Edictum()`, `from_yaml()`, and `from_yaml_string()`
- YAML schema: `effect: approve`, `timeout`, and `timeout_effect` on preconditions

## 0.9.0

### Added
- `custom_operators` parameter on `from_yaml()`, `from_yaml_string()`, and `from_template()` — register custom YAML condition operators
- `custom_selectors` parameter on `from_yaml()`, `from_yaml_string()`, and `from_template()` — register custom YAML value selectors
- `metadata.*` selector — contracts can reference bundle metadata fields
- `template_dirs` parameter on `from_template()` and `list_templates()` — load templates from custom directories
- `from_yaml_string()` and `load_bundle_string()` — load contracts from string/bytes input
- `on_deny` and `on_allow` lifecycle callbacks on `Edictum` — fire on every denial or allow decision
- `success_check` parameter on `Edictum` — custom tool success detection for postconditions
- `set_principal()` and `principal_resolver` on all 6 adapters — mutable principal for mid-session role changes
- `CompositeSink` — fan-out audit events to multiple sinks
- `--json` flag on CLI `check`, `validate`, and `diff` commands — machine-readable output
- `--environment` flag on CLI `test` command — pass environment variables to test cases
- `insecure` parameter on `configure_otel()` — disable TLS verification for development OTel collectors
- `terminate_on_deny` parameter on Semantic Kernel adapter

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
- Renamed `RuleResult` → `ContractResult` (`rule_id` → `contract_id`, `rule_type` → `contract_type`, `rules` → `contracts`, `rules_evaluated` → `contracts_evaluated`)
- CLI output now uses "contract" instead of "rule" in all user-facing strings

### Fixed
- Fixed terminology violations in comments, docstrings, and CLI output per .docs-style-guide.md
- Fixed GitHub release notes for v0.5.4, v0.7.0, and v0.8.0 (terminology and YAML schema corrections)

### Added
- Added terminology enforcement guardrails and pre-release checklist to CLAUDE.md

## 0.8.0

### Added
- `compose_bundles()` — multi-file YAML composition with deterministic left-to-right merge
- `from_yaml()` now accepts multiple file paths with automatic composition
- `observe_alongside: true` — dual-mode evaluation (shadow contracts run without affecting decisions)
- `CompositionReport` with override and shadow tracking
- `edictum validate` and `edictum diff` support multi-file arguments
- CLI composition report output for overrides and shadow contracts

## 0.7.0

### Added
- `env.*` selector — contracts can reference environment variables with automatic type coercion
- `Edictum.from_multiple()` — merge contracts from multiple guard instances
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
- `edictum test` CLI command — validate contracts against YAML test cases
  without spinning up an agent. Supports precondition testing with principal
  claims, expected verdicts, and contract ID matching.
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
  in `docs/findings.md`

### Documentation
- `docs/adapters/overview.md`: Full rewrite with real-world integration patterns,
  cross-framework comparison table, choosing-a-framework guide, and
  per-adapter known limitations
- `docs/findings.md`: Added framework-specific callback behavior table
- SK adapter: Documented chat history TOOL role filtering requirement
- CrewAI adapter: Documented global hooks, generic denial messages,
  token cost (~3x), and tracing prompt suppression

## 0.5.1

### Added
- `Finding` dataclass -- structured postcondition detection results
- `PostCallResult` dataclass -- tool call result with findings attached
- `on_postcondition_warn` callback parameter on all 6 adapters
- `classify_finding()` helper for standard finding type classification
- `docs/findings.md` -- full documentation with remediation examples

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
- Postcondition findings no longer depend on audit sink state (eliminates race condition
  with parallel tool calls when using `tracking_sink.last_event` pattern)

## 0.5.0

- OTel-native observability
- Custom sinks removed in favor of OpenTelemetry spans
- `configure_otel()` helper for quick setup
