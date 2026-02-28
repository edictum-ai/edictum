# Roadmap

This page tracks what Edictum has shipped, what is actively being built, and what is planned. Items move through three stages: [Shipped], [In Progress], and [Planned].

---

## [Shipped] Core Pipeline (v0.5.x)

The foundation is production-usable today as an in-process library (v0.6.0).

- **Enforcement pipeline** with preconditions, postconditions, and session contracts
- **7 framework adapters**: LangChain, OpenAI Agents SDK, CrewAI, Agno, Semantic Kernel, Claude Agent SDK, Nanobot
- **YAML contract engine** with JSON Schema validation and SHA-256 versioning
- **CLI tools**: `edictum validate`, `edictum check`, `edictum diff`, `edictum replay`, `edictum test`
- **OpenTelemetry** span emission with OTel Collector support
- **Observe mode** for shadow-testing contracts against live traffic before enforcing
- **Postcondition findings** interface with remediation callbacks (`on_postcondition_warn`)
- **Automatic secret redaction** in audit events via `RedactionPolicy`
- **Built-in contract templates**: `file-agent`, `research-agent`, `devops-agent`

---

## [Shipped] YAML Extensibility & Adapter Lifecycle (v0.9.0)

The contract engine and adapters are now extensible without forking.

- **Custom operators** — register domain-specific condition operators (e.g., `valid_iban`, `pii_free`) via `custom_operators` parameter
- **Custom selectors** — register custom value selectors for YAML conditions via `custom_selectors` parameter
- **`metadata.*` selector** — contracts can reference bundle metadata fields in conditions
- **`template_dirs`** — load templates from custom directories alongside built-in ones
- **`from_yaml_string()`** — load contracts from string/bytes input for dynamic scenarios
- **`on_deny` / `on_allow` callbacks** — lifecycle hooks on every decision for logging, alerting, or approval gates
- **`success_check` parameter** — custom tool success detection for postcondition evaluation
- **`set_principal()` / `principal_resolver`** — mutable principal for mid-session role escalation (analyst -> operator)
- **`CompositeSink`** — fan-out audit events to multiple sinks simultaneously
- **CLI `--json`** — machine-readable output on `check`, `validate`, and `diff` for CI/CD integration
- **CLI `--environment`** — pass environment variables to `edictum test` cases
- **OTel TLS support** — `insecure` parameter on `configure_otel()` for development collectors

---

## [Planned] PII Detection

Tool outputs often contain personally identifiable information that should not propagate back to the LLM or appear in logs. Basic PII finding classification already exists in `findings.py` (`classify_finding` returns `pii_detected` for contracts matching PII-related terms), but the full pluggable detection system is not yet implemented.

- **What exists today:** `classify_finding()` in findings.py classifies postcondition failures as `pii_detected` based on contract ID and message heuristics. Postcondition contracts can match PII patterns via YAML `matches:` operator and use `effect: redact` to strip them.
- **What's planned:**
    - `PIIDetector` protocol in core -- a pluggable detection interface decoupled from postcondition contracts
    - `RegexPIIDetector` in core -- built-in regex patterns (SSN, email, phone, etc.) for immediate use
    - ML-based detectors (Presidio) will be available as optional dependencies: `PresidioPIIDetector` (ML/NER via Presidio), `CompositePIIDetector` (multiple detectors with configurable thresholds)
    - YAML `pii_detection` shorthand for declaring PII checks directly in contract bundles

---

## [Shipped] Bundle Composition & Dual-Mode Evaluation (v0.8.0)

Teams can now compose multiple YAML bundles and shadow-test contract changes against live traffic.

- **`from_yaml(*paths)`** -- pass multiple YAML files; bundles are composed left-to-right with deterministic merge semantics
- **`compose_bundles()`** -- low-level composition primitive with replace-by-ID for contracts, deep merge for tools/metadata, later-wins for defaults/limits/observability
- **`observe_alongside: true`** -- dual-mode evaluation where a second bundle's contracts run as shadows, producing audit events without affecting real decisions
- **`CompositionReport`** -- reports overridden and shadow contracts; available via `return_report=True` on `from_yaml()`
- **CLI support** -- `edictum validate` and `edictum diff` support multi-file composition with override/shadow reports

---

## [Planned] Production Observability

Stdout and File (.jsonl) sinks ship today in core for development and local audit. Production deployments need audit data flowing to existing infrastructure.

- **Network audit sinks** -- Webhook, Splunk HEC, Datadog as core sink implementations or via server-managed ingestion for compliance-grade audit trails
- **Finding notifications** -- notifications on abnormal patterns (denial spikes, PII detections, session exhaustion)
- **Deployment recipes** -- end-to-end guides for OTel to Grafana, Datadog, and Splunk

---

## [Planned] Advanced Contracts

Single-call contracts cover most enforcement scenarios. Some problems require looking across multiple calls or letting non-engineers author contracts.

- **Sequence-aware contracts** -- detect suspicious patterns across multiple tool calls, not just single calls (e.g., read credentials then call external API)
- **NL -> YAML authoring** -- compliance officers describe a contract in English, system generates the YAML contract

---

## [In Progress] edictum-server

Single-agent, in-process enforcement covers most use cases today. For organizations running fleets of agents, the next step is centralized contract management. The server will be published as an open-source project.

**Shipped: Server SDK client** (`pip install edictum[server]`):

- **`EdictumServerClient`** -- async HTTP client with Bearer auth, agent ID headers, exponential backoff retry, `env` and `bundle_name` for multi-bundle targeting
- **`ServerApprovalBackend`** -- implements `ApprovalBackend` protocol via server approval queue (POST to create, poll GET until resolved)
- **`ServerAuditSink`** -- implements `AuditSink` protocol with batched event ingestion; includes `bundle_name` and `environment` in every event payload
- **`ServerBackend`** -- implements `StorageBackend` protocol for distributed session state
- **`ServerContractSource`** -- SSE client for receiving contract bundle updates with auto-reconnect; passes `env`, `bundle_name`, and `policy_version` as query params for server-side filtering and drift detection
- **`Edictum.from_server()`** -- one-line wiring of all server SDK components from a URL and API key
- **`Edictum.reload()`** -- atomic contract swap from new YAML bundle (fail-closed on errors)
- **`Edictum.close()`** -- graceful shutdown of SSE watcher, contract source, HTTP client, and audit sink

**Coming soon: edictum-server:**

- **Central policy server** -- agents pull contracts on startup, with versioning and hot-reload
- **Governance dashboard** -- visualize contract evaluations, denial rates, and contract drift across agents
- **RBAC for contract management** -- control who can create, modify, and deploy contracts
- **SSO integration** -- Okta, Azure AD
- **JWT/OIDC principal verification** -- server verifies the agent's claimed identity instead of trusting the caller
- **Production approval workflows** -- require human sign-off before specific tool calls execute (webhooks, Slack/Teams, review dashboard)
- **Cross-agent session tracking** -- correlate tool calls across multiple agents in a single workflow
