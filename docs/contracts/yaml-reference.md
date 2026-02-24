# YAML Contract Reference

This is the complete reference for `edictum/v1` contract bundles. A contract bundle is a single YAML file that declares all the contracts for an Edictum instance.

---

## Document Structure {#document-structure}

Every contract bundle starts with four required top-level fields:

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: my-agent-policy
  description: "Optional human-readable description."

defaults:
  mode: enforce

contracts:
  - id: example-contract
    type: pre
    tool: read_file
    when:
      args.path:
        contains: ".env"
    then:
      effect: deny
      message: "Denied."
```

| Field | Type | Required | Description |
|---|---|---|---|
| `apiVersion` | string | yes | Must be `edictum/v1`. |
| `kind` | string | yes | Must be `ContractBundle`. |
| `metadata.name` | string | yes | Bundle identifier. Slug format: `[a-z0-9][a-z0-9._-]*`. |
| `metadata.description` | string | no | Human-readable description. |
| `defaults.mode` | string | yes | `enforce` or `observe`. Applied to every contract that does not set its own `mode`. |
| `tools` | object | no | Tool side-effect classifications. See [Tool Classifications](#tool-classifications). |
| `observe_alongside` | boolean | no | When `true`, contracts in this bundle become shadow copies that evaluate in parallel without affecting real decisions. See [Bundle Composition](#bundle-composition). |
| `contracts` | array | yes | Minimum one contract. Each item is a precondition, postcondition, session, or sandbox contract. |

The bundle is loaded with `Edictum.from_yaml()`:

```python
from edictum import Edictum

guard = Edictum.from_yaml("contracts/my-policy.yaml")
```

Multiple bundles can be composed by passing multiple paths. Later bundles override earlier ones:

```python
guard = Edictum.from_yaml("contracts/base.yaml", "contracts/overrides.yaml")
```

### Loading from a String or Bytes {#from-yaml-string}

When YAML is generated programmatically or fetched from an API, use `from_yaml_string()` to skip the file system. Follows the `json.load()` / `json.loads()` convention:

```python
yaml_content = """
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: dynamic-policy
defaults:
  mode: enforce
contracts:
  - id: block-dotenv
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      effect: deny
      message: "Denied: {args.path}"
"""

guard = Edictum.from_yaml_string(yaml_content)
```

`from_yaml_string()` accepts `str` or `bytes` and supports the same keyword arguments as `from_yaml()` (`tools`, `mode`, `audit_sink`, `redaction`, `backend`, `environment`). The low-level equivalent is `load_bundle_string()` from `edictum.yaml_engine`.

See [Bundle Composition](#bundle-composition) for full details.

A SHA256 hash of the raw YAML bytes is computed at load time and stamped as `policy_version` on every `AuditEvent` and OpenTelemetry span. This gives you an immutable link between any audit record and the exact contract bundle that produced it. When multiple bundles are composed, the combined hash is derived from all individual bundle hashes.

---

## Tool Classifications {#tool-classifications}

The optional `tools:` section declares side-effect classifications for your agent's tools. This controls how postcondition `redact` and `deny` effects behave -- without it, all tools default to `SideEffect.IRREVERSIBLE` and redact/deny effects fall back to `warn`.

```yaml
tools:
  read_config:
    side_effect: read
  get_weather:
    side_effect: pure
    idempotent: true
  update_record:
    side_effect: write
  deploy_service:
    side_effect: irreversible
```

Each tool entry has the following fields:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `side_effect` | string | yes | -- | `pure`, `read`, `write`, or `irreversible`. |
| `idempotent` | boolean | no | `false` | Whether repeated calls with the same arguments produce the same result. |

**Side-effect levels:**

| Level | Meaning | Postcondition redact/deny |
|-------|---------|--------------------------|
| `pure` | No side effects. Returns computed data. | Enforced |
| `read` | Reads external state but does not modify it. | Enforced |
| `write` | Modifies external state (can be undone). | Falls back to `warn` |
| `irreversible` | Modifies external state (cannot be undone). | Falls back to `warn` |

Tools not listed in the `tools:` section default to `irreversible`. This is the conservative default -- if Edictum does not know a tool's side effects, it assumes the worst.

You can also pass tool classifications as a parameter to `from_yaml()`. Parameter values override YAML values for the same tool name:

```python
guard = Edictum.from_yaml(
    "contracts.yaml",
    tools={"my_custom_reader": {"side_effect": "read"}},
)
```

Both sources are merged: tools defined in the YAML `tools:` section and tools passed via the `tools=` parameter are combined, with the parameter winning on conflict.

---

## Contract Types {#contract-types}

Every contract shares a common set of fields, plus type-specific fields determined by the `type` discriminator.

### Common Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes | -- | Unique within the bundle. Format: `[a-z0-9][a-z0-9_-]*`. |
| `type` | string | yes | -- | `pre`, `post`, `session`, or `sandbox`. |
| `enabled` | boolean | no | `true` | Set to `false` to skip during evaluation. The contract still participates in validation. |
| `mode` | string | no | `defaults.mode` | Per-contract override: `enforce` or `observe`. |
| `then` | object | conditional | -- | Action block. Required for `pre`, `post`, and `session` types. Not used by `sandbox` type. See [Action Block](#action-block). |

### Precondition (`type: pre`) {#precondition}

Preconditions evaluate **before** tool execution. If the expression matches, the tool call is denied.

| Field | Type | Required | Description |
|---|---|---|---|
| `tool` | string | yes | Tool name, glob pattern (e.g. `mcp_*`), or `"*"` for all tools. Patterns use Python's `fnmatch`. |
| `when` | Expression | yes | Boolean expression tree. See [Expression Grammar](#expression-grammar). |

**Constraints:**

- `then.effect` must be `deny` or `approve`. Preconditions deny or require human approval; they do not warn.
- The `output.text` selector is invalid in preconditions because the tool has not run yet. Using it is a validation error.
- When `mode: observe` is set (either on the contract or via `defaults.mode`), a matching precondition emits a `CALL_WOULD_DENY` audit event instead of denying. The tool call proceeds.

**Approval effect:** When `effect: approve`, the pipeline pauses and requests human approval via the configured `approval_backend`. Two additional fields are available:

| Field | Type | Default | Description |
|---|---|---|---|
| `timeout` | integer | `300` | Seconds to wait for an approval decision before applying `timeout_effect`. |
| `timeout_effect` | `deny` or `allow` | `deny` | What happens when the approval times out. |

If no `approval_backend` is configured on the `Edictum` instance, `effect: approve` raises `EdictumDenied` immediately.

```yaml
- id: block-sensitive-reads
  type: pre
  tool: read_file
  when:
    args.path:
      contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa"]
  then:
    effect: deny
    message: "Sensitive file '{args.path}' denied. Skip and continue."
    tags: [secrets, dlp]
```

### Postcondition (`type: post`) {#postcondition}

Postconditions evaluate **after** tool execution. They inspect the tool's output and produce findings.

| Field | Type | Required | Description |
|---|---|---|---|
| `tool` | string | yes | Tool name, glob pattern (e.g. `mcp_*`), or `"*"` for all tools. Patterns use Python's `fnmatch`. |
| `when` | Expression | yes | Boolean expression tree. |

**Constraints:**

- `then.effect` must be `warn`, `redact`, or `deny`. See [Postcondition Effects](#postcondition-effects) for behavior.
- The `output.text` selector is available in postconditions. It contains the stringified tool response.

```yaml
- id: pii-in-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any:
        - '\b\d{3}-\d{2}-\d{4}\b'
        - '\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b'
  then:
    effect: warn
    message: "PII pattern detected in output. Redact before using."
    tags: [pii, compliance]
```

#### Postcondition Effects {#postcondition-effects}

Postconditions support three effects that control what happens when the condition matches:

| Effect | Behavior | Side-effect constraint |
|--------|----------|----------------------|
| `warn` | Produces a finding. The tool result is unchanged. | All side effects. |
| `redact` | Replaces matched patterns in the output with `[REDACTED]`. | **READ/PURE only.** Falls back to `warn` for WRITE/IRREVERSIBLE tools. |
| `deny` | Suppresses the entire tool output with `[OUTPUT SUPPRESSED]`. | **READ/PURE only.** Falls back to `warn` for WRITE/IRREVERSIBLE tools. |

The side-effect constraint reflects a design decision: for tools that only read data (`SideEffect.READ` or `SideEffect.PURE`), the output can be safely redacted or suppressed because the tool has no lasting effect. For tools that write or mutate state (`SideEffect.WRITE` or `SideEffect.IRREVERSIBLE`), the action already happened -- hiding the result only removes context the agent needs.

**`effect: redact`** uses the regex patterns from the `when` clause to do targeted replacement. If the `when` clause uses `output.text` with `matches` or `matches_any`, those exact patterns are used to find and replace sensitive tokens:

```yaml
- id: secrets-in-output
  type: post
  tool: "*"
  when:
    output.text:
      matches_any:
        - 'sk-prod-[a-z0-9]{8}'
        - 'AKIA-PROD-[A-Z]{12}'
  then:
    effect: redact
    message: "Secrets detected and redacted."
    tags: [secrets]
```

**`effect: deny`** suppresses the entire output. Use this when partial redaction still leaks sensitive content (e.g., accommodation records, privileged legal documents):

```yaml
- id: accommodation-confidential
  type: post
  tool: "*"
  when:
    output.text:
      matches: '\b(504\s*Plan|IEP|accommodation)\b'
  then:
    effect: deny
    message: "Accommodation info cannot be returned."
    tags: [ferpa]
```

**Observe mode** takes precedence over `redact` and `deny`. When a postcondition is in observe mode, the effect is always downgraded to a warning regardless of the declared effect.

### Session Contract (`type: session`) {#session-contract}

Session contracts enforce session-level gates that apply across all tool calls. They track cumulative counters -- total calls, total attempts, and per-tool call counts.

| Field | Type | Required | Description |
|---|---|---|---|
| `limits` | object | yes | At least one limit field is required. |
| `limits.max_tool_calls` | integer | no* | Maximum successful tool executions in the session. |
| `limits.max_attempts` | integer | no* | Maximum contract evaluations, including denied ones. Catches denial loops. |
| `limits.max_calls_per_tool` | map | no* | Per-tool execution caps. Keys are tool names, values are integer limits. |

*At least one of `max_tool_calls`, `max_attempts`, or `max_calls_per_tool` must be present.

**Constraints:**

- `then.effect` must be `deny`.
- Session contracts do not have `tool` or `when` fields. They are tool-agnostic.

```yaml
- id: session-limits
  type: session
  limits:
    max_tool_calls: 50
    max_attempts: 120
    max_calls_per_tool:
      deploy_service: 3
      send_notification: 10
  then:
    effect: deny
    message: "Session limit reached. Summarize progress and stop."
    tags: [rate-limit]
```

### Sandbox Contract (`type: sandbox`) {#sandbox-contract}

Sandbox contracts define allowlists -- what agents are permitted to do. Instead of enumerating dangerous patterns (deny-lists), sandbox contracts enumerate safe boundaries and deny everything outside them.

| Field | Type | Required | Description |
|---|---|---|---|
| `tool` | string | conditional | Tool name or glob pattern. One of `tool` or `tools` is required. |
| `tools` | array of strings | conditional | Multiple tool names or glob patterns. One of `tool` or `tools` is required. |
| `within` | array of strings | conditional | Allowed directory prefixes for file paths. At least one of `within` or `allows` must be present. |
| `not_within` | array of strings | no | Excluded directory prefixes (overrides `within`). Requires `within`. |
| `allows.commands` | array of strings | no | Allowed first-token commands for exec tools. |
| `allows.domains` | array of strings | no | Allowed domain patterns for URL tools (supports `*` wildcards via `fnmatch`). |
| `not_allows.domains` | array of strings | no | Excluded domains (overrides `allows.domains`). Requires `allows`. |
| `outside` | `deny` or `approve` | yes | Effect when a tool call falls outside the sandbox boundary. |
| `message` | string | yes | Human-readable message. Supports `{placeholder}` expansion. |
| `timeout` | integer | no | Seconds to wait for approval (only when `outside: approve`). Default `300`. |
| `timeout_effect` | `deny` or `allow` | no | What happens on approval timeout. Default `deny`. |

**Constraints:**

- No `when`/`then` block. Sandbox contracts use declarative boundary fields instead.
- `not_within` requires `within`. `not_allows` requires `allows`.
- At least one of `within` or `allows` must be present.
- Sandbox contracts have separate tool matching: they only evaluate for tools matching `tool`/`tools` patterns.

#### Path Matching

Paths are extracted from the envelope args: keys named `path`, `file_path`, `directory`, or any arg value starting with `/`, plus tokens parsed from command strings.

Matching uses string prefix logic: `path == allowed OR path.startswith(allowed.rstrip("/") + "/")`. This means `/workspace` allows `/workspace` itself and all children like `/workspace/src/main.py`.

`not_within` overrides `within` -- if a path matches an exclusion, it is denied even if it falls inside an allowed directory.

#### Command Matching

The first whitespace-delimited token of `args.command` or `envelope.bash_command` is extracted. That token must appear in the `allows.commands` list. If the command is `git status`, the first token is `git`.

#### Domain Matching

All envelope arg values are scanned for strings containing `://`. Hostnames are extracted with `urlparse`. Checking order: `not_allows.domains` first (deny on match), then `allows.domains` (must match at least one).

Domain patterns support `fnmatch` wildcards: `*.googleapis.com` matches `storage.googleapis.com`.

#### File Sandbox Example

```yaml
- id: file-sandbox
  type: sandbox
  tools: [read_file, write_file, edit_file]
  within:
    - /workspace
    - /tmp
  not_within:
    - /workspace/.git
  outside: deny
  message: "File access outside workspace: {args.path}"
```

#### Exec Sandbox Example

```yaml
- id: exec-sandbox
  type: sandbox
  tool: bash
  allows:
    commands: [git, npm, pnpm, node, python, pytest, ruff, ls, cat, grep]
  outside: deny
  message: "Command not in allowlist: {args.command}"
```

#### Web Sandbox Example

```yaml
- id: web-sandbox
  type: sandbox
  tools: [web_fetch, http_request]
  allows:
    domains:
      - "*.googleapis.com"
      - "api.github.com"
      - "registry.npmjs.org"
  not_allows:
    domains:
      - "internal.googleapis.com"
  outside: deny
  message: "Domain not allowed: {args.url}"
```

#### Combined Sandbox Example

A coding agent with file, exec, and web access -- all sandboxed in a single bundle:

```yaml
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file, write_file, edit_file]
    within:
      - /workspace
      - /tmp
    not_within:
      - /workspace/.git
      - /workspace/.env
    outside: deny
    message: "File access outside workspace: {args.path}"

  - id: exec-sandbox
    type: sandbox
    tool: bash
    allows:
      commands: [git, npm, pnpm, node, python, pytest, ruff]
    outside: deny
    message: "Command not in allowlist: {args.command}"

  - id: web-sandbox
    type: sandbox
    tools: [web_fetch, http_request]
    allows:
      domains:
        - "api.github.com"
        - "registry.npmjs.org"
    outside: approve
    message: "Domain requires approval: {args.url}"
    timeout: 120
    timeout_effect: deny
```

---

## Expression Grammar {#expression-grammar}

The `when` field accepts a recursive expression tree. Each node is exactly one of: a boolean combinator (`all`, `any`, `not`) or a leaf comparison.

### Boolean Nodes

```yaml
# AND — all children must be true
all:
  - <expression>
  - <expression>

# OR — at least one child must be true
any:
  - <expression>
  - <expression>

# NOT — negation of one child
not: <expression>
```

Boolean nodes nest arbitrarily. Minimum one child in `all` and `any` arrays.

### Leaf Nodes

A leaf is a single selector-operator pair:

```yaml
<selector>:
  <operator>: <value>
```

Exactly one selector key per leaf. Exactly one operator per selector.

### Selectors {#selectors}

Selectors resolve fields from the `ToolEnvelope` and `Principal` at evaluation time.

| Selector | Type | Available In | Source |
|---|---|---|---|
| `environment` | string | pre, post | `ToolEnvelope.environment` |
| `tool.name` | string | pre, post | `ToolEnvelope.tool_name` |
| `args.<key>` | any | pre, post | `ToolEnvelope.args[key]` |
| `args.<key>.<subkey>` | any | pre, post | Nested dict access |
| `principal.user_id` | string or null | pre, post | `Principal.user_id` |
| `principal.service_id` | string or null | pre, post | `Principal.service_id` |
| `principal.org_id` | string or null | pre, post | `Principal.org_id` |
| `principal.role` | string or null | pre, post | `Principal.role` |
| `principal.ticket_ref` | string or null | pre, post | `Principal.ticket_ref` |
| `principal.claims.<key>` | any | pre, post | `Principal.claims[key]` |
| `env.<VAR>` | string, bool, int, or float | pre, post | `os.environ[VAR]` with type coercion |
| `metadata.<key>` | any | pre, post | `ToolEnvelope.metadata[key]` |
| `metadata.<key>.<subkey>` | any | pre, post | Nested dict access into metadata |
| `output.text` | string | **post only** | Stringified tool response |

**Missing fields:** If a selector references a field that does not exist (missing key, null value, no principal, unset env var), the leaf evaluates to `false`. The contract does not fire. This is not an error.

**Nested args:** Dotted paths like `args.config.timeout` resolve through nested dicts: `envelope.args["config"]["timeout"]`. If any intermediate key is missing or the value is not a dict, the leaf evaluates to `false`.

**Environment variables:** The `env.<VAR>` selector reads from `os.environ` at evaluation time. No adapter changes or envelope modifications are needed -- set the env var and reference it in YAML. Values are automatically coerced: `"true"`/`"false"` (case-insensitive) become booleans, numeric strings become `int` or `float`, everything else stays a string. Unset env vars evaluate to `false` (same as any missing field). Because env vars are read at evaluation time, changing an env var mid-process takes effect on the next tool call.

**Envelope metadata:** The `metadata.<key>` selector reads from `ToolEnvelope.metadata` at evaluation time. Metadata is set per-call via `create_envelope(metadata={...})` or through adapter-specific mechanisms. Dotted paths like `metadata.tenant.tier` resolve through nested dicts. Missing keys evaluate to `false`.

### Custom Selectors {#custom-selectors}

The built-in selectors cover `args`, `principal`, `env`, `metadata`, and `output`. When contracts need data from sources outside the envelope -- risk scores, department codes, classification levels -- use the `custom_selectors` parameter.

```python
guard = Edictum.from_yaml(
    "contracts.yaml",
    custom_selectors={
        "risk": lambda envelope: compliance_api.get_risk(envelope.tool_name),
        "dept": lambda envelope: {"code": get_department(envelope.principal)},
    },
)
```

Each entry maps a selector prefix to a callable. The callable receives a `ToolEnvelope` and returns a `dict`. YAML contracts reference fields under the prefix with dotted paths:

```yaml
contracts:
  - id: block-high-risk
    type: pre
    tool: transfer
    when:
      risk.score: { gt: 80 }
    then:
      effect: deny
      message: "Risk score {risk.score} exceeds threshold"
```

Custom selector prefixes must not clash with built-in prefixes (`environment`, `tool`, `args`, `principal`, `output`, `env`, `metadata`). Attempting to register a clashing prefix raises `EdictumConfigError`.

`custom_selectors` is accepted by `from_yaml()`, `from_yaml_string()`, and `from_template()`.

#### When to use this

1. **Request-scoped context** -- Your API gateway attaches `request_id`, `client_ip`, and `region` to each tool call via envelope metadata. With `metadata.*` selectors, YAML contracts can enforce region restrictions without Python code: `when: metadata.region: {not_in: ["eu-west-1"]}`.

2. **Multi-tenant governance** -- Your SaaS platform sets `metadata.tenant_tier` per request. Contracts use `when: metadata.tenant_tier: {equals: "free"}` to restrict free-tier agents from expensive tools. Tenant logic stays in YAML, not hardcoded in Python.

3. **Feature flags** -- Your deployment system sets `metadata.feature_flags` as a string. Contracts check `when: metadata.feature_flags: {contains: "beta_tools"}` to gate access to experimental tools.

4. **Custom data sources** -- Your compliance system enriches envelopes with risk scores, department codes, or classification levels. Custom selectors let YAML contracts reference `risk.score`, `department.code`, or any domain-specific data path without modifying Edictum's core selector chain.

**Who benefits:**

- **Platform teams** -- route governance decisions based on runtime context (region, tenant, environment) without Python code
- **Compliance teams** -- write contracts against any envelope data, not just the built-in fields
- **Developers** -- attach per-request context and have it available in YAML conditions immediately

**Overlap with other selectors:** `env.*` covers environment variables (global, process-wide config). `metadata.*` covers per-call context attached programmatically. `principal.*` covers identity. Custom selectors extend to any data source. Use `env.*` for global config, `metadata.*` for request-scoped data, custom selectors for external data.

---

## Operators {#operators}

Fifteen operators are available, grouped into five categories. Each leaf uses exactly one operator.

For detailed examples of every operator, see the [Operator Reference](operators.md).

| Category | Operator | Value Type | Semantics |
|---|---|---|---|
| Presence | `exists` | boolean | `true`: field is present and not null. `false`: field is absent or null. |
| Equality | `equals` | scalar | Strict equality (`==`). |
| Equality | `not_equals` | scalar | Strict inequality (`!=`). |
| Membership | `in` | array | Selector value appears in the array. |
| Membership | `not_in` | array | Selector value does not appear in the array. |
| String | `contains` | string | Substring match (`value in field`). |
| String | `contains_any` | array of strings | Any element is a substring of the field. |
| String | `starts_with` | string | Field starts with the value. |
| String | `ends_with` | string | Field ends with the value. |
| String | `matches` | string (regex) | Python `re.search(pattern, field)` is truthy. |
| String | `matches_any` | array of strings | Any regex pattern matches. |
| Numeric | `gt` | number | Greater than. |
| Numeric | `gte` | number | Greater than or equal. |
| Numeric | `lt` | number | Less than. |
| Numeric | `lte` | number | Less than or equal. |

**Regex notes:** Patterns use Python's `re` module with `re.search()` (not `re.match()`), so patterns can match anywhere in the string. Patterns are compiled once at load time. Invalid regex causes a validation error at load.

**YAML regex tip:** Always use single-quoted strings for regex patterns. In YAML, `'\b'` is a literal backslash-b (word boundary). Double-quoted `"\b"` is a backspace character.

---

## Action Block {#action-block}

The `then` block defines what happens when a contract's condition matches. It is used by `pre`, `post`, and `session` contracts. Sandbox contracts (`type: sandbox`) do not use the `then` block -- they use `outside` and `message` fields directly at the contract level instead. See [Sandbox Contract](#sandbox-contract).

```yaml
then:
  effect: deny          # required: deny or warn
  message: "..."        # required: human-readable message, max 500 chars
  tags: [a, b]          # optional: classification tags
  metadata:             # optional: arbitrary key-value pairs
    severity: high
    runbook: "https://..."
```

| Field | Type | Required | Description |
|---|---|---|---|
| `effect` | string | yes | `deny` (block execution), `approve` (pause for human approval, pre only), `warn` (log only), or `redact`/`deny` for postconditions. Constrained by contract type. |
| `message` | string | yes | Human-readable message sent to the agent and recorded in audit. 1-500 characters. |
| `tags` | array of strings | no | Classification labels. Appear in audit events and can be filtered downstream. |
| `metadata` | object | no | Arbitrary key-value data stamped into the `Verdict` and audit event. |

### Effect Constraints

The allowed effect depends on the contract type:

| Contract Type | Allowed Effects | Rationale |
|---|---|---|
| `pre` | `deny`, `approve` | Preconditions deny or pause for human approval. |
| `post` | `warn`, `redact`, `deny` | `warn` produces findings. `redact` replaces matched patterns. `deny` suppresses output. See [Postcondition Effects](#postcondition-effects). |
| `session` | `deny` only | Session limits gate further execution. |
| `sandbox` | `outside: deny`, `outside: approve` | Sandbox contracts deny or request approval for calls outside the boundary. Set via the `outside` field, not via `then.effect`. |

Using an invalid effect for a contract type is a validation error at load time.

### Message Templating

Messages support `{placeholder}` expansion from the envelope context:

```yaml
message: "Read of '{args.path}' denied for user {principal.user_id}."
```

Available placeholders follow the same selector paths as the expression grammar: `{args.path}`, `{tool.name}`, `{environment}`, `{principal.user_id}`, `{principal.role}`, `{env.VAR_NAME}`, and so on.

If a placeholder references a missing field, it is kept as-is in the output (no crash, no empty string). Each placeholder expansion is capped at 200 characters.

---

## Error Handling {#error-handling}

Error behavior is hardcoded and not configurable. Edictum follows a fail-closed design: when in doubt, the contract fires.

| Scenario | Behavior |
|---|---|
| YAML parse error | `from_yaml()` raises `EdictumConfigError`. |
| Invalid regex in `matches` / `matches_any` | Validation error at load time. |
| Duplicate contract `id` within a bundle | Validation error at load time. |
| YAML contract evaluation throws | Contract yields `deny` (pre/session) or `warn` (post) with `policy_error: true`. Other contracts continue evaluating. |
| Python hook or precondition throws | Hook/contract yields `deny` with `policy_error: true`. Evaluation stops (first denial wins). |
| Python postcondition throws | Contract yields `warn` with `policy_error: true`. Other postconditions continue. |
| Selector references a missing field | Leaf evaluates to `false`. Not an error. |
| Type mismatch (e.g., `gt` applied to a string) | Contract yields `deny` or `warn` with `policy_error: true`. |
| Wrong `effect` for contract type | Validation error at load time. |
| `output.text` used in a precondition | Validation error at load time. |

---

## Audit Integration {#audit-integration}

YAML contracts integrate with the audit system automatically. Every contract evaluation stamps the following fields on `AuditEvent`:

| Audit Field | Source |
|---|---|
| `policy_version` | SHA256 hash of the raw YAML bytes. |
| `decision_name` | The contract's `id` field. |
| `decision_source` | `yaml_precondition`, `yaml_postcondition`, `yaml_session`, or `yaml_sandbox`. |
| `contracts_evaluated[].tags` | From `then.tags` on each contract. |
| `policy_error` | `true` if contract evaluation threw an error. |

OpenTelemetry span attributes (when OTel SDK is installed):

- `edictum.policy_version` -- the bundle hash.
- `edictum.policy_error` -- set to `true` if any contract had an evaluation error.

This means you can trace any audit record or OTel span back to the exact YAML file that produced it, and to the specific contract `id` that fired.

---

## Observability Configuration {#observability}

The optional `observability` block configures how Edictum emits telemetry. Place it at the top level of your contract bundle, alongside `metadata`, `defaults`, and `contracts`:

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: my-policy

observability:
  otel:
    enabled: true
    endpoint: "http://localhost:4317"
    protocol: grpc
    service_name: my-agent
    resource_attributes:
      deployment.environment: production
  stdout: true
  file: /var/log/edictum/events.jsonl

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "credentials"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `observability.otel.enabled` | bool | `false` | Enable OpenTelemetry span emission. |
| `observability.otel.endpoint` | string | `"http://localhost:4317"` | OTLP collector endpoint. |
| `observability.otel.protocol` | string | `"grpc"` | Transport protocol: `"grpc"` or `"http"`. |
| `observability.otel.service_name` | string | `"edictum-agent"` | OTel service name resource attribute. |
| `observability.otel.insecure` | bool | `true` | Use plaintext for gRPC. Set to `false` for TLS-enabled collectors. |
| `observability.otel.resource_attributes` | object | -- | Additional OTel resource attributes (string values). |
| `observability.stdout` | bool | `true` | Emit audit events to stdout via `StdoutAuditSink`. |
| `observability.file` | string or null | `null` | Path to a JSON lines audit file. When set, a `FileAuditSink` is created automatically. |

When `observability.otel.enabled` is `true`, `Edictum.from_yaml()` calls `configure_otel()` with the provided settings. If `observability.file` is set and no explicit `audit_sink` is passed to `from_yaml()`, a `FileAuditSink` is created for that path. If `observability.stdout` is `false` and no `file` is set, audit emission is disabled entirely.

Standard OpenTelemetry environment variables override YAML values: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`.

For detailed sink configuration and custom sinks, see [Audit and Observability](../audit/sinks.md).

---

## Bundle Composition {#bundle-composition}

When contracts grow beyond a single file, `from_yaml()` accepts multiple paths. Bundles are composed left-to-right with deterministic merge semantics: later layers have higher priority.

```python
from edictum import Edictum

guard = Edictum.from_yaml(
    "contracts/base.yaml",
    "contracts/team-overrides.yaml",
    "contracts/prod-overrides.yaml",
)
```

### Merge Rules

| Element | Merge Rule |
|---------|-----------|
| Contracts (same ID) | Later layer **replaces** earlier layer entirely |
| Contracts (unique ID) | Concatenated into final list |
| `defaults.mode` | Later layer wins |
| `limits` | Later layer wins (entire limits block replaced) |
| `tools` | Deep merge (tool configs from all layers combined) |
| `metadata` | Deep merge (later keys override earlier) |
| `observability` | Later layer wins |

Contract replacement is by `id`, not by position. If `base.yaml` has `id: deny-rm-rf` and `overrides.yaml` also has `id: deny-rm-rf`, the override version completely replaces the base version. No partial merging of conditions within a contract.

### Composition Report

Pass `return_report=True` to see what happened during composition:

```python
guard, report = Edictum.from_yaml(
    "contracts/base.yaml",
    "contracts/overrides.yaml",
    return_report=True,
)

for o in report.overridden_contracts:
    print(f"{o.contract_id}: overridden by {o.overridden_by} (was in {o.original_source})")

for s in report.shadow_contracts:
    print(f"{s.contract_id}: shadow from {s.observed_source} (enforced in {s.enforced_source})")
```

### Dual-Mode Evaluation with `observe_alongside` {#observe-alongside}

The `observe_alongside` flag enables running two versions of the same contract simultaneously -- one enforced, one observed. This is for shadow-testing contract updates against live traffic.

When a bundle has `observe_alongside: true`, its contracts are not merged by ID replacement. Instead, they become **shadow copies** that evaluate in parallel without affecting real decisions:

```yaml
# candidate-update.yaml
apiVersion: edictum/v1
kind: ContractBundle
observe_alongside: true

metadata:
  name: candidate-contracts

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa", ".key"]
    then:
      effect: deny
      message: "Denied: read of sensitive file {args.path}"
      tags: [secrets, dlp]
```

Load both bundles:

```python
guard = Edictum.from_yaml(
    "contracts/base.yaml",            # enforced
    "contracts/candidate-update.yaml", # observe_alongside: true
)
```

The result:

- `block-sensitive-reads` from `base.yaml` makes real allow/deny decisions
- `block-sensitive-reads:candidate` from `candidate-update.yaml` evaluates in parallel and emits separate audit events with `mode: "observe"`

Shadow contracts produce `CALL_WOULD_DENY` or `CALL_ALLOWED` audit events but never block tool calls. This lets you compare the candidate's behavior against the enforced version before promoting it.

**What `observe_alongside` affects:**

- Shadow preconditions and session contracts are evaluated after real contracts
- Shadow contract IDs are suffixed with `:candidate` (e.g., `block-sensitive-reads:candidate`)
- Shadow audit events always have `mode: "observe"` regardless of the contract's declared mode
- Shadow session contracts do not affect real session limits

### Low-Level API: `compose_bundles()`

For advanced use cases, the composition primitive is available directly:

```python
from edictum.yaml_engine import compose_bundles, load_bundle

composed = compose_bundles(
    (load_bundle("base.yaml")[0], "base.yaml"),
    (load_bundle("overrides.yaml")[0], "overrides.yaml"),
)

# composed.bundle — the merged bundle dict
# composed.report — CompositionReport with overrides and shadows
```

---

## Complete Example {#complete-example}

The following bundle demonstrates all four contract types working together for a DevOps agent:

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: devops-agent
  description: "Governance for CI/CD and infrastructure agents."

defaults:
  mode: enforce

tools:
  read_file:
    side_effect: read
  bash:
    side_effect: irreversible
  deploy_service:
    side_effect: irreversible
  call_api:
    side_effect: write
  send_notification:
    side_effect: write

contracts:
  # --- File safety ---
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied. Skip and continue."
      tags: [secrets, dlp]

  # --- Bash safety ---
  - id: block-destructive-bash
    type: pre
    tool: bash
    when:
      any:
        - args.command: { matches: '\brm\s+(-rf?|--recursive)\b' }
        - args.command: { matches: '\bmkfs\b' }
        - args.command: { matches: '\bdd\s+' }
        - args.command: { contains: '> /dev/' }
    then:
      effect: deny
      message: "Destructive command denied: '{args.command}'. Use a safer alternative."
      tags: [destructive, safety]

  # --- Production gate: role-based ---
  - id: prod-deploy-requires-senior
    type: pre
    tool: deploy_service
    when:
      all:
        - environment: { equals: production }
        - principal.role: { not_in: [senior_engineer, sre, admin] }
    then:
      effect: deny
      message: "Production deploys require senior role (sre/admin)."
      tags: [change-control, production]

  # --- Production gate: ticket required ---
  - id: prod-requires-ticket
    type: pre
    tool: deploy_service
    when:
      all:
        - environment: { equals: production }
        - principal.ticket_ref: { exists: false }
    then:
      effect: deny
      message: "Production changes require a ticket reference."
      tags: [change-control, compliance]

  # --- Post-execution: PII detection ---
  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\b\d{3}-\d{2}-\d{4}\b'
          - '\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b'
    then:
      effect: warn
      message: "PII pattern detected in output. Redact before using."
      tags: [pii, compliance]

  # --- Observe mode: shadow-test a new contract ---
  - id: experimental-api-rate-check
    type: pre
    mode: observe
    tool: call_api
    when:
      args.endpoint: { contains: "/v1/expensive" }
    then:
      effect: deny
      message: "Expensive API call detected (observe mode)."
      tags: [cost, experimental]

  # --- File path sandbox ---
  - id: file-sandbox
    type: sandbox
    tools: [read_file, bash]
    within:
      - /opt/app
      - /tmp
    not_within:
      - /opt/app/.git
      - /opt/app/.env
    outside: deny
    message: "File access outside allowed directories: {args.path}"

  # --- Session limits ---
  - id: session-limits
    type: session
    limits:
      max_tool_calls: 50
      max_attempts: 120
      max_calls_per_tool:
        deploy_service: 3
        send_notification: 10
    then:
      effect: deny
      message: "Session limit reached. Summarize progress and stop."
      tags: [rate-limit]
```

This bundle enforces eight distinct concerns:

1. **Secret file protection** -- denies reads of `.env`, credentials, and key files.
2. **Destructive command prevention** -- denies `rm -rf`, `mkfs`, `dd`, and writes to `/dev/`.
3. **Role-based production gate** -- only senior engineers, SREs, and admins can deploy to production.
4. **Ticket-required production gate** -- production deploys must have a ticket reference.
5. **PII detection** -- warns when tool output contains SSN or IBAN patterns.
6. **Observe-mode experimentation** -- logs expensive API calls without denying, for cost analysis.
7. **File path sandbox** -- restricts file access to `/opt/app` and `/tmp`, excluding `.git` and `.env` directories.
8. **Session limits** -- caps total calls at 50, attempts at 120, and per-tool limits on deploy and notification tools.
