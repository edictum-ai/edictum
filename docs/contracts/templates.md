# Templates

Edictum ships four built-in contract templates for common agent patterns, and you can create your own. Templates are complete, production-ready YAML bundles that you can load directly or use as a starting point.

## Use Cases

**Team/org-specific contract libraries.** A platform team creates a `shared-contracts/` directory with templates like `support-agent`, `billing-agent`, `onboarding-agent`. Individual developers load them by name without knowing the YAML details — `from_template("support-agent", template_dirs=["shared-contracts/"])`.

**Override built-in defaults per project.** A team that needs a stricter `file-agent` (e.g., blocking additional patterns like `terraform.tfvars`) can drop their custom `file-agent.yaml` into a project directory. The override is automatic — same `from_template("file-agent")` call, different behavior.

**Template discovery for tooling and CI.** `list_templates()` lets CLI tools, dashboards, or CI scripts enumerate all available templates across directories. A CI job can validate all templates in a repo without hardcoding names.

**Multi-repo contract sharing.** A monorepo or shared package can publish templates as YAML files. Consumer repos point `template_dirs` at the shared package's template directory.

---

## Which Template?

**Quick decision tree:**

- Need to protect files and bash commands? → `file-agent`
- Need output scanning and session limits? → `research-agent`
- Need role gates, ticket requirements, and all of the above? → `devops-agent`
- Using nanobot with approval gates and path restrictions? → `nanobot-agent`

**Comparison:**

| Capability | `file-agent` | `research-agent` | `devops-agent` | `nanobot-agent` |
|-----------|:---:|:---:|:---:|:---:|
| Secret file protection | Yes | Yes (3 patterns) | Yes | Yes (regex) |
| Destructive bash denial | Yes | -- | Yes | -- |
| Write scope enforcement | Yes | -- | -- | Yes (workspace path) |
| PII detection in output | -- | Yes | Yes | -- |
| Session limits | -- | 50 calls / 100 attempts | 20 calls / 50 attempts | 100 calls / 200 attempts |
| Role-gated deploys | -- | -- | Yes | -- |
| Ticket requirements | -- | -- | Yes | -- |
| Approval gates | -- | -- | -- | Yes (exec, spawn, cron, MCP) |
| Per-tool limits | -- | -- | -- | Yes (exec: 20, spawn: 5, cron: 10) |

All templates can be customized after loading. See [Customizing Built-in Templates](#customizing-built-in-templates) below.

---

## Loading a Template

Use `Edictum.from_template()` to load a built-in template by name:

```python
from edictum import Edictum

guard = Edictum.from_template("file-agent")
```

This is equivalent to calling `Edictum.from_yaml()` on the template's YAML file, which means it goes through the same validation, compilation, and contract bundle hashing path as any custom bundle.

All `from_yaml()` options are available on `from_template()`:

```python
from edictum import Edictum
from edictum.audit import FileAuditSink, RedactionPolicy

guard = Edictum.from_template(
    "devops-agent",
    environment="staging",
    mode="observe",                                # shadow-test before enforcing
    audit_sink=FileAuditSink("audit.jsonl"),
    redaction=RedactionPolicy(sensitive_keys={"database_url"}),
)
```

Available built-in template names:

| Template | Target Use Case |
|---|---|
| `file-agent` | Agents that read/write files and run shell commands |
| `research-agent` | Agents that call APIs, search the web, and produce reports |
| `devops-agent` | Agents that manage infrastructure, deploy services, and handle CI/CD |
| `nanobot-agent` | Multi-channel nanobot agents with approval gates and workspace path enforcement |

---

## `file-agent`

The file-agent template protects against the two most common file-handling risks: reading secrets and running destructive shell commands. It also enforces a write scope that prevents agents from writing to arbitrary absolute paths.

### Contracts

| Contract ID | Type | Tool | Description |
|---|---|---|---|
| `block-sensitive-reads` | pre | `read_file` | Blocks reads of files containing `.env`, `.secret`, `kubeconfig`, `credentials`, `.pem`, or `id_rsa` in the path. |
| `block-destructive-bash` | pre | `bash` | Blocks `rm -rf` / `rm --recursive`, `mkfs` (filesystem format), and writes to `/dev/`. |
| `block-write-outside-target` | pre | `write_file` | Blocks writes to absolute paths (starting with `/`). Forces agents to use relative paths within a controlled working directory. |

### Full YAML

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: file-agent
  description: "Contracts for file-handling agents. Blocks sensitive reads and destructive bash."

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets, dlp]

  - id: block-destructive-bash
    type: pre
    tool: bash
    when:
      any:
        - args.command: { matches: '\\brm\\s+(-rf?|--recursive)\\b' }
        - args.command: { matches: '\\bmkfs\\b' }
        - args.command: { contains: '> /dev/' }
    then:
      effect: deny
      message: "Destructive command denied: '{args.command}'."
      tags: [destructive, safety]

  - id: block-write-outside-target
    type: pre
    tool: write_file
    when:
      args.path:
        starts_with: /
    then:
      effect: deny
      message: "Write to absolute path '{args.path}' denied. Use relative paths."
      tags: [write-scope]
```

### Contract Details

**block-sensitive-reads** -- This precondition targets the `read_file` tool and checks whether `args.path` contains any of six sensitive file patterns. The `contains_any` operator is a substring match, so `args.path: "/home/user/.env.local"` would match on `.env`. This catches common secret files: environment configs (`.env`), credential stores, Kubernetes configs, SSH keys, and TLS certificates.

**block-destructive-bash** -- This precondition targets the `bash` tool and uses an `any` combinator to match three categories of destructive commands. The `matches` operator uses regex word boundaries (`\b`) to avoid false positives -- `rm -rf` is denied but `perform` is not. The `contains` check for `> /dev/` catches attempts to write to device files.

**block-write-outside-target** -- This precondition targets `write_file` and uses `starts_with: /` to block any absolute path. The intent is to force agents to operate within a relative working directory, preventing writes to system paths like `/etc/` or `/usr/`. If your agent needs to write to specific absolute paths, replace this contract with a more targeted allowlist.

---

## `research-agent`

The research-agent template is designed for agents that gather information from APIs, databases, and the web. It provides secret file protection, PII detection in output, and session-level rate limiting to prevent runaway agents.

### Contracts

| Contract ID | Type | Tool | Description |
|---|---|---|---|
| `block-sensitive-reads` | pre | `read_file` | Blocks reads of `.env`, `.secret`, and `credentials` files. |
| `pii-in-output` | post | `*` (all tools) | Warns when tool output contains US Social Security Number patterns. |
| `session-limits` | session | -- | Caps the session at 50 tool executions and 100 total attempts. |

### Full YAML

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: research-agent
  description: "Contracts for research agents. Rate limits and output caps."

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

  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII pattern detected in output. Redact before using."
      tags: [pii, compliance]

  - id: session-limits
    type: session
    limits:
      max_tool_calls: 50
      max_attempts: 100
    then:
      effect: deny
      message: "Session limit reached. Summarize progress and stop."
      tags: [rate-limit]
```

### Contract Details

**block-sensitive-reads** -- A targeted version of the file-agent's secret protection. It checks for three common patterns (`.env`, `.secret`, `credentials`) rather than the full six-pattern set. Research agents typically don't interact with SSH keys or TLS certificates, so the pattern list is narrower.

**pii-in-output** -- This postcondition runs against all tools (wildcard `*`) and uses `matches_any` with a regex pattern for US Social Security Numbers (`\d{3}-\d{2}-\d{4}`). Because this is a postcondition, it cannot block the tool call -- it emits a warning so the agent (or a human reviewer) knows to redact the output before using it downstream. To detect additional PII patterns like IBAN numbers or credit card numbers, add more regex patterns to the `matches_any` array.

**session-limits** -- The session contract sets two counters. `max_tool_calls: 50` caps successful executions, preventing an agent from doing unbounded work. `max_attempts: 100` caps total contract evaluations, including denied calls. The attempt limit is set higher than the tool call limit because some denied calls are expected (the agent may probe a few denied paths before finding an allowed one). If attempts hit the ceiling, the agent is likely stuck in a denial loop.

---

## `devops-agent`

The devops-agent template is the most comprehensive built-in contract bundle. It combines secret protection, destructive command denial, role-based access control for production deploys, ticket-required change management, PII detection, and session limits.

### Contracts

| Contract ID | Type | Tool | Description |
|---|---|---|---|
| `block-sensitive-reads` | pre | `read_file` | Blocks reads of six sensitive file patterns. |
| `block-destructive-bash` | pre | `bash` | Blocks `rm -rf`, `mkfs`, and writes to `/dev/`. |
| `prod-deploy-requires-senior` | pre | `deploy_service` | Production deploys require `senior_engineer`, `sre`, or `admin` role. |
| `prod-requires-ticket` | pre | `deploy_service` | Production deploys require a `ticket_ref` on the principal. |
| `pii-in-output` | post | `*` (all tools) | Warns on SSN patterns in output. |
| `session-limits` | session | -- | Caps at 20 tool calls, 50 attempts. |

### Full YAML

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: devops-agent
  description: "Contracts for DevOps agents. Prod gates, ticket requirements, PII detection."

defaults:
  mode: enforce

contracts:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets, dlp]

  - id: block-destructive-bash
    type: pre
    tool: bash
    when:
      any:
        - args.command: { matches: '\\brm\\s+(-rf?|--recursive)\\b' }
        - args.command: { matches: '\\bmkfs\\b' }
        - args.command: { contains: '> /dev/' }
    then:
      effect: deny
      message: "Destructive command denied: '{args.command}'."
      tags: [destructive, safety]

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

  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII pattern detected in output. Redact before using."
      tags: [pii, compliance]

  - id: session-limits
    type: session
    limits:
      max_tool_calls: 20
      max_attempts: 50
    then:
      effect: deny
      message: "Session limit reached. Summarize progress and stop."
      tags: [rate-limit]
```

### Contract Details

**block-sensitive-reads** -- Identical to the file-agent version. Catches the full six-pattern set of sensitive files.

**block-destructive-bash** -- Identical to the file-agent version. Uses regex word boundaries to precisely match destructive commands without false positives.

**prod-deploy-requires-senior** -- This precondition uses an `all` combinator with two conditions: the environment must be `production` AND the principal's role must not be in the `[senior_engineer, sre, admin]` list. Both conditions must be true for the deny to fire. This means the contract only denies production deploys by non-senior roles -- staging and development deploys by any role are unaffected. If no principal is attached to the call, `principal.role` evaluates as missing, which means the `not_in` check evaluates to `false`, and the `all` block short-circuits to `false` -- the contract does not fire. To catch missing principals, pair this with a separate `principal.role: { exists: false }` check.

**prod-requires-ticket** -- This precondition also uses `all` to combine two conditions: production environment and missing ticket reference. The `exists: false` operator checks whether `principal.ticket_ref` is absent or null. This enforces change management: every production deploy must be traceable to a ticket. Non-production environments are unaffected.

**pii-in-output** -- Same as the research-agent version. Detects US SSN patterns in tool output and emits a warning.

**session-limits** -- Tighter limits than the research-agent template (20 tool calls, 50 attempts). DevOps agents typically perform fewer but higher-impact operations, so lower caps are appropriate. The limit message instructs the agent to summarize progress and stop, which gives operators a chance to review what happened before allowing more work.

---

## `nanobot-agent`

The nanobot-agent template is designed for multi-channel nanobot agents. It provides approval gates for high-risk operations (shell commands, sub-agent spawning, cron jobs, MCP tool calls), workspace path enforcement for file writes and edits, sensitive file read protection, and session limits with per-tool caps.

### Contracts

| Contract ID | Type | Tool | Description |
|---|---|---|---|
| `approve-exec` | pre | `exec` | Requires approval before executing shell commands. |
| `approve-spawn` | pre | `spawn` | Requires approval before spawning sub-agents. |
| `approve-cron` | pre | `cron` | Requires approval before creating cron jobs. |
| `deny-write-outside-workspace` | pre | `write_file` | Denies writes to paths outside `/workspace/`. |
| `deny-edit-outside-workspace` | pre | `edit_file` | Denies edits to paths outside `/workspace/`. |
| `deny-sensitive-reads` | pre | `read_file` | Denies reads of `.env`, `.key`, `.pem`, and `.secret` files. |
| `approve-mcp-tools` | pre | `mcp_*` | Requires approval for any MCP tool call. |
| `session-limits` | session | -- | Caps at 100 tool calls, 200 attempts, with per-tool limits (exec: 20, spawn: 5, cron: 10). |

### Full YAML

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: nanobot-agent
  description: "Governance contracts for nanobot AI agents"

defaults:
  mode: enforce

tools:
  exec:
    side_effect: irreversible
  write_file:
    side_effect: irreversible
  edit_file:
    side_effect: irreversible
  read_file:
    side_effect: read
  list_dir:
    side_effect: read
  web_search:
    side_effect: read
  web_fetch:
    side_effect: read
  message:
    side_effect: write
  spawn:
    side_effect: irreversible
  cron:
    side_effect: irreversible
  "mcp_*":
    side_effect: irreversible

contracts:
  - id: approve-exec
    type: pre
    tool: exec
    when:
      tool.name:
        exists: true
    then:
      effect: approve
      message: "Shell command requires approval: {args.command}"
      timeout: 300
      timeout_effect: deny

  - id: approve-spawn
    type: pre
    tool: spawn
    when:
      tool.name:
        exists: true
    then:
      effect: approve
      message: "Sub-agent spawn requires approval: {args.task}"
      timeout: 300
      timeout_effect: deny

  - id: approve-cron
    type: pre
    tool: cron
    when:
      tool.name:
        exists: true
    then:
      effect: approve
      message: "Cron job requires approval: {args.schedule}"
      timeout: 300
      timeout_effect: deny

  - id: deny-write-outside-workspace
    type: pre
    tool: write_file
    when:
      args.path:
        matches: '^(?!/workspace/).*'
    then:
      effect: deny
      message: "Cannot write outside workspace: {args.path}"

  - id: deny-edit-outside-workspace
    type: pre
    tool: edit_file
    when:
      args.path:
        matches: '^(?!/workspace/).*'
    then:
      effect: deny
      message: "Cannot edit outside workspace: {args.path}"

  - id: deny-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        matches: '.*\.(env|key|pem|secret)$'
    then:
      effect: deny
      message: "Cannot read sensitive file: {args.path}"

  - id: approve-mcp-tools
    type: pre
    tool: "mcp_*"
    when:
      tool.name:
        exists: true
    then:
      effect: approve
      message: "MCP tool call requires approval: {tool.name}"
      timeout: 120
      timeout_effect: deny

  - id: session-limits
    type: session
    limits:
      max_attempts: 200
      max_tool_calls: 100
      max_calls_per_tool:
        exec: 20
        spawn: 5
        cron: 10
    then:
      effect: deny
      message: "Session limit reached. Summarize progress and stop."
```

### Contract Details

**approve-exec** -- Requires human approval for every shell command. The `tool.name: {exists: true}` condition is always true, meaning the contract fires for every `exec` call. The approval timeout is 300 seconds (5 minutes); if no decision is received, the call is denied. Configure an `approval_backend` on the guard to handle approval requests.

**approve-spawn** -- Requires approval before spawning sub-agents. Sub-agent spawning is a high-risk operation because it creates autonomous child processes. The same timeout and deny-on-timeout behavior applies.

**approve-cron** -- Requires approval before scheduling cron jobs. Cron jobs execute outside the current session, so human review is appropriate.

**deny-write-outside-workspace / deny-edit-outside-workspace** -- These preconditions use a negative lookahead regex (`^(?!/workspace/).*`) to deny any path that doesn't start with `/workspace/`. This confines file modifications to the workspace directory. Adjust the path prefix if your nanobot agent uses a different working directory.

**deny-sensitive-reads** -- Uses a regex match to deny reading files with sensitive extensions (`.env`, `.key`, `.pem`, `.secret`). The `$` anchor ensures the match is against the file extension, not substrings in the path.

**approve-mcp-tools** -- Uses the `mcp_*` wildcard tool selector to require approval for any MCP-prefixed tool call. MCP tools are external integrations, so requiring approval adds a checkpoint before calling unknown external services.

**session-limits** -- Sets generous overall limits (200 attempts, 100 tool calls) with tighter per-tool caps for high-risk operations: `exec` is capped at 20, `spawn` at 5, and `cron` at 10. These per-tool limits prevent an agent from repeatedly executing shell commands or spawning sub-agents within a single session.

---

## Custom Template Directories

You can create your own templates and load them with the `template_dirs` parameter. User directories are searched first; built-in templates serve as a fallback.

```python
from edictum import Edictum

# Load a custom template from your project
guard = Edictum.from_template(
    "support-agent",
    template_dirs=["./contracts/templates"],
)
```

Multiple directories are searched in order — the first match wins:

```python
guard = Edictum.from_template(
    "my-agent",
    template_dirs=["./team-contracts", "./shared-contracts"],
)
```

A user template with the same name as a built-in overrides it:

```python
# If ./contracts/templates/file-agent.yaml exists,
# it takes precedence over the built-in file-agent template
guard = Edictum.from_template(
    "file-agent",
    template_dirs=["./contracts/templates"],
)
```

Backward compatible — calling `from_template()` without `template_dirs` works exactly as before:

```python
guard = Edictum.from_template("file-agent")  # still loads the built-in
```

---

## Creating a Template

A template is a standard YAML contract bundle file (`.yaml`). Place it in a directory and pass that directory to `template_dirs`.

### Template structure

Every template follows the same YAML schema as any contract bundle:

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: support-agent
  description: "Contracts for customer support agents."

defaults:
  mode: enforce

contracts:
  - id: block-ticket-leak
    type: pre
    tool: send_message
    when:
      args.body: { contains: "TICKET-" }
    then:
      effect: deny
      message: "Internal ticket references must not appear in customer messages."
      tags: [compliance, data-leak]

  - id: session-limits
    type: session
    limits:
      max_tool_calls: 30
      max_attempts: 60
    then:
      effect: deny
      message: "Session limit reached."
      tags: [rate-limit]
```

### Project layout

A typical project keeps templates alongside application code:

```
my-agent/
├── contracts/
│   └── templates/
│       ├── support-agent.yaml
│       └── billing-agent.yaml
├── app.py
└── pyproject.toml
```

```python
# app.py
from edictum import Edictum

guard = Edictum.from_template(
    "support-agent",
    template_dirs=["./contracts/templates"],
)
```

### Tips for writing templates

- **Use descriptive contract IDs.** IDs like `block-ticket-leak` are searchable in audit logs. Avoid generic names like `rule-1`.
- **Tag contracts.** Tags (`tags: [compliance, pii]`) make it easy to filter audit events by category.
- **Set session limits.** Every production template should include a session contract to prevent runaway agents.
- **Start in observe mode.** Use `mode: observe` in `defaults:` while developing, then switch to `enforce` after validating with `edictum test`.
- **Validate before deploying.** Run `edictum validate contracts/templates/support-agent.yaml` to catch schema errors early.

---

## Discovering Templates

Use `Edictum.list_templates()` to discover all available templates — both built-in and from custom directories:

```python
from edictum import Edictum

# Built-in templates only
for t in Edictum.list_templates():
    print(f"{t.name} (built-in: {t.builtin})")
```

Output:

```
devops-agent (built-in: True)
file-agent (built-in: True)
nanobot-agent (built-in: True)
research-agent (built-in: True)
```

With custom directories:

```python
templates = Edictum.list_templates(
    template_dirs=["./contracts/templates"],
)
for t in templates:
    source = "built-in" if t.builtin else str(t.path)
    print(f"{t.name}: {source}")
```

Output:

```
support-agent: contracts/templates/support-agent.yaml
devops-agent: built-in
file-agent: built-in
nanobot-agent: built-in
research-agent: built-in
```

Each entry is a `TemplateInfo` with three fields:

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Template name (filename without `.yaml`) |
| `path` | `Path` | Absolute path to the YAML file |
| `builtin` | `bool` | `True` for built-in templates, `False` for user templates |

When a user template has the same name as a built-in, `list_templates()` returns only the user version — matching the search order of `from_template()`.

---

## Customizing Built-in Templates

Built-in templates are a starting point. Two approaches:

**Option 1: Override with `template_dirs`.** Copy a built-in template to your project directory, modify it, and load it by name. Your version takes priority automatically.

**Option 2: Load directly with `from_yaml()`.** Copy the template, rename it, and load the modified version:

```python
from edictum import Edictum

guard = Edictum.from_yaml("contracts/my-devops-policy.yaml")
```

Common customizations:

- **Add PII patterns.** Extend `pii-in-output` with IBAN, credit card, or country-specific ID number regex patterns in the `matches_any` array.
- **Adjust session limits.** Increase or decrease `max_tool_calls` and `max_attempts` based on your agent's expected workload.
- **Add per-tool limits.** Add `max_calls_per_tool` to the session contract to cap specific high-impact tools like `deploy_service` or `send_notification`.
- **Add observe-mode contracts.** Add new preconditions with `mode: observe` to shadow-test contracts before enforcing them. Observed denials are logged as `CALL_WOULD_DENY` audit events without denying the tool call.
- **Target additional tools.** Add preconditions for tools specific to your stack (e.g., `run_migration`, `delete_pod`, `send_email`).
- **Expand sensitive file patterns.** Add entries to `contains_any` arrays to cover patterns specific to your infrastructure (e.g., `terraform.tfvars`, `.npmrc`, `.pypirc`).
