# Use Cases

Real scenarios where Edictum prevents AI agents from causing harm. Each example includes a complete contract bundle you can copy and customize.

---

## Coding Agent

**The problem.** A coding agent has access to `read_file`, `write_file`, and `bash`. Without enforcement, it can read `.env` files, leak API keys in its responses, and run `rm -rf /` if a jailbreak succeeds. The BashClassifier and secret redaction handle most of this automatically.

**Quick start with a template:**

```python
from edictum import Edictum

guard = Edictum.from_template("file-agent")
```

**Complete contract bundle:**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: coding-agent

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

**Wiring code:**

```python
import asyncio
from edictum import Edictum, EdictumDenied

async def main():
    guard = Edictum.from_template("file-agent")

    # Every tool call goes through guard.run()
    try:
        result = await guard.run(
            "read_file",
            {"path": "/app/.env"},
            read_file_fn,
        )
    except EdictumDenied as e:
        print(f"Denied: {e.reason}")
        # => "Denied: Sensitive file '/app/.env' denied."

asyncio.run(main())
```

**What this showcases: automatic security.** Secret values are auto-redacted in audit events and denial messages. Bash commands are sanitized (passwords, tokens, connection strings). Contract errors fail closed -- a misconfigured contract denies by default, never silently passes.

**Stronger alternative: sandbox contracts.** The deny-list contracts above catch known-bad patterns. If red team bypasses keep appearing (`base64 /etc/shadow`, `awk '{print}' /etc/shadow`), switch to a sandbox that defines what's allowed:

```yaml
contracts:
  # Allowlist: only /workspace and /tmp
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

  # Allowlist: only approved commands
  - id: exec-sandbox
    type: sandbox
    tool: bash
    allows:
      commands: [git, npm, pnpm, node, python, pytest, ruff, ls, cat, grep, find]
    outside: deny
    message: "Command not in allowlist: {args.command}"
```

Now `base64 /etc/shadow` is denied -- not because `base64` is in a denylist, but because `/etc/shadow` is not in `/workspace` or `/tmp`. See [sandbox contracts](concepts/sandbox-contracts.md) for the full concept.

---

## Healthcare / Pharma

**The problem.** A clinical assistant has access to `query_clinical_data` and `update_patient_record`. A nurse should be able to read vitals for their assigned patients but never access psychiatric notes. An unauthenticated request should never reach patient data at all.

**Complete contract bundle:**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: healthcare-agent

defaults:
  mode: enforce

contracts:
  - id: require-authenticated-principal
    type: pre
    tool: query_clinical_data
    when:
      principal.role:
        exists: false
    then:
      effect: deny
      message: "Clinical data access requires an authenticated principal."
      tags: [access-control, hipaa]

  - id: restrict-psychiatric-notes
    type: pre
    tool: query_clinical_data
    when:
      all:
        - args.data_type: { equals: psychiatric_notes }
        - principal.role: { not_in: [psychiatrist, attending_physician] }
    then:
      effect: deny
      message: "Access to psychiatric notes denied for role '{principal.role}'. Requires psychiatrist or attending physician."
      tags: [access-control, hipaa, psychiatric]

  - id: restrict-patient-updates
    type: pre
    tool: update_patient_record
    when:
      principal.role: { not_in: [physician, attending_physician, nurse_practitioner] }
    then:
      effect: deny
      message: "Patient record updates denied for role '{principal.role}'."
      tags: [access-control, hipaa]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 30
      max_attempts: 60
    then:
      effect: deny
      message: "Session limit reached. End consultation and start a new session."
      tags: [rate-limit]
```

**Wiring code:**

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("healthcare.yaml")

# Principal comes from your auth layer -- JWT claims, session context, etc.
adapter = LangChainAdapter(
    guard,
    principal=Principal(
        role="nurse",
        claims={"department": "cardiology", "assigned_patients": ["P-1234"]},
    ),
)
wrapper = adapter.as_tool_wrapper()
```

**What this showcases: access control.** Principal claims and role gates enforce who can access what. Dynamic messages include the denied role so audit logs are immediately actionable. Session caps prevent runaway queries.

---

## Finance

**The problem.** A financial analysis agent queries databases and returns results to analysts. Query results often contain SSNs, account numbers, and other PII. The agent shouldn't be denied access to the data -- it needs it to do analysis -- but PII should never appear in the response the analyst sees.

**Complete contract bundle:**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: finance-agent

defaults:
  mode: enforce

tools:
  query_database:
    side_effect: read

contracts:
  - id: redact-ssn-in-output
    type: post
    tool: query_database
    when:
      output.text:
        matches: '\b\d{3}-\d{2}-\d{4}\b'
    then:
      effect: redact
      message: "SSN pattern detected and redacted from query result."
      tags: [pii, compliance]

  - id: redact-account-numbers
    type: post
    tool: query_database
    when:
      output.text:
        matches: '\b\d{8,17}\b'
    then:
      effect: redact
      message: "Account number pattern detected and redacted."
      tags: [pii, compliance]

  - id: block-bulk-export
    type: pre
    tool: query_database
    when:
      args.query:
        matches: '(?i)select\s+\*.*limit\s+\d{4,}'
    then:
      effect: deny
      message: "Bulk data export denied. Use targeted queries with reasonable limits."
      tags: [dlp, compliance]

  - id: transaction-session-cap
    type: session
    limits:
      max_tool_calls: 15
    then:
      effect: deny
      message: "Query limit reached for this analysis session."
      tags: [rate-limit]
```

**Wiring code:**

```python
from edictum import Edictum, EdictumDenied

guard = Edictum.from_yaml("finance.yaml")

# The tool executes, postconditions scan the output, PII is redacted
result = await guard.run(
    "query_database",
    {"query": "SELECT name, ssn, balance FROM accounts WHERE id = 42"},
    db_query_fn,
)
# result contains "***-**-****" instead of the actual SSN
```

**What this showcases: postcondition effects.** `effect: redact` strips PII from tool output before the agent sees it. The tool still executes -- the agent gets the data it needs for analysis, but sensitive patterns are replaced. `effect: deny` on postconditions suppresses the entire output.

---

## DevOps

**The problem.** A DevOps agent manages deployments, runs diagnostics, and modifies infrastructure. You need production deploy gates (only seniors, only with tickets), bash safety, and a way to roll out new contracts without breaking existing enforcement.

**Quick start with a template:**

```python
from edictum import Edictum

guard = Edictum.from_template("devops-agent")
```

**Complete contract bundle:**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: devops-agent

defaults:
  mode: enforce

contracts:
  - id: prod-deploy-requires-senior
    type: pre
    tool: deploy_service
    when:
      all:
        - env.DEPLOY_ENV: { equals: production }
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
        - env.DEPLOY_ENV: { equals: production }
        - principal.ticket_ref: { exists: false }
    then:
      effect: deny
      message: "Production changes require a ticket reference."
      tags: [change-control, compliance]

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
      message: "Destructive command denied."
      tags: [destructive, safety]

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

**Safe rollout with observe_alongside:**

```yaml
# new-deploy-contracts.yaml -- shadow-tested alongside production contracts
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: devops-v2-shadow

defaults:
  mode: observe_alongside

contracts:
  - id: require-rollback-plan
    type: pre
    tool: deploy_service
    when:
      principal.claims.rollback_plan:
        exists: false
    then:
      effect: deny
      message: "Deploy requires a rollback plan in principal claims."
      tags: [change-control]
```

```python
from edictum import Edictum

# Compose production + shadow contracts
guard = Edictum.from_yaml("devops.yaml", "new-deploy-contracts.yaml")

# Shadow contracts log what would be denied but don't block anything
# Review audit logs, then promote: change mode from observe_alongside to enforce
```

**Checking drift before promoting:**

```bash
# See what changed between bundle versions
$ edictum diff devops-v1.yaml devops-v2.yaml

# Replay historical audit events against new contracts
$ edictum replay --audit audit.jsonl --contracts devops-v2.yaml
```

**What this showcases: safe rollouts.** `observe_alongside` lets you shadow-test new contracts without affecting production enforcement. `edictum diff` shows exactly what changed. `edictum replay` predicts how new contracts would have affected past tool calls. Promote when you're confident.

---

## Education

**The problem.** A tutoring agent helps students with assignments. It has access to `search_web`, `run_code`, and `retrieve_document`. You need to prevent access to student records, cap tool calls per assignment session, and validate that your contracts behave correctly before deploying to students.

**Complete contract bundle:**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: education-agent

defaults:
  mode: enforce

contracts:
  - id: block-student-records
    type: pre
    tool: retrieve_document
    when:
      args.path:
        contains_any: ["/grades/", "/transcripts/", "/disciplinary/"]
    then:
      effect: deny
      message: "Access to student records denied."
      tags: [ferpa, student-privacy]

  - id: block-answer-keys
    type: pre
    tool: retrieve_document
    when:
      args.path:
        contains: "/answer-keys/"
    then:
      effect: deny
      message: "Access to answer keys denied during student sessions."
      tags: [academic-integrity]

  - id: assignment-session-cap
    type: session
    limits:
      max_tool_calls: 25
      max_attempts: 50
    then:
      effect: deny
      message: "Session limit reached for this assignment. Submit your work and start a new session."
      tags: [rate-limit, academic-integrity]
```

**Testing contracts before deployment:**

```python
from edictum import Edictum

guard = Edictum.from_yaml("education.yaml")

# Dry-run: does this call get denied?
result = guard.evaluate(
    "retrieve_document",
    {"path": "/grades/student-123.json"},
)
assert result.verdict == "deny"
assert "student records" in result.deny_reasons[0].lower()

# Batch: test multiple scenarios at once
results = guard.evaluate_batch([
    {"tool": "retrieve_document", "args": {"path": "/textbooks/chapter-1.pdf"}},
    {"tool": "retrieve_document", "args": {"path": "/grades/student-456.json"}},
    {"tool": "run_code", "args": {"code": "print('hello')"}},
])
assert results[0].verdict == "allow"
assert results[1].verdict == "deny"
assert results[2].verdict == "allow"
```

**YAML test cases with edictum test:**

```yaml
# education-tests.yaml
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: education-tests

tests:
  - description: "Student record access is denied"
    tool: retrieve_document
    args:
      path: "/grades/student-123.json"
    expect: deny

  - description: "Textbook access is allowed"
    tool: retrieve_document
    args:
      path: "/textbooks/chapter-1.pdf"
    expect: allow

  - description: "Answer key access is denied"
    tool: retrieve_document
    args:
      path: "/answer-keys/quiz-3.json"
    expect: deny
```

```bash
$ edictum test education.yaml --cases education-tests.yaml
  3 test cases: 3 passed, 0 failed
```

**What this showcases: contract testing.** `guard.evaluate()` dry-runs contracts without executing the tool. `evaluate_batch()` tests multiple scenarios at once. `edictum test` runs YAML test cases from the CLI with expected verdicts. CI/CD exit codes gate your deployment pipeline.

---

## Legal

**The problem.** A legal research agent has access to `search_documents`, `retrieve_case`, and `summarize_document`. It handles privileged attorney-client communications, confidential case files, and documents under regulatory hold. Every access must be auditable for compliance.

**Complete contract bundle:**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: legal-agent

defaults:
  mode: enforce

contracts:
  - id: restrict-privileged-docs
    type: pre
    tool: retrieve_case
    when:
      all:
        - args.classification: { equals: privileged }
        - principal.role: { not_in: [attorney, partner, legal_ops] }
    then:
      effect: deny
      message: "Privileged document access denied for role '{principal.role}'."
      tags: [privilege, compliance]

  - id: block-regulatory-hold
    type: pre
    tool: retrieve_case
    when:
      args.tags:
        contains: regulatory_hold
    then:
      effect: deny
      message: "Document under regulatory hold. Access requires manual approval."
      tags: [regulatory, compliance]

  - id: redact-client-pii
    type: post
    tool: search_documents
    when:
      output.text:
        matches: '\b\d{3}-\d{2}-\d{4}\b'
    then:
      effect: redact
      message: "Client PII detected and redacted from search results."
      tags: [pii, compliance]
```

**Wiring with audit trail:**

```python
from edictum import Edictum, Principal
from edictum.audit import FileAuditSink, RedactionPolicy

# File sink writes structured JSONL -- one event per line, queryable
redaction = RedactionPolicy()
audit_sink = FileAuditSink("legal-audit.jsonl", redaction)

guard = Edictum.from_yaml(
    "legal.yaml",
    audit_sink=audit_sink,
    redaction=redaction,
)

# Every evaluation produces a structured audit event:
# - tool name, args (with secrets redacted), principal, verdict
# - policy_version hash ties every event to the exact contract bundle
# - timestamps, session counters, environment context

result = await guard.run(
    "retrieve_case",
    {"case_id": "2024-CF-1234", "classification": "privileged"},
    retrieve_case_fn,
    principal=Principal(role="attorney", claims={"bar_number": "12345"}),
)
```

**Audit event example** (written to `legal-audit.jsonl`):

```json
{
  "action": "call_allowed",
  "tool_name": "retrieve_case",
  "tool_args": {"case_id": "2024-CF-1234", "classification": "privileged"},
  "principal": {"role": "attorney", "claims": {"bar_number": "12345"}},
  "policy_version": "a3f8c2...",
  "environment": "production",
  "session_attempt_count": 1,
  "session_execution_count": 1
}
```

**What this showcases: observability.** Every evaluation -- allowed, denied, or observed -- produces a structured audit event. The `policy_version` hash ties each event to the exact contract bundle that was loaded. `FileAuditSink` writes JSONL for compliance archives. OpenTelemetry spans emit the same data for Grafana, Datadog, or any OTel-compatible backend.

---

## Common Workflows

### Composing templates with custom contracts

Start with a built-in template and layer your own contracts on top:

```python
from edictum import Edictum

# Template provides base contracts, your YAML adds domain-specific ones
guard = Edictum.from_yaml(
    "file-agent",        # built-in template (secret protection, bash safety)
    "my-overrides.yaml", # your custom contracts
)
```

Or merge multiple guards programmatically:

```python
base = Edictum.from_template("file-agent")
custom = Edictum.from_yaml("custom.yaml")
guard = Edictum.from_multiple([base, custom])
```

### Dry-run testing

Test your contracts before deploying:

```python
guard = Edictum.from_yaml("contracts.yaml")

# Single call
result = guard.evaluate("read_file", {"path": ".env"})
print(result.verdict)       # "deny"
print(result.deny_reasons)  # ["Sensitive file '.env' denied."]

# Batch -- test an entire scenario
results = guard.evaluate_batch([
    {"tool": "read_file", "args": {"path": "README.md"}},
    {"tool": "read_file", "args": {"path": ".env"}},
    {"tool": "bash", "args": {"command": "ls -la"}},
    {"tool": "bash", "args": {"command": "rm -rf /"}},
])
# => [allow, deny, allow, deny]
```

From the CLI:

```bash
# Quick check
$ edictum check contracts.yaml --tool read_file --args '{"path": ".env"}'
  DENIED by block-sensitive-reads

# Run test suite
$ edictum test contracts.yaml --cases tests.yaml
  4 test cases: 4 passed, 0 failed
```

### Observe, then enforce

Start in observe mode to see what your contracts would deny without actually denying anything. Review the audit log. Tune. Then enforce.

```yaml
# Step 1: Deploy in observe mode
defaults:
  mode: observe

# Step 2: Review audit logs -- look for CALL_WOULD_DENY events
# Step 3: Tune contracts based on false positives
# Step 4: Switch to enforce
defaults:
  mode: enforce
```

For incremental rollout of new contracts alongside existing enforcement:

```yaml
# new-contracts.yaml
defaults:
  mode: observe_alongside

contracts:
  - id: new-restriction
    # ... this contract logs but doesn't deny
```

```python
guard = Edictum.from_yaml("production.yaml", "new-contracts.yaml")
# Production contracts enforce normally
# New contracts shadow-log only
```

---

## MCP Servers

MCP servers expose tools with known, stable names — `mcp__postgres__query`, `mcp__slack__send_message`, `mcp__github__create_issue`. This makes contract authoring straightforward: you know the exact tool names and argument shapes upfront.

**The problem.** Your agent connects to Postgres, Slack, and GitHub MCP servers. It can query any table, message any channel, and create issues with arbitrary content. One prompt injection in a document and it's exfiltrating data through Slack or creating spam issues.

**Complete contract bundle:**

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: mcp-servers

defaults:
  mode: enforce

tools:
  mcp__postgres__query: { side_effect: read }
  mcp__slack__send_message: { side_effect: write }
  mcp__github__create_issue: { side_effect: write }
  mcp__filesystem__read_file: { side_effect: read }

contracts:
  # --- Postgres MCP ---
  - id: deny-unrestricted-queries
    type: pre
    tool: mcp__postgres__query
    when:
      args.sql:
        matches: '(?i)SELECT\s+\*'
    then:
      effect: deny
      message: "SELECT * denied. Specify columns explicitly."
      tags: [data-protection, postgres]

  - id: deny-destructive-sql
    type: pre
    tool: mcp__postgres__query
    when:
      args.sql:
        matches: '(?i)\b(DROP|TRUNCATE|DELETE\s+FROM|ALTER)\b'
    then:
      effect: deny
      message: "Destructive SQL denied: {args.sql}"
      tags: [data-protection, postgres]

  - id: redact-pii-from-query-results
    type: post
    tool: mcp__postgres__query
    when:
      output.text:
        matches_any:
          - '\b\d{3}-\d{2}-\d{4}\b'
          - '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    then:
      effect: redact
      message: "PII redacted from query results."
      tags: [pii, postgres]

  # --- Slack MCP ---
  - id: slack-restrict-channels
    type: pre
    tool: mcp__slack__send_message
    when:
      args.channel:
        not_in: ["#agent-updates", "#alerts"]
    then:
      effect: deny
      message: "Agent can only post to #agent-updates and #alerts."
      tags: [access-control, slack]

  # --- GitHub MCP ---
  - id: github-require-label
    type: pre
    tool: mcp__github__create_issue
    when:
      args.labels:
        exists: false
    then:
      effect: deny
      message: "Issues must include at least one label."
      tags: [compliance, github]

  # --- Filesystem MCP ---
  - id: deny-sensitive-files
    type: pre
    tool: mcp__filesystem__read_file
    when:
      args.path:
        contains_any: [".env", ".pem", "credentials", "id_rsa"]
    then:
      effect: deny
      message: "Reading sensitive file denied: {args.path}"
      tags: [secrets, filesystem]

  # --- Session limits across all MCP tools ---
  - id: mcp-session-limits
    type: session
    limits:
      max_tool_calls: 100
      max_calls_per_tool:
        mcp__slack__send_message: 10
        mcp__github__create_issue: 5
    then:
      effect: deny
      message: "Session limit reached."

```

**Wiring it up:**

```python
from edictum import Edictum

guard = Edictum.from_yaml("mcp-contracts.yaml")

# Use guard.run() to wrap any MCP tool call
result = await guard.run(
    "mcp__postgres__query",
    {"sql": "SELECT name, email FROM users WHERE id = 42"},
    mcp_query_fn,
)
```

**What this showcases: real tool names from real MCP servers.** You know the tool names (`mcp__postgres__query`, `mcp__slack__send_message`) because MCP servers declare them. Write contracts against exact names and argument shapes. Combine preconditions (deny destructive SQL, restrict Slack channels), postconditions (redact PII from query results), and session limits (cap Slack messages) in one bundle.
