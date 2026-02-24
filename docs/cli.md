# CLI Reference

Edictum ships a command-line interface for validating contract files, checking
tool calls against contracts, diffing contract bundle versions, and replaying audit logs against updated contracts.

## When to use this

Read this page when you need to validate, test, diff, or replay contracts from the command line or in CI/CD. The CLI covers the full contract lifecycle outside of runtime: `edictum validate` catches schema errors, `edictum check` simulates a single tool call, `edictum test` runs batches of expected verdicts, `edictum diff` compares contract versions, and `edictum replay` re-evaluates historical audit events against new contracts. For runtime enforcement, use an [adapter](adapters/overview.md) or `guard.run()`. For programmatic dry-run evaluation, use [`evaluate()`](evaluation.md).

## Installation

```bash
pip install edictum[cli]
```

This pulls in [Click](https://click.palletsprojects.com/) and
[Rich](https://rich.readthedocs.io/) as additional dependencies. The `edictum`
command becomes available on your `PATH` via the entry point defined in `pyproject.toml`
(`edictum.cli.main:cli`).

---

## Commands

### `edictum validate`

Parse one or more YAML contract bundle files, validate them against the Edictum JSON
Schema, compile all regex patterns, check for unique contract IDs, and report any errors.

When two or more valid files are provided, bundles are composed and the composed result is also validated. This lets you verify that your layered bundles compose correctly.

**Usage**

```
edictum validate FILES... [--json]
```

Takes one or more file paths as positional arguments. Each file is validated independently first, then composed if multiple files are valid.

**Options**

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |

**Example -- single file**

```
$ edictum validate contracts/production.yaml

  production.yaml — 14 contracts (2 post, 8 pre, 1 sandbox, 2 session)
```

**Example -- multi-file composition**

```
$ edictum validate contracts/base.yaml contracts/overrides.yaml

  base.yaml — 9 contracts (1 post, 5 pre, 1 sandbox, 2 session)
  overrides.yaml — 3 contracts (3 pre)

Composed: 10 contracts (1 post, 6 pre, 1 sandbox, 2 session)

Composition report:
  ⇄ block-sensitive-reads — overridden by contracts/overrides.yaml (was in base.yaml)
```

When validation fails:

```
$ edictum validate contracts/broken.yaml

  broken.yaml — Invalid YAML: ...
```

**Example -- JSON output**

```
$ edictum validate contracts/production.yaml --json

{
  "files": [
    {
      "file": "production.yaml",
      "valid": true,
      "contracts": 14,
      "breakdown": {"pre": 8, "post": 2, "sandbox": 1, "session": 2}
    }
  ],
  "valid": true
}
```

Exit codes: `0` on success, `1` on validation errors.

---

### `edictum check`

Simulate a single tool call against your contracts. Builds a `ToolEnvelope`
from the provided tool name and arguments, evaluates all matching preconditions and
sandbox contracts, and prints the verdict. No tool actually executes.

**Usage**

```
edictum check <file.yaml> --tool <name> --args '<json>' [--json]
```

**Options**

| Flag | Description |
|------|-------------|
| `--tool TEXT` | Tool name to simulate (required) |
| `--args TEXT` | Tool arguments as a JSON string (required) |
| `--environment TEXT` | Environment name, defaults to `production` |
| `--principal-role TEXT` | Principal role |
| `--principal-user TEXT` | Principal user ID |
| `--principal-ticket TEXT` | Principal ticket ref |
| `--json` | Output results as JSON |

**Example -- allowed call**

```
$ edictum check contracts/production.yaml \
    --tool read_file \
    --args '{"path": "/app/config.json"}'

ALLOWED
  Contracts evaluated: 1
```

**Example -- denied call with principal**

```
$ edictum check contracts/production.yaml \
    --tool read_file \
    --args '{"path": "/home/user/.env"}' \
    --principal-role sre \
    --principal-user alice \
    --principal-ticket INC-4421

DENIED by contract block-sensitive-reads
  Message: Sensitive file '/home/user/.env' denied.
  Tags: secrets, dlp
  Contracts evaluated: 1
```

**Example -- role-gated production deploy**

```
$ edictum check contracts/production.yaml \
    --tool deploy_service \
    --args '{"env": "production", "service": "api"}' \
    --principal-role developer

DENIED by contract prod-deploy-requires-senior
  Message: Production deploys require senior role (sre/admin).
  Tags: change-control, production
  Contracts evaluated: 2
```

**Example -- passing with ticket and senior role**

```
$ edictum check contracts/production.yaml \
    --tool deploy_service \
    --args '{"env": "production", "service": "api"}' \
    --principal-role sre \
    --principal-user alice \
    --principal-ticket INC-4421

ALLOWED
  Contracts evaluated: 2
```

**Example -- denied by sandbox contract**

Sandbox contracts are also evaluated during `check`. A call outside the sandbox boundary is denied even if no precondition matches:

```
$ edictum check contracts/production.yaml \
    --tool read_file \
    --args '{"path": "/etc/shadow"}'

DENIED by sandbox contract file-sandbox
  Message: File access outside workspace: /etc/shadow
  Contracts evaluated: 2
```

The principal flags map directly to `Principal` fields:

| CLI Flag | Principal Field |
|----------|----------------|
| `--principal-role TEXT` | `Principal.role` |
| `--principal-user TEXT` | `Principal.user_id` |
| `--principal-ticket TEXT` | `Principal.ticket_ref` |

A `Principal` is constructed only when at least one `--principal-*` flag is provided. If none are set, the check runs without principal context (all `principal.*` selectors evaluate to `false`).

**Example -- JSON output**

```
$ edictum check contracts/production.yaml \
    --tool read_file \
    --args '{"path": "/home/user/.env"}' \
    --json

{
  "tool": "read_file",
  "args": {"path": "/home/user/.env"},
  "verdict": "deny",
  "reason": "Sensitive file '/home/user/.env' denied.",
  "contracts_evaluated": 1,
  "environment": "production",
  "contract_id": "block-sensitive-reads"
}
```

Exit codes: `0` on allow, `1` on deny, `2` on invalid JSON.

---

### `edictum diff`

Compare contract bundle files and report which contract IDs were added, removed,
or changed. Supports two or more files.

With exactly two files, a standard contract-by-contract diff is shown. With two or more files, a composition report shows overrides and shadow contracts.

**Usage**

```
edictum diff FILES... [--json]
```

Requires at least two file paths.

**Options**

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |

**Example -- two-file diff**

```
$ edictum diff contracts/v1.yaml contracts/v2.yaml

Added:
  + require-ticket-ref (type: pre)

Removed:
  - legacy-read-block (type: pre)

Changed:
  ~ no-secrets

Summary: 1 added, 1 removed, 1 changed, 3 unchanged
```

**Example -- multi-file composition diff**

```
$ edictum diff contracts/base.yaml contracts/overrides.yaml contracts/candidate.yaml

Composition report:
  ⇄ block-sensitive-reads — overridden by contracts/overrides.yaml (was in base.yaml)
  ⊕ block-sensitive-reads — shadow from contracts/candidate.yaml (enforced in contracts/overrides.yaml)
```

**Example -- JSON output**

```
$ edictum diff contracts/v1.yaml contracts/v2.yaml --json

{
  "added": [{"id": "require-ticket-ref", "type": "pre"}],
  "removed": [{"id": "legacy-read-block", "type": "pre"}],
  "changed": ["no-secrets"],
  "unchanged": ["pii-check", "session-cap", "bash-safety"],
  "has_changes": true
}
```

Exit codes: `0` if identical, `1` if differences found.

---

### `edictum replay`

Replay an audit log (JSONL) against a contract file and report what would change.
Each event in the audit log is re-evaluated as if the new contracts were in effect at
the time. This answers the question: "If I deploy these contracts, which past calls
would have been treated differently?"

Sandbox contracts are replayed alongside preconditions. Past tool calls that would now fall outside a sandbox boundary appear as changed verdicts.

**Usage**

```
edictum replay <file.yaml> --audit-log <events.jsonl>
```

**Options**

| Flag | Description |
|------|-------------|
| `--audit-log PATH` | JSONL audit log file to replay (required) |
| `--output PATH` | Write detailed report as JSONL |

**Example**

```
$ edictum replay contracts/v2.yaml --audit-log audit/last-week.jsonl

Replayed 1247 events, 2 would change

Changed verdicts:
  Bash: call_allowed -> denied
    Contract: no-sensitive-reads
  Write: call_allowed -> denied
    Contract: no-secrets
```

Exit codes: `0` if no changes, `1` if changes detected.

---

### `edictum test`

Two modes: YAML test cases with expected verdicts (`--cases`), or JSON tool calls
for dry-run evaluation (`--calls`). Exactly one must be provided.

**Usage**

```
edictum test <file.yaml> --cases <cases.yaml>
edictum test <file.yaml> --calls <calls.json> [--json]
```

**Options**

| Flag | Description |
|------|-------------|
| `--cases PATH` | YAML file with test cases (preconditions and sandbox contracts) |
| `--calls PATH` | JSON file with tool calls to evaluate (pre + postconditions) |
| `--json` | Output results as JSON (only with `--calls`) |
| `--environment TEXT` | Environment name for evaluation, defaults to `production` |

Exit codes: `0` if all cases pass / no denials, `1` if any fail / any denial, `2` on usage error.

---

#### Mode 1: `--cases` (YAML test cases)

Define expected outcomes in YAML and verify them in batch. Each case specifies a tool
call and the expected verdict -- like `pytest` for contracts.

```yaml
# tests/contract-cases.yaml
cases:
  - id: test-sensitive-read
    tool: read_file
    args:
      path: "/app/.env"
    principal:
      role: analyst
    expect: deny
    match_contract: block-sensitive-reads  # optional

  - id: test-normal-read
    tool: read_file
    args:
      path: "report.txt"
    principal:
      role: analyst
    expect: allow

  - id: test-with-claims
    tool: deploy_service
    args:
      env: production
    principal:
      role: developer
      claims:
        department: platform
        clearance: high
    expect: allow
```

Each test case supports:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | No | Test case identifier (shown in output) |
| `tool` | Yes | Tool name to simulate |
| `args` | Yes | Tool arguments as a YAML mapping |
| `expect` | Yes | Expected verdict: `allow` or `deny` |
| `principal` | No | Principal context (see below) |
| `match_contract` | No | Verify that this contract ID triggered the result |
| `environment` | No | Environment override (defaults to `--environment` flag value) |

The `principal` field supports `role`, `user_id`, `ticket_ref`, and `claims` (arbitrary key-value pairs).

**Example -- all passing**

```
$ edictum test contracts/production.yaml --cases tests/cases.yaml

  test-sensitive-read: read_file {"path": "/app/.env"} -> DENIED (block-sensitive-reads)
  test-normal-read: read_file {"path": "report.txt"} -> ALLOWED

2/2 passed, 0 failed
```

**Example -- with failures**

```
$ edictum test contracts/production.yaml --cases tests/cases.yaml

  test-block-env: read_file {"path": "/app/.env"} -> DENIED (block-sensitive-reads)
  test-wrong-expect: read_file {"path": "safe.txt"} -> expected DENY, got ALLOWED

1/2 passed, 1 failed
```

**Example -- wrong contract match**

When `match_contract` is specified but the wrong contract fires, the output shows
which contract actually triggered:

```
$ edictum test contracts/production.yaml --cases tests/cases.yaml

  test-wrong-match: read_file {"path": "/app/.env"} -> expected contract wrong-id, got block-sensitive-reads

0/1 passed, 1 failed
```

!!! note "Preconditions and sandbox contracts only"
    `--cases` evaluates preconditions and sandbox contracts. For postcondition testing, use `--calls`
    (see below) or [unit tests with pytest](guides/testing-contracts.md#unit-testing-with-pytest).

---

#### Mode 2: `--calls` (JSON tool calls)

Evaluate a JSON array of tool calls against contracts. Unlike `--cases`, this mode
supports both preconditions and postconditions (via the `output` field) and uses
`guard.evaluate_batch()` under the hood. All matching contracts are evaluated
exhaustively -- no short-circuit on first denial.

```json
[
  {"tool": "read_file", "args": {"path": "README.md"}},
  {"tool": "read_file", "args": {"path": "/app/.env"}},
  {"tool": "bash", "args": {"command": "ls -la"}},
  {
    "tool": "read_file",
    "args": {"path": "data.txt"},
    "output": "SSN: 123-45-6789"
  }
]
```

Each call object supports:

| Field | Required | Description |
|-------|----------|-------------|
| `tool` | Yes | Tool name |
| `args` | No | Tool arguments (defaults to `{}`) |
| `output` | No | Tool output string for postcondition evaluation |
| `principal` | No | Principal as `{"role": ..., "user_id": ..., "ticket_ref": ..., "claims": {...}}` |
| `environment` | No | Environment override |

**Example -- table output (default)**

```
$ edictum test contracts/production.yaml --calls tests/calls.json

  #  Tool        Verdict  Contracts  Details
  1  read_file   ALLOW    1          all contracts passed
  2  read_file   DENY     1          Sensitive file '/app/.env' denied.
  3  bash        ALLOW    0          all contracts passed
  4  read_file   WARN     1          PII detected.
  5  read_file   DENY     1          File access outside workspace: /etc/shadow
```

**Example -- JSON output**

```
$ edictum test contracts/production.yaml --calls tests/calls.json --json

[
  {
    "verdict": "allow",
    "tool_name": "read_file",
    "contracts_evaluated": 1,
    "deny_reasons": [],
    "warn_reasons": [],
    "policy_error": false,
    "contracts": [...]
  },
  ...
]
```

The `--json` output includes the full `contracts` array with `contract_id`, `contract_type`,
`passed`, `message`, `tags`, `observed`, and `policy_error` for each evaluated contract.

---

## Combining with CI/CD

All commands return structured exit codes suitable for pipeline gating:

```yaml
# GitHub Actions example
- name: Validate contracts
  run: edictum validate contracts/production.yaml

- name: Test contracts against cases
  run: edictum test contracts/production.yaml --cases tests/contract-cases.yaml

- name: Evaluate tool calls (including postconditions)
  run: edictum test contracts/production.yaml --calls tests/calls.json

- name: Diff against main
  run: |
    git show main:contracts/production.yaml > /tmp/old.yaml
    edictum diff /tmp/old.yaml contracts/production.yaml

- name: Replay last week's audit log
  run: |
    edictum replay contracts/production.yaml \
      --audit-log audit/last-week.jsonl \
      --output replay-report.jsonl
```
