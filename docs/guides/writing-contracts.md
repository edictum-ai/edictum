# Tutorial: Creating Contracts

This guide walks through the full workflow of creating, validating, and deploying an Edictum contract -- from requirement to production enforcement.

---

## When to use this

Start here when you need to turn an informal restriction into a working YAML contract. This guide walks through the full authoring workflow -- translating a requirement into selectors and operators, validating the result with `edictum check`, deploying in observe mode, and flipping to enforce once you are confident. It also covers common pitfalls like missing principal fields, regex escaping in YAML, and choosing the right operator. For testing contracts once they are written, see [Testing contracts](testing-contracts.md). For postcondition-specific design, see [Postcondition design](postcondition-design.md).

---

## Step 1: Start With a Requirement

Suppose your team has this requirement:

> Analysts should not be able to read secret files like `.env`, `.pem`, or credential files.

This is a precondition -- you want to block the tool call *before* it executes.

---

## Step 2: Translate to a YAML Contract

Create a file called `contracts.yaml` with a complete ContractBundle:

```yaml
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: analyst-file-policy
  description: "Prevent analysts from reading secret files."

defaults:
  mode: observe

contracts:
  - id: block-secret-reads
    type: pre
    tool: read_file
    when:
      all:
        - args.path:
            contains_any: [".env", ".secret", "credentials", ".pem", "id_rsa"]
        - principal.role:
            equals: analyst
    then:
      effect: deny
      message: "Analysts cannot read '{args.path}'. Ask an admin for help."
      tags: [secrets, dlp]
```

Key decisions in this contract:

- **`type: pre`** -- evaluate before the tool runs.
- **`tool: read_file`** -- only applies to the `read_file` tool.
- **`all`** -- both conditions must be true (sensitive path AND analyst role).
- **`effect: deny`** -- block the call. This is the only valid effect for preconditions.
- **`mode: observe`** in defaults -- start by observing, not enforcing.

---

## Step 3: Validate the Contract

Run the CLI validator to catch syntax and schema errors before deployment:

```
$ edictum validate contracts.yaml

  contracts.yaml — 1 contract (1 pre)
```

If there are errors (bad regex, wrong effect, duplicate IDs), the validator reports them and exits with code 1.

---

## Step 4: Test With `edictum check`

Simulate a tool call against the contract without executing anything:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": ".env"}' \
    --principal-role analyst

DENIED by contract block-secret-reads
  Message: Analysts cannot read '.env'. Ask an admin for help.
  Tags: secrets, dlp
  Contracts evaluated: 1
```

Verify that allowed calls pass:

```
$ edictum check contracts.yaml \
    --tool read_file \
    --args '{"path": "readme.txt"}' \
    --principal-role analyst

ALLOWED
  Contracts evaluated: 1 contract(s)
```

---

## Step 5: Deploy in Observe Mode

Notice that `defaults.mode` is set to `observe`. In this mode, Edictum logs what *would* be denied without actually denying anything. This is safe for production rollout.

```python
from edictum import Edictum, Principal
from edictum.adapters.langchain import LangChainAdapter

guard = Edictum.from_yaml("contracts.yaml")

adapter = LangChainAdapter(
    guard=guard,
    principal=Principal(user_id="alice", role="analyst"),
)

middleware = adapter.as_middleware()
# Tool calls proceed normally, but denials are logged
```

---

## Step 6: Review Audit Logs

In observe mode, denied calls produce `call_would_deny` audit events. Review them to confirm the contract fires on the right calls and not on legitimate ones:

```json
{
  "action": "call_would_deny",
  "tool_name": "read_file",
  "decision_name": "block-secret-reads",
  "tool_args": {"path": ".env"},
  "principal": {"user_id": "alice", "role": "analyst"},
  "reason": "Analysts cannot read '.env'. Ask an admin for help."
}
```

Check for:

- **False positives** -- legitimate calls that would be denied.
- **False negatives** -- calls that should be denied but are not.
- **Missing principal fields** -- if `principal.role` is null, the leaf evaluates to `false` and the contract never fires.

---

## Step 7: Flip to Enforce

Once you are confident in the contract behavior, change `mode` from `observe` to `enforce`:

```yaml
defaults:
  mode: enforce
```

Now denied calls are enforced. The tool callable is never invoked, and the agent sees the denial message.

---

## Common Mistakes

### Wrong operator

Using `equals` when you need `contains`:

```yaml
# Wrong -- only matches if the entire path is literally ".env"
args.path:
  equals: ".env"

# Right -- matches any path containing ".env"
args.path:
  contains: ".env"
```

### Missing principal field

If the principal does not have a `role` field set, selectors like `principal.role` resolve to null. A null selector causes the leaf to evaluate to `false`, so the contract never fires. The call is silently allowed.

Fix: ensure the principal is populated when creating the adapter:

```python
principal = Principal(user_id="alice", role="analyst")
adapter = LangChainAdapter(guard=guard, principal=principal)
```

### Regex escaping in YAML

YAML double-quoted strings interpret escape sequences. `"\b"` is a backspace character, not a word boundary. Always use single quotes for regex:

```yaml
# Wrong -- "\b" is backspace
args.command:
  matches: "\brm\b"

# Right -- '\b' is literal backslash-b (word boundary)
args.command:
  matches: '\brm\b'
```

### Using output.text in preconditions

The `output.text` selector is only available in postconditions (after the tool has run). Using it in a precondition is a validation error at load time:

```yaml
# Wrong -- output.text does not exist before the tool runs
- id: bad-pre
  type: pre
  tool: read_file
  when:
    output.text:
      contains: "SECRET"
  then:
    effect: deny
    message: "..."
```

### Postcondition effects

Since v0.6.0, postconditions support three effects:

| Effect | What happens |
|--------|-------------|
| `warn` | Emit a finding. Output passes through unchanged. Handle with `on_postcondition_warn` callback. |
| `redact` | Replace regex-matched patterns in the output with `[REDACTED]`. |
| `deny` | Replace the entire tool output with `[OUTPUT SUPPRESSED]`. |

```yaml
# Redact SSNs from output
- id: redact-ssn
  type: post
  tool: "*"
  when:
    output.text:
      matches: '\b\d{3}-\d{2}-\d{4}\b'
  then:
    effect: redact
    message: "SSN pattern redacted from output."
```

The effect you choose depends on the severity: `warn` for logging, `redact` for targeted cleanup, `deny` for full suppression when any match means the output is unsafe.

---

## Writing Sandbox Contracts

When deny-lists grow too long or bypass vectors keep appearing, switch to sandbox contracts. Instead of listing what's bad, define what's allowed.

### Example: File Path Sandbox

Requirement: the agent should only read/write files in `/workspace` and `/tmp`, never in `/workspace/.git`.

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

Key differences from preconditions:

- No `when`/`then` structure. Sandbox uses declarative boundary fields.
- `tools` accepts a list. One sandbox contract covers multiple tools.
- `within` + `not_within` define path allowlists, not pattern denylists.
- `outside` controls the effect: `deny` or `approve` (human approval gate).

### Command and Domain Allowlists

Sandbox contracts also support command and domain boundaries:

```yaml
- id: network-sandbox
  type: sandbox
  tool: fetch_url
  allows:
    domains: [api.example.com, cdn.example.com]
  not_allows:
    domains: [internal.example.com]
  outside: deny
  message: "Domain not in allowlist: {args.url}"
```

### When to Use Sandbox vs. Precondition

| Use... | When... |
|---|---|
| Precondition (`type: pre`) | You have a short, stable list of things to deny (`rm -rf /`, reverse shells, `.env` reads). The list does not grow with every red team. |
| Sandbox (`type: sandbox`) | The attack surface is open-ended. You would rather define what is allowed. New bypasses are denied by default. |

They compose: deny runs first (catch known-bad), sandbox runs second (catch unknown-bad).
