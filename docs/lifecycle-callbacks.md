# Lifecycle Callbacks

Edictum provides two lifecycle callbacks on the `Edictum` constructor for reacting to
allow/deny decisions in real time. Unlike [postcondition findings](findings.md), which
fire after tool execution, these callbacks fire **before** the tool runs -- at the
moment the pipeline decides whether to allow or deny.

## Signatures

```python
guard = Edictum(
    contracts=[...],
    on_deny=lambda envelope, reason, contract_id: ...,
    on_allow=lambda envelope: ...,
)
```

| Callback | Signature | When it fires |
|----------|-----------|---------------|
| `on_deny` | `(envelope: ToolEnvelope, reason: str, contract_id: str \| None) -> None` | A tool call is **denied** in enforce mode |
| `on_allow` | `(envelope: ToolEnvelope) -> None` | A tool call **passes** all pre-execution checks |

Both callbacks are sync. If a callback raises an exception, it is caught and logged --
the pipeline continues normally.

## When They Fire (and Don't)

| Scenario | `on_deny` | `on_allow` |
|----------|-----------|------------|
| Precondition denies in enforce mode | Fires | -- |
| Session contract denies | Fires | -- |
| Limit exceeded (max_attempts, max_tool_calls) | Fires | -- |
| All checks pass | -- | Fires |
| Observe mode converts deny to allow | -- | Fires |
| Approval granted (`effect: approve`) | -- | Fires |
| Approval denied or timed out (`effect: approve`) | Fires | -- |
| Postcondition warns after execution | -- | -- |

`on_deny` does **not** fire in observe mode. In observe mode, the call is allowed
through (with a `CALL_WOULD_DENY` audit event), so `on_allow` fires instead.

## Use Cases

### Real-time alerting

React to denials immediately instead of parsing audit logs after the fact:

```python
def alert_on_deny(envelope, reason, contract_id):
    slack.post(f"DENIED {envelope.tool_name}: {reason} (contract: {contract_id})")

guard = Edictum.from_yaml("contracts.yaml", on_deny=alert_on_deny)
```

### Metrics and dashboards

Track allow/deny rates without OTel infrastructure:

```python
from prometheus_client import Counter

denied = Counter("edictum_denied_total", "Denied tool calls", ["tool", "contract"])
allowed = Counter("edictum_allowed_total", "Allowed tool calls", ["tool"])

guard = Edictum(
    contracts=[...],
    on_deny=lambda env, reason, cid: denied.labels(tool=env.tool_name, contract=cid or "").inc(),
    on_allow=lambda env: allowed.labels(tool=env.tool_name).inc(),
)
```

### Circuit breaker

Disable the agent after too many denials in a window:

```python
denial_count = 0

def circuit_breaker(envelope, reason, contract_id):
    global denial_count
    denial_count += 1
    if denial_count > 10:
        raise SystemExit("Agent stuck in denial loop -- shutting down")

guard = Edictum(contracts=[...], on_deny=circuit_breaker)
```

### Development debugging

Print denials to the console during development:

```python
guard = Edictum(
    contracts=[...],
    on_deny=lambda env, reason, cid: print(f"DENIED {env.tool_name}: {reason} [{cid}]"),
    on_allow=lambda env: print(f"ALLOWED {env.tool_name}"),
)
```

## Callback Arguments

### `on_deny`

| Argument | Type | Description |
|----------|------|-------------|
| `envelope` | `ToolEnvelope` | Full context: tool name, args, principal, side effect, environment |
| `reason` | `str` | Human-readable denial reason from the contract or limit |
| `contract_id` | `str \| None` | Name of the contract that caused the denial, or limit name (e.g. `max_attempts`) |

### `on_allow`

| Argument | Type | Description |
|----------|------|-------------|
| `envelope` | `ToolEnvelope` | Full context: tool name, args, principal, side effect, environment |

## Works With All Entry Points

The callbacks are available on every way to create an `Edictum` instance:

```python
# Constructor
guard = Edictum(contracts=[...], on_deny=my_handler, on_allow=my_handler)

# YAML
guard = Edictum.from_yaml("contracts.yaml", on_deny=my_handler, on_allow=my_handler)

# Template
guard = Edictum.from_template("file-agent", on_deny=my_handler, on_allow=my_handler)

# Merged guards (inherits from first guard)
merged = Edictum.from_multiple([guard1, guard2])
```

## All 7 Adapters

Lifecycle callbacks fire in every adapter -- they are invoked by the adapter's
pre-execution path, not the pipeline itself. This means the same `on_deny` / `on_allow`
functions work regardless of which framework you use.

## Relationship to Other Features

| Feature | Purpose | Fires when |
|---------|---------|------------|
| **`on_deny`** | React to denials in real time | Pre-execution deny (enforce mode) |
| **`on_allow`** | React to allowed calls in real time | Pre-execution allow |
| **`on_postcondition_warn`** | Remediate bad tool output | Post-execution postcondition failure |
| **`approval_backend`** | Human-in-the-loop approval for tool calls | Pre-execution when `effect: approve` fires |
| **Audit sinks** | Persistent record of all decisions | Every decision (allow, deny, execute, fail) |
| **OTel spans** | Production observability | Every decision (with full trace context) |

Lifecycle callbacks are the lightweight, zero-dependency option for users who need
real-time reactions without setting up audit sink parsing or OTel infrastructure.
For production observability at scale, use [OTel](audit/telemetry.md).
For persistent audit trails, use [audit sinks](audit/sinks.md).

## Approval Backend

The `approval_backend` parameter enables human-in-the-loop approval workflows. When a
precondition with `effect: approve` fires, the pipeline pauses and delegates to the
configured backend.

```python
from edictum import Edictum, LocalApprovalBackend

guard = Edictum.from_yaml(
    "contracts.yaml",
    approval_backend=LocalApprovalBackend(),
)
```

The `ApprovalBackend` protocol requires two async methods:

| Method | Description |
|--------|-------------|
| `request_approval(tool_name, tool_args, message, *, timeout, timeout_effect, principal)` | Creates an approval request and returns an `ApprovalRequest` |
| `wait_for_decision(approval_id, timeout)` | Blocks until the request is approved, denied, or times out. Returns an `ApprovalDecision` |

`LocalApprovalBackend` prompts on stdout and reads from stdin -- suitable for local
development and testing. For production use, implement `ApprovalBackend` with your
own backend (Slack bot, web dashboard, approval queue).

If `effect: approve` fires but no `approval_backend` is configured, the pipeline
raises `EdictumDenied` immediately.
