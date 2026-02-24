# Dry-Run Evaluation

You need to test whether a tool call would be allowed or denied without actually executing it. The `evaluate()` and `evaluate_batch()` methods on the `Edictum` class check a tool call against all matching contracts and return a detailed result -- no tool execution, no session state changes, no audit events.

## When to use this

Read this page when you need to test whether a tool call would be allowed or denied without actually executing it. `evaluate()` is synchronous, produces no audit events, and evaluates all matching contracts exhaustively (no short-circuit on first denial). Use it for CI/CD gating, contract change impact analysis, or building approval workflows. For the full pipeline with session state and audit events, use `run()`. For command-line spot-checks, use `edictum check` or `edictum test`. See the [comparison table](#evaluate-vs-run-vs-cli) below.

---

## Quick Example

```python
from edictum import Edictum

guard = Edictum.from_yaml("contracts.yaml")

result = guard.evaluate("read_file", {"path": ".env"})
print(result.verdict)        # "deny"
print(result.deny_reasons)   # ["Sensitive file '.env' denied."]
```

---

## `evaluate()`

```python
def evaluate(
    self,
    tool_name: str,
    args: dict[str, Any],
    *,
    principal: Principal | None = None,
    output: str | None = None,
    environment: str | None = None,
) -> EvaluationResult
```

Evaluates a single tool call against all matching contracts. This method is **synchronous** -- no `await` required.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tool_name` | `str` | required | The tool being called |
| `args` | `dict[str, Any]` | required | Tool call arguments |
| `principal` | `Principal \| None` | `None` | Identity context for the call |
| `output` | `str \| None` | `None` | Simulated tool output. When provided, postconditions are evaluated against this value |
| `environment` | `str \| None` | `None` | Override the guard's default environment |

### Behavior

- **Exhaustive evaluation.** All matching contracts are evaluated. The pipeline does not short-circuit on the first denial -- you see every contract that would fire.
- **No tool execution.** The tool function is never called.
- **No session state.** Session contracts are skipped because there is no session context in a dry-run.
- **Sandbox contracts are evaluated.** Unlike session contracts, sandbox contracts are stateless and are always included in dry-run evaluation.
- **Postconditions require output.** Postconditions are only evaluated when `output` is provided. Without it, only preconditions and sandbox contracts are checked.
- **Synchronous.** Unlike `guard.run()`, this method does not require `asyncio`.

### Examples

Test a precondition:

```python
result = guard.evaluate("read_file", {"path": ".env"})
assert result.verdict == "deny"
assert result.contracts[0].contract_id == "block-dotenv"
```

Test with principal context:

```python
from edictum import Principal

result = guard.evaluate(
    "deploy_service",
    {"service": "api", "env": "production"},
    principal=Principal(role="sre", ticket_ref="JIRA-456"),
)
assert result.verdict == "allow"
```

Test postconditions by providing output:

```python
result = guard.evaluate(
    "read_file",
    {"path": "data.txt"},
    output="SSN: 123-45-6789",
)
assert result.verdict == "warn"
assert len(result.warn_reasons) > 0
```

Test with environment override:

```python
result = guard.evaluate(
    "deploy_service",
    {"service": "api"},
    environment="staging",
)
```

Test sandbox path allowlists:

```python
# Sandbox contracts are evaluated during dry-run
result = guard.evaluate("read_file", {"path": "/etc/shadow"})
assert result.verdict == "deny"

# Sandbox contracts appear in results
sandbox_results = [c for c in result.contracts if c.contract_type == "sandbox"]
assert len(sandbox_results) == 1
assert sandbox_results[0].passed is False
```

---

## `evaluate_batch()`

```python
def evaluate_batch(
    self,
    calls: list[dict[str, Any]],
) -> list[EvaluationResult]
```

Evaluates multiple tool calls. Each call is evaluated independently via `evaluate()`. This method is **synchronous**.

### Call Format

Each dict in the `calls` list accepts these keys:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `tool` | `str` | yes | Tool name |
| `args` | `dict` | no | Tool arguments (defaults to `{}`) |
| `principal` | `dict` | no | Principal as a dict with keys: `role`, `user_id`, `ticket_ref`, `claims` |
| `output` | `str \| dict` | no | Simulated output. Dicts are JSON-serialized automatically |
| `environment` | `str` | no | Environment override |

### Example

```python
results = guard.evaluate_batch([
    {"tool": "read_file", "args": {"path": ".env"}},
    {"tool": "read_file", "args": {"path": "readme.txt"}},
    {"tool": "read_file", "args": {"path": "data.txt"}, "output": "SSN: 123-45-6789"},
    {
        "tool": "deploy_service",
        "args": {"service": "api"},
        "principal": {"role": "sre", "ticket_ref": "JIRA-123"},
    },
])

assert results[0].verdict == "deny"
assert results[1].verdict == "allow"
assert results[2].verdict == "warn"
assert results[3].verdict == "allow"
```

---

## `EvaluationResult`

Returned by `evaluate()`. Contains the overall verdict and per-contract details.

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | `str` | `"allow"`, `"deny"`, or `"warn"` |
| `tool_name` | `str` | The tool name that was evaluated |
| `contracts` | `list[ContractResult]` | Per-contract results |
| `deny_reasons` | `list[str]` | Messages from failed preconditions |
| `warn_reasons` | `list[str]` | Messages from failed postconditions |
| `contracts_evaluated` | `int` | Total number of contracts checked |
| `policy_error` | `bool` | `True` if any contract raised an exception during evaluation |

The `verdict` is determined by:

- `"deny"` -- at least one precondition or sandbox contract failed (and was not in observe mode)
- `"warn"` -- no precondition or sandbox failures, but at least one postcondition failed
- `"allow"` -- all contracts passed

---

## `ContractResult`

One entry per evaluated contract. Found in `EvaluationResult.contracts`.

| Field | Type | Description |
|-------|------|-------------|
| `contract_id` | `str` | The contract's ID (from YAML `id:` or function `__name__`) |
| `contract_type` | `str` | `"precondition"`, `"postcondition"`, or `"sandbox"` |
| `passed` | `bool` | Whether the contract passed |
| `message` | `str \| None` | The contract's message (from `then.message` in YAML) |
| `tags` | `list[str]` | Tags attached to the contract |
| `observed` | `bool` | `True` if the contract is in observe mode and would have fired |
| `effect` | `str` | Postcondition effect: `"warn"`, `"redact"`, or `"deny"` |
| `policy_error` | `bool` | `True` if the contract raised an exception |

---

## `evaluate()` vs `run()` vs CLI

| | `evaluate()` | `run()` | `edictum check` / `edictum test` |
|---|---|---|---|
| Executes the tool | No | Yes | No |
| Session tracking | No | Yes | No |
| Audit events | No | Yes | No |
| Async required | No | Yes | N/A |
| Preconditions | Yes | Yes | Yes |
| Sandbox contracts | Yes | Yes | Yes |
| Postconditions | Only with `output` | Always | `--calls` only |
| Short-circuits | No (exhaustive) | Yes (first deny) | No |

Use `evaluate()` for fast, synchronous contract logic testing. Use `run()` when you need the full pipeline including session state, hooks, and audit. Use the CLI for quick spot-checks and CI pipelines.

---

## Next Steps

- [Testing contracts](guides/testing-contracts.md) -- YAML test cases, CI integration, and testing patterns
- [CLI reference](cli.md) -- `edictum check` and `edictum test` commands
- [Contracts](concepts/contracts.md) -- the four contract types
