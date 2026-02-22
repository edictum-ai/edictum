# Custom Tool Success Detection

The default heuristic for detecting tool failures only catches two patterns: strings starting with `"Error:"` or `"fatal:"`, and dicts with `{"is_error": true}`. If your tools return errors differently, Edictum misclassifies failures as successes — and session contracts that depend on accurate counts enforce at the wrong time.

```python
from edictum import Edictum

guard = Edictum.from_yaml(
    "contracts.yaml",
    success_check=lambda tool_name, result: not (
        isinstance(result, dict) and result.get("status", 200) >= 400
    ),
)
```

## When to use this

**REST API tools** — Your agent calls REST endpoints that return `{"status": 500, "error": "..."}` on failure. The default heuristic does not catch this — it only checks `startswith("Error:")`. A custom checker inspects the HTTP status code:

```python
def http_success_check(tool_name, result):
    if isinstance(result, dict) and result.get("status", 200) >= 400:
        return False
    return True
```

**Database tools** — Your DB query tool returns empty results (not an error), but your domain considers "no rows found" a failure for certain operations. Custom checker lets you define success per your domain logic:

```python
def db_success_check(tool_name, result):
    if tool_name == "query_users" and isinstance(result, dict):
        if not result.get("rows"):
            return False
    return True
```

**Tool-specific error formats** — Your codebase has tools that return `{"ok": false, "message": "..."}`, tools that return traceback strings, and tools that return `null` on failure. One `success_check` function normalizes all of them instead of hoping the heuristic catches each format:

```python
def unified_success_check(tool_name, result):
    if result is None:
        return False
    if isinstance(result, dict) and result.get("ok") is False:
        return False
    if isinstance(result, str) and "Traceback" in result:
        return False
    return True
```

**Session count accuracy** — Wrong `tool_success` values cascade: if a failed tool call is counted as successful, session contracts tracking "max 3 successful executions" count wrong, leading to premature or delayed enforcement.

### Who benefits

- **Teams with custom tool implementations** — define what "success" means for their tools
- **Anyone using session contracts** — accurate execution counts depend on correct success detection
- **Platform teams** — centralize error detection logic instead of hoping each tool follows the `"Error:"` convention

### How this relates to other features

`success_check` feeds INTO session contracts — it determines the counts that session contracts enforce against. It does not overlap with `on_deny` (governance decisions) or postconditions (output validation). Think of it as the input signal for session tracking accuracy.

## How it works

The `success_check` parameter accepts a callable with the signature:

```python
def success_check(tool_name: str, result: Any) -> bool:
    ...
```

- `tool_name`: the name of the tool that was called
- `result`: the value returned by the tool
- Returns `True` if the tool call succeeded, `False` if it failed

When provided, it replaces the default heuristic in all 7 framework adapters and in `Edictum.run()`. When not provided, the default heuristic applies unchanged.

The callable is passed through all factory methods:

```python
# Constructor
guard = Edictum(success_check=my_checker, ...)

# YAML
guard = Edictum.from_yaml("contracts.yaml", success_check=my_checker)

# YAML string
guard = Edictum.from_yaml_string(yaml_content, success_check=my_checker)

# Template
guard = Edictum.from_template("file-agent", success_check=my_checker)

# Merged guards — uses the first guard's success_check
merged = Edictum.from_multiple([guard1, guard2])
```

## Default heuristic

When no `success_check` is provided, the default heuristic checks:

1. `result` is `None` → success
2. `result` is a `dict` with `is_error` truthy → failure
3. `result` is a `str` starting with `"Error:"` or `"fatal:"` → failure
4. Everything else → success

Some adapters extend this with framework-specific checks (e.g., Semantic Kernel checks `FunctionResult.metadata.error`). A custom `success_check` replaces all of this — including the framework-specific checks.

## Next steps

- [Session contracts](../concepts/contracts.md) — how execution counts affect enforcement
- [Observability](observability.md) — audit events include `tool_success` for monitoring
- [Adapter comparison](adapter-comparison.md) — how each adapter handles tool results
