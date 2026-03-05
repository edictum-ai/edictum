# Google ADK

Agents built with Google ADK execute tools without contract enforcement. The `GoogleADKAdapter` connects Edictum's pipeline to ADK's plugin system and agent callbacks, enforcing contracts on every tool call across all agents managed by a runner.

## When to use this

- **Multi-agent governance**: You have a `Runner` managing multiple `LlmAgent` instances. The plugin applies contracts to ALL tool calls across ALL agents from a single registration point -- no per-agent wiring needed.
- **Tool sandboxing in ADK**: Your ADK agents use file-system or shell tools. [Sandbox contracts](../concepts/sandbox-contracts.md) restrict which paths and commands are allowed, and the adapter enforces them before the tool executes.
- **Audit trail for compliance**: You need a JSONL or OTel audit log of every tool call, including denials. The adapter emits [audit events](../audit/sinks.md) for every pipeline evaluation.
- **Live/streaming mode**: Your agents use ADK's live mode where plugins don't run. Agent callbacks provide governance where plugins cannot.

## Installation

```bash
pip install edictum google-adk
```

`google-adk` is not an Edictum dependency. Install it separately.

## Quick start -- Plugin path (recommended)

The plugin applies contracts globally to every tool call across all agents:

```python
from edictum import Edictum
from edictum.adapters.google_adk import GoogleADKAdapter
from google.adk.runners import InMemoryRunner

guard = Edictum.from_yaml("contracts.yaml")
adapter = GoogleADKAdapter(guard=guard)

runner = InMemoryRunner(
    agent=root_agent,
    app_name="my_app",
    plugins=[adapter.as_plugin()],
)
```

Every tool call through the runner is now checked against your contracts. Denied calls return `{"error": "DENIED: ..."}` to the agent.

## Agent callback integration

For per-agent scoping or live/streaming mode, use `as_agent_callbacks()`:

```python
from google.adk.agents import LlmAgent
from edictum import Edictum
from edictum.adapters.google_adk import GoogleADKAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = GoogleADKAdapter(guard=guard)

before_cb, after_cb = adapter.as_agent_callbacks()

agent = LlmAgent(
    name="researcher",
    model="gemini-2.0-flash",
    tools=[search_tool, file_tool],
    before_tool_callback=before_cb,
    after_tool_callback=after_cb,
)
```

Use this path when:

- You need different contracts per agent (create separate adapters)
- Your agents run in ADK's live/streaming mode (plugins don't run there)

## Principal resolution

The adapter resolves [principals](../concepts/principals.md) in three ways:

### Static principal

```python
from edictum import Principal

adapter = GoogleADKAdapter(
    guard=guard,
    principal=Principal(user_id="analyst", role="read-only"),
)
```

### Dynamic resolver

```python
def resolve_principal(tool_name: str, tool_input: dict) -> Principal:
    if tool_name.startswith("admin_"):
        return Principal(user_id="admin", role="admin")
    return Principal(user_id="default", role="viewer")

adapter = GoogleADKAdapter(guard=guard, principal_resolver=resolve_principal)
```

The resolver receives the tool name and input arguments. It overrides any static principal.

### Auto from ToolContext

When no principal or resolver is provided, the adapter reads `user_id` and `agent_name` from ADK's `ToolContext`:

```python
adapter = GoogleADKAdapter(guard=guard)
# Principal auto-resolved: user_id from context, adk_agent_name in claims
```

This creates a `Principal(user_id=ctx.user_id, claims={"adk_agent_name": ctx.agent_name})`. If the context has neither field, no principal is attached.

## Postcondition handling

### Redaction

When a postcondition has `effect: redact`, the `after_tool_callback` returns the redacted response as a replacement dict. The original output never reaches the agent.

### Denial

When a postcondition has `effect: deny` on a READ/PURE tool, the output is suppressed entirely. The callback returns `{"error": "DENIED: output suppressed by postcondition"}`.

### Warn callback

Both `as_plugin()` and `as_agent_callbacks()` accept an `on_postcondition_warn` callback:

```python
def handle_warn(result, findings):
    for f in findings:
        log.warning(f"Finding: {f.type} -- {f.message}")

plugin = adapter.as_plugin(on_postcondition_warn=handle_warn)
# or
before_cb, after_cb = adapter.as_agent_callbacks(on_postcondition_warn=handle_warn)
```

The callback receives the tool result and a list of `Finding` objects. It is called for side effects only -- it does not modify the response.

## Observe mode

Deploy contracts without denying tool calls to see what would happen:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
adapter = GoogleADKAdapter(guard=guard)
```

In observe mode, the adapter allows all tool calls through. `CALL_WOULD_DENY` audit events are emitted so you can review enforcement behavior before enabling it.

## Known limitations

### Live mode

Plugins are NOT invoked in ADK's live/streaming mode. Use `as_agent_callbacks()` instead for governance in live mode.

### Error callback

The plugin's `on_tool_error_callback` is observe-only -- it emits a `CALL_FAILED` audit event but does not suppress or modify errors. The original exception is always re-raised.

## API reference

### Constructor

```python
GoogleADKAdapter(
    guard: Edictum,
    session_id: str | None = None,
    principal: Principal | None = None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
)
```

| Parameter | Description |
|-----------|-------------|
| `guard` | An `Edictum` instance with loaded contracts |
| `session_id` | Session identifier for [session contracts](../concepts/contracts.md). Auto-generated UUID if omitted |
| `principal` | Static [principal](../concepts/principals.md) attached to every tool call |
| `principal_resolver` | Callable `(tool_name, tool_input) -> Principal` for dynamic resolution. Overrides static `principal` |

### `as_plugin()`

```python
adapter.as_plugin(
    on_postcondition_warn: Callable | None = None,
) -> BasePlugin
```

Returns a `BasePlugin` for `Runner(plugins=[...])`. Applies governance globally to all tools across all agents.

### `as_agent_callbacks()`

```python
adapter.as_agent_callbacks(
    on_postcondition_warn: Callable | None = None,
) -> tuple[Callable, Callable]
```

Returns `(before_tool_callback, after_tool_callback)` for `LlmAgent`. Use for per-agent scoping or live mode.

### `session_id`

```python
adapter.session_id  # str (read-only property)
```

The session ID used for session contract tracking.

### `set_principal()`

```python
adapter.set_principal(principal: Principal) -> None
```

Update the principal for subsequent tool calls. See the [mutable principal guide](../guides/mutable-principal.md) for mid-session role escalation patterns.
