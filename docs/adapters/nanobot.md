# Nanobot Adapter

The `NanobotAdapter` enforces contracts on tool calls made through
[nanobot](https://github.com/HKUDS/nanobot) agents. It provides a
`GovernedToolRegistry` that is a drop-in replacement for nanobot's
`ToolRegistry`, wrapping every tool execution with governance checks.

## When to use this

Use this adapter when your nanobot agent needs contract enforcement on tool
calls. The `GovernedToolRegistry` intercepts every `execute()` call, running
preconditions before the tool and postconditions after. Denials are returned as
`"[DENIED] reason"` strings so the LLM can see the denial and adjust its
behavior. Use `NanobotAdapter.principal_from_message()` to map nanobot's
`InboundMessage` to an Edictum `Principal` -- useful for multi-channel agents
where the same agent handles Telegram, Discord, and Slack with different
identity contexts. Use `for_subagent()` to propagate governance to child agents
created by `SubagentManager`.

## Installation

```bash
pip install edictum[yaml]
```

No additional framework dependencies are needed. The adapter uses duck typing
and does not import from nanobot at module level.

## Integration

### Basic Setup

```python
from edictum import Edictum, Principal
from edictum.adapters.nanobot import NanobotAdapter

guard = Edictum.from_yaml("contracts.yaml")
adapter = NanobotAdapter(
    guard=guard,
    session_id="session-001",
    principal=Principal(user_id="telegram:user123", role="user"),
)

# Wrap the agent's tool registry
governed_registry = adapter.wrap_registry(agent.tool_registry)

# Replace the agent's registry with the governed one
agent.tool_registry = governed_registry
```

### Direct GovernedToolRegistry

For more control, create `GovernedToolRegistry` directly:

```python
from edictum import Edictum, Principal
from edictum.adapters.nanobot import GovernedToolRegistry

guard = Edictum.from_yaml("contracts.yaml")
governed = GovernedToolRegistry(
    inner=agent.tool_registry,
    guard=guard,
    session_id="session-001",
    principal=Principal(user_id="telegram:user123", role="user"),
)
agent.tool_registry = governed
```

## Loading Contracts

Contracts can be loaded from a YAML file, the built-in nanobot template, or
defined in Python:

```python
# From a YAML contract bundle
guard = Edictum.from_yaml("contracts.yaml")

# From the built-in nanobot template
guard = Edictum.from_template("nanobot-agent")

# From Python contracts
from edictum import deny_sensitive_reads
guard = Edictum(contracts=[deny_sensitive_reads()])
```

The `nanobot-agent` template includes approval contracts for shell commands,
sub-agent spawning, cron jobs, and MCP tools, plus path-based write/edit
restrictions and session limits. See [Templates](../contracts/templates.md#nanobot-agent)
for full details.

## Deny Behavior

Nanobot's `ToolRegistry.execute()` returns strings. The adapter returns denial
messages as strings so the LLM can see the denial reason and adjust:

```python
result = await governed.execute("write_file", {"path": "/etc/passwd", "content": "..."})
# result == "[DENIED] Cannot write outside workspace: /etc/passwd"
```

In enforce mode, denied calls return `"[DENIED] {reason}"` and the tool never
executes. In observe mode, the tool executes normally and a `CALL_WOULD_DENY`
audit event is emitted.

## Principal from InboundMessage

Map nanobot's `InboundMessage` to an Edictum `Principal`:

```python
from edictum.adapters.nanobot import NanobotAdapter

# message is a nanobot InboundMessage
principal = NanobotAdapter.principal_from_message(message)
# Principal(
#     user_id="telegram:user123",
#     role="user",
#     claims={"channel": "telegram", "channel_id": "chat456"},
# )
```

Use this with a `principal_resolver` for per-message principal resolution:

```python
def resolve_principal(tool_name: str, tool_input: dict) -> Principal:
    # Look up the current message's sender
    return NanobotAdapter.principal_from_message(current_message)

governed = GovernedToolRegistry(
    inner=registry,
    guard=guard,
    principal_resolver=resolve_principal,
)
```

## Sub-agent Governance

When `SubagentManager` creates child agents, propagate governance with
`for_subagent()`:

```python
child_registry = governed.for_subagent(session_id="child-001")
# child_registry shares the same guard and contracts
# but has its own session for independent limit tracking
```

The child registry inherits the parent's principal and principal_resolver.

## Approval Workflows

Contracts with `effect: approve` trigger the approval flow. If the guard has an
`approval_backend`, the adapter requests approval and waits for a decision:

```python
from edictum import Edictum
from edictum.approval import LocalApprovalBackend

guard = Edictum.from_template(
    "nanobot-agent",
    approval_backend=LocalApprovalBackend(),
)
```

If no approval backend is configured, approval-required calls return
`"[DENIED] Approval required but no approval backend configured"`.

## Observe Mode

Deploy contracts without enforcement to see what would be denied:

```python
guard = Edictum.from_yaml("contracts.yaml", mode="observe")
governed = GovernedToolRegistry(inner=registry, guard=guard)

result = await governed.execute("exec", {"command": "rm -rf /"})
# Tool executes normally; CALL_WOULD_DENY audit event emitted
```

## Audit and Observability

Every tool call produces structured audit events:

```python
from edictum import Edictum
from edictum.audit import FileAuditSink, RedactionPolicy

redaction = RedactionPolicy()
sink = FileAuditSink("audit.jsonl", redaction=redaction)

guard = Edictum.from_yaml(
    "contracts.yaml",
    audit_sink=sink,
    redaction=redaction,
)
governed = GovernedToolRegistry(inner=registry, guard=guard)
```

Allowed calls emit `CALL_ALLOWED` + `CALL_EXECUTED`. Denied calls emit
`CALL_DENIED`. Observed denials emit `CALL_WOULD_DENY`.

## Session Tracking

The adapter tracks per-session state automatically:

- **`session_id`** groups tool calls into a session. Access it via
  `governed.session_id`.
- **Attempt count** increments before every contract evaluation.
- **Execution count** increments only when a tool actually runs.
- **Call index** is a monotonic counter within the registry instance.

## Known Limitations

- **String results only**: `GovernedToolRegistry.execute()` always returns a
  string (matching nanobot's `ToolRegistry` contract). Non-string results from
  the inner registry are converted via `str()`.

- **Full interception**: Unlike hook-based adapters, the governed registry wraps
  the entire execution flow. Postcondition `redact` and `deny` effects are
  applied before the result is returned. This means the adapter can redact
  content before the LLM sees it.
