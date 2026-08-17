"""Real-framework Claude Agent SDK smokes (L1.1 Claude Python).

Drives a canary through the SDK's own hook-callback + in-process MCP
execution path (``Query._handle_control_request``), not ``guard.run()``
and not a direct call of ``adapter._pre_tool_use``. The canary body runs
only inside ``Query._handle_sdk_mcp_request`` (tools/call). The host
honors the control_response the SDK wrote after PreToolUse: a deny does
not send tools/call. Only the LLM / CLI binary is absent.

Floor = claude-agent-sdk 0.1.2; latest = 0.2.139
(edictum-schemas L1.0 pins). Missing SDK is RED: this file claims the host.
Default/parity collection ignores this file (addopts + collect_ignore).
Dedicated smoke jobs set EDICTUM_CLAUDE_SMOKE=1 and must stay fail-closed.
"""

from __future__ import annotations

import json

import claude_agent_sdk  # noqa: F401 — claimed host; ImportError is RED
import pytest
from claude_agent_sdk._internal.query import Query
from mcp.types import CallToolRequest

from edictum import Decision, Edictum, precondition
from edictum.adapters.claude_agent_sdk import ADAPTER_INTERNAL_EXCEPTION_REASON, ClaudeAgentSDKAdapter
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

_CANARY_SERVER = "canary-host"


@precondition("canary")
def _block_canary(tool_call):
    return Decision.fail("canary blocked")


@precondition("other_tool")
def _block_other(tool_call):
    return Decision.fail("not the canary")


def _sdk_version() -> str:
    return getattr(claude_agent_sdk, "__version__", "unknown")


class _RecordingTransport:
    """Minimal transport so Query can write control responses."""

    def __init__(self) -> None:
        self.writes: list[str] = []

    async def connect(self) -> None:
        return None

    async def write(self, data: str) -> None:
        self.writes.append(data)

    async def read_messages(self):
        if False:
            yield {}

    async def close(self) -> None:
        return None

    def is_ready(self) -> bool:
        return True

    async def end_input(self) -> None:
        return None


class _CanaryServer:
    """Minimal in-process MCP server Query._handle_sdk_mcp_request can invoke.

    Floor create_sdk_mcp_server is incompatible with current mcp.Server
    (no list_tools). Query still executes tools via request_handlers[CallToolRequest].
    """

    def __init__(self, flag: dict[str, bool]) -> None:
        self.name = _CANARY_SERVER
        self.version = "1.0.0"
        self._flag = flag

        async def _call(_request):
            self._flag["flipped"] = True
            item = type("Text", (), {"type": "text", "text": "flipped"})()
            root = type("Root", (), {"content": [item], "is_error": False, "isError": False})()
            return type("Result", (), {"root": root})()

        self.request_handlers = {CallToolRequest: _call}


def _make_canary() -> tuple[dict[str, bool], dict]:
    """In-process MCP canary. The handler is the only place the flag flips."""
    flag = {"flipped": False}
    return flag, {_CANARY_SERVER: _CanaryServer(flag)}


def _register_hooks(query: Query, hooks: dict) -> dict[str, str]:
    """Register matcher callbacks the same way Query.initialize does."""
    ids: dict[str, str] = {}
    for event, matchers in hooks.items():
        for matcher in matchers:
            for callback in matcher.hooks:
                callback_id = f"hook_{query.next_callback_id}"
                query.next_callback_id += 1
                query.hook_callbacks[callback_id] = callback
                ids[event] = callback_id
    return ids


def _make_query(hooks: dict, sdk_mcp_servers: dict | None = None) -> tuple[Query, _RecordingTransport]:
    transport = _RecordingTransport()
    internal = {}
    for event, matchers in hooks.items():
        internal[event] = [{"matcher": getattr(m, "matcher", None), "hooks": m.hooks} for m in matchers]
    query = Query(
        transport=transport,
        is_streaming_mode=True,
        hooks=internal,
        sdk_mcp_servers=sdk_mcp_servers or {},
    )
    return query, transport


async def _dispatch_pre(
    query: Query, transport: _RecordingTransport, callback_id: str, tool_input: dict, tool_use_id: str = "tu-1"
) -> dict:
    request = {
        "type": "control_request",
        "request_id": f"req-{tool_use_id}",
        "request": {
            "subtype": "hook_callback",
            "callback_id": callback_id,
            "input": {
                "hook_event_name": "PreToolUse",
                "tool_name": "canary",
                "tool_input": tool_input,
                "tool_use_id": tool_use_id,
            },
            "tool_use_id": tool_use_id,
        },
    }
    await query._handle_control_request(request)
    assert transport.writes, "SDK Query wrote no control response"
    payload = json.loads(transport.writes[-1])
    response = payload.get("response") or {}
    assert response.get("subtype") != "error", f"SDK hook dispatcher error: {response}"
    return response.get("response") or {}


async def _dispatch_mcp_call(
    query: Query, transport: _RecordingTransport, tool_input: dict, tool_use_id: str = "tu-1"
) -> dict:
    """Execute the canary through Query's in-process MCP tools/call path."""
    request = {
        "type": "control_request",
        "request_id": f"mcp-{tool_use_id}",
        "request": {
            "subtype": "mcp_message",
            "server_name": _CANARY_SERVER,
            "message": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "canary", "arguments": tool_input},
            },
        },
    }
    await query._handle_control_request(request)
    assert transport.writes, "SDK Query wrote no MCP control response"
    payload = json.loads(transport.writes[-1])
    response = payload.get("response") or {}
    assert response.get("subtype") != "error", f"SDK MCP dispatcher error: {response}"
    return response.get("response") or {}


def _is_host_block(hook_output: dict) -> bool:
    specific = hook_output.get("hookSpecificOutput") or {}
    return specific.get("permissionDecision") == "deny"


async def _host_run_canary(
    query: Query,
    transport: _RecordingTransport,
    hook_output: dict,
    tool_input: dict,
    tool_use_id: str = "tu-1",
) -> None:
    """Honor the control_response the SDK wrote, then run the tool via Query.

    Deny does not send tools/call. Anything else executes the canary inside
    Query._handle_sdk_mcp_request. The test never flips the flag itself.
    If the host ignores the decision and always calls the tool, the block
    test fails.
    """
    if _is_host_block(hook_output):
        return
    await _dispatch_mcp_call(query, transport, tool_input, tool_use_id)


def test_blocked_call_does_not_flip_canary():
    """Sentence: a blocked call does not execute. Flag stays down."""
    import asyncio

    async def _run():
        sink = NullAuditSink()
        guard = Edictum(environment="test", rules=[_block_canary], backend=MemoryBackend(), audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-block")
        flag, servers = _make_canary()
        hooks = adapter.to_sdk_hooks()
        query, transport = _make_query(hooks, servers)
        ids = _register_hooks(query, hooks)
        tool_input = {"payload": "ping"}
        output = await _dispatch_pre(query, transport, ids["PreToolUse"], tool_input)
        await _host_run_canary(query, transport, output, tool_input)
        return flag, output, sink

    flag, output, sink = asyncio.run(_run())
    assert flag["flipped"] is False, f"canary ran under a block rule (claude-agent-sdk {_sdk_version()})"
    assert _is_host_block(output), f"framework did not surface a block: {output!r}"
    reason = (output.get("hookSpecificOutput") or {}).get("permissionDecisionReason") or ""
    assert "canary blocked" in reason
    blocked = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
    assert blocked, f"audit missing CALL_DENIED; got {[e.action for e in sink.events]}"
    assert any("canary blocked" in (e.reason or "") for e in blocked)


def test_allowed_call_does_flip_canary():
    """Control: no-match allow path must actually execute the tool."""
    import asyncio

    async def _run():
        sink = NullAuditSink()
        guard = Edictum(environment="test", rules=[_block_other], backend=MemoryBackend(), audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-allow")
        flag, servers = _make_canary()
        hooks = adapter.to_sdk_hooks()
        query, transport = _make_query(hooks, servers)
        ids = _register_hooks(query, hooks)
        tool_input = {"payload": "ping"}
        output = await _dispatch_pre(query, transport, ids["PreToolUse"], tool_input)
        await _host_run_canary(query, transport, output, tool_input)
        return flag, output, sink

    flag, output, sink = asyncio.run(_run())
    assert flag["flipped"] is True, (
        f"control did not flip the flag (claude-agent-sdk {_sdk_version()}); output={output!r}"
    )
    assert not _is_host_block(output)
    allowed = [e for e in sink.events if e.action == AuditAction.CALL_ALLOWED]
    assert allowed, f"audit missing CALL_ALLOWED; got {[e.action for e in sink.events]}"


def test_enforce_exception_fails_closed():
    """D7: enforce + internal exception → block + fixed reason + audit; flag stays down."""
    import asyncio

    async def _run():
        sink = NullAuditSink()
        guard = Edictum(environment="test", rules=[_block_other], backend=MemoryBackend(), audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-enforce-exc")

        async def explode(*args, **kwargs):
            raise RuntimeError("backend outage")

        adapter._pre_tool_use = explode
        flag, servers = _make_canary()
        hooks = adapter.to_sdk_hooks()
        query, transport = _make_query(hooks, servers)
        ids = _register_hooks(query, hooks)
        tool_input = {"payload": "ping"}
        output = await _dispatch_pre(query, transport, ids["PreToolUse"], tool_input)
        await _host_run_canary(query, transport, output, tool_input)
        return flag, output, sink, adapter

    flag, output, sink, adapter = asyncio.run(_run())
    assert flag["flipped"] is False
    assert _is_host_block(output), f"enforce exception did not surface a block: {output!r}"
    events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
    assert events, f"missing loud exception audit; got {[(e.action, e.reason) for e in sink.events]}"
    assert events[0].action == AuditAction.CALL_DENIED
    assert events[0].decision_source == "adapter"
    assert events[0].policy_error is True
    assert adapter._internal_exception_count == 1


def test_observe_exception_allows_loudly():
    """D7: observe + internal exception → allow + own reason code; flag flips."""
    import asyncio

    async def _run():
        sink = NullAuditSink()
        guard = Edictum(
            environment="test",
            mode="observe",
            rules=[_block_other],
            backend=MemoryBackend(),
            audit_sink=sink,
        )
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-observe-exc")

        async def explode(*args, **kwargs):
            raise RuntimeError("backend outage")

        adapter._pre_tool_use = explode
        flag, servers = _make_canary()
        hooks = adapter.to_sdk_hooks()
        query, transport = _make_query(hooks, servers)
        ids = _register_hooks(query, hooks)
        tool_input = {"payload": "ping"}
        output = await _dispatch_pre(query, transport, ids["PreToolUse"], tool_input)
        await _host_run_canary(query, transport, output, tool_input)
        return flag, output, sink, adapter

    flag, output, sink, adapter = asyncio.run(_run())
    assert flag["flipped"] is True, (
        f"observe exception must allow; flag stayed down (claude-agent-sdk {_sdk_version()}); output={output!r}"
    )
    events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
    assert events, f"missing loud observe-exception audit; got {[(e.action, e.reason) for e in sink.events]}"
    assert events[0].action == AuditAction.CALL_WOULD_DENY
    assert events[0].decision_source == "adapter"
    assert events[0].policy_error is True
    assert adapter._internal_exception_count == 1


@pytest.mark.security
def test_input_replacement_does_not_flip_canary():
    """Fail-closed: a replacement after PreToolUse does not execute."""
    import asyncio

    async def _run():
        sink = NullAuditSink()
        guard = Edictum(environment="test", rules=[_block_other], backend=MemoryBackend(), audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-replace")
        flag, servers = _make_canary()
        hooks = adapter.to_sdk_hooks()
        query, transport = _make_query(hooks, servers)
        ids = _register_hooks(query, hooks)
        first = await _dispatch_pre(query, transport, ids["PreToolUse"], {"payload": "ping"}, "tu-1")
        assert not _is_host_block(first)
        second = await _dispatch_pre(query, transport, ids["PreToolUse"], {"payload": "pwn"}, "tu-1")
        await _host_run_canary(query, transport, second, {"payload": "pwn"}, "tu-1")
        return flag, second

    flag, second = asyncio.run(_run())
    assert flag["flipped"] is False, f"replacement executed (claude-agent-sdk {_sdk_version()})"
    assert _is_host_block(second)
