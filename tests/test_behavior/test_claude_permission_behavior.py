"""Behavior coverage for ClaudeAgentSDKAdapter.wrap_can_use_tool.

Public path only: the callback parameter is exercised through wrap_can_use_tool.
"""

from __future__ import annotations

import pytest

from edictum import Edictum
from edictum.adapters.claude_agent_sdk import (
    _INPUT_REPLACEMENT_REASON,
    _PERMISSION_BOUNDARY_REASON,
    ClaudeAgentSDKAdapter,
)
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


def _pre_input(tool_name="canary", tool_input=None, tool_use_id="tu-1"):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {} if tool_input is None else tool_input,
        "tool_use_id": tool_use_id,
    }


async def _govern(adapter, tool_input=None, tool_use_id="tu-1"):
    pre = adapter.to_sdk_hooks()["PreToolUse"][0].hooks[0]
    result = await pre(_pre_input(tool_input=tool_input, tool_use_id=tool_use_id), tool_use_id, {"signal": None})
    assert result == {}
    return type("Ctx", (), {"tool_use_id": tool_use_id})()


class TestWrapCanUseToolCallback:
    """Supplying callback must change the observable permission result."""

    async def test_callback_allow_versus_block(self):
        async def allow_cb(_tool_name, _tool_input, _context):
            return {"behavior": "allow"}

        async def block_cb(_tool_name, _tool_input, _context):
            return {"behavior": "deny", "message": "callback blocked"}

        async def run(callback):
            adapter = ClaudeAgentSDKAdapter(_make_guard())
            ctx = await _govern(adapter, tool_input={"payload": "ping"})
            wrapped = adapter.wrap_can_use_tool(callback)
            return await wrapped("canary", {"payload": "ping"}, ctx)

        allowed = await run(allow_cb)
        blocked = await run(block_cb)
        assert allowed.behavior == "allow"
        assert blocked.behavior == "deny"
        assert blocked.message == "callback blocked"


class TestWrapCanUseToolSecurityBoundaries:
    """Permission-boundary bypass attempts must stay blocked on the public path."""

    @pytest.mark.security
    async def test_wrap_blocks_input_replacement(self):
        adapter = ClaudeAgentSDKAdapter(_make_guard())
        ctx = await _govern(adapter, tool_input={"payload": "ping"})

        async def allow_cb(_tool_name, _tool_input, _context):
            return {"behavior": "allow"}

        result = await adapter.wrap_can_use_tool(allow_cb)("canary", {"payload": "pwn"}, ctx)
        assert result.behavior == "deny"
        assert result.message == _INPUT_REPLACEMENT_REASON

    @pytest.mark.security
    async def test_wrap_blocks_updated_input(self):
        adapter = ClaudeAgentSDKAdapter(_make_guard())
        ctx = await _govern(adapter, tool_input={"payload": "ping"})

        async def rewrite_cb(_tool_name, _tool_input, _context):
            return {"behavior": "allow", "updated_input": {"payload": "pwn"}}

        result = await adapter.wrap_can_use_tool(rewrite_cb)("canary", {"payload": "ping"}, ctx)
        assert result.behavior == "deny"
        assert result.message == _PERMISSION_BOUNDARY_REASON

    @pytest.mark.security
    async def test_wrap_clears_pending_when_context_id_unhashable(self):
        """Unhashable tool_use_id must still match and clear the governed pending entry."""
        adapter = ClaudeAgentSDKAdapter(_make_guard())
        await _govern(adapter, tool_input={"payload": "ping"})
        assert "tu-1" in adapter._pending

        async def block_cb(_tool_name, _tool_input, _context):
            return {"behavior": "deny", "message": "callback blocked"}

        result = await adapter.wrap_can_use_tool(block_cb)(
            "canary",
            {"payload": "ping"},
            type("Ctx", (), {"tool_use_id": ["tu-1"]})(),
        )
        assert result.behavior == "deny"
        assert result.message == "callback blocked"
        assert "tu-1" not in adapter._pending
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}
