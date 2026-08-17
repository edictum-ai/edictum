"""Real-framework Claude Agent SDK smokes (L1.1 Claude Python).

Drives a Bash sentinel through the SDK's public ``query()`` API and the
real Claude Code CLI host — the same model as edictum-ts#179
``live-sdk-hook-proof.mjs`` at 830b0f0. The CLI consumes PreToolUse
``permissionDecision`` and either runs or skips the tool. Query
in-process does not honor deny (``hook_callback`` and ``mcp_message``
tools/call are independent), so this file does not offer tools/call
itself and does not install a permissionDecision gate.

Floor = claude-agent-sdk 0.1.2; latest = 0.2.139
(edictum-schemas L1.0 pins). Missing SDK or CLI is RED: this file
claims the host. Default/parity collection ignores this file
(addopts + collect_ignore). Dedicated smoke jobs set
EDICTUM_CLAUDE_SMOKE=1 and must stay fail-closed.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import claude_agent_sdk  # noqa: F401 — claimed host; ImportError is RED
from claude_agent_sdk import ClaudeAgentOptions, query

from edictum import Decision, Edictum, precondition
from edictum.adapters.claude_agent_sdk import ADAPTER_INTERNAL_EXCEPTION_REASON, ClaudeAgentSDKAdapter
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _sdk_version() -> str:
    return getattr(claude_agent_sdk, "__version__", "unknown")


def _find_cli() -> str | None:
    which = shutil.which("claude")
    if which:
        return which
    bundled = Path(claude_agent_sdk.__file__).parent / "_bundled" / "claude"
    if bundled.is_file():
        return str(bundled)
    return None


_CLI = _find_cli()
if not _CLI:
    raise RuntimeError(
        "EDICTUM_CLAUDE_SMOKE=1 requires the Claude Code CLI; missing host for a claimed capability is RED"
    )


@precondition("other_tool")
def _block_other(tool_call):
    return Decision.fail("not the canary")


def _block_sentinel(sentinel: Path):
    @precondition("Bash")
    def _block(tool_call):
        command = tool_call.args.get("command")
        if isinstance(command, str) and "touch" in command and str(sentinel) in command:
            return Decision.fail("canary blocked")
        return Decision.pass_()

    return _block


def _sentinel_path() -> Path:
    run_id = os.environ.get("EDICTUM_LIVE_PROOF_RUN_ID") or str(os.getpid())
    return Path(f"/tmp/edictum-py-claude-sdk-hook-sentinel-{run_id}-{uuid.uuid4().hex}")


def _query_options(hooks: dict) -> ClaudeAgentOptions:
    kwargs: dict = {
        "allowed_tools": ["Bash"],
        "permission_mode": "acceptEdits",
        "setting_sources": [],
        "max_turns": 2,
        "hooks": hooks,
    }
    fields = getattr(ClaudeAgentOptions, "__dataclass_fields__", {})
    if "cli_path" in fields:
        kwargs["cli_path"] = _CLI
    return ClaudeAgentOptions(**kwargs)


async def _live_touch(hooks: dict, sentinel: Path) -> None:
    """Drive the real CLI host via query(). Do not inspect permissionDecision."""
    if sentinel.exists():
        sentinel.unlink()
    prompt = f"Use the Bash tool exactly once to run this exact command, then stop: touch {sentinel}"
    result = None
    try:
        async for message in query(prompt=prompt, options=_query_options(hooks)):
            if type(message).__name__ == "ResultMessage":
                result = message
    except Exception as exc:
        if result is None:
            raise RuntimeError(
                f"Claude CLI host path failed (claude-agent-sdk {_sdk_version()}); "
                "the smoke must drive query()+CLI, not a test-installed deny gate"
            ) from exc
    if result is None:
        raise RuntimeError(
            f"Claude CLI host path emitted no result (claude-agent-sdk {_sdk_version()}); "
            "missing host for a claimed capability is RED"
        )
    if getattr(result, "is_error", False):
        detail = getattr(result, "result", None) or getattr(result, "subtype", None) or "error"
        raise RuntimeError(
            f"Claude CLI host path failed (claude-agent-sdk {_sdk_version()}): {detail}; missing host login/API is RED"
        )


def test_blocked_call_does_not_flip_canary():
    """Sentence: a blocked call does not execute. Sentinel stays absent."""
    import asyncio

    async def _run():
        sentinel = _sentinel_path()
        sink = NullAuditSink()
        denied = {"value": False}

        def _on_block(*_args):
            denied["value"] = True

        guard = Edictum(
            environment="test",
            rules=[_block_sentinel(sentinel)],
            tools={"Bash": {"side_effect": "irreversible"}},
            backend=MemoryBackend(),
            audit_sink=sink,
            on_block=_on_block,
        )
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-block")
        try:
            await _live_touch(adapter.to_sdk_hooks(), sentinel)
        finally:
            present = sentinel.exists()
            if present:
                sentinel.unlink()
        return present, denied["value"], sink

    present, hook_denied, sink = asyncio.run(_run())
    assert present is False, f"canary ran under a block rule (claude-agent-sdk {_sdk_version()})"
    assert hook_denied is True
    blocked = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
    assert blocked, f"audit missing CALL_DENIED; got {[e.action for e in sink.events]}"
    assert any("canary blocked" in (e.reason or "") for e in blocked)


def test_allowed_call_does_flip_canary():
    """Control: no-match allow path must actually execute the tool."""
    import asyncio

    async def _run():
        sentinel = _sentinel_path()
        sink = NullAuditSink()
        denied = {"value": False}

        def _on_block(*_args):
            denied["value"] = True

        guard = Edictum(
            environment="test",
            rules=[_block_other],
            tools={"Bash": {"side_effect": "irreversible"}},
            backend=MemoryBackend(),
            audit_sink=sink,
            on_block=_on_block,
        )
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-allow")
        try:
            await _live_touch(adapter.to_sdk_hooks(), sentinel)
        finally:
            present = sentinel.exists()
            if present:
                sentinel.unlink()
        return present, denied["value"], sink

    present, hook_denied, sink = asyncio.run(_run())
    assert present is True, f"control did not flip the flag (claude-agent-sdk {_sdk_version()})"
    assert hook_denied is False
    allowed = [e for e in sink.events if e.action == AuditAction.CALL_ALLOWED]
    assert allowed, f"audit missing CALL_ALLOWED; got {[e.action for e in sink.events]}"


def test_enforce_exception_fails_closed():
    """D7: enforce + internal exception → block + fixed reason + audit; sentinel stays absent."""
    import asyncio

    async def _run():
        sentinel = _sentinel_path()
        sink = NullAuditSink()
        guard = Edictum(
            environment="test",
            rules=[_block_other],
            tools={"Bash": {"side_effect": "irreversible"}},
            backend=MemoryBackend(),
            audit_sink=sink,
        )
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-enforce-exc")

        async def explode(*args, **kwargs):
            raise RuntimeError("backend outage")

        adapter._pre_tool_use = explode
        try:
            await _live_touch(adapter.to_sdk_hooks(), sentinel)
        finally:
            present = sentinel.exists()
            if present:
                sentinel.unlink()
        return present, sink, adapter

    present, sink, adapter = asyncio.run(_run())
    assert present is False
    events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
    assert events, f"missing loud exception audit; got {[(e.action, e.reason) for e in sink.events]}"
    assert events[0].action == AuditAction.CALL_DENIED
    assert events[0].decision_source == "adapter"
    assert events[0].policy_error is True
    assert adapter._internal_exception_count == 1


def test_observe_exception_allows_loudly():
    """D7: observe + internal exception → allow + own reason code; sentinel is created."""
    import asyncio

    async def _run():
        sentinel = _sentinel_path()
        sink = NullAuditSink()
        guard = Edictum(
            environment="test",
            mode="observe",
            rules=[_block_other],
            tools={"Bash": {"side_effect": "irreversible"}},
            backend=MemoryBackend(),
            audit_sink=sink,
        )
        adapter = ClaudeAgentSDKAdapter(guard, session_id="smoke-observe-exc")

        async def explode(*args, **kwargs):
            raise RuntimeError("backend outage")

        adapter._pre_tool_use = explode
        try:
            await _live_touch(adapter.to_sdk_hooks(), sentinel)
        finally:
            present = sentinel.exists()
            if present:
                sentinel.unlink()
        return present, sink, adapter

    present, sink, adapter = asyncio.run(_run())
    assert present is True, f"observe exception must allow; sentinel stayed absent (claude-agent-sdk {_sdk_version()})"
    events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
    assert events, f"missing loud observe-exception audit; got {[(e.action, e.reason) for e in sink.events]}"
    assert events[0].action == AuditAction.CALL_WOULD_DENY
    assert events[0].decision_source == "adapter"
    assert events[0].policy_error is True
    assert adapter._internal_exception_count == 1
