"""Tests for CrewAIAdapter."""

from __future__ import annotations

from types import SimpleNamespace

from edictum import Decision, Edictum, precondition
from edictum.adapters.crewai import CrewAIAdapter
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


def _make_before_context(tool_name: str = "TestTool", tool_input: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        tool_name=tool_name,
        tool_input=tool_input or {},
        agent=None,
        task=None,
    )


def _make_after_context(
    tool_name: str = "TestTool",
    tool_input: dict | None = None,
    tool_result: str = "ok",
) -> SimpleNamespace:
    return SimpleNamespace(
        tool_name=tool_name,
        tool_input=tool_input or {},
        tool_result=tool_result,
        agent=None,
        task=None,
    )


class TestCrewAIAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard, session_id="test-session")
        result = await adapter._before_hook(_make_before_context())
        assert result is None

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        sink = NullAuditSink()
        guard = make_guard(rules=[always_deny], audit_sink=sink)
        adapter = CrewAIAdapter(guard)
        result = await adapter._before_hook(_make_before_context())
        assert isinstance(result, str) and "DENIED" in result
        # Verify audit contains the reason
        deny_events = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(deny_events) == 1
        assert deny_events[0].reason == "denied"

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)

        # Before hook stores pending
        await adapter._before_hook(_make_before_context())
        assert adapter._pending_envelope is not None
        assert adapter._pending_span is not None

        # After hook clears pending
        await adapter._after_hook(_make_after_context())
        assert adapter._pending_envelope is None
        assert adapter._pending_span is None

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("no")

        guard = make_guard(rules=[always_deny])
        adapter = CrewAIAdapter(guard)

        await adapter._before_hook(_make_before_context())
        assert adapter._pending_envelope is None
        assert adapter._pending_span is None

    async def test_post_without_pending_returns_empty(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)
        # After hook with no pending state is a no-op
        result = await adapter._after_hook(_make_after_context(tool_name="unknown"))
        assert result is None

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)

        await adapter._before_hook(_make_before_context(tool_name="T1"))
        # Clear pending so next before can proceed cleanly
        await adapter._after_hook(_make_after_context(tool_name="T1"))
        await adapter._before_hook(_make_before_context(tool_name="T2"))
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would be denied")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        adapter = CrewAIAdapter(guard)

        result = await adapter._before_hook(_make_before_context())
        # Should allow through (None)
        assert result is None
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert adapter._pending_envelope is not None

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = CrewAIAdapter(guard)

        await adapter._before_hook(_make_before_context(tool_name="T"))
        await adapter._after_hook(_make_after_context(tool_name="T"))

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)

        assert adapter._check_tool_success("TestTool", None) is True
        assert adapter._check_tool_success("TestTool", "ok") is True
        assert adapter._check_tool_success("TestTool", "Error: something failed") is False
        assert adapter._check_tool_success("TestTool", "fatal: not a git repo") is False

    async def test_public_api_returns_framework_native(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard)
        # register() requires crewai, but _before_hook/_after_hook are exposed
        assert callable(adapter._before_hook)
        assert callable(adapter._after_hook)
        assert callable(adapter.register)


class TestCrewAIRegisterRegression:
    """Regression tests for register() bound method fix (v0.5.2).

    The adapter previously used CrewAI's @before_tool_call/@after_tool_call
    decorators which called setattr(func, marker, True) — failing on bound
    methods. Now uses register_before_tool_call_hook()/register_after_tool_call_hook()
    with plain functions.
    """

    async def test_register_succeeds(self):
        """register() should not raise on bound method setattr."""
        import sys
        from types import ModuleType
        from unittest.mock import MagicMock

        # Mock the crewai.hooks.tool_hooks module
        mock_hooks = ModuleType("crewai.hooks.tool_hooks")
        mock_hooks.register_before_tool_call_hook = MagicMock()
        mock_hooks.register_after_tool_call_hook = MagicMock()

        # Also ensure crewai and crewai.hooks exist in sys.modules
        mock_crewai = sys.modules.get("crewai") or ModuleType("crewai")
        mock_crewai_hooks = sys.modules.get("crewai.hooks") or ModuleType("crewai.hooks")

        orig_crewai = sys.modules.get("crewai")
        orig_hooks_parent = sys.modules.get("crewai.hooks")
        orig_hooks = sys.modules.get("crewai.hooks.tool_hooks")

        sys.modules["crewai"] = mock_crewai
        sys.modules["crewai.hooks"] = mock_crewai_hooks
        sys.modules["crewai.hooks.tool_hooks"] = mock_hooks

        try:
            guard = make_guard()
            adapter = CrewAIAdapter(guard)
            # This should NOT raise (previously failed with setattr on bound methods)
            adapter.register()

            # Verify hooks were registered
            assert mock_hooks.register_before_tool_call_hook.called
            assert mock_hooks.register_after_tool_call_hook.called
        finally:
            if orig_crewai is not None:
                sys.modules["crewai"] = orig_crewai
            else:
                sys.modules.pop("crewai", None)
            if orig_hooks_parent is not None:
                sys.modules["crewai.hooks"] = orig_hooks_parent
            else:
                sys.modules.pop("crewai.hooks", None)
            if orig_hooks is not None:
                sys.modules["crewai.hooks.tool_hooks"] = orig_hooks
            else:
                sys.modules.pop("crewai.hooks.tool_hooks", None)

    async def test_register_with_postcondition_callback(self):
        """register() should accept on_postcondition_warn callback."""
        import sys
        from types import ModuleType
        from unittest.mock import MagicMock

        mock_hooks = ModuleType("crewai.hooks.tool_hooks")
        mock_hooks.register_before_tool_call_hook = MagicMock()
        mock_hooks.register_after_tool_call_hook = MagicMock()

        mock_crewai = sys.modules.get("crewai") or ModuleType("crewai")
        mock_crewai_hooks = sys.modules.get("crewai.hooks") or ModuleType("crewai.hooks")

        orig_crewai = sys.modules.get("crewai")
        orig_hooks_parent = sys.modules.get("crewai.hooks")
        orig_hooks = sys.modules.get("crewai.hooks.tool_hooks")

        sys.modules["crewai"] = mock_crewai
        sys.modules["crewai.hooks"] = mock_crewai_hooks
        sys.modules["crewai.hooks.tool_hooks"] = mock_hooks

        try:
            callback = MagicMock()
            guard = make_guard()
            adapter = CrewAIAdapter(guard)
            adapter.register(on_postcondition_warn=callback)

            assert adapter._on_postcondition_warn is callback
        finally:
            if orig_crewai is not None:
                sys.modules["crewai"] = orig_crewai
            else:
                sys.modules.pop("crewai", None)
            if orig_hooks_parent is not None:
                sys.modules["crewai.hooks"] = orig_hooks_parent
            else:
                sys.modules.pop("crewai.hooks", None)
            if orig_hooks is not None:
                sys.modules["crewai.hooks.tool_hooks"] = orig_hooks
            else:
                sys.modules.pop("crewai.hooks.tool_hooks", None)


class TestCrewAIAsyncBridge:
    """Tests for the sync-to-async bridge used in register() hooks."""

    async def test_before_hook_works_with_active_event_loop(self):
        """Hooks should work when called from within an active event loop.

        CrewAI may call hooks from sync code while an asyncio loop is running.
        The bridge must spawn a worker thread to avoid blocking the caller.
        """
        import sys
        from types import ModuleType

        mock_hooks = ModuleType("crewai.hooks.tool_hooks")

        captured_before = None
        captured_after = None

        def capture_before(fn):
            nonlocal captured_before
            captured_before = fn

        def capture_after(fn):
            nonlocal captured_after
            captured_after = fn

        mock_hooks.register_before_tool_call_hook = capture_before
        mock_hooks.register_after_tool_call_hook = capture_after

        mock_crewai = sys.modules.get("crewai") or ModuleType("crewai")
        mock_crewai_hooks = sys.modules.get("crewai.hooks") or ModuleType("crewai.hooks")

        orig_crewai = sys.modules.get("crewai")
        orig_hooks_parent = sys.modules.get("crewai.hooks")
        orig_hooks = sys.modules.get("crewai.hooks.tool_hooks")

        sys.modules["crewai"] = mock_crewai
        sys.modules["crewai.hooks"] = mock_crewai_hooks
        sys.modules["crewai.hooks.tool_hooks"] = mock_hooks

        try:
            guard = make_guard()
            adapter = CrewAIAdapter(guard)
            adapter.register()

            assert captured_before is not None
            assert captured_after is not None

            # Call the before hook — we are inside an active event loop
            # (pytest-asyncio runs this in an event loop), so the bridge
            # must use the ThreadPoolExecutor path.
            context = _make_before_context(tool_name="Test Tool")
            result = captured_before(context)

            # Should allow (None) — no denying rules
            assert result is None
        finally:
            if orig_crewai is not None:
                sys.modules["crewai"] = orig_crewai
            else:
                sys.modules.pop("crewai", None)
            if orig_hooks_parent is not None:
                sys.modules["crewai.hooks"] = orig_hooks_parent
            else:
                sys.modules.pop("crewai.hooks", None)
            if orig_hooks is not None:
                sys.modules["crewai.hooks.tool_hooks"] = orig_hooks
            else:
                sys.modules.pop("crewai.hooks.tool_hooks", None)


class TestCrewAIToolNameNormalization:
    """Regression tests for tool name normalization (v0.5.2)."""

    def test_normalize_human_readable_names(self):
        assert CrewAIAdapter._normalize_tool_name("Search Documents") == "search_documents"
        assert CrewAIAdapter._normalize_tool_name("Update Record") == "update_record"

    def test_normalize_already_snake_case(self):
        assert CrewAIAdapter._normalize_tool_name("search_documents") == "search_documents"

    def test_normalize_single_word(self):
        assert CrewAIAdapter._normalize_tool_name("Search") == "search"

    def test_normalize_hyphens(self):
        assert CrewAIAdapter._normalize_tool_name("Read-Database") == "read_database"
        assert CrewAIAdapter._normalize_tool_name("my-tool-name") == "my_tool_name"

    def test_normalize_mixed_separators(self):
        assert CrewAIAdapter._normalize_tool_name("Search - Documents  Here") == "search_documents_here"
