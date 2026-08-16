"""Tests for CrewAIAdapter."""

from __future__ import annotations

from types import SimpleNamespace

from edictum import Decision, Edictum, precondition
from edictum.adapters.crewai import ADAPTER_UNKNOWN_TOOL_NAME, CrewAIAdapter
from edictum.audit import AuditAction
from edictum.envelope import Principal
from edictum.pipeline import PreDecision
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


def _capture_registered_hooks(adapter: CrewAIAdapter):
    """Register adapter hooks against a mocked CrewAI hook module."""
    import sys
    from contextlib import contextmanager
    from types import ModuleType

    @contextmanager
    def _ctx():
        mock_hooks = ModuleType("crewai.hooks.tool_hooks")
        captured: dict = {}

        def capture_before(fn):
            captured["before"] = fn

        def capture_after(fn):
            captured["after"] = fn

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
            adapter.register()
            yield captured["before"], captured["after"]
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

    return _ctx()


class TestCrewAIAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = CrewAIAdapter(guard, session_id="test-session")
        result = await adapter._before_hook(_make_before_context())
        assert result is None

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("blocked")

        sink = NullAuditSink()
        guard = make_guard(rules=[always_deny], audit_sink=sink)
        adapter = CrewAIAdapter(guard)
        result = await adapter._before_hook(_make_before_context())
        # CrewAI's executor blocks only on exactly False; any other value
        # (including a reason string) lets the tool run.
        assert result is False
        # Verify audit contains the reason
        deny_events = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(deny_events) == 1
        assert deny_events[0].reason == "blocked"

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
            return Decision.fail("would be blocked")

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

    async def test_observe_ask_does_not_ping_approval(self):
        from edictum.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus

        class Spy:
            def __init__(self):
                self.requests = []

            async def request_approval(self, **kwargs):
                self.requests.append(kwargs)
                return ApprovalRequest(
                    approval_id="spy",
                    tool_name=kwargs.get("tool_name", ""),
                    tool_args=kwargs.get("tool_args") or {},
                    message=kwargs.get("message") or "",
                    timeout=30,
                )

            async def wait_for_decision(self, approval_id, timeout=None):
                return ApprovalDecision(approved=False, reason="spy", status=ApprovalStatus.DENIED)

        yaml_content = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: observe-ask
defaults:
  mode: observe
rules:
  - id: ask-test
    type: pre
    tool: TestTool
    when:
      args.payload: {equals: ping}
    then:
      action: ask
      message: would ask
"""
        spy = Spy()
        sink = NullAuditSink()
        guard = Edictum.from_yaml_string(
            yaml_content, backend=MemoryBackend(), audit_sink=sink, approval_backend=spy, mode="observe"
        )
        adapter = CrewAIAdapter(guard)
        result = await adapter._before_hook(_make_before_context(tool_input={"payload": "ping"}))
        assert result is None
        assert spy.requests == []
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)

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


class TestCrewAIInternalExceptionTelemetry:
    """D7: a dead audit sink must not drop the exception counter/span."""

    async def test_internal_exception_records_telemetry_when_audit_sink_fails(self):
        """Revert-red: recording telemetry after emit loses the signal.

        The register() wrapper swallows a second sink failure, so
        ``record_adapter_exception`` must run before the awaited emit.
        """

        class FailingSink:
            async def emit(self, event):
                raise RuntimeError("audit sink down")

        guard = make_guard(audit_sink=FailingSink())
        adapter = CrewAIAdapter(guard, session_id="crewai-sink-fail")
        recorded: list[tuple[str, str]] = []

        def capture(tool_name: str, mode: str) -> None:
            recorded.append((tool_name, mode))

        guard.telemetry.record_adapter_exception = capture

        raised: Exception | None = None
        try:
            await adapter._on_internal_exception("Search Documents")
        except Exception as exc:
            raised = exc

        assert raised is not None
        leaves = list(getattr(raised, "exceptions", (raised,)))
        assert any("audit sink down" in str(exc) for exc in leaves)
        assert recorded == [("search_documents", guard.mode)]
        assert adapter._internal_exception_count == 1

    async def test_internal_exception_audit_includes_policy_version(self):
        """Exception audits must carry policy_version like other adapter audit paths."""
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink, policy_version="pv-test-1")
        adapter = CrewAIAdapter(guard, session_id="crewai-exc-pv")

        await adapter._on_internal_exception("Search Documents")

        assert sink.events, "expected an exception audit event"
        event = sink.events[-1]
        assert event.reason == "adapter_internal_exception"
        assert event.policy_version == "pv-test-1"
        assert event.policy_version is not None

    async def test_internal_exception_replaces_invalid_tool_name(self):
        """Revert-red: exception path must not republish control chars or path separators."""
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = CrewAIAdapter(guard, session_id="crewai-exc-name")
        recorded: list[str] = []

        def capture(tool_name: str, mode: str) -> None:
            recorded.append(tool_name)

        guard.telemetry.record_adapter_exception = capture

        await adapter._on_internal_exception("foo/bar")
        await adapter._on_internal_exception("tool\\name")
        await adapter._on_internal_exception("bad\x00name")
        await adapter._on_internal_exception("Search Documents")

        assert recorded == [
            ADAPTER_UNKNOWN_TOOL_NAME,
            ADAPTER_UNKNOWN_TOOL_NAME,
            ADAPTER_UNKNOWN_TOOL_NAME,
            "search_documents",
        ]
        assert [e.tool_name for e in sink.events] == recorded
        for name in recorded[:3]:
            assert "/" not in name
            assert "\\" not in name
            assert "\x00" not in name


class TestCrewAIObserveExceptionPending:
    """Observe-mode hook exceptions must still record the allowed execution."""

    async def test_observe_exception_records_execution_on_after_hook(self):
        """Revert-red: missing pending after observe exception drops CALL_EXECUTED."""
        sink = NullAuditSink()
        guard = make_guard(mode="observe", audit_sink=sink)
        adapter = CrewAIAdapter(guard, session_id="crewai-obs-exc-exec")

        async def explode(context):
            raise RuntimeError("backend outage")

        with _capture_registered_hooks(adapter) as (before, after):
            adapter._before_hook = explode
            result = before(_make_before_context(tool_name="canary", tool_input={"payload": "ping"}))
            assert result is None
            assert adapter._pending_envelope is not None
            assert adapter._pending_span is not None
            assert adapter._pending_decision is not None
            after(_make_after_context(tool_name="canary", tool_input={"payload": "ping"}, tool_result="ok"))

        executed = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert executed, f"missing CALL_EXECUTED; got {[e.action for e in sink.events]}"
        assert await adapter._session.execution_count() == 1
        assert executed[0].tool_name == "canary"

    async def test_observe_exception_does_not_retry_failing_principal_resolver(self):
        """Revert-red: fallback re-invokes principal_resolver and drops pending."""
        sink = NullAuditSink()
        resolver_calls: list[tuple[str, dict]] = []
        static = Principal(user_id="static-user")

        def boom_resolver(tool_name: str, tool_input: dict) -> Principal:
            resolver_calls.append((tool_name, dict(tool_input)))
            raise RuntimeError("resolver down")

        guard = make_guard(mode="observe", audit_sink=sink)
        adapter = CrewAIAdapter(
            guard,
            session_id="crewai-obs-exc-resolver",
            principal=static,
            principal_resolver=boom_resolver,
        )

        with _capture_registered_hooks(adapter) as (before, after):
            result = before(_make_before_context(tool_name="canary", tool_input={"payload": "ping"}))
            assert result is None
            assert adapter._pending_envelope is not None
            assert adapter._pending_span is not None
            assert adapter._pending_decision is not None
            assert adapter._pending_envelope.principal == static
            assert len(resolver_calls) == 1
            after(_make_after_context(tool_name="canary", tool_input={"payload": "ping"}, tool_result="ok"))

        executed = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert executed, f"missing CALL_EXECUTED; got {[e.action for e in sink.events]}"
        assert await adapter._session.execution_count() == 1
        assert len(resolver_calls) == 1

    async def test_observe_exception_preserves_resolved_principal(self):
        """Revert-red: fallback rebuilds envelope with static principal."""
        sink = NullAuditSink()
        static = Principal(user_id="static-user")
        resolved = Principal(user_id="resolved-user", role="admin")
        resolver_calls: list[tuple[str, dict]] = []

        def resolver(tool_name: str, tool_input: dict) -> Principal:
            resolver_calls.append((tool_name, dict(tool_input)))
            return resolved

        guard = make_guard(mode="observe", audit_sink=sink)
        adapter = CrewAIAdapter(
            guard,
            session_id="crewai-obs-exc-resolved-principal",
            principal=static,
            principal_resolver=resolver,
        )

        async def boom_pre(*args, **kwargs):
            raise RuntimeError("pipeline outage")

        adapter._pipeline.pre_execute = boom_pre

        with _capture_registered_hooks(adapter) as (before, after):
            result = before(_make_before_context(tool_name="canary", tool_input={"payload": "ping"}))
            assert result is None
            assert adapter._pending_envelope is not None
            assert adapter._pending_envelope.principal == resolved
            assert adapter._pending_envelope.principal != static
            assert len(resolver_calls) == 1
            after(_make_after_context(tool_name="canary", tool_input={"payload": "ping"}, tool_result="ok"))

        executed = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert executed, f"missing CALL_EXECUTED; got {[e.action for e in sink.events]}"
        assert executed[0].principal is not None
        assert executed[0].principal["user_id"] == "resolved-user"
        assert executed[0].principal["role"] == "admin"
        assert len(resolver_calls) == 1

    async def test_observe_exception_preserves_counters_advanced_by_failed_hook(self):
        """Revert-red: fallback increments again after pre_execute already did."""
        sink = NullAuditSink()
        guard = make_guard(mode="observe", audit_sink=sink)
        adapter = CrewAIAdapter(guard, session_id="crewai-obs-exc-counters")

        async def boom_pre(*args, **kwargs):
            raise RuntimeError("pipeline outage")

        adapter._pipeline.pre_execute = boom_pre

        with _capture_registered_hooks(adapter) as (before, after):
            result = before(_make_before_context(tool_name="canary", tool_input={"payload": "ping"}))
            assert result is None
            assert adapter._pending_envelope is not None
            assert adapter._call_index == 1
            assert await adapter._session.attempt_count() == 1
            assert adapter._pending_envelope.call_index == 0
            after(_make_after_context(tool_name="canary", tool_input={"payload": "ping"}, tool_result="ok"))

        executed = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert executed, f"missing CALL_EXECUTED; got {[e.action for e in sink.events]}"
        assert executed[0].call_index == 0
        assert executed[0].session_attempt_count == 1
        assert adapter._call_index == 1
        assert await adapter._session.attempt_count() == 1
        assert await adapter._session.execution_count() == 1

    async def test_observe_exception_does_not_retry_failed_attempt_increment(self):
        """Revert-red: fallback retries increment_attempts after it raised."""
        sink = NullAuditSink()
        guard = make_guard(mode="observe", audit_sink=sink)
        adapter = CrewAIAdapter(guard, session_id="crewai-obs-exc-incr")
        increment_calls: list[int] = []
        real_increment = adapter._session.increment_attempts

        async def timeout_after_apply() -> int:
            increment_calls.append(1)
            await real_increment()
            raise TimeoutError("backend increment timed out")

        adapter._session.increment_attempts = timeout_after_apply

        with _capture_registered_hooks(adapter) as (before, after):
            result = before(_make_before_context(tool_name="canary", tool_input={"payload": "ping"}))
            assert result is None
            assert adapter._pending_envelope is not None
            assert adapter._pending_span is not None
            assert adapter._pending_decision is not None
            assert increment_calls == [1]
            assert await adapter._session.attempt_count() == 1
            after(_make_after_context(tool_name="canary", tool_input={"payload": "ping"}, tool_result="ok"))

        executed = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert executed, f"missing CALL_EXECUTED; got {[e.action for e in sink.events]}"
        assert increment_calls == [1]
        assert executed[0].session_attempt_count == 1
        assert await adapter._session.attempt_count() == 1
        assert await adapter._session.execution_count() == 1

    async def test_observe_exception_preserves_evaluated_workflow_state(self):
        """Revert-red: fallback discards workflow fields after pre_execute succeeded."""
        sink = NullAuditSink()
        guard = make_guard(mode="observe", audit_sink=sink)
        adapter = CrewAIAdapter(guard, session_id="crewai-obs-exc-workflow")
        snapshot = {"name": "obs-exc", "current_stage": "read-context"}
        evaluated = PreDecision(
            action="allow",
            reason="ok",
            decision_source="workflow",
            decision_name="read-context",
            workflow_involved=True,
            workflow_stage_id="read-context",
            workflow=snapshot,
        )

        async def pre(*args, **kwargs):
            return evaluated

        async def boom_emit(*args, **kwargs):
            raise RuntimeError("workflow event emit failed")

        record_calls: list[str] = []

        class _Runtime:
            definition = object()

            async def record_result(self, session, stage_id, envelope, mcp_result=None):
                record_calls.append(stage_id)
                return []

            async def state(self, session):
                return SimpleNamespace()

        adapter._pipeline.pre_execute = pre
        adapter._emit_workflow_events = boom_emit
        guard._workflow_runtime = _Runtime()

        from edictum.adapters import crewai as crewai_mod

        orig_snapshot = crewai_mod.build_workflow_snapshot
        crewai_mod.build_workflow_snapshot = lambda definition, state: {
            "current_stage": "read-context",
            "status": "recorded",
        }
        try:
            with _capture_registered_hooks(adapter) as (before, after):
                result = before(_make_before_context(tool_name="canary", tool_input={"payload": "ping"}))
                assert result is None
                assert adapter._pending_decision is evaluated
                assert adapter._pending_decision.workflow_involved is True
                assert adapter._pending_decision.workflow_stage_id == "read-context"
                assert adapter._pending_decision.workflow == snapshot
                after(_make_after_context(tool_name="canary", tool_input={"payload": "ping"}, tool_result="ok"))
        finally:
            crewai_mod.build_workflow_snapshot = orig_snapshot

        executed = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert executed, f"missing CALL_EXECUTED; got {[e.action for e in sink.events]}"
        assert record_calls == ["read-context"]
        assert executed[0].workflow == {"current_stage": "read-context", "status": "recorded"}
        assert await adapter._session.execution_count() == 1
