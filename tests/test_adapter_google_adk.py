"""Tests for GoogleADKAdapter."""

from __future__ import annotations

import re
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from edictum import Edictum, Principal, Verdict, postcondition, precondition
from edictum.adapters.google_adk import GoogleADKAdapter
from edictum.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus
from edictum.audit import AuditAction
from edictum.findings import PostCallResult
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

_READ_TOOLS = {"TestTool": {"side_effect": "read"}}


def make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


class TestGoogleADKAdapter:
    async def test_allow_returns_none(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard, session_id="test-session")
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={"key": "value"},
            call_id="call-1",
        )
        assert result is None

    async def test_deny_returns_dict(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("denied")

        guard = make_guard(contracts=[always_deny])
        adapter = GoogleADKAdapter(guard)
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert result is not None
        assert isinstance(result, dict)
        assert "error" in result
        assert "DENIED:" in result["error"]
        assert "denied" in result["error"]

    async def test_deny_dict_format(self):
        result = GoogleADKAdapter._deny("reason")
        assert result == {"error": "DENIED: reason"}

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert "call-1" in adapter._pending

        await adapter._post(call_id="call-1", tool_response="ok")
        assert "call-1" not in adapter._pending

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("no")

        guard = make_guard(contracts=[always_deny])
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert "call-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        result = await adapter._post(call_id="unknown", tool_response="ok")
        assert isinstance(result, PostCallResult)
        assert result.postconditions_passed is True
        assert result.result == "ok"

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._pre(tool_name="T", tool_input={}, call_id="call-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("would be denied")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", contracts=[always_deny], audit_sink=sink)
        adapter = GoogleADKAdapter(guard)

        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert result is None
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        assert "call-1" in adapter._pending

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._post(call_id="call-1", tool_response="ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        assert adapter._check_tool_success("TestTool", None) is True
        assert adapter._check_tool_success("TestTool", "ok") is True
        assert adapter._check_tool_success("TestTool", "Error: something failed") is False
        assert adapter._check_tool_success("TestTool", "fatal: not a git repo") is False

    async def test_tool_success_error_dict(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        assert adapter._check_tool_success("TestTool", {"error": "something"}) is False
        assert adapter._check_tool_success("TestTool", {"is_error": True}) is False

    async def test_session_id_default(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        assert adapter.session_id
        assert isinstance(adapter.session_id, str)

    async def test_session_id_custom(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard, session_id="custom")
        assert adapter.session_id == "custom"

    async def test_set_principal(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        p = Principal(role="admin")
        adapter.set_principal(p)
        assert adapter._principal is p

    async def test_principal_resolver(self):
        @precondition("*")
        def require_admin(envelope):
            if envelope.principal is None or envelope.principal.role != "admin":
                return Verdict.fail("admin required")
            return Verdict.pass_()

        def resolver(tool_name, tool_input):
            return Principal(role="admin")

        guard = make_guard(contracts=[require_admin])
        adapter = GoogleADKAdapter(guard, principal_resolver=resolver)

        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert result is None  # allowed

    async def test_auto_principal_from_context(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        mock_context = SimpleNamespace(
            function_call_id="fc-1",
            user_id="u1",
            agent_name="a1",
        )

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="fc-1",
            tool_context=mock_context,
        )

        envelope, _ = adapter._pending["fc-1"]
        assert envelope.principal is not None
        assert envelope.principal.user_id == "u1"
        assert envelope.principal.claims.get("adk_agent_name") == "a1"

    async def test_metadata_from_context(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        mock_context = SimpleNamespace(
            function_call_id="fc-1",
            invocation_id="inv-1",
            agent_name="research_agent",
        )

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="fc-1",
            tool_context=mock_context,
        )

        envelope, _ = adapter._pending["fc-1"]
        assert envelope.metadata.get("adk_invocation_id") == "inv-1"
        assert envelope.metadata.get("adk_agent_name") == "research_agent"

    async def test_postcondition_warn_callback(self):
        @postcondition("TestTool")
        def detect_issue(envelope, result):
            return Verdict.fail("issue found in output")

        callback = MagicMock()
        guard = make_guard(contracts=[detect_issue])
        adapter = GoogleADKAdapter(guard)
        adapter._on_postcondition_warn = callback

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        await adapter._post(call_id="call-1", tool_response="some result")

        assert callback.call_count == 1

    async def test_postcondition_warn_exception_safety(self):
        @postcondition("TestTool")
        def detect_issue(envelope, result):
            return Verdict.fail("issue found")

        def exploding_callback(result, findings):
            raise RuntimeError("boom")

        guard = make_guard(contracts=[detect_issue])
        adapter = GoogleADKAdapter(guard)
        adapter._on_postcondition_warn = exploding_callback

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        result = await adapter._post(call_id="call-1", tool_response="original")

        assert isinstance(result, PostCallResult)
        assert result.result == "original"

    async def test_post_redaction(self):
        @postcondition("TestTool")
        def detect_secret(envelope, result):
            if "sk-" in str(result):
                return Verdict.fail("secret detected")
            return Verdict.pass_()

        detect_secret._edictum_effect = "redact"
        detect_secret._edictum_redact_patterns = [re.compile(r"sk-\w+")]

        guard = make_guard(contracts=[detect_secret], tools=_READ_TOOLS)
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        result = await adapter._post(call_id="call-1", tool_response="key: sk-prod12345")

        assert isinstance(result, PostCallResult)
        assert result.result is not None
        assert "sk-prod12345" not in str(result.result)

    async def test_post_output_suppressed(self):
        @postcondition("TestTool")
        def detect_secret(envelope, result):
            return Verdict.fail("secret detected")

        detect_secret._edictum_effect = "deny"

        guard = make_guard(contracts=[detect_secret], tools=_READ_TOOLS)
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        result = await adapter._post(call_id="call-1", tool_response="secret data")

        assert isinstance(result, PostCallResult)
        assert result.output_suppressed is True

    async def test_on_deny_callback(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("not allowed")

        on_deny = MagicMock()
        guard = make_guard(contracts=[always_deny], on_deny=on_deny)
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert on_deny.call_count == 1

    async def test_on_allow_callback(self):
        on_allow = MagicMock()
        guard = make_guard(on_allow=on_allow)
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert on_allow.call_count == 1

    async def test_per_contract_observe(self):
        @precondition("*")
        def observed_deny(envelope):
            return Verdict.fail("would deny")

        observed_deny._edictum_mode = "observe"

        sink = NullAuditSink()
        guard = make_guard(contracts=[observed_deny], audit_sink=sink)
        adapter = GoogleADKAdapter(guard)

        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert result is None  # allowed through
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)


class TestPluginIntegration:
    def _mock_adk_modules(self):
        """Set up sys.modules mocks for google.adk.plugins.base_plugin."""
        mock_base_plugin_mod = ModuleType("google.adk.plugins.base_plugin")

        class MockBasePlugin:
            def __init__(self, name=""):
                self.name = name

        mock_base_plugin_mod.BasePlugin = MockBasePlugin

        # Build module hierarchy
        mock_google = ModuleType("google")
        mock_google_adk = ModuleType("google.adk")
        mock_google_adk_plugins = ModuleType("google.adk.plugins")

        originals = {}
        for mod_name in [
            "google",
            "google.adk",
            "google.adk.plugins",
            "google.adk.plugins.base_plugin",
        ]:
            originals[mod_name] = sys.modules.get(mod_name)

        sys.modules["google"] = mock_google
        sys.modules["google.adk"] = mock_google_adk
        sys.modules["google.adk.plugins"] = mock_google_adk_plugins
        sys.modules["google.adk.plugins.base_plugin"] = mock_base_plugin_mod

        return MockBasePlugin, originals

    def _restore_modules(self, originals):
        for mod_name, orig in originals.items():
            if orig is not None:
                sys.modules[mod_name] = orig
            else:
                sys.modules.pop(mod_name, None)

    async def test_as_plugin_returns_base_plugin(self):
        mock_base_plugin_cls, originals = self._mock_adk_modules()
        try:
            guard = make_guard()
            adapter = GoogleADKAdapter(guard)
            plugin = adapter.as_plugin()
            assert isinstance(plugin, mock_base_plugin_cls)
        finally:
            self._restore_modules(originals)

    async def test_plugin_name(self):
        mock_base_plugin_cls, originals = self._mock_adk_modules()
        try:
            guard = make_guard()
            adapter = GoogleADKAdapter(guard)
            plugin = adapter.as_plugin()
            assert plugin.name == "edictum"
        finally:
            self._restore_modules(originals)

    async def test_plugin_before_tool_deny(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("denied by policy")

        mock_base_plugin_cls, originals = self._mock_adk_modules()
        try:
            guard = make_guard(contracts=[always_deny])
            adapter = GoogleADKAdapter(guard)
            plugin = adapter.as_plugin()

            mock_tool = SimpleNamespace(name="TestTool")
            mock_context = SimpleNamespace(function_call_id="fc-1")

            result = await plugin.before_tool_callback(
                tool=mock_tool,
                tool_args={"key": "value"},
                tool_context=mock_context,
            )
            assert isinstance(result, dict)
            assert "DENIED:" in result["error"]
        finally:
            self._restore_modules(originals)

    async def test_plugin_before_tool_allow(self):
        mock_base_plugin_cls, originals = self._mock_adk_modules()
        try:
            guard = make_guard()
            adapter = GoogleADKAdapter(guard)
            plugin = adapter.as_plugin()

            mock_tool = SimpleNamespace(name="TestTool")
            mock_context = SimpleNamespace(function_call_id="fc-1")

            result = await plugin.before_tool_callback(
                tool=mock_tool,
                tool_args={"key": "value"},
                tool_context=mock_context,
            )
            assert result is None
        finally:
            self._restore_modules(originals)

    async def test_plugin_after_tool_passthrough(self):
        mock_base_plugin_cls, originals = self._mock_adk_modules()
        try:
            guard = make_guard()
            adapter = GoogleADKAdapter(guard)
            plugin = adapter.as_plugin()

            mock_tool = SimpleNamespace(name="TestTool")
            mock_context = SimpleNamespace(function_call_id="fc-1")

            await plugin.before_tool_callback(
                tool=mock_tool,
                tool_args={},
                tool_context=mock_context,
            )
            result = await plugin.after_tool_callback(
                tool=mock_tool,
                tool_args={},
                tool_context=mock_context,
                result="ok",
            )
            assert result is None  # keep original
        finally:
            self._restore_modules(originals)

    async def test_plugin_after_tool_redact(self):
        @postcondition("TestTool")
        def detect_secret(envelope, result):
            if "sk-" in str(result):
                return Verdict.fail("secret detected")
            return Verdict.pass_()

        detect_secret._edictum_effect = "redact"
        detect_secret._edictum_redact_patterns = [re.compile(r"sk-\w+")]

        mock_base_plugin_cls, originals = self._mock_adk_modules()
        try:
            guard = make_guard(contracts=[detect_secret], tools=_READ_TOOLS)
            adapter = GoogleADKAdapter(guard)
            plugin = adapter.as_plugin()

            mock_tool = SimpleNamespace(name="TestTool")
            mock_context = SimpleNamespace(function_call_id="fc-1")

            await plugin.before_tool_callback(
                tool=mock_tool,
                tool_args={},
                tool_context=mock_context,
            )
            result = await plugin.after_tool_callback(
                tool=mock_tool,
                tool_args={},
                tool_context=mock_context,
                result="key: sk-prod12345",
            )
            assert result is not None
            assert "sk-prod12345" not in str(result)
        finally:
            self._restore_modules(originals)

    async def test_plugin_on_tool_error(self):
        mock_base_plugin_cls, originals = self._mock_adk_modules()
        try:
            sink = NullAuditSink()
            guard = make_guard(audit_sink=sink)
            adapter = GoogleADKAdapter(guard)
            plugin = adapter.as_plugin()

            mock_tool = SimpleNamespace(name="TestTool")
            mock_context = SimpleNamespace(function_call_id="fc-1")

            await plugin.before_tool_callback(
                tool=mock_tool,
                tool_args={},
                tool_context=mock_context,
            )
            result = await plugin.on_tool_error_callback(
                tool=mock_tool,
                tool_args={},
                tool_context=mock_context,
                error=RuntimeError("tool crashed"),
            )
            assert result is None  # re-raise
            assert any(e.action == AuditAction.CALL_FAILED for e in sink.events)
        finally:
            self._restore_modules(originals)


class TestAgentCallbacks:
    async def test_as_agent_callbacks_returns_tuple(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        callbacks = adapter.as_agent_callbacks()
        assert isinstance(callbacks, tuple)
        assert len(callbacks) == 3
        assert callable(callbacks[0])
        assert callable(callbacks[1])
        assert callable(callbacks[2])

    async def test_agent_before_callback_deny(self):
        @precondition("*")
        def always_deny(envelope):
            return Verdict.fail("denied by policy")

        guard = make_guard(contracts=[always_deny])
        adapter = GoogleADKAdapter(guard)
        before_cb, _, _ = adapter.as_agent_callbacks()

        mock_tool = SimpleNamespace(name="TestTool")
        mock_context = SimpleNamespace(function_call_id="fc-1")

        result = await before_cb(mock_tool, {"key": "value"}, mock_context)
        assert isinstance(result, dict)
        assert "DENIED:" in result["error"]

    async def test_agent_before_callback_allow(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        before_cb, _, _ = adapter.as_agent_callbacks()

        mock_tool = SimpleNamespace(name="TestTool")
        mock_context = SimpleNamespace(function_call_id="fc-1")

        result = await before_cb(mock_tool, {"key": "value"}, mock_context)
        assert result is None

    async def test_agent_after_callback_passthrough(self):
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        before_cb, after_cb, _ = adapter.as_agent_callbacks()

        mock_tool = SimpleNamespace(name="TestTool")
        mock_context = SimpleNamespace(function_call_id="fc-1")

        await before_cb(mock_tool, {}, mock_context)
        result = await after_cb(mock_tool, {}, mock_context, "ok")
        assert result is None  # keep original

    async def test_agent_after_callback_redact(self):
        @postcondition("TestTool")
        def detect_secret(envelope, result):
            if "sk-" in str(result):
                return Verdict.fail("secret detected")
            return Verdict.pass_()

        detect_secret._edictum_effect = "redact"
        detect_secret._edictum_redact_patterns = [re.compile(r"sk-\w+")]

        guard = make_guard(contracts=[detect_secret], tools=_READ_TOOLS)
        adapter = GoogleADKAdapter(guard)
        before_cb, after_cb, _ = adapter.as_agent_callbacks()

        mock_tool = SimpleNamespace(name="TestTool")
        mock_context = SimpleNamespace(function_call_id="fc-1")

        await before_cb(mock_tool, {}, mock_context)
        result = await after_cb(mock_tool, {}, mock_context, "key: sk-prod12345")
        assert result is not None
        assert "sk-prod12345" not in str(result)

    async def test_agent_error_callback_cleans_pending(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = GoogleADKAdapter(guard)
        before_cb, _, error_cb = adapter.as_agent_callbacks()

        mock_tool = SimpleNamespace(name="TestTool")
        mock_context = SimpleNamespace(function_call_id="fc-1")

        await before_cb(mock_tool, {}, mock_context)
        assert "fc-1" in adapter._pending

        await error_cb(mock_tool, {}, mock_context, RuntimeError("boom"))
        assert "fc-1" not in adapter._pending
        assert any(e.action == AuditAction.CALL_FAILED for e in sink.events)

    async def test_call_id_persists_across_callbacks_without_function_call_id(self):
        """When function_call_id is absent, UUID fallback is shared via _edictum_call_id."""
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        before_cb, after_cb, _ = adapter.as_agent_callbacks()

        mock_tool = SimpleNamespace(name="TestTool")
        mock_context = SimpleNamespace()  # no function_call_id

        await before_cb(mock_tool, {}, mock_context)
        # Should have stored _edictum_call_id on context
        assert hasattr(mock_context, "_edictum_call_id")
        assert len(adapter._pending) == 1

        await after_cb(mock_tool, {}, mock_context, "ok")
        # Pending should be cleaned up via the persisted call_id
        assert len(adapter._pending) == 0


class TestApproval:
    async def test_approval_granted_proceeds(self):
        @precondition("*")
        def require_approval(envelope):
            return Verdict.fail("needs approval")

        require_approval._edictum_effect = "approve"
        require_approval._edictum_timeout = 60
        require_approval._edictum_timeout_effect = "deny"

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="needs approval",
            timeout=60,
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=True,
            approver="admin",
            status=ApprovalStatus.APPROVED,
        )

        guard = make_guard(contracts=[require_approval], approval_backend=mock_backend)
        adapter = GoogleADKAdapter(guard)

        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert result is None  # allowed

    async def test_approval_denied_returns_dict(self):
        @precondition("*")
        def require_approval(envelope):
            return Verdict.fail("needs approval")

        require_approval._edictum_effect = "approve"
        require_approval._edictum_timeout = 60
        require_approval._edictum_timeout_effect = "deny"

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="needs approval",
            timeout=60,
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=False,
            reason="rejected by reviewer",
            status=ApprovalStatus.DENIED,
        )

        guard = make_guard(contracts=[require_approval], approval_backend=mock_backend)
        adapter = GoogleADKAdapter(guard)

        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert isinstance(result, dict)
        assert "DENIED:" in result["error"]
        assert "Approval denied" in result["error"]

    async def test_approval_timeout_deny(self):
        @precondition("*")
        def require_approval(envelope):
            return Verdict.fail("needs approval")

        require_approval._edictum_effect = "approve"
        require_approval._edictum_timeout = 1
        require_approval._edictum_timeout_effect = "deny"

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="needs approval",
            timeout=1,
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=False,
            status=ApprovalStatus.TIMEOUT,
        )

        guard = make_guard(contracts=[require_approval], approval_backend=mock_backend)
        adapter = GoogleADKAdapter(guard)

        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert isinstance(result, dict)
        assert "DENIED:" in result["error"]
        assert "timed out" in result["error"].lower()

    async def test_approval_timeout_allow(self):
        @precondition("*")
        def require_approval(envelope):
            return Verdict.fail("needs approval")

        require_approval._edictum_effect = "approve"
        require_approval._edictum_timeout = 1
        require_approval._edictum_timeout_effect = "allow"

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="needs approval",
            timeout=1,
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=False,
            status=ApprovalStatus.TIMEOUT,
        )

        guard = make_guard(contracts=[require_approval], approval_backend=mock_backend)
        adapter = GoogleADKAdapter(guard)

        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert result is None  # timeout_effect=allow

    async def test_approval_no_backend_denies(self):
        @precondition("*")
        def require_approval(envelope):
            return Verdict.fail("needs approval")

        require_approval._edictum_effect = "approve"

        sink = NullAuditSink()
        guard = make_guard(contracts=[require_approval], audit_sink=sink)
        adapter = GoogleADKAdapter(guard)

        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert isinstance(result, dict)
        assert "DENIED:" in result["error"]
        assert "no approval backend" in result["error"].lower()
        # Audit must record CALL_DENIED, not CALL_ALLOWED
        assert any(e.action == AuditAction.CALL_DENIED for e in sink.events)
