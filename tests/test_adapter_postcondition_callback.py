"""Tests for on_postcondition_warn callback in adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from edictum import Edictum, Decision, postcondition
from edictum.adapters.langchain import LangChainAdapter
from edictum.findings import Finding, PostCallResult
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


def _make_request(tool_name: str = "TestTool", tool_args: dict | None = None, tool_call_id: str = "tc-1") -> Any:
    request = MagicMock()
    request.tool_call = {
        "name": tool_name,
        "args": tool_args or {},
        "id": tool_call_id,
    }
    return request


@dataclass
class FakeToolMessage:
    content: str = ""
    tool_call_id: str = ""


class TestPostToolCallReturnsPostCallResult:
    """Verify _post_tool_call returns PostCallResult."""

    async def test_returns_postcallresult_on_success(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        request = _make_request()

        await adapter._pre_tool_call(request)
        result = await adapter._post_tool_call(request, "ok")

        assert isinstance(result, PostCallResult)
        assert result.postconditions_passed is True
        assert result.violations == []
        assert result.result == "ok"

    async def test_returns_postcallresult_with_findings_on_failure(self):
        @postcondition("TestTool")
        def detect_pii(tool_call, result):
            if "SSN" in str(result):
                return Decision.fail("PII detected: SSN pattern found")
            return Decision.pass_()

        guard = make_guard(rules=[detect_pii])
        adapter = LangChainAdapter(guard)
        request = _make_request()

        await adapter._pre_tool_call(request)
        post_result = await adapter._post_tool_call(request, "Patient SSN: 123-45-6789")

        assert isinstance(post_result, PostCallResult)
        assert post_result.postconditions_passed is False
        assert len(post_result.violations) == 1
        assert post_result.violations[0].type == "pii_detected"
        assert post_result.violations[0].rule_id == "detect_pii"
        assert "PII detected" in post_result.violations[0].message

    async def test_returns_postcallresult_when_no_pending(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        request = _make_request(tool_call_id="unknown")

        result = await adapter._post_tool_call(request, "ok")
        assert isinstance(result, PostCallResult)
        assert result.postconditions_passed is True
        assert result.result == "ok"


class TestPostconditionCallback:
    """Test on_postcondition_warn callback via as_tool_wrapper / as_async_tool_wrapper."""

    async def test_callback_not_called_when_postconditions_pass(self):
        """Callback should NOT be invoked when postconditions pass."""
        callback = MagicMock(return_value="[REDACTED]")
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper(on_postcondition_warn=callback)
        request = _make_request()

        async def handler(req):
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        result = await wrapper(request, handler)
        callback.assert_not_called()
        assert result.content == "ok"

    async def test_callback_called_when_postconditions_warn(self):
        """Callback should be invoked with result and violations when postconditions warn."""

        @postcondition("TestTool")
        def detect_pii(tool_call, result):
            return Decision.fail("SSN pattern found in output")

        callback = MagicMock(return_value="[REDACTED]")
        guard = make_guard(rules=[detect_pii])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper(on_postcondition_warn=callback)
        request = _make_request()

        async def handler(req):
            return "Patient SSN: 123-45-6789"

        result = await wrapper(request, handler)
        callback.assert_called_once()
        assert result == "[REDACTED]"

        # Verify callback args
        call_args = callback.call_args
        assert call_args[0][0] == "Patient SSN: 123-45-6789"  # original result
        violations = call_args[0][1]
        assert len(violations) == 1
        assert isinstance(violations[0], Finding)

    async def test_no_callback_returns_original_result(self):
        """Without callback, postcondition warnings are logged but result unchanged."""

        @postcondition("TestTool")
        def detect_pii(tool_call, result):
            return Decision.fail("SSN found")

        guard = make_guard(rules=[detect_pii])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper()  # no callback
        request = _make_request()

        async def handler(req):
            return "Patient SSN: 123-45-6789"

        result = await wrapper(request, handler)
        assert result == "Patient SSN: 123-45-6789"  # unchanged

    async def test_callback_receives_correct_findings(self):
        """Callback should receive Finding objects with correct attributes."""

        @postcondition("TestTool")
        def detect_pii(tool_call, result):
            return Decision.fail("PII detected: SSN pattern")

        received_findings = []

        def capture_callback(result, violations):
            received_findings.extend(violations)
            return result

        guard = make_guard(rules=[detect_pii])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper(on_postcondition_warn=capture_callback)
        request = _make_request()

        async def handler(req):
            return "data with SSN"

        await wrapper(request, handler)

        assert len(received_findings) == 1
        f = received_findings[0]
        assert isinstance(f, Finding)
        assert f.rule_id == "detect_pii"
        assert f.field == "output"
        assert "PII detected" in f.message

    async def test_callback_can_transform_result(self):
        """Callback can return a completely different result."""

        @postcondition("TestTool")
        def detect_issue(tool_call, result):
            return Decision.fail("bad output")

        def replace_result(result, violations):
            return {"redacted": True, "finding_count": len(violations)}

        guard = make_guard(rules=[detect_issue])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper(on_postcondition_warn=replace_result)
        request = _make_request()

        async def handler(req):
            return "raw output"

        result = await wrapper(request, handler)
        assert result == {"redacted": True, "finding_count": 1}

    async def test_multiple_findings(self):
        """Multiple failing postconditions produce multiple violations."""

        @postcondition("TestTool")
        def detect_pii(tool_call, result):
            return Decision.fail("SSN found in patient data")

        @postcondition("TestTool")
        def detect_secret(tool_call, result):
            return Decision.fail("API token exposed in output")

        received = []

        def capture(result, violations):
            received.extend(violations)
            return "[REDACTED]"

        guard = make_guard(rules=[detect_pii, detect_secret])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper(on_postcondition_warn=capture)
        request = _make_request()

        async def handler(req):
            return "raw"

        result = await wrapper(request, handler)
        assert result == "[REDACTED]"
        assert len(received) == 2


class TestSyncToolWrapperCallback:
    """Test on_postcondition_warn via the sync as_tool_wrapper."""

    async def test_sync_wrapper_callback_invoked(self):
        @postcondition("TestTool")
        def detect_issue(tool_call, result):
            return Decision.fail("issue found")

        callback = MagicMock(return_value="[FIXED]")
        guard = make_guard(rules=[detect_issue])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_tool_wrapper(on_postcondition_warn=callback)
        request = _make_request()

        def handler(req):
            return FakeToolMessage(content="raw", tool_call_id="tc-1")

        result = wrapper(request, handler)
        callback.assert_called_once()
        assert result == "[FIXED]"

    async def test_sync_wrapper_no_callback_backward_compat(self):
        """as_tool_wrapper() without callback still works as before."""
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_tool_wrapper()
        request = _make_request()

        def handler(req):
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        result = wrapper(request, handler)
        assert result.content == "ok"


class TestCallbackExceptionSafety:
    """Callback exceptions should be caught, logged, and not break execution."""

    async def test_callback_exception_returns_original_result(self):
        """If callback raises, original result is returned unchanged."""

        @postcondition("TestTool")
        def detect_issue(tool_call, result):
            return Decision.fail("issue found")

        def exploding_callback(result, violations):
            raise RuntimeError("callback exploded")

        guard = make_guard(rules=[detect_issue])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper(on_postcondition_warn=exploding_callback)
        request = _make_request()

        async def handler(req):
            return "original output"

        result = await wrapper(request, handler)
        assert result == "original output"

    async def test_sync_wrapper_callback_exception_returns_original(self):
        """Sync wrapper: callback exception returns original result."""

        @postcondition("TestTool")
        def detect_issue(tool_call, result):
            return Decision.fail("issue found")

        def exploding_callback(result, violations):
            raise ValueError("boom")

        guard = make_guard(rules=[detect_issue])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_tool_wrapper(on_postcondition_warn=exploding_callback)
        request = _make_request()

        def handler(req):
            return FakeToolMessage(content="raw", tool_call_id="tc-1")

        result = wrapper(request, handler)
        assert result.content == "raw"


class TestFindingsImportableFromEdictum:
    """Verify Finding and PostCallResult are in the public API."""

    def test_finding_importable(self):
        from edictum import Finding

        f = Finding(type="test", rule_id="c", field="f", message="m")
        assert f.type == "test"

    def test_postcallresult_importable(self):
        from edictum import PostCallResult

        r = PostCallResult(result="x")
        assert r.postconditions_passed is True
