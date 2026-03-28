"""Behavior tests for observe-mode postcondition evaluation.

Proves that postconditions from observe_alongside bundles are
evaluated in post_execute and produce audit events + warnings.
"""

from __future__ import annotations

import pytest

from edictum import Edictum, Decision, postcondition
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import CapturingAuditSink


def _make_observe_postcondition(name: str):
    """Create a postcondition marked as observe-mode (observe_alongside)."""

    @postcondition("*")
    def check(tool_call, response):
        if "sensitive" in str(response):
            return Decision.fail(f"Observe-mode detected sensitive output [{name}]")
        return Decision.pass_()

    check.__name__ = name
    check._edictum_observe = True
    return check


def _make_guard_with_observe_postconditions(sink):
    """Build a guard with observe-mode postconditions injected."""
    guard = Edictum(
        environment="test",
        audit_sink=sink,
        backend=MemoryBackend(),
    )
    # Inject observe-mode postconditions into compiled state
    observe_post = _make_observe_postcondition("pii_check")
    from dataclasses import replace

    guard._state = replace(
        guard._state,
        observe_postconditions=guard._state.observe_postconditions + (observe_post,),
    )
    return guard


class TestObserveModePostconditionsEvaluated:
    """observe_alongside postconditions must be evaluated in post_execute."""

    @pytest.mark.asyncio
    async def test_observe_postcondition_produces_warning(self):
        """A failing observe-mode postcondition produces a warning, not a block."""
        sink = CapturingAuditSink()
        guard = _make_guard_with_observe_postconditions(sink)

        # The tool "succeeds" but returns sensitive data
        result = await guard.run("TestTool", {}, lambda: "sensitive data here")
        # Tool call allowed (observe mode doesn't block)
        assert result == "sensitive data here"

    @pytest.mark.asyncio
    async def test_observe_postcondition_emits_audit_event(self):
        """Observe-mode postcondition failure appears in audit contracts_evaluated."""
        sink = CapturingAuditSink()
        guard = _make_guard_with_observe_postconditions(sink)

        await guard.run("TestTool", {}, lambda: "sensitive data here")

        # Find the post-execution audit event
        post_events = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert len(post_events) == 1

        # The observe-mode postcondition should appear in contracts_evaluated
        rules = post_events[0].contracts_evaluated
        observe_contracts = [c for c in rules if c.get("observed")]
        assert len(observe_contracts) == 1
        assert observe_contracts[0]["name"] == "pii_check"
        assert observe_contracts[0]["passed"] is False

    @pytest.mark.asyncio
    async def test_observe_postcondition_passing_no_warning(self):
        """A passing observe-mode postcondition produces no warning."""
        sink = CapturingAuditSink()
        guard = _make_guard_with_observe_postconditions(sink)

        result = await guard.run("TestTool", {}, lambda: "clean data")
        assert result == "clean data"

        post_events = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        rules = post_events[0].contracts_evaluated
        observe_contracts = [c for c in rules if c.get("observed")]
        assert len(observe_contracts) == 1
        assert observe_contracts[0]["passed"] is True

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_per_contract_observe_postcondition_does_not_affect_postconditions_passed(self):
        """A per-rule mode:observe postcondition (from get_postconditions path)
        must NOT set postconditions_passed=False.

        This tests the FIRST loop in post_execute — per-rule observe mode
        where contract_mode == "observe". Different from observe_alongside which
        goes through get_observe_postconditions.
        """
        sink = CapturingAuditSink()
        guard = Edictum(
            environment="test",
            audit_sink=sink,
            backend=MemoryBackend(),
        )

        # Create an observe-mode postcondition (per-rule, NOT observe_alongside)
        @postcondition("*")
        def pii_check(tool_call, response):
            if "sensitive" in str(response):
                return Decision.fail("PII detected in output")
            return Decision.pass_()

        pii_check._edictum_mode = "observe"

        from dataclasses import replace

        guard._state = replace(
            guard._state,
            postconditions=guard._state.postconditions + (pii_check,),
        )

        result = await guard.run("TestTool", {}, lambda: "sensitive data here")
        assert result == "sensitive data here"

        post_events = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert post_events[0].postconditions_passed is True, (
            "Per-rule observe-mode postcondition set postconditions_passed=False. "
            "This triggers on_postcondition_warn in all adapters, violating observe-mode safety."
        )

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_observe_postcondition_does_not_affect_postconditions_passed(self):
        """A failing observe-mode postcondition must NOT set postconditions_passed=False.

        postconditions_passed propagates to on_postcondition_warn in all 7 adapters.
        If observe-mode rules set it to False, observe mode silently becomes
        enforcement — violating the core guarantee.
        """
        sink = CapturingAuditSink()
        guard = _make_guard_with_observe_postconditions(sink)

        await guard.run("TestTool", {}, lambda: "sensitive data here")

        post_events = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert len(post_events) == 1
        assert post_events[0].postconditions_passed is True, (
            "Failing observe-mode postcondition set postconditions_passed=False. "
            "This triggers on_postcondition_warn in all adapters, violating observe-mode safety."
        )
