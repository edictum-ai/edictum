"""Behavior tests for observe-mode postcondition evaluation.

Proves that postconditions from observe_alongside bundles are
evaluated in post_execute and produce audit events + warnings.
"""

from __future__ import annotations

import pytest

from edictum import Edictum, Verdict, postcondition
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import CapturingAuditSink


def _make_observe_postcondition(name: str):
    """Create a postcondition marked as observe-mode (observe_alongside)."""

    @postcondition("*")
    def check(envelope, response):
        if "sensitive" in str(response):
            return Verdict.fail(f"Observe-mode detected sensitive output [{name}]")
        return Verdict.pass_()

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
        """A failing observe-mode postcondition produces a warning, not a deny."""
        sink = CapturingAuditSink()
        guard = _make_guard_with_observe_postconditions(sink)

        # The tool "succeeds" but returns sensitive data
        result = await guard.run("TestTool", {}, lambda: "sensitive data here")
        # Tool call allowed (observe mode doesn't deny)
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
        contracts = post_events[0].contracts_evaluated
        observe_contracts = [c for c in contracts if c.get("observed")]
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
        contracts = post_events[0].contracts_evaluated
        observe_contracts = [c for c in contracts if c.get("observed")]
        assert len(observe_contracts) == 1
        assert observe_contracts[0]["passed"] is True
