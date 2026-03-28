"""Tests for CheckPipeline — full pre_execute and post_execute flows."""

from __future__ import annotations

import pytest

from edictum import Edictum, OperationLimits, Decision, precondition, session_contract
from edictum.envelope import SideEffect, create_envelope
from edictum.hooks import HookDecision
from edictum.pipeline import CheckPipeline
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.types import HookRegistration
from tests.conftest import NullAuditSink


@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def session(backend):
    return Session("pipeline-test", backend)


def make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


class TestPreExecute:
    async def test_allow_with_no_rules(self, session):
        guard = make_guard(backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()
        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "allow"
        assert decision.reason is None

    async def test_attempt_limit_deny(self):
        backend = MemoryBackend()
        guard = make_guard(limits=OperationLimits(max_attempts=2), backend=backend)
        session = Session("test", backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})

        # Simulate 2 attempts (>= max_attempts=2)
        await session.increment_attempts()
        await session.increment_attempts()

        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "block"
        assert decision.decision_source == "attempt_limit"
        assert "retry loop" in decision.reason.lower()

    async def test_hook_deny(self, session):
        def deny_all(tool_call):
            return HookDecision.block("denied by hook")

        hook = HookRegistration(phase="before", tool="*", callback=deny_all)
        guard = make_guard(hooks=[hook], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()

        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "block"
        assert decision.decision_source == "hook"
        assert decision.reason == "denied by hook"
        assert len(decision.hooks_evaluated) == 1
        assert decision.hooks_evaluated[0]["result"] == "block"

    async def test_hook_allow_continues(self, session):
        def allow_all(tool_call):
            return HookDecision.allow()

        hook = HookRegistration(phase="before", tool="*", callback=allow_all)
        guard = make_guard(hooks=[hook], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()

        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "allow"
        assert len(decision.hooks_evaluated) == 1

    async def test_precondition_deny(self, session):
        @precondition("*")
        def must_have_name(tool_call):
            if "name" not in tool_call.args:
                return Decision.fail("Missing required arg: name")
            return Decision.pass_()

        guard = make_guard(rules=[must_have_name], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()

        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "block"
        assert decision.decision_source == "precondition"
        assert "name" in decision.reason

    async def test_precondition_pass(self, session):
        @precondition("*")
        def must_have_name(tool_call):
            if "name" not in tool_call.args:
                return Decision.fail("Missing required arg: name")
            return Decision.pass_()

        guard = make_guard(rules=[must_have_name], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {"name": "test"})
        await session.increment_attempts()

        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "allow"

    async def test_session_contract_deny(self, session):
        @session_contract
        async def max_3_execs(sess):
            count = await sess.execution_count()
            if count >= 3:
                return Decision.fail("Too many executions")
            return Decision.pass_()

        # Simulate 3 executions
        for _ in range(3):
            await session.record_execution("T", success=True)

        guard = make_guard(rules=[max_3_execs], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()

        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "block"
        assert decision.decision_source == "session_contract"

    async def test_execution_limit_deny(self):
        backend = MemoryBackend()
        guard = make_guard(limits=OperationLimits(max_tool_calls=2), backend=backend)
        session = Session("test", backend)
        pipeline = CheckPipeline(guard)

        # Record 2 executions
        await session.record_execution("T", success=True)
        await session.record_execution("T", success=True)
        await session.increment_attempts()

        tool_call = create_envelope("TestTool", {})
        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "block"
        assert decision.decision_source == "operation_limit"
        assert decision.decision_name == "max_tool_calls"

    async def test_per_tool_limit_deny(self):
        backend = MemoryBackend()
        guard = make_guard(
            limits=OperationLimits(max_calls_per_tool={"Bash": 1}),
            backend=backend,
        )
        session = Session("test", backend)
        pipeline = CheckPipeline(guard)

        await session.record_execution("Bash", success=True)
        await session.increment_attempts()

        tool_call = create_envelope("Bash", {"command": "ls"})
        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "block"
        assert "per-tool limit" in decision.reason.lower()

    async def test_evaluation_order(self, session):
        """Verify hooks run before preconditions."""
        order = []

        def tracking_hook(tool_call):
            order.append("hook")
            return HookDecision.allow()

        @precondition("*")
        def tracking_precondition(tool_call):
            order.append("precondition")
            return Decision.pass_()

        hook = HookRegistration(phase="before", tool="*", callback=tracking_hook)
        guard = make_guard(rules=[tracking_precondition], hooks=[hook], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()

        await pipeline.pre_execute(tool_call, session)
        assert order == ["hook", "precondition"]

    async def test_contracts_evaluated_populated(self, session):
        @precondition("*")
        def check_a(tool_call):
            return Decision.pass_()

        guard = make_guard(rules=[check_a], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()

        decision = await pipeline.pre_execute(tool_call, session)
        assert len(decision.contracts_evaluated) == 1
        assert decision.contracts_evaluated[0]["type"] == "precondition"
        assert decision.contracts_evaluated[0]["passed"] is True

    async def test_tool_specific_precondition(self, session):
        @precondition("Bash")
        def bash_only(tool_call):
            return Decision.fail("bash denied")

        guard = make_guard(rules=[bash_only], backend=session._backend)
        pipeline = CheckPipeline(guard)

        # Non-Bash tool should not be affected
        tool_call = create_envelope("Read", {"file_path": "/tmp/x"})
        await session.increment_attempts()
        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "allow"

        # Bash tool should be denied
        bash_envelope = create_envelope("Bash", {"command": "ls"})
        decision = await pipeline.pre_execute(bash_envelope, session)
        assert decision.action == "block"


class TestPostExecute:
    async def test_success_no_postconditions(self, session):
        guard = make_guard(backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})

        decision = await pipeline.post_execute(tool_call, "ok", True)
        assert decision.tool_success is True
        assert decision.postconditions_passed is True
        assert decision.warnings == []

    async def test_postcondition_failure_pure_tool(self, session):
        from edictum.rules import postcondition as postc

        @postc("TestTool")
        def check_result(tool_call, result):
            if result != "expected":
                return Decision.fail("Unexpected result")
            return Decision.pass_()

        guard = make_guard(rules=[check_result], backend=session._backend)
        # Need to register TestTool as PURE for retry suggestion
        guard.tool_registry.register("TestTool", SideEffect.PURE)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {}, registry=guard.tool_registry)

        decision = await pipeline.post_execute(tool_call, "wrong", True)
        assert decision.postconditions_passed is False
        assert len(decision.warnings) == 1
        assert "consider retrying" in decision.warnings[0].lower()

    async def test_postcondition_failure_write_tool(self, session):
        from edictum.rules import postcondition as postc

        @postc("WriteTool")
        def check_write(tool_call, result):
            return Decision.fail("Write verification failed")

        guard = make_guard(rules=[check_write], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("WriteTool", {})

        decision = await pipeline.post_execute(tool_call, "result", True)
        assert decision.postconditions_passed is False
        assert "assess before proceeding" in decision.warnings[0].lower()

    async def test_after_hooks_called(self, session):
        called = []

        def after_hook(tool_call, result):
            called.append(result)

        hook = HookRegistration(phase="after", tool="*", callback=after_hook)
        guard = make_guard(hooks=[hook], backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})

        await pipeline.post_execute(tool_call, "the_result", True)
        assert called == ["the_result"]

    async def test_tool_failure_reported(self, session):
        guard = make_guard(backend=session._backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})

        decision = await pipeline.post_execute(tool_call, "Error: failed", False)
        assert decision.tool_success is False


class TestObserveMode:
    async def test_observe_mode_converts_deny_to_allow(self):
        @precondition("*")
        def always_fail(tool_call):
            return Decision.fail("always fails")

        backend = MemoryBackend()
        guard = make_guard(mode="observe", rules=[always_fail], backend=backend)
        session = Session("test", backend)
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})
        await session.increment_attempts()

        # Pipeline still returns block (mode handling is in adapter/guard.run)
        decision = await pipeline.pre_execute(tool_call, session)
        assert decision.action == "block"
        # The observe mode conversion happens in the adapter/Edictum.run(), not pipeline
