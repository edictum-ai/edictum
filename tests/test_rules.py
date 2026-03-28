"""Tests for Decision and rule decorators."""

from __future__ import annotations

from edictum.rules import Decision, postcondition, precondition, session_contract


class TestDecision:
    def test_pass(self):
        v = Decision.pass_()
        assert v.passed is True
        assert v.message is None
        assert v.metadata == {}

    def test_fail(self):
        v = Decision.fail("something went wrong")
        assert v.passed is False
        assert v.message == "something went wrong"

    def test_fail_truncation(self):
        long_msg = "x" * 600
        v = Decision.fail(long_msg)
        assert len(v.message) == 500
        assert v.message.endswith("...")

    def test_fail_exact_500(self):
        msg = "x" * 500
        v = Decision.fail(msg)
        assert v.message == msg

    def test_fail_with_metadata(self):
        v = Decision.fail("err", key1="val1", key2=42)
        assert v.metadata == {"key1": "val1", "key2": 42}


class TestPrecondition:
    def test_decorator_sets_attributes(self):
        @precondition("Bash")
        def my_check(tool_call):
            return Decision.pass_()

        assert my_check._edictum_type == "precondition"
        assert my_check._edictum_tool == "Bash"
        assert my_check._edictum_when is None

    def test_decorator_with_when(self):
        def when_fn(e):
            return e.tool_name == "Bash"

        @precondition("Bash", when=when_fn)
        def my_check(tool_call):
            return Decision.pass_()

        assert my_check._edictum_when is when_fn

    def test_wildcard_tool(self):
        @precondition("*")
        def check_all(tool_call):
            return Decision.pass_()

        assert check_all._edictum_tool == "*"


class TestPostcondition:
    def test_decorator_sets_attributes(self):
        @postcondition("Write")
        def verify_output(tool_call, result):
            return Decision.pass_()

        assert verify_output._edictum_type == "postcondition"
        assert verify_output._edictum_tool == "Write"


class TestSessionContract:
    def test_decorator_sets_attributes(self):
        @session_contract
        async def max_ops(session):
            return Decision.pass_()

        assert max_ops._edictum_type == "session_contract"
