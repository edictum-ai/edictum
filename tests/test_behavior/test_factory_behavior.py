"""Behavior tests for _factory.py — from_multiple() observe-mode rule merging."""

from __future__ import annotations

from edictum import Edictum
from edictum.rules import Decision, postcondition, precondition


class _NullSink:
    async def emit(self, event):
        pass


def _make_observe(fn):
    """Mark a rule function as observe-mode."""
    fn._edictum_observe = True
    return fn


class TestFromMultipleObserveModeContracts:
    """from_multiple() must merge observe-mode rules from all guards."""

    def test_observe_preconditions_merged_from_both_guards(self):
        @precondition("Bash")
        def observe_pre_a(tool_call):
            return Decision.fail("Observe-mode pre A")

        observe_pre_a._edictum_id = "observe-pre-a"
        _make_observe(observe_pre_a)

        @precondition("Write")
        def observe_pre_b(tool_call):
            return Decision.fail("Observe-mode pre B")

        observe_pre_b._edictum_id = "observe-pre-b"
        _make_observe(observe_pre_b)

        g1 = Edictum(mode="enforce", rules=[observe_pre_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", rules=[observe_pre_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.observe_preconditions]
        assert len(ids) == 2
        assert "observe-pre-a" in ids
        assert "observe-pre-b" in ids
        # Enforced lists should be empty
        assert len(merged._state.preconditions) == 0

    def test_observe_postconditions_merged(self):
        @postcondition("*")
        def observe_post_a(tool_call, response):
            return Decision.pass_()

        observe_post_a._edictum_id = "observe-post-a"
        _make_observe(observe_post_a)

        @postcondition("*")
        def observe_post_b(tool_call, response):
            return Decision.pass_()

        observe_post_b._edictum_id = "observe-post-b"
        _make_observe(observe_post_b)

        g1 = Edictum(mode="enforce", rules=[observe_post_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", rules=[observe_post_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.observe_postconditions]
        assert len(ids) == 2
        assert "observe-post-a" in ids
        assert "observe-post-b" in ids

    def test_mixed_enforce_and_observe_merged(self):
        """Only one guard has observe-mode rules; merged guard retains them."""

        @precondition("Bash")
        def enforced_pre(tool_call):
            return Decision.fail("Enforced")

        enforced_pre._edictum_id = "enforced-pre"

        @precondition("Write")
        def observe_pre(tool_call):
            return Decision.fail("Observe-mode")

        observe_pre._edictum_id = "observe-pre"
        _make_observe(observe_pre)

        g_enforce = Edictum(mode="enforce", rules=[enforced_pre], audit_sink=_NullSink())
        g_observe = Edictum(mode="enforce", rules=[observe_pre], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g_enforce, g_observe])

        assert len(merged._state.preconditions) == 1
        assert getattr(merged._state.preconditions[0], "_edictum_id", None) == "enforced-pre"

        assert len(merged._state.observe_preconditions) == 1
        assert getattr(merged._state.observe_preconditions[0], "_edictum_id", None) == "observe-pre"

    def test_observe_dedup_by_id(self):
        """Duplicate observe-mode rule IDs are deduplicated (first wins)."""

        @precondition("Bash")
        def observe_a(tool_call):
            return Decision.fail("First")

        observe_a._edictum_id = "same-id"
        _make_observe(observe_a)

        @precondition("Bash")
        def observe_b(tool_call):
            return Decision.fail("Second")

        observe_b._edictum_id = "same-id"
        _make_observe(observe_b)

        g1 = Edictum(mode="enforce", rules=[observe_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", rules=[observe_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        assert len(merged._state.observe_preconditions) == 1

    def test_observe_session_contracts_merged(self):
        """Observe-mode session rules from both guards appear in merged guard."""

        @precondition("*")
        def observe_sess_a(tool_call):
            return Decision.pass_()

        observe_sess_a._edictum_id = "observe-sess-a"
        observe_sess_a._edictum_type = "session_contract"
        _make_observe(observe_sess_a)

        @precondition("*")
        def observe_sess_b(tool_call):
            return Decision.pass_()

        observe_sess_b._edictum_id = "observe-sess-b"
        observe_sess_b._edictum_type = "session_contract"
        _make_observe(observe_sess_b)

        g1 = Edictum(mode="enforce", rules=[observe_sess_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", rules=[observe_sess_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.observe_session_contracts]
        assert len(ids) == 2
        assert "observe-sess-a" in ids
        assert "observe-sess-b" in ids

    def test_observe_sandbox_contracts_merged(self):
        """Observe-mode sandbox rules from both guards appear in merged guard."""

        @precondition("*")
        def observe_sb_a(tool_call):
            return Decision.pass_()

        observe_sb_a._edictum_id = "observe-sb-a"
        observe_sb_a._edictum_type = "sandbox"
        observe_sb_a._edictum_tools = ["*"]
        _make_observe(observe_sb_a)

        @precondition("*")
        def observe_sb_b(tool_call):
            return Decision.pass_()

        observe_sb_b._edictum_id = "observe-sb-b"
        observe_sb_b._edictum_type = "sandbox"
        observe_sb_b._edictum_tools = ["*"]
        _make_observe(observe_sb_b)

        g1 = Edictum(mode="enforce", rules=[observe_sb_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", rules=[observe_sb_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.observe_sandbox_contracts]
        assert len(ids) == 2
        assert "observe-sb-a" in ids
        assert "observe-sb-b" in ids

    def test_cross_type_id_collision_does_not_drop_observe(self):
        """An observe-mode rule with the same ID as a regular rule must NOT be dropped."""

        @precondition("Bash")
        def enforced(tool_call):
            return Decision.fail("Enforced")

        enforced._edictum_id = "shared-id"

        @precondition("Bash")
        def observe(tool_call):
            return Decision.fail("Observe-mode")

        observe._edictum_id = "shared-id"
        _make_observe(observe)

        g1 = Edictum(mode="enforce", rules=[enforced], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", rules=[observe], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        assert len(merged._state.preconditions) == 1
        assert len(merged._state.observe_preconditions) == 1
