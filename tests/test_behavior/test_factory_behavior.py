"""Behavior tests for _factory.py — from_multiple() observe-mode contract merging."""

from __future__ import annotations

from edictum import Edictum
from edictum.contracts import Verdict, postcondition, precondition


class _NullSink:
    async def emit(self, event):
        pass


def _make_shadow(fn):
    """Mark a contract function as observe-mode (shadow)."""
    fn._edictum_shadow = True
    return fn


class TestFromMultipleShadowContracts:
    """from_multiple() must merge observe-mode contracts from all guards."""

    def test_shadow_preconditions_merged_from_both_guards(self):
        @precondition("Bash")
        def shadow_pre_a(envelope):
            return Verdict.fail("Shadow pre A")

        shadow_pre_a._edictum_id = "shadow-pre-a"
        _make_shadow(shadow_pre_a)

        @precondition("Write")
        def shadow_pre_b(envelope):
            return Verdict.fail("Shadow pre B")

        shadow_pre_b._edictum_id = "shadow-pre-b"
        _make_shadow(shadow_pre_b)

        g1 = Edictum(mode="enforce", contracts=[shadow_pre_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", contracts=[shadow_pre_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.shadow_preconditions]
        assert len(ids) == 2
        assert "shadow-pre-a" in ids
        assert "shadow-pre-b" in ids
        # Enforced lists should be empty
        assert len(merged._state.preconditions) == 0

    def test_shadow_postconditions_merged(self):
        @postcondition("*")
        def shadow_post_a(envelope, response):
            return Verdict.pass_()

        shadow_post_a._edictum_id = "shadow-post-a"
        _make_shadow(shadow_post_a)

        @postcondition("*")
        def shadow_post_b(envelope, response):
            return Verdict.pass_()

        shadow_post_b._edictum_id = "shadow-post-b"
        _make_shadow(shadow_post_b)

        g1 = Edictum(mode="enforce", contracts=[shadow_post_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", contracts=[shadow_post_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.shadow_postconditions]
        assert len(ids) == 2
        assert "shadow-post-a" in ids
        assert "shadow-post-b" in ids

    def test_mixed_enforce_and_shadow_merged(self):
        """Only one guard has observe-mode contracts; merged guard retains them."""

        @precondition("Bash")
        def enforced_pre(envelope):
            return Verdict.fail("Enforced")

        enforced_pre._edictum_id = "enforced-pre"

        @precondition("Write")
        def shadow_pre(envelope):
            return Verdict.fail("Shadow")

        shadow_pre._edictum_id = "shadow-pre"
        _make_shadow(shadow_pre)

        g_enforce = Edictum(mode="enforce", contracts=[enforced_pre], audit_sink=_NullSink())
        g_observe = Edictum(mode="enforce", contracts=[shadow_pre], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g_enforce, g_observe])

        assert len(merged._state.preconditions) == 1
        assert getattr(merged._state.preconditions[0], "_edictum_id", None) == "enforced-pre"

        assert len(merged._state.shadow_preconditions) == 1
        assert getattr(merged._state.shadow_preconditions[0], "_edictum_id", None) == "shadow-pre"

    def test_shadow_dedup_by_id(self):
        """Duplicate observe-mode contract IDs are deduplicated (first wins)."""

        @precondition("Bash")
        def shadow_a(envelope):
            return Verdict.fail("First")

        shadow_a._edictum_id = "same-id"
        _make_shadow(shadow_a)

        @precondition("Bash")
        def shadow_b(envelope):
            return Verdict.fail("Second")

        shadow_b._edictum_id = "same-id"
        _make_shadow(shadow_b)

        g1 = Edictum(mode="enforce", contracts=[shadow_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", contracts=[shadow_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        assert len(merged._state.shadow_preconditions) == 1

    def test_shadow_session_contracts_merged(self):
        """Shadow session contracts from both guards appear in merged guard."""

        @precondition("*")
        def shadow_sess_a(envelope):
            return Verdict.pass_()

        shadow_sess_a._edictum_id = "shadow-sess-a"
        shadow_sess_a._edictum_type = "session_contract"
        _make_shadow(shadow_sess_a)

        @precondition("*")
        def shadow_sess_b(envelope):
            return Verdict.pass_()

        shadow_sess_b._edictum_id = "shadow-sess-b"
        shadow_sess_b._edictum_type = "session_contract"
        _make_shadow(shadow_sess_b)

        g1 = Edictum(mode="enforce", contracts=[shadow_sess_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", contracts=[shadow_sess_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.shadow_session_contracts]
        assert len(ids) == 2
        assert "shadow-sess-a" in ids
        assert "shadow-sess-b" in ids

    def test_shadow_sandbox_contracts_merged(self):
        """Shadow sandbox contracts from both guards appear in merged guard."""

        @precondition("*")
        def shadow_sb_a(envelope):
            return Verdict.pass_()

        shadow_sb_a._edictum_id = "shadow-sb-a"
        shadow_sb_a._edictum_type = "sandbox"
        shadow_sb_a._edictum_tools = ["*"]
        _make_shadow(shadow_sb_a)

        @precondition("*")
        def shadow_sb_b(envelope):
            return Verdict.pass_()

        shadow_sb_b._edictum_id = "shadow-sb-b"
        shadow_sb_b._edictum_type = "sandbox"
        shadow_sb_b._edictum_tools = ["*"]
        _make_shadow(shadow_sb_b)

        g1 = Edictum(mode="enforce", contracts=[shadow_sb_a], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", contracts=[shadow_sb_b], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.shadow_sandbox_contracts]
        assert len(ids) == 2
        assert "shadow-sb-a" in ids
        assert "shadow-sb-b" in ids

    def test_cross_type_id_collision_does_not_drop_shadow(self):
        """A shadow contract with the same ID as a regular contract must NOT be dropped."""

        @precondition("Bash")
        def enforced(envelope):
            return Verdict.fail("Enforced")

        enforced._edictum_id = "shared-id"

        @precondition("Bash")
        def shadow(envelope):
            return Verdict.fail("Shadow")

        shadow._edictum_id = "shared-id"
        _make_shadow(shadow)

        g1 = Edictum(mode="enforce", contracts=[enforced], audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", contracts=[shadow], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])

        assert len(merged._state.preconditions) == 1
        assert len(merged._state.shadow_preconditions) == 1
