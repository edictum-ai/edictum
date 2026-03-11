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

        ids = [getattr(c, "_edictum_id", None) for c in merged._shadow_preconditions]
        assert len(ids) == 2
        assert "shadow-pre-a" in ids
        assert "shadow-pre-b" in ids
        # Enforced lists should be empty
        assert len(merged._preconditions) == 0

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

        ids = [getattr(c, "_edictum_id", None) for c in merged._shadow_postconditions]
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

        assert len(merged._preconditions) == 1
        assert getattr(merged._preconditions[0], "_edictum_id", None) == "enforced-pre"

        assert len(merged._shadow_preconditions) == 1
        assert getattr(merged._shadow_preconditions[0], "_edictum_id", None) == "shadow-pre"

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

        assert len(merged._shadow_preconditions) == 1
