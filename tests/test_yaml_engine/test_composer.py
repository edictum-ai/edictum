"""Tests for bundle composition."""

from __future__ import annotations

import pytest

from edictum.yaml_engine.composer import (
    ComposedBundle,
    CompositionReport,
    compose_bundles,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_bundle(**overrides) -> dict:
    """Minimal valid bundle dict."""
    b = {
        "apiVersion": "edictum/v1",
        "kind": "Ruleset",
        "metadata": {"name": "base"},
        "defaults": {"mode": "enforce"},
        "rules": [],
    }
    b.update(overrides)
    return b


def _contract(cid: str, ctype: str = "pre", **extra) -> dict:
    """Minimal rule dict."""
    c: dict = {"id": cid, "type": ctype}
    if ctype in ("pre", "post"):
        c.setdefault("tool", "*")
        c.setdefault("when", {"tool.name": {"exists": True}})
        c.setdefault("then", {"action": "block" if ctype == "pre" else "warn", "message": f"msg-{cid}"})
    elif ctype == "session":
        c.setdefault("limits", {"max_tool_calls": 100})
        c.setdefault("then", {"action": "block", "message": f"msg-{cid}"})
    c.update(extra)
    return c


# ---------------------------------------------------------------------------
# compose_bundles() — basic
# ---------------------------------------------------------------------------


class TestComposeBundlesBasic:
    def test_empty_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            compose_bundles()

    def test_single_bundle_passthrough(self):
        b = _base_bundle(rules=[_contract("a")])
        result = compose_bundles((b, "base.yaml"))
        assert isinstance(result, ComposedBundle)
        assert result.bundle["rules"][0]["id"] == "a"
        assert result.report == CompositionReport()

    def test_single_bundle_is_a_copy(self):
        b = _base_bundle(rules=[_contract("a")])
        result = compose_bundles((b, "base.yaml"))
        # Mutating result should not affect original
        result.bundle["rules"][0]["id"] = "mutated"
        assert b["rules"][0]["id"] == "a"


# ---------------------------------------------------------------------------
# Rule merge rules
# ---------------------------------------------------------------------------


class TestContractMerge:
    def test_same_id_replacement(self):
        base = _base_bundle(rules=[_contract("block-rm", then={"action": "block", "message": "old"})])
        override = _base_bundle(rules=[_contract("block-rm", then={"action": "block", "message": "new"})])

        result = compose_bundles((base, "base.yaml"), (override, "override.yaml"))
        rules = result.bundle["rules"]

        assert len(rules) == 1
        assert rules[0]["then"]["message"] == "new"

    def test_same_id_reports_override(self):
        base = _base_bundle(rules=[_contract("block-rm")])
        override = _base_bundle(rules=[_contract("block-rm")])

        result = compose_bundles((base, "base.yaml"), (override, "override.yaml"))

        assert len(result.report.overridden_rules) == 1
        ov = result.report.overridden_rules[0]
        assert ov.rule_id == "block-rm"
        assert ov.overridden_by == "override.yaml"
        assert ov.original_source == "base.yaml"

    def test_unique_id_concatenation(self):
        base = _base_bundle(rules=[_contract("a")])
        layer = _base_bundle(rules=[_contract("b")])

        result = compose_bundles((base, "base"), (layer, "layer"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert ids == ["a", "b"]
        assert len(result.report.overridden_rules) == 0

    def test_mixed_replace_and_append(self):
        base = _base_bundle(rules=[_contract("a"), _contract("b")])
        layer = _base_bundle(rules=[_contract("b"), _contract("c")])

        result = compose_bundles((base, "base"), (layer, "layer"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert ids == ["a", "b", "c"]
        assert len(result.report.overridden_rules) == 1
        assert result.report.overridden_rules[0].rule_id == "b"

    def test_three_layers_last_wins(self):
        b1 = _base_bundle(rules=[_contract("x", then={"action": "block", "message": "v1"})])
        b2 = _base_bundle(rules=[_contract("x", then={"action": "block", "message": "v2"})])
        b3 = _base_bundle(rules=[_contract("x", then={"action": "block", "message": "v3"})])

        result = compose_bundles((b1, "l1"), (b2, "l2"), (b3, "l3"))
        assert result.bundle["rules"][0]["then"]["message"] == "v3"
        assert len(result.report.overridden_rules) == 2


# ---------------------------------------------------------------------------
# defaults.mode merge
# ---------------------------------------------------------------------------


class TestDefaultsMerge:
    def test_later_mode_wins(self):
        base = _base_bundle()
        base["defaults"]["mode"] = "enforce"
        override = _base_bundle()
        override["defaults"]["mode"] = "observe"

        result = compose_bundles((base, "base"), (override, "override"))
        assert result.bundle["defaults"]["mode"] == "observe"

    def test_first_mode_preserved_if_later_omits(self):
        base = _base_bundle()
        base["defaults"]["mode"] = "observe"
        layer = _base_bundle()
        # layer has defaults.mode = "enforce" by helper default, override it
        del layer["defaults"]["mode"]

        result = compose_bundles((base, "base"), (layer, "layer"))
        assert result.bundle["defaults"]["mode"] == "observe"

    def test_environment_later_wins(self):
        base = _base_bundle()
        base["defaults"]["environment"] = "staging"
        override = _base_bundle()
        override["defaults"]["environment"] = "production"

        result = compose_bundles((base, "base"), (override, "override"))
        assert result.bundle["defaults"]["environment"] == "production"


# ---------------------------------------------------------------------------
# limits merge
# ---------------------------------------------------------------------------


class TestLimitsMerge:
    def test_later_limits_replace_entirely(self):
        base = _base_bundle()
        base["limits"] = {"max_tool_calls": 50, "max_attempts": 200}
        override = _base_bundle()
        override["limits"] = {"max_tool_calls": 10}

        result = compose_bundles((base, "base"), (override, "override"))
        assert result.bundle["limits"] == {"max_tool_calls": 10}
        assert "max_attempts" not in result.bundle["limits"]


# ---------------------------------------------------------------------------
# tools merge (deep)
# ---------------------------------------------------------------------------


class TestToolsMerge:
    def test_deep_merge_combines_tools(self):
        base = _base_bundle()
        base["tools"] = {"read_file": {"side_effect": "read"}}
        override = _base_bundle()
        override["tools"] = {"write_file": {"side_effect": "write"}}

        result = compose_bundles((base, "base"), (override, "override"))
        assert "read_file" in result.bundle["tools"]
        assert "write_file" in result.bundle["tools"]

    def test_deep_merge_later_overrides_same_tool(self):
        base = _base_bundle()
        base["tools"] = {"run": {"side_effect": "read"}}
        override = _base_bundle()
        override["tools"] = {"run": {"side_effect": "irreversible"}}

        result = compose_bundles((base, "base"), (override, "override"))
        assert result.bundle["tools"]["run"]["side_effect"] == "irreversible"


# ---------------------------------------------------------------------------
# metadata merge (deep)
# ---------------------------------------------------------------------------


class TestMetadataMerge:
    def test_deep_merge_metadata(self):
        base = _base_bundle()
        base["metadata"] = {"name": "base", "author": "alice"}
        override = _base_bundle()
        override["metadata"] = {"name": "composed", "version": "2"}

        result = compose_bundles((base, "base"), (override, "override"))
        assert result.bundle["metadata"]["name"] == "composed"
        assert result.bundle["metadata"]["author"] == "alice"
        assert result.bundle["metadata"]["version"] == "2"


# ---------------------------------------------------------------------------
# observability merge
# ---------------------------------------------------------------------------


class TestObservabilityMerge:
    def test_later_observability_wins(self):
        base = _base_bundle()
        base["observability"] = {"stdout": True}
        override = _base_bundle()
        override["observability"] = {"file": "audit.jsonl"}

        result = compose_bundles((base, "base"), (override, "override"))
        assert result.bundle["observability"] == {"file": "audit.jsonl"}
        assert "stdout" not in result.bundle["observability"]


# ---------------------------------------------------------------------------
# observe_alongside
# ---------------------------------------------------------------------------


class TestObserveAlongside:
    def test_observe_rules_added_with_candidate_suffix(self):
        base = _base_bundle(rules=[_contract("pharma")])
        candidate = _base_bundle(rules=[_contract("pharma")])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (candidate, "candidate"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert "pharma" in ids
        assert "pharma:candidate" in ids
        assert len(ids) == 2

    def test_observe_contract_forced_to_observe_mode(self):
        base = _base_bundle(rules=[_contract("pharma")])
        candidate = _base_bundle(rules=[_contract("pharma")])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (candidate, "candidate"))
        # Internal _observe flag marks this as an observe-mode copy
        observe = [c for c in result.bundle["rules"] if c["id"] == "pharma:candidate"][0]
        assert observe["mode"] == "observe"
        assert observe["_observe"] is True

    def test_observe_contract_report(self):
        base = _base_bundle(rules=[_contract("pharma")])
        candidate = _base_bundle(rules=[_contract("pharma")])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (candidate, "candidate"))
        assert len(result.report.observe_rules) == 1
        sc = result.report.observe_rules[0]
        assert sc.rule_id == "pharma"
        assert sc.enforced_source == "base"
        assert sc.observed_source == "candidate"

    def test_observe_alongside_does_not_replace_enforced(self):
        base = _base_bundle(rules=[_contract("pharma", then={"action": "block", "message": "original"})])
        candidate = _base_bundle(rules=[_contract("pharma", then={"action": "block", "message": "candidate"})])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (candidate, "candidate"))
        enforced = [c for c in result.bundle["rules"] if c["id"] == "pharma"][0]
        assert enforced["then"]["message"] == "original"
        assert len(result.report.overridden_rules) == 0

    def test_observe_alongside_new_contract_no_enforced_counterpart(self):
        base = _base_bundle(rules=[_contract("existing")])
        candidate = _base_bundle(rules=[_contract("brand-new")])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (candidate, "candidate"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert "existing" in ids
        assert "brand-new:candidate" in ids

        sc = result.report.observe_rules[0]
        assert sc.rule_id == "brand-new"
        assert sc.enforced_source == ""  # no enforced counterpart

    def test_observe_alongside_session_contract_gets_candidate_id(self):
        base = _base_bundle(rules=[_contract("limits", ctype="session")])
        candidate = _base_bundle(rules=[_contract("limits", ctype="session")])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (candidate, "candidate"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert "limits" in ids
        assert "limits:candidate" in ids

    def test_mixed_standard_and_observe_alongside(self):
        base = _base_bundle(rules=[_contract("a"), _contract("b")])
        override = _base_bundle(rules=[_contract("a", then={"action": "block", "message": "replaced"})])
        candidate = _base_bundle(rules=[_contract("b")])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (override, "override"), (candidate, "candidate"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert ids == ["a", "b", "b:candidate"]
        assert len(result.report.overridden_rules) == 1
        assert len(result.report.observe_rules) == 1


# ---------------------------------------------------------------------------
# Edge cases from test review
# ---------------------------------------------------------------------------


class TestComposerEdgeCases:
    """P0/P1 edge cases found by test review."""

    def test_multi_bundle_originals_not_mutated(self):
        """compose_bundles must not mutate the original bundle dicts."""
        base = _base_bundle(rules=[_contract("a")])
        override = _base_bundle(rules=[_contract("a", then={"action": "block", "message": "new"})])
        original_base_msg = base["rules"][0]["then"]["message"]

        compose_bundles((base, "base"), (override, "override"))

        # Originals untouched
        assert base["rules"][0]["then"]["message"] == original_base_msg
        assert override["rules"][0]["then"]["message"] == "new"

    def test_observe_alongside_false_behaves_as_standard(self):
        """observe_alongside: false should merge normally (replace by ID)."""
        base = _base_bundle(rules=[_contract("x", then={"action": "block", "message": "old"})])
        layer = _base_bundle(rules=[_contract("x", then={"action": "block", "message": "new"})])
        layer["observe_alongside"] = False

        result = compose_bundles((base, "base"), (layer, "layer"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert ids == ["x"]
        assert result.bundle["rules"][0]["then"]["message"] == "new"
        assert len(result.report.observe_rules) == 0
        assert len(result.report.overridden_rules) == 1

    def test_empty_contracts_list_in_overlay(self):
        """Layer with empty rules list — should not crash, no overrides."""
        base = _base_bundle(rules=[_contract("a")])
        layer = _base_bundle(rules=[])

        result = compose_bundles((base, "base"), (layer, "layer"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert ids == ["a"]
        assert len(result.report.overridden_rules) == 0

    def test_empty_contracts_in_base(self):
        """Base with empty rules, layer adds new ones."""
        base = _base_bundle(rules=[])
        layer = _base_bundle(rules=[_contract("new-rule")])

        result = compose_bundles((base, "base"), (layer, "layer"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert ids == ["new-rule"]

    def test_observe_alongside_with_empty_contracts(self):
        """observe_alongside bundle with no rules -- no observe-mode rules, no crash."""
        base = _base_bundle(rules=[_contract("a")])
        candidate = _base_bundle(rules=[])
        candidate["observe_alongside"] = True

        result = compose_bundles((base, "base"), (candidate, "candidate"))
        ids = [c["id"] for c in result.bundle["rules"]]
        assert ids == ["a"]
        assert len(result.report.observe_rules) == 0

    def test_observe_alongside_as_first_bundle(self):
        """observe_alongside as the first bundle (unusual but valid)."""
        candidate = _base_bundle(rules=[_contract("x")])
        candidate["observe_alongside"] = True
        normal = _base_bundle(rules=[_contract("y")])

        result = compose_bundles((candidate, "candidate"), (normal, "normal"))
        # First bundle is copied as-is (no observe_alongside processing on first bundle)
        ids = [c["id"] for c in result.bundle["rules"]]
        assert "x" in ids
        assert "y" in ids

    def test_layer_without_defaults_key(self):
        """Layer missing 'defaults' entirely should not crash."""
        base = _base_bundle()
        base["defaults"]["mode"] = "observe"
        layer = _base_bundle(rules=[_contract("b")])
        del layer["defaults"]

        result = compose_bundles((base, "base"), (layer, "layer"))
        assert result.bundle["defaults"]["mode"] == "observe"
