"""Tests for Edictum.from_yaml() multi-path composition."""

from __future__ import annotations

import pytest

from edictum import Edictum, EdictumConfigError, EdictumDenied
from edictum.envelope import create_envelope
from edictum.yaml_engine.composer import CompositionReport

# ---------------------------------------------------------------------------
# YAML fixtures as strings
# ---------------------------------------------------------------------------

BASE_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: base-bundle
defaults:
  mode: enforce
rules:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret"]
    then:
      action: block
      message: "Sensitive file denied"
      tags: [secrets]
"""

OVERRIDE_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: override-bundle
defaults:
  mode: enforce
rules:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".pem"]
    then:
      action: block
      message: "PEM file denied"
      tags: [override]
"""

EXTRA_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: extra-bundle
defaults:
  mode: enforce
rules:
  - id: block-exec
    type: pre
    tool: execute
    when:
      args.command:
        contains: "rm -rf"
    then:
      action: block
      message: "Dangerous command denied"
      tags: [safety]
"""

OBSERVE_ALONGSIDE_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: candidate-bundle
observe_alongside: true
defaults:
  mode: enforce
rules:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".key"]
    then:
      action: block
      message: "Key file denied (candidate)"
      tags: [candidate]
"""


class NullAuditSink:
    """Collects audit events for inspection."""

    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


def _write_yaml(tmp_path, name, content):
    """Write a YAML string to a file and return the path."""
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSinglePathBackwardCompat:
    """from_yaml(single_path) behaves exactly as before."""

    def test_creates_guard(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        guard = Edictum.from_yaml(base)
        assert guard is not None
        assert guard.mode == "enforce"

    def test_policy_version_is_sha256(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        guard = Edictum.from_yaml(base)
        assert guard.policy_version is not None
        assert len(guard.policy_version) == 64

    def test_preconditions_loaded(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        guard = Edictum.from_yaml(base)
        env = create_envelope("read_file", {"path": ".env"})
        assert len(guard.get_preconditions(env)) == 1

    async def test_denies_sensitive_file(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        sink = NullAuditSink()
        guard = Edictum.from_yaml(base, audit_sink=sink)
        with pytest.raises(EdictumDenied, match="Sensitive file denied"):
            await guard.run("read_file", {"path": "/x/.env"}, lambda path: "data")


class TestTwoPaths:
    """Base + override compose correctly."""

    def test_override_replaces_contract(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        override = _write_yaml(tmp_path, "override.yaml", OVERRIDE_BUNDLE)
        guard = Edictum.from_yaml(base, override)

        # The overridden rule should block .pem, not .env
        env_pem = create_envelope("read_file", {"path": "key.pem"})
        preconditions = guard.get_preconditions(env_pem)
        assert len(preconditions) == 1

        # .env should no longer be denied (overridden)
        result = guard.evaluate("read_file", {"path": "app.env"})
        assert result.decision == "allow"

        # .pem should be denied
        result = guard.evaluate("read_file", {"path": "cert.pem"})
        assert result.decision == "block"

    def test_combined_policy_version(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        override = _write_yaml(tmp_path, "override.yaml", OVERRIDE_BUNDLE)
        guard = Edictum.from_yaml(base, override)

        # Policy version should be a SHA256 of combined hashes
        assert guard.policy_version is not None
        assert len(guard.policy_version) == 64

        # Should differ from single-path version
        single_guard = Edictum.from_yaml(base)
        assert guard.policy_version != single_guard.policy_version


class TestThreePaths:
    """Multiple layers stack correctly."""

    def test_three_layer_composition(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        override = _write_yaml(tmp_path, "override.yaml", OVERRIDE_BUNDLE)
        extra = _write_yaml(tmp_path, "extra.yaml", EXTRA_BUNDLE)
        guard = Edictum.from_yaml(base, override, extra)

        # Override replaced block-sensitive-reads → .pem denied, .env not
        result = guard.evaluate("read_file", {"path": "cert.pem"})
        assert result.decision == "block"
        result = guard.evaluate("read_file", {"path": "app.env"})
        assert result.decision == "allow"

        # Extra layer added block-exec
        result = guard.evaluate("execute", {"command": "rm -rf /"})
        assert result.decision == "block"
        assert "Dangerous command" in result.block_reasons[0]

    def test_three_path_policy_version(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        override = _write_yaml(tmp_path, "override.yaml", OVERRIDE_BUNDLE)
        extra = _write_yaml(tmp_path, "extra.yaml", EXTRA_BUNDLE)
        guard = Edictum.from_yaml(base, override, extra)
        assert len(guard.policy_version) == 64


class TestObserveAlongside:
    """Load a YAML with observe_alongside: true, verify observe-mode rules."""

    def test_observe_rules_created(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        candidate = _write_yaml(tmp_path, "candidate.yaml", OBSERVE_ALONGSIDE_BUNDLE)
        guard, report = Edictum.from_yaml(base, candidate, return_report=True)

        # Observe-mode rule should be in the report
        assert len(report.observe_rules) == 1
        assert report.observe_rules[0].rule_id == "block-sensitive-reads"

    def test_observe_rules_in_observe_mode(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        candidate = _write_yaml(tmp_path, "candidate.yaml", OBSERVE_ALONGSIDE_BUNDLE)
        guard = Edictum.from_yaml(base, candidate)

        # Original rule still works -- .env denied
        result = guard.evaluate("read_file", {"path": "app.env"})
        assert result.decision == "block"

        # Observe-mode rules are routed to separate lists
        env = create_envelope("read_file", {"path": "test.key"})
        preconditions = guard.get_preconditions(env)
        observe_preconditions = guard.get_observe_preconditions(env)
        # Original precondition in main list
        assert len(preconditions) == 1
        # Observe-mode :candidate in observe list
        assert len(observe_preconditions) == 1
        assert getattr(observe_preconditions[0], "_edictum_observe", False) is True


class TestReturnReport:
    """return_report flag behavior."""

    def test_return_report_with_multiple_paths(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        override = _write_yaml(tmp_path, "override.yaml", OVERRIDE_BUNDLE)
        result = Edictum.from_yaml(base, override, return_report=True)

        assert isinstance(result, tuple)
        guard, report = result
        assert isinstance(guard, Edictum)
        assert isinstance(report, CompositionReport)
        assert len(report.overridden_rules) == 1
        assert report.overridden_rules[0].rule_id == "block-sensitive-reads"

    def test_return_report_with_single_path(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        result = Edictum.from_yaml(base, return_report=True)

        assert isinstance(result, tuple)
        guard, report = result
        assert isinstance(guard, Edictum)
        assert isinstance(report, CompositionReport)
        assert report.overridden_rules == []
        assert report.observe_rules == []

    def test_without_return_report(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        result = Edictum.from_yaml(base)
        assert isinstance(result, Edictum)


class TestModeOverride:
    """mode= parameter still overrides the bundle default."""

    def test_mode_override_single_path(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        guard = Edictum.from_yaml(base, mode="observe")
        assert guard.mode == "observe"

    def test_mode_override_multiple_paths(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        override = _write_yaml(tmp_path, "override.yaml", OVERRIDE_BUNDLE)
        guard = Edictum.from_yaml(base, override, mode="observe")
        assert guard.mode == "observe"

    async def test_observe_mode_does_not_deny(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        sink = NullAuditSink()
        guard = Edictum.from_yaml(base, mode="observe", audit_sink=sink)
        # Should NOT raise in observe mode
        result = await guard.run("read_file", {"path": "/x/.env"}, lambda path: "data")
        assert result == "data"


class TestEdgeCases:
    """Edge cases and error handling."""

    def test_no_paths_raises(self):
        with pytest.raises(EdictumConfigError, match="at least one path"):
            Edictum.from_yaml()

    def test_multi_path_with_path_objects(self, tmp_path):
        """from_yaml accepts pathlib.Path objects (not just strings)."""
        from pathlib import Path

        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        override = _write_yaml(tmp_path, "override.yaml", OVERRIDE_BUNDLE)
        # Pass Path objects, not strings
        guard = Edictum.from_yaml(Path(base), Path(override))
        result = guard.evaluate("read_file", {"path": "cert.pem"})
        assert result.decision == "block"

    def test_multi_path_nonexistent_second_file(self, tmp_path):
        """Second file doesn't exist — should raise clear error."""
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        with pytest.raises(FileNotFoundError):
            Edictum.from_yaml(base, tmp_path / "nonexistent.yaml")


class TestEvaluateDryRunExcludesObserveMode:
    """evaluate() must NOT include observe-mode rules in dry-run results."""

    def test_evaluate_ignores_observe_rules(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        candidate = _write_yaml(tmp_path, "candidate.yaml", OBSERVE_ALONGSIDE_BUNDLE)
        guard = Edictum.from_yaml(base, candidate)

        # .key triggers observe-mode but not enforced. evaluate() should allow.
        result = guard.evaluate("read_file", {"path": "app.key"})
        assert result.decision == "allow"

        # .env triggers enforced. evaluate() should block.
        result = guard.evaluate("read_file", {"path": "app.env"})
        assert result.decision == "block"

    def test_evaluate_does_not_report_observe_rules(self, tmp_path):
        base = _write_yaml(tmp_path, "base.yaml", BASE_BUNDLE)
        candidate = _write_yaml(tmp_path, "candidate.yaml", OBSERVE_ALONGSIDE_BUNDLE)
        guard = Edictum.from_yaml(base, candidate)

        result = guard.evaluate("read_file", {"path": "app.key"})
        # Observe-mode rules should not appear in rules_evaluated
        rule_ids = [r.rule_id for r in result.rules]
        assert not any(":candidate" in cid for cid in rule_ids)


class TestFromTemplateBackwardCompat:
    """from_template() must still work after from_yaml signature change."""

    def test_from_template_still_works(self):
        """from_template passes a single Path to from_yaml — must not break."""
        try:
            guard = Edictum.from_template("file-agent")
            assert guard is not None
            assert guard.mode in ("enforce", "observe")
        except EdictumConfigError as e:
            if "Template" in str(e) and "not found" in str(e):
                pytest.skip("file-agent template not available")
            raise
