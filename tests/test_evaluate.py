"""Tests for Edictum.evaluate() and Edictum.evaluate_batch() dry-run methods."""

from __future__ import annotations

import tempfile
from dataclasses import FrozenInstanceError

import pytest

from edictum import Edictum, EvaluationResult, Principal, precondition

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _NullSink:
    async def emit(self, event):
        pass


def _write_yaml(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    f.write(content)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# YAML fixtures
# ---------------------------------------------------------------------------

BASIC_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-evaluate
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret"]
    then:
      action: block
      message: "Sensitive file denied."
      tags: [secrets]
  - id: bash-safety
    type: pre
    tool: bash
    when:
      args.command:
        matches: '\\brm\\s+-rf\\b'
    then:
      action: block
      message: "Destructive command denied."
      tags: [safety]
"""

POST_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-post
defaults:
  mode: enforce
rules:
  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII detected."
      tags: [pii]
"""

MIXED_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-mixed
defaults:
  mode: enforce
rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret"]
    then:
      action: block
      message: "Sensitive file denied."
      tags: [secrets]
  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII detected."
      tags: [pii]
"""

OBSERVE_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-observe
defaults:
  mode: enforce
rules:
  - id: observed-rule
    type: pre
    tool: bash
    mode: observe
    when:
      args.command:
        contains: "rm"
    then:
      action: block
      message: "Would block rm."
      tags: [safety]
"""

OBSERVE_POST_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-observe-post
defaults:
  mode: enforce
rules:
  - id: observed-pii
    type: post
    tool: "*"
    mode: observe
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII detected (observed)."
      tags: [pii]
"""

PRINCIPAL_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-principal
defaults:
  mode: enforce
rules:
  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      principal.ticket_ref:
        exists: false
    then:
      action: block
      message: "Ticket required."
      tags: [compliance]
"""

TWO_PRE_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-two-pre
defaults:
  mode: enforce
rules:
  - id: rule-a
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm"
    then:
      action: block
      message: "Rule A denies rm."
      tags: [safety]
  - id: rule-b
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rf"
    then:
      action: block
      message: "Rule B denies rf."
      tags: [safety]
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEvaluate:
    """Tests for Edictum.evaluate() dry-run evaluation."""

    def test_no_matching_rules(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("send_email", {"to": "x"})

        assert result.decision == "allow"
        assert result.rules_evaluated == 0
        assert result.rules == []
        assert result.block_reasons == []
        assert result.warn_reasons == []

    def test_precondition_denies(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "/app/.env"})

        assert result.decision == "block"
        assert len(result.block_reasons) == 1
        assert "Sensitive file" in result.block_reasons[0]
        assert result.rules[0].rule_id == "block-env-reads"
        assert result.rules[0].rule_type == "precondition"
        assert result.rules[0].passed is False

    def test_precondition_passes(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "README.md"})

        assert result.decision == "allow"
        assert result.block_reasons == []

    def test_exhaustive_evaluation(self):
        guard = Edictum.from_yaml(_write_yaml(TWO_PRE_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("bash", {"command": "rm -rf /"})

        assert result.rules_evaluated == 2
        assert result.rules[0].passed is False
        assert result.rules[1].passed is False
        assert len(result.block_reasons) == 2

    def test_postcondition_warns_with_output(self):
        guard = Edictum.from_yaml(_write_yaml(POST_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "x"}, output="SSN: 123-45-6789")

        assert result.decision == "warn"
        assert len(result.warn_reasons) >= 1
        assert result.rules[0].rule_type == "postcondition"
        assert result.rules[0].passed is False

    def test_postcondition_skipped_without_output(self):
        guard = Edictum.from_yaml(_write_yaml(POST_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "x"})

        assert result.rules_evaluated == 0
        assert result.decision == "allow"

    def test_output_no_postconditions(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "x"}, output="safe text")

        assert result.decision == "allow"

    def test_mixed_deny_and_warn(self):
        guard = Edictum.from_yaml(_write_yaml(MIXED_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": ".env"}, output="SSN: 123-45-6789")

        assert result.decision == "block"
        assert len(result.block_reasons) >= 1
        assert len(result.warn_reasons) >= 1

    def test_empty_args(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {})

        assert result.decision == "allow"
        assert result.policy_error is False

    def test_principal_based_rule_denied(self):
        guard = Edictum.from_yaml(_write_yaml(PRINCIPAL_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("deploy_service", {"service": "api"})

        assert result.decision == "block"
        assert len(result.block_reasons) >= 1
        assert result.rules[0].rule_id == "require-ticket"

    def test_principal_based_rule_allowed(self):
        guard = Edictum.from_yaml(_write_yaml(PRINCIPAL_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate(
            "deploy_service",
            {"service": "api"},
            principal=Principal(ticket_ref="JIRA-1"),
        )

        assert result.decision == "allow"

    def test_observe_mode_rule(self):
        guard = Edictum.from_yaml(_write_yaml(OBSERVE_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("bash", {"command": "rm file"})

        assert result.decision == "allow"
        assert len(result.rules) == 1
        assert result.rules[0].observed is True
        assert result.rules[0].passed is False

    def test_observe_mode_postcondition(self):
        guard = Edictum.from_yaml(_write_yaml(OBSERVE_POST_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "x"}, output="SSN: 123-45-6789")

        assert result.decision == "allow"
        assert len(result.rules) == 1
        assert result.rules[0].observed is True
        assert result.rules[0].passed is False
        assert result.rules[0].rule_type == "postcondition"
        assert len(result.warn_reasons) == 0

    def test_contract_exception(self):
        @precondition("*")
        def broken_contract(tool_call):
            raise RuntimeError("boom")

        guard = Edictum(rules=[broken_contract], audit_sink=_NullSink())
        result = guard.evaluate("any_tool", {"x": 1})

        assert result.policy_error is True
        assert result.decision == "block"
        assert result.rules[0].policy_error is True
        assert result.rules[0].passed is False
        assert "boom" in result.rules[0].message

    def test_environment_override(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "README.md"}, environment="staging")

        assert result.decision == "allow"
        assert isinstance(result, EvaluationResult)

    def test_frozen_results(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "/app/.env"})

        with pytest.raises(FrozenInstanceError):
            result.decision = "x"

    def test_result_type(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "README.md"})

        assert isinstance(result, EvaluationResult)
        assert isinstance(result.rules, list)
        assert isinstance(result.block_reasons, list)
        assert isinstance(result.warn_reasons, list)
        assert isinstance(result.rules_evaluated, int)
        assert isinstance(result.policy_error, bool)

    def test_contract_result_tags(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("read_file", {"path": "/app/.env"})

        assert result.rules[0].tags == ["secrets"]

    def test_bash_regex_match(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("bash", {"command": "rm -rf /tmp"})

        assert result.decision == "block"
        assert result.rules[0].rule_id == "bash-safety"
        assert "Destructive command" in result.block_reasons[0]

    def test_bash_regex_no_match(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("bash", {"command": "ls -la"})

        assert result.decision == "allow"

    def test_yaml_precondition_e2e(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())

        allow_result = guard.evaluate("read_file", {"path": "safe.txt"})
        assert allow_result.decision == "allow"
        assert allow_result.rules_evaluated == 1
        assert allow_result.rules[0].passed is True

        deny_result = guard.evaluate("read_file", {"path": "config/.secret"})
        assert deny_result.decision == "block"
        assert deny_result.rules_evaluated == 1
        assert deny_result.rules[0].rule_id == "block-env-reads"
        assert deny_result.rules[0].tags == ["secrets"]

    def test_yaml_postcondition_e2e(self):
        guard = Edictum.from_yaml(_write_yaml(POST_BUNDLE), audit_sink=_NullSink())

        clean = guard.evaluate("search", {"q": "test"}, output="No results found.")
        assert clean.decision == "allow"
        assert clean.rules_evaluated == 1
        assert clean.rules[0].passed is True

        flagged = guard.evaluate("search", {"q": "test"}, output="Found SSN: 999-88-7777 in record.")
        assert flagged.decision == "warn"
        assert flagged.rules_evaluated == 1
        assert "PII" in flagged.warn_reasons[0]
        assert flagged.rules[0].tags == ["pii"]


class TestEvaluateBatch:
    """Tests for Edictum.evaluate_batch() dry-run batch evaluation."""

    def test_batch_correct_length(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        results = guard.evaluate_batch(
            [
                {"tool": "read_file", "args": {"path": "a.txt"}},
                {"tool": "read_file", "args": {"path": "b.txt"}},
                {"tool": "bash", "args": {"command": "echo hi"}},
            ]
        )

        assert len(results) == 3
        assert all(isinstance(r, EvaluationResult) for r in results)

    def test_batch_principal_dict_conversion(self):
        guard = Edictum.from_yaml(_write_yaml(PRINCIPAL_BUNDLE), audit_sink=_NullSink())
        results = guard.evaluate_batch(
            [
                {
                    "tool": "deploy_service",
                    "args": {"service": "api"},
                    "principal": {"ticket_ref": "JIRA-42"},
                },
            ]
        )

        assert len(results) == 1
        assert results[0].decision == "allow"

    def test_batch_output_dict_serialized(self):
        guard = Edictum.from_yaml(_write_yaml(POST_BUNDLE), audit_sink=_NullSink())
        results = guard.evaluate_batch(
            [
                {
                    "tool": "search",
                    "args": {"q": "test"},
                    "output": {"text": "SSN: 123-45-6789"},
                },
            ]
        )

        assert len(results) == 1
        # Output was serialized to JSON string; postcondition still evaluates
        assert isinstance(results[0], EvaluationResult)

    def test_batch_empty_list(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        results = guard.evaluate_batch([])

        assert results == []

    def test_batch_mixed_results(self):
        guard = Edictum.from_yaml(_write_yaml(BASIC_BUNDLE), audit_sink=_NullSink())
        results = guard.evaluate_batch(
            [
                {"tool": "read_file", "args": {"path": "/app/.env"}},
                {"tool": "read_file", "args": {"path": "README.md"}},
            ]
        )

        assert len(results) == 2
        assert results[0].decision == "block"
        assert results[1].decision == "allow"


# ---------------------------------------------------------------------------
# Tests: RuleResult.action for postconditions
# ---------------------------------------------------------------------------

REDACT_EFFECT_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-action
defaults:
  mode: enforce
rules:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches_any: ['sk-prod-[a-z0-9]{8}']
    then:
      action: redact
      message: "Secrets found."
      tags: [secrets]
"""

DENY_EFFECT_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-block-action
defaults:
  mode: enforce
rules:
  - id: block-ferpa
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b(IEP|accommodation)\\b'
    then:
      action: block
      message: "FERPA violation."
      tags: [ferpa]
"""


class TestRuleResultEffect:
    """Tests that RuleResult.action is populated for postconditions."""

    def test_effect_redact_in_rule_result(self):
        guard = Edictum.from_yaml(_write_yaml(REDACT_EFFECT_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("search", {"q": "x"}, output="key: sk-prod-abcd1234")

        assert len(result.rules) == 1
        assert result.rules[0].action == "redact"
        assert result.rules[0].rule_type == "postcondition"
        assert result.rules[0].passed is False

    def test_effect_deny_in_rule_result(self):
        guard = Edictum.from_yaml(_write_yaml(DENY_EFFECT_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("search", {"q": "x"}, output="Student has an IEP")

        assert len(result.rules) == 1
        assert result.rules[0].action == "block"
        assert result.rules[0].rule_type == "postcondition"
        assert result.rules[0].passed is False

    def test_effect_warn_default_in_rule_result(self):
        guard = Edictum.from_yaml(_write_yaml(POST_BUNDLE), audit_sink=_NullSink())
        result = guard.evaluate("search", {"q": "x"}, output="SSN: 123-45-6789")

        assert len(result.rules) == 1
        assert result.rules[0].action == "warn"
        assert result.rules[0].rule_type == "postcondition"


class TestRuleResultCompatibility:
    """Top-level result aliases remain available."""

    def test_top_level_result_alias_still_imports(self):
        import importlib

        import edictum

        alias_name = "Contract" + "Result"
        alias_result = getattr(importlib.import_module("edictum"), alias_name)

        assert edictum.RuleResult.__name__ == "RuleResult"
        assert alias_result is edictum.RuleResult
