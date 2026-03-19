"""Tests for postcondition effects: redact, deny, warn."""

from __future__ import annotations

import tempfile

import pytest

from edictum import Edictum, GovernancePipeline, SideEffect, create_envelope
from edictum.envelope import ToolRegistry
from edictum.pipeline import PostDecision

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


def _make_envelope(tool_name: str = "search", side_effect: SideEffect = SideEffect.READ):
    registry = ToolRegistry()
    registry.register(tool_name, side_effect=side_effect)
    return create_envelope(
        tool_name=tool_name,
        tool_input={},
        registry=registry,
    )


async def _post_execute(guard: Edictum, envelope, tool_response: str) -> PostDecision:
    pipeline = GovernancePipeline(guard)
    return await pipeline.post_execute(envelope, tool_response, True)


# ---------------------------------------------------------------------------
# YAML fixtures
# ---------------------------------------------------------------------------

REDACT_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-redact
defaults:
  mode: enforce
contracts:
  - id: secrets-redact
    type: post
    tool: "*"
    when:
      output.text:
        matches_any: ['sk-prod-[a-z0-9]{8}', 'AKIA-PROD-[A-Z]{12}']
    then:
      effect: redact
      message: "Secrets detected and redacted."
      tags: [secrets]
"""

DENY_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-deny
defaults:
  mode: enforce
contracts:
  - id: accommodation-deny
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b(504\\s*Plan|IEP|accommodation)\\b'
    then:
      effect: deny
      message: "Accommodation info cannot be returned."
      tags: [ferpa]
"""

WARN_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-warn
defaults:
  mode: enforce
contracts:
  - id: pii-warn
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII detected in output."
      tags: [pii]
"""

OBSERVE_REDACT_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-observe-redact
defaults:
  mode: enforce
contracts:
  - id: observed-redact
    type: post
    tool: "*"
    mode: observe
    when:
      output.text:
        matches_any: ['sk-prod-[a-z0-9]{8}']
    then:
      effect: redact
      message: "Secrets detected (observed)."
      tags: [secrets]
"""

MULTI_REDACT_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-multi-redact
defaults:
  mode: enforce
contracts:
  - id: redact-api-keys
    type: post
    tool: "*"
    when:
      output.text:
        matches_any: ['sk-prod-[a-z0-9]{8}']
    then:
      effect: redact
      message: "API keys redacted."
      tags: [secrets]
  - id: redact-aws-keys
    type: post
    tool: "*"
    when:
      output.text:
        matches_any: ['AKIA-PROD-[A-Z]{12}']
    then:
      effect: redact
      message: "AWS keys redacted."
      tags: [secrets]
"""

DENY_AFTER_REDACT_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-deny-after-redact
defaults:
  mode: enforce
contracts:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches_any: ['sk-prod-[a-z0-9]{8}']
    then:
      effect: redact
      message: "Secrets redacted."
      tags: [secrets]
  - id: deny-accommodation
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b(accommodation)\\b'
    then:
      effect: deny
      message: "Accommodation info suppressed."
      tags: [ferpa]
"""

NESTED_EXPR_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-nested
defaults:
  mode: enforce
contracts:
  - id: nested-redact
    type: post
    tool: "*"
    when:
      any:
        - output.text:
            matches: 'sk-prod-[a-z0-9]{8}'
        - all:
            - output.text:
                matches_any: ['AKIA-PROD-[A-Z]{12}', 'ghp_[a-zA-Z0-9]{36}']
    then:
      effect: redact
      message: "Secrets detected in nested expression."
      tags: [secrets]
"""

NO_PATTERN_REDACT_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-no-pattern
defaults:
  mode: enforce
contracts:
  - id: generic-redact
    type: post
    tool: "*"
    when:
      output.text:
        contains: "secret_value"
    then:
      effect: redact
      message: "Sensitive data found."
      tags: [secrets]
"""


# ---------------------------------------------------------------------------
# Tests: effect: redact
# ---------------------------------------------------------------------------


class TestRedactEffect:
    """Tests for effect: redact postcondition behavior."""

    @pytest.mark.asyncio
    async def test_redact_read_removes_patterns(self):
        """effect: redact + SideEffect.READ -> redacted_response has [REDACTED], patterns removed."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found key: sk-prod-abcd1234 and more text"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is not None
        assert "[REDACTED]" in decision.redacted_response
        assert "sk-prod-abcd1234" not in decision.redacted_response
        assert "more text" in decision.redacted_response
        assert not decision.output_suppressed

    @pytest.mark.asyncio
    async def test_redact_pure_removes_patterns(self):
        """effect: redact + SideEffect.PURE -> same behavior as READ."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.PURE)
        response = "Key is AKIA-PROD-ABCDEFGHIJKL in config"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is not None
        assert "[REDACTED]" in decision.redacted_response
        assert "AKIA-PROD-ABCDEFGHIJKL" not in decision.redacted_response
        assert "config" in decision.redacted_response
        assert not decision.output_suppressed

    @pytest.mark.asyncio
    async def test_redact_write_falls_back_to_warn(self):
        """effect: redact + SideEffect.WRITE -> redacted_response is None, warning mentions 'Tool already executed'."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.WRITE)
        response = "Found key: sk-prod-abcd1234"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert not decision.output_suppressed
        assert len(decision.warnings) >= 1
        assert any("Tool already executed" in w for w in decision.warnings)

    @pytest.mark.asyncio
    async def test_redact_irreversible_falls_back_to_warn(self):
        """effect: redact + SideEffect.IRREVERSIBLE -> same as WRITE, falls back to warn."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.IRREVERSIBLE)
        response = "Found key: sk-prod-abcd1234"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert any("Tool already executed" in w for w in decision.warnings)

    @pytest.mark.asyncio
    async def test_redact_multiple_patterns(self):
        """Multiple matches_any patterns are all redacted."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Keys: sk-prod-abcd1234 and AKIA-PROD-ABCDEFGHIJKL found"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is not None
        assert "sk-prod-abcd1234" not in decision.redacted_response
        assert "AKIA-PROD-ABCDEFGHIJKL" not in decision.redacted_response
        assert "[REDACTED]" in decision.redacted_response

    @pytest.mark.asyncio
    async def test_redact_no_match_passes(self):
        """When redact rule doesn't match, no redaction occurs."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "This is safe output with no secrets"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert decision.postconditions_passed is True
        assert len(decision.warnings) == 0

    @pytest.mark.asyncio
    async def test_redact_warning_mentions_contract_name(self):
        """Redaction warning includes the contract name."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found key: sk-prod-abcd1234"

        decision = await _post_execute(guard, envelope, response)

        assert any("secrets-redact" in w for w in decision.warnings)


# ---------------------------------------------------------------------------
# Tests: effect: deny
# ---------------------------------------------------------------------------


class TestDenyEffect:
    """Tests for effect: deny postcondition behavior."""

    @pytest.mark.asyncio
    async def test_deny_read_suppresses_output(self):
        """effect: deny + READ -> suppressed output, output_suppressed True."""
        guard = Edictum.from_yaml(_write_yaml(DENY_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Student has an IEP with specific accommodation requirements"

        decision = await _post_execute(guard, envelope, response)

        assert decision.output_suppressed is True
        assert decision.redacted_response is not None
        assert decision.redacted_response.startswith("[OUTPUT SUPPRESSED]")
        assert "Accommodation info cannot be returned" in decision.redacted_response

    @pytest.mark.asyncio
    async def test_deny_pure_suppresses_output(self):
        """effect: deny + SideEffect.PURE -> same as READ, full suppression."""
        guard = Edictum.from_yaml(_write_yaml(DENY_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.PURE)
        response = "The 504 Plan details are as follows..."

        decision = await _post_execute(guard, envelope, response)

        assert decision.output_suppressed is True
        assert decision.redacted_response.startswith("[OUTPUT SUPPRESSED]")

    @pytest.mark.asyncio
    async def test_deny_write_falls_back_to_warn(self):
        """effect: deny + SideEffect.WRITE -> redacted_response is None, falls back to warn."""
        guard = Edictum.from_yaml(_write_yaml(DENY_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.WRITE)
        response = "Student requires accommodation for testing"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert not decision.output_suppressed
        assert len(decision.warnings) >= 1
        assert any("Tool already executed" in w for w in decision.warnings)

    @pytest.mark.asyncio
    async def test_deny_warning_mentions_contract_name(self):
        """Deny warning includes the contract name."""
        guard = Edictum.from_yaml(_write_yaml(DENY_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Student has an IEP"

        decision = await _post_execute(guard, envelope, response)

        assert any("accommodation-deny" in w for w in decision.warnings)

    @pytest.mark.asyncio
    async def test_deny_no_match_passes(self):
        """When deny rule doesn't match, output passes through."""
        guard = Edictum.from_yaml(_write_yaml(DENY_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Student has good grades and attendance"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert not decision.output_suppressed
        assert decision.postconditions_passed is True


# ---------------------------------------------------------------------------
# Tests: effect: warn (default)
# ---------------------------------------------------------------------------


class TestWarnEffect:
    """Tests for effect: warn (default) postcondition behavior."""

    @pytest.mark.asyncio
    async def test_warn_default_behavior_read(self):
        """effect: warn + SideEffect.READ -> redacted_response is None, warning with 'Consider retrying'."""
        guard = Edictum.from_yaml(_write_yaml(WARN_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found SSN: 123-45-6789"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert not decision.output_suppressed
        assert len(decision.warnings) >= 1
        assert any("Consider retrying" in w for w in decision.warnings)

    @pytest.mark.asyncio
    async def test_warn_default_behavior_write(self):
        """effect: warn + SideEffect.WRITE -> redacted_response is None, warning with 'Tool already executed'."""
        guard = Edictum.from_yaml(_write_yaml(WARN_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.WRITE)
        response = "Wrote SSN: 123-45-6789 to file"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert not decision.output_suppressed
        assert len(decision.warnings) >= 1
        assert any("Tool already executed" in w for w in decision.warnings)

    @pytest.mark.asyncio
    async def test_warn_postconditions_not_passed(self):
        """Warn effect still marks postconditions_passed as False."""
        guard = Edictum.from_yaml(_write_yaml(WARN_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found SSN: 123-45-6789"

        decision = await _post_execute(guard, envelope, response)

        assert not decision.postconditions_passed


# ---------------------------------------------------------------------------
# Tests: observe mode
# ---------------------------------------------------------------------------


class TestObserveModeRedact:
    """Tests for observe mode with redact effect."""

    @pytest.mark.asyncio
    async def test_observe_redact_no_redaction(self):
        """Observe mode + effect: redact -> no redaction, observe warning only."""
        guard = Edictum.from_yaml(_write_yaml(OBSERVE_REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found key: sk-prod-abcd1234"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is None
        assert not decision.output_suppressed
        assert len(decision.warnings) >= 1
        assert any("[observe]" in w for w in decision.warnings)
        # The original secret should NOT appear in redacted_response because it's None
        # (observe mode prevents redaction action)

    @pytest.mark.asyncio
    async def test_observe_redact_postconditions_passed_true(self):
        """Observe mode must NOT affect postconditions_passed.

        postconditions_passed propagates to on_postcondition_warn in all
        7 adapters. If observe-mode contracts set it to False, observe mode
        silently becomes enforcement — violating the core guarantee.
        """
        guard = Edictum.from_yaml(_write_yaml(OBSERVE_REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found key: sk-prod-abcd1234"

        decision = await _post_execute(guard, envelope, response)

        assert decision.postconditions_passed


# ---------------------------------------------------------------------------
# Tests: multiple postconditions
# ---------------------------------------------------------------------------


class TestMultiplePostconditions:
    """Tests for chained postconditions."""

    @pytest.mark.asyncio
    async def test_second_redact_operates_on_already_redacted(self):
        """Multiple redact postconditions: second operates on already-redacted text."""
        guard = Edictum.from_yaml(_write_yaml(MULTI_REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Keys: sk-prod-abcd1234 and AKIA-PROD-ABCDEFGHIJKL found"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is not None
        assert "sk-prod-abcd1234" not in decision.redacted_response
        assert "AKIA-PROD-ABCDEFGHIJKL" not in decision.redacted_response
        assert decision.redacted_response.count("[REDACTED]") >= 2
        assert len(decision.warnings) == 2

    @pytest.mark.asyncio
    async def test_deny_after_redact_overrides(self):
        """deny after redact overrides with full suppression."""
        guard = Edictum.from_yaml(_write_yaml(DENY_AFTER_REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "sk-prod-abcd1234 accommodation details"

        decision = await _post_execute(guard, envelope, response)

        assert decision.output_suppressed is True
        assert decision.redacted_response.startswith("[OUTPUT SUPPRESSED]")
        assert len(decision.warnings) >= 2


# ---------------------------------------------------------------------------
# Tests: nested expressions
# ---------------------------------------------------------------------------


class TestNestedExpressionPatterns:
    """Tests for regex pattern extraction from nested all/any expressions."""

    @pytest.mark.asyncio
    async def test_nested_any_patterns_extracted(self):
        """Regex patterns correctly extracted from nested any expression."""
        guard = Edictum.from_yaml(_write_yaml(NESTED_EXPR_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found key: sk-prod-abcd1234 in config"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is not None
        assert "sk-prod-abcd1234" not in decision.redacted_response
        assert "[REDACTED]" in decision.redacted_response

    @pytest.mark.asyncio
    async def test_nested_all_patterns_extracted(self):
        """Regex patterns correctly extracted from nested all expression."""
        guard = Edictum.from_yaml(_write_yaml(NESTED_EXPR_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        # This matches the 'any' branch via the 'all' sub-branch
        response = "Found key: AKIA-PROD-ABCDEFGHIJKL in config"

        decision = await _post_execute(guard, envelope, response)

        assert decision.redacted_response is not None
        assert "AKIA-PROD-ABCDEFGHIJKL" not in decision.redacted_response
        assert "[REDACTED]" in decision.redacted_response


# ---------------------------------------------------------------------------
# Tests: fallback to RedactionPolicy
# ---------------------------------------------------------------------------


class TestFallbackToRedactionPolicy:
    """Tests for fallback when no matches/matches_any patterns in when clause."""

    @pytest.mark.asyncio
    async def test_no_pattern_redact_uses_redaction_policy(self):
        """Fallback to RedactionPolicy when no regex patterns in the when expression."""
        guard = Edictum.from_yaml(_write_yaml(NO_PATTERN_REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "The secret_value is exposed here"

        decision = await _post_execute(guard, envelope, response)

        # RedactionPolicy is applied as fallback since no matches/matches_any patterns
        assert decision.redacted_response is not None
        assert len(decision.warnings) >= 1


# ---------------------------------------------------------------------------
# Tests: PostDecision fields
# ---------------------------------------------------------------------------


class TestPostDecisionFields:
    """Tests for PostDecision dataclass fields."""

    @pytest.mark.asyncio
    async def test_contracts_evaluated_populated(self):
        """contracts_evaluated list is populated with contract info."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found key: sk-prod-abcd1234"

        decision = await _post_execute(guard, envelope, response)

        assert len(decision.contracts_evaluated) == 1
        assert decision.contracts_evaluated[0]["name"] == "secrets-redact"
        assert decision.contracts_evaluated[0]["type"] == "postcondition"
        assert decision.contracts_evaluated[0]["passed"] is False

    @pytest.mark.asyncio
    async def test_tool_success_field(self):
        """tool_success is correctly passed through."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        pipeline = GovernancePipeline(guard)
        envelope = _make_envelope(side_effect=SideEffect.READ)

        decision = await pipeline.post_execute(envelope, "safe output", True)
        assert decision.tool_success is True

        decision = await pipeline.post_execute(envelope, "safe output", False)
        assert decision.tool_success is False

    @pytest.mark.asyncio
    async def test_policy_error_false_on_normal(self):
        """policy_error is False for normal evaluation."""
        guard = Edictum.from_yaml(_write_yaml(REDACT_BUNDLE), audit_sink=_NullSink())
        envelope = _make_envelope(side_effect=SideEffect.READ)
        response = "Found key: sk-prod-abcd1234"

        decision = await _post_execute(guard, envelope, response)

        assert decision.policy_error is False
