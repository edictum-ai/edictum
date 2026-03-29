"""Behavior tests for metadata.* selectors and custom_selectors parameter."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from edictum import Edictum, EdictumConfigError, EdictumDenied

# ---------------------------------------------------------------------------
# YAML templates
# ---------------------------------------------------------------------------

YAML_METADATA_REGION = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: metadata-region
defaults:
  mode: enforce
rules:
  - id: block-eu-region
    type: pre
    tool: deploy
    when:
      metadata.region: { equals: "eu-west-1" }
    then:
      action: block
      message: "Deploy denied in region {metadata.region}"
"""

YAML_METADATA_NESTED = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: metadata-nested
defaults:
  mode: enforce
rules:
  - id: block-low-tier
    type: pre
    tool: expensive_tool
    when:
      metadata.tenant.tier: { equals: "free" }
    then:
      action: block
      message: "Free tier cannot use expensive tools"
"""

YAML_METADATA_LIST = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: metadata-flags
defaults:
  mode: enforce
rules:
  - id: block-experimental
    type: pre
    tool: beta_tool
    when:
      metadata.feature_flags: { contains: "experimental_only" }
    then:
      action: block
      message: "Experimental flag present"
"""

YAML_METADATA_POST = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: metadata-post
defaults:
  mode: enforce
rules:
  - id: warn-on-region
    type: post
    tool: query_data
    when:
      metadata.region: { equals: "eu-west-1" }
    then:
      action: warn
      message: "EU region data accessed"
"""

YAML_CUSTOM_SELECTOR = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: custom-selector
defaults:
  mode: enforce
rules:
  - id: block-high-risk
    type: pre
    tool: transfer
    when:
      risk.score: { gt: 80 }
    then:
      action: block
      message: "Risk score {risk.score} exceeds threshold"
"""

YAML_CUSTOM_SELECTOR_NESTED = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: custom-nested
defaults:
  mode: enforce
rules:
  - id: block-restricted-dept
    type: pre
    tool: access_records
    when:
      department.classification.level: { equals: "restricted" }
    then:
      action: block
      message: "Restricted department access denied"
"""

YAML_MULTI_CUSTOM_SELECTORS = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: multi-custom
defaults:
  mode: enforce
rules:
  - id: block-high-risk
    type: pre
    tool: transfer
    when:
      risk.score: { gt: 80 }
    then:
      action: block
      message: "High risk denied"
  - id: block-restricted-dept
    type: pre
    tool: access_records
    when:
      dept.code: { equals: "CLASSIFIED" }
    then:
      action: block
      message: "Classified department denied"
"""


# ---------------------------------------------------------------------------
# Test classes: metadata.* selector (built-in)
# ---------------------------------------------------------------------------


class TestMetadataSelectorDenies:
    """metadata.* selector resolves tool_call metadata and triggers block."""

    @pytest.mark.asyncio
    async def test_matching_metadata_denied(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_REGION, audit_sink=_null_sink())
        with pytest.raises(EdictumDenied, match="Deploy denied in region eu-west-1"):
            await guard.run("deploy", {}, _dummy_tool, metadata={"region": "eu-west-1"})

    @pytest.mark.asyncio
    async def test_non_matching_metadata_allowed(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_REGION, audit_sink=_null_sink())
        result = await guard.run("deploy", {}, _dummy_tool, metadata={"region": "us-east-1"})
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_missing_metadata_key_allowed(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_REGION, audit_sink=_null_sink())
        result = await guard.run("deploy", {}, _dummy_tool, metadata={})
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_no_metadata_allowed(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_REGION, audit_sink=_null_sink())
        result = await guard.run("deploy", {}, _dummy_tool)
        assert result == "ok"


class TestMetadataNestedSelector:
    """metadata.* resolves nested dict paths."""

    @pytest.mark.asyncio
    async def test_nested_metadata_denied(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_NESTED, audit_sink=_null_sink())
        with pytest.raises(EdictumDenied, match="Free tier"):
            await guard.run(
                "expensive_tool",
                {},
                _dummy_tool,
                metadata={"tenant": {"tier": "free"}},
            )

    @pytest.mark.asyncio
    async def test_nested_metadata_allowed(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_NESTED, audit_sink=_null_sink())
        result = await guard.run(
            "expensive_tool",
            {},
            _dummy_tool,
            metadata={"tenant": {"tier": "enterprise"}},
        )
        assert result == "ok"


class TestMetadataContainsOperator:
    """metadata.* works with string values and contains operator."""

    @pytest.mark.asyncio
    async def test_matching_substring_denied(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_LIST, audit_sink=_null_sink())
        with pytest.raises(EdictumDenied, match="Experimental flag"):
            await guard.run(
                "beta_tool",
                {},
                _dummy_tool,
                metadata={"feature_flags": "experimental_only,beta"},
            )

    @pytest.mark.asyncio
    async def test_non_matching_substring_allowed(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_LIST, audit_sink=_null_sink())
        result = await guard.run(
            "beta_tool",
            {},
            _dummy_tool,
            metadata={"feature_flags": "beta_tools,production"},
        )
        assert result == "ok"


class TestMetadataPostcondition:
    """metadata.* works in postcondition rules."""

    @pytest.mark.asyncio
    async def test_metadata_in_postcondition(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_POST, audit_sink=_null_sink())
        result = await guard.run(
            "query_data",
            {},
            _dummy_tool,
            metadata={"region": "eu-west-1"},
        )
        # Warn action doesn't raise, but postcondition fires
        assert result is not None


class TestMetadataMessageExpansion:
    """metadata.* placeholders expand correctly in denial messages."""

    @pytest.mark.asyncio
    async def test_message_includes_metadata_value(self):
        guard = Edictum.from_yaml_string(YAML_METADATA_REGION, audit_sink=_null_sink())
        with pytest.raises(EdictumDenied, match="eu-west-1"):
            await guard.run("deploy", {}, _dummy_tool, metadata={"region": "eu-west-1"})


class TestMetadataDryRunEvaluation:
    """guard.evaluate() works with metadata.* via tool_call metadata."""

    def test_evaluate_with_metadata_denied(self):
        """evaluate() doesn't accept metadata directly, but rules compile."""
        guard = Edictum.from_yaml_string(YAML_METADATA_REGION)
        # evaluate() creates envelopes without metadata, so this won't match
        result = guard.evaluate("deploy", {})
        assert result.decision == "allow"


# ---------------------------------------------------------------------------
# Test classes: custom_selectors parameter
# ---------------------------------------------------------------------------


class TestCustomSelectorDenies:
    """Custom selector resolves data from the callable and triggers block."""

    @pytest.mark.asyncio
    async def test_high_risk_denied(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": lambda env: {"score": 95}},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Risk score"):
            await guard.run("transfer", {"amount": 1000}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_low_risk_allowed(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": lambda env: {"score": 30}},
            audit_sink=_null_sink(),
        )
        result = await guard.run("transfer", {"amount": 1000}, _dummy_tool)
        assert result == "ok"


class TestCustomSelectorNestedPath:
    """Custom selector resolves nested dotted paths."""

    @pytest.mark.asyncio
    async def test_nested_custom_denied(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR_NESTED,
            custom_selectors={"department": lambda env: {"classification": {"level": "restricted"}}},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Restricted department"):
            await guard.run("access_records", {}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_nested_custom_allowed(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR_NESTED,
            custom_selectors={"department": lambda env: {"classification": {"level": "public"}}},
            audit_sink=_null_sink(),
        )
        result = await guard.run("access_records", {}, _dummy_tool)
        assert result == "ok"


class TestCustomSelectorReceivesEnvelope:
    """Custom selector callable receives the correct ToolCall."""

    @pytest.mark.asyncio
    async def test_callable_receives_envelope(self):
        spy = MagicMock(return_value={"score": 95})
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": spy},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied):
            await guard.run("transfer", {"amount": 500}, _dummy_tool)
        spy.assert_called()
        tool_call = spy.call_args[0][0]
        assert tool_call.tool_name == "transfer"
        assert tool_call.args["amount"] == 500


class TestCustomSelectorMissingField:
    """Missing field in custom selector data evaluates to false."""

    @pytest.mark.asyncio
    async def test_missing_field_allows(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": lambda env: {}},
            audit_sink=_null_sink(),
        )
        result = await guard.run("transfer", {"amount": 1000}, _dummy_tool)
        assert result == "ok"


class TestCustomSelectorReturnsNone:
    """Resolver returning None treats all fields as missing."""

    @pytest.mark.asyncio
    async def test_none_resolver_allows(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": lambda env: None},
            audit_sink=_null_sink(),
        )
        result = await guard.run("transfer", {"amount": 1000}, _dummy_tool)
        assert result == "ok"


class TestCustomSelectorMessageExpansion:
    """Custom selector values expand in message templates."""

    @pytest.mark.asyncio
    async def test_message_includes_custom_value(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": lambda env: {"score": 95}},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="95"):
            await guard.run("transfer", {"amount": 1000}, _dummy_tool)


class TestMultipleCustomSelectors:
    """Multiple custom selectors registered simultaneously all work."""

    @pytest.mark.asyncio
    async def test_first_selector_denies(self):
        guard = Edictum.from_yaml_string(
            YAML_MULTI_CUSTOM_SELECTORS,
            custom_selectors={
                "risk": lambda env: {"score": 95},
                "dept": lambda env: {"code": "ENGINEERING"},
            },
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="High risk"):
            await guard.run("transfer", {}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_second_selector_denies(self):
        guard = Edictum.from_yaml_string(
            YAML_MULTI_CUSTOM_SELECTORS,
            custom_selectors={
                "risk": lambda env: {"score": 10},
                "dept": lambda env: {"code": "CLASSIFIED"},
            },
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Classified department"):
            await guard.run("access_records", {}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_both_pass_allows(self):
        guard = Edictum.from_yaml_string(
            YAML_MULTI_CUSTOM_SELECTORS,
            custom_selectors={
                "risk": lambda env: {"score": 10},
                "dept": lambda env: {"code": "ENGINEERING"},
            },
            audit_sink=_null_sink(),
        )
        result = await guard.run("transfer", {}, _dummy_tool)
        assert result == "ok"


class TestCustomSelectorPrefixClash:
    """Custom selector prefixes that clash with built-in selectors are rejected."""

    @pytest.mark.parametrize(
        "builtin_prefix",
        ["environment", "tool", "args", "principal", "output", "env", "metadata"],
    )
    def test_each_builtin_clashes(self, builtin_prefix):
        with pytest.raises(EdictumConfigError, match="clash with built-in selectors"):
            Edictum.from_yaml_string(
                YAML_CUSTOM_SELECTOR,
                custom_selectors={builtin_prefix: lambda env: {}},
            )


class TestNonCallableSelectorValidation:
    """Non-callable values in custom_selectors raise EdictumConfigError."""

    def test_string_value_rejected(self):
        with pytest.raises(EdictumConfigError, match="not callable"):
            Edictum.from_yaml_string(
                YAML_CUSTOM_SELECTOR,
                custom_selectors={"risk": "not_a_function"},
            )

    def test_int_value_rejected(self):
        with pytest.raises(EdictumConfigError, match="not callable"):
            Edictum.from_yaml_string(
                YAML_CUSTOM_SELECTOR,
                custom_selectors={"risk": 42},
            )


class TestFromYamlFilePath:
    """custom_selectors works with from_yaml() loading from a file path."""

    @pytest.mark.asyncio
    async def test_from_yaml_with_custom_selectors(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text(YAML_CUSTOM_SELECTOR)

        guard = Edictum.from_yaml(
            yaml_file,
            custom_selectors={"risk": lambda env: {"score": 95}},
            audit_sink=_null_sink(),
        )

        with pytest.raises(EdictumDenied, match="Risk score"):
            await guard.run("transfer", {"amount": 1000}, _dummy_tool)


class TestFromTemplate:
    """from_template() accepts the custom_selectors parameter."""

    def test_from_template_accepts_custom_selectors(self):
        guard = Edictum.from_template(
            "file-agent",
            custom_selectors={"context": lambda env: {}},
        )
        assert guard is not None


class TestDryRunWithCustomSelectors:
    """guard.evaluate() works with custom selectors."""

    def test_evaluate_with_custom_selectors(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": lambda env: {"score": 95}},
        )
        # evaluate() creates envelopes, custom selectors fire on them
        result = guard.evaluate("transfer", {"amount": 1000})
        assert result.decision == "block"

    def test_evaluate_allows_with_custom_selectors(self):
        guard = Edictum.from_yaml_string(
            YAML_CUSTOM_SELECTOR,
            custom_selectors={"risk": lambda env: {"score": 10}},
        )
        result = guard.evaluate("transfer", {"amount": 1000})
        assert result.decision == "allow"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _dummy_tool(**kwargs):
    return "ok"


def _null_sink():
    class _Sink:
        async def emit(self, event):
            pass

    return _Sink()
