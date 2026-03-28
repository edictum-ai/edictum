"""Tests for YAML tools: section and from_yaml(tools=...) parameter."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from edictum import Edictum, EdictumConfigError, CheckPipeline, SideEffect, create_envelope
from edictum.envelope import BashClassifier, ToolRegistry
from edictum.pipeline import PostDecision

FIXTURES = Path(__file__).parent / "test_yaml_engine" / "fixtures"

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
    return create_envelope(tool_name=tool_name, tool_input={}, registry=registry)


async def _post_execute(guard: Edictum, tool_call, tool_response: str) -> PostDecision:
    pipeline = CheckPipeline(guard)
    return await pipeline.post_execute(tool_call, tool_response, True)


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    """Verify the JSON schema accepts/rejects tools: section correctly."""

    def test_valid_bundle_with_tools_loads(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle_with_tools.yaml",
            audit_sink=_NullSink(),
        )
        assert guard is not None

    def test_tools_invalid_side_effect_rejected(self):
        with pytest.raises(EdictumConfigError):
            Edictum.from_yaml(
                FIXTURES / "invalid_tools_bad_side_effect.yaml",
                audit_sink=_NullSink(),
            )

    def test_tools_invalid_structure_rejected(self):
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bad-tools-structure
defaults:
  mode: enforce
tools: "not-an-object"
rules:
  - id: placeholder
    type: pre
    tool: "*"
    when:
      args.path:
        exists: true
    then:
      action: block
      message: "Denied."
"""
        with pytest.raises(EdictumConfigError):
            Edictum.from_yaml(_write_yaml(yaml_content), audit_sink=_NullSink())

    def test_tools_empty_object_allowed(self):
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: empty-tools
defaults:
  mode: enforce
tools: {}
rules:
  - id: placeholder
    type: pre
    tool: "*"
    when:
      args.path:
        exists: true
    then:
      action: block
      message: "Denied."
"""
        guard = Edictum.from_yaml(_write_yaml(yaml_content), audit_sink=_NullSink())
        assert guard is not None

    def test_bundle_without_tools_still_loads(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=_NullSink(),
        )
        assert guard is not None


# ---------------------------------------------------------------------------
# from_yaml() registry integration
# ---------------------------------------------------------------------------


class TestFromYamlRegistry:
    """Verify from_yaml populates ToolRegistry from YAML and params."""

    def test_from_yaml_tools_section_populates_registry(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle_with_tools.yaml",
            audit_sink=_NullSink(),
        )
        se, idem = guard.tool_registry.classify("read_config", {})
        assert se == SideEffect.READ

    def test_from_yaml_tools_classifies_correctly(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle_with_tools.yaml",
            audit_sink=_NullSink(),
        )
        se_pure, idem_pure = guard.tool_registry.classify("get_weather", {})
        assert se_pure == SideEffect.PURE
        assert idem_pure is True

        se_irrev, idem_irrev = guard.tool_registry.classify("deploy", {})
        assert se_irrev == SideEffect.IRREVERSIBLE
        assert idem_irrev is False

    def test_from_yaml_tools_param_populates_registry(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            tools={"my_tool": {"side_effect": "pure"}},
            audit_sink=_NullSink(),
        )
        se, _ = guard.tool_registry.classify("my_tool", {})
        assert se == SideEffect.PURE

    def test_from_yaml_tools_param_overrides_yaml(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle_with_tools.yaml",
            tools={"read_config": {"side_effect": "write"}},
            audit_sink=_NullSink(),
        )
        se, _ = guard.tool_registry.classify("read_config", {})
        assert se == SideEffect.WRITE

    def test_from_yaml_tools_param_merges_with_yaml(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle_with_tools.yaml",
            tools={"extra_tool": {"side_effect": "pure", "idempotent": True}},
            audit_sink=_NullSink(),
        )
        # From YAML
        se_yaml, _ = guard.tool_registry.classify("read_config", {})
        assert se_yaml == SideEffect.READ

        # From param
        se_param, idem_param = guard.tool_registry.classify("extra_tool", {})
        assert se_param == SideEffect.PURE
        assert idem_param is True

    def test_from_yaml_without_tools_empty_registry(self):
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=_NullSink(),
        )
        # Unregistered tool defaults to IRREVERSIBLE
        se, _ = guard.tool_registry.classify("anything", {})
        assert se == SideEffect.IRREVERSIBLE


# ---------------------------------------------------------------------------
# End-to-end: YAML tools + postcondition effects
# ---------------------------------------------------------------------------


REDACT_WITH_TOOLS = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: e2e-redact-tools
defaults:
  mode: enforce
tools:
  read_config:
    side_effect: read
rules:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches: 'sk-[a-zA-Z0-9]{10,}'
    then:
      action: redact
      message: "API key detected."
"""

DENY_WITH_TOOLS = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: e2e-block-tools
defaults:
  mode: enforce
tools:
  search_db:
    side_effect: pure
rules:
  - id: block-pii
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: block
      message: "PII detected — suppressing output."
"""


class TestE2EToolsAndEffects:
    """The key tests: YAML tools enable postcondition redact/block."""

    @pytest.mark.asyncio
    async def test_yaml_tools_read_enables_redact(self):
        guard = Edictum.from_yaml(_write_yaml(REDACT_WITH_TOOLS), audit_sink=_NullSink())
        tool_call = create_envelope(
            tool_name="read_config",
            tool_input={},
            registry=guard.tool_registry,
        )
        assert tool_call.side_effect == SideEffect.READ

        post = await _post_execute(guard, tool_call, "key: sk-liveABC12345xyz")
        assert post.redacted_response is not None
        assert "sk-liveABC12345xyz" not in post.redacted_response

    @pytest.mark.asyncio
    async def test_yaml_tools_pure_enables_deny(self):
        guard = Edictum.from_yaml(_write_yaml(DENY_WITH_TOOLS), audit_sink=_NullSink())
        tool_call = create_envelope(
            tool_name="search_db",
            tool_input={},
            registry=guard.tool_registry,
        )
        assert tool_call.side_effect == SideEffect.PURE

        post = await _post_execute(guard, tool_call, "SSN: 123-45-6789")
        assert post.redacted_response is not None
        assert "[OUTPUT SUPPRESSED]" in post.redacted_response

    @pytest.mark.asyncio
    async def test_yaml_tools_write_redact_falls_back(self):
        """Write side_effect should cause redact to fall back to warn."""
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: write-fallback
defaults:
  mode: enforce
tools:
  update_record:
    side_effect: write
rules:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches: 'sk-[a-zA-Z0-9]{10,}'
    then:
      action: redact
      message: "API key detected."
"""
        guard = Edictum.from_yaml(_write_yaml(yaml_content), audit_sink=_NullSink())
        tool_call = create_envelope(
            tool_name="update_record",
            tool_input={},
            registry=guard.tool_registry,
        )
        assert tool_call.side_effect == SideEffect.WRITE

        post = await _post_execute(guard, tool_call, "key: sk-liveABC12345xyz")
        # Falls back to warn — no redaction applied
        assert post.redacted_response is None
        assert not post.postconditions_passed

    @pytest.mark.asyncio
    async def test_no_tools_section_redact_falls_back(self):
        """Without tools section, unregistered tool defaults to IRREVERSIBLE → warn."""
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: no-tools
defaults:
  mode: enforce
rules:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches: 'sk-[a-zA-Z0-9]{10,}'
    then:
      action: redact
      message: "API key detected."
"""
        guard = Edictum.from_yaml(_write_yaml(yaml_content), audit_sink=_NullSink())
        tool_call = create_envelope(
            tool_name="some_tool",
            tool_input={},
            registry=guard.tool_registry,
        )
        assert tool_call.side_effect == SideEffect.IRREVERSIBLE

        post = await _post_execute(guard, tool_call, "key: sk-liveABC12345xyz")
        # Falls back to warn — no redaction
        assert post.redacted_response is None
        assert not post.postconditions_passed


# ---------------------------------------------------------------------------
# guard.run() integration
# ---------------------------------------------------------------------------


class TestRunIntegration:
    """Verify guard.run() returns redacted/suppressed responses correctly."""

    @pytest.mark.asyncio
    async def test_run_with_yaml_tools_returns_redacted(self):
        guard = Edictum.from_yaml(_write_yaml(REDACT_WITH_TOOLS), audit_sink=_NullSink())

        async def fake_tool(**kwargs):
            return "result: sk-liveABC12345xyz"

        result = await guard.run("read_config", {}, fake_tool)
        assert "sk-liveABC12345xyz" not in result

    @pytest.mark.asyncio
    async def test_run_without_tools_returns_original(self):
        """Without tools section, redact falls back — original result returned."""
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: no-tools-run
defaults:
  mode: enforce
rules:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches: 'sk-[a-zA-Z0-9]{10,}'
    then:
      action: redact
      message: "API key detected."
"""
        guard = Edictum.from_yaml(_write_yaml(yaml_content), audit_sink=_NullSink())

        async def fake_tool(**kwargs):
            return "result: sk-liveABC12345xyz"

        result = await guard.run("unknown_tool", {}, fake_tool)
        # Falls back to warn — original result returned
        assert "sk-liveABC12345xyz" in result


# ---------------------------------------------------------------------------
# Post-construction register (demo user's workaround)
# ---------------------------------------------------------------------------


class TestPostRegister:
    """Validate that registering tools after from_yaml() works."""

    @pytest.mark.asyncio
    async def test_post_register_after_from_yaml_enables_redact(self):
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: post-register
defaults:
  mode: enforce
rules:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches: 'sk-[a-zA-Z0-9]{10,}'
    then:
      action: redact
      message: "API key detected."
"""
        guard = Edictum.from_yaml(_write_yaml(yaml_content), audit_sink=_NullSink())

        # Register after construction
        guard.tool_registry.register("my_reader", side_effect=SideEffect.READ)

        tool_call = create_envelope(
            tool_name="my_reader",
            tool_input={},
            registry=guard.tool_registry,
        )
        assert tool_call.side_effect == SideEffect.READ

        post = await _post_execute(guard, tool_call, "key: sk-liveABC12345xyz")
        assert post.redacted_response is not None
        assert "sk-liveABC12345xyz" not in post.redacted_response


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases for tool registry interactions."""

    @pytest.mark.asyncio
    async def test_bash_classifier_overrides_yaml_tools(self):
        """BashClassifier still applies for bash tools regardless of YAML registry."""
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bash-override
defaults:
  mode: enforce
tools:
  bash:
    side_effect: read
rules:
  - id: redact-secrets
    type: post
    tool: "*"
    when:
      output.text:
        matches: 'sk-[a-zA-Z0-9]{10,}'
    then:
      action: redact
      message: "API key detected."
"""
        guard = Edictum.from_yaml(_write_yaml(yaml_content), audit_sink=_NullSink())

        # Registry classifies bash as READ per YAML
        se, _ = guard.tool_registry.classify("bash", {})
        assert se == SideEffect.READ

        # But BashClassifier independently classifies commands
        assert BashClassifier.classify("rm -rf /tmp/test") == SideEffect.IRREVERSIBLE

    @pytest.mark.asyncio
    async def test_wildcard_contract_specific_tool_registry(self):
        """tool: '*' rule works with specific tool in registry."""
        guard = Edictum.from_yaml(
            FIXTURES / "valid_tools_and_redact.yaml",
            audit_sink=_NullSink(),
        )

        # read_config is registered as 'read' → redact works
        tool_call = create_envelope(
            tool_name="read_config",
            tool_input={},
            registry=guard.tool_registry,
        )
        post = await _post_execute(guard, tool_call, "found: sk-liveABCDEFGHIJ")
        assert post.redacted_response is not None
        assert "sk-liveABCDEFGHIJ" not in post.redacted_response

        # unregistered_tool defaults to IRREVERSIBLE → redact falls back
        envelope2 = create_envelope(
            tool_name="unregistered_tool",
            tool_input={},
            registry=guard.tool_registry,
        )
        post2 = await _post_execute(guard, envelope2, "found: sk-liveABCDEFGHIJ")
        assert post2.redacted_response is None
