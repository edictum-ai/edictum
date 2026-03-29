"""Behavior tests for from_yaml_string() and load_bundle_string()."""

from __future__ import annotations

import pytest

from edictum import Edictum, EdictumConfigError, EdictumDenied

VALID_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-string-bundle
defaults:
  mode: enforce
rules:
  - id: block-dotenv
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      action: block
      message: "Denied: {args.path}"
"""

VALID_YAML_OBSERVE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-observe
defaults:
  mode: observe
rules:
  - id: block-dotenv
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      action: block
      message: "Denied: {args.path}"
"""


class TestFromYamlStringCreatesGuard:
    """from_yaml_string() creates a working Edictum instance from YAML content."""

    def test_string_input_creates_guard(self):
        guard = Edictum.from_yaml_string(VALID_YAML)
        assert guard is not None
        assert guard.mode == "enforce"
        assert len(guard._state.preconditions) == 1

    def test_bytes_input_creates_guard(self):
        guard = Edictum.from_yaml_string(VALID_YAML.encode("utf-8"))
        assert guard is not None
        assert guard.mode == "enforce"
        assert len(guard._state.preconditions) == 1


class TestFromYamlStringEnforcesContracts:
    """Contracts loaded via from_yaml_string() evaluate correctly."""

    @pytest.mark.asyncio
    async def test_denies_matching_call(self):
        guard = Edictum.from_yaml_string(VALID_YAML, audit_sink=_null_sink())

        with pytest.raises(EdictumDenied, match="Denied: .env"):
            await guard.run("read_file", {"path": ".env"}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_allows_non_matching_call(self):
        guard = Edictum.from_yaml_string(VALID_YAML, audit_sink=_null_sink())

        result = await guard.run("read_file", {"path": "readme.txt"}, _dummy_tool)
        assert result == "ok"


class TestFromYamlStringModeOverride:
    """The mode parameter overrides the YAML default mode."""

    def test_mode_override_changes_guard_mode(self):
        guard = Edictum.from_yaml_string(VALID_YAML, mode="observe")
        assert guard.mode == "observe"

    def test_yaml_mode_used_when_no_override(self):
        guard = Edictum.from_yaml_string(VALID_YAML_OBSERVE)
        assert guard.mode == "observe"


class TestFromYamlStringPolicyVersion:
    """from_yaml_string() computes a policy_version hash."""

    def test_policy_version_set(self):
        guard = Edictum.from_yaml_string(VALID_YAML)
        assert guard.policy_version is not None
        assert len(guard.policy_version) == 64  # SHA256 hex digest

    def test_same_content_same_hash(self):
        guard1 = Edictum.from_yaml_string(VALID_YAML)
        guard2 = Edictum.from_yaml_string(VALID_YAML)
        assert guard1.policy_version == guard2.policy_version

    def test_bytes_and_string_same_hash(self):
        guard_str = Edictum.from_yaml_string(VALID_YAML)
        guard_bytes = Edictum.from_yaml_string(VALID_YAML.encode("utf-8"))
        assert guard_str.policy_version == guard_bytes.policy_version


class TestFromYamlStringErrors:
    """from_yaml_string() raises EdictumConfigError on invalid input."""

    def test_invalid_yaml_raises(self):
        with pytest.raises(EdictumConfigError, match="YAML parse error"):
            Edictum.from_yaml_string("not: valid: yaml: {{{{")

    def test_non_mapping_raises(self):
        with pytest.raises(EdictumConfigError, match="must be a mapping"):
            Edictum.from_yaml_string("- just a list")

    def test_schema_violation_raises(self):
        bad_yaml = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bad
defaults:
  mode: enforce
rules: []
"""
        with pytest.raises(EdictumConfigError, match="Schema validation failed"):
            Edictum.from_yaml_string(bad_yaml)


class TestLoadBundleString:
    """load_bundle_string() in yaml_engine is importable and functional."""

    def test_importable(self):
        from edictum.yaml_engine import load_bundle_string

        data, bundle_hash = load_bundle_string(VALID_YAML)
        assert data["metadata"]["name"] == "test-string-bundle"
        assert len(str(bundle_hash)) == 64


class TestFromYamlStringToolsMerge:
    """The tools parameter merges with YAML tools (parameter wins)."""

    def test_tools_parameter_applied(self):
        yaml_with_tools = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: tools-test
defaults:
  mode: enforce
tools:
  read_file:
    side_effect: read
rules:
  - id: block-dotenv
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      action: block
      message: "Denied"
"""
        guard = Edictum.from_yaml_string(
            yaml_with_tools,
            tools={"custom_tool": {"side_effect": "pure"}},
        )
        # Both YAML tools and parameter tools should be registered
        assert "read_file" in guard.tool_registry._tools
        assert "custom_tool" in guard.tool_registry._tools


# -- Helpers --


async def _dummy_tool(**kwargs):
    return "ok"


def _null_sink():
    class _Sink:
        async def emit(self, event):
            pass

    return _Sink()
