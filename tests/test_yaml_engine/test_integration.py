"""End-to-end integration tests for YAML rule engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from edictum import Edictum, EdictumConfigError, EdictumDenied
from edictum.rules import Decision, precondition
from edictum.envelope import create_envelope

FIXTURES = Path(__file__).parent / "fixtures"


class NullAuditSink:
    """Collects audit events for inspection."""

    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


class TestFromYaml:
    def test_creates_guard(self):
        guard = Edictum.from_yaml(FIXTURES / "valid_bundle.yaml")
        assert guard is not None
        assert guard.mode == "enforce"

    def test_policy_version_set(self):
        guard = Edictum.from_yaml(FIXTURES / "valid_bundle.yaml")
        assert guard.policy_version is not None
        assert len(guard.policy_version) == 64  # SHA256 hex

    def test_mode_override(self):
        guard = Edictum.from_yaml(FIXTURES / "valid_bundle.yaml", mode="observe")
        assert guard.mode == "observe"

    def test_limits_from_yaml(self):
        guard = Edictum.from_yaml(FIXTURES / "valid_bundle.yaml")
        assert guard.limits.max_tool_calls == 50
        assert guard.limits.max_attempts == 120

    def test_preconditions_loaded(self):
        guard = Edictum.from_yaml(FIXTURES / "valid_bundle.yaml")
        env = create_envelope("read_file", {"path": ".env"})
        preconditions = guard.get_preconditions(env)
        assert len(preconditions) == 1

    def test_postconditions_loaded(self):
        guard = Edictum.from_yaml(FIXTURES / "valid_bundle.yaml")
        env = create_envelope("some_tool", {})
        postconditions = guard.get_postconditions(env)
        assert len(postconditions) == 1  # wildcard tool

    def test_invalid_yaml_raises(self):
        with pytest.raises(EdictumConfigError):
            Edictum.from_yaml(FIXTURES / "invalid_missing_apiversion.yaml")

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            Edictum.from_yaml(FIXTURES / "nonexistent.yaml")


class TestFromTemplate:
    def test_template_not_found_raises(self):
        with pytest.raises(EdictumConfigError, match="Template 'nonexistent' not found"):
            Edictum.from_template("nonexistent")


class TestEndToEndDeny:
    async def test_yaml_precondition_denies(self):
        sink = NullAuditSink()
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=sink,
        )
        with pytest.raises(EdictumDenied) as exc_info:
            await guard.run(
                "read_file",
                {"path": "/home/.env"},
                lambda path: f"contents of {path}",
            )
        assert ".env" in str(exc_info.value) or "denied" in str(exc_info.value).lower()

    async def test_yaml_precondition_allows(self):
        sink = NullAuditSink()
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=sink,
        )
        result = await guard.run(
            "read_file",
            {"path": "/home/readme.md"},
            lambda path: f"contents of {path}",
        )
        assert result == "contents of /home/readme.md"

    async def test_non_matching_tool_passes(self):
        sink = NullAuditSink()
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=sink,
        )
        result = await guard.run(
            "write_file",
            {"path": ".env", "content": "test"},
            lambda path, content: "ok",
        )
        assert result == "ok"


class TestPolicyVersionInAudit:
    async def test_policy_version_stamped_on_allow(self):
        sink = NullAuditSink()
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=sink,
        )
        await guard.run(
            "write_file",
            {"path": "readme.md"},
            lambda path: "ok",
        )
        assert len(sink.events) >= 1
        for event in sink.events:
            assert event.policy_version == guard.policy_version

    async def test_policy_version_stamped_on_deny(self):
        sink = NullAuditSink()
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=sink,
        )
        with pytest.raises(EdictumDenied):
            await guard.run(
                "read_file",
                {"path": ".env"},
                lambda path: "contents",
            )
        assert len(sink.events) >= 1
        assert sink.events[0].policy_version == guard.policy_version


ENV_BUNDLE_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: env-test
defaults:
  mode: enforce
rules:
  - id: dry-run-block
    type: pre
    tool: "*"
    when:
      all:
        - env.DRY_RUN: { equals: true }
        - tool.name: { in: [Bash, Write] }
    then:
      action: block
      message: "Dry run mode — modifications denied"
"""


class TestEnvSelectorIntegration:
    """End-to-end tests for env.* selectors loaded from YAML."""

    async def test_env_precondition_denies_when_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DRY_RUN", "true")
        bundle_path = tmp_path / "env_bundle.yaml"
        bundle_path.write_text(ENV_BUNDLE_YAML)

        sink = NullAuditSink()
        guard = Edictum.from_yaml(bundle_path, audit_sink=sink)

        with pytest.raises(EdictumDenied, match="Dry run mode"):
            await guard.run("Bash", {"command": "rm -rf /"}, lambda **kw: "ok")

    async def test_env_precondition_allows_when_unset(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DRY_RUN", raising=False)
        bundle_path = tmp_path / "env_bundle.yaml"
        bundle_path.write_text(ENV_BUNDLE_YAML)

        sink = NullAuditSink()
        guard = Edictum.from_yaml(bundle_path, audit_sink=sink)

        result = await guard.run("Bash", {"command": "echo hello"}, lambda **kw: "hello")
        assert result == "hello"

    async def test_env_precondition_allows_non_matching_tool(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DRY_RUN", "true")
        bundle_path = tmp_path / "env_bundle.yaml"
        bundle_path.write_text(ENV_BUNDLE_YAML)

        sink = NullAuditSink()
        guard = Edictum.from_yaml(bundle_path, audit_sink=sink)

        result = await guard.run("read_file", {"path": "/tmp/test"}, lambda **kw: "contents")
        assert result == "contents"

    def test_env_evaluate_dry_run(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DRY_RUN", "true")
        bundle_path = tmp_path / "env_bundle.yaml"
        bundle_path.write_text(ENV_BUNDLE_YAML)

        guard = Edictum.from_yaml(bundle_path)
        result = guard.evaluate("Write", {"path": "/tmp/file", "content": "data"})
        assert result.decision == "block"
        assert any("Dry run mode" in r.message for r in result.rules if r.message)


ENV_MESSAGE_TEMPLATE_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: env-message-test
defaults:
  mode: enforce
rules:
  - id: env-message-expand
    type: pre
    tool: "*"
    when:
      env.BLOCK_REASON: { exists: true }
    then:
      action: block
      message: "Denied: {env.BLOCK_REASON}"
"""

ENV_POSTCONDITION_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: env-post-test
defaults:
  mode: enforce
rules:
  - id: env-post-check
    type: post
    tool: "*"
    when:
      all:
        - env.AUDIT_STRICT: { equals: true }
        - output.text: { contains: "secret" }
    then:
      action: warn
      message: "Strict audit: sensitive output detected"
"""


class TestEnvSelectorEdgeCases:
    """Edge case integration tests for env.* selectors."""

    def test_env_message_template_expansion(self, tmp_path, monkeypatch):
        """Message templates can expand {env.FOO} placeholders."""
        monkeypatch.setenv("BLOCK_REASON", "maintenance window")
        bundle_path = tmp_path / "env_msg.yaml"
        bundle_path.write_text(ENV_MESSAGE_TEMPLATE_YAML)

        guard = Edictum.from_yaml(bundle_path)
        result = guard.evaluate("Bash", {"command": "deploy"})
        assert result.decision == "block"
        assert "maintenance window" in result.deny_reasons[0]

    def test_env_message_template_unset_keeps_placeholder(self, tmp_path, monkeypatch):
        """When env var is unset, message placeholder is kept as-is."""
        monkeypatch.delenv("BLOCK_REASON", raising=False)
        bundle_path = tmp_path / "env_msg.yaml"
        bundle_path.write_text(ENV_MESSAGE_TEMPLATE_YAML)

        guard = Edictum.from_yaml(bundle_path)
        result = guard.evaluate("Bash", {"command": "deploy"})
        # Rule doesn't fire because env.BLOCK_REASON doesn't exist
        assert result.decision == "allow"

    def test_env_postcondition_with_output(self, tmp_path, monkeypatch):
        """env.* in postcondition when clause works alongside output.text."""
        monkeypatch.setenv("AUDIT_STRICT", "true")
        bundle_path = tmp_path / "env_post.yaml"
        bundle_path.write_text(ENV_POSTCONDITION_YAML)

        guard = Edictum.from_yaml(bundle_path)
        # Both env and output match → should warn
        result = guard.evaluate("Read", {"path": "/tmp/x"}, output="contains secret data")
        assert result.decision == "warn"

    def test_env_postcondition_unset_no_warn(self, tmp_path, monkeypatch):
        """Postcondition with env.* doesn't fire when env var is unset."""
        monkeypatch.delenv("AUDIT_STRICT", raising=False)
        bundle_path = tmp_path / "env_post.yaml"
        bundle_path.write_text(ENV_POSTCONDITION_YAML)

        guard = Edictum.from_yaml(bundle_path)
        result = guard.evaluate("Read", {"path": "/tmp/x"}, output="contains secret data")
        assert result.decision == "allow"


class TestYamlVsPythonEquivalence:
    """Verify YAML-loaded guard produces identical verdicts to equivalent Python rules."""

    async def test_equivalent_verdicts(self):
        # YAML guard
        yaml_sink = NullAuditSink()
        yaml_guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=yaml_sink,
        )

        # Equivalent Python guard
        @precondition("read_file")
        def block_sensitive_reads(tool_call):
            path = tool_call.args.get("path", "")
            if any(s in path for s in [".env", ".secret"]):
                return Decision.fail(f"Sensitive file '{path}' denied.")
            return Decision.pass_()

        python_sink = NullAuditSink()
        python_guard = Edictum(
            mode="enforce",
            rules=[block_sensitive_reads],
            audit_sink=python_sink,
        )

        # Both should block .env reads
        with pytest.raises(EdictumDenied):
            await yaml_guard.run(
                "read_file",
                {"path": "/home/.env"},
                lambda path: "contents",
            )

        with pytest.raises(EdictumDenied):
            await python_guard.run(
                "read_file",
                {"path": "/home/.env"},
                lambda path: "contents",
            )

        # Both should allow readme reads
        yaml_result = await yaml_guard.run(
            "read_file",
            {"path": "/home/readme.md"},
            lambda path: "readme contents",
        )
        python_result = await python_guard.run(
            "read_file",
            {"path": "/home/readme.md"},
            lambda path: "readme contents",
        )
        assert yaml_result == python_result == "readme contents"

    async def test_observe_mode_yaml(self):
        sink = NullAuditSink()
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            mode="observe",
            audit_sink=sink,
        )
        # Should NOT raise in observe mode, even on .env
        result = await guard.run(
            "read_file",
            {"path": "/home/.env"},
            lambda path: f"contents of {path}",
        )
        assert "contents" in result
        # Audit event should show would_deny
        deny_events = [e for e in sink.events if e.action.value == "call_would_deny"]
        assert len(deny_events) == 1
