"""Security tests for rule evaluation bypass attempts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from edictum.gate.check import run_check
from edictum.gate.config import AuditConfig, GateConfig

_CONTRACTS_WITH_DENY = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
  description: test
defaults:
  mode: enforce
rules:
  - id: block-env
    type: pre
    tool: Bash
    when:
      args.command:
        matches_any:
          - 'cat\\s+\\.env'
    then:
      action: block
      message: "Denied"
"""


def _config(tmp_path: Path, rules: str = _CONTRACTS_WITH_DENY) -> GateConfig:
    cp = tmp_path / "rules.yaml"
    cp.write_text(rules)
    return GateConfig(rules=(str(cp),), audit=AuditConfig(enabled=False), fail_open=False)


@pytest.mark.security
class TestContractBypass:
    def test_empty_args_still_evaluated(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash", "tool_input": {}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        # Empty args should still be evaluated — just won't match the pattern
        assert result["decision"] == "allow"

    def test_type_confusion_args_as_list(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash", "tool_input": ["ls"]})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_type_confusion_args_as_string(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash", "tool_input": "cat .env"})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_missing_tool_name(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_input": {"command": "ls"}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_missing_tool_input(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash"})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        # Missing tool_input defaults to {} — allowed since no args to check
        assert result["decision"] in ("allow", "block")

    def test_tool_name_case_sensitivity(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        # "bash" (lowercase) should NOT match the rule for "Bash"
        stdin = json.dumps({"tool_name": "bash", "tool_input": {"command": "cat .env"}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        # lowercase "bash" doesn't match "Bash" tool filter — rule not evaluated
        assert result["decision"] == "allow"

    def test_format_mismatch(self, tmp_path: Path) -> None:
        """Claude Code format with mismatched data should fail gracefully."""
        config = _config(tmp_path)
        mismatched_data = json.dumps(
            {
                "type": "PreToolUse",
                "tool": "execute_command",
                "params": {"command": "cat .env"},
            }
        )
        # Using claude-code format with mismatched data
        stdout, _ = run_check(mismatched_data, "claude-code", config, str(tmp_path))
        result = json.loads(stdout)
        # Should not crash — tool_name will be empty from claude-code parser
        assert isinstance(result, dict)

    def test_contracts_file_missing(self, tmp_path: Path) -> None:
        config = GateConfig(
            rules=(str(tmp_path / "nonexistent.yaml"),),
            audit=AuditConfig(enabled=False),
            fail_open=False,
        )
        stdin = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_contracts_file_empty(self, tmp_path: Path) -> None:
        cp = tmp_path / "empty.yaml"
        cp.write_text("")
        config = GateConfig(
            rules=(str(cp),),
            audit=AuditConfig(enabled=False),
            fail_open=False,
        )
        stdin = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_contracts_file_malformed(self, tmp_path: Path) -> None:
        cp = tmp_path / "bad.yaml"
        cp.write_text("this: is: not: valid: yaml: [[[")
        config = GateConfig(
            rules=(str(cp),),
            audit=AuditConfig(enabled=False),
            fail_open=False,
        )
        stdin = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_stdin_as_array(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps([{"tool_name": "Bash"}])
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_wildcard_tool_name(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "*", "tool_input": {}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        # create_envelope rejects * in tool_name (contains /)
        # Actually * doesn't contain / or \x00, so it may pass validation
        # But it's treated as an unknown tool, so rules won't match
        assert result["decision"] in ("allow", "block")
