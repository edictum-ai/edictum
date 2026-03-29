"""Security tests for malicious stdin payloads."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from edictum.gate.check import run_check
from edictum.gate.config import AuditConfig, GateConfig

_MINIMAL_CONTRACTS = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
  description: test
defaults:
  mode: enforce
rules:
  - id: noop
    type: pre
    tool: __never_match__
    when:
      args.x:
        equals: __never__
    then:
      action: block
      message: noop
"""


def _config(tmp_path: Path) -> GateConfig:
    cp = tmp_path / "rules.yaml"
    cp.write_text(_MINIMAL_CONTRACTS)
    return GateConfig(rules=(str(cp),), audit=AuditConfig(enabled=False), fail_open=False)


@pytest.mark.security
class TestMaliciousStdin:
    def test_oversized_stdin(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        huge = "x" * (10 * 1024 * 1024 + 1)
        stdout, _ = run_check(huge, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_null_bytes_in_tool_name(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash\x00evil", "tool_input": {}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_null_bytes_in_args(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls\x00evil"}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        # Should not crash — may allow or block depending on rules
        result = json.loads(stdout)
        assert result["decision"] in ("allow", "block")

    def test_control_chars_in_tool_name(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash\nInjected", "tool_input": {}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_unicode_homoglyph_tool_name(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        # Cyrillic B instead of Latin B
        stdin = json.dumps({"tool_name": "\u0412ash", "tool_input": {"command": "ls"}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        # Should not be matched as "Bash" — treated as unknown tool
        assert result["decision"] in ("allow", "block")

    def test_nested_json_bomb(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        # Deeply nested but valid JSON
        inner: dict = {"command": "ls"}
        for _ in range(100):
            inner = {"nested": inner}
        stdin = json.dumps({"tool_name": "Bash", "tool_input": inner})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] in ("allow", "block")

    def test_non_json_stdin(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdout, _ = run_check(b"\x89PNG\r\n\x1a\n".decode("latin-1"), "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_empty_tool_input(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash", "tool_input": {}})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "allow"

    def test_tool_input_not_dict(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps({"tool_name": "Bash", "tool_input": "string"})
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "block"

    def test_extra_keys_ignored(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        stdin = json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
                "extra_key": "ignored",
                "another": 42,
            }
        )
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["decision"] == "allow"
