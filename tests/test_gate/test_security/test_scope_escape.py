"""Security tests for scope enforcement bypass attempts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from edictum.gate.check import _check_scope, run_check
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
class TestScopeEscape:
    def test_symlink_escape(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_text("secret")

        project = tmp_path / "project"
        project.mkdir()
        link = project / "link.txt"
        link.symlink_to(secret)

        ok, reason = _check_scope(str(link), str(project))
        assert not ok

    def test_dot_dot_traversal(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        ok, reason = _check_scope(str(project / ".." / "etc" / "passwd"), str(project))
        assert not ok

    def test_dot_dot_in_middle(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        ok, reason = _check_scope(str(project / "src" / ".." / ".." / "etc" / "shadow"), str(project))
        assert not ok

    def test_absolute_path_outside_cwd(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        ok, reason = _check_scope("/etc/passwd", str(project))
        assert not ok

    def test_cwd_itself_allowed(self, tmp_path: Path) -> None:
        ok, reason = _check_scope(str(tmp_path), str(tmp_path))
        assert ok

    def test_subdirectory_allowed(self, tmp_path: Path) -> None:
        sub = tmp_path / "src" / "file.py"
        ok, reason = _check_scope(str(sub), str(tmp_path))
        assert ok

    def test_double_slash(self, tmp_path: Path) -> None:
        ok, reason = _check_scope("//etc/passwd", str(tmp_path))
        assert not ok

    def test_scope_via_run_check(self, tmp_path: Path) -> None:
        """End-to-end: Write outside cwd is denied by scope enforcement."""
        config = _config(tmp_path)
        project = tmp_path / "project"
        project.mkdir()
        # Use a path outside cwd that doesn't match any rule pattern
        outside_file = str(tmp_path / "other" / "file.txt")
        stdin = json.dumps(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": outside_file},
                "cwd": str(project),
            }
        )
        stdout, _ = run_check(stdin, "raw", config, str(project))
        result = json.loads(stdout)
        assert result["decision"] == "block"
        assert result["rule_id"] == "gate-scope-enforcement"

    def test_scope_read_not_blocked(self, tmp_path: Path) -> None:
        """Read outside cwd is NOT denied by scope enforcement (only Write/Edit)."""
        config = _config(tmp_path)
        stdin = json.dumps(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/etc/passwd"},
            }
        )
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        # Read is not subject to scope enforcement
        assert result["decision"] == "allow"

    def test_edit_outside_cwd_denied(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        project = tmp_path / "project"
        project.mkdir()
        stdin = json.dumps(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": "/etc/hosts"},
                "cwd": str(project),
            }
        )
        stdout, _ = run_check(stdin, "raw", config, str(project))
        result = json.loads(stdout)
        assert result["decision"] == "block"
