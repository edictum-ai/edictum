"""Behavior tests for gate check flow."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from edictum.gate.check import _check_scope, resolve_category, run_check
from edictum.gate.config import AuditConfig, GateConfig, RedactionConfig

# Minimal contract YAML for testing
_MINIMAL_CONTRACTS = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test
  description: test
defaults:
  mode: enforce
contracts:
  - id: deny-env-dump
    type: pre
    tool: Bash
    when:
      args.command:
        matches_any:
          - 'cat\\s+\\.env'
    then:
      effect: deny
      message: "Denied: environment variable access"
  - id: deny-destructive
    type: pre
    tool: Bash
    when:
      args.command:
        matches_any:
          - 'rm\\s+-rf\\s+/'
    then:
      effect: deny
      message: "Denied: destructive command"
"""


def _make_config(tmp_path: Path) -> GateConfig:
    """Create a GateConfig pointing to a temp contract file."""
    contract_path = tmp_path / "contracts.yaml"
    contract_path.write_text(_MINIMAL_CONTRACTS)
    return GateConfig(
        contracts=(str(contract_path),),
        audit=AuditConfig(enabled=False),
        redaction=RedactionConfig(enabled=False),
        fail_open=False,
    )


def _stdin(tool_name: str, tool_input: dict, cwd: str | None = None) -> str:
    d: dict = {"tool_name": tool_name, "tool_input": tool_input}
    if cwd:
        d["cwd"] = cwd
    return json.dumps(d)


class TestRunCheck:
    def test_allow_safe_command(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        stdout, code = run_check(_stdin("Bash", {"command": "ls"}), "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"

    def test_deny_secret_read(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        stdout, code = run_check(_stdin("Bash", {"command": "cat .env"}), "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-env-dump"

    def test_deny_destructive_command(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        stdout, code = run_check(_stdin("Bash", {"command": "rm -rf /"}), "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_fail_closed_on_error(self, tmp_path: Path) -> None:
        config = GateConfig(
            contracts=(str(tmp_path / "nonexistent.yaml"),),
            audit=AuditConfig(enabled=False),
            fail_open=False,
        )
        stdout, code = run_check(_stdin("Bash", {"command": "ls"}), "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_fail_open_on_error(self, tmp_path: Path) -> None:
        config = GateConfig(
            contracts=(str(tmp_path / "nonexistent.yaml"),),
            audit=AuditConfig(enabled=False),
            fail_open=True,
        )
        stdout, code = run_check(_stdin("Bash", {"command": "ls"}), "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"

    def test_invalid_json_stdin(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        stdout, code = run_check("not json", "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_empty_stdin(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        stdout, code = run_check("", "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_raw_output_format(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        stdout, code = run_check(_stdin("Bash", {"command": "cat .env"}), "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert "verdict" in result
        assert "contracts_evaluated" in result

    def test_scope_deny_write_outside_cwd(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        stdin = _stdin("Write", {"file_path": "/etc/passwd"}, cwd=str(tmp_path))
        stdout, code = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "gate-scope-enforcement"

    def test_scope_allow_write_inside_cwd(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        target = tmp_path / "src" / "foo.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        stdin = _stdin("Write", {"file_path": str(target)}, cwd=str(tmp_path))
        stdout, code = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"

    def test_scope_symlink_escape(self, tmp_path: Path) -> None:
        # Create a symlink inside cwd that points outside
        outside = tmp_path / "outside"
        outside.mkdir()
        target_file = outside / "secret.txt"
        target_file.write_text("secret")

        project = tmp_path / "project"
        project.mkdir()
        symlink = project / "link.txt"
        symlink.symlink_to(target_file)

        config = _make_config(tmp_path)
        stdin = _stdin("Write", {"file_path": str(symlink)}, cwd=str(project))
        stdout, code = run_check(stdin, "raw", config, str(project))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"


class TestCategoryMapping:
    def test_bash_category(self) -> None:
        assert resolve_category("Bash") == "shell"

    def test_read_category(self) -> None:
        assert resolve_category("Read") == "file.read"

    def test_write_category(self) -> None:
        assert resolve_category("Write") == "file.write"

    def test_edit_category(self) -> None:
        assert resolve_category("Edit") == "file.edit"

    def test_glob_category(self) -> None:
        assert resolve_category("Glob") == "file.search"

    def test_grep_category(self) -> None:
        assert resolve_category("Grep") == "file.search"

    def test_webfetch_category(self) -> None:
        assert resolve_category("WebFetch") == "browser"

    def test_mcp_prefix(self) -> None:
        assert resolve_category("mcp__chrome__click") == "mcp"

    def test_unknown_tool(self) -> None:
        assert resolve_category("SomeNewTool") == "unknown"

    def test_notebook_category(self) -> None:
        assert resolve_category("NotebookEdit") == "notebook"

    def test_task_category(self) -> None:
        assert resolve_category("Task") == "task"


class TestCheckScope:
    def test_within_cwd(self, tmp_path: Path) -> None:
        target = tmp_path / "file.py"
        ok, reason = _check_scope(str(target), str(tmp_path))
        assert ok

    def test_outside_cwd(self, tmp_path: Path) -> None:
        ok, reason = _check_scope("/etc/passwd", str(tmp_path))
        assert not ok

    def test_none_path(self, tmp_path: Path) -> None:
        ok, reason = _check_scope(None, str(tmp_path))
        assert ok

    def test_cwd_itself(self, tmp_path: Path) -> None:
        ok, reason = _check_scope(str(tmp_path), str(tmp_path))
        assert ok

    def test_allowlist_permits_outside_cwd(self, tmp_path: Path) -> None:
        """Paths matching scope_allowlist bypass scope enforcement."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        target = allowed_dir / "memory.md"
        target.write_text("test")
        ok, reason = _check_scope(str(target), str(tmp_path / "project"), allowlist=(str(allowed_dir) + os.sep,))
        assert ok

    def test_allowlist_does_not_permit_other_paths(self, tmp_path: Path) -> None:
        """Allowlist only covers its specific prefixes."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        other = tmp_path / "other" / "secret.txt"
        ok, reason = _check_scope(str(other), str(tmp_path / "project"), allowlist=(str(allowed_dir) + os.sep,))
        assert not ok

    def test_allowlist_symlink_escape(self, tmp_path: Path) -> None:
        """Symlink inside allowlisted dir pointing outside is still resolved."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_text("secret")
        symlink = allowed_dir / "link.txt"
        symlink.symlink_to(secret)
        # Symlink resolves to outside — should be denied
        ok, reason = _check_scope(str(symlink), str(tmp_path / "project"), allowlist=(str(allowed_dir) + os.sep,))
        # realpath resolves to outside/secret.txt which IS outside the allowlisted dir
        assert not ok

    def test_scope_allowlist_via_run_check(self, tmp_path: Path) -> None:
        """End-to-end: Write to allowlisted path outside cwd is allowed."""
        allowed_dir = tmp_path / "claude-memory"
        allowed_dir.mkdir()
        target = allowed_dir / "MEMORY.md"
        target.write_text("test")

        contract_path = tmp_path / "contracts.yaml"
        contract_path.write_text(_MINIMAL_CONTRACTS)
        config = GateConfig(
            contracts=(str(contract_path),),
            audit=AuditConfig(enabled=False),
            scope_allowlist=(str(allowed_dir) + os.sep,),
            fail_open=False,
        )

        project = tmp_path / "project"
        project.mkdir()
        stdin = _stdin("Write", {"file_path": str(target)}, cwd=str(project))
        stdout, code = run_check(stdin, "raw", config, str(project))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"


def _make_enforced_base_config(tmp_path: Path) -> GateConfig:
    """Config using the real coding-assistant-base.yaml template, overridden to enforce mode.

    The shipped template defaults to observe mode (non-blocking), but tests need
    enforce mode to assert deny verdicts.
    """
    import importlib.resources

    template_dir = importlib.resources.files("edictum.yaml_engine.templates")
    base_text = (template_dir / "coding-assistant-base.yaml").read_text()
    # Override mode to enforce for testing
    enforced = base_text.replace("mode: observe", "mode: enforce", 1)
    enforced_path = tmp_path / "base-enforced.yaml"
    enforced_path.write_text(enforced)
    return GateConfig(
        contracts=(str(enforced_path),),
        audit=AuditConfig(enabled=False),
        redaction=RedactionConfig(enabled=False),
        scope_allowlist=(),
        fail_open=False,
    )


class TestSecretFileContracts:
    """Tests for deny-secret-file-reads/writes/edits contracts (brace expansion fix)."""

    def test_read_env_denied(self, tmp_path: Path) -> None:
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/project/.env"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-secret-file-reads"

    def test_write_env_denied(self, tmp_path: Path) -> None:
        config = _make_enforced_base_config(tmp_path)
        target = tmp_path / ".env"
        stdin = _stdin("Write", {"file_path": str(target)}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-secret-file-writes"

    def test_edit_env_denied(self, tmp_path: Path) -> None:
        config = _make_enforced_base_config(tmp_path)
        target = tmp_path / ".env"
        stdin = _stdin("Edit", {"file_path": str(target)}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-secret-file-edits"

    def test_read_credentials_denied(self, tmp_path: Path) -> None:
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/project/credentials.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_read_pem_denied(self, tmp_path: Path) -> None:
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/project/server.pem"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_read_safe_file_allowed(self, tmp_path: Path) -> None:
        config = _make_enforced_base_config(tmp_path)
        target = tmp_path / "app.py"
        stdin = _stdin("Read", {"file_path": str(target)}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"


class TestEnvDumpNarrowing:
    """Tests for narrowed echo regex — no false positives on echo $PATH."""

    def test_echo_path_allowed(self, tmp_path: Path) -> None:
        """echo $PATH should NOT be denied."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "echo $PATH"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"

    def test_echo_home_allowed(self, tmp_path: Path) -> None:
        """echo $HOME should NOT be denied."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "echo $HOME"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"

    def test_echo_aws_secret_denied(self, tmp_path: Path) -> None:
        """echo $AWS_SECRET_ACCESS_KEY should be denied."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "echo $AWS_SECRET_ACCESS_KEY"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_echo_api_key_denied(self, tmp_path: Path) -> None:
        """echo $API_KEY should be denied."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "echo $API_KEY"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_printenv_still_denied(self, tmp_path: Path) -> None:
        """printenv should still be denied."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "printenv"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_cat_env_still_denied(self, tmp_path: Path) -> None:
        """cat .env should still be denied."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "cat .env"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"


@pytest.mark.security
class TestGateSelfProtection:
    """Verify the assistant cannot disable or tamper with Gate infrastructure.

    These tests attempt bypass vectors that a governed assistant might try:
    reading hook config, editing gate settings, using Bash to modify files.
    """

    # -- File tool bypass: read hook config ------------------------------------

    def test_read_claude_settings_denied(self, tmp_path: Path) -> None:
        """Assistant must not read ~/.claude/settings.json (contains hook config)."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/Users/me/.claude/settings.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-reads"

    def test_read_cursor_hooks_denied(self, tmp_path: Path) -> None:
        """Assistant must not read ~/.cursor/hooks.json."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/Users/me/.cursor/hooks.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-reads"

    def test_read_gate_config_denied(self, tmp_path: Path) -> None:
        """Assistant must not read ~/.edictum/gate.yaml."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/Users/me/.edictum/gate.yaml"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-reads"

    def test_read_gate_contracts_denied(self, tmp_path: Path) -> None:
        """Assistant must not read ~/.edictum/contracts/base.yaml."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/Users/me/.edictum/contracts/base.yaml"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-reads"

    def test_read_gemini_settings_denied(self, tmp_path: Path) -> None:
        """Assistant must not read .gemini/settings.json."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/project/.gemini/settings.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-reads"

    # -- File tool bypass: write/edit hook config ------------------------------

    def test_write_claude_settings_denied(self, tmp_path: Path) -> None:
        """Assistant must not overwrite ~/.claude/settings.json to remove hook."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Write", {"file_path": "/Users/me/.claude/settings.json", "content": "{}"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-writes"

    def test_edit_claude_settings_denied(self, tmp_path: Path) -> None:
        """Assistant must not edit ~/.claude/settings.json to remove hook."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin(
            "Edit",
            {"file_path": "/Users/me/.claude/settings.json", "old_string": "edictum", "new_string": ""},
            cwd=str(tmp_path),
        )
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-edits"

    def test_write_gate_config_denied(self, tmp_path: Path) -> None:
        """Assistant must not overwrite ~/.edictum/gate.yaml."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin(
            "Write", {"file_path": "/Users/me/.edictum/gate.yaml", "content": "fail_open: true"}, cwd=str(tmp_path)
        )
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-writes"

    # -- Bash bypass: shell commands to modify config --------------------------

    def test_bash_rm_settings_denied(self, tmp_path: Path) -> None:
        """Assistant must not delete settings.json via shell."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "rm ~/.claude/settings.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_bash_echo_redirect_settings_denied(self, tmp_path: Path) -> None:
        """Assistant must not overwrite settings.json via echo redirect."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "echo '{}' > ~/.claude/settings.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_bash_sed_settings_denied(self, tmp_path: Path) -> None:
        """Assistant must not use sed to remove hook from settings.json."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "sed -i 's/edictum//g' settings.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_bash_gate_uninstall_denied(self, tmp_path: Path) -> None:
        """Assistant must not run edictum gate uninstall."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "edictum gate uninstall claude-code"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_bash_modify_edictum_dir_denied(self, tmp_path: Path) -> None:
        """Assistant must not modify files under ~/.edictum/."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "echo 'fail_open: true' > ~/.edictum/gate.yaml"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_bash_cat_hooks_json_denied(self, tmp_path: Path) -> None:
        """Assistant must not read hooks.json via cat."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "cat ~/.cursor/hooks.json"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    # -- Verify deny message tells assistant to ask the human ------------------

    def test_deny_message_instructs_human(self, tmp_path: Path) -> None:
        """Deny message must tell the assistant to ask the human to make changes."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Edit", {"file_path": "/Users/me/.edictum/gate.yaml"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert "human" in result["reason"].lower()

    # -- Non-gate files still allowed ------------------------------------------

    def test_read_normal_json_allowed(self, tmp_path: Path) -> None:
        """Reading a normal .json file should not be denied by gate protection."""
        config = _make_enforced_base_config(tmp_path)
        normal = tmp_path / "package.json"
        normal.write_text("{}")
        stdin = _stdin("Read", {"file_path": str(normal)}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"

    def test_bash_ls_allowed(self, tmp_path: Path) -> None:
        """Normal Bash commands should not be denied by gate protection."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "ls -la"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"


def _make_observe_base_config(tmp_path: Path) -> GateConfig:
    """Config using the real coding-assistant-base.yaml template in observe mode (default)."""
    import importlib.resources

    template_dir = importlib.resources.files("edictum.yaml_engine.templates")
    base_text = (template_dir / "coding-assistant-base.yaml").read_text()
    observe_path = tmp_path / "base-observe.yaml"
    observe_path.write_text(base_text)
    return GateConfig(
        contracts=(str(observe_path),),
        audit=AuditConfig(enabled=False),
        redaction=RedactionConfig(enabled=False),
        scope_allowlist=(),
        fail_open=False,
    )


class TestObserveModeScope:
    """Scope enforcement respects observe mode — logs but does not block."""

    def test_scope_observe_allows_write_outside_cwd(self, tmp_path: Path) -> None:
        """In observe mode, scope violation returns allow (not deny)."""
        config = _make_observe_base_config(tmp_path)
        stdin = _stdin("Write", {"file_path": "/etc/passwd"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "allow"

    def test_scope_enforce_blocks_write_outside_cwd(self, tmp_path: Path) -> None:
        """In enforce mode, scope violation returns deny."""
        config = _make_enforced_base_config(tmp_path)
        stdin = _stdin("Write", {"file_path": "/etc/passwd"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"

    def test_self_protection_always_enforces(self, tmp_path: Path) -> None:
        """Self-protection contracts have explicit mode: enforce, even when defaults are observe."""
        config = _make_observe_base_config(tmp_path)
        stdin = _stdin("Read", {"file_path": "/Users/me/.edictum/gate.yaml"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"
        assert result["contract_id"] == "deny-gate-config-reads"

    def test_self_protection_bash_always_enforces(self, tmp_path: Path) -> None:
        """Bash self-protection enforces even in observe mode."""
        config = _make_observe_base_config(tmp_path)
        stdin = _stdin("Bash", {"command": "edictum gate uninstall claude-code"}, cwd=str(tmp_path))
        stdout, _ = run_check(stdin, "raw", config, str(tmp_path))
        result = json.loads(stdout)
        assert result["verdict"] == "deny"


class TestCursorAutoDetection:
    """Verify that Cursor stdin is auto-detected when hook is registered as claude-code."""

    def test_cursor_version_triggers_detection(self, tmp_path: Path) -> None:
        """If stdin has cursor_version, use cursor format even when --format=claude-code."""
        config = _make_config(tmp_path)
        data = {
            "tool_name": "Shell",
            "tool_input": {"command": "rm -rf /"},
            "cwd": str(tmp_path),
            "cursor_version": "1.7.2",
        }
        stdout, code = run_check(json.dumps(data), "claude-code", config, str(tmp_path))
        result = json.loads(stdout)
        # Cursor format uses "decision" key, not Claude Code's "hookSpecificOutput"
        assert result.get("decision") == "deny"

    def test_workspace_roots_triggers_detection(self, tmp_path: Path) -> None:
        """If stdin has workspace_roots list, use cursor format."""
        config = _make_config(tmp_path)
        data = {
            "tool_name": "Shell",
            "tool_input": {"command": "rm -rf /"},
            "cwd": str(tmp_path),
            "workspace_roots": [str(tmp_path)],
        }
        stdout, code = run_check(json.dumps(data), "claude-code", config, str(tmp_path))
        result = json.loads(stdout)
        assert result.get("decision") == "deny"

    def test_claude_code_without_cursor_fields(self, tmp_path: Path) -> None:
        """Normal Claude Code stdin stays as claude-code format."""
        config = _make_config(tmp_path)
        data = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "cwd": str(tmp_path),
        }
        stdout, code = run_check(json.dumps(data), "claude-code", config, str(tmp_path))
        result = json.loads(stdout)
        # Claude Code format uses hookSpecificOutput
        assert "hookSpecificOutput" in result

    def test_explicit_cursor_format_unaffected(self, tmp_path: Path) -> None:
        """When --format=cursor is explicit, detection doesn't interfere."""
        config = _make_config(tmp_path)
        data = {
            "tool_name": "Shell",
            "tool_input": {"command": "ls"},
            "cwd": str(tmp_path),
            "cursor_version": "1.7.2",
        }
        stdout, code = run_check(json.dumps(data), "cursor", config, str(tmp_path))
        result = json.loads(stdout)
        assert result.get("decision") == "allow"

    def test_cursor_allow_uses_cursor_format(self, tmp_path: Path) -> None:
        """Allow responses also use cursor format when auto-detected."""
        config = _make_config(tmp_path)
        data = {
            "tool_name": "Read",
            "tool_input": {"file_path": str(tmp_path / "foo.txt")},
            "cwd": str(tmp_path),
            "cursor_version": "1.7.2",
        }
        stdout, code = run_check(json.dumps(data), "claude-code", config, str(tmp_path))
        result = json.loads(stdout)
        assert result.get("decision") == "allow"
