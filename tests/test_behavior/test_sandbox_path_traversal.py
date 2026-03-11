"""Behavior tests for sandbox path traversal normalization.

Every test proves that path traversal sequences (.. / . / //) are
normalized before sandbox within/not_within evaluation, closing the
bypass demonstrated in red team session 2026-02-24.
"""

from __future__ import annotations

import os

import pytest

from edictum import Edictum, create_envelope
from edictum.storage import MemoryBackend
from edictum.yaml_engine.sandbox_compiler import _extract_paths


class NullSink:
    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


def _guard(yaml: str) -> Edictum:
    return Edictum.from_yaml_string(yaml, audit_sink=NullSink(), backend=MemoryBackend())


# --- _extract_paths normalization ---


class TestExtractPathsNormalization:
    """Paths extracted from envelopes are resolved via os.path.realpath."""

    def test_traversal_resolved(self):
        """Paths with .. segments are resolved before extraction."""
        envelope = create_envelope("read_file", {"path": "/tmp/../etc/shadow"})
        paths = _extract_paths(envelope)
        assert paths == [os.path.realpath("/etc/shadow")]

    def test_dot_segments_collapsed(self):
        """Redundant . segments are collapsed."""
        envelope = create_envelope("read_file", {"path": "/tmp/./foo/../bar"})
        paths = _extract_paths(envelope)
        assert paths == [os.path.realpath("/tmp/bar")]

    def test_double_slash_collapsed(self):
        """Double slashes are collapsed."""
        envelope = create_envelope("read_file", {"path": "/tmp//foo//bar"})
        paths = _extract_paths(envelope)
        assert paths == [os.path.realpath("/tmp/foo/bar")]

    def test_workspace_breakout_resolved(self):
        """Workspace-rooted traversal is resolved."""
        envelope = create_envelope("read_file", {"path": "/root/.nanobot/workspace/../../.ssh/id_rsa"})
        paths = _extract_paths(envelope)
        assert paths == [os.path.realpath("/root/.ssh/id_rsa")]

    def test_command_path_tokens_normalized(self):
        """Path tokens in commands are also resolved."""
        envelope = create_envelope("exec", {"command": "cat /tmp/../etc/shadow"})
        paths = _extract_paths(envelope)
        assert os.path.realpath("/etc/shadow") in paths

    def test_clean_paths_unchanged(self):
        """realpath on already-clean paths without symlinks is identity."""
        # Use paths that don't involve symlinks on this platform
        clean = os.path.realpath("/usr/local/bin")
        assert os.path.realpath(clean) == clean


# --- Sandbox within bypass ---


WITHIN_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: traversal-test
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within: [/tmp]
    outside: deny
    message: "Denied"
"""


class TestSandboxWithinTraversal:
    """Path traversal that escapes within boundary is denied."""

    def test_traversal_tmp_to_etc(self):
        """/tmp/../etc/shadow resolves to /etc/shadow -- must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("read_file", {"path": "/tmp/../etc/shadow"})
        assert result.verdict == "deny"

    def test_traversal_double_dotdot(self):
        """/tmp/./../../etc/passwd -- multiple traversal segments."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("read_file", {"path": "/tmp/./../../etc/passwd"})
        assert result.verdict == "deny"

    def test_clean_path_still_allowed(self):
        """Normal path within boundary still passes."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("read_file", {"path": "/tmp/myfile.txt"})
        assert result.verdict == "allow"

    def test_direct_outside_path_still_denied(self):
        """Direct /etc/shadow (no traversal) is still denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("read_file", {"path": "/etc/shadow"})
        assert result.verdict == "deny"


# --- Sandbox not_within bypass ---


NOT_WITHIN_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: not-within-traversal
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within: [/workspace]
    not_within: [/workspace/.git]
    outside: deny
    message: "Denied"
"""


class TestSandboxNotWithinTraversal:
    """Path traversal that lands in not_within target is denied."""

    def test_traversal_into_excluded_dir(self):
        """Traversal that resolves into .git is denied."""
        guard = _guard(NOT_WITHIN_YAML)
        result = guard.evaluate("read_file", {"path": "/workspace/foo/../../workspace/.git/config"})
        assert result.verdict == "deny"

    def test_direct_excluded_still_denied(self):
        """Direct access to .git is still denied."""
        guard = _guard(NOT_WITHIN_YAML)
        result = guard.evaluate("read_file", {"path": "/workspace/.git/config"})
        assert result.verdict == "deny"


# --- Exec sandbox path traversal ---


EXEC_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: exec-traversal
defaults:
  mode: enforce
contracts:
  - id: exec-sandbox
    type: sandbox
    tools: [exec]
    allows:
      commands: [cat]
    within: [/tmp]
    outside: deny
    message: "Denied"
"""


class TestExecSandboxTraversal:
    """Path tokens in exec commands are normalized."""

    def test_exec_command_traversal_denied(self):
        """cat /tmp/../etc/shadow -- path escapes within via traversal."""
        guard = _guard(EXEC_YAML)
        result = guard.evaluate("exec", {"command": "cat /tmp/../etc/shadow"})
        assert result.verdict == "deny"

    def test_exec_clean_path_allowed(self):
        """cat /tmp/ok.txt -- clean path within boundary."""
        guard = _guard(EXEC_YAML)
        result = guard.evaluate("exec", {"command": "cat /tmp/ok.txt"})
        assert result.verdict == "allow"


# --- Red team fixture traversal vectors ---


class TestRedTeamTraversalVectors:
    """All 7 vectors from the red team session spec."""

    YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: red-team-vectors
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within:
      - /root/.nanobot/workspace
      - /tmp
    outside: deny
    message: "Denied"
"""

    def test_tmp_etc_shadow(self):
        guard = _guard(self.YAML)
        result = guard.evaluate("read_file", {"path": "/tmp/../etc/shadow"})
        assert result.verdict == "deny"

    def test_workspace_ssh_breakout(self):
        guard = _guard(self.YAML)
        result = guard.evaluate("read_file", {"path": "/root/.nanobot/workspace/../../.ssh/id_rsa"})
        assert result.verdict == "deny"

    def test_tmp_proc_environ(self):
        guard = _guard(self.YAML)
        result = guard.evaluate("read_file", {"path": "/tmp/../proc/1/environ"})
        assert result.verdict == "deny"

    def test_double_traversal_etc_passwd(self):
        guard = _guard(self.YAML)
        result = guard.evaluate("read_file", {"path": "/tmp/./../../etc/passwd"})
        assert result.verdict == "deny"

    def test_workspace_config_breakout(self):
        guard = _guard(self.YAML)
        result = guard.evaluate("read_file", {"path": "/root/.nanobot/workspace/../config.json"})
        assert result.verdict == "deny"

    def test_direct_etc_shadow_still_denied(self):
        guard = _guard(self.YAML)
        result = guard.evaluate("read_file", {"path": "/etc/shadow"})
        assert result.verdict == "deny"

    def test_clean_workspace_path_still_allowed(self):
        guard = _guard(self.YAML)
        result = guard.evaluate("read_file", {"path": "/root/.nanobot/workspace/README.md"})
        assert result.verdict == "allow"


@pytest.mark.security
class TestSymlinkSandboxEscape:
    """Security: symlinks inside allowed dirs pointing outside are denied."""

    def test_symlink_inside_allowed_dir_pointing_outside_denied(self, tmp_path):
        """Symlink inside within dir pointing outside is denied."""
        allowed = tmp_path / "workspace"
        allowed.mkdir()
        target = tmp_path / "secrets"
        target.mkdir()
        (target / "creds.txt").write_text("secret")

        # Create symlink: workspace/escape -> ../secrets
        escape_link = allowed / "escape"
        escape_link.symlink_to(target)

        yaml_str = f"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: symlink-test
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within: ["{allowed}"]
    outside: deny
    message: "Denied"
"""
        guard = _guard(yaml_str)
        # Access through symlink: workspace/escape/creds.txt
        result = guard.evaluate("read_file", {"path": str(escape_link / "creds.txt")})
        assert result.verdict == "deny"

    def test_symlink_chain_resolved(self, tmp_path):
        """Chained symlinks resolved: a -> b -> outside."""
        allowed = tmp_path / "workspace"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        # Chain: workspace/a -> workspace/b -> outside
        b_link = allowed / "b"
        b_link.symlink_to(outside)
        a_link = allowed / "a"
        a_link.symlink_to(b_link)

        yaml_str = f"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: chain-test
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within: ["{allowed}"]
    outside: deny
    message: "Denied"
"""
        guard = _guard(yaml_str)
        result = guard.evaluate("read_file", {"path": str(a_link / "data.txt")})
        assert result.verdict == "deny"

    def test_realpath_still_allows_normal_paths(self, tmp_path):
        """Regular file inside within dir is still allowed."""
        allowed = tmp_path / "workspace"
        allowed.mkdir()
        (allowed / "readme.txt").write_text("hello")

        yaml_str = f"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: normal-test
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within: ["{allowed}"]
    outside: deny
    message: "Denied"
"""
        guard = _guard(yaml_str)
        result = guard.evaluate("read_file", {"path": str(allowed / "readme.txt")})
        assert result.verdict == "allow"

    def test_realpath_still_blocks_dotdot_traversal(self, tmp_path):
        """Existing .. traversal protection still works."""
        allowed = tmp_path / "workspace"
        allowed.mkdir()

        yaml_str = f"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: dotdot-test
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within: ["{allowed}"]
    outside: deny
    message: "Denied"
"""
        guard = _guard(yaml_str)
        result = guard.evaluate("read_file", {"path": str(allowed / ".." / "etc" / "passwd")})
        assert result.verdict == "deny"

    def test_nonexistent_path_handled(self, tmp_path):
        """Non-existent path doesn't crash -- realpath normalizes it."""
        allowed = tmp_path / "workspace"
        allowed.mkdir()

        yaml_str = f"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: nonexistent-test
defaults:
  mode: enforce
contracts:
  - id: file-sandbox
    type: sandbox
    tools: [read_file]
    within: ["{allowed}"]
    outside: deny
    message: "Denied"
"""
        guard = _guard(yaml_str)
        # Non-existent path within workspace -- should not crash, still allowed
        result = guard.evaluate("read_file", {"path": str(allowed / "nonexistent" / "file.txt")})
        assert result.verdict == "allow"
