"""Tests for Claude Code format handler."""

from __future__ import annotations

import json
import os

from edictum.gate.formats.claude_code import ClaudeCodeFormat


class TestClaudeCodeParse:
    def setup_method(self) -> None:
        self.fmt = ClaudeCodeFormat()

    def test_parse_stdin_basic(self) -> None:
        data = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/project"}
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Bash"
        assert tool_input == {"command": "ls"}
        assert cwd == "/project"

    def test_parse_stdin_with_session(self) -> None:
        data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "foo.py"},
            "session_id": "abc123",
            "cwd": "/project",
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Read"
        assert tool_input == {"file_path": "foo.py"}

    def test_parse_stdin_missing_cwd(self) -> None:
        data = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        _, _, cwd = self.fmt.parse_stdin(data)
        assert cwd == os.getcwd()

    def test_tool_names_passthrough(self) -> None:
        for tool in ["Bash", "Read", "Write", "Edit", "Glob", "Grep"]:
            data = {"tool_name": tool, "tool_input": {}}
            name, _, _ = self.fmt.parse_stdin(data)
            assert name == tool


class TestClaudeCodeOutput:
    def setup_method(self) -> None:
        self.fmt = ClaudeCodeFormat()

    def test_format_allow(self) -> None:
        stdout, code = self.fmt.format_output("allow", None, None, 5)
        assert json.loads(stdout) == {}
        assert code == 0

    def test_format_deny(self) -> None:
        stdout, code = self.fmt.format_output("deny", "test-contract", "Not allowed", 5)
        result = json.loads(stdout)
        assert code == 0
        hook = result["hookSpecificOutput"]
        assert hook["hookEventName"] == "PreToolUse"
        assert hook["permissionDecision"] == "deny"
        assert "test-contract" in hook["permissionDecisionReason"]
        assert "Not allowed" in hook["permissionDecisionReason"]

    def test_format_deny_no_contract(self) -> None:
        stdout, code = self.fmt.format_output("deny", None, "Generic deny", 0)
        result = json.loads(stdout)
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
