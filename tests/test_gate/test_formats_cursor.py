"""Tests for Cursor format handler."""

from __future__ import annotations

import json
import os

from edictum.gate.formats.cursor import CURSOR_TOOL_MAP, CursorFormat


class TestCursorParse:
    def setup_method(self) -> None:
        self.fmt = CursorFormat()

    def test_parse_stdin_full_schema(self) -> None:
        data = {
            "conversation_id": "conv-123",
            "generation_id": "gen-456",
            "model": "claude-sonnet-4-20250514",
            "hook_event_name": "preToolUse",
            "cursor_version": "1.7.2",
            "workspace_roots": ["/project"],
            "tool_name": "Shell",
            "tool_input": {"command": "npm install", "working_directory": "/project"},
            "tool_use_id": "abc123",
            "cwd": "/project",
            "agent_message": "Installing dependencies...",
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Bash"
        assert tool_input == {"command": "npm install", "working_directory": "/project"}
        assert cwd == "/project"

    def test_parse_stdin_read(self) -> None:
        data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/project/src/main.py"},
            "cwd": "/project",
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Read"
        assert tool_input["file_path"] == "/project/src/main.py"

    def test_parse_stdin_write(self) -> None:
        data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "foo.py", "content": "print('hello')"},
            "cwd": "/project",
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Write"

    def test_parse_stdin_edit(self) -> None:
        data = {
            "tool_name": "Edit",
            "tool_input": {"file_path": "foo.py", "old_string": "a", "new_string": "b"},
            "cwd": "/project",
        }
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "Edit"

    def test_parse_stdin_task(self) -> None:
        data = {"tool_name": "Task", "tool_input": {}, "cwd": "/project"}
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "Task"

    def test_parse_stdin_missing_cwd(self) -> None:
        data = {"tool_name": "Shell", "tool_input": {"command": "ls"}}
        _, _, cwd = self.fmt.parse_stdin(data)
        assert cwd == os.getcwd()

    def test_tool_mapping_shell_to_bash(self) -> None:
        assert CURSOR_TOOL_MAP["Shell"] == "Bash"

    def test_tool_mapping_read(self) -> None:
        assert CURSOR_TOOL_MAP["Read"] == "Read"

    def test_tool_mapping_write(self) -> None:
        assert CURSOR_TOOL_MAP["Write"] == "Write"

    def test_tool_mapping_edit(self) -> None:
        assert CURSOR_TOOL_MAP["Edit"] == "Edit"

    def test_tool_mapping_task(self) -> None:
        assert CURSOR_TOOL_MAP["Task"] == "Task"

    def test_unknown_tool_passthrough(self) -> None:
        data = {
            "tool_name": "SomeCustomTool",
            "tool_input": {"key": "value"},
            "cwd": "/project",
        }
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "SomeCustomTool"

    def test_mcp_tool_passthrough(self) -> None:
        data = {
            "tool_name": "mcp__server__tool",
            "tool_input": {"arg": "val"},
            "cwd": "/project",
        }
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "mcp__server__tool"


class TestCursorOutput:
    def setup_method(self) -> None:
        self.fmt = CursorFormat()

    def test_format_allow(self) -> None:
        stdout, code = self.fmt.format_output("allow", None, None, 5)
        result = json.loads(stdout)
        assert result["decision"] == "allow"
        assert code == 0

    def test_format_allow_no_reason(self) -> None:
        stdout, code = self.fmt.format_output("allow", "some-rule", None, 3)
        result = json.loads(stdout)
        assert result["decision"] == "allow"
        assert "reason" not in result

    def test_format_deny(self) -> None:
        stdout, code = self.fmt.format_output("block", "test-rule", "Not allowed", 5)
        result = json.loads(stdout)
        assert result["decision"] == "block"
        assert "test-rule" in result["reason"]
        assert "Not allowed" in result["reason"]
        assert code == 0

    def test_format_deny_no_contract(self) -> None:
        stdout, code = self.fmt.format_output("block", None, "Generic block", 0)
        result = json.loads(stdout)
        assert result["decision"] == "block"
        assert result["reason"] == "Generic block"

    def test_format_deny_contract_only(self) -> None:
        stdout, code = self.fmt.format_output("block", "my-rule", None, 1)
        result = json.loads(stdout)
        assert result["decision"] == "block"
        assert "my-rule" in result["reason"]

    def test_format_warn_treated_as_allow(self) -> None:
        stdout, code = self.fmt.format_output("warn", None, None, 2)
        result = json.loads(stdout)
        assert result["decision"] == "allow"
        assert code == 0
