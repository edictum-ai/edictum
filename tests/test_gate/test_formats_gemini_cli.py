"""Tests for Gemini CLI format handler."""

from __future__ import annotations

import json
import os

from edictum.gate.formats.gemini_cli import GEMINI_CLI_TOOL_MAP, GeminiCliFormat


class TestGeminiCliParse:
    def setup_method(self) -> None:
        self.fmt = GeminiCliFormat()

    def test_parse_stdin_full_schema(self) -> None:
        data = {
            "session_id": "test-123",
            "cwd": "/tmp/test",
            "hook_event_name": "BeforeTool",
            "tool_name": "write_file",
            "tool_input": {
                "file_path": "test.txt",
                "content": "Test content",
            },
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Write"
        assert tool_input == {"file_path": "test.txt", "content": "Test content"}
        assert cwd == "/tmp/test"

    def test_parse_stdin_shell(self) -> None:
        data = {
            "session_id": "s1",
            "cwd": "/project",
            "hook_event_name": "BeforeTool",
            "tool_name": "shell",
            "tool_input": {"command": "ls -la"},
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Bash"
        assert tool_input == {"command": "ls -la"}
        assert cwd == "/project"

    def test_parse_stdin_read_file(self) -> None:
        data = {
            "tool_name": "read_file",
            "tool_input": {"file_path": "/project/main.py"},
            "cwd": "/project",
        }
        tool_name, tool_input, _ = self.fmt.parse_stdin(data)
        assert tool_name == "Read"
        assert tool_input["file_path"] == "/project/main.py"

    def test_parse_stdin_edit_file(self) -> None:
        data = {
            "tool_name": "edit_file",
            "tool_input": {"file_path": "foo.py"},
            "cwd": "/project",
        }
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "Edit"

    def test_parse_stdin_glob(self) -> None:
        data = {"tool_name": "glob", "tool_input": {"pattern": "*.py"}, "cwd": "/project"}
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "Glob"

    def test_parse_stdin_grep(self) -> None:
        data = {"tool_name": "grep", "tool_input": {"pattern": "TODO"}, "cwd": "/project"}
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "Grep"

    def test_parse_stdin_web_fetch(self) -> None:
        data = {"tool_name": "web_fetch", "tool_input": {"url": "https://example.com"}, "cwd": "/project"}
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "WebFetch"

    def test_parse_stdin_web_search(self) -> None:
        data = {"tool_name": "web_search", "tool_input": {"query": "python docs"}, "cwd": "/project"}
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "WebSearch"

    def test_parse_stdin_missing_cwd(self) -> None:
        data = {"tool_name": "shell", "tool_input": {"command": "ls"}}
        _, _, cwd = self.fmt.parse_stdin(data)
        assert cwd == os.getcwd()

    def test_tool_mapping_shell(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["shell"] == "Bash"

    def test_tool_mapping_write_file(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["write_file"] == "Write"

    def test_tool_mapping_read_file(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["read_file"] == "Read"

    def test_tool_mapping_edit_file(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["edit_file"] == "Edit"

    def test_tool_mapping_glob(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["glob"] == "Glob"

    def test_tool_mapping_grep(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["grep"] == "Grep"

    def test_tool_mapping_web_fetch(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["web_fetch"] == "WebFetch"

    def test_tool_mapping_web_search(self) -> None:
        assert GEMINI_CLI_TOOL_MAP["web_search"] == "WebSearch"

    def test_unknown_tool_passthrough(self) -> None:
        data = {
            "tool_name": "some_custom_tool",
            "tool_input": {"key": "value"},
            "cwd": "/project",
        }
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "some_custom_tool"


class TestGeminiCliOutput:
    def setup_method(self) -> None:
        self.fmt = GeminiCliFormat()

    def test_format_allow(self) -> None:
        stdout, code = self.fmt.format_output("allow", None, None, 5)
        result = json.loads(stdout)
        assert result == {}
        assert code == 0

    def test_format_allow_with_contract(self) -> None:
        stdout, code = self.fmt.format_output("allow", "some-contract", None, 3)
        result = json.loads(stdout)
        assert result == {}
        assert code == 0

    def test_format_deny(self) -> None:
        stdout, code = self.fmt.format_output("deny", "test-contract", "Not allowed", 5)
        assert "test-contract" in stdout
        assert "Not allowed" in stdout
        assert code == 2

    def test_format_deny_exit_code(self) -> None:
        _, code = self.fmt.format_output("deny", "c1", "bad", 1)
        assert code == 2

    def test_format_deny_no_contract(self) -> None:
        stdout, code = self.fmt.format_output("deny", None, "Generic deny", 0)
        assert stdout == "Generic deny"
        assert code == 2

    def test_format_deny_contract_only(self) -> None:
        stdout, code = self.fmt.format_output("deny", "my-contract", None, 1)
        assert "my-contract" in stdout
        assert code == 2

    def test_format_warn_treated_as_allow(self) -> None:
        stdout, code = self.fmt.format_output("warn", None, None, 2)
        result = json.loads(stdout)
        assert result == {}
        assert code == 0
