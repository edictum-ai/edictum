"""Tests for GitHub Copilot CLI format handler."""

from __future__ import annotations

import json

from edictum.gate.formats.copilot_cli import COPILOT_CLI_TOOL_MAP, CopilotCliFormat


class TestCopilotCliParse:
    def setup_method(self) -> None:
        self.fmt = CopilotCliFormat()

    def test_parse_stdin_basic(self) -> None:
        data = {
            "timestamp": 1704614600000,
            "cwd": "/project",
            "toolName": "bash",
            "toolArgs": '{"command": "ls"}',
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Bash"
        assert tool_input == {"command": "ls"}
        assert cwd == "/project"

    def test_parse_stdin_tool_args_is_json_string(self) -> None:
        """toolArgs is a JSON string, not an object — must be parsed."""
        data = {
            "cwd": "/project",
            "toolName": "bash",
            "toolArgs": '{"command":"rm -rf dist","description":"Clean build"}',
        }
        tool_name, tool_input, cwd = self.fmt.parse_stdin(data)
        assert tool_name == "Bash"
        assert tool_input["command"] == "rm -rf dist"
        assert tool_input["description"] == "Clean build"

    def test_parse_stdin_tool_args_invalid_json(self) -> None:
        """Invalid toolArgs JSON string should result in empty dict."""
        data = {"cwd": "/project", "toolName": "bash", "toolArgs": "not json"}
        _, tool_input, _ = self.fmt.parse_stdin(data)
        assert tool_input == {}

    def test_parse_stdin_tool_args_as_dict(self) -> None:
        """Tolerate toolArgs as dict (future-proofing)."""
        data = {"cwd": "/project", "toolName": "bash", "toolArgs": {"command": "ls"}}
        _, tool_input, _ = self.fmt.parse_stdin(data)
        assert tool_input == {"command": "ls"}

    def test_parse_stdin_tool_args_parses_to_non_dict(self) -> None:
        """toolArgs that parses to a non-dict (e.g. array) should result in empty dict."""
        data = {"cwd": "/project", "toolName": "bash", "toolArgs": '["a", "b"]'}
        _, tool_input, _ = self.fmt.parse_stdin(data)
        assert tool_input == {}

    def test_tool_mapping_bash(self) -> None:
        assert COPILOT_CLI_TOOL_MAP["bash"] == "Bash"

    def test_tool_mapping_edit(self) -> None:
        assert COPILOT_CLI_TOOL_MAP["edit"] == "Edit"

    def test_tool_mapping_view(self) -> None:
        assert COPILOT_CLI_TOOL_MAP["view"] == "Read"

    def test_tool_mapping_create(self) -> None:
        assert COPILOT_CLI_TOOL_MAP["create"] == "Write"

    def test_tool_mapping_unknown(self) -> None:
        data = {"cwd": "/project", "toolName": "some_custom_tool", "toolArgs": "{}"}
        tool_name, _, _ = self.fmt.parse_stdin(data)
        assert tool_name == "some_custom_tool"


class TestCopilotCliOutput:
    def setup_method(self) -> None:
        self.fmt = CopilotCliFormat()

    def test_format_allow(self) -> None:
        stdout, code = self.fmt.format_output("allow", None, None, 5)
        result = json.loads(stdout)
        assert result == {}
        assert code == 0

    def test_format_deny(self) -> None:
        stdout, code = self.fmt.format_output("block", "test-rule", "Not allowed", 5)
        result = json.loads(stdout)
        assert result["permissionDecision"] == "block"
        assert "test-rule" in result["permissionDecisionReason"]
        assert "Not allowed" in result["permissionDecisionReason"]
        assert code == 0

    def test_format_deny_no_contract(self) -> None:
        stdout, code = self.fmt.format_output("block", None, "Bad command", 5)
        result = json.loads(stdout)
        assert result["permissionDecision"] == "block"
        assert result["permissionDecisionReason"] == "Bad command"

    def test_format_deny_only_rule_id(self) -> None:
        stdout, code = self.fmt.format_output("block", "my-rule", None, 5)
        result = json.loads(stdout)
        assert result["permissionDecision"] == "block"
        assert "my-rule" in result["permissionDecisionReason"]
