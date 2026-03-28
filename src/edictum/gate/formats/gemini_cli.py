"""Gemini CLI format handler — BeforeTool hook stdin/stdout.

Gemini CLI stdin schema (from docs):
{
  "session_id": "test-123",
  "cwd": "/tmp/test",
  "hook_event_name": "BeforeTool",
  "tool_name": "write_file",
  "tool_input": {
    "file_path": "test.txt",
    "content": "Test content"
  }
}
"""

from __future__ import annotations

import json
import os

GEMINI_CLI_TOOL_MAP: dict[str, str] = {
    "shell": "Bash",
    "run_shell_command": "Bash",
    "write_file": "Write",
    "read_file": "Read",
    "edit_file": "Edit",
    "replace_in_file": "Edit",
    "glob": "Glob",
    "list_files": "Glob",
    "grep": "Grep",
    "search_files": "Grep",
    "web_fetch": "WebFetch",
    "web_search": "WebSearch",
}


class GeminiCliFormat:
    """Parse Gemini CLI BeforeTool hook stdin, format output.

    Gemini CLI uses snake_case tool names and top-level tool_name/tool_input/cwd.
    Deny exits with code 2 and reason on stderr (stdout for the gate).
    """

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from Gemini CLI stdin.

        Returns:
            (tool_name, tool_input, cwd)
        """
        raw_tool = data.get("tool_name", "")
        tool_name = GEMINI_CLI_TOOL_MAP.get(raw_tool, raw_tool)
        tool_input = data.get("tool_input", {})
        cwd = data.get("cwd", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, decision: str, rule_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format decision for Gemini CLI.

        Allow: empty JSON object {}, exit 0.
        Deny: reason string, exit 2.
        """
        if decision != "block":
            return json.dumps({}), 0

        deny_reason = ""
        if rule_id and reason:
            deny_reason = f"Rule '{rule_id}': {reason}"
        elif reason:
            deny_reason = reason
        elif rule_id:
            deny_reason = f"Denied by rule '{rule_id}'"

        return deny_reason, 2
