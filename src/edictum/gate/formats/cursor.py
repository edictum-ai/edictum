"""Cursor format handler — preToolUse hook stdin/stdout.

Cursor stdin schema (from docs):
{
  "conversation_id": "conv-123",
  "generation_id": "gen-456",
  "model": "claude-sonnet-4-20250514",
  "hook_event_name": "preToolUse",
  "cursor_version": "1.7.2",
  "workspace_roots": ["/project"],
  "tool_name": "Shell",
  "tool_input": { "command": "npm install", "working_directory": "/project" },
  "tool_use_id": "abc123",
  "cwd": "/project",
  "agent_message": "Installing dependencies..."
}
"""

from __future__ import annotations

import json
import os

CURSOR_TOOL_MAP: dict[str, str] = {
    "Shell": "Bash",
    "Read": "Read",
    "Write": "Write",
    "Edit": "Edit",
    "Task": "Task",
}


class CursorFormat:
    """Parse Cursor preToolUse hook stdin, format output.

    Cursor uses top-level tool_name/tool_input/cwd like Claude Code,
    but with different tool names (Shell instead of Bash).
    """

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from Cursor stdin.

        Returns:
            (tool_name, tool_input, cwd)
        """
        raw_tool = data.get("tool_name", "")
        tool_name = CURSOR_TOOL_MAP.get(raw_tool, raw_tool)
        tool_input = data.get("tool_input", {})
        cwd = data.get("cwd", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, decision: str, rule_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format decision for Cursor.

        Allow: {"decision": "allow"}, exit 0.
        Deny: {"decision": "block", "reason": "..."}, exit 0.
        """
        if decision != "block":
            return json.dumps({"decision": "allow"}), 0

        deny_reason = ""
        if rule_id and reason:
            deny_reason = f"Rule '{rule_id}': {reason}"
        elif reason:
            deny_reason = reason
        elif rule_id:
            deny_reason = f"Denied by rule '{rule_id}'"

        output = {
            "decision": "block",
            "reason": deny_reason,
        }
        return json.dumps(output), 0
