"""Claude Code format handler — PreToolUse hook stdin/stdout."""

from __future__ import annotations

import json
import os


class ClaudeCodeFormat:
    """Parse Claude Code PreToolUse hook stdin, format output.

    Claude Code tool names are already edictum-native (Bash, Read, Write, etc.)
    so no mapping is needed.
    """

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from Claude Code stdin.

        Returns:
            (tool_name, tool_input, cwd)
        """
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        cwd = data.get("cwd", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(self, decision: str, rule_id: str | None, reason: str | None, evaluated: int) -> tuple[str, int]:
        """Format decision for Claude Code.

        Allow: empty JSON, exit 0.
        Deny: hookSpecificOutput with permissionDecision block, exit 0.
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

        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "block",
                "permissionDecisionReason": deny_reason,
            }
        }
        return json.dumps(output), 0
