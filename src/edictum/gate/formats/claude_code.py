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

    def format_output(
        self, verdict: str, contract_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format verdict for Claude Code.

        Allow: empty JSON, exit 0.
        Deny: hookSpecificOutput with permissionDecision deny, exit 0.
        """
        if verdict != "deny":
            return json.dumps({}), 0

        deny_reason = ""
        if contract_id and reason:
            deny_reason = f"Contract '{contract_id}': {reason}"
        elif reason:
            deny_reason = reason
        elif contract_id:
            deny_reason = f"Denied by contract '{contract_id}'"

        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": deny_reason,
            }
        }
        return json.dumps(output), 0
