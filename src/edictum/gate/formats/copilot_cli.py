"""GitHub Copilot CLI format handler — preToolUse hook stdin/stdout.

Copilot CLI stdin schema (from docs):
{
  "timestamp": 1704614600000,
  "cwd": "/path/to/project",
  "toolName": "bash",
  "toolArgs": "{\"command\":\"rm -rf dist\",\"description\":\"Clean build directory\"}"
}

NOTE: toolArgs is a JSON *string*, not an object. Must be parsed with json.loads().

Copilot CLI output schema:
  Allow: omit output or empty JSON, exit 0.
  Deny: {"permissionDecision": "deny", "permissionDecisionReason": "..."}, exit 0.
"""

from __future__ import annotations

import json
import os

COPILOT_CLI_TOOL_MAP: dict[str, str] = {
    "bash": "Bash",
    "edit": "Edit",
    "view": "Read",
    "create": "Write",
}


class CopilotCliFormat:
    """Parse GitHub Copilot CLI preToolUse hook stdin, format output."""

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from Copilot CLI stdin.

        Copilot CLI uses camelCase keys: toolName, toolArgs (JSON string), cwd.
        """
        raw_tool = data.get("toolName", "")
        tool_name = COPILOT_CLI_TOOL_MAP.get(raw_tool, raw_tool)

        # toolArgs is a JSON string, not an object
        tool_args_raw = data.get("toolArgs", "{}")
        if isinstance(tool_args_raw, str):
            try:
                tool_input = json.loads(tool_args_raw)
            except (json.JSONDecodeError, ValueError):
                tool_input = {}
        elif isinstance(tool_args_raw, dict):
            # Tolerate dict in case format changes
            tool_input = tool_args_raw
        else:
            tool_input = {}

        if not isinstance(tool_input, dict):
            tool_input = {}

        cwd = data.get("cwd", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, verdict: str, contract_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format verdict for Copilot CLI.

        Allow: empty JSON, exit 0.
        Deny: {"permissionDecision": "deny", "permissionDecisionReason": "..."}, exit 0.
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
            "permissionDecision": "deny",
            "permissionDecisionReason": deny_reason,
        }
        return json.dumps(output), 0
