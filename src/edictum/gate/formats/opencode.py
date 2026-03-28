"""OpenCode format handler — tool.execute.before plugin stdin/stdout.

OpenCode plugin API (from docs):
  "tool.execute.before": async (input, output) => {
    // input.tool = "bash", "read", etc.
    // output.args = {command: "ls"}, {filePath: "/foo"}, etc.
  }

The gate plugin serializes this as:
{
  "tool": input.tool,
  "args": output.args,
  "directory": ctx.directory
}
"""

from __future__ import annotations

import json
import os

OPENCODE_TOOL_MAP: dict[str, str] = {
    "bash": "Bash",
    "shell": "Bash",
    "read": "Read",
    "write": "Write",
    "patch": "Edit",
    "glob": "Glob",
    "grep": "Grep",
    "browser": "WebFetch",
}

# OpenCode uses different arg key names than edictum-native.
# Map them so rules using args.file_path / args.command work.
OPENCODE_ARG_MAP: dict[str, str] = {
    "filePath": "file_path",
}


class OpenCodeFormat:
    """Parse OpenCode tool.execute.before plugin stdin, format output."""

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from OpenCode stdin.

        OpenCode uses 'tool' and 'args' keys with lowercase tool names.
        """
        raw_tool = data.get("tool", "")
        tool_name = OPENCODE_TOOL_MAP.get(raw_tool, raw_tool)
        raw_args = data.get("args", {})
        if not isinstance(raw_args, dict):
            raw_args = {}
        # Normalize arg keys to edictum-native names
        tool_input = {}
        for k, v in raw_args.items():
            normalized = OPENCODE_ARG_MAP.get(k, k)
            tool_input[normalized] = v
        cwd = data.get("directory", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, decision: str, rule_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format decision for OpenCode.

        Allow: {"allow": true}.
        Deny: {"allow": false, "reason": "..."}.
        """
        if decision != "block":
            return json.dumps({"allow": True}), 0

        deny_reason = ""
        if rule_id and reason:
            deny_reason = f"Rule '{rule_id}': {reason}"
        elif reason:
            deny_reason = reason
        elif rule_id:
            deny_reason = f"Denied by rule '{rule_id}'"

        output = {
            "allow": False,
            "reason": deny_reason,
        }
        return json.dumps(output), 0
