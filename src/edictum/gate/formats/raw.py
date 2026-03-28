"""Raw format handler — full JSON output for scripting and testing."""

from __future__ import annotations

import json
import os


class RawFormat:
    """Raw format: parse standard keys, output full decision details."""

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from raw stdin."""
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        cwd = data.get("cwd", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, decision: str, rule_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format full decision details.

        Exit code: 0 for allow, 1 for block.
        """
        output: dict = {
            "decision": decision,
            "contracts_evaluated": evaluated,
        }
        if rule_id:
            output["rule_id"] = rule_id
        if reason:
            output["reason"] = reason

        exit_code = 1 if decision == "block" else 0
        return json.dumps(output), exit_code
