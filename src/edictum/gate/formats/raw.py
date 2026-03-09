"""Raw format handler — full JSON output for scripting and testing."""

from __future__ import annotations

import json
import os


class RawFormat:
    """Raw format: parse standard keys, output full verdict details."""

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Extract tool_name, tool_input, cwd from raw stdin."""
        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        cwd = data.get("cwd", os.getcwd())
        return tool_name, tool_input, cwd

    def format_output(
        self, verdict: str, contract_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format full verdict details.

        Exit code: 0 for allow, 1 for deny.
        """
        output: dict = {
            "verdict": verdict,
            "contracts_evaluated": evaluated,
        }
        if contract_id:
            output["contract_id"] = contract_id
        if reason:
            output["reason"] = reason

        exit_code = 1 if verdict == "deny" else 0
        return json.dumps(output), exit_code
