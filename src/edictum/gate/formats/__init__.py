"""Format handlers for coding assistant input/output translation."""

from __future__ import annotations

from typing import Protocol


class FormatHandler(Protocol):
    """Protocol for assistant-specific stdin parsing and output formatting."""

    def parse_stdin(self, data: dict) -> tuple[str, dict, str]:
        """Parse assistant-specific stdin. Returns (tool_name, tool_input, cwd)."""
        ...

    def format_output(
        self, decision: str, rule_id: str | None, reason: str | None, evaluated: int
    ) -> tuple[str, int]:
        """Format decision for assistant. Returns (json_string, exit_code)."""
        ...


FORMAT_REGISTRY: dict[str, FormatHandler] = {}


def get_format(name: str) -> FormatHandler:
    """Look up a format handler by name."""
    if not FORMAT_REGISTRY:
        _register_formats()
    handler = FORMAT_REGISTRY.get(name)
    if handler is None:
        available = ", ".join(sorted(FORMAT_REGISTRY.keys()))
        raise ValueError(f"Unknown format '{name}'. Available: {available}")
    return handler


def _register_formats() -> None:
    """Register all built-in format handlers."""
    from edictum.gate.formats.claude_code import ClaudeCodeFormat
    from edictum.gate.formats.copilot_cli import CopilotCliFormat
    from edictum.gate.formats.cursor import CursorFormat
    from edictum.gate.formats.gemini_cli import GeminiCliFormat
    from edictum.gate.formats.opencode import OpenCodeFormat
    from edictum.gate.formats.raw import RawFormat

    FORMAT_REGISTRY["claude-code"] = ClaudeCodeFormat()
    FORMAT_REGISTRY["copilot"] = CopilotCliFormat()
    FORMAT_REGISTRY["cursor"] = CursorFormat()
    FORMAT_REGISTRY["gemini"] = GeminiCliFormat()
    FORMAT_REGISTRY["opencode"] = OpenCodeFormat()
    FORMAT_REGISTRY["raw"] = RawFormat()
