"""Gate install/uninstall — register hooks with coding assistants."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

_EDICTUM_HOOK_MARKER = "edictum gate check"


def install_claude_code(home: Path | None = None) -> str:
    """Register the edictum gate hook with Claude Code.

    Adds a PreToolUse hook entry to ~/.claude/settings.json.
    Merges with existing hooks — does NOT overwrite other hooks.
    """
    home = home or Path.home()
    settings_path = home / ".claude" / "settings.json"

    # Read existing settings
    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}

    if not isinstance(settings, dict):
        settings = {}

    # Build the hook entry
    hook_entry = {
        "type": "command",
        "command": "edictum gate check --format claude-code",
    }
    matcher_entry = {
        "matcher": "",
        "hooks": [hook_entry],
    }

    # Merge into existing hooks
    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])

    # Check if already installed
    for entry in pre_tool_use:
        for h in entry.get("hooks", []):
            if isinstance(h, dict) and _EDICTUM_HOOK_MARKER in h.get("command", ""):
                return "Edictum gate hook already installed in Claude Code settings"

    pre_tool_use.append(matcher_entry)

    # Write atomically
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(settings, indent=2) + "\n")
    os.replace(str(tmp), str(settings_path))

    return f"Installed edictum gate hook in {settings_path}"


def uninstall_claude_code(home: Path | None = None) -> str:
    """Remove the edictum gate hook from Claude Code settings."""
    home = home or Path.home()
    settings_path = home / ".claude" / "settings.json"

    if not settings_path.exists():
        return "No Claude Code settings found"

    try:
        settings = json.loads(settings_path.read_text())
    except (json.JSONDecodeError, OSError):
        return "Could not read Claude Code settings"

    hooks = settings.get("hooks", {})
    pre_tool_use = hooks.get("PreToolUse", [])

    # Filter out edictum entries
    filtered = []
    removed = False
    for entry in pre_tool_use:
        entry_hooks = entry.get("hooks", [])
        clean_hooks = [
            h for h in entry_hooks if not (isinstance(h, dict) and _EDICTUM_HOOK_MARKER in h.get("command", ""))
        ]
        if len(clean_hooks) < len(entry_hooks):
            removed = True
        if clean_hooks:
            entry["hooks"] = clean_hooks
            filtered.append(entry)

    if not removed:
        return "Edictum gate hook not found in Claude Code settings"

    hooks["PreToolUse"] = filtered
    settings["hooks"] = hooks

    tmp = settings_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(settings, indent=2) + "\n")
    os.replace(str(tmp), str(settings_path))

    return f"Removed edictum gate hook from {settings_path}"


def install_cursor(home: Path | None = None) -> str:
    """Register the edictum gate hook with Cursor.

    Adds a preToolUse hook entry to .cursor/hooks.json.
    Merges with existing hooks — does NOT overwrite other hooks.
    """
    home = home or Path.home()
    hooks_path = home / ".cursor" / "hooks.json"

    # Read existing hooks
    hooks_config: dict = {}
    if hooks_path.exists():
        try:
            hooks_config = json.loads(hooks_path.read_text())
        except (json.JSONDecodeError, OSError):
            hooks_config = {}

    if not isinstance(hooks_config, dict):
        hooks_config = {}

    # Build the hook entry
    hook_entry = {
        "command": "edictum gate check --format cursor",
        "timeout": 5,
    }

    # Merge into existing hooks
    hooks = hooks_config.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("preToolUse", [])

    # Check if already installed
    for entry in pre_tool_use:
        if isinstance(entry, dict) and _EDICTUM_HOOK_MARKER in entry.get("command", ""):
            return "Edictum gate hook already installed in Cursor hooks"

    pre_tool_use.append(hook_entry)

    # Write atomically
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = hooks_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(hooks_config, indent=2) + "\n")
    os.replace(str(tmp), str(hooks_path))

    return f"Installed edictum gate hook in {hooks_path}"


def uninstall_cursor(home: Path | None = None) -> str:
    """Remove the edictum gate hook from Cursor."""
    home = home or Path.home()
    hooks_path = home / ".cursor" / "hooks.json"

    if not hooks_path.exists():
        return "No Cursor hooks found"

    try:
        hooks_config = json.loads(hooks_path.read_text())
    except (json.JSONDecodeError, OSError):
        return "Could not read Cursor hooks"

    hooks = hooks_config.get("hooks", {})
    pre_tool_use = hooks.get("preToolUse", [])

    # Filter out edictum entries
    filtered = [
        entry
        for entry in pre_tool_use
        if not (isinstance(entry, dict) and _EDICTUM_HOOK_MARKER in entry.get("command", ""))
    ]

    if len(filtered) == len(pre_tool_use):
        return "Edictum gate hook not found in Cursor hooks"

    hooks["preToolUse"] = filtered
    hooks_config["hooks"] = hooks

    tmp = hooks_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(hooks_config, indent=2) + "\n")
    os.replace(str(tmp), str(hooks_path))

    return f"Removed edictum gate hook from {hooks_path}"


_GEMINI_CLI_HOOK_CONTENT = """\
#!/usr/bin/env bash
# Edictum Gate hook for Gemini CLI
# Generated by: edictum gate install gemini
input=$(cat)
result=$(echo "$input" | edictum gate check --format gemini 2>/dev/null)
exit_code=$?
if [ $exit_code -eq 2 ]; then
  echo "$result" >&2
  exit 2
fi
# Fail-closed: if edictum is missing or crashed (non-0, non-2), block the call
if [ $exit_code -ne 0 ]; then
  echo "Edictum gate check failed (exit $exit_code)" >&2
  exit 2
fi
echo "{}"
exit 0
"""


def install_gemini_cli(home: Path | None = None) -> str:
    """Register the edictum gate hook with Gemini CLI.

    Gemini CLI loads hooks from the project-level .gemini/ directory.
    Hooks must be registered in .gemini/settings.json — they are NOT auto-discovered.

    1. Creates .gemini/hooks/edictum-gate.sh (executable script)
    2. Registers it in .gemini/settings.json under hooks.BeforeTool
    """
    cwd = Path.cwd()
    settings_path = cwd / ".gemini" / "settings.json"

    # Check if already installed (before writing anything)
    if settings_path.exists():
        try:
            existing = json.loads(settings_path.read_text())
            for entry in existing.get("hooks", {}).get("BeforeTool", []):
                for h in entry.get("hooks", []):
                    if isinstance(h, dict) and ("edictum" in h.get("name", "") or "edictum" in h.get("command", "")):
                        return "Edictum gate hook already installed for Gemini CLI"
        except Exception:
            pass

    # 1. Write the hook script
    hooks_dir = cwd / ".gemini" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    script_path = hooks_dir / "edictum-gate.sh"
    script_path.write_text(_GEMINI_CLI_HOOK_CONTENT)
    script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # 2. Register in .gemini/settings.json
    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    if not isinstance(settings, dict):
        settings = {}

    hook_entry = {
        "matcher": "*",
        "hooks": [
            {
                "name": "edictum-gate",
                "type": "command",
                "command": ".gemini/hooks/edictum-gate.sh",
            }
        ],
    }

    hooks = settings.setdefault("hooks", {})
    before_tool = hooks.setdefault("BeforeTool", [])
    before_tool.append(hook_entry)

    # Write atomically
    tmp = settings_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(settings, indent=2) + "\n")
    os.replace(str(tmp), str(settings_path))

    return f"Installed edictum gate hook at {script_path} (registered in {settings_path})"


def uninstall_gemini_cli(home: Path | None = None) -> str:
    """Remove the edictum gate hook from Gemini CLI."""
    cwd = Path.cwd()
    script_path = cwd / ".gemini" / "hooks" / "edictum-gate.sh"
    settings_path = cwd / ".gemini" / "settings.json"

    removed_script = False
    if script_path.exists():
        script_path.unlink()
        removed_script = True

    # Remove from settings.json
    removed_setting = False
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
            before_tool = settings.get("hooks", {}).get("BeforeTool", [])
            filtered = []
            for entry in before_tool:
                entry_hooks = entry.get("hooks", [])
                clean = [
                    h
                    for h in entry_hooks
                    if not (
                        isinstance(h, dict) and ("edictum" in h.get("name", "") or "edictum" in h.get("command", ""))
                    )
                ]
                if len(clean) < len(entry_hooks):
                    removed_setting = True
                if clean:
                    entry["hooks"] = clean
                    filtered.append(entry)
            settings["hooks"]["BeforeTool"] = filtered
            tmp = settings_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(settings, indent=2) + "\n")
            os.replace(str(tmp), str(settings_path))
        except Exception:
            pass

    if removed_script or removed_setting:
        return f"Removed edictum gate hook from {cwd / '.gemini'}"
    return "Edictum gate hook not found for Gemini CLI"


def install_copilot_cli(home: Path | None = None) -> str:
    """Register the edictum gate hook with GitHub Copilot CLI.

    Adds a preToolUse hook entry to .github/hooks/hooks.json in the cwd.
    Copilot CLI loads hooks from the current working directory.
    """
    hooks_path = Path.cwd() / ".github" / "hooks" / "hooks.json"

    # Read existing hooks
    hooks_config: dict = {}
    if hooks_path.exists():
        try:
            hooks_config = json.loads(hooks_path.read_text())
        except (json.JSONDecodeError, OSError):
            hooks_config = {}

    if not isinstance(hooks_config, dict):
        hooks_config = {}

    hooks_config.setdefault("version", 1)

    # Build the hook entry
    hook_entry = {
        "type": "command",
        "bash": "edictum gate check --format copilot",
        "timeoutSec": 5,
    }

    # Merge into existing hooks
    hooks = hooks_config.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("preToolUse", [])

    # Check if already installed
    for entry in pre_tool_use:
        if isinstance(entry, dict) and _EDICTUM_HOOK_MARKER in entry.get("bash", ""):
            return "Edictum gate hook already installed for Copilot CLI"

    pre_tool_use.append(hook_entry)

    # Write atomically
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = hooks_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(hooks_config, indent=2) + "\n")
    os.replace(str(tmp), str(hooks_path))

    return f"Installed edictum gate hook in {hooks_path}"


def uninstall_copilot_cli(home: Path | None = None) -> str:
    """Remove the edictum gate hook from Copilot CLI."""
    hooks_path = Path.cwd() / ".github" / "hooks" / "hooks.json"

    if not hooks_path.exists():
        return "No Copilot CLI hooks found"

    try:
        hooks_config = json.loads(hooks_path.read_text())
    except (json.JSONDecodeError, OSError):
        return "Could not read Copilot CLI hooks"

    hooks = hooks_config.get("hooks", {})
    pre_tool_use = hooks.get("preToolUse", [])

    # Filter out edictum entries
    filtered = [
        entry
        for entry in pre_tool_use
        if not (isinstance(entry, dict) and _EDICTUM_HOOK_MARKER in entry.get("bash", ""))
    ]

    if len(filtered) == len(pre_tool_use):
        return "Edictum gate hook not found in Copilot CLI hooks"

    hooks["preToolUse"] = filtered
    hooks_config["hooks"] = hooks

    tmp = hooks_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(hooks_config, indent=2) + "\n")
    os.replace(str(tmp), str(hooks_path))

    return f"Removed edictum gate hook from {hooks_path}"


_OPENCODE_PLUGIN_CONTENT = """\
// Edictum Gate plugin for OpenCode
// Generated by: edictum gate install opencode
import { spawnSync } from "child_process";

export const EdictumGate = async ({ directory }) => {
  return {
    "tool.execute.before": async (input, output) => {
      const payload = JSON.stringify({
        tool: input.tool,
        args: output.args,
        directory: directory || process.cwd(),
      });
      try {
        const proc = spawnSync(
          "edictum",
          ["gate", "check", "--format", "opencode"],
          { input: payload, encoding: "utf-8", timeout: 5000, shell: false }
        );
        if (proc.error) {
          throw new Error("Edictum gate check failed: " + proc.error.message);
        }
        const result = (proc.stdout || "").trim();
        if (!result) return;
        const parsed = JSON.parse(result);
        if (parsed.allow === false) {
          throw new Error(parsed.reason || "Denied by edictum gate");
        }
      } catch (e) {
        if (e.message && e.message.startsWith("Denied")) throw e;
        if (e.message && e.message.startsWith("Rule")) throw e;
        // Fail-closed: unknown error blocks the tool call
        throw new Error("Edictum gate check failed: " + e.message);
      }
    }
  };
};
"""


def install_opencode(home: Path | None = None) -> str:
    """Register the edictum gate hook with OpenCode."""
    home = home or Path.home()
    plugins_dir = home / ".opencode" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    plugin_path = plugins_dir / "edictum-gate.ts"

    # Idempotency: don't overwrite if already installed
    if plugin_path.exists():
        content = plugin_path.read_text()
        if _EDICTUM_HOOK_MARKER in content:
            return "Edictum gate plugin already installed for OpenCode"

    plugin_path.write_text(_OPENCODE_PLUGIN_CONTENT)

    return f"Installed edictum gate plugin at {plugin_path}"


def uninstall_opencode(home: Path | None = None) -> str:
    """Remove the edictum gate hook from OpenCode."""
    home = home or Path.home()
    plugin_path = home / ".opencode" / "plugins" / "edictum-gate.ts"

    if not plugin_path.exists():
        return "Edictum gate plugin not found for OpenCode"

    plugin_path.unlink()
    return f"Removed edictum gate plugin from {plugin_path}"


INSTALLER_REGISTRY: dict[str, tuple] = {
    "claude-code": (install_claude_code, uninstall_claude_code),
    "copilot": (install_copilot_cli, uninstall_copilot_cli),
    "cursor": (install_cursor, uninstall_cursor),
    "gemini": (install_gemini_cli, uninstall_gemini_cli),
    "opencode": (install_opencode, uninstall_opencode),
}
