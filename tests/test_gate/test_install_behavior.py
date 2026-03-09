"""Behavior tests for gate install/uninstall."""

from __future__ import annotations

import json
import os
from pathlib import Path

from edictum.gate.install import (
    install_claude_code,
    install_copilot_cli,
    install_cursor,
    install_gemini_cli,
    install_opencode,
    uninstall_claude_code,
    uninstall_copilot_cli,
    uninstall_cursor,
    uninstall_gemini_cli,
    uninstall_opencode,
)


class TestClaudeCodeInstall:
    def test_install_creates_settings(self, tmp_path: Path) -> None:
        result = install_claude_code(home=tmp_path)
        settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 1
        assert "edictum gate check" in hooks[0]["hooks"][0]["command"]
        assert "Installed" in result

    def test_install_merges_hooks(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        existing = {"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "other-hook"}]}]}}
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        install_claude_code(home=tmp_path)
        settings = json.loads((claude_dir / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 2  # existing + edictum

    def test_install_idempotent(self, tmp_path: Path) -> None:
        install_claude_code(home=tmp_path)
        result = install_claude_code(home=tmp_path)
        assert "already installed" in result

        settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 1  # No duplicate

    def test_uninstall_removes_hook(self, tmp_path: Path) -> None:
        install_claude_code(home=tmp_path)
        uninstall_claude_code(home=tmp_path)
        settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 0

    def test_uninstall_missing_file(self, tmp_path: Path) -> None:
        result = uninstall_claude_code(home=tmp_path)
        assert "No Claude Code settings" in result


class TestCursorInstall:
    def test_install_creates_hooks_json(self, tmp_path: Path) -> None:
        result = install_cursor(home=tmp_path)
        hooks_path = tmp_path / ".cursor" / "hooks.json"
        assert hooks_path.exists()
        config = json.loads(hooks_path.read_text())
        pre_tool_use = config["hooks"]["preToolUse"]
        assert len(pre_tool_use) == 1
        assert pre_tool_use[0]["command"] == "edictum gate check --format cursor"
        assert pre_tool_use[0]["timeout"] == 5
        assert "Installed" in result

    def test_install_idempotent(self, tmp_path: Path) -> None:
        install_cursor(home=tmp_path)
        result = install_cursor(home=tmp_path)
        assert "already installed" in result

        config = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())
        pre_tool_use = config["hooks"]["preToolUse"]
        assert len(pre_tool_use) == 1  # No duplicate

    def test_install_merges_hooks(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        existing = {
            "hooks": {
                "preToolUse": [{"command": "other-hook", "timeout": 10}],
            }
        }
        (cursor_dir / "hooks.json").write_text(json.dumps(existing))

        install_cursor(home=tmp_path)
        config = json.loads((cursor_dir / "hooks.json").read_text())
        pre_tool_use = config["hooks"]["preToolUse"]
        assert len(pre_tool_use) == 2  # existing + edictum

    def test_uninstall_removes_hook(self, tmp_path: Path) -> None:
        install_cursor(home=tmp_path)
        result = uninstall_cursor(home=tmp_path)
        config = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())
        pre_tool_use = config["hooks"]["preToolUse"]
        assert len(pre_tool_use) == 0
        assert "Removed" in result

    def test_uninstall_missing_file(self, tmp_path: Path) -> None:
        result = uninstall_cursor(home=tmp_path)
        assert "No Cursor hooks" in result


class TestGeminiCliInstall:
    def test_install_creates_script_and_settings(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        result = install_gemini_cli()
        script = tmp_path / ".gemini" / "hooks" / "edictum-gate.sh"
        settings = tmp_path / ".gemini" / "settings.json"
        assert script.exists()
        assert settings.exists()
        assert "Installed" in result
        config = json.loads(settings.read_text())
        assert "BeforeTool" in config["hooks"]

    def test_install_executable(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        install_gemini_cli()
        script = tmp_path / ".gemini" / "hooks" / "edictum-gate.sh"
        assert os.access(str(script), os.X_OK)

    def test_install_script_content(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        install_gemini_cli()
        script = tmp_path / ".gemini" / "hooks" / "edictum-gate.sh"
        content = script.read_text()
        assert "edictum gate check --format gemini" in content
        assert "#!/usr/bin/env bash" in content
        assert "exit 2" in content

    def test_install_idempotent(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        install_gemini_cli()
        result = install_gemini_cli()
        assert "already installed" in result

    def test_uninstall_removes_script(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        install_gemini_cli()
        result = uninstall_gemini_cli()
        script = tmp_path / ".gemini" / "hooks" / "edictum-gate.sh"
        assert not script.exists()
        assert "Removed" in result

    def test_uninstall_missing_script(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        result = uninstall_gemini_cli()
        assert "not found" in result


class TestCopilotCliInstall:
    def test_install_creates_hooks_json(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        result = install_copilot_cli()
        hooks_path = tmp_path / ".github" / "hooks" / "hooks.json"
        assert hooks_path.exists()
        config = json.loads(hooks_path.read_text())
        assert config["version"] == 1
        pre_tool_use = config["hooks"]["preToolUse"]
        assert len(pre_tool_use) == 1
        assert pre_tool_use[0]["bash"] == "edictum gate check --format copilot"
        assert pre_tool_use[0]["timeoutSec"] == 5
        assert "Installed" in result

    def test_install_idempotent(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        install_copilot_cli()
        result = install_copilot_cli()
        assert "already installed" in result

        config = json.loads((tmp_path / ".github" / "hooks" / "hooks.json").read_text())
        assert len(config["hooks"]["preToolUse"]) == 1

    def test_install_merges_hooks(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        hooks_dir = tmp_path / ".github" / "hooks"
        hooks_dir.mkdir(parents=True)
        existing = {"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "other-hook"}]}}
        (hooks_dir / "hooks.json").write_text(json.dumps(existing))

        install_copilot_cli()
        config = json.loads((hooks_dir / "hooks.json").read_text())
        assert len(config["hooks"]["preToolUse"]) == 2

    def test_uninstall_removes_hook(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        install_copilot_cli()
        result = uninstall_copilot_cli()
        config = json.loads((tmp_path / ".github" / "hooks" / "hooks.json").read_text())
        assert len(config["hooks"]["preToolUse"]) == 0
        assert "Removed" in result

    def test_uninstall_missing_file(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.chdir(tmp_path)
        result = uninstall_copilot_cli()
        assert "No Copilot CLI hooks" in result


class TestOpenCodeInstall:
    def test_install_creates_plugin(self, tmp_path: Path) -> None:
        install_opencode(home=tmp_path)
        plugin = tmp_path / ".opencode" / "plugins" / "edictum-gate.ts"
        assert plugin.exists()
        content = plugin.read_text()
        assert "edictum" in content and "gate" in content and "check" in content

    def test_uninstall_removes_plugin(self, tmp_path: Path) -> None:
        install_opencode(home=tmp_path)
        uninstall_opencode(home=tmp_path)
        plugin = tmp_path / ".opencode" / "plugins" / "edictum-gate.ts"
        assert not plugin.exists()
