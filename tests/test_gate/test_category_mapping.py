"""Tests for tool category mapping."""

from __future__ import annotations

from edictum.gate.check import resolve_category


class TestCategoryMapping:
    def test_bash_category(self) -> None:
        assert resolve_category("Bash") == "shell"

    def test_read_category(self) -> None:
        assert resolve_category("Read") == "file.read"

    def test_write_category(self) -> None:
        assert resolve_category("Write") == "file.write"

    def test_edit_category(self) -> None:
        assert resolve_category("Edit") == "file.edit"

    def test_glob_category(self) -> None:
        assert resolve_category("Glob") == "file.search"

    def test_grep_category(self) -> None:
        assert resolve_category("Grep") == "file.search"

    def test_webfetch_category(self) -> None:
        assert resolve_category("WebFetch") == "browser"

    def test_websearch_category(self) -> None:
        assert resolve_category("WebSearch") == "browser"

    def test_mcp_prefix(self) -> None:
        assert resolve_category("mcp__chrome__click") == "mcp"

    def test_unknown_tool(self) -> None:
        assert resolve_category("SomeNewTool") == "unknown"

    def test_notebook_category(self) -> None:
        assert resolve_category("NotebookEdit") == "notebook"

    def test_task_category(self) -> None:
        assert resolve_category("Task") == "task"
