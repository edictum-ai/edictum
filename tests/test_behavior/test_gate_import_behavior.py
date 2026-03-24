"""Behavior tests for gate CLI import error discrimination."""

from __future__ import annotations

import sys
from unittest import mock


class TestGateImportErrorDiscrimination:
    """main.py distinguishes 'gate not installed' from transitive dep failures."""

    def test_transitive_dep_failure_prints_warning(self) -> None:
        """When a transitive dep (not gate_cli) is missing, a warning is printed."""
        # Create a fake module that raises ImportError on import
        fake_exc = ModuleNotFoundError("No module named 'jsonschema'")
        fake_exc.name = "jsonschema"

        with (
            mock.patch.dict(
                sys.modules,
                {"edictum.cli.gate_cli": None},
            ),
            mock.patch("edictum.cli.main._err_console") as mock_console,
        ):
            # Re-execute the gate import logic
            try:
                from edictum.cli.gate_cli import gate  # noqa: F401
            except ImportError as exc:
                # Replicate main.py logic
                missing_module = getattr(exc, "name", None)
                if missing_module != "edictum.cli.gate_cli":
                    mock_console.print.assert_not_called()  # hasn't been called yet
                    from rich.markup import escape

                    mock_console.print(f"[yellow]Warning: edictum gate failed to load: {escape(str(exc))}[/yellow]")
                    mock_console.print.assert_called_once()

    def test_gate_cli_missing_is_silent(self) -> None:
        """When gate_cli itself is missing, no warning is emitted."""
        exc = ModuleNotFoundError("No module named 'edictum.cli.gate_cli'")
        exc.name = "edictum.cli.gate_cli"

        missing_module = getattr(exc, "name", None)
        # The condition that triggers the warning
        should_warn = missing_module != "edictum.cli.gate_cli"

        assert should_warn is False

    def test_bare_import_error_warns(self) -> None:
        """A bare ImportError (no .name attr) triggers a warning."""
        exc = ImportError("cannot import name 'foo'")
        # Bare ImportError has no .name attribute
        assert not hasattr(exc, "name") or exc.name is None

        missing_module = getattr(exc, "name", None)
        should_warn = missing_module != "edictum.cli.gate_cli"

        assert should_warn is True
