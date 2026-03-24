"""Behavior tests for gate CLI import error discrimination."""

from __future__ import annotations


class TestGateImportErrorDiscrimination:
    """_should_warn_gate_import distinguishes gate-missing from transitive failures."""

    def test_transitive_dep_failure_should_warn(self) -> None:
        """A missing transitive dep (e.g. jsonschema) triggers a warning."""
        from edictum.cli.main import _should_warn_gate_import

        exc = ModuleNotFoundError("No module named 'jsonschema'")
        exc.name = "jsonschema"

        assert _should_warn_gate_import(exc) is True

    def test_gate_cli_missing_should_not_warn(self) -> None:
        """A missing gate_cli module is silently skipped."""
        from edictum.cli.main import _should_warn_gate_import

        exc = ModuleNotFoundError("No module named 'edictum.cli.gate_cli'")
        exc.name = "edictum.cli.gate_cli"

        assert _should_warn_gate_import(exc) is False

    def test_bare_import_error_should_warn(self) -> None:
        """A bare ImportError (no .name attr) triggers a warning."""
        from edictum.cli.main import _should_warn_gate_import

        exc = ImportError("cannot import name 'foo'")

        assert _should_warn_gate_import(exc) is True
