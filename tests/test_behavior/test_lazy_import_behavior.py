"""Behavior tests for lazy yaml_engine imports in edictum.__init__."""

from __future__ import annotations

import sys
from unittest import mock


class TestCompositionReportLazyImport:
    """CompositionReport is lazy-loaded from yaml_engine."""

    def test_accessible_when_yaml_extras_installed(self) -> None:
        """from edictum import CompositionReport works with yaml extras."""
        from edictum import CompositionReport
        from edictum.yaml_engine.composer import (
            CompositionReport as DirectCompositionReport,
        )

        assert CompositionReport is DirectCompositionReport

    def test_in_all(self) -> None:
        """CompositionReport is listed in __all__."""
        import edictum

        assert "CompositionReport" in edictum.__all__

    def test_hasattr_true_when_installed(self) -> None:
        """hasattr returns True when yaml extras are available."""
        import edictum

        assert hasattr(edictum, "CompositionReport")

    def test_hasattr_false_when_yaml_missing(self) -> None:
        """hasattr returns False (not ImportError) when yaml extras missing."""
        import edictum

        # Clear cached value so __getattr__ fires
        edictum.__dict__.pop("CompositionReport", None)

        with mock.patch.dict(sys.modules, {"edictum.yaml_engine.composer": None}):
            # Must also clear from importlib cache
            result = hasattr(edictum, "CompositionReport")

        # Restore by re-triggering the lazy load
        edictum.__dict__.pop("CompositionReport", None)
        _ = edictum.CompositionReport

        assert result is False

    def test_raises_attribute_error_not_import_error(self) -> None:
        """__getattr__ raises AttributeError (PEP 562), not ImportError."""
        import pytest

        import edictum

        edictum.__dict__.pop("CompositionReport", None)

        with mock.patch.dict(sys.modules, {"edictum.yaml_engine.composer": None}):
            with pytest.raises(AttributeError, match="edictum\\[yaml\\]"):
                _ = edictum.CompositionReport

        # Restore
        edictum.__dict__.pop("CompositionReport", None)
        _ = edictum.CompositionReport

    def test_unknown_attr_raises_attribute_error(self) -> None:
        """Accessing a nonexistent attr raises AttributeError."""
        import pytest

        import edictum

        with pytest.raises(AttributeError, match="no_such_thing"):
            _ = edictum.no_such_thing  # type: ignore[attr-defined]

    def test_cached_after_first_access(self) -> None:
        """Lazy value is cached in module dict after first access."""
        import edictum

        # Clear and re-access
        edictum.__dict__.pop("CompositionReport", None)
        _ = edictum.CompositionReport

        # Now it should be in the module dict directly
        assert "CompositionReport" in edictum.__dict__


class TestNoUnintendedExports:
    """Only CompositionReport is lazy-exported, not other yaml_engine symbols."""

    def test_load_bundle_not_accessible(self) -> None:
        import edictum

        assert not hasattr(edictum, "load_bundle")

    def test_compile_contracts_not_accessible(self) -> None:
        import edictum

        assert not hasattr(edictum, "compile_contracts")

    def test_compose_bundles_not_accessible(self) -> None:
        import edictum

        assert not hasattr(edictum, "compose_bundles")
