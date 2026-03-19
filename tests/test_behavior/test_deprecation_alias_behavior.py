"""Behavior tests for deprecation aliases.

Proves that renamed public API symbols still work with a DeprecationWarning
for one release cycle before removal.
"""

from __future__ import annotations

import warnings

import pytest


class TestShadowContractAlias:
    """ShadowContract import must work with a DeprecationWarning."""

    def test_import_emits_deprecation_warning(self):
        """Importing ShadowContract emits DeprecationWarning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from edictum.yaml_engine import ShadowContract  # noqa: F811, F401

            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "ObserveContract" in str(deprecations[0].message)

    def test_alias_returns_correct_class(self):
        """ShadowContract resolves to ObserveContract."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from edictum.yaml_engine import ObserveContract, ShadowContract  # noqa: F811

            assert ShadowContract is ObserveContract

    def test_nonexistent_attr_raises(self):
        """Accessing a truly missing attribute still raises AttributeError."""
        with pytest.raises(AttributeError, match="has no attribute"):
            from edictum import yaml_engine

            yaml_engine.NonexistentThing  # noqa: B018
