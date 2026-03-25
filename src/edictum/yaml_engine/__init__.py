"""YAML Contract Pipeline — parse, validate, and compile YAML contract bundles.

Requires optional dependencies: ``pip install edictum[yaml]``
"""

from __future__ import annotations

from edictum.yaml_engine.compiler import CompiledBundle
from edictum.yaml_engine.composer import (
    ComposedBundle,
    CompositionOverride,
    CompositionReport,
    ObserveContract,
    compose_bundles,
)
from edictum.yaml_engine.loader import BundleHash


def load_bundle(source: str) -> tuple[dict, BundleHash]:
    """Load and validate a YAML contract bundle. See :func:`loader.load_bundle`."""
    from edictum.yaml_engine.loader import load_bundle as _load

    return _load(source)


def load_bundle_string(content: str | bytes) -> tuple[dict, BundleHash]:
    """Load and validate a YAML contract bundle from a string or bytes. See :func:`loader.load_bundle_string`."""
    from edictum.yaml_engine.loader import load_bundle_string as _load_string

    return _load_string(content)


def compile_contracts(bundle: dict, *, custom_operators: dict | None = None) -> CompiledBundle:
    """Compile a parsed bundle into contract objects. See :func:`compiler.compile_contracts`."""
    from edictum.yaml_engine.compiler import compile_contracts as _compile

    return _compile(bundle, custom_operators=custom_operators)


__all__ = [
    "BundleHash",
    "CompiledBundle",
    "ComposedBundle",
    "CompositionOverride",
    "CompositionReport",
    "ObserveContract",
    "compile_contracts",
    "compose_bundles",
    "load_bundle",
    "load_bundle_string",
]
