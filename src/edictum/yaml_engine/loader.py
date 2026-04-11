"""YAML Bundle Loader — parse, validate against JSON Schema, compute bundle hash."""

from __future__ import annotations

import hashlib
import importlib.resources as _resources
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import jsonschema
    import yaml
except ImportError as _exc:
    raise ImportError(
        "The YAML engine requires pyyaml and jsonschema. Install them with: pip install edictum[yaml]"
    ) from _exc

MAX_BUNDLE_SIZE = 1_048_576  # 1 MB

# Lazy-loaded schema singleton
_schema_cache: dict[str, dict] = {}


def _get_schema(version: str) -> dict:
    """Load and cache a JSON Schema for validation."""
    import json

    global _schema_cache  # noqa: PLW0603
    if version not in _schema_cache:
        schema_text = (
            _resources.files("edictum.yaml_engine")
            .joinpath(f"edictum-{version}.schema.json")
            .read_text(encoding="utf-8")
        )
        _schema_cache[version] = json.loads(schema_text)
    return _schema_cache[version]


@dataclass(frozen=True)
class BundleHash:
    """SHA256 hash of raw YAML bytes, used as policy_version."""

    hex: str

    def __str__(self) -> str:
        return self.hex


def _compute_hash(raw_bytes: bytes) -> BundleHash:
    """Compute SHA256 hash of raw YAML bytes."""
    return BundleHash(hex=hashlib.sha256(raw_bytes).hexdigest())


def _validate_schema(data: dict) -> None:
    """Validate parsed YAML against the Edictum v2 JSON Schema."""
    from edictum import EdictumConfigError

    schema = _get_schema("v2")

    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as error:
        raise EdictumConfigError(f"Schema validation failed: {error.message}") from error


def _validate_unique_ids(data: dict) -> None:
    """Ensure all rule IDs are unique within the bundle."""
    from edictum import EdictumConfigError

    ids: set[str] = set()
    for rule in data.get("rules", []):
        rule_id = rule.get("id")
        if rule_id in ids:
            raise EdictumConfigError(f"Duplicate rule id: '{rule_id}'")
        ids.add(rule_id)


def _validate_regexes(data: dict) -> None:
    """Compile all regex patterns at load time to catch invalid patterns early."""

    for rule in data.get("rules", []):
        when = rule.get("when")
        if when:
            _validate_expression_regexes(when)


def _validate_expression_regexes(expr: dict | Any) -> None:
    """Recursively validate regex patterns in expressions."""

    if not isinstance(expr, dict):
        return

    # Boolean nodes
    if "all" in expr:
        for sub in expr["all"]:
            _validate_expression_regexes(sub)
        return
    if "any" in expr:
        for sub in expr["any"]:
            _validate_expression_regexes(sub)
        return
    if "not" in expr:
        _validate_expression_regexes(expr["not"])
        return

    # Leaf node: selector -> operator
    for _selector, operator in expr.items():
        if not isinstance(operator, dict):
            continue
        if "matches" in operator:
            _try_compile_regex(operator["matches"])
        if "matches_any" in operator:
            for pattern in operator["matches_any"]:
                _try_compile_regex(pattern)


def _validate_pre_selectors(data: dict) -> None:
    """Reject output.text selectors in type: pre rules (spec violation)."""
    from edictum import EdictumConfigError

    for rule in data.get("rules", []):
        if rule.get("type") != "pre":
            continue
        when = rule.get("when")
        if when and _expression_has_selector(when, "output.text"):
            raise EdictumConfigError(
                f"Rule '{rule.get('id', '?')}': output.text selector is not available in type: pre rules"
            )


def _expression_has_selector(expr: dict | Any, target: str) -> bool:
    """Check if an expression tree contains a specific selector."""
    if not isinstance(expr, dict):
        return False
    if "all" in expr:
        return any(_expression_has_selector(sub, target) for sub in expr["all"])
    if "any" in expr:
        return any(_expression_has_selector(sub, target) for sub in expr["any"])
    if "not" in expr:
        return _expression_has_selector(expr["not"], target)
    # Leaf node: check selector keys
    return target in expr


def _try_compile_regex(pattern: str) -> None:
    """Attempt to compile a regex pattern, raising EdictumConfigError on failure."""
    from edictum import EdictumConfigError

    try:
        re.compile(pattern)
    except re.error as e:
        raise EdictumConfigError(f"Invalid regex pattern '{pattern}': {e}") from e


def _validate_sandbox_contracts(data: dict) -> None:
    """Validate sandbox rule field dependencies."""
    from edictum import EdictumConfigError

    for rule in data.get("rules", []):
        if rule.get("type") != "sandbox":
            continue
        rid = rule.get("id", "?")
        # not_within requires within
        if "not_within" in rule and "within" not in rule:
            raise EdictumConfigError(f"Rule '{rid}': not_within requires within to also be set")
        # not_allows requires allows
        if "not_allows" in rule and "allows" not in rule:
            raise EdictumConfigError(f"Rule '{rid}': not_allows requires allows to also be set")
        # not_allows.domains requires allows.domains
        if "not_allows" in rule and "domains" in rule.get("not_allows", {}):
            if "domains" not in rule.get("allows", {}):
                raise EdictumConfigError(f"Rule '{rid}': not_allows.domains requires allows.domains to also be set")


def _load_data(raw_bytes: bytes) -> tuple[dict, BundleHash]:
    from edictum import EdictumConfigError

    bundle_hash = _compute_hash(raw_bytes)

    try:
        data = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as e:
        raise EdictumConfigError(f"YAML parse error: {e}") from e

    if not isinstance(data, dict):
        raise EdictumConfigError("YAML document must be a mapping")

    _validate_schema(data)
    normalized = data
    _validate_unique_ids(normalized)
    _validate_regexes(normalized)
    _validate_pre_selectors(normalized)
    _validate_sandbox_contracts(normalized)

    return normalized, bundle_hash


_MAX_EXTENDS_DEPTH = 50


def resolve_ruleset_extends(rulesets: dict[str, dict], name: str, *, _seen: frozenset[str] | None = None) -> dict:
    """Resolve extends: inheritance for a named ruleset within a registry.

    Merges parent rules before child rules. Child defaults override parent defaults.

    Args:
        rulesets: Mapping of ruleset names to raw ruleset dicts.
        name: Name of the ruleset to resolve.

    Returns:
        Merged ruleset dict ready for compilation.

    Raises:
        KeyError: If a referenced ruleset is not in the registry.
        ValueError: If a circular extends reference is detected or the chain
            exceeds the maximum depth (_MAX_EXTENDS_DEPTH).
    """
    seen = _seen or frozenset()
    if name in seen:
        raise ValueError(f"extends: circular reference detected for ruleset '{name}'")
    if len(seen) >= _MAX_EXTENDS_DEPTH:
        raise ValueError(f"extends: inheritance chain exceeds maximum depth ({_MAX_EXTENDS_DEPTH})")
    child = dict(rulesets[name])
    parent_name = child.pop("extends", None)
    if parent_name is None:
        return child
    parent = resolve_ruleset_extends(rulesets, str(parent_name), _seen=seen | {name})
    return _merge_parent_bundle(parent, child)


def _merge_parent_bundle(parent: dict, child: dict) -> dict:
    """Merge parent bundle into child: parent rules first, child defaults win."""
    merged = dict(parent)
    # Child defaults override parent defaults
    if "defaults" in child:
        merged["defaults"] = child["defaults"]
    # Child metadata overrides parent
    if "metadata" in child:
        merged["metadata"] = child["metadata"]
    # Rules: parent first, then child
    parent_rules = list(parent.get("rules", []))
    child_rules = list(child.get("rules", []))
    merged["rules"] = parent_rules + child_rules
    # All other top-level fields: child wins
    for key, value in child.items():
        if key not in ("defaults", "metadata", "rules"):
            merged[key] = value
    return merged


def load_bundle(source: str | Path) -> tuple[dict, BundleHash]:
    """Load and validate a YAML rules bundle.

    Args:
        source: Path to a YAML file.

    Returns:
        Tuple of (parsed normalized bundle dict, bundle hash).

    Raises:
        EdictumConfigError: If the YAML is invalid, fails schema validation,
            has duplicate rule IDs, or contains invalid regex patterns.
        FileNotFoundError: If the file does not exist.
    """
    from edictum import EdictumConfigError

    path = Path(source)

    file_size = path.stat().st_size
    if file_size > MAX_BUNDLE_SIZE:
        raise EdictumConfigError(f"Bundle file too large ({file_size} bytes, max {MAX_BUNDLE_SIZE})")

    raw_bytes = path.read_bytes()
    return _load_data(raw_bytes)


def load_bundle_string(content: str | bytes) -> tuple[dict, BundleHash]:
    """Load and validate a YAML rules bundle from a string or bytes.

    Like :func:`load_bundle` but accepts YAML content directly instead of
    a file path. Useful when YAML is generated programmatically or fetched
    from an API.

    Args:
        content: YAML content as a string or bytes.

    Returns:
        Tuple of (parsed normalized bundle dict, bundle hash).

    Raises:
        EdictumConfigError: If the YAML is invalid, fails schema validation,
            has duplicate rule IDs, or contains invalid regex patterns.
    """
    from edictum import EdictumConfigError

    if isinstance(content, str):
        raw_bytes = content.encode("utf-8")
    else:
        raw_bytes = content

    if len(raw_bytes) > MAX_BUNDLE_SIZE:
        raise EdictumConfigError(f"Bundle content too large ({len(raw_bytes)} bytes, max {MAX_BUNDLE_SIZE})")

    return _load_data(raw_bytes)
