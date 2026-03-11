"""Bundle Composer — merge multiple parsed YAML bundles into one."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CompositionOverride:
    """Records a contract that was replaced during composition."""

    contract_id: str
    overridden_by: str  # source label of the winning layer
    original_source: str  # source label of the replaced layer


@dataclass(frozen=True)
class ShadowContract:
    """Records a contract added as an observe-mode copy (observe_alongside)."""

    contract_id: str
    enforced_source: str  # source label of the enforced version
    observed_source: str  # source label of the observe-mode version


@dataclass(frozen=True)
class CompositionReport:
    """Report of what happened during composition."""

    overridden_contracts: list[CompositionOverride] = field(default_factory=list)
    shadow_contracts: list[ShadowContract] = field(default_factory=list)


@dataclass(frozen=True)
class ComposedBundle:
    """Result of composing multiple bundles."""

    bundle: dict[str, Any]
    report: CompositionReport


def compose_bundles(*bundles: tuple[dict[str, Any], str]) -> ComposedBundle:
    """Merge multiple parsed bundle dicts left to right.

    Each bundle is a tuple of (parsed_dict, source_label). Later layers
    have higher priority.

    Args:
        *bundles: Tuples of (bundle_data, source_label).

    Returns:
        ComposedBundle with the merged bundle dict and composition report.

    Raises:
        ValueError: If no bundles are provided.
    """
    if not bundles:
        raise ValueError("compose_bundles() requires at least one bundle")

    if len(bundles) == 1:
        data, _label = bundles[0]
        return ComposedBundle(bundle=_deep_copy_bundle(data), report=CompositionReport())

    overrides: list[CompositionOverride] = []
    shadows: list[ShadowContract] = []

    # Start with a copy of the first bundle
    first_data, first_label = bundles[0]
    merged = _deep_copy_bundle(first_data)

    # Track contract origins: contract_id -> source_label
    contract_sources: dict[str, str] = {}
    for c in merged.get("contracts", []):
        contract_sources[c["id"]] = first_label

    for data, label in bundles[1:]:
        is_observe_alongside = data.get("observe_alongside", False)

        if is_observe_alongside:
            _merge_observe_alongside(merged, data, label, contract_sources, shadows)
        else:
            _merge_standard(merged, data, label, contract_sources, overrides)

    return ComposedBundle(
        bundle=merged,
        report=CompositionReport(
            overridden_contracts=overrides,
            shadow_contracts=shadows,
        ),
    )


def _deep_copy_bundle(data: dict[str, Any]) -> dict[str, Any]:
    """Deep copy a bundle dict (no external deps)."""
    import copy

    return copy.deepcopy(data)


def _merge_standard(
    merged: dict[str, Any],
    layer: dict[str, Any],
    label: str,
    contract_sources: dict[str, str],
    overrides: list[CompositionOverride],
) -> None:
    """Merge a standard (non-observe_alongside) layer into the merged bundle."""
    # defaults.mode: later wins
    if "defaults" in layer:
        layer_defaults = layer["defaults"]
        if "mode" in layer_defaults:
            merged.setdefault("defaults", {})["mode"] = layer_defaults["mode"]
        if "environment" in layer_defaults:
            merged.setdefault("defaults", {})["environment"] = layer_defaults["environment"]

    # limits: later wins (entire block replaced)
    if "limits" in layer:
        merged["limits"] = _deep_copy_bundle(layer["limits"])

    # tools: deep merge
    if "tools" in layer:
        merged_tools = merged.get("tools", {})
        for tool_name, tool_config in layer["tools"].items():
            merged_tools[tool_name] = dict(tool_config)
        merged["tools"] = merged_tools

    # metadata: deep merge
    if "metadata" in layer:
        merged_meta = merged.get("metadata", {})
        for key, value in layer["metadata"].items():
            merged_meta[key] = value
        merged["metadata"] = merged_meta

    # observability: later wins
    if "observability" in layer:
        merged["observability"] = _deep_copy_bundle(layer["observability"])

    # contracts: same ID replaces, unique ID concatenates
    if "contracts" in layer:
        existing_by_id: dict[str, int] = {}
        for i, c in enumerate(merged.get("contracts", [])):
            existing_by_id[c["id"]] = i

        for contract in layer["contracts"]:
            cid = contract["id"]
            new_contract = _deep_copy_bundle(contract)

            if cid in existing_by_id:
                # Replace existing contract
                idx = existing_by_id[cid]
                original_source = contract_sources.get(cid, "unknown")
                overrides.append(
                    CompositionOverride(
                        contract_id=cid,
                        overridden_by=label,
                        original_source=original_source,
                    )
                )
                merged["contracts"][idx] = new_contract
                contract_sources[cid] = label
            else:
                # Append new contract
                merged.setdefault("contracts", []).append(new_contract)
                existing_by_id[cid] = len(merged["contracts"]) - 1
                contract_sources[cid] = label


def _merge_observe_alongside(
    merged: dict[str, Any],
    layer: dict[str, Any],
    label: str,
    contract_sources: dict[str, str],
    shadows: list[ShadowContract],
) -> None:
    """Merge an observe_alongside layer — contracts become observe-mode copies."""
    for contract in layer.get("contracts", []):
        cid = contract["id"]
        shadow_id = f"{cid}:candidate"

        shadow_contract = _deep_copy_bundle(contract)
        shadow_contract["id"] = shadow_id
        shadow_contract["mode"] = "observe"
        shadow_contract["_shadow"] = True

        merged.setdefault("contracts", []).append(shadow_contract)

        enforced_source = contract_sources.get(cid, "")
        shadows.append(
            ShadowContract(
                contract_id=cid,
                enforced_source=enforced_source,
                observed_source=label,
            )
        )

    # observe_alongside layers can also carry metadata/tools — deep merge them
    if "tools" in layer:
        merged_tools = merged.get("tools", {})
        for tool_name, tool_config in layer["tools"].items():
            merged_tools[tool_name] = dict(tool_config)
        merged["tools"] = merged_tools

    if "metadata" in layer:
        merged_meta = merged.get("metadata", {})
        for key, value in layer["metadata"].items():
            merged_meta[key] = value
        merged["metadata"] = merged_meta
