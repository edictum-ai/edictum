"""Factory functions for creating Edictum instances from YAML, templates, and merging."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from edictum._exceptions import EdictumConfigError
from edictum._validators import validate_custom_operators, validate_custom_selectors
from edictum.audit import AuditSink, FileAuditSink, RedactionPolicy
from edictum.envelope import Principal
from edictum.storage import StorageBackend

if TYPE_CHECKING:
    from edictum._guard import Edictum
    from edictum.approval import ApprovalBackend
    from edictum.envelope import ToolEnvelope
    from edictum.yaml_engine.composer import CompositionReport

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TemplateInfo:
    """Metadata about a discovered contract template."""

    name: str
    path: Path
    builtin: bool


class _NullSink:
    """No-op audit sink for when stdout is disabled and no file is configured."""

    async def emit(self, event):
        pass


def _build_guard_from_compiled(
    cls: type[Edictum],
    compiled,
    bundle_data: dict,
    policy_version: str,
    *,
    mode: str | None,
    tools: dict[str, dict] | None,
    audit_sink: AuditSink | list[AuditSink] | None,
    redaction: RedactionPolicy | None,
    backend: StorageBackend | None,
    environment: str,
    on_deny: Callable[[ToolEnvelope, str, str | None], None] | None,
    on_allow: Callable[[ToolEnvelope], None] | None,
    success_check: Callable[[str, Any], bool] | None,
    principal: Principal | None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None,
    approval_backend: ApprovalBackend | None,
) -> Edictum:
    """Shared guard construction from compiled contracts and bundle data."""
    # Handle observability config
    obs_config = bundle_data.get("observability", {})
    otel_config = obs_config.get("otel", {})
    if otel_config.get("enabled"):
        from edictum.otel import configure_otel

        configure_otel(
            service_name=otel_config.get("service_name", "edictum-agent"),
            endpoint=otel_config.get("endpoint", "http://localhost:4317"),
            protocol=otel_config.get("protocol", "grpc"),
            resource_attributes=otel_config.get("resource_attributes"),
            insecure=otel_config.get("insecure", True),
        )

    # Auto-configure audit sink from observability block if not explicitly provided
    if audit_sink is None:
        obs_file = obs_config.get("file")
        obs_stdout = obs_config.get("stdout", True)
        if obs_file:
            audit_sink = FileAuditSink(obs_file, redaction)
        elif obs_stdout is False:
            audit_sink = _NullSink()

    effective_mode = mode or compiled.default_mode
    all_contracts = (
        compiled.preconditions + compiled.postconditions + compiled.session_contracts + compiled.sandbox_contracts
    )

    # Merge YAML tools with parameter tools (parameter wins on conflict)
    yaml_tools = compiled.tools
    merged_tools = {**yaml_tools, **(tools or {})}

    return cls(
        environment=environment,
        mode=effective_mode,
        limits=compiled.limits,
        tools=merged_tools if merged_tools else None,
        contracts=all_contracts,
        audit_sink=audit_sink,
        redaction=redaction,
        backend=backend,
        policy_version=policy_version,
        on_deny=on_deny,
        on_allow=on_allow,
        success_check=success_check,
        principal=principal,
        principal_resolver=principal_resolver,
        approval_backend=approval_backend,
    )


def _from_yaml(
    cls: type[Edictum],
    *paths: str | Path,
    tools: dict[str, dict] | None = None,
    mode: str | None = None,
    audit_sink: AuditSink | list[AuditSink] | None = None,
    redaction: RedactionPolicy | None = None,
    backend: StorageBackend | None = None,
    environment: str = "production",
    return_report: bool = False,
    on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
    on_allow: Callable[[ToolEnvelope], None] | None = None,
    custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
    custom_selectors: dict[str, Callable[[ToolEnvelope], dict[str, Any]]] | None = None,
    success_check: Callable[[str, Any], bool] | None = None,
    principal: Principal | None = None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    approval_backend: ApprovalBackend | None = None,
) -> Edictum | tuple[Edictum, CompositionReport]:
    """Create an Edictum instance from one or more YAML contract bundles.

    Args:
        *paths: One or more paths to YAML contract files. When multiple
            paths are given, bundles are composed left-to-right (later
            layers override earlier ones).
        tools: Tool side-effect classifications. Merged with any ``tools:``
            section in the YAML bundle (parameter wins on conflict).
        mode: Override the bundle's default mode (enforce/observe).
        audit_sink: Custom audit sink, or a list of sinks (auto-wrapped
            in CompositeSink).
        redaction: Custom redaction policy.
        backend: Custom storage backend.
        environment: Environment name for envelope context.
        return_report: If True, return ``(guard, CompositionReport)``
            instead of just the guard.
        custom_operators: Mapping of operator names to callables.
        custom_selectors: Mapping of selector prefixes to resolver callables.
        principal: Static principal for all tool calls.
        principal_resolver: Per-call dynamic principal resolution.
        approval_backend: Backend for human-in-the-loop approval workflows.

    Returns:
        Configured Edictum instance, or a tuple of (Edictum, CompositionReport)
        when *return_report* is True.

    Raises:
        EdictumConfigError: If the YAML is invalid or custom extensions clash.
    """
    from edictum.yaml_engine.compiler import compile_contracts
    from edictum.yaml_engine.composer import CompositionReport, compose_bundles
    from edictum.yaml_engine.loader import load_bundle

    if custom_operators:
        validate_custom_operators(custom_operators)
    if custom_selectors:
        validate_custom_selectors(custom_selectors)

    if not paths:
        raise EdictumConfigError("from_yaml() requires at least one path")

    # Load all bundles
    loaded: list[tuple[dict, Any]] = []
    for p in paths:
        loaded.append(load_bundle(p))

    if len(loaded) == 1:
        bundle_data, bundle_hash = loaded[0]
        policy_version = str(bundle_hash)
        report = CompositionReport()
    else:
        bundle_tuples = [(data, str(p)) for (data, _hash), p in zip(loaded, paths)]
        composed = compose_bundles(*bundle_tuples)
        bundle_data = composed.bundle
        report = composed.report
        policy_version = hashlib.sha256(":".join(str(h) for _d, h in loaded).encode()).hexdigest()

    compiled = compile_contracts(bundle_data, custom_operators=custom_operators, custom_selectors=custom_selectors)

    guard = _build_guard_from_compiled(
        cls,
        compiled,
        bundle_data,
        policy_version,
        mode=mode,
        tools=tools,
        audit_sink=audit_sink,
        redaction=redaction,
        backend=backend,
        environment=environment,
        on_deny=on_deny,
        on_allow=on_allow,
        success_check=success_check,
        principal=principal,
        principal_resolver=principal_resolver,
        approval_backend=approval_backend,
    )

    if return_report:
        return guard, report
    return guard


def _from_yaml_string(
    cls: type[Edictum],
    content: str | bytes,
    *,
    tools: dict[str, dict] | None = None,
    mode: str | None = None,
    audit_sink: AuditSink | list[AuditSink] | None = None,
    redaction: RedactionPolicy | None = None,
    backend: StorageBackend | None = None,
    environment: str = "production",
    on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
    on_allow: Callable[[ToolEnvelope], None] | None = None,
    custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
    custom_selectors: dict[str, Callable[[ToolEnvelope], dict[str, Any]]] | None = None,
    success_check: Callable[[str, Any], bool] | None = None,
    principal: Principal | None = None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    approval_backend: ApprovalBackend | None = None,
) -> Edictum:
    """Create an Edictum instance from a YAML string or bytes.

    Like :meth:`from_yaml` but accepts YAML content directly instead of
    a file path.  Follows the ``json.load()`` / ``json.loads()`` convention.

    Raises:
        EdictumConfigError: If the YAML is invalid or custom extensions clash.
    """
    from edictum.yaml_engine.compiler import compile_contracts
    from edictum.yaml_engine.loader import load_bundle_string

    if custom_operators:
        validate_custom_operators(custom_operators)
    if custom_selectors:
        validate_custom_selectors(custom_selectors)

    bundle_data, bundle_hash = load_bundle_string(content)
    policy_version = str(bundle_hash)

    compiled = compile_contracts(bundle_data, custom_operators=custom_operators, custom_selectors=custom_selectors)

    return _build_guard_from_compiled(
        cls,
        compiled,
        bundle_data,
        policy_version,
        mode=mode,
        tools=tools,
        audit_sink=audit_sink,
        redaction=redaction,
        backend=backend,
        environment=environment,
        on_deny=on_deny,
        on_allow=on_allow,
        success_check=success_check,
        principal=principal,
        principal_resolver=principal_resolver,
        approval_backend=approval_backend,
    )


def _from_template(
    cls: type[Edictum],
    name: str,
    *,
    template_dirs: list[str | Path] | None = None,
    tools: dict[str, dict] | None = None,
    mode: str | None = None,
    audit_sink: AuditSink | list[AuditSink] | None = None,
    redaction: RedactionPolicy | None = None,
    backend: StorageBackend | None = None,
    environment: str = "production",
    on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
    on_allow: Callable[[ToolEnvelope], None] | None = None,
    custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
    custom_selectors: dict[str, Callable[[ToolEnvelope], dict[str, Any]]] | None = None,
    success_check: Callable[[str, Any], bool] | None = None,
    principal: Principal | None = None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    approval_backend: ApprovalBackend | None = None,
) -> Edictum:
    """Create an Edictum instance from a named template.

    Searches user-provided directories first, then built-in templates.

    Raises:
        EdictumConfigError: If the template is not found in any directory.
    """
    builtin_dir = Path(__file__).parent / "yaml_engine" / "templates"
    search_dirs = [Path(d) for d in (template_dirs or [])] + [builtin_dir]

    for directory in search_dirs:
        candidate = directory / f"{name}.yaml"
        if candidate.exists():
            return cls.from_yaml(
                candidate,
                tools=tools,
                mode=mode,
                audit_sink=audit_sink,
                redaction=redaction,
                backend=backend,
                environment=environment,
                on_deny=on_deny,
                on_allow=on_allow,
                custom_operators=custom_operators,
                custom_selectors=custom_selectors,
                success_check=success_check,
                principal=principal,
                principal_resolver=principal_resolver,
                approval_backend=approval_backend,
            )

    all_templates: set[str] = set()
    for directory in search_dirs:
        if directory.is_dir():
            all_templates.update(p.stem for p in directory.glob("*.yaml"))

    available = ", ".join(sorted(all_templates)) if all_templates else "none"
    raise EdictumConfigError(f"Template '{name}' not found. Available: {available}")


def _list_templates(
    cls: type[Edictum],
    template_dirs: list[str | Path] | None = None,
) -> list[TemplateInfo]:
    """Discover available contract templates.

    Returns templates from user-provided directories and built-in
    templates. When a user template has the same name as a built-in,
    the user template takes precedence.
    """
    builtin_dir = Path(__file__).parent / "yaml_engine" / "templates"

    seen: set[str] = set()
    results: list[TemplateInfo] = []

    for d in template_dirs or []:
        directory = Path(d)
        if not directory.is_dir():
            continue
        for p in sorted(directory.glob("*.yaml")):
            if p.stem not in seen:
                seen.add(p.stem)
                results.append(TemplateInfo(name=p.stem, path=p, builtin=False))

    if builtin_dir.is_dir():
        for p in sorted(builtin_dir.glob("*.yaml")):
            if p.stem not in seen:
                seen.add(p.stem)
                results.append(TemplateInfo(name=p.stem, path=p, builtin=True))

    return results


def _from_multiple(cls: type[Edictum], guards: list[Edictum]) -> Edictum:
    """Create a new Edictum instance by merging multiple guards.

    Concatenates preconditions, postconditions, and session contracts
    from all guards in order.  The first guard's audit config, mode,
    environment, and limits are used as the base.

    Duplicate contract IDs are detected: first occurrence wins and
    a warning is logged for each duplicate.

    Raises:
        EdictumConfigError: If the guards list is empty.
    """
    if not guards:
        raise EdictumConfigError("from_multiple() requires at least one guard")

    first = guards[0]
    merged = cls(
        environment=first.environment,
        mode=first.mode,
        limits=first.limits,
        audit_sink=first.audit_sink,
        redaction=first.redaction,
        backend=first.backend,
        policy_version=first.policy_version,
        on_deny=first._on_deny,
        on_allow=first._on_allow,
        success_check=first._success_check,
        approval_backend=first._approval_backend,
    )
    merged.tool_registry = first.tool_registry

    regular_attrs = ("_preconditions", "_postconditions", "_session_contracts", "_sandbox_contracts")
    shadow_attrs = (
        "_shadow_preconditions",
        "_shadow_postconditions",
        "_shadow_session_contracts",
        "_shadow_sandbox_contracts",
    )

    seen_regular_ids: set[str] = set()
    seen_shadow_ids: set[str] = set()

    for guard in guards:
        for attr, seen in (
            *((a, seen_regular_ids) for a in regular_attrs),
            *((a, seen_shadow_ids) for a in shadow_attrs),
        ):
            for contract in getattr(guard, attr):
                cid = getattr(contract, "_edictum_id", None)
                if cid and cid in seen:
                    logger.warning("Duplicate contract id '%s' in from_multiple() — first wins", cid)
                    continue
                if cid:
                    seen.add(cid)
                getattr(merged, attr).append(contract)

    return merged
