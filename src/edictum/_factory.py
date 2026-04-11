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
    from edictum.envelope import ToolCall
    from edictum.workflow import WorkflowRuntime
    from edictum.yaml_engine.composer import CompositionReport

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TemplateInfo:
    """Metadata about a discovered rule template."""

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
    on_block: Callable[[ToolCall, str, str | None], None] | None,
    on_allow: Callable[[ToolCall], None] | None,
    success_check: Callable[[str, Any], bool] | None,
    principal: Principal | None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None,
    approval_backend: ApprovalBackend | None,
    workflow_runtime: WorkflowRuntime | None,
) -> Edictum:
    """Shared guard construction from compiled rules and bundle data."""
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
        rules=all_contracts,
        audit_sink=audit_sink,
        redaction=redaction,
        backend=backend,
        policy_version=policy_version,
        on_block=on_block,
        on_allow=on_allow,
        success_check=success_check,
        principal=principal,
        principal_resolver=principal_resolver,
        approval_backend=approval_backend,
        workflow_runtime=workflow_runtime,
    )


def _load_workflow_runtime(
    *,
    workflow_path: str | Path | None = None,
    workflow_content: str | bytes | None = None,
    workflow_exec_evaluator_enabled: bool = False,
):
    if workflow_path is None and workflow_content is None:
        return None
    if workflow_path is not None and workflow_content is not None:
        raise EdictumConfigError("Specify only one of workflow_path or workflow_content")

    from edictum.workflow import WorkflowRuntime, load_workflow, load_workflow_string

    if workflow_path is not None:
        definition = load_workflow(workflow_path)
    else:
        assert workflow_content is not None
        definition = load_workflow_string(workflow_content)
    return WorkflowRuntime(
        definition,
        exec_evaluator_enabled=workflow_exec_evaluator_enabled,
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
    on_block: Callable[[ToolCall, str, str | None], None] | None = None,
    on_allow: Callable[[ToolCall], None] | None = None,
    custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
    custom_selectors: dict[str, Callable[[ToolCall], dict[str, Any]]] | None = None,
    success_check: Callable[[str, Any], bool] | None = None,
    principal: Principal | None = None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    approval_backend: ApprovalBackend | None = None,
    workflow_path: str | Path | None = None,
    workflow_exec_evaluator_enabled: bool = False,
) -> Edictum | tuple[Edictum, CompositionReport]:
    """Create an Edictum instance from one or more YAML rule bundles.

    Args:
        *paths: One or more paths to YAML rule files. When multiple
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
    workflow_runtime = _load_workflow_runtime(
        workflow_path=workflow_path,
        workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
    )

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
        on_block=on_block,
        on_allow=on_allow,
        success_check=success_check,
        principal=principal,
        principal_resolver=principal_resolver,
        approval_backend=approval_backend,
        workflow_runtime=workflow_runtime,
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
    on_block: Callable[[ToolCall, str, str | None], None] | None = None,
    on_allow: Callable[[ToolCall], None] | None = None,
    custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
    custom_selectors: dict[str, Callable[[ToolCall], dict[str, Any]]] | None = None,
    success_check: Callable[[str, Any], bool] | None = None,
    principal: Principal | None = None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    approval_backend: ApprovalBackend | None = None,
    workflow_content: str | bytes | None = None,
    workflow_exec_evaluator_enabled: bool = False,
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
    workflow_runtime = _load_workflow_runtime(
        workflow_content=workflow_content,
        workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
    )

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
        on_block=on_block,
        on_allow=on_allow,
        success_check=success_check,
        principal=principal,
        principal_resolver=principal_resolver,
        approval_backend=approval_backend,
        workflow_runtime=workflow_runtime,
    )


def _from_bundle_dict(
    cls: type[Edictum],
    bundle: dict,
    policy_version: str,
    *,
    mode: str | None = None,
    audit_sink: AuditSink | list[AuditSink] | None = None,
    redaction: RedactionPolicy | None = None,
    backend: StorageBackend | None = None,
    environment: str = "production",
) -> Edictum:
    """Create an Edictum instance from an already-parsed bundle dict."""
    from edictum.yaml_engine.compiler import compile_contracts
    from edictum.yaml_engine.loader import (
        _validate_pre_selectors,
        _validate_regexes,
        _validate_sandbox_contracts,
        _validate_unique_ids,
    )

    _validate_unique_ids(bundle)
    _validate_regexes(bundle)
    _validate_pre_selectors(bundle)
    _validate_sandbox_contracts(bundle)
    compiled = compile_contracts(bundle)
    return _build_guard_from_compiled(
        cls,
        compiled,
        bundle,
        policy_version,
        mode=mode,
        tools=None,
        audit_sink=audit_sink,
        redaction=redaction,
        backend=backend,
        environment=environment,
        on_block=None,
        on_allow=None,
        success_check=None,
        principal=None,
        principal_resolver=None,
        approval_backend=None,
        workflow_runtime=None,
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
    on_block: Callable[[ToolCall, str, str | None], None] | None = None,
    on_allow: Callable[[ToolCall], None] | None = None,
    custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
    custom_selectors: dict[str, Callable[[ToolCall], dict[str, Any]]] | None = None,
    success_check: Callable[[str, Any], bool] | None = None,
    principal: Principal | None = None,
    principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    approval_backend: ApprovalBackend | None = None,
    workflow_path: str | Path | None = None,
    workflow_content: str | bytes | None = None,
    workflow_exec_evaluator_enabled: bool = False,
) -> Edictum:
    """Create an Edictum instance from a named template.

    Searches user-provided directories first, then built-in templates.

    Raises:
        EdictumConfigError: If the template is not found in any directory.
    """
    if workflow_path is not None and workflow_content is not None:
        raise EdictumConfigError("Specify only one of workflow_path or workflow_content")

    builtin_dir = Path(__file__).parent / "yaml_engine" / "templates"
    search_dirs = [Path(d) for d in (template_dirs or [])] + [builtin_dir]

    for directory in search_dirs:
        candidate = directory / f"{name}.yaml"
        if candidate.exists():
            if workflow_content is None:
                result = cls.from_yaml(
                    candidate,
                    tools=tools,
                    mode=mode,
                    audit_sink=audit_sink,
                    redaction=redaction,
                    backend=backend,
                    environment=environment,
                    on_block=on_block,
                    on_allow=on_allow,
                    custom_operators=custom_operators,
                    custom_selectors=custom_selectors,
                    success_check=success_check,
                    principal=principal,
                    principal_resolver=principal_resolver,
                    approval_backend=approval_backend,
                    workflow_path=workflow_path,
                    workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
                )
            else:
                result = cls.from_yaml_string(
                    candidate.read_bytes(),
                    tools=tools,
                    mode=mode,
                    audit_sink=audit_sink,
                    redaction=redaction,
                    backend=backend,
                    environment=environment,
                    on_block=on_block,
                    on_allow=on_allow,
                    custom_operators=custom_operators,
                    custom_selectors=custom_selectors,
                    success_check=success_check,
                    principal=principal,
                    principal_resolver=principal_resolver,
                    approval_backend=approval_backend,
                    workflow_content=workflow_content,
                    workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
                )
            if isinstance(result, tuple):
                return result[0]
            return result

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
    """Discover available rule templates.

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

    Concatenates preconditions, postconditions, and session rules
    from all guards in order.  The first guard's audit config, mode,
    environment, and limits are used as the base.

    Duplicate rule IDs are detected: first occurrence wins and
    a warning is logged for each duplicate.

    Raises:
        EdictumConfigError: If the guards list is empty.
    """
    from edictum._guard import _CompiledState

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
        on_block=first._on_deny,
        on_allow=first._on_allow,
        success_check=first._success_check,
        approval_backend=first._approval_backend,
        workflow_runtime=first._workflow_runtime,
    )
    merged.tool_registry = first.tool_registry

    regular_attrs = ("preconditions", "postconditions", "session_contracts", "sandbox_contracts")
    observe_attrs = (
        "observe_preconditions",
        "observe_postconditions",
        "observe_session_contracts",
        "observe_sandbox_contracts",
    )

    seen_regular_ids: set[str] = set()
    seen_observe_ids: set[str] = set()

    collected: dict[str, list] = {a: [] for a in (*regular_attrs, *observe_attrs)}

    for guard in guards:
        for attr, seen in (
            *((a, seen_regular_ids) for a in regular_attrs),
            *((a, seen_observe_ids) for a in observe_attrs),
        ):
            for rule in getattr(guard._state, attr):
                cid = getattr(rule, "_edictum_id", None)
                if cid and cid in seen:
                    logger.warning("Duplicate rule id '%s' in from_multiple() — first wins", cid)
                    continue
                if cid:
                    seen.add(cid)
                collected[attr].append(rule)

    merged._state = _CompiledState(
        preconditions=tuple(collected["preconditions"]),
        postconditions=tuple(collected["postconditions"]),
        session_contracts=tuple(collected["session_contracts"]),
        sandbox_contracts=tuple(collected["sandbox_contracts"]),
        observe_preconditions=tuple(collected["observe_preconditions"]),
        observe_postconditions=tuple(collected["observe_postconditions"]),
        observe_session_contracts=tuple(collected["observe_session_contracts"]),
        observe_sandbox_contracts=tuple(collected["observe_sandbox_contracts"]),
        limits=merged._state.limits,
        policy_version=merged._state.policy_version,
    )

    return merged
