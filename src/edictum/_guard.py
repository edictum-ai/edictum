"""Core Edictum class — construction, rule registry, and method delegation."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING, Any

from edictum.approval import ApprovalBackend
from edictum.audit import (
    AuditSink,
    CollectingAuditSink,
    CompositeSink,
    RedactionPolicy,
)
from edictum.envelope import Principal, SideEffect, ToolCall, ToolRegistry
from edictum.limits import OperationLimits
from edictum.otel import get_tracer
from edictum.storage import MemoryBackend, StorageBackend
from edictum.telemetry import GovernanceTelemetry
from edictum.types import HookRegistration

if TYPE_CHECKING:
    from edictum._factory import TemplateInfo
    from edictum.evaluation import EvaluationResult
    from edictum.workflow import WorkflowRuntime
    from edictum.yaml_engine.composer import CompositionReport

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _CompiledState:
    """Immutable snapshot of compiled rules.

    All rule lists are tuples (immutable). The entire state is
    replaced atomically via a single reference assignment in reload(),
    ensuring concurrent evaluations never see a mix of old and new
    rules.
    """

    preconditions: tuple = ()
    postconditions: tuple = ()
    session_contracts: tuple = ()
    sandbox_contracts: tuple = ()
    observe_preconditions: tuple = ()
    observe_postconditions: tuple = ()
    observe_session_contracts: tuple = ()
    observe_sandbox_contracts: tuple = ()
    limits: OperationLimits = field(default_factory=OperationLimits)
    policy_version: str | None = None


class Edictum:
    """Main configuration and entrypoint.

    Two usage modes:
    1. With Claude Agent SDK: use ClaudeAgentSDKAdapter
    2. Framework-agnostic: use guard.run() directly
    """

    def __init__(
        self,
        *,
        environment: str = "production",
        mode: str = "enforce",
        limits: OperationLimits | None = None,
        tools: dict[str, dict] | None = None,
        rules: list | None = None,
        hooks: list | None = None,
        audit_sink: AuditSink | list[AuditSink] | None = None,
        redaction: RedactionPolicy | None = None,
        backend: StorageBackend | None = None,
        policy_version: str | None = None,
        on_block: Callable[[ToolCall, str, str | None], None] | None = None,
        on_allow: Callable[[ToolCall], None] | None = None,
        success_check: Callable[[str, Any], bool] | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        approval_backend: ApprovalBackend | None = None,
        workflow_runtime: WorkflowRuntime | None = None,
    ):
        self.environment = environment
        self.mode = mode
        self.backend = backend or MemoryBackend()
        self.redaction = redaction or RedactionPolicy()
        self._local_sink = CollectingAuditSink()
        if isinstance(audit_sink, list):
            self.audit_sink: AuditSink = CompositeSink([self._local_sink] + audit_sink)
        elif audit_sink is not None:
            self.audit_sink = CompositeSink([self._local_sink, audit_sink])
        else:
            self.audit_sink = self._local_sink
        self.telemetry = GovernanceTelemetry()
        self._gov_tracer = get_tracer("edictum.governance")
        self._on_deny = on_block
        self._on_allow = on_allow
        self._success_check = success_check
        self._principal = principal
        self._principal_resolver = principal_resolver
        self._approval_backend = approval_backend
        self._workflow_runtime = workflow_runtime
        self._server_client: Any | None = None
        self._rule_source: Any | None = None
        self._sse_task: Any | None = None
        self._assignment_ready: Any | None = None
        self._verify_signatures = False
        self._signing_public_key: str | None = None

        # Build tool registry
        self.tool_registry = ToolRegistry()
        if tools:
            for name, config in tools.items():
                self.tool_registry.register(
                    name,
                    side_effect=SideEffect(config.get("side_effect", "irreversible")),
                    idempotent=config.get("idempotent", False),
                )

        # Classify rules into mutable local lists during construction
        pre: list = []
        post: list = []
        session: list = []
        sandbox: list = []
        s_pre: list = []
        s_post: list = []
        s_session: list = []
        s_sandbox: list = []

        for item in rules or []:
            item_type = getattr(item, "_edictum_type", None)
            is_observe = getattr(item, "_edictum_observe", False)

            if is_observe:
                if item_type == "precondition":
                    s_pre.append(item)
                elif item_type == "postcondition":
                    s_post.append(item)
                elif item_type == "session_contract":
                    s_session.append(item)
                elif item_type == "sandbox":
                    s_sandbox.append(item)
            elif item_type == "precondition":
                pre.append(item)
            elif item_type == "postcondition":
                post.append(item)
            elif item_type == "session_contract":
                session.append(item)
            elif item_type == "sandbox":
                sandbox.append(item)

        # Freeze all rule state into a single immutable snapshot.
        # Concurrent evaluations read self._state; reload() replaces it
        # via a single reference assignment (atomic under CPython's GIL
        # and safe under asyncio cooperative scheduling).
        self._state = _CompiledState(
            preconditions=tuple(pre),
            postconditions=tuple(post),
            session_contracts=tuple(session),
            sandbox_contracts=tuple(sandbox),
            observe_preconditions=tuple(s_pre),
            observe_postconditions=tuple(s_post),
            observe_session_contracts=tuple(s_session),
            observe_sandbox_contracts=tuple(s_sandbox),
            limits=limits or OperationLimits(),
            policy_version=policy_version,
        )

        # Hooks are not reloaded — mutable lists are fine
        self._before_hooks: list[HookRegistration] = []
        self._after_hooks: list[HookRegistration] = []
        for item in hooks or []:
            self._register_hook(item)

        # Persistent session for accumulating limits across run() calls
        self._session_id = str(uuid.uuid4())

    @property
    def local_sink(self) -> CollectingAuditSink:
        """The local in-memory audit event collector.

        Always present regardless of construction method (``__init__``,
        ``from_yaml()``, ``from_server()``). Use ``mark()`` /
        ``since_mark()`` to inspect governance decisions programmatically.
        """
        return self._local_sink

    @property
    def limits(self) -> OperationLimits:
        """Operation limits for the current rule set."""
        return self._state.limits

    @limits.setter
    def limits(self, value: OperationLimits) -> None:
        self._state = replace(self._state, limits=value)

    @property
    def policy_version(self) -> str | None:
        """SHA256 hash identifying the active rule bundle."""
        return self._state.policy_version

    @policy_version.setter
    def policy_version(self, value: str | None) -> None:
        self._state = replace(self._state, policy_version=value)

    async def reload(self, contracts_yaml: bytes | str) -> None:
        """Atomically replace all rules from a YAML bundle.

        Builds a complete ``_CompiledState``, then swaps via a single
        reference assignment. Concurrent evaluations see either
        fully-old or fully-new rules, never a mix.

        On failure, existing rules are preserved (fail-closed).
        """
        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.loader import load_bundle_string

        bundle_data, bundle_hash = load_bundle_string(contracts_yaml)
        compiled = compile_contracts(bundle_data)

        # Sort compiled rules into enforced vs observe-mode lists,
        # mirroring the classification that __init__() does at construction time.
        # Build the full state before touching self._state for atomicity.
        all_contracts = (
            compiled.preconditions + compiled.postconditions + compiled.session_contracts + compiled.sandbox_contracts
        )
        pre: list = []
        post: list = []
        session: list = []
        sandbox: list = []
        observe_pre: list = []
        observe_post: list = []
        observe_session: list = []
        observe_sandbox: list = []
        for rule in all_contracts:
            ctype = getattr(rule, "_edictum_type", None)
            is_observe = getattr(rule, "_edictum_observe", False)
            if is_observe:
                if ctype == "precondition":
                    observe_pre.append(rule)
                elif ctype == "postcondition":
                    observe_post.append(rule)
                elif ctype == "session_contract":
                    observe_session.append(rule)
                elif ctype == "sandbox":
                    observe_sandbox.append(rule)
            elif ctype == "precondition":
                pre.append(rule)
            elif ctype == "postcondition":
                post.append(rule)
            elif ctype == "session_contract":
                session.append(rule)
            elif ctype == "sandbox":
                sandbox.append(rule)

        new_state = _CompiledState(
            preconditions=tuple(pre),
            postconditions=tuple(post),
            session_contracts=tuple(session),
            sandbox_contracts=tuple(sandbox),
            observe_preconditions=tuple(observe_pre),
            observe_postconditions=tuple(observe_post),
            observe_session_contracts=tuple(observe_session),
            observe_sandbox_contracts=tuple(observe_sandbox),
            limits=compiled.limits,
            policy_version=str(bundle_hash),
        )

        # Atomic swap — single reference assignment guarantees concurrent
        # evaluations see a consistent rule set.
        self._state = new_state

        # Update tool registry (safe: individual dict updates)
        if compiled.tools:
            for tool_name, config in compiled.tools.items():
                self.tool_registry.register(
                    tool_name,
                    side_effect=SideEffect(config.get("side_effect", "irreversible")),
                    idempotent=config.get("idempotent", False),
                )

        logger.info("Rules reloaded, policy_version=%s", self._state.policy_version)

    def set_principal(self, principal: Principal) -> None:
        """Update the principal used for subsequent tool calls."""
        self._principal = principal

    def _resolve_principal(self, tool_name: str, tool_input: dict[str, Any]) -> Principal | None:
        """Resolve the principal for a tool call."""
        if self._principal_resolver is not None:
            return self._principal_resolver(tool_name, tool_input)
        return self._principal

    def _register_hook(self, item: Any) -> None:
        if isinstance(item, HookRegistration):
            if item.phase == "before":
                self._before_hooks.append(item)
            else:
                self._after_hooks.append(item)

    def get_hooks(self, phase: str, tool_call: ToolCall) -> list[HookRegistration]:
        hooks = self._before_hooks if phase == "before" else self._after_hooks
        return [h for h in hooks if h.tool == "*" or fnmatch(tool_call.tool_name, h.tool)]

    @staticmethod
    def _filter_by_tool(rules: Sequence[Any], tool_call: ToolCall) -> list[Any]:
        result = []
        for p in rules:
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
            if tool != "*" and not fnmatch(tool_call.tool_name, tool):
                continue
            if when and not when(tool_call):
                continue
            result.append(p)
        return result

    @staticmethod
    def _filter_sandbox(rules: Sequence[Any], tool_call: ToolCall) -> list[Any]:
        result = []
        for s in rules:
            tools = getattr(s, "_edictum_tools", ["*"])
            if any(fnmatch(tool_call.tool_name, p) for p in tools):
                result.append(s)
        return result

    def get_preconditions(self, tool_call: ToolCall) -> list:
        return self._filter_by_tool(self._state.preconditions, tool_call)

    def get_postconditions(self, tool_call: ToolCall) -> list:
        return self._filter_by_tool(self._state.postconditions, tool_call)

    def get_session_contracts(self) -> list:
        return list(self._state.session_contracts)

    def get_observe_preconditions(self, tool_call: ToolCall) -> list:
        return self._filter_by_tool(self._state.observe_preconditions, tool_call)

    def get_observe_postconditions(self, tool_call: ToolCall) -> list:
        return self._filter_by_tool(self._state.observe_postconditions, tool_call)

    def get_sandbox_contracts(self, tool_call: ToolCall) -> list:
        return self._filter_sandbox(self._state.sandbox_contracts, tool_call)

    def get_observe_sandbox_contracts(self, tool_call: ToolCall) -> list:
        return self._filter_sandbox(self._state.observe_sandbox_contracts, tool_call)

    def get_observe_session_contracts(self) -> list:
        return list(self._state.observe_session_contracts)

    # --- Delegated methods (implementation in separate modules) ---

    @classmethod
    def from_yaml(
        cls,
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
        """Create an Edictum instance from one or more YAML rule bundles."""
        from edictum._factory import _from_yaml

        return _from_yaml(
            cls,
            *paths,
            tools=tools,
            mode=mode,
            audit_sink=audit_sink,
            redaction=redaction,
            backend=backend,
            environment=environment,
            return_report=return_report,
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

    @classmethod
    def from_bundle_dict(
        cls,
        bundle: dict,
        policy_version: str,
        *,
        mode: str | None = None,
        audit_sink: AuditSink | list[AuditSink] | None = None,
        redaction: RedactionPolicy | None = None,
        backend: StorageBackend | None = None,
        environment: str = "production",
        principal: Principal | None = None,
        approval_backend: ApprovalBackend | None = None,
        on_block: Callable[[ToolCall, str, str | None], None] | None = None,
        on_allow: Callable[[ToolCall], None] | None = None,
        workflow_content: str | bytes | None = None,
        workflow_exec_evaluator_enabled: bool = False,
    ) -> Edictum:
        """Create an Edictum instance from an already-parsed bundle dict."""
        from edictum._factory import _from_bundle_dict

        return _from_bundle_dict(
            cls,
            bundle,
            policy_version,
            mode=mode,
            audit_sink=audit_sink,
            redaction=redaction,
            backend=backend,
            environment=environment,
            principal=principal,
            approval_backend=approval_backend,
            on_block=on_block,
            on_allow=on_allow,
            workflow_content=workflow_content,
            workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
        )

    @classmethod
    def from_yaml_string(
        cls,
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
        """Create an Edictum instance from a YAML string or bytes."""
        from edictum._factory import _from_yaml_string

        return _from_yaml_string(
            cls,
            content,
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

    @classmethod
    def from_template(
        cls,
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
        """Create an Edictum instance from a named template."""
        from edictum._factory import _from_template

        return _from_template(
            cls,
            name,
            template_dirs=template_dirs,
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
            workflow_content=workflow_content,
            workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
        )

    @classmethod
    def list_templates(
        cls,
        template_dirs: list[str | Path] | None = None,
    ) -> list[TemplateInfo]:
        """Discover available rule templates."""
        from edictum._factory import _list_templates

        return _list_templates(cls, template_dirs)

    @classmethod
    def from_multiple(cls, guards: list[Edictum]) -> Edictum:
        """Create a new Edictum instance by merging multiple guards."""
        from edictum._factory import _from_multiple

        return _from_multiple(cls, guards)

    @classmethod
    async def from_server(
        cls,
        url: str,
        api_key: str,
        agent_id: str,
        *,
        env: str | None = None,
        bundle_name: str | None = None,
        tags: dict[str, str] | None = None,
        audit_sink: AuditSink | None = None,
        approval_backend: ApprovalBackend | None = None,
        storage_backend: StorageBackend | None = None,
        mode: str = "enforce",
        on_block: Callable[[ToolCall, str, str | None], None] | None = None,
        on_allow: Callable[[ToolCall], None] | None = None,
        success_check: Callable[[str, Any], bool] | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        auto_watch: bool = True,
        allow_insecure: bool = False,
        verify_signatures: bool = False,
        signing_public_key: str | None = None,
        workflow_runtime: WorkflowRuntime | None = None,
        workflow_path: str | Path | None = None,
        workflow_content: str | bytes | None = None,
        workflow_exec_evaluator_enabled: bool = False,
    ) -> Edictum:
        """Create an Edictum instance wired to a remote edictum-server.

        For M1, server-backed rules and workflow loading stay explicit.
        The server provides rules; callers may attach a local workflow via
        ``workflow_path`` or ``workflow_content``.
        """
        from edictum._server_factory import _from_server

        return await _from_server(
            cls,
            url,
            api_key,
            agent_id,
            env=env,
            bundle_name=bundle_name,
            tags=tags,
            audit_sink=audit_sink,
            approval_backend=approval_backend,
            storage_backend=storage_backend,
            mode=mode,
            on_block=on_block,
            on_allow=on_allow,
            success_check=success_check,
            principal=principal,
            principal_resolver=principal_resolver,
            auto_watch=auto_watch,
            allow_insecure=allow_insecure,
            verify_signatures=verify_signatures,
            signing_public_key=signing_public_key,
            workflow_runtime=workflow_runtime,
            workflow_path=workflow_path,
            workflow_content=workflow_content,
            workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
        )

    async def run(
        self,
        tool_name: str,
        args: dict[str, Any],
        tool_callable: Callable,
        *,
        session_id: str | None = None,
        **envelope_kwargs,
    ) -> Any:
        """Framework-agnostic entrypoint."""
        from edictum._runner import _run

        return await _run(
            self,
            tool_name,
            args,
            tool_callable,
            session_id=session_id,
            **envelope_kwargs,
        )

    def evaluate(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        principal: Principal | None = None,
        output: str | None = None,
        environment: str | None = None,
    ) -> EvaluationResult:
        """Dry-run evaluation of a tool call against all matching rules."""
        from edictum._dry_run import _evaluate

        return _evaluate(
            self,
            tool_name,
            args,
            principal=principal,
            output=output,
            environment=environment,
        )

    def evaluate_batch(self, calls: list[dict[str, Any]]) -> list[EvaluationResult]:
        """Evaluate a batch of tool calls. Thin wrapper over evaluate()."""
        from edictum._dry_run import _evaluate_batch

        return _evaluate_batch(self, calls)

    async def close(self) -> None:
        """Shut down server resources (SSE watcher, HTTP client)."""
        from edictum._server_factory import _close

        await _close(self)

    async def _start_sse_watcher(self) -> None:
        """Start a background task that watches for SSE rule updates."""
        from edictum._server_factory import _start_sse_watcher

        await _start_sse_watcher(self)

    async def _stop_sse_watcher(self) -> None:
        """Stop the SSE background watcher and close server resources."""
        from edictum._server_factory import _stop_sse_watcher

        await _stop_sse_watcher(self)
