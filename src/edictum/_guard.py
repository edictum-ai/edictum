"""Core Edictum class — construction, contract registry, and method delegation."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
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
from edictum.envelope import Principal, SideEffect, ToolEnvelope, ToolRegistry
from edictum.limits import OperationLimits
from edictum.otel import get_tracer
from edictum.storage import MemoryBackend, StorageBackend
from edictum.telemetry import GovernanceTelemetry
from edictum.types import HookRegistration

if TYPE_CHECKING:
    from edictum._factory import TemplateInfo
    from edictum.evaluation import EvaluationResult
    from edictum.yaml_engine.composer import CompositionReport

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _CompiledState:
    """Immutable snapshot of compiled contracts.

    All contract lists are tuples (immutable). The entire state is
    replaced atomically via a single reference assignment in reload(),
    ensuring concurrent evaluations never see a mix of old and new
    contracts.
    """

    preconditions: tuple = ()
    postconditions: tuple = ()
    session_contracts: tuple = ()
    sandbox_contracts: tuple = ()
    shadow_preconditions: tuple = ()
    shadow_postconditions: tuple = ()
    shadow_session_contracts: tuple = ()
    shadow_sandbox_contracts: tuple = ()
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
        contracts: list | None = None,
        hooks: list | None = None,
        audit_sink: AuditSink | list[AuditSink] | None = None,
        redaction: RedactionPolicy | None = None,
        backend: StorageBackend | None = None,
        policy_version: str | None = None,
        on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
        on_allow: Callable[[ToolEnvelope], None] | None = None,
        success_check: Callable[[str, Any], bool] | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        approval_backend: ApprovalBackend | None = None,
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
        self._on_deny = on_deny
        self._on_allow = on_allow
        self._success_check = success_check
        self._principal = principal
        self._principal_resolver = principal_resolver
        self._approval_backend = approval_backend

        # Build tool registry
        self.tool_registry = ToolRegistry()
        if tools:
            for name, config in tools.items():
                self.tool_registry.register(
                    name,
                    side_effect=SideEffect(config.get("side_effect", "irreversible")),
                    idempotent=config.get("idempotent", False),
                )

        # Classify contracts into mutable local lists during construction
        pre: list = []
        post: list = []
        session: list = []
        sandbox: list = []
        s_pre: list = []
        s_post: list = []
        s_session: list = []
        s_sandbox: list = []

        for item in contracts or []:
            contract_type = getattr(item, "_edictum_type", None)
            is_shadow = getattr(item, "_edictum_shadow", False)

            if is_shadow:
                if contract_type == "precondition":
                    s_pre.append(item)
                elif contract_type == "postcondition":
                    s_post.append(item)
                elif contract_type == "session_contract":
                    s_session.append(item)
                elif contract_type == "sandbox":
                    s_sandbox.append(item)
            elif contract_type == "precondition":
                pre.append(item)
            elif contract_type == "postcondition":
                post.append(item)
            elif contract_type == "session_contract":
                session.append(item)
            elif contract_type == "sandbox":
                sandbox.append(item)

        # Freeze all contract state into a single immutable snapshot.
        # Concurrent evaluations read self._state; reload() replaces it
        # via a single reference assignment (atomic under CPython's GIL
        # and safe under asyncio cooperative scheduling).
        self._state = _CompiledState(
            preconditions=tuple(pre),
            postconditions=tuple(post),
            session_contracts=tuple(session),
            sandbox_contracts=tuple(sandbox),
            shadow_preconditions=tuple(s_pre),
            shadow_postconditions=tuple(s_post),
            shadow_session_contracts=tuple(s_session),
            shadow_sandbox_contracts=tuple(s_sandbox),
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
        """Operation limits for the current contract set."""
        return self._state.limits

    @limits.setter
    def limits(self, value: OperationLimits) -> None:
        self._state = replace(self._state, limits=value)

    @property
    def policy_version(self) -> str | None:
        """SHA256 hash identifying the active contract bundle."""
        return self._state.policy_version

    @policy_version.setter
    def policy_version(self, value: str | None) -> None:
        self._state = replace(self._state, policy_version=value)

    async def reload(self, contracts_yaml: bytes | str) -> None:
        """Atomically replace all contracts from a YAML bundle.

        Builds a complete ``_CompiledState``, then swaps via a single
        reference assignment. Concurrent evaluations see either
        fully-old or fully-new contracts, never a mix.

        On failure, existing contracts are preserved (fail-closed).
        """
        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.loader import load_bundle_string

        bundle_data, bundle_hash = load_bundle_string(contracts_yaml)
        compiled = compile_contracts(bundle_data)

        # Sort compiled contracts into enforced vs observe-mode lists,
        # mirroring the classification that __init__() does at construction time.
        # Build the full state before touching self._state for atomicity.
        all_contracts = (
            compiled.preconditions + compiled.postconditions + compiled.session_contracts + compiled.sandbox_contracts
        )
        pre: list = []
        post: list = []
        session: list = []
        sandbox: list = []
        shadow_pre: list = []
        shadow_post: list = []
        shadow_session: list = []
        shadow_sandbox: list = []
        for contract in all_contracts:
            ctype = getattr(contract, "_edictum_type", None)
            is_shadow = getattr(contract, "_edictum_shadow", False)
            if is_shadow:
                if ctype == "precondition":
                    shadow_pre.append(contract)
                elif ctype == "postcondition":
                    shadow_post.append(contract)
                elif ctype == "session_contract":
                    shadow_session.append(contract)
                elif ctype == "sandbox":
                    shadow_sandbox.append(contract)
            elif ctype == "precondition":
                pre.append(contract)
            elif ctype == "postcondition":
                post.append(contract)
            elif ctype == "session_contract":
                session.append(contract)
            elif ctype == "sandbox":
                sandbox.append(contract)

        new_state = _CompiledState(
            preconditions=tuple(pre),
            postconditions=tuple(post),
            session_contracts=tuple(session),
            sandbox_contracts=tuple(sandbox),
            shadow_preconditions=tuple(shadow_pre),
            shadow_postconditions=tuple(shadow_post),
            shadow_session_contracts=tuple(shadow_session),
            shadow_sandbox_contracts=tuple(shadow_sandbox),
            limits=compiled.limits,
            policy_version=str(bundle_hash),
        )

        # Atomic swap — single reference assignment guarantees concurrent
        # evaluations see a consistent contract set.
        self._state = new_state

        # Update tool registry (safe: individual dict updates)
        if compiled.tools:
            for tool_name, config in compiled.tools.items():
                self.tool_registry.register(
                    tool_name,
                    side_effect=SideEffect(config.get("side_effect", "irreversible")),
                    idempotent=config.get("idempotent", False),
                )

        logger.info("Contracts reloaded, policy_version=%s", self._state.policy_version)

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

    def get_hooks(self, phase: str, envelope: ToolEnvelope) -> list[HookRegistration]:
        hooks = self._before_hooks if phase == "before" else self._after_hooks
        return [h for h in hooks if h.tool == "*" or fnmatch(envelope.tool_name, h.tool)]

    @staticmethod
    def _filter_by_tool(contracts: list, envelope: ToolEnvelope) -> list:
        result = []
        for p in contracts:
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
            if tool != "*" and not fnmatch(envelope.tool_name, tool):
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    @staticmethod
    def _filter_sandbox(contracts: list, envelope: ToolEnvelope) -> list:
        result = []
        for s in contracts:
            tools = getattr(s, "_edictum_tools", ["*"])
            if any(fnmatch(envelope.tool_name, p) for p in tools):
                result.append(s)
        return result

    def get_preconditions(self, envelope: ToolEnvelope) -> list:
        return self._filter_by_tool(self._state.preconditions, envelope)

    def get_postconditions(self, envelope: ToolEnvelope) -> list:
        return self._filter_by_tool(self._state.postconditions, envelope)

    def get_session_contracts(self) -> list:
        return list(self._state.session_contracts)

    def get_shadow_preconditions(self, envelope: ToolEnvelope) -> list:
        return self._filter_by_tool(self._state.shadow_preconditions, envelope)

    def get_shadow_postconditions(self, envelope: ToolEnvelope) -> list:
        return self._filter_by_tool(self._state.shadow_postconditions, envelope)

    def get_sandbox_contracts(self, envelope: ToolEnvelope) -> list:
        return self._filter_sandbox(self._state.sandbox_contracts, envelope)

    def get_shadow_sandbox_contracts(self, envelope: ToolEnvelope) -> list:
        return self._filter_sandbox(self._state.shadow_sandbox_contracts, envelope)

    def get_shadow_session_contracts(self) -> list:
        return list(self._state.shadow_session_contracts)

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
        on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
        on_allow: Callable[[ToolEnvelope], None] | None = None,
        custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
        custom_selectors: dict[str, Callable[[ToolEnvelope], dict[str, Any]]] | None = None,
        success_check: Callable[[str, Any], bool] | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        approval_backend: ApprovalBackend | None = None,
    ) -> Edictum | tuple[Edictum, CompositionReport]:
        """Create an Edictum instance from one or more YAML contract bundles."""
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
            on_deny=on_deny,
            on_allow=on_allow,
            custom_operators=custom_operators,
            custom_selectors=custom_selectors,
            success_check=success_check,
            principal=principal,
            principal_resolver=principal_resolver,
            approval_backend=approval_backend,
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
        on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
        on_allow: Callable[[ToolEnvelope], None] | None = None,
        custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
        custom_selectors: dict[str, Callable[[ToolEnvelope], dict[str, Any]]] | None = None,
        success_check: Callable[[str, Any], bool] | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        approval_backend: ApprovalBackend | None = None,
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
            on_deny=on_deny,
            on_allow=on_allow,
            custom_operators=custom_operators,
            custom_selectors=custom_selectors,
            success_check=success_check,
            principal=principal,
            principal_resolver=principal_resolver,
            approval_backend=approval_backend,
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
        on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
        on_allow: Callable[[ToolEnvelope], None] | None = None,
        custom_operators: dict[str, Callable[[Any, Any], bool]] | None = None,
        custom_selectors: dict[str, Callable[[ToolEnvelope], dict[str, Any]]] | None = None,
        success_check: Callable[[str, Any], bool] | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        approval_backend: ApprovalBackend | None = None,
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
            on_deny=on_deny,
            on_allow=on_allow,
            custom_operators=custom_operators,
            custom_selectors=custom_selectors,
            success_check=success_check,
            principal=principal,
            principal_resolver=principal_resolver,
            approval_backend=approval_backend,
        )

    @classmethod
    def list_templates(
        cls,
        template_dirs: list[str | Path] | None = None,
    ) -> list[TemplateInfo]:
        """Discover available contract templates."""
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
        on_deny: Callable[[ToolEnvelope, str, str | None], None] | None = None,
        on_allow: Callable[[ToolEnvelope], None] | None = None,
        success_check: Callable[[str, Any], bool] | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        auto_watch: bool = True,
        allow_insecure: bool = False,
        verify_signatures: bool = False,
        signing_public_key: str | None = None,
    ) -> Edictum:
        """Create an Edictum instance wired to a remote edictum-server."""
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
            on_deny=on_deny,
            on_allow=on_allow,
            success_check=success_check,
            principal=principal,
            principal_resolver=principal_resolver,
            auto_watch=auto_watch,
            allow_insecure=allow_insecure,
            verify_signatures=verify_signatures,
            signing_public_key=signing_public_key,
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
        """Dry-run evaluation of a tool call against all matching contracts."""
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
        """Start a background task that watches for SSE contract updates."""
        from edictum._server_factory import _start_sse_watcher

        await _start_sse_watcher(self)

    async def _stop_sse_watcher(self) -> None:
        """Stop the SSE background watcher and close server resources."""
        from edictum._server_factory import _stop_sse_watcher

        await _stop_sse_watcher(self)
