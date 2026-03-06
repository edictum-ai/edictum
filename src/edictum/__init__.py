"""Edictum — Runtime safety for AI agents."""

from __future__ import annotations

from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("edictum")
except Exception:  # pragma: no cover — editable installs, test envs
    __version__ = "0.0.0-dev"

import asyncio
import base64
import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from edictum.approval import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    LocalApprovalBackend,
)
from edictum.audit import (
    AuditAction,
    AuditEvent,
    AuditSink,
    CollectingAuditSink,
    CompositeSink,
    FileAuditSink,
    MarkEvictedError,
    RedactionPolicy,
    StdoutAuditSink,
)
from edictum.builtins import deny_sensitive_reads
from edictum.contracts import Verdict, postcondition, precondition, session_contract
from edictum.envelope import (
    BashClassifier,
    Principal,
    SideEffect,
    ToolEnvelope,
    ToolRegistry,
    create_envelope,
)
from edictum.evaluation import ContractResult, EvaluationResult
from edictum.findings import Finding, PostCallResult
from edictum.hooks import HookDecision, HookResult
from edictum.limits import OperationLimits
from edictum.otel import configure_otel, get_tracer, has_otel
from edictum.pipeline import GovernancePipeline, PostDecision, PreDecision
from edictum.session import Session
from edictum.storage import MemoryBackend, StorageBackend
from edictum.telemetry import GovernanceTelemetry
from edictum.types import HookRegistration
from edictum.yaml_engine.composer import CompositionReport

logger = logging.getLogger(__name__)

# How long from_server() waits for the server to push a bundle in
# server-assigned mode (bundle_name=None) before raising EdictumConfigError.
_ASSIGNMENT_TIMEOUT_SECS = 30.0

__all__ = [
    "__version__",
    "ApprovalBackend",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "LocalApprovalBackend",
    "Edictum",
    "EdictumConfigError",
    "EdictumDenied",
    "EdictumToolError",
    "SideEffect",
    "Principal",
    "ToolEnvelope",
    "create_envelope",
    "ToolRegistry",
    "BashClassifier",
    "HookDecision",
    "HookRegistration",
    "HookResult",
    "Verdict",
    "precondition",
    "postcondition",
    "session_contract",
    "OperationLimits",
    "Session",
    "StorageBackend",
    "MemoryBackend",
    "AuditAction",
    "AuditEvent",
    "AuditSink",
    "CollectingAuditSink",
    "CompositeSink",
    "FileAuditSink",
    "MarkEvictedError",
    "StdoutAuditSink",
    "RedactionPolicy",
    "GovernanceTelemetry",
    "GovernancePipeline",
    "PreDecision",
    "PostDecision",
    "deny_sensitive_reads",
    "configure_otel",
    "has_otel",
    "Finding",
    "PostCallResult",
    "EvaluationResult",
    "ContractResult",
    "CompositionReport",
    "TemplateInfo",
]


@dataclass(frozen=True)
class TemplateInfo:
    """Metadata about a discovered contract template."""

    name: str
    path: Path
    builtin: bool


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
        self.limits = limits or OperationLimits()
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
        self.policy_version = policy_version
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

        # Organize contracts and hooks by type
        self._preconditions: list = []
        self._postconditions: list = []
        self._session_contracts: list = []
        self._shadow_preconditions: list = []
        self._shadow_postconditions: list = []
        self._shadow_session_contracts: list = []
        self._sandbox_contracts: list = []
        self._shadow_sandbox_contracts: list = []
        self._before_hooks: list[HookRegistration] = []
        self._after_hooks: list[HookRegistration] = []

        # Persistent session for accumulating limits across run() calls
        self._session_id = str(uuid.uuid4())

        for item in contracts or []:
            self._register_contract(item)
        for item in hooks or []:
            self._register_hook(item)

    @property
    def local_sink(self) -> CollectingAuditSink:
        """The local in-memory audit event collector.

        Always present regardless of construction method (``__init__``,
        ``from_yaml()``, ``from_server()``). Use ``mark()`` /
        ``since_mark()`` to inspect governance decisions programmatically.
        """
        return self._local_sink

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
    ) -> Edictum:
        """Create an Edictum instance wired to a remote edictum-server.

        Auto-configures all server components (audit, approval, session,
        contract source) from a single URL and API key.

        Args:
            url: Base URL of the edictum-server (e.g. ``https://console.edictum.dev``).
            api_key: API key for authentication.
            agent_id: Unique identifier for this agent instance.
            env: Environment name (defaults to ``"production"``).
            bundle_name: Which bundle lineage this agent tracks. When
                ``None``, the server assigns a bundle based on agent
                tags and assignment rules (requires ``auto_watch=True``).
            tags: Key-value metadata describing this agent (e.g.
                ``{"team": "billing", "tier": "production"}``). Sent to
                the server on SSE connect for assignment resolution.
            audit_sink: Override the default ``ServerAuditSink``.
            approval_backend: Override the default ``ServerApprovalBackend``.
            storage_backend: Override the default ``ServerBackend``.
            mode: Enforcement mode (``"enforce"`` or ``"observe"``).
            on_deny: Callback invoked when a tool call is denied.
            on_allow: Callback invoked when a tool call is allowed.
            success_check: Callable ``(tool_name, result) -> bool``.
            principal: Static principal for all tool calls.
            principal_resolver: Per-call dynamic principal resolution.
            auto_watch: If True (default), start an SSE background task
                that automatically reloads contracts when the server
                pushes updates. Must be True when ``bundle_name`` is None.

        Returns:
            Configured Edictum instance connected to the server.

        Raises:
            EdictumConfigError: If the server is unreachable or returns
                invalid contract data, or if the server does not push a
                bundle assignment within 30 seconds.
            ValueError: If ``bundle_name`` is None and ``auto_watch`` is False.
        """
        from edictum.server.approval_backend import ServerApprovalBackend
        from edictum.server.audit_sink import ServerAuditSink
        from edictum.server.backend import ServerBackend
        from edictum.server.client import EdictumServerClient
        from edictum.server.contract_source import ServerContractSource
        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.loader import load_bundle_string

        if bundle_name is None and not auto_watch:
            raise ValueError(
                "auto_watch must be True when bundle_name is None. "
                "Server-assigned mode requires the SSE connection to receive the bundle."
            )

        environment = env or "production"

        # 1. Shared HTTP client
        client = EdictumServerClient(
            url,
            api_key,
            agent_id=agent_id,
            env=environment,
            bundle_name=bundle_name,
            tags=tags,
        )

        # 2. Server-backed components (use overrides if provided)
        effective_sink = audit_sink or ServerAuditSink(client)
        effective_approval = approval_backend or ServerApprovalBackend(client)
        effective_backend = storage_backend or ServerBackend(client)

        if bundle_name is not None:
            # 3a. Fetch current contracts from the server
            try:
                response = await client.get(
                    f"/api/v1/bundles/{bundle_name}/current",
                    env=client.env,
                )
                yaml_b64 = response.get("yaml_bytes", "")
                bundle_yaml = base64.b64decode(yaml_b64) if yaml_b64 else b""
            except Exception as exc:
                await client.close()
                raise EdictumConfigError(f"Failed to fetch contracts from server: {exc}") from exc

            # 4a. Parse and compile contracts
            try:
                bundle_data, bundle_hash = load_bundle_string(bundle_yaml)
                compiled = compile_contracts(bundle_data)
            except Exception as exc:
                await client.close()
                raise EdictumConfigError(f"Failed to parse server contracts: {exc}") from exc

            policy_version = str(bundle_hash)
            effective_mode = mode or compiled.default_mode
            all_contracts = (
                compiled.preconditions
                + compiled.postconditions
                + compiled.session_contracts
                + compiled.sandbox_contracts
            )

            # Merge YAML tools
            yaml_tools = compiled.tools

            guard = cls(
                environment=environment,
                mode=effective_mode,
                limits=compiled.limits,
                tools=yaml_tools if yaml_tools else None,
                contracts=all_contracts,
                audit_sink=effective_sink,
                backend=effective_backend,
                policy_version=policy_version,
                on_deny=on_deny,
                on_allow=on_allow,
                success_check=success_check,
                principal=principal,
                principal_resolver=principal_resolver,
                approval_backend=effective_approval,
            )
        else:
            # 3b. Server-assigned mode: start with empty contracts,
            # wait for the server to push a bundle via SSE.
            guard = cls(
                environment=environment,
                mode=mode,
                limits=None,
                tools=None,
                contracts=[],
                audit_sink=effective_sink,
                backend=effective_backend,
                policy_version=None,
                on_deny=on_deny,
                on_allow=on_allow,
                success_check=success_check,
                principal=principal,
                principal_resolver=principal_resolver,
                approval_backend=effective_approval,
            )
            guard._assignment_ready = asyncio.Event()

        # Store server resources for lifecycle management
        guard._server_client = client
        guard._contract_source = ServerContractSource(client)
        guard._sse_task: asyncio.Task | None = None

        # 5. Optionally start SSE watcher for live contract updates
        if auto_watch:
            await guard._start_sse_watcher()

        # 6. In server-assigned mode, block until first bundle arrives
        if bundle_name is None:
            try:
                await asyncio.wait_for(
                    guard._assignment_ready.wait(),
                    timeout=_ASSIGNMENT_TIMEOUT_SECS,
                )
            except TimeoutError:
                await guard.close()
                raise EdictumConfigError(
                    f"Server did not push a bundle assignment within "
                    f"{_ASSIGNMENT_TIMEOUT_SECS} seconds. Check that the server "
                    f"has an assignment rule matching this agent's tags."
                ) from None

        return guard

    async def reload(self, contracts_yaml: bytes | str) -> None:
        """Atomically replace all contracts from a YAML bundle.

        Parses the YAML, compiles contracts, and swaps the contract
        lists in place.  In-flight evaluations that already obtained
        references to the old contract lists are unaffected (Python
        list identity guarantees).

        On failure, existing contracts are preserved (fail-closed).

        Args:
            contracts_yaml: Raw YAML bundle as bytes or a string.
        """
        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.loader import load_bundle_string

        bundle_data, bundle_hash = load_bundle_string(contracts_yaml)
        compiled = compile_contracts(bundle_data)

        # Atomic swaps — each assignment replaces the list reference.
        # In-flight evaluations that already captured the old list are
        # unaffected because they hold their own reference.
        self._preconditions = compiled.preconditions
        self._postconditions = compiled.postconditions
        self._session_contracts = compiled.session_contracts
        self._sandbox_contracts = compiled.sandbox_contracts
        self.policy_version = str(bundle_hash)

        # Update limits if the new bundle redefines them
        self.limits = compiled.limits

        # Merge tool classifications from the new bundle
        if compiled.tools:
            for tool_name, config in compiled.tools.items():
                self.tool_registry.register(
                    tool_name,
                    side_effect=SideEffect(config.get("side_effect", "irreversible")),
                    idempotent=config.get("idempotent", False),
                )

        logger.info("Contracts reloaded, policy_version=%s", self.policy_version)

    async def _start_sse_watcher(self) -> None:
        """Start a background task that watches for SSE contract updates."""
        source = getattr(self, "_contract_source", None)
        if source is None:
            return

        await source.connect()

        async def _watch_loop() -> None:
            try:
                async for bundle in source.watch():
                    try:
                        if bundle.get("_assignment_changed"):
                            # Assignment changed: fetch the new bundle's contracts
                            new_name = bundle["bundle_name"]
                            response = await self._server_client.get(
                                f"/api/v1/bundles/{new_name}/current",
                                env=self._server_client.env,
                            )
                            yaml_b64 = response.get("yaml_bytes", "")
                            yaml_data = base64.b64decode(yaml_b64) if yaml_b64 else b""
                        else:
                            yaml_b64 = bundle.get("yaml_bytes", "")
                            yaml_data = base64.b64decode(yaml_b64) if yaml_b64 else b""
                        await self.reload(yaml_data)
                        # Commit bundle_name only after successful reload.
                        # This ensures failed fetches don't block retries
                        # via deduplication in contract_source.
                        if bundle.get("_assignment_changed"):
                            self._server_client.bundle_name = bundle["bundle_name"]
                        # Signal readiness after first successful reload
                        ready_event = getattr(self, "_assignment_ready", None)
                        if ready_event is not None and not ready_event.is_set():
                            ready_event.set()
                    except Exception:
                        # Fail closed: keep existing contracts on reload error
                        logger.warning("Failed to reload contracts from SSE update, keeping existing contracts")
            except asyncio.CancelledError:
                return
            except Exception:
                logger.warning("SSE watcher loop exited unexpectedly")

        self._sse_task = asyncio.create_task(_watch_loop())

    async def _stop_sse_watcher(self) -> None:
        """Stop the SSE background watcher and close server resources."""
        task = getattr(self, "_sse_task", None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            self._sse_task = None

        source = getattr(self, "_contract_source", None)
        if source is not None:
            await source.close()

        client = getattr(self, "_server_client", None)
        if client is not None:
            await client.close()

    async def close(self) -> None:
        """Shut down server resources (SSE watcher, HTTP client).

        Safe to call on non-server instances (no-op).
        """
        await self._stop_sse_watcher()

        # Flush audit sink if it supports close()
        sink_close = getattr(self.audit_sink, "close", None)
        if sink_close is not None:
            result = sink_close()
            if asyncio.iscoroutine(result):
                await result

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
        """Create a Edictum instance from one or more YAML contract bundles.

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
            custom_operators: Mapping of operator names to callables. Each
                callable receives ``(field_value, operator_value)`` and returns
                ``bool``. Names must not clash with the 15 built-in operators.
            custom_selectors: Mapping of selector prefixes to resolver callables.
                Each callable receives a ``ToolEnvelope`` and returns a ``dict``
                that is searched via dotted-path resolution. For example,
                ``{"context": lambda env: env.metadata}`` makes ``context.key``
                selectors available in YAML contracts. Prefixes must not clash
                with built-in selector prefixes.
            principal: Static principal for all tool calls.
            principal_resolver: Callable ``(tool_name, tool_input) -> Principal``
                for per-call dynamic resolution. Overrides static principal.
            approval_backend: Backend for human-in-the-loop approval workflows.

        Returns:
            Configured Edictum instance, or a tuple of (Edictum, CompositionReport)
            when *return_report* is True.

        Raises:
            EdictumConfigError: If the YAML is invalid, custom operator names
                clash with built-in operators, or custom selector prefixes clash
                with built-in selector prefixes.
        """
        import hashlib

        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.composer import CompositionReport, compose_bundles
        from edictum.yaml_engine.loader import load_bundle

        if custom_operators:
            _validate_custom_operators(custom_operators)
        if custom_selectors:
            _validate_custom_selectors(custom_selectors)

        if not paths:
            raise EdictumConfigError("from_yaml() requires at least one path")

        # Load all bundles
        loaded: list[tuple[dict, Any]] = []
        for p in paths:
            loaded.append(load_bundle(p))

        if len(loaded) == 1:
            # Single path — backward compatible, no composition
            bundle_data, bundle_hash = loaded[0]
            policy_version = str(bundle_hash)
            report = CompositionReport()
        else:
            # Multiple paths — compose bundles
            bundle_tuples = [(data, str(p)) for (data, _hash), p in zip(loaded, paths)]
            composed = compose_bundles(*bundle_tuples)
            bundle_data = composed.bundle
            report = composed.report
            # Combined hash from all individual hashes
            policy_version = hashlib.sha256(":".join(str(h) for _d, h in loaded).encode()).hexdigest()

        compiled = compile_contracts(bundle_data, custom_operators=custom_operators, custom_selectors=custom_selectors)

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

                class _NullSink:
                    async def emit(self, event):
                        pass

                audit_sink = _NullSink()

        effective_mode = mode or compiled.default_mode
        all_contracts = (
            compiled.preconditions + compiled.postconditions + compiled.session_contracts + compiled.sandbox_contracts
        )

        # Merge YAML tools with parameter tools (parameter wins on conflict)
        yaml_tools = compiled.tools
        merged_tools = {**yaml_tools, **(tools or {})}

        guard = cls(
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

        if return_report:
            return guard, report
        return guard

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
        """Create an Edictum instance from a YAML string or bytes.

        Like :meth:`from_yaml` but accepts YAML content directly instead of
        a file path.  Follows the ``json.load()`` / ``json.loads()`` convention.

        Args:
            content: YAML contract bundle as a string or bytes.
            tools: Tool side-effect classifications. Merged with any ``tools:``
                section in the YAML bundle (parameter wins on conflict).
            mode: Override the bundle's default mode (enforce/observe).
            audit_sink: Custom audit sink, or a list of sinks (auto-wrapped
                in CompositeSink).
            redaction: Custom redaction policy.
            backend: Custom storage backend.
            environment: Environment name for envelope context.
            custom_operators: Mapping of operator names to callables. Each
                callable receives ``(field_value, operator_value)`` and returns
                ``bool``. Names must not clash with the 15 built-in operators.
            custom_selectors: Mapping of selector prefixes to resolver callables.
                Each callable receives a ``ToolEnvelope`` and returns a ``dict``
                that is searched via dotted-path resolution. Prefixes must not
                clash with built-in selector prefixes.
            principal: Static principal for all tool calls.
            principal_resolver: Callable ``(tool_name, tool_input) -> Principal``
                for per-call dynamic resolution. Overrides static principal.
            approval_backend: Backend for human-in-the-loop approval workflows.

        Returns:
            Configured Edictum instance.

        Raises:
            EdictumConfigError: If the YAML is invalid, custom operator names
                clash with built-in operators, or custom selector prefixes clash
                with built-in selector prefixes.
        """
        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.loader import load_bundle_string

        if custom_operators:
            _validate_custom_operators(custom_operators)
        if custom_selectors:
            _validate_custom_selectors(custom_selectors)

        bundle_data, bundle_hash = load_bundle_string(content)
        policy_version = str(bundle_hash)

        compiled = compile_contracts(bundle_data, custom_operators=custom_operators, custom_selectors=custom_selectors)

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

                class _NullSink:
                    async def emit(self, event):
                        pass

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
        """Create an Edictum instance from a template.

        Searches user-provided directories first, then built-in templates.

        Args:
            name: Template name (e.g., "file-agent", "support-agent").
            template_dirs: Directories to search before built-in templates.
                User directories are searched in order; built-in templates
                serve as a fallback.
            tools: Tool side-effect classifications. Forwarded to ``from_yaml()``.
            mode: Override the template's default mode.
            audit_sink: Custom audit sink.
            redaction: Custom redaction policy.
            backend: Custom storage backend.
            environment: Environment name for envelope context.
            custom_operators: Mapping of operator names to callables. Forwarded
                to ``from_yaml()``.
            custom_selectors: Mapping of selector prefixes to resolver callables.
                Forwarded to ``from_yaml()``.
            principal: Static principal for all tool calls. Forwarded to
                ``from_yaml()``.
            principal_resolver: Callable ``(tool_name, tool_input) -> Principal``
                for per-call dynamic resolution. Forwarded to ``from_yaml()``.
            approval_backend: Backend for human-in-the-loop approval workflows.
                Forwarded to ``from_yaml()``.

        Returns:
            Configured Edictum instance.

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

    @classmethod
    def list_templates(
        cls,
        template_dirs: list[str | Path] | None = None,
    ) -> list[TemplateInfo]:
        """Discover available contract templates.

        Returns templates from user-provided directories and built-in
        templates. When a user template has the same name as a built-in,
        the user template takes precedence (matching ``from_template()``
        search order).

        Args:
            template_dirs: Additional directories to search for templates.

        Returns:
            List of :class:`TemplateInfo` with name, path, and builtin flag.
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

    @classmethod
    def from_multiple(cls, guards: list[Edictum]) -> Edictum:
        """Create a new Edictum instance by merging multiple guards.

        Concatenates preconditions, postconditions, and session contracts
        from all guards in order.  The first guard's audit config, mode,
        environment, and limits are used as the base.

        Duplicate contract IDs are detected: first occurrence wins and
        a warning is logged for each duplicate.

        Args:
            guards: List of Edictum instances to merge. Must not be empty.

        Returns:
            A new Edictum instance containing all contracts.

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

        seen_ids: set[str] = set()

        for guard in guards:
            for contract in guard._preconditions:
                cid = getattr(contract, "_edictum_id", None)
                if cid and cid in seen_ids:
                    logger.warning("Duplicate contract id '%s' in from_multiple() — first wins", cid)
                    continue
                if cid:
                    seen_ids.add(cid)
                merged._preconditions.append(contract)

            for contract in guard._postconditions:
                cid = getattr(contract, "_edictum_id", None)
                if cid and cid in seen_ids:
                    logger.warning("Duplicate contract id '%s' in from_multiple() — first wins", cid)
                    continue
                if cid:
                    seen_ids.add(cid)
                merged._postconditions.append(contract)

            for contract in guard._session_contracts:
                cid = getattr(contract, "_edictum_id", None)
                if cid and cid in seen_ids:
                    logger.warning("Duplicate contract id '%s' in from_multiple() — first wins", cid)
                    continue
                if cid:
                    seen_ids.add(cid)
                merged._session_contracts.append(contract)

            for contract in guard._sandbox_contracts:
                cid = getattr(contract, "_edictum_id", None)
                if cid and cid in seen_ids:
                    logger.warning("Duplicate contract id '%s' in from_multiple() — first wins", cid)
                    continue
                if cid:
                    seen_ids.add(cid)
                merged._sandbox_contracts.append(contract)

        return merged

    def set_principal(self, principal: Principal) -> None:
        """Update the principal used for subsequent tool calls.

        Does not affect in-flight calls or session state (attempt counts,
        execution history).
        """
        self._principal = principal

    def _resolve_principal(self, tool_name: str, tool_input: dict[str, Any]) -> Principal | None:
        """Resolve the principal for a tool call.

        If a principal_resolver is set, it is called with (tool_name, tool_input)
        and its result overrides the static principal.
        """
        if self._principal_resolver is not None:
            return self._principal_resolver(tool_name, tool_input)
        return self._principal

    def _register_contract(self, item: Any) -> None:
        contract_type = getattr(item, "_edictum_type", None)
        is_shadow = getattr(item, "_edictum_shadow", False)

        if is_shadow:
            if contract_type == "precondition":
                self._shadow_preconditions.append(item)
            elif contract_type == "postcondition":
                self._shadow_postconditions.append(item)
            elif contract_type == "session_contract":
                self._shadow_session_contracts.append(item)
            elif contract_type == "sandbox":
                self._shadow_sandbox_contracts.append(item)
        elif contract_type == "precondition":
            self._preconditions.append(item)
        elif contract_type == "postcondition":
            self._postconditions.append(item)
        elif contract_type == "session_contract":
            self._session_contracts.append(item)
        elif contract_type == "sandbox":
            self._sandbox_contracts.append(item)

    def _register_hook(self, item: Any) -> None:
        if isinstance(item, HookRegistration):
            if item.phase == "before":
                self._before_hooks.append(item)
            else:
                self._after_hooks.append(item)

    def get_hooks(self, phase: str, envelope: ToolEnvelope) -> list[HookRegistration]:
        hooks = self._before_hooks if phase == "before" else self._after_hooks
        return [h for h in hooks if h.tool == "*" or fnmatch(envelope.tool_name, h.tool)]

    def get_preconditions(self, envelope: ToolEnvelope) -> list:
        result = []
        for p in self._preconditions:
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
            if tool != "*" and not fnmatch(envelope.tool_name, tool):
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    def get_postconditions(self, envelope: ToolEnvelope) -> list:
        result = []
        for p in self._postconditions:
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
            if tool != "*" and not fnmatch(envelope.tool_name, tool):
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    def get_session_contracts(self) -> list:
        return self._session_contracts

    def get_shadow_preconditions(self, envelope: ToolEnvelope) -> list:
        result = []
        for p in self._shadow_preconditions:
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
            if tool != "*" and not fnmatch(envelope.tool_name, tool):
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    def get_shadow_postconditions(self, envelope: ToolEnvelope) -> list:
        result = []
        for p in self._shadow_postconditions:
            tool = getattr(p, "_edictum_tool", "*")
            when = getattr(p, "_edictum_when", None)
            if tool != "*" and not fnmatch(envelope.tool_name, tool):
                continue
            if when and not when(envelope):
                continue
            result.append(p)
        return result

    def get_sandbox_contracts(self, envelope: ToolEnvelope) -> list:
        result = []
        for s in self._sandbox_contracts:
            tools = getattr(s, "_edictum_tools", ["*"])
            if any(fnmatch(envelope.tool_name, p) for p in tools):
                result.append(s)
        return result

    def get_shadow_sandbox_contracts(self, envelope: ToolEnvelope) -> list:
        result = []
        for s in self._shadow_sandbox_contracts:
            tools = getattr(s, "_edictum_tools", ["*"])
            if any(fnmatch(envelope.tool_name, p) for p in tools):
                result.append(s)
        return result

    def get_shadow_session_contracts(self) -> list:
        return self._shadow_session_contracts

    def evaluate(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        principal: Principal | None = None,
        output: str | None = None,
        environment: str | None = None,
    ) -> EvaluationResult:
        """Dry-run evaluation of a tool call against all matching contracts.

        Unlike run(), this never executes the tool and evaluates all
        matching contracts exhaustively (no short-circuit on first deny).
        Session contracts are skipped (no session state in dry-run).
        """
        env = environment or self.environment
        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=args,
            environment=env,
            principal=principal,
            registry=self.tool_registry,
        )

        contracts: list[ContractResult] = []
        deny_reasons: list[str] = []
        warn_reasons: list[str] = []

        # Evaluate all matching preconditions (exhaustive, no short-circuit)
        for contract in self.get_preconditions(envelope):
            contract_id = getattr(contract, "_edictum_id", None) or getattr(contract, "__name__", "unknown")
            try:
                verdict = contract(envelope)
            except Exception as exc:
                contract_result = ContractResult(
                    contract_id=contract_id,
                    contract_type="precondition",
                    passed=False,
                    message=f"Precondition error: {exc}",
                    policy_error=True,
                )
                contracts.append(contract_result)
                deny_reasons.append(contract_result.message)
                continue

            tags = verdict.metadata.get("tags", []) if verdict.metadata else []
            is_observed = getattr(contract, "_edictum_mode", None) == "observe" and not verdict.passed
            pe = verdict.metadata.get("policy_error", False) if verdict.metadata else False

            contract_result = ContractResult(
                contract_id=contract_id,
                contract_type="precondition",
                passed=verdict.passed,
                message=verdict.message,
                tags=tags,
                observed=is_observed,
                policy_error=pe,
            )
            contracts.append(contract_result)

            if not verdict.passed and not is_observed:
                deny_reasons.append(verdict.message or "")

        # Evaluate sandbox contracts (exhaustive, no short-circuit)
        for contract in self.get_sandbox_contracts(envelope):
            contract_id = getattr(contract, "_edictum_id", None) or getattr(contract, "__name__", "unknown")
            try:
                verdict = contract(envelope)
            except Exception as exc:
                contract_result = ContractResult(
                    contract_id=contract_id,
                    contract_type="sandbox",
                    passed=False,
                    message=f"Sandbox error: {exc}",
                    policy_error=True,
                )
                contracts.append(contract_result)
                deny_reasons.append(contract_result.message)
                continue

            tags = verdict.metadata.get("tags", []) if verdict.metadata else []
            is_observed = getattr(contract, "_edictum_mode", None) == "observe" and not verdict.passed
            pe = verdict.metadata.get("policy_error", False) if verdict.metadata else False

            contract_result = ContractResult(
                contract_id=contract_id,
                contract_type="sandbox",
                passed=verdict.passed,
                message=verdict.message,
                tags=tags,
                observed=is_observed,
                policy_error=pe,
            )
            contracts.append(contract_result)

            if not verdict.passed and not is_observed:
                deny_reasons.append(verdict.message or "")

        # Evaluate postconditions only when output is provided
        if output is not None:
            for contract in self.get_postconditions(envelope):
                contract_id = getattr(contract, "_edictum_id", None) or getattr(contract, "__name__", "unknown")
                try:
                    verdict = contract(envelope, output)
                except Exception as exc:
                    contract_result = ContractResult(
                        contract_id=contract_id,
                        contract_type="postcondition",
                        passed=False,
                        message=f"Postcondition error: {exc}",
                        policy_error=True,
                    )
                    contracts.append(contract_result)
                    warn_reasons.append(contract_result.message)
                    continue

                tags = verdict.metadata.get("tags", []) if verdict.metadata else []
                is_observed = getattr(contract, "_edictum_mode", None) == "observe" and not verdict.passed
                pe = verdict.metadata.get("policy_error", False) if verdict.metadata else False
                effect = getattr(contract, "_edictum_effect", "warn")

                contract_result = ContractResult(
                    contract_id=contract_id,
                    contract_type="postcondition",
                    passed=verdict.passed,
                    message=verdict.message,
                    tags=tags,
                    observed=is_observed,
                    effect=effect,
                    policy_error=pe,
                )
                contracts.append(contract_result)

                if not verdict.passed and not is_observed:
                    warn_reasons.append(verdict.message or "")

        # Compute verdict
        if deny_reasons:
            verdict_str = "deny"
        elif warn_reasons:
            verdict_str = "warn"
        else:
            verdict_str = "allow"

        return EvaluationResult(
            verdict=verdict_str,
            tool_name=tool_name,
            contracts=contracts,
            deny_reasons=deny_reasons,
            warn_reasons=warn_reasons,
            contracts_evaluated=len(contracts),
            policy_error=any(r.policy_error for r in contracts),
        )

    def evaluate_batch(self, calls: list[dict[str, Any]]) -> list[EvaluationResult]:
        """Evaluate a batch of tool calls. Thin wrapper over evaluate()."""
        results: list[EvaluationResult] = []
        for call in calls:
            tool = call["tool"]
            args = call.get("args", {})

            # Convert principal dict to Principal object
            principal = None
            principal_data = call.get("principal")
            if principal_data and isinstance(principal_data, dict):
                principal = Principal(
                    role=principal_data.get("role"),
                    user_id=principal_data.get("user_id"),
                    ticket_ref=principal_data.get("ticket_ref"),
                    claims=principal_data.get("claims", {}),
                )

            # Normalize output
            output = call.get("output")
            if isinstance(output, dict):
                output = json.dumps(output)

            environment = call.get("environment")

            results.append(
                self.evaluate(
                    tool,
                    args,
                    principal=principal,
                    output=output,
                    environment=environment,
                )
            )
        return results

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
        session_id = session_id or self._session_id
        session = Session(session_id, self.backend)
        pipeline = GovernancePipeline(self)

        # Allow per-call environment override; fall back to guard-level default
        env = envelope_kwargs.pop("environment", self.environment)

        # Resolve principal: per-call resolver > static > envelope_kwargs
        if "principal" not in envelope_kwargs:
            resolved = self._resolve_principal(tool_name, args)
            if resolved is not None:
                envelope_kwargs["principal"] = resolved

        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=args,
            run_id=session_id,
            environment=env,
            registry=self.tool_registry,
            **envelope_kwargs,
        )

        # Increment attempts
        await session.increment_attempts()

        # Start OTel span
        span = self.telemetry.start_tool_span(envelope)
        if self.policy_version:
            span.set_attribute("edictum.policy_version", self.policy_version)

        # Pre-execute
        pre = await pipeline.pre_execute(envelope, session)

        # Handle pending_approval: request approval from backend
        if pre.action == "pending_approval":
            if self._approval_backend is None:
                span.end()
                raise EdictumDenied(
                    reason=f"Approval required but no approval backend configured: {pre.reason}",
                    decision_source=pre.decision_source,
                    decision_name=pre.decision_name,
                )
            principal_dict = asdict(envelope.principal) if envelope.principal else None
            approval_request = await self._approval_backend.request_approval(
                tool_name=envelope.tool_name,
                tool_args=envelope.args,
                message=pre.approval_message or pre.reason or "",
                timeout=pre.approval_timeout,
                timeout_effect=pre.approval_timeout_effect,
                principal=principal_dict,
            )
            await self._emit_run_pre_audit(envelope, session, AuditAction.CALL_APPROVAL_REQUESTED, pre)
            decision = await self._approval_backend.wait_for_decision(
                approval_id=approval_request.approval_id,
                timeout=pre.approval_timeout,
            )
            # Resolve approval: approved, denied, or timeout (with timeout_effect)
            approved = False
            if decision.status == ApprovalStatus.TIMEOUT:
                # Timeout — audit as timeout regardless of approved flag
                await self._emit_run_pre_audit(envelope, session, AuditAction.CALL_APPROVAL_TIMEOUT, pre)
                if pre.approval_timeout_effect == "allow":
                    approved = True
            elif not decision.approved:
                # Explicit human denial
                await self._emit_run_pre_audit(envelope, session, AuditAction.CALL_APPROVAL_DENIED, pre)
            else:
                # Explicit human approval
                approved = True
                await self._emit_run_pre_audit(envelope, session, AuditAction.CALL_APPROVAL_GRANTED, pre)

            if approved:
                self.telemetry.record_allowed(envelope)
                if self._on_allow:
                    try:
                        self._on_allow(envelope)
                    except Exception:
                        logger.exception("on_allow callback raised")
                span.set_attribute("governance.action", "approved")
                # Skip the normal pre-execution audit/callback logic below —
                # approval-granted path handles its own audit and callbacks.
            else:
                self.telemetry.record_denial(envelope, decision.reason or pre.reason)
                if self._on_deny:
                    try:
                        self._on_deny(envelope, decision.reason or pre.reason or "", pre.decision_name)
                    except Exception:
                        logger.exception("on_deny callback raised")
                span.set_attribute("governance.action", "denied")
                span.set_attribute("governance.reason", decision.reason or pre.reason or "")
                span.end()
                raise EdictumDenied(
                    reason=decision.reason or pre.reason,
                    decision_source=pre.decision_source,
                    decision_name=pre.decision_name,
                )

        # Determine if this is a real deny or just per-contract observed denials
        real_deny = pre.action == "deny" and not pre.observed

        # Skip pre-execution audit for approval-granted path (already handled above)
        if pre.action == "pending_approval":
            pass  # Fall through directly to tool execution
        elif real_deny:
            audit_action = AuditAction.CALL_WOULD_DENY if self.mode == "observe" else AuditAction.CALL_DENIED
            await self._emit_run_pre_audit(envelope, session, audit_action, pre)
            self.telemetry.record_denial(envelope, pre.reason)
            if self.mode == "enforce":
                if self._on_deny:
                    try:
                        self._on_deny(envelope, pre.reason or "", pre.decision_name)
                    except Exception:
                        logger.exception("on_deny callback raised")
                span.set_attribute("governance.action", "denied")
                span.set_attribute("governance.reason", pre.reason or "")
                span.end()
                raise EdictumDenied(
                    reason=pre.reason,
                    decision_source=pre.decision_source,
                    decision_name=pre.decision_name,
                )
            # observe mode: fall through to execute
            span.set_attribute("governance.action", "would_deny")
            span.set_attribute("governance.would_deny_reason", pre.reason or "")
        else:
            # Emit CALL_WOULD_DENY for any per-contract observed denials
            for cr in pre.contracts_evaluated:
                if cr.get("observed") and not cr.get("passed"):
                    observed_event = AuditEvent(
                        action=AuditAction.CALL_WOULD_DENY,
                        run_id=envelope.run_id,
                        call_id=envelope.call_id,
                        tool_name=envelope.tool_name,
                        tool_args=self.redaction.redact_args(envelope.args),
                        side_effect=envelope.side_effect.value,
                        environment=envelope.environment,
                        principal=asdict(envelope.principal) if envelope.principal else None,
                        decision_source="precondition",
                        decision_name=cr["name"],
                        reason=cr["message"],
                        mode="observe",
                        policy_version=self.policy_version,
                        policy_error=pre.policy_error,
                    )
                    await self.audit_sink.emit(observed_event)
                    self._emit_otel_governance_span(observed_event)
            await self._emit_run_pre_audit(envelope, session, AuditAction.CALL_ALLOWED, pre)
            self.telemetry.record_allowed(envelope)
            if self._on_allow:
                try:
                    self._on_allow(envelope)
                except Exception:
                    logger.exception("on_allow callback raised")
            span.set_attribute("governance.action", "allowed")

        # Emit shadow audit events (never affect the real decision)
        for sr in pre.shadow_results:
            shadow_action = AuditAction.CALL_WOULD_DENY if not sr["passed"] else AuditAction.CALL_ALLOWED
            shadow_event = AuditEvent(
                action=shadow_action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                tool_name=envelope.tool_name,
                tool_args=self.redaction.redact_args(envelope.args),
                side_effect=envelope.side_effect.value,
                environment=envelope.environment,
                principal=asdict(envelope.principal) if envelope.principal else None,
                decision_source=sr["source"],
                decision_name=sr["name"],
                reason=sr["message"],
                mode="observe",
                policy_version=self.policy_version,
            )
            await self.audit_sink.emit(shadow_event)
            self._emit_otel_governance_span(shadow_event)

        # Execute tool
        try:
            result = tool_callable(**args)
            if asyncio.iscoroutine(result):
                result = await result
            if self._success_check:
                tool_success = self._success_check(tool_name, result)
            else:
                tool_success = True
        except Exception as e:
            result = str(e)
            tool_success = False

        # Post-execute
        post = await pipeline.post_execute(envelope, result, tool_success)
        await session.record_execution(tool_name, success=tool_success)

        # Emit post-execute audit
        post_action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
        post_event = AuditEvent(
            action=post_action,
            run_id=envelope.run_id,
            call_id=envelope.call_id,
            tool_name=envelope.tool_name,
            tool_args=self.redaction.redact_args(envelope.args),
            side_effect=envelope.side_effect.value,
            environment=envelope.environment,
            principal=asdict(envelope.principal) if envelope.principal else None,
            tool_success=tool_success,
            postconditions_passed=post.postconditions_passed,
            contracts_evaluated=post.contracts_evaluated,
            session_attempt_count=await session.attempt_count(),
            session_execution_count=await session.execution_count(),
            mode=self.mode,
            policy_version=self.policy_version,
            policy_error=post.policy_error,
        )
        await self.audit_sink.emit(post_event)
        self._emit_otel_governance_span(post_event)

        span.set_attribute("governance.tool_success", tool_success)
        span.set_attribute("governance.postconditions_passed", post.postconditions_passed)
        span.end()

        if not tool_success:
            raise EdictumToolError(result)

        return post.redacted_response if post.redacted_response is not None else result

    async def _emit_run_pre_audit(self, envelope, session, action: AuditAction, pre: PreDecision) -> None:
        event = AuditEvent(
            action=action,
            run_id=envelope.run_id,
            call_id=envelope.call_id,
            tool_name=envelope.tool_name,
            tool_args=self.redaction.redact_args(envelope.args),
            side_effect=envelope.side_effect.value,
            environment=envelope.environment,
            principal=asdict(envelope.principal) if envelope.principal else None,
            decision_source=pre.decision_source,
            decision_name=pre.decision_name,
            reason=pre.reason,
            hooks_evaluated=pre.hooks_evaluated,
            contracts_evaluated=pre.contracts_evaluated,
            session_attempt_count=await session.attempt_count(),
            session_execution_count=await session.execution_count(),
            mode=self.mode,
            policy_version=self.policy_version,
            policy_error=pre.policy_error,
        )
        await self.audit_sink.emit(event)
        self._emit_otel_governance_span(event)

    def _emit_otel_governance_span(self, audit_event: AuditEvent) -> None:
        """Emit an OTel span with governance attributes from an AuditEvent."""
        if not has_otel():
            return

        from opentelemetry.trace import StatusCode

        with self._gov_tracer.start_as_current_span("edictum.evaluate") as span:
            span.set_attribute("edictum.tool.name", audit_event.tool_name)
            span.set_attribute("edictum.verdict", audit_event.action.value)
            span.set_attribute("edictum.verdict.reason", audit_event.reason or "")
            span.set_attribute("edictum.decision.source", audit_event.decision_source or "")
            span.set_attribute("edictum.decision.name", audit_event.decision_name or "")
            span.set_attribute("edictum.side_effect", audit_event.side_effect)
            span.set_attribute("edictum.environment", audit_event.environment)
            span.set_attribute("edictum.mode", audit_event.mode)
            span.set_attribute("edictum.session.attempt_count", audit_event.session_attempt_count or 0)
            span.set_attribute("edictum.session.execution_count", audit_event.session_execution_count or 0)

            tool_args_str = json.dumps(audit_event.tool_args, default=str) if audit_event.tool_args else "{}"
            span.set_attribute("edictum.tool.args", tool_args_str)

            if audit_event.principal:
                for key in ("role", "team", "ticket_ref", "user_id", "org_id"):
                    val = audit_event.principal.get(key)
                    if val:
                        span.set_attribute(f"edictum.principal.{key}", val)

            if audit_event.policy_version:
                span.set_attribute("edictum.policy_version", audit_event.policy_version)
            if audit_event.policy_error:
                span.set_attribute("edictum.policy_error", True)

            if audit_event.action.value in ("call_denied",):
                span.set_status(StatusCode.ERROR, audit_event.reason or "denied")
            else:
                span.set_status(StatusCode.OK)


def _validate_custom_operators(custom_operators: dict[str, Any]) -> None:
    """Validate custom operator names don't clash with built-in operators."""
    from edictum.yaml_engine.evaluator import BUILTIN_OPERATOR_NAMES

    clashes = set(custom_operators) & BUILTIN_OPERATOR_NAMES
    if clashes:
        raise EdictumConfigError(f"Custom operator names clash with built-in operators: {sorted(clashes)}")
    for name, fn in custom_operators.items():
        if not callable(fn):
            raise EdictumConfigError(f"Custom operator '{name}' is not callable")


def _validate_custom_selectors(custom_selectors: dict[str, Any]) -> None:
    """Validate custom selector prefixes don't clash with built-in selectors."""
    from edictum.yaml_engine.evaluator import BUILTIN_SELECTOR_PREFIXES

    clashes = set(custom_selectors) & BUILTIN_SELECTOR_PREFIXES
    if clashes:
        raise EdictumConfigError(f"Custom selector prefixes clash with built-in selectors: {sorted(clashes)}")
    for name, fn in custom_selectors.items():
        if not callable(fn):
            raise EdictumConfigError(f"Custom selector '{name}' is not callable")


class EdictumDenied(Exception):  # noqa: N818
    """Raised when guard.run() denies a tool call in enforce mode."""

    def __init__(self, reason, decision_source=None, decision_name=None):
        self.reason = reason
        self.decision_source = decision_source
        self.decision_name = decision_name
        super().__init__(reason)


class EdictumConfigError(Exception):
    """Raised for configuration/load-time errors (invalid YAML, schema failures, etc.)."""

    pass


class EdictumToolError(Exception):
    """Raised when the governed tool itself fails."""

    pass
