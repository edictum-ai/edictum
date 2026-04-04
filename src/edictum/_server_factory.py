"""Server factory and SSE lifecycle for Edictum.from_server()."""

from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from edictum._exceptions import EdictumConfigError
from edictum.approval import ApprovalBackend
from edictum.audit import AuditSink
from edictum.envelope import Principal
from edictum.storage import StorageBackend

if TYPE_CHECKING:
    from edictum._guard import Edictum
    from edictum.envelope import ToolCall
    from edictum.workflow import WorkflowRuntime

logger = logging.getLogger(__name__)

# How long from_server() waits for the server to push a bundle in
# server-assigned mode (bundle_name=None) before raising EdictumConfigError.
_ASSIGNMENT_TIMEOUT_SECS = 30.0


async def _from_server(
    cls: type[Edictum],
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

    Auto-configures all server components (audit, approval, session,
    rule source) from a single URL and API key.

    Args:
        url: Base URL of the edictum-server.
        api_key: API key for authentication.
        agent_id: Unique identifier for this agent instance.
        env: Environment name (defaults to ``"production"``).
        bundle_name: Which bundle lineage this agent tracks. When
            ``None``, the server assigns a bundle via SSE.
        tags: Key-value metadata describing this agent.
        audit_sink: Override the default ``ServerAuditSink``.
        approval_backend: Override the default ``ServerApprovalBackend``.
        storage_backend: Override the default ``ServerBackend``.
        mode: Enforcement mode (``"enforce"`` or ``"observe"``).
        on_block: Callback invoked when a tool call is denied.
        on_allow: Callback invoked when a tool call is allowed.
        success_check: Callable ``(tool_name, result) -> bool``.
        principal: Static principal for all tool calls.
        principal_resolver: Per-call dynamic principal resolution.
        auto_watch: If True (default), start an SSE background task.
        allow_insecure: If True, allow plaintext HTTP to non-loopback
            hosts (logs a warning). Defaults to False (raises ValueError).
        verify_signatures: If True, verify Ed25519 signatures on bundles.
            Requires the ``edictum[verified]`` extra (PyNaCl).
        signing_public_key: Hex-encoded Ed25519 public key for signature
            verification. Required when ``verify_signatures=True``.
        workflow_runtime: Pre-built workflow runtime for explicit M1 workflow
            loading with server-backed rules.
        workflow_path: Explicit local workflow YAML path for M1 workflow gates.
        workflow_content: Explicit local workflow YAML content for M1 workflow gates.
        workflow_exec_evaluator_enabled: Enable trusted ``exec(...)`` workflow
            conditions for the locally attached workflow.

    Returns:
        Configured Edictum instance connected to the server.

    Raises:
        EdictumConfigError: If the server is unreachable or returns
            invalid data, if signature verification fails, or if
            assignment times out.
        ValueError: If ``bundle_name`` is None and ``auto_watch`` is False,
            or if ``verify_signatures=True`` without ``signing_public_key``.
    """
    from edictum._factory import _load_workflow_runtime
    from edictum.server.approval_backend import ServerApprovalBackend
    from edictum.server.audit_sink import ServerAuditSink
    from edictum.server.backend import ServerBackend
    from edictum.server.client import EdictumServerClient
    from edictum.server.rule_source import ServerContractSource
    from edictum.session import Session
    from edictum.workflow.state import build_workflow_snapshot
    from edictum.yaml_engine.compiler import compile_contracts
    from edictum.yaml_engine.loader import load_bundle_string

    if bundle_name is None and not auto_watch:
        raise ValueError(
            "auto_watch must be True when bundle_name is None. "
            "Server-assigned mode requires the SSE connection to receive the bundle."
        )

    if verify_signatures and signing_public_key is None:
        raise ValueError("signing_public_key is required when verify_signatures=True")
    if workflow_runtime is not None and (workflow_path is not None or workflow_content is not None):
        raise EdictumConfigError("Specify workflow_runtime or workflow_path/workflow_content, not both")

    environment = env or "production"

    client = EdictumServerClient(
        url,
        api_key,
        agent_id=agent_id,
        env=environment,
        bundle_name=bundle_name,
        tags=tags,
        allow_insecure=allow_insecure,
    )

    effective_sink = audit_sink or ServerAuditSink(client)
    effective_approval = approval_backend or ServerApprovalBackend(client)
    effective_backend = storage_backend or ServerBackend(client)
    effective_workflow_runtime = workflow_runtime or _load_workflow_runtime(
        workflow_path=workflow_path,
        workflow_content=workflow_content,
        workflow_exec_evaluator_enabled=workflow_exec_evaluator_enabled,
    )

    if bundle_name is not None:
        try:
            response = await client.get(
                f"/v1/rulesets/{bundle_name}/current",
                env=client.env,
            )
            yaml_b64 = response.get("yaml_bytes", "")
            bundle_yaml = base64.b64decode(yaml_b64) if yaml_b64 else b""
        except Exception as exc:
            await client.close()
            raise EdictumConfigError(f"Failed to fetch rules from server: {exc}") from exc

        if verify_signatures:
            from edictum.server.verification import BundleVerificationError, verify_bundle_signature

            signature = response.get("signature")
            if not signature:
                await client.close()
                raise EdictumConfigError("Server response does not include a signature, but verify_signatures=True")

            try:
                verify_bundle_signature(bundle_yaml, signature, signing_public_key)  # type: ignore[arg-type]
            except BundleVerificationError as exc:
                await client.close()
                raise EdictumConfigError(f"Bundle signature verification failed: {exc}") from exc
            except ImportError as exc:
                await client.close()
                raise EdictumConfigError(
                    f"Bundle signature verification requires PyNaCl: {exc}. "
                    "Install with: pip install 'edictum[verified]'"
                ) from exc

        try:
            bundle_data, bundle_hash = load_bundle_string(bundle_yaml)
            compiled = compile_contracts(bundle_data)
        except Exception as exc:
            await client.close()
            raise EdictumConfigError(f"Failed to parse server rules: {exc}") from exc

        policy_version = str(bundle_hash)
        effective_mode = mode or compiled.default_mode
        all_contracts = (
            compiled.preconditions + compiled.postconditions + compiled.session_contracts + compiled.sandbox_contracts
        )
        yaml_tools = compiled.tools

        guard = cls(
            environment=environment,
            mode=effective_mode,
            limits=compiled.limits,
            tools=yaml_tools if yaml_tools else None,
            rules=all_contracts,
            audit_sink=effective_sink,
            backend=effective_backend,
            policy_version=policy_version,
            on_block=on_block,
            on_allow=on_allow,
            success_check=success_check,
            principal=principal,
            principal_resolver=principal_resolver,
            approval_backend=effective_approval,
            workflow_runtime=effective_workflow_runtime,
        )
    else:
        guard = cls(
            environment=environment,
            mode=mode,
            limits=None,
            tools=None,
            rules=[],
            audit_sink=effective_sink,
            backend=effective_backend,
            policy_version=None,
            on_block=on_block,
            on_allow=on_allow,
            success_check=success_check,
            principal=principal,
            principal_resolver=principal_resolver,
            approval_backend=effective_approval,
            workflow_runtime=effective_workflow_runtime,
        )
        guard._assignment_ready = asyncio.Event()

    guard._server_client = client
    guard._rule_source = ServerContractSource(client)
    guard._sse_task = None  # asyncio.Task | None, set by _start_sse_watcher
    guard._verify_signatures = verify_signatures
    guard._signing_public_key = signing_public_key

    if effective_workflow_runtime is not None and hasattr(effective_sink, "_workflow_snapshot_provider"):

        async def _workflow_snapshot_provider(event: Any) -> dict[str, Any] | None:
            session_id = getattr(event, "session_id", None)
            if not isinstance(session_id, str) or not session_id:
                return None
            session = Session(session_id, effective_backend)
            state = await effective_workflow_runtime.state(session)
            return build_workflow_snapshot(effective_workflow_runtime.definition, state)

        effective_sink._workflow_snapshot_provider = _workflow_snapshot_provider

    if auto_watch:
        await _start_sse_watcher(guard)

    if bundle_name is None:
        ready_event = guard._assignment_ready
        assert ready_event is not None
        try:
            await asyncio.wait_for(
                ready_event.wait(),
                timeout=_ASSIGNMENT_TIMEOUT_SECS,
            )
        except TimeoutError:
            await _close(guard)
            raise EdictumConfigError(
                f"Server did not push a bundle assignment within "
                f"{_ASSIGNMENT_TIMEOUT_SECS} seconds. Check that the server "
                f"has an assignment rule matching this agent's tags."
            ) from None

    return guard


async def _start_sse_watcher(self: Edictum) -> None:
    """Start a background task that watches for SSE rule updates."""
    source = getattr(self, "_rule_source", None)
    if source is None:
        return

    await source.connect()

    async def _watch_loop() -> None:
        try:
            async for bundle in source.watch():
                try:
                    if bundle.get("_assignment_changed"):
                        new_name = bundle["bundle_name"]
                        server_client = self._server_client
                        if server_client is None:
                            logger.warning("Server client missing during SSE assignment update")
                            continue
                        response = await server_client.get(
                            f"/v1/rulesets/{new_name}/current",
                            env=server_client.env,
                        )
                        yaml_b64 = response.get("yaml_bytes", "")
                        yaml_data = base64.b64decode(yaml_b64) if yaml_b64 else b""
                        signature = response.get("signature")
                    else:
                        yaml_b64 = bundle.get("yaml_bytes", "")
                        yaml_data = base64.b64decode(yaml_b64) if yaml_b64 else b""
                        signature = bundle.get("signature")

                    if getattr(self, "_verify_signatures", False):
                        from edictum.server.verification import (
                            BundleVerificationError,
                            verify_bundle_signature,
                        )

                        public_key = getattr(self, "_signing_public_key", None)

                        if not signature:
                            logger.warning("Unsigned bundle received with verify_signatures=True — rejecting")
                            continue
                        if not isinstance(public_key, str):
                            logger.warning("Missing signing_public_key for bundle verification — rejecting")
                            continue

                        try:
                            verify_bundle_signature(yaml_data, signature, public_key)
                        except (BundleVerificationError, ImportError) as exc:
                            logger.warning("Bundle signature verification failed: %s — rejecting", exc)
                            continue

                    await self.reload(yaml_data)
                    if bundle.get("_assignment_changed"):
                        server_client = self._server_client
                        if server_client is not None:
                            server_client.bundle_name = bundle["bundle_name"]
                    ready_event = getattr(self, "_assignment_ready", None)
                    if ready_event is not None and not ready_event.is_set():
                        ready_event.set()
                except Exception:
                    logger.warning("Failed to reload rules from SSE update, keeping existing rules")
        except asyncio.CancelledError:
            return
        except Exception:
            logger.warning("SSE watcher loop exited unexpectedly")

    self._sse_task = asyncio.create_task(_watch_loop())


async def _stop_sse_watcher(self: Edictum) -> None:
    """Stop the SSE background watcher and close server resources."""
    task = getattr(self, "_sse_task", None)
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        self._sse_task = None

    source = getattr(self, "_rule_source", None)
    if source is not None:
        await source.close()

    client = getattr(self, "_server_client", None)
    if client is not None:
        await client.close()


async def _close(self: Edictum) -> None:
    """Shut down server resources (SSE watcher, HTTP client).

    Safe to call on non-server instances (no-op).
    """
    await _stop_sse_watcher(self)

    # Flush audit sink if it supports close()
    sink_close = getattr(self.audit_sink, "close", None)
    if sink_close is not None:
        result = sink_close()
        if asyncio.iscoroutine(result):
            await result
