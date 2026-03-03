"""Tests for SSE -> reload wiring."""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum import Edictum


def _b64(yaml_str: str) -> str:
    """Base64-encode YAML, matching server's yaml_bytes format."""
    return base64.b64encode(yaml_str.encode("utf-8")).decode("ascii")


BUNDLE_V1 = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-v1
defaults:
  mode: enforce
contracts:
  - id: deny-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      effect: deny
      message: "Destructive command denied."
"""

BUNDLE_V2 = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-v2
defaults:
  mode: enforce
contracts:
  - id: deny-curl
    type: pre
    tool: bash
    when:
      args.command:
        contains: "curl"
    then:
      effect: deny
      message: "Network access denied."
  - id: deny-wget
    type: pre
    tool: bash
    when:
      args.command:
        contains: "wget"
    then:
      effect: deny
      message: "Network access denied."
"""


def _server_patches():
    return (
        patch("edictum.server.client.EdictumServerClient"),
        patch("edictum.server.audit_sink.ServerAuditSink"),
        patch("edictum.server.approval_backend.ServerApprovalBackend"),
        patch("edictum.server.backend.ServerBackend"),
        patch("edictum.server.contract_source.ServerContractSource"),
    )


class TestSSEReload:
    @pytest.mark.asyncio
    async def test_sse_event_triggers_reload(self):
        """SSE contract_update event triggers reload with new contracts."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = MagicMock()
            client.bundle_name = "default"
            client.env = "production"
            client.get = AsyncMock(return_value={"yaml_bytes": _b64(BUNDLE_V1)})
            client.close = AsyncMock()
            mock_cls.return_value = client

            update_received = asyncio.Event()

            async def mock_watch():
                yield {"yaml_bytes": _b64(BUNDLE_V2)}
                update_received.set()

            source = MagicMock()
            source.connect = AsyncMock()
            source.close = AsyncMock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                auto_watch=True,
            )

            await asyncio.wait_for(update_received.wait(), timeout=2.0)
            await asyncio.sleep(0.05)

            assert len(guard._preconditions) == 2

            await guard.close()

    @pytest.mark.asyncio
    async def test_sse_malformed_base64_does_not_kill_watcher(self):
        """Malformed base64 in SSE event skips the event but keeps watcher alive."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = MagicMock()
            client.bundle_name = "default"
            client.env = "production"
            client.get = AsyncMock(return_value={"yaml_bytes": _b64(BUNDLE_V1)})
            client.close = AsyncMock()
            mock_cls.return_value = client

            update_received = asyncio.Event()

            async def mock_watch():
                # First event: malformed base64 — should be skipped
                yield {"yaml_bytes": "!!!not-valid-base64!!!"}
                # Second event: valid bundle — should be applied
                yield {"yaml_bytes": _b64(BUNDLE_V2)}
                update_received.set()

            source = MagicMock()
            source.connect = AsyncMock()
            source.close = AsyncMock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                auto_watch=True,
            )

            assert len(guard._preconditions) == 1  # V1: deny-rm only

            await asyncio.wait_for(update_received.wait(), timeout=2.0)
            await asyncio.sleep(0.05)

            # V2 was applied despite the bad event before it
            assert len(guard._preconditions) == 2

            await guard.close()

    @pytest.mark.asyncio
    async def test_sse_invalid_yaml_preserves_contracts(self):
        """SSE event with invalid YAML keeps existing contracts."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = MagicMock()
            client.bundle_name = "default"
            client.env = "production"
            client.get = AsyncMock(return_value={"yaml_bytes": _b64(BUNDLE_V1)})
            client.close = AsyncMock()
            mock_cls.return_value = client

            update_received = asyncio.Event()

            async def mock_watch():
                yield {"yaml_bytes": _b64("invalid: yaml: [")}
                update_received.set()

            source = MagicMock()
            source.connect = AsyncMock()
            source.close = AsyncMock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                auto_watch=True,
            )

            original_count = len(guard._preconditions)

            await asyncio.wait_for(update_received.wait(), timeout=2.0)
            await asyncio.sleep(0.05)

            assert len(guard._preconditions) == original_count

            await guard.close()

    @pytest.mark.asyncio
    async def test_stop_sse_watcher(self):
        """_stop_sse_watcher cancels the background task."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = MagicMock()
            client.bundle_name = "default"
            client.env = "production"
            client.get = AsyncMock(return_value={"yaml_bytes": _b64(BUNDLE_V1)})
            client.close = AsyncMock()
            mock_cls.return_value = client

            async def mock_watch():
                await asyncio.sleep(9999)
                return
                yield  # noqa: RET504 — makes this an async generator

            source = MagicMock()
            source.connect = AsyncMock()
            source.close = AsyncMock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                auto_watch=True,
            )

            assert guard._sse_task is not None
            assert not guard._sse_task.done()

            await guard.close()

            assert guard._sse_task is None
            source.close.assert_called_once()
            client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_idempotent_on_non_server_instance(self):
        """close() is a no-op on instances created without from_server()."""
        guard = Edictum.from_yaml_string(BUNDLE_V1)
        await guard.close()

    @pytest.mark.asyncio
    async def test_auto_watch_false_no_sse_task(self):
        """auto_watch=False skips the SSE watcher."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = MagicMock()
            client.bundle_name = "default"
            client.env = "production"
            client.get = AsyncMock(return_value={"yaml_bytes": _b64(BUNDLE_V1)})
            client.close = AsyncMock()
            mock_cls.return_value = client

            source = MagicMock()
            source.connect = AsyncMock()
            source.close = AsyncMock()
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                auto_watch=False,
            )

            assert guard._sse_task is None
            source.connect.assert_not_called()

            await guard.close()
