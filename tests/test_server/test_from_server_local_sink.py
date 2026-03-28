"""Integration tests for local_sink in server mode (from_server construction path)."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum import AuditAction, Edictum
from edictum.audit import CollectingAuditSink
from edictum.storage import MemoryBackend

VALID_BUNDLE_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: block-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      action: block
      message: "Destructive command denied."
"""


def _b64_yaml(yaml_str: str = VALID_BUNDLE_YAML) -> str:
    return base64.b64encode(yaml_str.encode("utf-8")).decode("ascii")


def _make_client_mock():
    client = MagicMock()
    client.bundle_name = "default"
    client.env = "production"
    client.get = AsyncMock(return_value={"yaml_bytes": _b64_yaml()})
    client.close = AsyncMock()
    return client


def _make_source_mock():
    source = MagicMock()
    source.connect = AsyncMock()
    source.close = AsyncMock()
    return source


def _server_patches():
    return (
        patch("edictum.server.client.EdictumServerClient"),
        patch("edictum.server.audit_sink.ServerAuditSink"),
        patch("edictum.server.approval_backend.ServerApprovalBackend"),
        patch("edictum.server.backend.ServerBackend"),
        patch("edictum.server.rule_source.ServerContractSource"),
    )


class TestFromServerLocalSink:
    @pytest.mark.asyncio
    async def test_from_server_has_local_sink(self):
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
            )

            assert isinstance(guard.local_sink, CollectingAuditSink)
            await guard.close()

    @pytest.mark.asyncio
    async def test_from_server_local_sink_receives_events(self):
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink as mock_sink_cls, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()
            server_sink = MagicMock()
            server_sink.emit = AsyncMock()
            mock_sink_cls.return_value = server_sink

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
                storage_backend=MemoryBackend(),
            )

            await guard.run("read_file", {"path": "/tmp/test"}, lambda **kw: "ok")

            events = guard.local_sink.events
            assert len(events) >= 2
            actions = {e.action for e in events}
            assert AuditAction.CALL_ALLOWED in actions
            await guard.close()

    @pytest.mark.asyncio
    async def test_from_server_custom_sink_tees(self):
        custom_sink = MagicMock()
        custom_sink.emit = AsyncMock()

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                audit_sink=custom_sink,
                auto_watch=False,
                storage_backend=MemoryBackend(),
            )

            await guard.run("read_file", {"path": "/tmp/test"}, lambda **kw: "ok")

            # Both local_sink and custom sink received events
            assert len(guard.local_sink.events) >= 2
            assert custom_sink.emit.call_count >= 2
            await guard.close()

    @pytest.mark.asyncio
    async def test_from_server_server_sink_in_composite(self):
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink as mock_sink_cls, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()
            server_sink = MagicMock()
            mock_sink_cls.return_value = server_sink

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
            )

            sinks = guard.audit_sink.sinks
            assert guard.local_sink in sinks
            assert server_sink in sinks
            await guard.close()
