"""Tests for ServerContractSource."""

from __future__ import annotations

import json
import sys
from contextlib import asynccontextmanager
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from edictum.server.client import EdictumServerClient
from edictum.server.contract_source import ServerContractSource


def _make_client(*, env: str = "production", bundle_name: str = "default") -> EdictumServerClient:
    """Create a real client with specified env/bundle_name."""
    return EdictumServerClient("http://localhost", "key", env=env, bundle_name=bundle_name)


def _make_sse_event(data: dict, event_type: str = "contract_update") -> MagicMock:
    """Create a mock SSE event."""
    ev = MagicMock()
    ev.event = event_type
    ev.data = json.dumps(data)
    return ev


def _install_fake_httpx_sse(events: list[MagicMock], captured_params: list[dict]):
    """Install a fake httpx_sse module that captures params and yields events."""

    @asynccontextmanager
    async def fake_aconnect_sse(http_client, method, url, *, params=None):
        captured_params.append(params or {})
        source = MagicMock()

        async def aiter():
            for ev in events:
                yield ev

        source.aiter_sse = aiter
        yield source

    mod = ModuleType("httpx_sse")
    mod.aconnect_sse = fake_aconnect_sse  # type: ignore[attr-defined]
    sys.modules["httpx_sse"] = mod
    return mod


class TestServerContractSource:
    def test_init(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client, reconnect_delay=2.0, max_reconnect_delay=120.0)
        assert source._reconnect_delay == 2.0
        assert source._max_reconnect_delay == 120.0
        assert source._connected is False
        assert source._closed is False

    def test_init_defaults(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        assert source._reconnect_delay == 1.0
        assert source._max_reconnect_delay == 60.0
        assert source._current_revision is None
        assert source._last_public_key is None

    @pytest.mark.asyncio
    async def test_connect(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        await source.connect()
        assert source._connected is True
        assert source._closed is False

    @pytest.mark.asyncio
    async def test_close(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        await source.connect()
        await source.close()
        assert source._closed is True
        assert source._connected is False

    @pytest.mark.asyncio
    async def test_close_without_connect(self):
        client = MagicMock(spec=EdictumServerClient)
        source = ServerContractSource(client)
        await source.close()  # Should not raise
        assert source._closed is True

    @pytest.mark.asyncio
    async def test_watch_passes_env_and_bundle_name_in_sse_params(self):
        """SSE connection includes env and bundle_name query params."""
        client = _make_client(env="staging", bundle_name="devops-agent")
        source = ServerContractSource(client)

        event = _make_sse_event({"yaml": "test", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([event], captured)

        async for _bundle in source.watch():
            await source.close()

        assert len(captured) == 1
        assert captured[0]["env"] == "staging"
        assert captured[0]["bundle_name"] == "devops-agent"

    @pytest.mark.asyncio
    async def test_watch_passes_policy_version_after_first_update(self):
        """After receiving a contract_update, _current_revision is updated."""
        client = _make_client()
        source = ServerContractSource(client)

        events = [
            _make_sse_event({"yaml": "v1", "revision_hash": "rev-abc"}),
            _make_sse_event({"yaml": "v2", "revision_hash": "rev-def"}),
        ]
        captured: list[dict] = []
        _install_fake_httpx_sse(events, captured)

        received = []
        async for bundle in source.watch():
            received.append(bundle)
            if len(received) == 2:
                await source.close()

        # First connection should not have policy_version
        assert "policy_version" not in captured[0]
        # After events, _current_revision should be set to last received
        assert source._current_revision == "rev-def"

    @pytest.mark.asyncio
    async def test_watch_stores_public_key(self):
        """contract_update with public_key stores it for future verification."""
        client = _make_client()
        source = ServerContractSource(client)

        event = _make_sse_event(
            {
                "yaml": "test",
                "revision_hash": "abc",
                "public_key": "ed25519-pub-hex-123",
            }
        )
        captured: list[dict] = []
        _install_fake_httpx_sse([event], captured)

        async for _bundle in source.watch():
            await source.close()

        assert source._last_public_key == "ed25519-pub-hex-123"
