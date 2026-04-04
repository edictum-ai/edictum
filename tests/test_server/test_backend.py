"""Tests for ServerBackend."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from edictum.server.backend import ServerBackend
from edictum.server.client import EdictumServerClient, EdictumServerError


@pytest.fixture
def mock_client():
    client = MagicMock(spec=EdictumServerClient)
    client.get = AsyncMock()
    client.post = AsyncMock()
    client.put = AsyncMock()
    client.delete = AsyncMock()
    return client


class TestServerBackend:
    @pytest.mark.asyncio
    async def test_get_returns_value(self, mock_client):
        mock_client.get.return_value = {"value": "hello"}
        backend = ServerBackend(mock_client)
        result = await backend.get("my-key")
        assert result == "hello"
        mock_client.get.assert_called_once_with("/v1/sessions/my-key")

    @pytest.mark.asyncio
    async def test_get_returns_none_on_404(self, mock_client):
        mock_client.get.side_effect = EdictumServerError(404, "Not Found")
        backend = ServerBackend(mock_client)
        result = await backend.get("missing-key")
        assert result is None

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_get_raises_on_connection_error(self, mock_client):
        mock_client.get.side_effect = ConnectionError("refused")
        backend = ServerBackend(mock_client)
        with pytest.raises(ConnectionError, match="refused"):
            await backend.get("key")

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_get_raises_on_timeout(self, mock_client):
        mock_client.get.side_effect = TimeoutError("timeout")
        backend = ServerBackend(mock_client)
        with pytest.raises(TimeoutError, match="timeout"):
            await backend.get("key")

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_get_raises_on_500(self, mock_client):
        mock_client.get.side_effect = EdictumServerError(500, "Internal")
        backend = ServerBackend(mock_client)
        with pytest.raises(EdictumServerError, match="HTTP 500"):
            await backend.get("key")

    @pytest.mark.asyncio
    async def test_set_value(self, mock_client):
        mock_client.put.return_value = {"ok": True}
        backend = ServerBackend(mock_client)
        await backend.set("key", "value")
        mock_client.put.assert_called_once_with("/v1/sessions/key", {"value": "value"})

    @pytest.mark.asyncio
    async def test_delete(self, mock_client):
        mock_client.delete.return_value = {}
        backend = ServerBackend(mock_client)
        await backend.delete("key")
        mock_client.delete.assert_called_once_with("/v1/sessions/key")

    @pytest.mark.asyncio
    async def test_delete_ignores_404(self, mock_client):
        mock_client.delete.side_effect = EdictumServerError(404, "Not Found")
        backend = ServerBackend(mock_client)
        await backend.delete("missing-key")  # Should not raise

    @pytest.mark.asyncio
    async def test_delete_raises_on_other_errors(self, mock_client):
        mock_client.delete.side_effect = EdictumServerError(500, "Server Error")
        backend = ServerBackend(mock_client)
        with pytest.raises(EdictumServerError, match="HTTP 500"):
            await backend.delete("key")

    @pytest.mark.asyncio
    async def test_increment(self, mock_client):
        mock_client.post.return_value = {"value": 5.0}
        backend = ServerBackend(mock_client)
        result = await backend.increment("counter", 2.0)
        assert result == 5.0
        mock_client.post.assert_called_once_with(
            "/v1/sessions/counter/increment",
            {"amount": 2.0},
        )

    @pytest.mark.asyncio
    async def test_increment_default_amount(self, mock_client):
        mock_client.post.return_value = {"value": 1.0}
        backend = ServerBackend(mock_client)
        result = await backend.increment("counter")
        assert result == 1.0
        mock_client.post.assert_called_once_with(
            "/v1/sessions/counter/increment",
            {"amount": 1},
        )

    def test_implements_protocol(self, mock_client):
        """Verify ServerBackend has all StorageBackend methods."""
        backend = ServerBackend(mock_client)
        assert hasattr(backend, "get")
        assert hasattr(backend, "set")
        assert hasattr(backend, "delete")
        assert hasattr(backend, "increment")
        assert hasattr(backend, "batch_get")
