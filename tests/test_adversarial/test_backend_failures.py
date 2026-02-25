"""Adversarial tests for storage backend failure modes."""

from __future__ import annotations

import asyncio

import pytest

from edictum.storage import MemoryBackend

pytestmark = pytest.mark.security


class TestMemoryBackendConcurrency:
    @pytest.mark.asyncio
    async def test_concurrent_increments_atomic(self):
        backend = MemoryBackend()
        n = 200
        await asyncio.gather(*[backend.increment("counter") for _ in range(n)])
        result = await backend.get("counter")
        assert int(result) == n

    @pytest.mark.asyncio
    async def test_concurrent_increment_and_delete_no_crash(self):
        backend = MemoryBackend()

        async def increment_loop():
            for _ in range(50):
                await backend.increment("key")

        async def delete_loop():
            for _ in range(50):
                await backend.delete("key")

        await asyncio.gather(increment_loop(), delete_loop())


class TestServerBackendFailClosed:
    @pytest.mark.asyncio
    async def test_get_raises_on_connection_error(self):
        pytest.importorskip("edictum.server")
        from unittest.mock import AsyncMock, MagicMock

        from edictum.server.backend import ServerBackend

        client = MagicMock()
        client.get = AsyncMock(side_effect=ConnectionError("refused"))
        backend = ServerBackend(client)

        with pytest.raises(ConnectionError):
            await backend.get("any-key")

    @pytest.mark.asyncio
    async def test_get_raises_on_timeout(self):
        pytest.importorskip("edictum.server")
        from unittest.mock import AsyncMock, MagicMock

        from edictum.server.backend import ServerBackend

        client = MagicMock()
        client.get = AsyncMock(side_effect=TimeoutError("timeout"))
        backend = ServerBackend(client)

        with pytest.raises(TimeoutError):
            await backend.get("any-key")
