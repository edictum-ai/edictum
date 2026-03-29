"""Behavior tests for StorageBackend and MemoryBackend.

Every accepted parameter must have an observable action.
If a parameter is accepted but ignored, these tests fail.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from edictum.storage import MemoryBackend


class TestMemoryBackendParameterEffects:
    """Every parameter accepted by MemoryBackend must have an observable action."""

    def test_set_does_not_accept_ttl(self):
        """MemoryBackend.set() must not have a ttl parameter.

        TTL is a dead parameter — no callers use it, Redis/DB backends are
        dropped features, and the Edictum Server (ee/) will handle session
        coordination differently.
        """
        backend = MemoryBackend()
        sig = inspect.signature(backend.set)
        assert "ttl" not in sig.parameters, (
            "MemoryBackend.set() should not accept a ttl parameter. TTL support was removed as a dead parameter."
        )

    async def test_increment_amount_parameter_has_effect(self):
        """increment(amount=N) must increase by N, not by 1."""
        backend = MemoryBackend()
        result = await backend.increment("counter", amount=5)
        assert result == 5, "amount parameter must affect the increment value"
        result = await backend.increment("counter", amount=3)
        assert result == 8, "subsequent increments must accumulate correctly"

    async def test_increment_default_amount_is_one(self):
        """increment() with no amount must default to 1."""
        backend = MemoryBackend()
        result = await backend.increment("counter")
        assert result == 1, "default increment amount must be 1"

    async def test_delete_removes_both_data_and_counters(self):
        """delete() must remove from both _data and _counters stores."""
        backend = MemoryBackend()
        await backend.set("data_key", "value")
        await backend.increment("counter_key")

        await backend.delete("data_key")
        await backend.delete("counter_key")

        assert await backend.get("data_key") is None
        assert await backend.get("counter_key") is None


@pytest.mark.security
class TestMemoryBackendAtomicity:
    """Security: concurrent operations maintain data integrity."""

    async def test_concurrent_increments_atomic(self):
        """100 concurrent increments should produce exactly 100."""
        backend = MemoryBackend()

        async def inc():
            await backend.increment("counter")

        await asyncio.gather(*[inc() for _ in range(100)])
        result = await backend.get("counter")
        assert result == "100"

    async def test_concurrent_increment_and_delete(self):
        """Race between increment and delete should not crash or corrupt state."""
        backend = MemoryBackend()

        async def inc():
            for _ in range(10):
                await backend.increment("key")

        async def delete():
            for _ in range(10):
                await backend.delete("key")

        # Should not crash
        await asyncio.gather(inc(), delete())
        # State should be consistent (either key exists with a count or doesn't)
        result = await backend.get("key")
        if result is not None:
            assert float(result) > 0
