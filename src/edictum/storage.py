"""StorageBackend protocol + MemoryBackend implementation."""

from __future__ import annotations

import asyncio
from typing import Protocol


class StorageBackend(Protocol):
    """Protocol for persistent state storage.

    Requirements:
    - increment() MUST be atomic
    - get/set for simple key-value

    v0.0.1: No append() method (counters only, no list ops).
    """

    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def increment(self, key: str, amount: float = 1) -> float: ...


class MemoryBackend:
    """In-memory storage for development and testing.

    WARNING: State lost on restart. Session rules reset.
    Suitable for: local dev, tests, single-process scripts.
    """

    def __init__(self):
        self._data: dict[str, str] = {}
        self._counters: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> str | None:
        if key in self._data:
            return self._data[key]
        if key in self._counters:
            v = self._counters[key]
            return str(int(v)) if v == int(v) else str(v)
        return None

    async def set(self, key: str, value: str) -> None:
        self._data[key] = value

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)
            self._counters.pop(key, None)

    async def increment(self, key: str, amount: float = 1) -> float:
        async with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount
            return self._counters[key]

    async def batch_get(self, keys: list[str]) -> dict[str, str | None]:
        """Retrieve multiple values in a single operation.

        In-memory implementation: multiple dict lookups, no network overhead.
        """
        result: dict[str, str | None] = {}
        for key in keys:
            result[key] = await self.get(key)
        return result
