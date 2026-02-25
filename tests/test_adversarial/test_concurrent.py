"""Concurrency tests for session and pipeline."""

from __future__ import annotations

import asyncio

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend

pytestmark = pytest.mark.security


class TestSessionConcurrency:
    @pytest.mark.asyncio
    async def test_attempt_limit_holds_under_gather(self):
        backend = MemoryBackend()
        session = Session("test-session", backend)

        await asyncio.gather(*[session.increment_attempts() for _ in range(100)])
        final_count = await session.attempt_count()
        assert final_count == 100
