"""Behavior tests for SSE connection timeout separation.

Proves that the SSE stream uses a different read timeout than
the connection timeout, preventing premature stream termination.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

httpx = pytest.importorskip("httpx")
httpx_sse = pytest.importorskip("httpx_sse")

from edictum.server.rule_source import ServerContractSource  # noqa: E402


class TestSSETimeoutSeparation:
    """SSE connection must use separate connect and read timeouts."""

    @pytest.mark.asyncio
    async def test_sse_uses_extended_read_timeout(self):
        """The SSE stream passes a timeout with read > connect to aconnect_sse."""
        client = MagicMock()
        client.env = "test"
        client.bundle_name = "test-bundle"
        client.tags = None

        mock_http_client = MagicMock()
        client._ensure_client.return_value = mock_http_client

        source = ServerContractSource(client)
        source._connected = True

        captured_kwargs = {}

        # Patch aconnect_sse to capture the timeout kwarg
        class MockEventSource:
            async def aiter_sse(self):
                return
                yield  # make it an async generator

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        def capture_aconnect(*args, **kwargs):
            captured_kwargs.update(kwargs)
            # Close the source to break the loop after capture
            source._closed = True
            return MockEventSource()

        with patch.object(httpx_sse, "aconnect_sse", side_effect=capture_aconnect):
            async for _ in source.watch():
                pass  # pragma: no cover

        assert "timeout" in captured_kwargs, "SSE connection must pass explicit timeout"
        timeout = captured_kwargs["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.connect == 30.0
        assert timeout.read == 300.0, (
            f"SSE read timeout should be 300s (5min), got {timeout.read}. "
            "A 30s read timeout kills SSE streams between events."
        )
