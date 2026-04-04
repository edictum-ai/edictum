"""Tests for ServerContractSource."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from edictum.server.client import EdictumServerClient
from edictum.server.rule_source import _STABLE_CONNECTION_SECS, ServerContractSource


def _make_client(*, env: str = "production", bundle_name: str = "default") -> EdictumServerClient:
    """Create a real client with specified env/bundle_name."""
    return EdictumServerClient("http://localhost", "key", env=env, bundle_name=bundle_name)


def _make_sse_event(data: dict, event_type: str = "contract_update") -> MagicMock:
    """Create a mock SSE event."""
    ev = MagicMock()
    ev.event = event_type
    ev.data = json.dumps(data)
    return ev


def _install_fake_httpx_sse(
    events: list[MagicMock],
    captured_params: list[dict],
    captured_urls: list[str] | None = None,
):
    """Install a fake httpx_sse module that captures params and yields events."""

    @asynccontextmanager
    async def fake_aconnect_sse(http_client, method, url, *, params=None, **kwargs):
        captured_params.append(params or {})
        if captured_urls is not None:
            captured_urls.append(url)
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
        captured_urls: list[str] = []
        _install_fake_httpx_sse([event], captured, captured_urls)

        async for _bundle in source.watch():
            await source.close()

        assert len(captured) == 1
        assert captured_urls == ["/v1/stream"]
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
    async def test_watch_skips_non_dict_json_payload(self, caplog):
        """Non-dict JSON payloads are logged and skipped, not yielded."""
        client = _make_client()
        source = ServerContractSource(client)

        # Server sends a JSON array instead of an object
        bad_event = MagicMock()
        bad_event.event = "contract_update"
        bad_event.data = json.dumps([1, 2, 3])

        good_event = _make_sse_event({"yaml": "v1", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([bad_event, good_event], captured)

        received = []
        with caplog.at_level(logging.WARNING, logger="edictum.server.rule_source"):
            async for bundle in source.watch():
                received.append(bundle)
                await source.close()

        # Only the valid dict bundle was yielded
        assert len(received) == 1
        assert received[0]["yaml"] == "v1"
        assert any("not an object" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_watch_does_not_store_public_key_from_stream(self):
        """Public keys must NOT come from the same SSE channel as rule data."""
        client = _make_client()
        source = ServerContractSource(client)

        event = _make_sse_event(
            {
                "yaml": "test",
                "revision_hash": "abc",
                "public_key": "attacker-injected-key",
            }
        )
        captured: list[dict] = []
        _install_fake_httpx_sse([event], captured)

        async for bundle in source.watch():
            # Bundle is yielded as-is — caller can inspect but source doesn't trust it
            assert "public_key" in bundle
            assert not hasattr(source, "_last_public_key")
            await source.close()

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_watch_programming_error_propagates(self):
        """Programming errors (TypeError etc.) must NOT be swallowed as reconnects."""
        client = _make_client()
        source = ServerContractSource(client)

        @asynccontextmanager
        async def buggy_sse(http_client, method, url, *, params=None, **kwargs):
            source_mock = MagicMock()

            async def aiter():
                raise TypeError("unexpected type in event processing")
                yield  # noqa: RET503

            source_mock.aiter_sse = aiter
            yield source_mock

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = buggy_sse  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        with pytest.raises(TypeError, match="unexpected type"):
            async for _bundle in source.watch():
                pass

    @pytest.mark.asyncio
    async def test_watch_backoff_escalates_on_short_lived_connections(self):
        """Backoff escalates when connections drop before the stable threshold."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0, max_reconnect_delay=60.0)

        call_count = 0
        sleep_delays: list[float] = []

        @asynccontextmanager
        async def failing_sse(http_client, method, url, *, params=None, **kwargs):
            nonlocal call_count
            call_count += 1
            # Simulate connection established then immediate drop
            source_mock = MagicMock()

            async def aiter():
                raise ConnectionError("proxy dropped connection")
                yield  # noqa: RET503 — make this an async generator

            source_mock.aiter_sse = aiter
            yield source_mock

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = failing_sse  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        async def capture_sleep(delay):
            sleep_delays.append(delay)
            if len(sleep_delays) >= 3:
                await source.close()

        with patch("asyncio.sleep", side_effect=capture_sleep):
            with patch("time.monotonic", side_effect=[0.0, 5.0, 5.0, 10.0, 10.0, 15.0]):
                async for _bundle in source.watch():
                    pass

        assert sleep_delays == [1.0, 2.0, 4.0]

    @pytest.mark.asyncio
    async def test_watch_backoff_resets_after_stable_connection(self):
        """Backoff resets to initial delay after a connection survives past the stable threshold."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0, max_reconnect_delay=60.0)

        sleep_delays: list[float] = []

        @asynccontextmanager
        async def sse_with_stable_then_drop(http_client, method, url, *, params=None, **kwargs):
            source_mock = MagicMock()

            async def aiter():
                raise ConnectionError("dropped")
                yield  # noqa: RET503

            source_mock.aiter_sse = aiter
            yield source_mock

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = sse_with_stable_then_drop  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        # Sequence: connect at t=0, fail at t=0+stable+1 (stable), then connect at t2, fail at t2+1 (short)
        monotonic_values = [
            0.0,
            _STABLE_CONNECTION_SECS + 1,  # attempt 1: connected_at=0, elapsed=31 → stable → reset
            _STABLE_CONNECTION_SECS + 2,
            _STABLE_CONNECTION_SECS + 3,  # attempt 2: short → escalate
        ]

        async def capture_sleep(delay):
            sleep_delays.append(delay)
            if len(sleep_delays) >= 2:
                await source.close()

        with patch("asyncio.sleep", side_effect=capture_sleep):
            with patch("time.monotonic", side_effect=monotonic_values):
                async for _bundle in source.watch():
                    pass

        # First failure after stable connection: delay resets to 1.0
        # Second failure after short connection: delay escalates to 2.0
        assert sleep_delays == [1.0, 2.0]

    @pytest.mark.asyncio
    async def test_watch_logs_exception_on_first_failure(self, caplog):
        """First reconnect logs at WARNING level and includes the exception."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0)

        @asynccontextmanager
        async def failing_sse(http_client, method, url, *, params=None, **kwargs):
            raise ConnectionError("server unreachable")
            yield  # noqa: RET503

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = failing_sse  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        async def stop_after_one(delay):
            await source.close()

        with patch("asyncio.sleep", side_effect=stop_after_one):
            with caplog.at_level(logging.DEBUG, logger="edictum.server.rule_source"):
                async for _bundle in source.watch():
                    pass

        warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warning_records) == 1
        assert "server unreachable" in warning_records[0].message
        assert "reconnecting in" in warning_records[0].message

    @pytest.mark.asyncio
    async def test_watch_demotes_log_level_after_repeated_failures(self, caplog):
        """Log level: attempt 1=WARNING, 2-3=INFO, 4+=DEBUG."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0)

        @asynccontextmanager
        async def failing_sse(http_client, method, url, *, params=None, **kwargs):
            raise ConnectionError("timeout")
            yield  # noqa: RET503

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = failing_sse  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        call_count = 0

        async def capture_sleep(delay):
            nonlocal call_count
            call_count += 1
            if call_count >= 5:
                await source.close()

        with patch("asyncio.sleep", side_effect=capture_sleep):
            with caplog.at_level(logging.DEBUG, logger="edictum.server.rule_source"):
                async for _bundle in source.watch():
                    pass

        sse_records = [r for r in caplog.records if "SSE" in r.message and "reconnect" in r.message.lower()]
        assert len(sse_records) == 5
        assert sse_records[0].levelno == logging.WARNING  # attempt 1
        assert sse_records[1].levelno == logging.INFO  # attempt 2
        assert sse_records[2].levelno == logging.INFO  # attempt 3
        assert sse_records[3].levelno == logging.DEBUG  # attempt 4
        assert sse_records[4].levelno == logging.DEBUG  # attempt 5

    @pytest.mark.asyncio
    async def test_watch_stale_connected_at_after_clean_stream_exit(self):
        """After a clean stream close, connected_at must not leak into the next failure."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0, max_reconnect_delay=60.0)

        attempt = 0
        sleep_delays: list[float] = []

        @asynccontextmanager
        async def sse_then_fail(http_client, method, url, *, params=None, **kwargs):
            nonlocal attempt
            attempt += 1
            source_mock = MagicMock()

            if attempt == 1:
                # First: long-lived stream that ends cleanly (no events, iterator exhausts)
                async def aiter_clean():
                    return
                    yield  # noqa: RET503

                source_mock.aiter_sse = aiter_clean
                yield source_mock
            else:
                # Second+: connection established then immediate error
                async def aiter_fail():
                    raise ConnectionError("refused")
                    yield  # noqa: RET503

                source_mock.aiter_sse = aiter_fail
                yield source_mock

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = sse_then_fail  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        # attempt 1: connect at t=0, clean exit at t=50 (>30s stable)
        # attempt 2: connect at t=51, fail at t=52 (short)
        # Without the fix, connected_at from attempt 1 (t=0) would leak,
        # and elapsed would be t=52 - t=0 = 52s → incorrectly reset backoff.
        # With the fix, connected_at is None after clean exit, so attempt 2
        # sets connected_at=t=51, elapsed=t=52-t=51=1s → backoff escalates.
        monotonic_values = [
            0.0,  # attempt 1 connected_at
            # clean exit, no monotonic call in except (connected_at is None)
            51.0,  # attempt 2 connected_at
            52.0,  # attempt 2 elapsed check
        ]

        async def capture_sleep(delay):
            sleep_delays.append(delay)
            await source.close()

        with patch("asyncio.sleep", side_effect=capture_sleep):
            with patch("time.monotonic", side_effect=monotonic_values):
                async for _bundle in source.watch():
                    pass

        # Backoff should NOT have reset — short-lived connection
        assert sleep_delays == [1.0]

    @pytest.mark.asyncio
    async def test_watch_connected_flag_false_during_backoff(self):
        """_connected must be False while waiting to reconnect."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0)

        connected_during_sleep: list[bool] = []

        @asynccontextmanager
        async def failing_sse(http_client, method, url, *, params=None, **kwargs):
            source_mock = MagicMock()

            async def aiter():
                raise ConnectionError("dropped")
                yield  # noqa: RET503

            source_mock.aiter_sse = aiter
            yield source_mock

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = failing_sse  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        async def check_connected(delay):
            connected_during_sleep.append(source._connected)
            await source.close()

        with patch("asyncio.sleep", side_effect=check_connected):
            with patch("time.monotonic", side_effect=[0.0, 1.0]):
                async for _bundle in source.watch():
                    pass

        assert connected_during_sleep == [False]

    @pytest.mark.asyncio
    async def test_watch_connected_flag_false_after_clean_exit(self):
        """_connected must be False between a clean stream exit and the next connection."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0)

        attempt = 0
        connected_between_iterations: list[bool] = []

        @asynccontextmanager
        async def sse_clean_then_check(http_client, method, url, *, params=None, **kwargs):
            nonlocal attempt
            attempt += 1

            if attempt == 2:
                # On the second connect, capture _connected before it's set True
                connected_between_iterations.append(source._connected)
                await source.close()

            source_mock = MagicMock()

            async def aiter():
                return
                yield  # noqa: RET503

            source_mock.aiter_sse = aiter
            yield source_mock

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = sse_clean_then_check  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        async for _bundle in source.watch():
            pass

        assert connected_between_iterations == [False]

    @pytest.mark.asyncio
    async def test_watch_clean_exit_resets_backoff_after_prior_failures(self, caplog):
        """Prior failures → clean stream exit → next failure starts fresh (delay=1.0, WARNING)."""
        client = _make_client()
        source = ServerContractSource(client, reconnect_delay=1.0, max_reconnect_delay=60.0)

        attempt = 0
        sleep_delays: list[float] = []

        @asynccontextmanager
        async def mixed_sse(http_client, method, url, *, params=None, **kwargs):
            nonlocal attempt
            attempt += 1
            source_mock = MagicMock()

            if attempt <= 2:
                # Attempts 1-2: connection established then immediate failure
                async def aiter_fail():
                    raise ConnectionError("refused")
                    yield  # noqa: RET503

                source_mock.aiter_sse = aiter_fail
                yield source_mock
            elif attempt == 3:
                # Attempt 3: clean stream that ends normally
                async def aiter_clean():
                    return
                    yield  # noqa: RET503

                source_mock.aiter_sse = aiter_clean
                yield source_mock
            else:
                # Attempt 4: another failure — should be treated as fresh
                async def aiter_fail_again():
                    raise ConnectionError("refused again")
                    yield  # noqa: RET503

                source_mock.aiter_sse = aiter_fail_again
                yield source_mock

        mod = ModuleType("httpx_sse")
        mod.aconnect_sse = mixed_sse  # type: ignore[attr-defined]
        sys.modules["httpx_sse"] = mod

        # attempts 1,2: short connections (connected_at set, fail immediately)
        # attempt 3: clean exit (no monotonic calls in except)
        # attempt 4: short connection, fail
        monotonic_values = [
            0.0,
            1.0,  # attempt 1: connected_at=0, elapsed=1 (short)
            2.0,
            3.0,  # attempt 2: connected_at=2, elapsed=1 (short)
            # attempt 3: clean exit — connected_at set then else resets it
            4.0,
            5.0,
            6.0,  # attempt 4: connected_at=5, elapsed=1 (short)
        ]

        async def capture_sleep(delay):
            sleep_delays.append(delay)
            if len(sleep_delays) >= 3:
                await source.close()

        with patch("asyncio.sleep", side_effect=capture_sleep):
            with patch("time.monotonic", side_effect=monotonic_values):
                with caplog.at_level(logging.DEBUG, logger="edictum.server.rule_source"):
                    async for _bundle in source.watch():
                        pass

        # Attempts 1-2 escalate: 1.0, 2.0
        # Attempt 3 clean exit resets everything
        # Attempt 4 starts fresh: 1.0
        assert sleep_delays == [1.0, 2.0, 1.0]

        # Attempt 4 should log at WARNING (fresh sequence), not INFO/DEBUG
        sse_records = [r for r in caplog.records if "SSE" in r.message and "reconnect" in r.message.lower()]
        assert sse_records[-1].levelno == logging.WARNING

    @pytest.mark.asyncio
    async def test_watch_sends_tags_in_sse_params(self):
        """SSE connection includes JSON-encoded tags query param."""
        client = _make_client(env="production", bundle_name="default")
        client.tags = {"role": "finance", "team": "accounting"}
        source = ServerContractSource(client)

        event = _make_sse_event({"yaml": "test", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([event], captured)

        async for _bundle in source.watch():
            await source.close()

        assert len(captured) == 1
        assert "tags" in captured[0]
        assert json.loads(captured[0]["tags"]) == {"role": "finance", "team": "accounting"}

    @pytest.mark.asyncio
    async def test_watch_no_tags_when_none(self):
        """SSE connection omits tags param when tags is None."""
        client = _make_client(env="production", bundle_name="default")
        client.tags = None
        source = ServerContractSource(client)

        event = _make_sse_event({"yaml": "test", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([event], captured)

        async for _bundle in source.watch():
            await source.close()

        assert len(captured) == 1
        assert "tags" not in captured[0]

    @pytest.mark.asyncio
    async def test_watch_handles_assignment_changed_event(self):
        """assignment_changed event yields dict with _assignment_changed flag."""
        client = _make_client(env="production", bundle_name="old-bundle")
        source = ServerContractSource(client)

        event = _make_sse_event({"bundle_name": "new-bundle"}, event_type="assignment_changed")
        captured: list[dict] = []
        _install_fake_httpx_sse([event], captured)

        received = []
        async for bundle in source.watch():
            received.append(bundle)
            await source.close()

        assert len(received) == 1
        assert received[0].get("_assignment_changed") is True
        assert received[0]["bundle_name"] == "new-bundle"
        # bundle_name is NOT updated here — the watcher commits it after
        # successful reload to avoid deduplication blocking retries.
        assert client.bundle_name == "old-bundle"

    @pytest.mark.asyncio
    async def test_watch_ignores_assignment_changed_same_bundle(self):
        """assignment_changed with same bundle_name is ignored."""
        client = _make_client(env="production", bundle_name="same-bundle")
        source = ServerContractSource(client)

        same_event = _make_sse_event({"bundle_name": "same-bundle"}, event_type="assignment_changed")
        normal_event = _make_sse_event({"yaml": "v1", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([same_event, normal_event], captured)

        received = []
        async for bundle in source.watch():
            received.append(bundle)
            await source.close()

        # Only the normal contract_update event should be yielded
        assert len(received) == 1
        assert received[0]["yaml"] == "v1"

    @pytest.mark.asyncio
    async def test_watch_no_bundle_name_omits_param(self):
        """When bundle_name is None, it is not included in SSE params."""
        client = _make_client(env="production", bundle_name="default")
        client.bundle_name = None  # Override for server-assigned mode
        source = ServerContractSource(client)

        event = _make_sse_event({"yaml": "test", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([event], captured)

        async for _bundle in source.watch():
            await source.close()

        assert len(captured) == 1
        assert "bundle_name" not in captured[0]

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_watch_rejects_assignment_changed_path_traversal(self):
        """assignment_changed with path traversal bundle_name is rejected."""
        client = _make_client(env="production", bundle_name="old-bundle")
        source = ServerContractSource(client)

        event = _make_sse_event({"bundle_name": "../../admin/secrets"}, event_type="assignment_changed")
        normal_event = _make_sse_event({"yaml": "v1", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([event, normal_event], captured)

        received = []
        async for bundle in source.watch():
            received.append(bundle)
            await source.close()

        # Path traversal should be rejected; only the normal event yielded
        assert len(received) == 1
        assert received[0]["yaml"] == "v1"
        # Client's bundle_name should NOT have been updated
        assert client.bundle_name == "old-bundle"

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_watch_rejects_assignment_changed_non_dict(self):
        """assignment_changed with non-dict payload is ignored."""
        client = _make_client(env="production", bundle_name="old-bundle")
        source = ServerContractSource(client)

        bad_event = MagicMock()
        bad_event.event = "assignment_changed"
        bad_event.data = json.dumps([1, 2, 3])

        normal_event = _make_sse_event({"yaml": "v1", "revision_hash": "abc"})
        captured: list[dict] = []
        _install_fake_httpx_sse([bad_event, normal_event], captured)

        received = []
        async for bundle in source.watch():
            received.append(bundle)
            await source.close()

        assert len(received) == 1
        assert received[0]["yaml"] == "v1"
