"""Shared test fixtures."""

from __future__ import annotations

import pytest

from edictum import Edictum, create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend


class NullAuditSink:
    """Audit sink that discards all events (for tests)."""

    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


class CapturingAuditSink:
    """Test fixture that records all emitted audit events.

    Use to assert not just enforcement outcomes (allow/deny)
    but audit fidelity (correct AuditAction emitted).
    """

    def __init__(self):
        self.events: list = []

    async def emit(self, event) -> None:
        self.events.append(event)

    @property
    def actions(self) -> list:
        return [e.action for e in self.events]

    def get_by_action(self, action) -> list:
        return [e for e in self.events if e.action == action]

    def assert_action_emitted(self, action, *, times: int = 1):
        actual = len(self.get_by_action(action))
        assert actual == times, (
            f"Expected {action.value} emitted {times} time(s), "
            f"got {actual}. Actions emitted: {[a.value for a in self.actions]}"
        )

    def assert_action_not_emitted(self, action):
        matches = self.get_by_action(action)
        assert not matches, f"Expected {action.value} NOT emitted, " f"but found {len(matches)} event(s)"

    def reset(self):
        self.events.clear()


@pytest.fixture
def capturing_sink():
    return CapturingAuditSink()


@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def session(backend):
    return Session("test-session", backend)


@pytest.fixture
def null_sink():
    return NullAuditSink()


@pytest.fixture
def guard(null_sink, backend):
    return Edictum(
        environment="test",
        audit_sink=null_sink,
        backend=backend,
    )


@pytest.fixture
def envelope():
    return create_envelope("TestTool", {"key": "value"})


@pytest.fixture
def bash_envelope():
    return create_envelope("Bash", {"command": "ls -la"})


@pytest.fixture
def read_envelope():
    return create_envelope("Read", {"file_path": "/tmp/test.txt"})
