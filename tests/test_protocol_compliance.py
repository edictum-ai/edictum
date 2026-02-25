"""Protocol compliance tests -- verify implementations match protocol contracts."""

from __future__ import annotations

import asyncio

import pytest


class TestStorageBackendCompliance:
    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_memory_backend_increment_atomic(self):
        from edictum.storage import MemoryBackend

        backend = MemoryBackend()
        n = 200
        await asyncio.gather(*[backend.increment("k") for _ in range(n)])
        result = await backend.get("k")
        assert int(result) == n

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_memory_backend_delete_then_increment(self):
        from edictum.storage import MemoryBackend

        backend = MemoryBackend()
        for _ in range(100):
            await backend.increment("k")
        await backend.delete("k")
        for _ in range(50):
            await backend.increment("k")
        result = await backend.get("k")
        assert int(result) == 50


class TestAuditSinkCompliance:
    @pytest.mark.asyncio
    async def test_stdout_sink_accepts_event(self, capsys):
        from edictum.audit import AuditAction, AuditEvent, StdoutAuditSink

        sink = StdoutAuditSink()
        event = AuditEvent(action=AuditAction.CALL_DENIED, tool_name="test")
        await sink.emit(event)
        captured = capsys.readouterr()
        assert "call_denied" in captured.out

    @pytest.mark.asyncio
    async def test_file_sink_accepts_event(self, tmp_path):
        from edictum.audit import AuditAction, AuditEvent, FileAuditSink

        sink = FileAuditSink(tmp_path / "audit.jsonl")
        event = AuditEvent(action=AuditAction.CALL_ALLOWED, tool_name="test")
        await sink.emit(event)
        content = (tmp_path / "audit.jsonl").read_text()
        assert "call_allowed" in content
