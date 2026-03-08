"""Tests for gate audit buffer (WAL write, read, rotate)."""

from __future__ import annotations

import json
from pathlib import Path

from edictum.gate.audit_buffer import AuditBuffer, GateAuditEvent, build_audit_event
from edictum.gate.config import AuditConfig


def _make_audit_config(tmp_path: Path) -> AuditConfig:
    wal = tmp_path / "audit" / "wal.jsonl"
    return AuditConfig(
        enabled=True,
        buffer_path=str(wal),
        max_buffer_size_mb=50,
    )


def _make_event(**kwargs) -> GateAuditEvent:
    defaults = {
        "call_id": "test-call-id",
        "agent_id": "test-agent",
        "user": "testuser",
        "assistant": "ClaudeCodeFormat",
        "tool_name": "Bash",
        "tool_category": "shell",
        "args_preview": '{"command": "ls"}',
        "verdict": "allow",
        "mode": "enforce",
        "contract_id": None,
        "reason": None,
        "cwd": "/project",
        "timestamp": "2026-03-01T00:00:00+00:00",
        "duration_ms": 2,
        "contracts_evaluated": 5,
    }
    defaults.update(kwargs)
    return GateAuditEvent(**defaults)


class TestAuditBufferWrite:
    def test_write_creates_wal(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        wal = Path(config.buffer_path)
        assert wal.exists()
        lines = wal.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_write_appends(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(verdict="allow"))
        buffer.write(_make_event(verdict="deny"))
        wal = Path(config.buffer_path)
        lines = wal.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_write_valid_jsonl(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        wal = Path(config.buffer_path)
        for line in wal.read_text().strip().split("\n"):
            event = json.loads(line)
            assert isinstance(event, dict)

    def test_write_event_fields(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(tool_name="Read", verdict="deny"))
        wal = Path(config.buffer_path)
        event = json.loads(wal.read_text().strip())
        assert event["tool_name"] == "Read"
        assert event["verdict"] == "deny"

    def test_write_survives_missing_directory(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "deep" / "nested" / "wal.jsonl"
        config = AuditConfig(buffer_path=str(deep_path))
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        assert deep_path.exists()


class TestAuditBufferRead:
    def test_read_recent_default(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        for i in range(25):
            buffer.write(_make_event(tool_name=f"Tool{i}"))
        events = buffer.read_recent()
        assert len(events) == 20

    def test_read_recent_with_limit(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        for i in range(10):
            buffer.write(_make_event())
        events = buffer.read_recent(limit=5)
        assert len(events) == 5

    def test_read_recent_filter_tool(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(tool_name="Bash"))
        buffer.write(_make_event(tool_name="Read"))
        buffer.write(_make_event(tool_name="Bash"))
        events = buffer.read_recent(tool="Bash")
        assert len(events) == 2

    def test_read_recent_filter_verdict(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(_make_event(verdict="allow"))
        buffer.write(_make_event(verdict="deny"))
        buffer.write(_make_event(verdict="allow"))
        events = buffer.read_recent(verdict="deny")
        assert len(events) == 1


class TestAuditBufferRotate:
    def test_rotate_when_exceeded(self, tmp_path: Path) -> None:
        wal = tmp_path / "wal.jsonl"
        config = AuditConfig(buffer_path=str(wal), max_buffer_size_mb=0)  # 0 = always rotate
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        buffer.rotate_if_needed()
        backup = wal.with_suffix(".jsonl.1")
        assert backup.exists()

    def test_rotate_keeps_one_backup(self, tmp_path: Path) -> None:
        wal = tmp_path / "wal.jsonl"
        config = AuditConfig(buffer_path=str(wal), max_buffer_size_mb=0)
        buffer = AuditBuffer(config)
        buffer.write(_make_event())
        buffer.rotate_if_needed()
        # Write again and rotate again
        buffer.write(_make_event())
        buffer.rotate_if_needed()
        backup1 = wal.with_suffix(".jsonl.1")
        backup2 = wal.with_suffix(".jsonl.2")
        assert backup1.exists()
        assert not backup2.exists()


class TestBuildAuditEvent:
    def test_basic_event(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"command": "ls"},
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="ClaudeCodeFormat",
        )
        assert event.tool_name == "Bash"
        assert event.verdict == "allow"
        assert event.tool_category == "shell"
        assert event.call_id  # UUID generated
        assert event.user  # OS user resolved
        assert event.mode == "enforce"

    def test_args_preview_truncated(self) -> None:
        long_args = {"command": "x" * 500}
        event = build_audit_event(
            tool_name="Bash",
            tool_input=long_args,
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            contracts_evaluated=5,
            assistant="ClaudeCodeFormat",
        )
        assert len(event.args_preview) <= 200


class TestConsoleEventMapping:
    """Verify _to_console_event maps WAL fields to core AuditEvent conventions."""

    def test_allow_maps_to_call_allowed(self) -> None:
        raw = {"verdict": "allow", "mode": "enforce", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["verdict"] == "call_allowed"

    def test_deny_enforce_maps_to_call_denied(self) -> None:
        raw = {"verdict": "deny", "mode": "enforce", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["verdict"] == "call_denied"

    def test_deny_observe_maps_to_call_would_deny(self) -> None:
        raw = {"verdict": "deny", "mode": "observe", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["verdict"] == "call_would_deny"

    def test_contract_id_maps_to_decision_name(self) -> None:
        raw = {
            "verdict": "deny",
            "mode": "enforce",
            "tool_name": "Read",
            "contract_id": "deny-secret-file-reads",
            "reason": "Denied: secrets",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["payload"]["decision_name"] == "deny-secret-file-reads"
        assert result["payload"]["decision_source"] == "yaml_precondition"
        assert result["payload"]["reason"] == "Denied: secrets"

    def test_scope_enforcement_maps_to_gate_scope(self) -> None:
        raw = {
            "verdict": "deny",
            "mode": "enforce",
            "tool_name": "Write",
            "contract_id": "gate-scope-enforcement",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["payload"]["decision_source"] == "gate_scope"

    def test_args_preview_parsed_to_tool_args(self) -> None:
        raw = {
            "verdict": "allow",
            "mode": "enforce",
            "tool_name": "Bash",
            "args_preview": '{"command": "ls -la"}',
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["payload"]["tool_args"] == {"command": "ls -la"}

    def test_truncated_args_preview_wrapped(self) -> None:
        raw = {
            "verdict": "allow",
            "mode": "enforce",
            "tool_name": "Bash",
            "args_preview": '{"command": "very long...',  # invalid JSON (truncated)
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["payload"]["tool_args"]["_preview"] == '{"command": "very long...'

    def test_empty_agent_id_falls_back_to_user(self) -> None:
        raw = {
            "verdict": "allow",
            "mode": "enforce",
            "tool_name": "Bash",
            "agent_id": "",
            "user": "acartagena",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["agent_id"] == "acartagena"

    def test_agent_id_preserved_when_set(self) -> None:
        raw = {
            "verdict": "allow",
            "mode": "enforce",
            "tool_name": "Bash",
            "agent_id": "my-agent-1",
            "user": "acartagena",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["agent_id"] == "my-agent-1"

    def test_mode_passed_through(self) -> None:
        raw = {"verdict": "allow", "mode": "observe", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["mode"] == "observe"
