"""Tests for gate audit buffer (WAL write, read, rotate)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

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
        "timestamp": "2026-03-01T00:00:00+00:00",
        "agent_id": "test-agent",
        "tool_name": "Bash",
        "tool_args": {"command": "ls"},
        "side_effect": "shell",
        "action": "call_allowed",
        "decision_source": None,
        "decision_name": None,
        "reason": None,
        "contracts_evaluated": [],
        "mode": "enforce",
        "duration_ms": 2,
        "assistant": "ClaudeCodeFormat",
        "user": "testuser",
        "cwd": "/project",
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
        buffer.write(_make_event(action="call_allowed"))
        buffer.write(_make_event(action="call_denied"))
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
        buffer.write(_make_event(tool_name="Read", action="call_denied"))
        wal = Path(config.buffer_path)
        event = json.loads(wal.read_text().strip())
        assert event["tool_name"] == "Read"
        assert event["action"] == "call_denied"

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
        buffer.write(_make_event(action="call_allowed"))
        buffer.write(_make_event(action="call_denied"))
        buffer.write(_make_event(action="call_allowed"))
        events = buffer.read_recent(decision="block")
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
            decision="allow",
            mode="enforce",
            rule_id=None,
            decision_source=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            assistant="ClaudeCodeFormat",
        )
        assert event.tool_name == "Bash"
        assert event.action == "call_allowed"
        assert event.side_effect == "shell"
        assert event.call_id  # UUID generated
        assert event.user  # OS user resolved
        assert event.mode == "enforce"

    def test_tool_args_preserved(self) -> None:
        long_args = {"command": "x" * 500}
        event = build_audit_event(
            tool_name="Bash",
            tool_input=long_args,
            category="shell",
            decision="allow",
            mode="enforce",
            rule_id=None,
            decision_source=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            assistant="ClaudeCodeFormat",
        )
        assert isinstance(event.tool_args, dict)
        assert "command" in event.tool_args


class TestConsoleEventMapping:
    """Verify _to_console_event maps WAL fields to the current server schema."""

    def test_allow_maps_to_call_allowed(self) -> None:
        raw = {"action": "call_allowed", "mode": "enforce", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["action"] == "call_allowed"

    def test_deny_enforce_maps_to_call_denied(self) -> None:
        raw = {"action": "call_denied", "mode": "enforce", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["action"] == "call_blocked"

    def test_deny_observe_maps_to_call_would_deny(self) -> None:
        raw = {"action": "call_would_deny", "mode": "observe", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["action"] == "call_would_block"

    def test_decision_fields_flattened(self) -> None:
        raw = {
            "action": "call_denied",
            "mode": "enforce",
            "tool_name": "Read",
            "decision_name": "block-secret-file-reads",
            "decision_source": "yaml_precondition",
            "reason": "Denied: secrets",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["decision_name"] == "block-secret-file-reads"
        assert result["decision_source"] == "yaml_precondition"
        assert result["reason"] == "Denied: secrets"

    def test_scope_enforcement_decision_source(self) -> None:
        raw = {
            "action": "call_denied",
            "mode": "enforce",
            "tool_name": "Write",
            "decision_name": "gate-scope-enforcement",
            "decision_source": "gate_scope",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["decision_source"] == "gate_scope"

    def test_tool_args_flattened(self) -> None:
        raw = {
            "action": "call_allowed",
            "mode": "enforce",
            "tool_name": "Bash",
            "tool_args": {"command": "ls -la"},
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["tool_args"] == {"command": "ls -la"}

    def test_backward_compat_args_preview_parsed(self) -> None:
        """Old WAL events with args_preview are still handled."""
        raw = {
            "action": "call_allowed",
            "mode": "enforce",
            "tool_name": "Bash",
            "args_preview": '{"command": "ls -la"}',
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["tool_args"] == {"command": "ls -la"}

    def test_backward_compat_truncated_args_preview_wrapped(self) -> None:
        """Old WAL events with truncated args_preview are wrapped."""
        raw = {
            "action": "call_allowed",
            "mode": "enforce",
            "tool_name": "Bash",
            "args_preview": '{"command": "very long...',  # invalid JSON (truncated)
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["tool_args"]["_preview"] == '{"command": "very long...'

    def test_empty_agent_id_falls_back_to_user(self) -> None:
        raw = {
            "action": "call_allowed",
            "mode": "enforce",
            "tool_name": "Bash",
            "agent_id": "",
            "user": "acartagena",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["agent_id"] == "acartagena"

    def test_agent_id_preserved_when_set(self) -> None:
        raw = {
            "action": "call_allowed",
            "mode": "enforce",
            "tool_name": "Bash",
            "agent_id": "my-agent-1",
            "user": "acartagena",
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["agent_id"] == "my-agent-1"

    def test_mode_passed_through(self) -> None:
        raw = {"action": "call_allowed", "mode": "observe", "tool_name": "Bash"}
        result = AuditBuffer._to_console_event(raw)
        assert result["mode"] == "observe"

    def test_contracts_evaluated_upconverts_to_rules_evaluated(self) -> None:
        raw = {
            "action": "call_allowed",
            "mode": "enforce",
            "tool_name": "Bash",
            "contracts_evaluated": [{"name": "rule-1"}],
        }
        result = AuditBuffer._to_console_event(raw)
        assert result["rules_evaluated"] == [{"name": "rule-1"}]
        assert "payload" not in result
        assert "decision" not in result


class TestConsoleFlush:
    def test_flush_posts_current_endpoint_and_wire_payload(self, tmp_path: Path) -> None:
        config = _make_audit_config(tmp_path)
        buffer = AuditBuffer(config)
        buffer.write(
            _make_event(
                action="call_denied",
                decision_name="gate-scope-enforcement",
                decision_source="gate_scope",
                reason="blocked",
                contracts_evaluated=[{"name": "rule-1"}],
            )
        )
        console_config = MagicMock(url="https://console.example.com", api_key="secret", agent_id="gate-agent")

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_client.post.return_value = mock_response

        with patch("httpx.Client", return_value=mock_client):
            flushed = buffer.flush_to_console(console_config)

        assert flushed == 1
        mock_client.post.assert_called_once()
        path = mock_client.post.call_args.args[0]
        payload = mock_client.post.call_args.kwargs["json"]
        assert path == "/v1/events"
        assert payload["events"][0]["action"] == "call_blocked"
        assert payload["events"][0]["decision_name"] == "gate-scope-enforcement"
        assert payload["events"][0]["decision_source"] == "gate_scope"
        assert payload["events"][0]["rules_evaluated"] == [{"name": "rule-1"}]
        assert "payload" not in payload["events"][0]
        assert "decision" not in payload["events"][0]
        mock_response.raise_for_status.assert_called_once_with()
        mock_client.close.assert_called_once_with()
