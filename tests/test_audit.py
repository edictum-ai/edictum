"""Tests for AuditEvent, RedactionPolicy, and sinks."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from edictum.audit import (
    AuditAction,
    AuditEvent,
    FileAuditSink,
    RedactionPolicy,
    StdoutAuditSink,
)


class TestRedactionPolicy:
    def test_redact_sensitive_keys(self):
        policy = RedactionPolicy()
        args = {"username": "alice", "password": "secret123", "data": "safe"}
        result = policy.redact_args(args)
        assert result["username"] == "alice"
        assert result["password"] == "[REDACTED]"
        assert result["data"] == "safe"

    def test_redact_nested_dicts(self):
        policy = RedactionPolicy()
        args = {"config": {"api_key": "sk-abc123", "url": "https://example.com"}}
        result = policy.redact_args(args)
        assert result["config"]["api_key"] == "[REDACTED]"
        assert result["config"]["url"] == "https://example.com"

    def test_redact_lists(self):
        policy = RedactionPolicy()
        args = {"items": [{"token": "abc"}, {"name": "safe"}]}
        result = policy.redact_args(args)
        assert result["items"][0]["token"] == "[REDACTED]"
        assert result["items"][1]["name"] == "safe"

    def test_key_normalization(self):
        policy = RedactionPolicy()
        args = {"PASSWORD": "secret", "Api_Key": "key123"}
        result = policy.redact_args(args)
        assert result["PASSWORD"] == "[REDACTED]"
        assert result["Api_Key"] == "[REDACTED]"

    def test_partial_key_match(self):
        policy = RedactionPolicy()
        args = {"auth_token": "abc", "my_secret_key": "xyz", "name": "safe"}
        result = policy.redact_args(args)
        assert result["auth_token"] == "[REDACTED]"
        assert result["my_secret_key"] == "[REDACTED]"
        assert result["name"] == "safe"

    def test_secret_value_detection_openai(self):
        policy = RedactionPolicy()
        args = {"value": "sk-abcdefghijklmnopqrstuvwxyz"}
        result = policy.redact_args(args)
        assert result["value"] == "[REDACTED]"

    def test_secret_value_detection_aws(self):
        policy = RedactionPolicy()
        args = {"value": "AKIAIOSFODNN7EXAMPLE"}
        result = policy.redact_args(args)
        assert result["value"] == "[REDACTED]"

    def test_secret_value_detection_jwt(self):
        policy = RedactionPolicy()
        args = {"value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload"}
        result = policy.redact_args(args)
        assert result["value"] == "[REDACTED]"

    def test_secret_value_detection_github(self):
        policy = RedactionPolicy()
        args = {"value": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}
        result = policy.redact_args(args)
        assert result["value"] == "[REDACTED]"

    def test_secret_value_detection_slack(self):
        policy = RedactionPolicy()
        args = {"value": "xoxb-123456789-abcdefghij"}
        result = policy.redact_args(args)
        assert result["value"] == "[REDACTED]"

    def test_no_false_positive_on_normal_values(self):
        policy = RedactionPolicy()
        args = {"value": "hello world", "count": 42}
        result = policy.redact_args(args)
        assert result["value"] == "hello world"
        assert result["count"] == 42

    def test_long_string_truncation(self):
        policy = RedactionPolicy()
        long_str = "x" * 1500
        args = {"data": long_str}
        result = policy.redact_args(args)
        assert len(result["data"]) == 1000
        assert result["data"].endswith("...")

    def test_detect_values_disabled(self):
        policy = RedactionPolicy(detect_secret_values=False)
        args = {"value": "sk-abcdefghijklmnopqrstuvwxyz"}
        result = policy.redact_args(args)
        assert result["value"] == "sk-abcdefghijklmnopqrstuvwxyz"

    def test_redact_bash_command(self):
        policy = RedactionPolicy()
        cmd = "export MY_SECRET_KEY=abc123"
        result = policy.redact_bash_command(cmd)
        assert "[REDACTED]" in result
        assert "abc123" not in result

    def test_redact_bash_password_flag(self):
        policy = RedactionPolicy()
        cmd = "mysql -p mypassword -u root"
        result = policy.redact_bash_command(cmd)
        assert "[REDACTED]" in result

    def test_redact_url_credentials(self):
        policy = RedactionPolicy()
        cmd = "curl https://user:password123@example.com/api"
        result = policy.redact_bash_command(cmd)
        assert "password123" not in result

    def test_redact_result(self):
        policy = RedactionPolicy()
        result = policy.redact_result("short result")
        assert result == "short result"

    def test_redact_result_truncation(self):
        policy = RedactionPolicy()
        long_result = "x" * 600
        result = policy.redact_result(long_result)
        assert len(result) == 500
        assert result.endswith("...")

    def test_cap_payload_under_limit(self):
        policy = RedactionPolicy()
        data = {"tool_args": {"key": "value"}, "tool_name": "test"}
        result = policy.cap_payload(data)
        assert "_truncated" not in result

    def test_cap_payload_over_limit(self):
        policy = RedactionPolicy()
        data = {"tool_args": {"key": "x" * 40000}, "result_summary": "big"}
        result = policy.cap_payload(data)
        assert result["_truncated"] is True
        assert result["tool_args"] == {"_redacted": "payload exceeded 32KB"}
        assert "result_summary" not in result

    def test_custom_sensitive_keys(self):
        policy = RedactionPolicy(sensitive_keys={"my_custom_field"})
        args = {"my_custom_field": "secret", "other": "safe"}
        result = policy.redact_args(args)
        assert result["my_custom_field"] == "[REDACTED]"
        assert result["other"] == "safe"


class TestAuditEvent:
    def test_defaults(self):
        event = AuditEvent()
        assert event.schema_version == "0.3.0"
        assert event.action == AuditAction.CALL_DENIED
        assert event.mode == "enforce"
        assert event.tool_success is None
        assert event.hooks_evaluated == []
        assert event.contracts_evaluated == []
        assert event.session_id is None
        assert event.parent_session_id is None
        assert event.policy_version is None
        assert event.policy_error is False

    def test_custom_fields(self):
        event = AuditEvent(
            action=AuditAction.CALL_EXECUTED,
            tool_name="Bash",
            tool_success=True,
            mode="observe",
            session_id="child-session",
            parent_session_id="parent-session",
        )
        assert event.action == AuditAction.CALL_EXECUTED
        assert event.tool_name == "Bash"
        assert event.tool_success is True
        assert event.mode == "observe"
        assert event.session_id == "child-session"
        assert event.parent_session_id == "parent-session"

    def test_policy_version_field(self):
        event = AuditEvent(
            action=AuditAction.CALL_ALLOWED,
            tool_name="Read",
            policy_version="sha256:abc123def456",
        )
        assert event.policy_version == "sha256:abc123def456"
        assert event.policy_error is False

    def test_policy_error_field(self):
        event = AuditEvent(
            action=AuditAction.CALL_DENIED,
            tool_name="Bash",
            policy_version="sha256:abc123def456",
            policy_error=True,
        )
        assert event.policy_version == "sha256:abc123def456"
        assert event.policy_error is True


class TestAuditAction:
    def test_values(self):
        assert AuditAction.CALL_DENIED.value == "call_denied"
        assert AuditAction.CALL_WOULD_DENY.value == "call_would_deny"
        assert AuditAction.CALL_ALLOWED.value == "call_allowed"
        assert AuditAction.CALL_EXECUTED.value == "call_executed"
        assert AuditAction.CALL_FAILED.value == "call_failed"
        assert AuditAction.WORKFLOW_STATE_UPDATED.value == "workflow_state_updated"
        assert AuditAction.POSTCONDITION_WARNING.value == "postcondition_warning"


class TestStdoutAuditSink:
    async def test_emit_prints_json(self, capsys):
        sink = StdoutAuditSink()
        event = AuditEvent(action=AuditAction.CALL_ALLOWED, tool_name="Test")
        await sink.emit(event)
        output = capsys.readouterr().out
        data = json.loads(output)
        assert data["action"] == "call_allowed"
        assert data["tool_name"] == "Test"

    async def test_emit_includes_policy_version(self, capsys):
        sink = StdoutAuditSink()
        event = AuditEvent(
            action=AuditAction.CALL_ALLOWED,
            tool_name="Read",
            policy_version="sha256:abc123",
            policy_error=False,
        )
        await sink.emit(event)
        data = json.loads(capsys.readouterr().out)
        assert data["policy_version"] == "sha256:abc123"
        assert data["policy_error"] is False

    async def test_emit_includes_policy_error(self, capsys):
        sink = StdoutAuditSink()
        event = AuditEvent(
            action=AuditAction.CALL_DENIED,
            tool_name="Bash",
            policy_version="sha256:abc123",
            policy_error=True,
        )
        await sink.emit(event)
        data = json.loads(capsys.readouterr().out)
        assert data["policy_version"] == "sha256:abc123"
        assert data["policy_error"] is True

    async def test_emit_includes_lineage_fields(self, capsys):
        sink = StdoutAuditSink()
        event = AuditEvent(
            action=AuditAction.CALL_ALLOWED,
            tool_name="Read",
            session_id="child-session",
            parent_session_id="parent-session",
        )
        await sink.emit(event)
        data = json.loads(capsys.readouterr().out)
        assert data["session_id"] == "child-session"
        assert data["parent_session_id"] == "parent-session"


class TestFileAuditSink:
    async def test_emit_writes_jsonl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        sink = FileAuditSink(path)
        event = AuditEvent(action=AuditAction.CALL_EXECUTED, tool_name="Bash")
        await sink.emit(event)

        content = Path(path).read_text()
        data = json.loads(content.strip())
        assert data["action"] == "call_executed"
        assert data["tool_name"] == "Bash"

    async def test_emit_appends(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        sink = FileAuditSink(path)
        await sink.emit(AuditEvent(action=AuditAction.CALL_ALLOWED))
        await sink.emit(AuditEvent(action=AuditAction.CALL_EXECUTED))

        lines = Path(path).read_text().strip().split("\n")
        assert len(lines) == 2

    async def test_emit_includes_policy_fields(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            path = f.name

        sink = FileAuditSink(path)
        event = AuditEvent(
            action=AuditAction.CALL_DENIED,
            tool_name="Bash",
            policy_version="sha256:def789",
            policy_error=True,
        )
        await sink.emit(event)

        data = json.loads(Path(path).read_text().strip())
        assert data["policy_version"] == "sha256:def789"
        assert data["policy_error"] is True

    async def test_emit_includes_lineage_fields(self, tmp_path):
        path = tmp_path / "lineage.jsonl"
        sink = FileAuditSink(path)
        await sink.emit(
            AuditEvent(
                action=AuditAction.CALL_ALLOWED,
                tool_name="Read",
                session_id="child-session",
                parent_session_id="parent-session",
            )
        )

        data = json.loads(path.read_text().strip())
        assert data["session_id"] == "child-session"
        assert data["parent_session_id"] == "parent-session"
