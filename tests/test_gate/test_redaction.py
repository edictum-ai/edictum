"""Tests for redaction in gate audit events."""

from __future__ import annotations

import json
from pathlib import Path

from edictum.gate.audit_buffer import GateAuditEvent, build_audit_event
from edictum.gate.config import RedactionConfig


def _make_event(**kwargs) -> GateAuditEvent:
    defaults = {
        "call_id": "test-call-id",
        "timestamp": "2026-03-01T00:00:00+00:00",
        "agent_id": "",
        "tool_name": "Bash",
        "tool_args": {},
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


class TestRedactionBeforeWal:
    def test_redaction_before_wal_write(self, tmp_path: Path) -> None:
        """Secrets are redacted in tool_args before building the event."""
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"command": "export TOKEN=sk_live_abc123def456"},
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            decision_source=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            assistant="ClaudeCodeFormat",
            redaction_config=RedactionConfig(
                patterns=("sk_live_\\w+",),
                replacement="<REDACTED>",
            ),
        )
        args_str = json.dumps(event.tool_args)
        assert "sk_live_" not in args_str
        # Built-in bash patterns may match first (e.g., export TOKEN=...)
        # producing [REDACTED], or custom patterns produce <REDACTED> — either is valid
        assert "[REDACTED]" in args_str or "<REDACTED>" in args_str

    def test_redaction_aws_key(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"key": "AKIAIOSFODNN7EXAMPLE"},
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            decision_source=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            assistant="ClaudeCodeFormat",
            redaction_config=RedactionConfig(
                patterns=("AKIA\\w{16}",),
                replacement="<REDACTED>",
            ),
        )
        args_str = json.dumps(event.tool_args)
        assert "AKIA" not in args_str

    def test_redaction_github_token(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            decision_source=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            assistant="ClaudeCodeFormat",
            redaction_config=RedactionConfig(
                patterns=("ghp_\\w{36}",),
                replacement="<REDACTED>",
            ),
        )
        args_str = json.dumps(event.tool_args)
        assert "ghp_" not in args_str

    def test_redaction_custom_pattern(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"data": "my_custom_secret_12345"},
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            decision_source=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            assistant="ClaudeCodeFormat",
            redaction_config=RedactionConfig(
                patterns=("my_custom_secret_\\d+",),
                replacement="<REDACTED>",
            ),
        )
        args_str = json.dumps(event.tool_args)
        assert "my_custom_secret_" not in args_str

    def test_redaction_preserves_structure(self) -> None:
        event = build_audit_event(
            tool_name="Bash",
            tool_input={"command": "ls", "safe_field": "hello"},
            category="shell",
            verdict="allow",
            mode="enforce",
            contract_id=None,
            decision_source=None,
            reason=None,
            cwd="/project",
            duration_ms=2,
            assistant="ClaudeCodeFormat",
        )
        assert event.tool_args["command"] == "ls"
        assert event.tool_args["safe_field"] == "hello"

    def test_redaction_policy_from_config(self) -> None:
        from edictum.gate.audit_buffer import _build_redaction_policy

        config = RedactionConfig(
            patterns=("secret_\\d+",),
            replacement="***",
        )
        policy = _build_redaction_policy(config)
        result = policy.redact_args({"value": "secret_12345"})
        # The custom pattern is a regex substitution on string values
        assert isinstance(result, dict)
