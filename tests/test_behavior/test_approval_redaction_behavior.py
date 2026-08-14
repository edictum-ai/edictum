"""Behavior tests for LocalApprovalBackend redaction.

Proves that tool_args are redacted before printing to stdout.
"""

from __future__ import annotations

import pytest

from edictum.approval import LocalApprovalBackend


class TestLocalApprovalRedaction:
    """LocalApprovalBackend must redact sensitive args in stdout output."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sensitive_args_redacted_in_stdout(self, capsys):
        """tool_args containing api_key must be redacted in stdout."""
        backend = LocalApprovalBackend()
        await backend.request_approval(
            "dangerous_tool",
            {"api_key": "sk-secret123", "query": "SELECT 1"},
            "Approve this?",
        )
        captured = capsys.readouterr()
        assert "sk-secret123" not in captured.out
        assert "[REDACTED]" in captured.out
        # Non-sensitive args should still be visible
        assert "SELECT 1" in captured.out

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_password_redacted_in_stdout(self, capsys):
        """tool_args containing password must be redacted."""
        backend = LocalApprovalBackend()
        await backend.request_approval(
            "connect_db",
            {"password": "hunter2", "host": "localhost"},
            "Approve?",
        )
        captured = capsys.readouterr()
        assert "hunter2" not in captured.out
        assert "[REDACTED]" in captured.out
        assert "localhost" in captured.out


class TestApprovalRequestRedaction:
    """Approval requests must receive the same redaction as audit events.

    ServerApprovalBackend posts tool_args to /v1/approvals, which fans out to
    Slack/Telegram/Discord — raw credentials must not reach human channels or
    third-party chat logs.
    """

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_runner_redacts_args_before_approval_request(self):
        from edictum import Edictum

        rules = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: approval-redaction
defaults:
  mode: enforce
rules:
  - id: ask-deploy
    type: pre
    tool: deploy
    when:
      tool.name: {equals: deploy}
    then:
      action: ask
      message: deploy?
"""
        captured = {}

        class Capture(LocalApprovalBackend):
            async def request_approval(self, tool_name, tool_args, message, **kw):
                captured["args"] = dict(tool_args)
                return await super().request_approval(tool_name, tool_args, message, **kw)

        guard = Edictum.from_yaml_string(rules, approval_backend=Capture())
        try:
            await guard.run("deploy", {"api_key": "sk-live-xyz123", "note": "x"}, lambda **kw: "ok")
        except Exception:
            pass
        assert captured["args"].get("api_key") == "[REDACTED]"

    @pytest.mark.security
    def test_camel_case_sensitive_keys_are_redacted(self):
        from edictum.audit import RedactionPolicy

        policy = RedactionPolicy()
        redacted = policy.redact_args(
            {"clientSecret": "hunter2", "accessToken": "tok", "sessionKey": "k", "maxTokens": 100}
        )
        assert redacted["clientSecret"] == "[REDACTED]"
        assert redacted["accessToken"] == "[REDACTED]"
        assert redacted["sessionKey"] == "[REDACTED]"
        assert redacted["maxTokens"] == 100  # safe compound key survives
