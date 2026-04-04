"""Behavior tests for AuditEvent lineage fields."""

from __future__ import annotations

import json

import pytest

from edictum import Edictum
from edictum.audit import AuditAction, AuditEvent, StdoutAuditSink
from edictum.storage import MemoryBackend


class TestAuditLineageBehavior:
    """AuditEvent lineage parameters change emitted payloads."""

    async def test_session_id_changes_stdout_payload(self, capsys):
        sink = StdoutAuditSink()

        await sink.emit(
            AuditEvent(
                action=AuditAction.CALL_ALLOWED,
                tool_name="Read",
                session_id="session-123",
            )
        )

        payload = json.loads(capsys.readouterr().out)
        assert payload["session_id"] == "session-123"

    async def test_parent_session_id_changes_stdout_payload(self, capsys):
        sink = StdoutAuditSink()

        await sink.emit(
            AuditEvent(
                action=AuditAction.CALL_ALLOWED,
                tool_name="Read",
                parent_session_id="parent-456",
            )
        )

        payload = json.loads(capsys.readouterr().out)
        assert payload["parent_session_id"] == "parent-456"

    @pytest.mark.asyncio
    async def test_run_emits_audit_events_with_session_id(self):
        guard = Edictum(backend=MemoryBackend())

        await guard.run("Read", {"path": "spec.md"}, lambda path: "ok", session_id="session-789")

        assert len(guard.local_sink.events) >= 2
        assert {event.session_id for event in guard.local_sink.events} == {"session-789"}

    @pytest.mark.asyncio
    async def test_run_emits_audit_events_with_parent_session_id(self):
        guard = Edictum(backend=MemoryBackend())

        await guard.run(
            "Read",
            {"path": "spec.md"},
            lambda path: "ok",
            session_id="session-789",
            metadata={"parent_session_id": "parent-789"},
        )

        assert len(guard.local_sink.events) >= 2
        assert {event.parent_session_id for event in guard.local_sink.events} == {"parent-789"}

    @pytest.mark.asyncio
    async def test_workflow_events_use_run_session_id(self):
        guard = Edictum.from_yaml_string(
            """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: workflow-audit-lineage
defaults:
  mode: enforce
rules:
  - id: noop-read
    type: pre
    tool: Read
    when:
      args.path:
        equals: never
    then:
      action: block
      message: never
""",
            backend=MemoryBackend(),
            workflow_content="""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: workflow-audit-lineage
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: Read spec first
  - id: push
    entry:
      - condition: stage_complete("read-context")
    tools: [Bash]
""",
        )

        await guard.run("Read", {"path": "spec.md"}, lambda path: "ok", session_id="session-999")
        await guard.run(
            "Bash",
            {"command": "git status"},
            lambda command: "ok",
            session_id="session-999",
        )

        workflow_events = [
            event
            for event in guard.local_sink.events
            if event.action in {AuditAction.WORKFLOW_STAGE_ADVANCED, AuditAction.WORKFLOW_COMPLETED}
        ]
        assert len(workflow_events) >= 1
        assert {event.session_id for event in workflow_events} == {"session-999"}
