"""Behavior tests for workflow runtime auto-advancement."""

from __future__ import annotations

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend
from tests.workflow.conftest import make_envelope, make_runtime


@pytest.mark.asyncio
@pytest.mark.security
async def test_current_stage_check_failure_blocks_before_no_exit_auto_advance():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-no-exit-check-barrier
stages:
  - id: implement
    tools: [Bash]
    checks:
      - command_not_matches: "^git push"
        message: Push is blocked during implement
  - id: push
    entry:
      - condition: stage_complete("implement")
    tools: [Bash]
"""
    )
    session = Session("behavior-no-exit-check-barrier", MemoryBackend())

    decision = await runtime.evaluate(
        session,
        make_envelope("Bash", {"command": "git push origin feature"}),
    )
    state = await runtime.state(session)

    assert decision.action == "block"
    assert decision.stage_id == "implement"
    assert decision.reason == "Push is blocked during implement"
    assert state.active_stage == "implement"
    assert state.completed_stages == []
