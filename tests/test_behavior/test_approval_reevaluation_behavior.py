"""Behavior tests for post-approval re-evaluation of non-workflow ask rules.

An approved ask rule must not waive the checks ordered after it in the
pipeline (sandbox, session rules, workflow gates, limits): after a grant, the
remaining checks are re-run and a block from the re-run is honored. The grant
binds to the exact call (rule id + call id) so the re-run does not re-ask.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum._exceptions import EdictumDenied
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
from edictum.adapters.langchain import LangChainAdapter
from edictum.approval import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
)
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend

_RULES = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: approval-reevaluation
defaults:
  mode: enforce
rules:
  - id: ask-before-bash
    type: pre
    tool: Bash
    when:
      tool.name: {equals: Bash}
    then:
      action: ask
      message: run this bash command?
  - id: path-sandbox
    type: sandbox
    tools: [Bash]
    within:
      - /tmp/safe-zone
    message: path outside sandbox
"""


class AutoApprove(ApprovalBackend):
    def __init__(self):
        self.requests = 0

    async def request_approval(self, tool_name, tool_args, message, **kw):
        self.requests += 1
        return ApprovalRequest(
            approval_id=f"a{self.requests}",
            tool_name=tool_name,
            tool_args=tool_args,
            message=message,
            timeout=30,
        )

    async def wait_for_decision(self, approval_id, timeout=None):
        return ApprovalDecision(approved=True, approver="human", status=ApprovalStatus.APPROVED)


def _guard():
    return Edictum.from_yaml_string(_RULES, backend=MemoryBackend(), approval_backend=AutoApprove())


class TestPostApprovalReevaluation:
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_approval_does_not_waive_sandbox(self):
        guard = _guard()
        with pytest.raises(EdictumDenied, match="path outside sandbox"):
            await guard.run("Bash", {"command": "cat /etc/passwd"}, lambda **kw: "ran")
        executed = [e for e in guard.local_sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert not executed

    @pytest.mark.asyncio
    async def test_approved_call_within_sandbox_executes(self):
        guard = _guard()
        result = await guard.run("Bash", {"command": "cat /tmp/safe-zone/file"}, lambda **kw: "ok")
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_grant_binds_to_the_call_no_reask(self):
        guard = _guard()
        await guard.run("Bash", {"command": "cat /tmp/safe-zone/file"}, lambda **kw: "ok")
        assert guard._approval_backend.requests == 1, "the approved rule must not be re-asked"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_new_call_asks_again(self):
        guard = _guard()
        await guard.run("Bash", {"command": "cat /tmp/safe-zone/a"}, lambda **kw: "ok")
        await guard.run("Bash", {"command": "cat /tmp/safe-zone/b"}, lambda **kw: "ok")
        assert guard._approval_backend.requests == 2, "a new call must ask again"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_langchain_honors_post_approval_block(self):
        guard = _guard()
        adapter = LangChainAdapter(guard, session_id="re-eval-lc")
        req = SimpleNamespace(tool_call={"name": "Bash", "args": {"command": "cat /etc/passwd"}, "id": "d1"})
        result = await adapter._pre_tool_call(req)
        assert result is not None, "sandbox-blocked call must not execute after approval"

    @pytest.mark.asyncio
    async def test_claude_adapter_still_executes_clean_call(self):
        guard = _guard()
        adapter = ClaudeAgentSDKAdapter(guard, session_id="re-eval-cl")
        result = await adapter._pre_tool_use("Bash", {"command": "cat /tmp/safe-zone/f"}, "c1")
        assert result == {}
