from __future__ import annotations

import os
from pathlib import Path

import pytest

from edictum.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus
from edictum.envelope import create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowRuntime, load_workflow_string


def workflow_fixture_path() -> Path:
    env_value = os.environ.get("EDICTUM_SCHEMAS_DIR")
    env_dir = Path(env_value) if env_value is not None else None
    candidates = []
    if env_dir is not None:
        candidates.append(env_dir / "fixtures" / "workflow" / "core.workflow.yaml")
    candidates.extend(
        [
            Path("fixtures/workflow/core.workflow.yaml"),
            Path("/Users/acartagena/project/edictum-schemas/fixtures/workflow/core.workflow.yaml"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("shared workflow fixtures not found")


def make_runtime(content: str, *, exec_evaluator_enabled: bool = False) -> WorkflowRuntime:
    return WorkflowRuntime(
        load_workflow_string(content),
        exec_evaluator_enabled=exec_evaluator_enabled,
    )


def make_envelope(tool: str, args: dict) -> object:
    return create_envelope(tool_name=tool, tool_input=args)


@pytest.fixture
def memory_backend() -> MemoryBackend:
    return MemoryBackend()


class AutoApproveBackend:
    async def request_approval(
        self,
        tool_name: str,
        tool_args: dict,
        message: str,
        *,
        timeout: int = 300,
        timeout_effect: str = "deny",
        principal: dict | None = None,
        metadata: dict | None = None,
    ) -> ApprovalRequest:
        return ApprovalRequest(
            approval_id="auto-approve",
            tool_name=tool_name,
            tool_args=tool_args,
            message=message,
            timeout=timeout,
            timeout_effect=timeout_effect,
            principal=principal,
            metadata=metadata or {},
        )

    async def wait_for_decision(self, approval_id: str, timeout: int | None = None) -> ApprovalDecision:
        return ApprovalDecision(
            approved=True,
            approver="tests",
            status=ApprovalStatus.APPROVED,
        )


class AutoDenyBackend(AutoApproveBackend):
    async def wait_for_decision(self, approval_id: str, timeout: int | None = None) -> ApprovalDecision:
        return ApprovalDecision(
            approved=False,
            approver="tests",
            reason="denied in test",
            status=ApprovalStatus.DENIED,
        )


async def workflow_session(session_id: str, backend: MemoryBackend | None = None) -> Session:
    return Session(session_id, backend or MemoryBackend())
