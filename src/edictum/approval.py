"""Approval protocol for human-in-the-loop tool call authorization."""

from __future__ import annotations

import asyncio
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class ApprovalRequest:
    """A request for human approval of a tool call."""

    approval_id: str
    tool_name: str
    tool_args: dict[str, Any]
    message: str
    timeout: int  # seconds
    timeout_action: str = "block"  # block | allow
    principal: dict | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class ApprovalDecision:
    """The result of a human approval decision."""

    approved: bool
    approver: str | None = None
    reason: str | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@runtime_checkable
class ApprovalBackend(Protocol):
    """Protocol for human-in-the-loop approval providers."""

    async def request_approval(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        message: str,
        *,
        timeout: int = 300,
        timeout_action: str = "block",
        principal: dict | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalRequest: ...

    async def wait_for_decision(
        self,
        approval_id: str,
        timeout: int | None = None,
    ) -> ApprovalDecision: ...


class LocalApprovalBackend:
    """CLI-based approval backend for local testing.

    Prompts on stdout, reads from stdin. Blocks until response or timeout.
    """

    def __init__(self) -> None:
        self._pending: dict[str, ApprovalRequest] = {}
        from edictum.audit import RedactionPolicy

        self._redaction = RedactionPolicy()

    async def request_approval(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        message: str,
        *,
        timeout: int = 300,
        timeout_action: str = "block",
        principal: dict | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        approval_id = str(uuid.uuid4())
        request = ApprovalRequest(
            approval_id=approval_id,
            tool_name=tool_name,
            tool_args=tool_args,
            message=message,
            timeout=timeout,
            timeout_action=timeout_action,
            principal=principal,
            metadata=metadata or {},
        )
        self._pending[approval_id] = request
        print(f"[APPROVAL REQUIRED] {message}")
        print(f"  Tool: {tool_name}")
        print(f"  Args: {self._redaction.redact_args(tool_args)}")
        print(f"  ID:   {approval_id}")
        sys.stdout.flush()
        return request

    async def wait_for_decision(
        self,
        approval_id: str,
        timeout: int | None = None,
    ) -> ApprovalDecision:
        request = self._pending.get(approval_id)
        effective_timeout = timeout if timeout is not None else (request.timeout if request else 300)

        loop = asyncio.get_running_loop()

        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(None, self._read_stdin, approval_id),
                timeout=effective_timeout,
            )
        except TimeoutError:
            timeout_action = request.timeout_action if request else "block"
            approved = timeout_action == "allow"
            return ApprovalDecision(
                approved=approved,
                status=ApprovalStatus.TIMEOUT,
            )

        approved = response.strip().lower() in ("y", "yes", "ask")
        status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        return ApprovalDecision(
            approved=approved,
            approver="local",
            status=status,
        )

    def _read_stdin(self, approval_id: str) -> str:
        """Read a single line from stdin (runs in executor)."""
        print(f"Approve? [y/N] (id: {approval_id}): ", end="", flush=True)
        return input()
