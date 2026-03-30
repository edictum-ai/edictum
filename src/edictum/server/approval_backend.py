"""Server-backed approval backend for human-in-the-loop workflows."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from edictum.approval import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
)
from edictum.server.client import EdictumServerClient

logger = logging.getLogger(__name__)

_LEGACY_BLOCKED_STATUS = "denied"
_LEGACY_TIMEOUT_STATUS = "timeout"


class ServerApprovalBackend:
    """Approval backend that delegates to the edictum-server approval queue.

    Creates approval requests via HTTP POST, then polls GET until resolved.
    """

    def __init__(
        self,
        client: EdictumServerClient,
        *,
        poll_interval: float = 2.0,
    ) -> None:
        self._client = client
        self._poll_interval = poll_interval
        self._pending: dict[str, ApprovalRequest] = {}

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
        """Create an approval request on the server."""
        body = {
            "agent_id": self._client.agent_id,
            "tool_name": tool_name,
            "tool_args": tool_args,
            "message": message,
            "timeout": timeout,
            "timeout_action": timeout_action,
        }
        response = await self._client.post("/v1/approvals", body)

        request = ApprovalRequest(
            approval_id=response["id"],
            tool_name=tool_name,
            tool_args=tool_args,
            message=message,
            timeout=timeout,
            timeout_action=timeout_action,
            principal=principal,
            metadata=metadata or {},
        )
        self._pending[response["id"]] = request
        return request

    async def wait_for_decision(
        self,
        approval_id: str,
        timeout: int | None = None,
    ) -> ApprovalDecision:
        """Poll the server until the approval is resolved or timeout is exceeded."""
        request = self._pending.get(approval_id)
        effective_timeout = timeout if timeout is not None else (request.timeout if request else 300)
        timeout_action = request.timeout_action if request else "block"

        deadline = asyncio.get_running_loop().time() + effective_timeout

        while True:
            response = await self._client.get(f"/v1/approvals/{approval_id}")
            status = response["status"]

            if status == "approved":
                return ApprovalDecision(
                    approved=True,
                    approver=response.get("decided_by"),
                    reason=response.get("decision_reason"),
                    status=ApprovalStatus.APPROVED,
                    timestamp=datetime.now(UTC),
                )

            if status in {_LEGACY_BLOCKED_STATUS, "rejected"}:
                return ApprovalDecision(
                    approved=False,
                    approver=response.get("decided_by"),
                    reason=response.get("decision_reason"),
                    status=ApprovalStatus.DENIED,
                    timestamp=datetime.now(UTC),
                )

            if status in {_LEGACY_TIMEOUT_STATUS, "timed_out"}:
                return ApprovalDecision(
                    approved=(timeout_action == "allow"),
                    status=ApprovalStatus.TIMEOUT,
                    timestamp=datetime.now(UTC),
                )

            # Still pending — check local deadline
            if asyncio.get_running_loop().time() >= deadline:
                return ApprovalDecision(
                    approved=(timeout_action == "allow"),
                    status=ApprovalStatus.TIMEOUT,
                    timestamp=datetime.now(UTC),
                )

            await asyncio.sleep(self._poll_interval)
