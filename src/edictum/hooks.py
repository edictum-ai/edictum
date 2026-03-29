"""Hook interception — before/after tool execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class HookResult(Enum):
    ALLOW = "allow"
    DENY = "block"


@dataclass
class HookDecision:
    result: HookResult
    reason: str | None = None

    @classmethod
    def allow(cls) -> HookDecision:
        return cls(result=HookResult.ALLOW)

    @classmethod
    def block(cls, reason: str) -> HookDecision:
        if len(reason) > 500:
            reason = reason[:497] + "..."
        return cls(result=HookResult.DENY, reason=reason)

    deny = block  # deprecated alias; kept for compatibility
