"""Pre/Post Conditions — rule decorators for tool governance."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Decision:
    passed: bool
    message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def pass_(cls) -> Decision:
        return cls(passed=True)

    @classmethod
    def fail(cls, message: str, **metadata: Any) -> Decision:
        """Fail with an actionable message (truncated to 500 chars).

        Make it SPECIFIC and INSTRUCTIVE -- the agent uses it to self-correct.
        """
        if len(message) > 500:
            message = message[:497] + "..."
        return cls(passed=False, message=message, metadata=metadata)


def precondition(tool: str, when: Callable | None = None):
    """Before execution. Safe to block -- tool hasn't run yet."""

    def decorator(func: Callable) -> Callable:
        func._edictum_type = "precondition"
        func._edictum_tool = tool
        func._edictum_when = when
        return func

    return decorator


def postcondition(tool: str, when: Callable | None = None):
    """After execution. v0.0.1: observe-and-log ONLY.

    On failure for pure/read: inject context suggesting retry.
    On failure for write/irreversible: warn only, NO retry coaching.
    """

    def decorator(func: Callable) -> Callable:
        func._edictum_type = "postcondition"
        func._edictum_tool = tool
        func._edictum_when = when
        return func

    return decorator


def session_contract(func: Callable) -> Callable:
    """Cross-turn governance using persisted atomic counters.

    The decorated function **must** accept a ``session`` parameter —
    the pipeline calls ``rule(session)`` at evaluation time.

    Session methods are ASYNC. Session rules must be async:

        @session_contract
        async def max_operations(session: Session) -> Decision:
            count = await session.execution_count()
            if count >= 200:
                return Decision.fail("Session limit reached.")
            return Decision.pass_()
    """
    func._edictum_type = "session_contract"
    return func
