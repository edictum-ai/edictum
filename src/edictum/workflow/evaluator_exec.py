"""Trusted exec(...) workflow evaluator."""

from __future__ import annotations

import asyncio
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from edictum.workflow.evaluator import EvaluateRequest, FactResult

MAX_EXEC_EVIDENCE_OUTPUT = 4096
MAX_EXEC_TIMEOUT_SECONDS = 30.0
MAX_EXEC_REAP_TIMEOUT_SECONDS = 5.0


class ExecEvaluator:
    """Run trusted exec(...) workflow gate conditions.

    Subprocess stdout is copied into workflow evidence and may reach audit sinks.
    Callers should only enable this evaluator for commands whose output is safe to retain.
    """

    async def evaluate(self, req: EvaluateRequest) -> FactResult:
        from edictum.workflow.evaluator import FactResult

        parsed = req.parsed
        argv = shlex.split(parsed.arg)
        if not argv:
            raise ValueError(f'workflow: exec evaluator "{parsed.arg}" resolved to an empty command')

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=MAX_EXEC_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            proc.kill()
            try:
                await asyncio.wait_for(proc.communicate(), timeout=MAX_EXEC_REAP_TIMEOUT_SECONDS)
            except (TimeoutError, OSError):
                pass
            raise ValueError(
                f'workflow: exec evaluator "{parsed.arg}" timed out after {MAX_EXEC_TIMEOUT_SECONDS} seconds'
            ) from exc
        output = (stdout or b"").decode("utf-8", errors="replace")
        exit_code = proc.returncode
        assert exit_code is not None
        return FactResult(
            passed=exit_code == parsed.exit_code,
            evidence=f"exit_code={exit_code} output={_truncate_exec_output(output)}",
            kind="exec",
            condition=parsed.condition,
            message=req.gate.message,
            stage_id=req.stage.id,
            workflow=req.definition.metadata.name,
        )


def _truncate_exec_output(output: str) -> str:
    if len(output) <= MAX_EXEC_EVIDENCE_OUTPUT:
        return output
    return output[:MAX_EXEC_EVIDENCE_OUTPUT] + "...[truncated]"
