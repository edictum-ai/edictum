"""Trusted exec(...) workflow evaluator."""

from __future__ import annotations

import asyncio
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from edictum.workflow.evaluator import EvaluateRequest, FactResult

MAX_EXEC_EVIDENCE_OUTPUT = 4096


class ExecEvaluator:
    """Run trusted exec(...) workflow gate conditions."""

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
        stdout, _ = await proc.communicate()
        output = (stdout or b"").decode("utf-8", errors="replace")
        exit_code = proc.returncode
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
