"""Workflow runtime result and state types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkflowEvaluation:
    """Workflow pre-execution decision."""

    action: str = "allow"  # "allow" | "block" | "pending_approval"
    reason: str = ""
    stage_id: str = ""
    records: list[dict[str, Any]] = field(default_factory=list)
    audit: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class WorkflowEvidence:
    """Persisted workflow evidence."""

    reads: list[str] = field(default_factory=list)
    stage_calls: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class WorkflowState:
    """Persisted workflow instance state."""

    session_id: str = ""
    active_stage: str = ""
    completed_stages: list[str] = field(default_factory=list)
    approvals: dict[str, str] = field(default_factory=dict)
    evidence: WorkflowEvidence = field(default_factory=WorkflowEvidence)

    def completed(self, stage_id: str) -> bool:
        return stage_id in self.completed_stages

    def ensure_defaults(self) -> None:
        if self.completed_stages is None:
            self.completed_stages = []
        if self.approvals is None:
            self.approvals = {}
        if self.evidence is None:
            self.evidence = WorkflowEvidence()
        if self.evidence.reads is None:
            self.evidence.reads = []
        if self.evidence.stage_calls is None:
            self.evidence.stage_calls = {}
