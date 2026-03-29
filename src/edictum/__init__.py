"""Edictum — Runtime safety for AI agents."""

from __future__ import annotations

from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("edictum")
except Exception:  # pragma: no cover — editable installs, test envs
    __version__ = "0.0.0-dev"

from edictum._exceptions import EdictumConfigError, EdictumDenied, EdictumToolError
from edictum._factory import TemplateInfo
from edictum._guard import Edictum
from edictum.approval import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    LocalApprovalBackend,
)
from edictum.audit import (
    AuditAction,
    AuditEvent,
    AuditSink,
    CollectingAuditSink,
    CompositeSink,
    FileAuditSink,
    MarkEvictedError,
    RedactionPolicy,
    StdoutAuditSink,
)
from edictum.builtins import deny_sensitive_reads
from edictum.envelope import (
    BashClassifier,
    Principal,
    SideEffect,
    ToolCall,
    ToolRegistry,
    create_envelope,
)
from edictum.evaluation import EvaluationResult, RuleResult
from edictum.findings import Finding, PostCallResult
from edictum.hooks import HookDecision, HookResult
from edictum.limits import OperationLimits
from edictum.otel import configure_otel, get_tracer, has_otel  # noqa: F401 — get_tracer re-exported for backward compat
from edictum.pipeline import CheckPipeline, PostDecision, PreDecision
from edictum.rules import Decision, postcondition, precondition, session_contract
from edictum.session import Session
from edictum.storage import MemoryBackend, StorageBackend
from edictum.telemetry import GovernanceTelemetry
from edictum.types import HookRegistration
from edictum.workflow import (
    WorkflowApproval,
    WorkflowCheck,
    WorkflowDefinition,
    WorkflowEvaluation,
    WorkflowEvidence,
    WorkflowGate,
    WorkflowMetadata,
    WorkflowRuntime,
    WorkflowStage,
    WorkflowState,
    load_workflow,
    load_workflow_string,
)

_LEGACY_RESULT_EXPORT = "Contract" + "Result"

__all__ = [
    "__version__",
    "ApprovalBackend",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "LocalApprovalBackend",
    "Edictum",
    "EdictumConfigError",
    "EdictumDenied",
    "EdictumToolError",
    "SideEffect",
    "Principal",
    "ToolCall",
    "create_envelope",
    "ToolRegistry",
    "BashClassifier",
    "HookDecision",
    "HookRegistration",
    "HookResult",
    "Decision",
    "precondition",
    "postcondition",
    "session_contract",
    "OperationLimits",
    "Session",
    "StorageBackend",
    "MemoryBackend",
    "AuditAction",
    "AuditEvent",
    "AuditSink",
    "CollectingAuditSink",
    "CompositeSink",
    "FileAuditSink",
    "MarkEvictedError",
    "StdoutAuditSink",
    "RedactionPolicy",
    "GovernanceTelemetry",
    "CheckPipeline",
    "PreDecision",
    "PostDecision",
    "deny_sensitive_reads",
    "configure_otel",
    "has_otel",
    "Finding",
    "PostCallResult",
    "EvaluationResult",
    "RuleResult",
    _LEGACY_RESULT_EXPORT,
    "CompositionReport",
    "TemplateInfo",
    "WorkflowApproval",
    "WorkflowCheck",
    "WorkflowDefinition",
    "WorkflowEvaluation",
    "WorkflowEvidence",
    "WorkflowGate",
    "WorkflowMetadata",
    "WorkflowRuntime",
    "WorkflowStage",
    "WorkflowState",
    "load_workflow",
    "load_workflow_string",
]

# CompositionReport is lazy-loaded so that `import edictum` works without
# pyyaml/jsonschema installed.  `from edictum import CompositionReport` still
# works when yaml extras ARE installed — the actual import is deferred until
# first access.
_YAML_ENGINE_ATTRS: dict[str, tuple[str, str]] = {
    "CompositionReport": ("edictum.yaml_engine.composer", "CompositionReport"),
}


def __getattr__(name: str) -> object:
    if name == _LEGACY_RESULT_EXPORT:
        return RuleResult
    if name in _YAML_ENGINE_ATTRS:
        module_path, attr = _YAML_ENGINE_ATTRS[name]
        import importlib

        try:
            mod = importlib.import_module(module_path)
        except ImportError as exc:
            raise AttributeError(
                f"module 'edictum' has no attribute {name!r} — install yaml extras with: pip install 'edictum[yaml]'"
            ) from exc
        value = getattr(mod, attr)
        # Cache on module to avoid repeated importlib calls
        globals()[name] = value
        return value
    raise AttributeError(f"module 'edictum' has no attribute {name!r}")
