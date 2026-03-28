"""Structured postcondition violations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from edictum.pipeline import PostDecision


@dataclass(frozen=True)
class Finding:
    """A structured finding from a postcondition evaluation.

    Produced when a postcondition warns or detects an issue.
    Returned to the caller via PostCallResult so they can
    decide how to remediate.

    Examples:
        Finding(
            type="pii_detected",
            rule_id="pii-in-any-output",
            field="output.text",
            message="SSN pattern detected in tool output",
        )
        Finding(
            type="policy_violation",
            rule_id="require-ticket-for-updates",
            field="principal.ticket_ref",
            message="Case report update requires CAPA ticket",
        )
    """

    type: str  # "pii_detected", "secret_detected", "policy_violation", etc.
    rule_id: str  # which rule produced this finding
    field: str  # which field/selector triggered it (e.g., "output.text", "args.content")
    message: str  # human-readable description
    metadata: dict[str, Any] = field(default_factory=dict)  # extra context


@dataclass
class PostCallResult:
    """Result from a governed tool call, including postcondition violations.

    Returned by adapter's _post_tool_call and available via as_tool_wrapper.

    When postconditions_passed is False, the violations list contains
    structured Finding objects describing what was detected. The caller
    can then decide how to remediate (redact, replace, log, etc.).

    Usage:
        # The adapter returns this from _post_tool_call
        post_result = PostCallResult(
            result=tool_output,
            postconditions_passed=False,
            violations=[Finding(type="pii_detected", ...)],
        )

        # The on_postcondition_warn callback can transform the result
        adapter.as_tool_wrapper(
            on_postcondition_warn=lambda result, violations: redact_pii(result, violations)
        )
    """

    result: Any  # the original tool result
    postconditions_passed: bool = True  # did all postconditions pass?
    violations: list[Finding] = field(default_factory=list)
    output_suppressed: bool = False  # True when a postcondition with action=block fired


def classify_finding(rule_id: str, verdict_message: str) -> str:
    """Classify a postcondition finding type from rule ID and message.

    Returns a standard finding type string.
    """
    contract_lower = rule_id.lower()
    message_lower = (verdict_message or "").lower()

    if any(term in contract_lower or term in message_lower for term in ("pii", "ssn", "patient", "name", "dob")):
        return "pii_detected"
    if any(
        term in contract_lower or term in message_lower for term in ("secret", "token", "key", "credential", "password")
    ):
        return "secret_detected"
    if any(term in contract_lower or term in message_lower for term in ("session", "limit", "max_calls", "budget")):
        return "limit_exceeded"

    return "policy_violation"


def build_findings(post_decision: PostDecision) -> list[Finding]:
    """Build Finding objects from a PostDecision's failed postconditions.

    The ``field`` value is extracted from ``metadata["field"]`` if the
    rule provides it (e.g. ``Decision.fail("msg", field="output.text")``),
    otherwise defaults to ``"output"`` for postconditions.
    """
    violations = []
    for cr in post_decision.contracts_evaluated:
        if not cr.get("passed"):
            meta = cr.get("metadata", {})
            violations.append(
                Finding(
                    type=classify_finding(cr["name"], cr.get("message", "")),
                    rule_id=cr["name"],
                    field=meta.get("field", "output"),
                    message=cr.get("message", ""),
                    metadata=meta,
                )
            )
    return violations
