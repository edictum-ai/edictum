"""Conformance runner for v0.18 workflow fixtures from edictum-schemas.

Reads fixture files from edictum-schemas/fixtures/workflow-v0.18/:
  - wildcard-tools.workflow-v0.18.yaml
  - terminal-stage.workflow-v0.18.yaml
  - mcp-result-evidence.workflow-v0.18.yaml
  - extends-inheritance.workflow-v0.18.yaml

Each fixture drives the Python workflow runtime or pipeline and asserts
the expected decision and final evidence state.

Fixture discovery (first match wins):
  1. EDICTUM_SCHEMAS_DIR env var / fixtures/workflow-v0.18/
  2. <repo-root>/edictum-schemas/fixtures/workflow-v0.18/
  3. <repo-root>/../edictum-schemas/fixtures/workflow-v0.18/
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from edictum.envelope import create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowEvidence, WorkflowRuntime, WorkflowState, load_workflow_string
from edictum.workflow.state import save_state
from edictum.yaml_engine.loader import resolve_ruleset_extends

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFORMANCE_REQUIRED = os.environ.get("EDICTUM_CONFORMANCE_REQUIRED") == "1"


def _find_v018_dir() -> Path | None:
    candidates: list[Path] = []

    env = os.environ.get("EDICTUM_SCHEMAS_DIR")
    if env:
        candidates.append(Path(env) / "fixtures" / "workflow-v0.18")

    candidates.append(_REPO_ROOT / "edictum-schemas" / "fixtures" / "workflow-v0.18")
    candidates.append(_REPO_ROOT.parent / "edictum-schemas" / "fixtures" / "workflow-v0.18")

    for c in candidates:
        if c.is_dir():
            return c
    return None


_V018_DIR = _find_v018_dir()

if _CONFORMANCE_REQUIRED and _V018_DIR is None:
    raise FileNotFoundError(
        "EDICTUM_CONFORMANCE_REQUIRED=1 but workflow-v0.18 fixtures were not found. "
        "Set EDICTUM_SCHEMAS_DIR or ensure edictum-schemas is checked out."
    )

pytestmark = pytest.mark.skipif(
    _V018_DIR is None,
    reason="edictum-schemas/fixtures/workflow-v0.18 not found (set EDICTUM_SCHEMAS_DIR)",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_suite(filename: str) -> dict | None:
    if _V018_DIR is None:
        return None
    path = _V018_DIR / filename
    if not path.is_file():
        return None
    return yaml.safe_load(path.read_text())


def _make_workflow_yaml(wf: dict) -> str:
    return yaml.dump(wf)


def _seed_state(initial: dict[str, Any]) -> WorkflowState:
    evidence_data = initial.get("evidence", {})
    mcp_raw = evidence_data.get("mcp_results") or {}
    state = WorkflowState(
        session_id=initial["session_id"],
        active_stage=initial["active_stage"],
        completed_stages=list(initial["completed_stages"]),
        approvals=dict(initial["approvals"]),
        evidence=WorkflowEvidence(
            reads=list(evidence_data.get("reads", [])),
            stage_calls={k: list(v) for k, v in (evidence_data.get("stage_calls") or {}).items()},
            mcp_results={k: [dict(r) for r in v] for k, v in mcp_raw.items()},
        ),
    )
    state.ensure_defaults()
    return state


def _make_envelope(tool: str, args: dict) -> Any:
    return create_envelope(tool_name=tool, tool_input=args)


def _decision_from_evaluation(evaluation: Any) -> str:
    if evaluation.action == "block":
        return "deny"
    if evaluation.action == "allow":
        return "allow"
    return evaluation.action


def _assert_evidence_matches(state: WorkflowState, expect_evidence: dict) -> None:
    if "reads" in expect_evidence:
        assert state.evidence.reads == expect_evidence["reads"], (
            f"reads mismatch: {state.evidence.reads!r} != {expect_evidence['reads']!r}"
        )
    if "stage_calls" in expect_evidence:
        assert state.evidence.stage_calls == expect_evidence["stage_calls"], (
            f"stage_calls mismatch: {state.evidence.stage_calls!r} != {expect_evidence['stage_calls']!r}"
        )
    if "mcp_results" in expect_evidence:
        assert state.evidence.mcp_results == expect_evidence["mcp_results"], (
            f"mcp_results mismatch: {state.evidence.mcp_results!r} != {expect_evidence['mcp_results']!r}"
        )


# ---------------------------------------------------------------------------
# Workflow fixture runner (wildcard-tools, terminal-stage, mcp-result-evidence)
# ---------------------------------------------------------------------------


async def _run_workflow_fixture(suite: dict, fixture: dict, *, session_suffix: str = "") -> None:
    workflows: dict[str, dict] = suite.get("workflows", {})
    workflow_name = fixture["workflow"]
    wf_dict = workflows[workflow_name]
    wf_yaml = _make_workflow_yaml(wf_dict)

    runtime = WorkflowRuntime(load_workflow_string(wf_yaml))

    initial = fixture["initial_state"]
    session_id = initial["session_id"] + session_suffix
    session = Session(session_id, MemoryBackend())

    state = _seed_state({**initial, "session_id": session_id})
    await save_state(session, runtime.definition, state)

    for step in fixture["steps"]:
        call = step["call"]
        tool = call["tool"]
        args = call.get("args", {})
        execution = step.get("execution", "success")
        mcp_result = step.get("mcp_result")
        expect = step["expect"]

        envelope = _make_envelope(tool, args)
        evaluation = await runtime.evaluate(session, envelope)

        actual_decision = _decision_from_evaluation(evaluation)
        assert actual_decision == expect["decision"], (
            f"step {step['id']}: expected decision={expect['decision']!r}, "
            f"got={actual_decision!r} (reason={evaluation.reason!r})"
        )

        if expect.get("message_contains"):
            assert expect["message_contains"] in evaluation.reason, (
                f"step {step['id']}: expected message_contains={expect['message_contains']!r} "
                f"in reason={evaluation.reason!r}"
            )

        if execution == "success":
            record_mcp = mcp_result if mcp_result is not None else None
            await runtime.record_result(session, evaluation.stage_id, envelope, mcp_result=record_mcp)

        final_state = await runtime.state(session)

        assert final_state.active_stage == expect["active_stage"], (
            f"step {step['id']}: active_stage expected={expect['active_stage']!r}, got={final_state.active_stage!r}"
        )
        assert final_state.completed_stages == expect["completed_stages"], (
            f"step {step['id']}: completed_stages expected={expect['completed_stages']!r}, "
            f"got={final_state.completed_stages!r}"
        )
        assert final_state.approvals == expect["approvals"], (
            f"step {step['id']}: approvals expected={expect['approvals']!r}, got={final_state.approvals!r}"
        )
        if "evidence" in expect:
            _assert_evidence_matches(final_state, expect["evidence"])


# ---------------------------------------------------------------------------
# Wildcard-tools fixtures
# ---------------------------------------------------------------------------


def _wildcard_params() -> list[Any]:
    suite = _load_suite("wildcard-tools.workflow-v0.18.yaml")
    if suite is None:
        return []
    return [pytest.param(suite, f, id=f"{suite.get('suite', 'wildcard')}/{f['id']}") for f in suite.get("fixtures", [])]


@pytest.mark.asyncio
@pytest.mark.parametrize("suite,fixture", _wildcard_params())
async def test_workflow_v018_wildcard_tools(suite: dict, fixture: dict) -> None:
    await _run_workflow_fixture(suite, fixture)


# ---------------------------------------------------------------------------
# Terminal-stage fixtures
# ---------------------------------------------------------------------------


def _terminal_params() -> list[Any]:
    suite = _load_suite("terminal-stage.workflow-v0.18.yaml")
    if suite is None:
        return []
    return [pytest.param(suite, f, id=f"{suite.get('suite', 'terminal')}/{f['id']}") for f in suite.get("fixtures", [])]


@pytest.mark.asyncio
@pytest.mark.parametrize("suite,fixture", _terminal_params())
async def test_workflow_v018_terminal_stage(suite: dict, fixture: dict) -> None:
    await _run_workflow_fixture(suite, fixture)


# ---------------------------------------------------------------------------
# MCP result evidence fixtures
# ---------------------------------------------------------------------------


def _mcp_params() -> list[Any]:
    suite = _load_suite("mcp-result-evidence.workflow-v0.18.yaml")
    if suite is None:
        return []
    return [pytest.param(suite, f, id=f"{suite.get('suite', 'mcp')}/{f['id']}") for f in suite.get("fixtures", [])]


@pytest.mark.asyncio
@pytest.mark.parametrize("suite,fixture", _mcp_params())
async def test_workflow_v018_mcp_result_evidence(suite: dict, fixture: dict) -> None:
    await _run_workflow_fixture(suite, fixture)


# ---------------------------------------------------------------------------
# Extends-inheritance fixtures
# ---------------------------------------------------------------------------


def _extends_params() -> list[Any]:
    suite = _load_suite("extends-inheritance.workflow-v0.18.yaml")
    if suite is None:
        return []
    return [pytest.param(suite, f, id=f"{suite.get('suite', 'extends')}/{f['id']}") for f in suite.get("fixtures", [])]


@pytest.mark.parametrize("suite,fixture", _extends_params())
def test_workflow_v018_extends_inheritance(suite: dict, fixture: dict) -> None:
    from edictum import Edictum

    rulesets: dict[str, dict] = suite.get("rulesets", {})

    ruleset_ref = fixture["contract"]  # "contract" is the shared fixture schema key name
    envelope_data = fixture["envelope"]
    expected = fixture["expected"]

    # Resolve extends: chain to get the merged raw dict
    merged = resolve_ruleset_extends(rulesets, ruleset_ref)

    # Create a guard from the merged bundle (no reload needed)
    guard = Edictum.from_bundle_dict(merged, f"conformance-{ruleset_ref}")

    result = guard.evaluate(envelope_data["tool_name"], envelope_data.get("arguments", {}))

    expected_verdict = expected["verdict"]
    if expected_verdict in ("denied", "block"):  # "denied" is the shared fixture schema's legacy term
        assert result.decision == "block", (
            f"fixture {fixture['id']}: expected verdict=blocked, got decision={result.decision!r}"
        )
        if expected.get("message_contains"):
            assert any(expected["message_contains"] in r for r in result.block_reasons), (
                f"fixture {fixture['id']}: message_contains={expected['message_contains']!r} "
                f"not in block_reasons={result.block_reasons!r}"
            )
    elif expected_verdict == "allowed":
        assert result.decision == "allow", (
            f"fixture {fixture['id']}: expected verdict=allowed, got decision={result.decision!r}"
        )
    else:
        pytest.fail(f"fixture {fixture['id']}: unknown expected verdict {expected_verdict!r}")
