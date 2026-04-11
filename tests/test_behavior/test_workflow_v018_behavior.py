"""Behavior tests for v0.18 workflow features.

Covers:
  1. Wildcard prefix in stage.tools via fnmatch
  2. terminal: true stage primitive
  3. MCP result evidence + mcp_result_matches() gate condition
  4. extends: ruleset inheritance (resolve_ruleset_extends + from_bundle_dict)
"""

from __future__ import annotations

import pytest

from edictum.envelope import create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowEvidence, WorkflowRuntime, WorkflowState, load_workflow_string
from edictum.workflow.state import save_state

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _runtime(yaml_content: str) -> WorkflowRuntime:
    return WorkflowRuntime(load_workflow_string(yaml_content))


def _envelope(tool: str, **kwargs):
    return create_envelope(tool_name=tool, tool_input=kwargs)


async def _session_with_state(runtime: WorkflowRuntime, **state_kwargs) -> Session:
    session = Session("test-session", MemoryBackend())
    state = WorkflowState(**state_kwargs)
    state.ensure_defaults()
    await save_state(session, runtime.definition, state)
    return session


# ---------------------------------------------------------------------------
# 1. Wildcard prefix in stage.tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wildcard_tools_allows_matching_tool():
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: wc-test
stages:
  - id: only
    tools: ["mcp__*"]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="only")
    result = await rt.evaluate(session, _envelope("mcp__github__list_prs"))
    assert result.action == "allow"


@pytest.mark.asyncio
async def test_wildcard_tools_blocks_non_matching_tool():
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: wc-test
stages:
  - id: only
    tools: ["mcp__*"]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="only")
    result = await rt.evaluate(session, _envelope("Edit"))
    assert result.action == "block"


@pytest.mark.asyncio
async def test_wildcard_narrower_namespace_blocks_sibling():
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: wc-test
stages:
  - id: ci-only
    tools: ["mcp__ci__*"]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="ci-only")
    result = await rt.evaluate(session, _envelope("mcp__github__list_prs"))
    assert result.action == "block"


@pytest.mark.asyncio
async def test_wildcard_mixed_exact_and_pattern():
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: wc-test
stages:
  - id: research
    tools: [Read, "mcp__*"]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="research")

    result_read = await rt.evaluate(session, _envelope("Read", path="README.md"))
    assert result_read.action == "allow"

    result_mcp = await rt.evaluate(session, _envelope("mcp__github__list_prs", repo="x"))
    assert result_mcp.action == "allow"

    result_edit = await rt.evaluate(session, _envelope("Edit", path="src/app.ts"))
    assert result_edit.action == "block"


@pytest.mark.asyncio
async def test_wildcard_stage_does_not_auto_advance_on_blocked_tool():
    """A stage with wildcards should block — not auto-advance — when a non-matching tool is tried."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: wc-test
stages:
  - id: research
    tools: [Read, "mcp__*"]
  - id: implement
    entry:
      - condition: stage_complete("research")
    tools: [Edit]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="research")
    result = await rt.evaluate(session, _envelope("Edit", path="src/app.ts"))
    assert result.action == "block"

    state = await rt.state(session)
    assert state.active_stage == "research"
    assert state.completed_stages == []


# ---------------------------------------------------------------------------
# 2. terminal: true stage primitive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_terminal_no_tools_denies_all():
    """Terminal stage with no tools denies all tool calls."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: terminal-test
stages:
  - id: implement
    tools: [Edit]
  - id: done
    entry:
      - condition: stage_complete("implement")
    terminal: true
""")
    session = await _session_with_state(
        rt, session_id="s1", active_stage="done", completed_stages=["implement"]
    )

    for tool in ("Edit", "Read", "Bash"):
        result = await rt.evaluate(session, _envelope(tool, path="x"))
        assert result.action == "block", f"{tool} should be blocked in terminal stage"


@pytest.mark.asyncio
async def test_terminal_with_tools_allows_matching():
    """Terminal stage with tools allows matching tool calls."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: terminal-test
stages:
  - id: implement
    tools: [Edit]
  - id: verify
    entry:
      - condition: stage_complete("implement")
    tools: [Bash]
    exit:
      - condition: command_matches("^pytest$")
        message: "Run pytest"
    terminal: true
""")
    session = await _session_with_state(
        rt, session_id="s1", active_stage="verify", completed_stages=["implement"]
    )
    result = await rt.evaluate(session, _envelope("Bash", command="pytest"))
    assert result.action == "allow"


@pytest.mark.asyncio
async def test_terminal_blocks_after_exit_conditions_met():
    """Once exit conditions are satisfied on a terminal stage, all calls are blocked."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: terminal-test
stages:
  - id: implement
    tools: [Edit]
  - id: verify
    entry:
      - condition: stage_complete("implement")
    tools: [Bash]
    exit:
      - condition: command_matches("^pytest$")
        message: "Run pytest"
    terminal: true
""")
    evidence = WorkflowEvidence(stage_calls={"verify": ["pytest"]})
    session = await _session_with_state(
        rt,
        session_id="s1",
        active_stage="verify",
        completed_stages=["implement"],
        evidence=evidence,
    )

    # Even a matching tool should be blocked after exit conditions are met
    result = await rt.evaluate(session, _envelope("Bash", command="pytest"))
    assert result.action == "block"
    assert "complete" in result.reason.lower()


@pytest.mark.asyncio
async def test_terminal_auto_advance_on_blocked_prior_stage():
    """A non-exit prior stage auto-advances into terminal; triggering call is denied there."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: terminal-test
stages:
  - id: implement
    tools: [Edit]
  - id: done
    entry:
      - condition: stage_complete("implement")
    terminal: true
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="implement")

    result = await rt.evaluate(session, _envelope("Bash", command="echo hi"))
    assert result.action == "block"

    state = await rt.state(session)
    assert state.active_stage == "done"
    assert "implement" in state.completed_stages


@pytest.mark.asyncio
async def test_terminal_advance_after_success_does_not_move_stage():
    """record_result on a terminal stage does not auto-advance past it."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: terminal-test
stages:
  - id: implement
    tools: [Edit]
  - id: verify
    entry:
      - condition: stage_complete("implement")
    tools: [Bash]
    exit:
      - condition: command_matches("^pytest$")
        message: "Run pytest"
    terminal: true
""")
    session = await _session_with_state(
        rt, session_id="s1", active_stage="verify", completed_stages=["implement"]
    )
    envelope = _envelope("Bash", command="pytest")
    result = await rt.evaluate(session, envelope)
    assert result.action == "allow"

    await rt.record_result(session, result.stage_id, envelope)

    state = await rt.state(session)
    # Stage should still be active, not advanced away
    assert state.active_stage == "verify"


# ---------------------------------------------------------------------------
# 3. MCP result evidence + mcp_result_matches() gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mcp_result_records_on_success():
    """Successful MCP call records its result in evidence.mcp_results."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: mcp-test
stages:
  - id: check
    tools: ["mcp__ci__*"]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="check")
    envelope = _envelope("mcp__ci__status", branch="main")

    result = await rt.evaluate(session, envelope)
    assert result.action == "allow"

    await rt.record_result(
        session, result.stage_id, envelope, mcp_result={"outcome": "passing", "run_id": "42"}
    )

    state = await rt.state(session)
    assert "mcp__ci__status" in state.evidence.mcp_results
    recorded = state.evidence.mcp_results["mcp__ci__status"]
    assert len(recorded) == 1
    assert recorded[0]["outcome"] == "passing"


@pytest.mark.asyncio
async def test_mcp_result_not_recorded_on_no_mcp_result():
    """Calling record_result without mcp_result leaves mcp_results empty."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: mcp-test
stages:
  - id: check
    tools: ["mcp__ci__*"]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="check")
    envelope = _envelope("mcp__ci__status", branch="main")

    result = await rt.evaluate(session, envelope)
    await rt.record_result(session, result.stage_id, envelope)  # no mcp_result

    state = await rt.state(session)
    assert state.evidence.mcp_results == {}


@pytest.mark.asyncio
async def test_mcp_result_matches_gate_passes_when_evidence_present():
    """mcp_result_matches exit gate passes when matching evidence is recorded."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: mcp-test
stages:
  - id: check-ci
    tools: ["mcp__ci__*"]
    exit:
      - condition: mcp_result_matches("mcp__ci__status", "outcome", "passing")
        message: "CI must be passing"
  - id: deploy
    entry:
      - condition: stage_complete("check-ci")
    tools: ["mcp__deploy__*"]
""")
    evidence = WorkflowEvidence(
        mcp_results={"mcp__ci__status": [{"outcome": "passing", "branch": "main"}]}
    )
    session = await _session_with_state(
        rt, session_id="s1", active_stage="check-ci", evidence=evidence
    )

    result = await rt.evaluate(session, _envelope("mcp__deploy__trigger", env="prod"))
    assert result.action == "allow"

    state = await rt.state(session)
    assert state.active_stage == "deploy"


@pytest.mark.asyncio
async def test_mcp_result_matches_gate_blocks_when_value_mismatch():
    """mcp_result_matches gate blocks when recorded value doesn't match."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: mcp-test
stages:
  - id: check-ci
    tools: ["mcp__ci__*"]
    exit:
      - condition: mcp_result_matches("mcp__ci__status", "outcome", "passing")
        message: "CI must be passing"
  - id: deploy
    entry:
      - condition: stage_complete("check-ci")
    tools: ["mcp__deploy__*"]
""")
    evidence = WorkflowEvidence(
        mcp_results={"mcp__ci__status": [{"outcome": "failing", "branch": "main"}]}
    )
    session = await _session_with_state(
        rt, session_id="s1", active_stage="check-ci", evidence=evidence
    )

    result = await rt.evaluate(session, _envelope("mcp__deploy__trigger", env="prod"))
    assert result.action == "block"
    assert "CI must be passing" in result.reason


@pytest.mark.asyncio
async def test_mcp_result_matches_gate_blocks_when_no_evidence():
    """mcp_result_matches gate blocks when no MCP evidence has been recorded."""
    rt = _runtime("""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: mcp-test
stages:
  - id: check-ci
    tools: ["mcp__ci__*"]
    exit:
      - condition: mcp_result_matches("mcp__ci__status", "outcome", "passing")
        message: "CI must be passing"
  - id: deploy
    entry:
      - condition: stage_complete("check-ci")
    tools: ["mcp__deploy__*"]
""")
    session = await _session_with_state(rt, session_id="s1", active_stage="check-ci")

    result = await rt.evaluate(session, _envelope("mcp__deploy__trigger", env="prod"))
    assert result.action == "block"


# ---------------------------------------------------------------------------
# 4. extends: ruleset inheritance
# ---------------------------------------------------------------------------


def test_extends_child_inherits_parent_rule():
    """Child ruleset inherits parent rules; parent rule fires on matching call."""
    from edictum import Edictum
    from edictum.yaml_engine.loader import resolve_ruleset_extends

    rulesets = {
        "base": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "base"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "block-push-main",
                    "type": "pre",
                    "tool": "Bash",
                    "when": {"args.command": {"matches": "^git push.*\\bmain\\b"}},
                    "then": {"action": "block", "message": "blocked by parent"},
                }
            ],
        },
        "child": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "child"},
            "extends": "base",
            "defaults": {"mode": "enforce"},
            "rules": [],
        },
    }
    merged = resolve_ruleset_extends(rulesets, "child")
    guard = Edictum.from_bundle_dict(merged, "test-child")
    result = guard.evaluate("Bash", {"command": "git push origin main"})
    assert result.decision == "block"
    assert any("blocked by parent" in r for r in result.block_reasons)


def test_extends_child_own_rule_fires():
    """Child ruleset's own rules also fire independently."""
    from edictum import Edictum
    from edictum.yaml_engine.loader import resolve_ruleset_extends

    rulesets = {
        "base": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "base"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "block-push-main",
                    "type": "pre",
                    "tool": "Bash",
                    "when": {"args.command": {"matches": "^git push.*\\bmain\\b"}},
                    "then": {"action": "block", "message": "blocked by parent"},
                }
            ],
        },
        "child": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "child"},
            "extends": "base",
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "block-force-push",
                    "type": "pre",
                    "tool": "Bash",
                    "when": {"args.command": {"matches": "^git push --force"}},
                    "then": {"action": "block", "message": "blocked by child"},
                }
            ],
        },
    }
    merged = resolve_ruleset_extends(rulesets, "child")
    guard = Edictum.from_bundle_dict(merged, "test-child")
    result = guard.evaluate("Bash", {"command": "git push --force origin feat/wip"})
    assert result.decision == "block"
    assert any("blocked by child" in r for r in result.block_reasons)


def test_extends_non_matching_call_is_allowed():
    """Call matching neither parent nor child rule is allowed."""
    from edictum import Edictum
    from edictum.yaml_engine.loader import resolve_ruleset_extends

    rulesets = {
        "base": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "base"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "block-push-main",
                    "type": "pre",
                    "tool": "Bash",
                    "when": {"args.command": {"matches": "^git push.*\\bmain\\b"}},
                    "then": {"action": "block", "message": "blocked by parent"},
                }
            ],
        },
        "child": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "child"},
            "extends": "base",
            "defaults": {"mode": "enforce"},
            "rules": [],
        },
    }
    merged = resolve_ruleset_extends(rulesets, "child")
    guard = Edictum.from_bundle_dict(merged, "test-child")
    result = guard.evaluate("Bash", {"command": "git push origin feat/wip"})
    assert result.decision == "allow"


def test_extends_child_defaults_override_parent():
    """Child defaults (e.g., observe mode) override parent defaults."""
    from edictum import Edictum
    from edictum.yaml_engine.loader import resolve_ruleset_extends

    rulesets = {
        "base": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "base"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "block-push-main",
                    "type": "pre",
                    "tool": "Bash",
                    "when": {"args.command": {"matches": "^git push.*\\bmain\\b"}},
                    "then": {"action": "block", "message": "blocked by parent"},
                }
            ],
        },
        "observe-child": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "observe-child"},
            "extends": "base",
            "defaults": {"mode": "observe"},
            "rules": [],
        },
    }
    merged = resolve_ruleset_extends(rulesets, "observe-child")
    guard = Edictum.from_bundle_dict(merged, "test-observe-child")
    # In observe mode, block rules don't actually block
    result = guard.evaluate("Bash", {"command": "git push origin main"})
    assert result.decision == "allow"


def test_extends_circular_reference_raises():
    """Circular extends references raise ValueError."""
    from edictum.yaml_engine.loader import resolve_ruleset_extends

    rulesets = {
        "a": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "a"},
            "extends": "b",
            "rules": [],
        },
        "b": {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "b"},
            "extends": "a",
            "rules": [],
        },
    }
    with pytest.raises(ValueError, match="circular"):
        resolve_ruleset_extends(rulesets, "a")


def test_extends_parent_rules_come_before_child_rules():
    """Merged ruleset has parent rules first, child rules after."""
    from edictum.yaml_engine.loader import _merge_parent_bundle

    parent = {"rules": [{"id": "p1"}, {"id": "p2"}], "metadata": {"name": "parent"}}
    child = {"rules": [{"id": "c1"}], "metadata": {"name": "child"}}

    merged = _merge_parent_bundle(parent, child)
    rule_ids = [r["id"] for r in merged["rules"]]
    assert rule_ids == ["p1", "p2", "c1"]
