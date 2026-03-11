"""Tests for observe_alongside dual-mode evaluation."""

from __future__ import annotations

import pytest

from edictum import Edictum, EdictumDenied
from edictum.audit import AuditAction

# ---------------------------------------------------------------------------
# YAML fixtures (written to tmp_path at test time)
# ---------------------------------------------------------------------------

ENFORCED_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: enforced-policy
defaults:
  mode: enforce
contracts:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      effect: deny
      message: "Denied read of .env file"
  - id: session-limit
    type: session
    limits:
      max_tool_calls: 100
    then:
      effect: deny
      message: "Session limit reached (enforced)"
"""

CANDIDATE_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: candidate-policy
defaults:
  mode: enforce
observe_alongside: true
contracts:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".secret" }
    then:
      effect: deny
      message: "Denied read of .secret file"
  - id: new-observe-only
    type: pre
    tool: "*"
    when:
      args.cmd: { contains: "rm -rf" }
    then:
      effect: deny
      message: "Dangerous rm command denied"
  - id: session-limit
    type: session
    limits:
      max_tool_calls: 5
    then:
      effect: deny
      message: "Session limit reached (candidate)"
"""


class _CaptureSink:
    """Audit sink that captures events for test assertions."""

    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


def _write_bundles(tmp_path):
    """Write enforced and candidate YAML bundles and return their paths."""
    enforced = tmp_path / "enforced.yaml"
    enforced.write_text(ENFORCED_BUNDLE)
    candidate = tmp_path / "candidate.yaml"
    candidate.write_text(CANDIDATE_BUNDLE)
    return enforced, candidate


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestObserveModeAuditEvents:
    """Observe-mode evaluation produces separate audit events with mode='observe'."""

    async def test_observe_mode_produces_audit_events(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # read_file with .secret triggers the observe-mode contract but not the enforced one
        result = await guard.run(
            "read_file",
            {"path": "/home/config.secret"},
            lambda path: f"contents of {path}",
        )
        assert result == "contents of /home/config.secret"

        # Check for observe-mode audit events with mode="observe"
        observe_events = [e for e in sink.events if e.mode == "observe"]
        assert len(observe_events) >= 1

        # The observe-mode denial should have CALL_WOULD_DENY
        observe_deny = [e for e in observe_events if e.action == AuditAction.CALL_WOULD_DENY]
        assert len(observe_deny) >= 1
        assert "block-env-reads:candidate" in observe_deny[0].decision_name


class TestObserveModeDoesNotBlockRealCalls:
    """Observe-mode contracts don't block real calls -- PreDecision still allows."""

    async def test_observe_deny_does_not_block(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # .secret would be denied by the candidate but NOT by the enforced bundle
        result = await guard.run(
            "read_file",
            {"path": "/home/data.secret"},
            lambda path: f"contents of {path}",
        )
        assert "contents of /home/data.secret" == result

    async def test_enforced_contract_still_denies(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # .env should still be denied by the enforced contract
        with pytest.raises(EdictumDenied, match="Denied read of .env file"):
            await guard.run(
                "read_file",
                {"path": "/home/.env"},
                lambda path: f"contents of {path}",
            )


class TestObserveModeSessionContracts:
    """Observe-mode session contracts track counters independently."""

    async def test_observe_session_evaluates_against_real_counters(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # The candidate has max_tool_calls=5, enforced has 100
        # After 5 calls, the observe-mode session contract should report would-deny
        # but the real session should still allow
        for _ in range(6):
            await guard.run(
                "some_tool",
                {"data": "test"},
                lambda data: "ok",
            )

        # All calls should succeed (enforced limit is 100)
        # But we should see observe-mode audit events after the 5th call
        observe_events = [e for e in sink.events if e.mode == "observe"]
        # Observe-mode session contract events should appear
        assert len(observe_events) > 0


class TestObserveModeWithoutEnforcedCounterpart:
    """observe_alongside with new contract ID (no enforced counterpart) -- observe-mode still evaluates."""

    async def test_new_observe_only_contract(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # new-observe-only:candidate should trigger for rm -rf
        result = await guard.run(
            "bash",
            {"cmd": "rm -rf /"},
            lambda cmd: "done",
        )
        assert result == "done"  # Not denied -- observe-mode only

        observe_events = [e for e in sink.events if e.mode == "observe"]
        observe_deny = [e for e in observe_events if e.action == AuditAction.CALL_WOULD_DENY]
        rm_events = [e for e in observe_deny if "new-observe-only:candidate" in (e.decision_name or "")]
        assert len(rm_events) >= 1


class TestObserveModeAuditActions:
    """Observe-mode audit events use CALL_WOULD_DENY / CALL_ALLOWED actions."""

    async def test_observe_pass_uses_call_allowed(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # A call that passes both enforced and observe-mode
        await guard.run(
            "some_tool",
            {"data": "safe"},
            lambda data: "ok",
        )

        # Observe-mode events that pass should use CALL_ALLOWED
        observe_events = [e for e in sink.events if e.mode == "observe"]
        # The new-observe-only contract matches tool="*" but only triggers on rm -rf
        # So it should pass and produce a CALL_ALLOWED observe-mode event
        assert any(e.action == AuditAction.CALL_ALLOWED for e in observe_events)

    async def test_observe_fail_uses_call_would_deny(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # Trigger the observe-mode contract but not the enforced
        await guard.run(
            "read_file",
            {"path": "/home/app.secret"},
            lambda path: "data",
        )

        observe_events = [e for e in sink.events if e.mode == "observe"]
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in observe_events)


class TestNormalContractsRegression:
    """Normal contracts still work exactly as before (regression)."""

    async def test_enforced_deny_unchanged(self, tmp_path):
        enforced_path = tmp_path / "enforced.yaml"
        enforced_path.write_text(ENFORCED_BUNDLE)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, audit_sink=sink)

        with pytest.raises(EdictumDenied, match="Denied read of .env file"):
            await guard.run(
                "read_file",
                {"path": "/home/.env"},
                lambda path: "contents",
            )

    async def test_enforced_allow_unchanged(self, tmp_path):
        enforced_path = tmp_path / "enforced.yaml"
        enforced_path.write_text(ENFORCED_BUNDLE)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, audit_sink=sink)

        result = await guard.run(
            "read_file",
            {"path": "/home/readme.md"},
            lambda path: f"contents of {path}",
        )
        assert result == "contents of /home/readme.md"

        # No observe-mode events when there's no candidate bundle
        observe_events = [e for e in sink.events if e.mode == "observe"]
        assert len(observe_events) == 0

    async def test_no_observe_lists_without_candidate(self, tmp_path):
        enforced_path = tmp_path / "enforced.yaml"
        enforced_path.write_text(ENFORCED_BUNDLE)
        guard = Edictum.from_yaml(enforced_path)
        assert guard._state.shadow_preconditions == ()
        assert guard._state.shadow_postconditions == ()
        assert guard._state.shadow_session_contracts == ()
