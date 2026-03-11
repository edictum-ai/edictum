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
  - id: new-shadow-only
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


class TestShadowAuditEvents:
    """Shadow evaluation produces separate audit events with mode='observe'."""

    async def test_shadow_produces_observe_audit_events(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # read_file with .secret triggers the shadow contract but not the enforced one
        result = await guard.run(
            "read_file",
            {"path": "/home/config.secret"},
            lambda path: f"contents of {path}",
        )
        assert result == "contents of /home/config.secret"

        # Check for shadow audit events with mode="observe"
        shadow_events = [e for e in sink.events if e.mode == "observe"]
        assert len(shadow_events) >= 1

        # The shadow denial should have CALL_WOULD_DENY
        shadow_deny = [e for e in shadow_events if e.action == AuditAction.CALL_WOULD_DENY]
        assert len(shadow_deny) >= 1
        assert "block-env-reads:candidate" in shadow_deny[0].decision_name


class TestShadowDoesNotBlockRealCalls:
    """Shadow contracts don't block real calls — PreDecision still allows."""

    async def test_shadow_deny_does_not_block(self, tmp_path):
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


class TestShadowSessionContracts:
    """Shadow session contracts track counters independently."""

    async def test_shadow_session_evaluates_against_real_counters(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # The candidate has max_tool_calls=5, enforced has 100
        # After 5 calls, the shadow session contract should report would-deny
        # but the real session should still allow
        for _ in range(6):
            await guard.run(
                "some_tool",
                {"data": "test"},
                lambda data: "ok",
            )

        # All calls should succeed (enforced limit is 100)
        # But we should see shadow audit events after the 5th call
        shadow_events = [e for e in sink.events if e.mode == "observe"]
        # Shadow session contract events should appear
        assert len(shadow_events) > 0


class TestShadowWithoutEnforcedCounterpart:
    """observe_alongside with new contract ID (no enforced counterpart) — shadow still evaluates."""

    async def test_new_shadow_only_contract(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # new-shadow-only:candidate should trigger for rm -rf
        result = await guard.run(
            "bash",
            {"cmd": "rm -rf /"},
            lambda cmd: "done",
        )
        assert result == "done"  # Not denied — shadow only

        shadow_events = [e for e in sink.events if e.mode == "observe"]
        shadow_deny = [e for e in shadow_events if e.action == AuditAction.CALL_WOULD_DENY]
        rm_events = [e for e in shadow_deny if "new-shadow-only:candidate" in (e.decision_name or "")]
        assert len(rm_events) >= 1


class TestShadowAuditActions:
    """Shadow audit events use CALL_WOULD_DENY / CALL_ALLOWED actions."""

    async def test_shadow_pass_uses_call_allowed(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # A call that passes both enforced and shadow
        await guard.run(
            "some_tool",
            {"data": "safe"},
            lambda data: "ok",
        )

        # Shadow events that pass should use CALL_ALLOWED
        shadow_events = [e for e in sink.events if e.mode == "observe"]
        # The new-shadow-only contract matches tool="*" but only triggers on rm -rf
        # So it should pass and produce a CALL_ALLOWED shadow event
        assert any(e.action == AuditAction.CALL_ALLOWED for e in shadow_events)

    async def test_shadow_fail_uses_call_would_deny(self, tmp_path):
        enforced_path, candidate_path = _write_bundles(tmp_path)
        sink = _CaptureSink()
        guard = Edictum.from_yaml(enforced_path, candidate_path, audit_sink=sink)

        # Trigger the shadow but not the enforced
        await guard.run(
            "read_file",
            {"path": "/home/app.secret"},
            lambda path: "data",
        )

        shadow_events = [e for e in sink.events if e.mode == "observe"]
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in shadow_events)


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

        # No shadow events when there's no candidate bundle
        shadow_events = [e for e in sink.events if e.mode == "observe"]
        assert len(shadow_events) == 0

    async def test_no_shadow_lists_without_candidate(self, tmp_path):
        enforced_path = tmp_path / "enforced.yaml"
        enforced_path.write_text(ENFORCED_BUNDLE)
        guard = Edictum.from_yaml(enforced_path)
        assert guard._state.shadow_preconditions == ()
        assert guard._state.shadow_postconditions == ()
        assert guard._state.shadow_session_contracts == ()
