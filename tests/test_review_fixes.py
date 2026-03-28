"""Tests for v0.3.0 code review fixes (issues 1-22)."""

from __future__ import annotations

from pathlib import Path

import pytest

from edictum import (
    Decision,
    Edictum,
    EdictumConfigError,
    EdictumDenied,
    Principal,
    create_envelope,
    precondition,
)
from edictum.adapters.agno import AgnoAdapter
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
from edictum.adapters.crewai import CrewAIAdapter
from edictum.adapters.langchain import LangChainAdapter
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
from edictum.audit import AuditAction, AuditEvent
from edictum.rules import postcondition
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.types import HookRegistration
from edictum.yaml_engine.compiler import _expand_message, compile_contracts
from edictum.yaml_engine.loader import load_bundle

FIXTURES = Path(__file__).parent / "test_yaml_engine" / "fixtures"


class NullSink:
    def __init__(self):
        self.events: list[AuditEvent] = []

    async def emit(self, event):
        self.events.append(event)


def _guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


# ── Fix 1: Reject output.text in type: pre rules at load time ──


class TestFix1OutputTextInPre:
    def test_output_text_in_pre_raises(self):
        with pytest.raises(EdictumConfigError, match="output.text selector"):
            load_bundle(FIXTURES / "invalid_output_text_in_pre.yaml")

    def test_output_text_in_post_allowed(self):
        data, _ = load_bundle(FIXTURES / "valid_bundle.yaml")
        post = data["rules"][1]
        assert post["type"] == "post"
        assert "output.text" in post["when"]

    def test_output_text_nested_in_pre_raises(self, tmp_path):
        bundle = tmp_path / "nested.yaml"
        bundle.write_text(
            """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: nested-test
defaults:
  mode: enforce
rules:
  - id: nested-output
    type: pre
    tool: "*"
    when:
      any:
        - output.text:
            contains: "secret"
        - args.path:
            contains: ".env"
    then:
      action: block
      message: "denied"
"""
        )
        with pytest.raises(EdictumConfigError, match="output.text selector"):
            load_bundle(bundle)


# ── Fix 2: Stamp yaml-prefixed decision_source ──


class TestFix2YamlDecisionSource:
    def test_precondition_source_yaml_prefixed(self):
        data, _ = load_bundle(FIXTURES / "valid_bundle.yaml")
        compiled = compile_contracts(data)
        fn = compiled.preconditions[0]
        assert fn._edictum_source == "yaml_precondition"

    def test_postcondition_source_yaml_prefixed(self):
        data, _ = load_bundle(FIXTURES / "valid_bundle.yaml")
        compiled = compile_contracts(data)
        fn = compiled.postconditions[0]
        assert fn._edictum_source == "yaml_postcondition"

    def test_session_source_yaml_prefixed(self):
        data, _ = load_bundle(FIXTURES / "valid_bundle.yaml")
        compiled = compile_contracts(data)
        fn = compiled.session_contracts[0]
        assert fn._edictum_source == "yaml_session"

    async def test_deny_audit_has_yaml_decision_source(self):
        sink = NullSink()
        guard = Edictum.from_yaml(
            FIXTURES / "valid_bundle.yaml",
            audit_sink=sink,
            backend=MemoryBackend(),
        )

        async def noop(**kw):
            return "ok"

        with pytest.raises(EdictumDenied) as exc:
            await guard.run("read_file", {"path": ".env"}, noop)
        assert exc.value.decision_source == "yaml_precondition"

        denied_events = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(denied_events) == 1
        assert denied_events[0].decision_source == "yaml_precondition"


# ── Fix 3: Propagate policy_error ──


class TestFix3PolicyError:
    async def test_policy_error_in_pre_audit(self):
        """Type mismatch in YAML rule sets policy_error on AuditEvent."""
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "type-mismatch",
                    "type": "pre",
                    "tool": "*",
                    "when": {"args.count": {"gt": 5}},
                    "then": {"action": "block", "message": "Count too high."},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        sink = NullSink()
        guard = _guard(
            rules=compiled.preconditions,
            audit_sink=sink,
        )

        async def noop(**kw):
            return "ok"

        with pytest.raises(EdictumDenied):
            await guard.run("TestTool", {"count": "not_a_number"}, noop)

        denied = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(denied) == 1
        assert denied[0].policy_error is True


# ── Fix 4: Per-rule observe mode in adapters ──


class TestFix4PerRuleObserve:
    async def test_observed_rule_allows_through_in_run(self):
        """An observe-mode precondition in an enforce bundle should log, not block."""

        @precondition("*")
        def observed_deny(tool_call):
            return Decision.fail("observed violation")

        observed_deny._edictum_mode = "observe"

        sink = NullSink()
        guard = _guard(rules=[observed_deny], audit_sink=sink)

        async def noop(**kw):
            return "ok"

        result = await guard.run("TestTool", {}, noop)
        assert result == "ok"

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_WOULD_DENY in actions
        assert AuditAction.CALL_ALLOWED in actions

    async def test_observed_and_enforced_rules_together(self):
        """Enforced rule blocks even if an observed rule also fires."""

        @precondition("*")
        def observed_deny(tool_call):
            return Decision.fail("observed violation")

        observed_deny._edictum_mode = "observe"

        @precondition("*")
        def enforced_deny(tool_call):
            return Decision.fail("enforced violation")

        enforced_deny._edictum_mode = "enforce"

        sink = NullSink()
        guard = _guard(rules=[observed_deny, enforced_deny], audit_sink=sink)

        async def noop(**kw):
            return "ok"

        with pytest.raises(EdictumDenied, match="enforced violation"):
            await guard.run("TestTool", {}, noop)

    async def test_observe_mode_in_claude_adapter(self):
        @precondition("*")
        def observed_deny(tool_call):
            return Decision.fail("observed")

        observed_deny._edictum_mode = "observe"

        sink = NullSink()
        guard = _guard(rules=[observed_deny], audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)

        result = await adapter._pre_tool_use(tool_name="TestTool", tool_input={}, tool_use_id="tu-1")
        # Should allow through
        assert result == {}
        # Should have CALL_WOULD_DENY
        would_deny = [e for e in sink.events if e.action == AuditAction.CALL_WOULD_DENY]
        assert len(would_deny) >= 1


# ── Fix 5: Catch exceptions in pipeline ──


class TestFix5ExceptionSafety:
    async def test_precondition_exception_denies_not_crashes(self):
        @precondition("*")
        def bad_pre(tool_call):
            raise ValueError("kaboom")

        sink = NullSink()
        guard = _guard(rules=[bad_pre], audit_sink=sink)

        async def noop(**kw):
            return "ok"

        with pytest.raises(EdictumDenied, match="Precondition error"):
            await guard.run("TestTool", {}, noop)

        denied = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(denied) == 1
        assert denied[0].policy_error is True

    async def test_postcondition_exception_warns_not_crashes(self):
        @postcondition("*")
        def bad_post(tool_call, result):
            raise RuntimeError("boom")

        sink = NullSink()
        guard = _guard(rules=[bad_post], audit_sink=sink)

        async def noop(**kw):
            return "ok"

        result = await guard.run("TestTool", {}, noop)
        assert result == "ok"

        executed = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert len(executed) == 1
        assert executed[0].policy_error is True

    async def test_hook_exception_denies(self):
        def bad_hook(tool_call):
            raise TypeError("hook broke")

        hook = HookRegistration(phase="before", tool="*", callback=bad_hook)
        sink = NullSink()
        guard = _guard(hooks=[hook], audit_sink=sink)

        async def noop(**kw):
            return "ok"

        with pytest.raises(EdictumDenied, match="Hook error"):
            await guard.run("TestTool", {}, noop)


# ── Fix 6: Cap regex input length ──


class TestFix6RegexCap:
    def test_large_input_no_hang(self):
        from edictum.yaml_engine.evaluator import _op_matches

        large = "a" * 50_000
        # Should not hang — evaluates truncated portion
        result = _op_matches(large, "^a+$")
        assert isinstance(result, bool)

    def test_truncated_still_evaluates(self):
        from edictum.yaml_engine.evaluator import _op_matches

        # Pattern matches in first 10K chars
        value = "secret" + "x" * 50_000
        assert _op_matches(value, "secret") is True

    def test_matches_any_with_large_input(self):
        from edictum.yaml_engine.evaluator import _op_matches_any

        large = "a" * 50_000
        result = _op_matches_any(large, ["^a+$"])
        assert isinstance(result, bool)


# ── Fix 7: Secret detection in message templates ──


class TestFix7SecretRedaction:
    def test_secret_in_placeholder_redacted(self):
        env = create_envelope("TestTool", {"token": "sk-abc123456789012345678901234567890"})
        msg = _expand_message("Token: {args.token}", env)
        assert "[REDACTED]" in msg
        assert "sk-abc" not in msg

    def test_non_secret_not_redacted(self):
        env = create_envelope("TestTool", {"path": "/tmp/test.txt"})
        msg = _expand_message("Path: {args.path}", env)
        assert msg == "Path: /tmp/test.txt"

    def test_jwt_in_placeholder_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"
        env = create_envelope("TestTool", {"auth": jwt})
        msg = _expand_message("Auth: {args.auth}", env)
        assert "[REDACTED]" in msg


# ── Fix 8: Deep-copy Principal.claims ──


class TestFix8PrincipalDeepCopy:
    def test_claims_deep_copied(self):
        claims = {"dept": "eng", "nested": {"level": 1}}
        principal = Principal(user_id="alice", claims=claims)
        tool_call = create_envelope("TestTool", {}, principal=principal)

        # Mutate original claims
        claims["dept"] = "sales"
        claims["nested"]["level"] = 99

        # Envelope should be unaffected
        assert tool_call.principal.claims["dept"] == "eng"
        assert tool_call.principal.claims["nested"]["level"] == 1


# ── Fix 11: Session limits default comparison ──


class TestFix11SessionLimitsDefault:
    async def test_max_attempts_at_default_still_enforced(self):
        """max_attempts: 500 (same as default) should still be enforced."""
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "session-default-limit",
                    "type": "session",
                    "limits": {"max_tool_calls": 1000, "max_attempts": 500},
                    "then": {"action": "block", "message": "limit hit"},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        assert compiled.limits.max_attempts == 500

        # The session rule should enforce the limit
        fn = compiled.session_contracts[0]
        backend = MemoryBackend()
        session = Session("test", backend)

        # Set attempt count to 500
        for _ in range(500):
            await session.increment_attempts()

        decision = await fn(session)
        assert not decision.passed


# ── Fix 12: __all__ exports ──


class TestFix12Exports:
    def test_bundle_hash_importable(self):
        from edictum.yaml_engine import BundleHash

        assert BundleHash is not None

    def test_compiled_bundle_importable(self):
        from edictum.yaml_engine import CompiledBundle

        assert CompiledBundle is not None


# ── Fix 13: Normalize _check_tool_success ──


class TestFix13CheckToolSuccess:
    def test_all_adapters_check_dict_is_error(self):
        sink = NullSink()
        guard = _guard(audit_sink=sink)

        adapters = [
            ClaudeAgentSDKAdapter(guard),
            LangChainAdapter(guard),
            AgnoAdapter(guard),
            SemanticKernelAdapter(guard),
        ]

        for adapter in adapters:
            assert adapter._check_tool_success("TestTool", {"is_error": True}) is False, (
                f"{type(adapter).__name__} failed dict is_error check"
            )

    def test_crewai_checks_dict_is_error(self):
        sink = NullSink()
        guard = _guard(audit_sink=sink)
        adapter = CrewAIAdapter(guard)
        assert adapter._check_tool_success("TestTool", {"is_error": True}) is False

    def test_openai_agents_checks_dict_is_error(self):
        sink = NullSink()
        guard = _guard(audit_sink=sink)
        adapter = OpenAIAgentsAdapter(guard)
        assert adapter._check_tool_success("TestTool", {"is_error": True}) is False


# ── Fix 14: OpenAI Agents FIFO correlation ──


class TestFix14OpenAICorrelation:
    async def test_two_concurrent_calls_correlate(self):
        sink = NullSink()
        guard = _guard(audit_sink=sink)
        adapter = OpenAIAgentsAdapter(guard)

        # Pre-execute two calls
        await adapter._pre("ToolA", {"x": 1}, "call-A")
        await adapter._pre("ToolB", {"y": 2}, "call-B")

        # Post-execute in reverse order
        await adapter._post("call-B", "result-B")
        await adapter._post("call-A", "result-A")

        # Both should have been matched
        assert len(adapter._pending) == 0

        # Check audit events correlate correctly
        executed = [e for e in sink.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)]
        tool_names = {e.tool_name for e in executed}
        assert "ToolA" in tool_names
        assert "ToolB" in tool_names


# ── Fix 15: tool_use_id in Agno and CrewAI ──


class TestFix15ToolUseId:
    async def test_agno_envelope_has_tool_use_id(self):
        sink = NullSink()
        guard = _guard(audit_sink=sink)
        adapter = AgnoAdapter(guard)

        await adapter._pre("TestTool", {}, "my-call-id")
        # Check the pending tool_call
        tool_call, _ = adapter._pending["my-call-id"]
        assert tool_call.tool_use_id == "my-call-id"

    async def test_crewai_envelope_has_tool_use_id(self):
        import types

        sink = NullSink()
        guard = _guard(audit_sink=sink)
        adapter = CrewAIAdapter(guard)

        ctx = types.SimpleNamespace(tool_name="TestTool", tool_input={})
        await adapter._before_hook(ctx)

        # Pending tool_call should have tool_use_id set
        tool_call = adapter._pending_envelope
        assert tool_call is not None
        assert tool_call.tool_use_id is not None
        assert len(tool_call.tool_use_id) > 0


# ── Fix 16: FileAuditSink async write ──


class TestFix16FileAuditAsync:
    async def test_file_sink_uses_executor(self, tmp_path):
        from edictum.audit import FileAuditSink

        path = tmp_path / "audit.jsonl"
        sink = FileAuditSink(path)
        event = AuditEvent(
            action=AuditAction.CALL_ALLOWED,
            tool_name="TestTool",
        )
        await sink.emit(event)

        content = path.read_text()
        assert "TestTool" in content
        assert "call_allowed" in content


# ── Fix 22: YAML file size limit ──


class TestFix22FileSizeLimit:
    def test_large_file_rejected(self, tmp_path):
        big = tmp_path / "big.yaml"
        big.write_bytes(b"x" * (1_048_576 + 1))
        with pytest.raises(EdictumConfigError, match="Bundle file too large"):
            load_bundle(big)

    def test_normal_file_accepted(self):
        # valid_bundle.yaml is well under 1MB
        data, _ = load_bundle(FIXTURES / "valid_bundle.yaml")
        assert data is not None
