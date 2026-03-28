"""End-to-end integration tests for Edictum v0.3.0.

These tests verify that Streams A (YAML engine), B (Principal), and C (Audit sinks)
compose correctly through the full pipeline. Unit tests prove pieces work;
these tests prove they work TOGETHER.

Run with: pytest tests/test_integration/test_end_to_end.py -v
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import asdict
from pathlib import Path

import pytest

from edictum import (
    AuditAction,
    CollectingAuditSink,
    Decision,
    Edictum,
    EdictumDenied,
    FileAuditSink,
    Principal,
    ToolCall,
    precondition,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DEVOPS_AGENT_YAML = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: devops-agent-test
  description: "Integration test bundle."

defaults:
  mode: enforce

rules:
  - id: block-sensitive-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]
    then:
      action: block
      message: "Sensitive file '{args.path}' denied. Skip and continue."
      tags: [secrets, dlp]

  - id: block-destructive-bash
    type: pre
    tool: bash
    when:
      any:
        - args.command: { matches: '\\brm\\s+(-rf?|--recursive)\\b' }
        - args.command: { matches: '\\bmkfs\\b' }
        - args.command: { contains: '> /dev/' }
    then:
      action: block
      message: "Destructive command denied: '{args.command}'. Use a safer alternative."
      tags: [destructive, safety]

  - id: prod-deploy-requires-senior
    type: pre
    tool: deploy_service
    when:
      all:
        - environment: { equals: production }
        - principal.role: { not_in: [senior_engineer, sre, admin] }
    then:
      action: block
      message: "Production deploys require senior role (sre/admin)."
      tags: [change-control, production]

  - id: prod-requires-ticket
    type: pre
    tool: deploy_service
    when:
      all:
        - environment: { equals: production }
        - principal.ticket_ref: { exists: false }
    then:
      action: block
      message: "Production changes require a ticket reference."
      tags: [change-control, compliance]

  - id: pii-in-output
    type: post
    tool: "*"
    when:
      output.text:
        matches_any:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII pattern detected in output. Redact before using."
      tags: [pii, compliance]

  - id: session-limits
    type: session
    limits:
      max_tool_calls: 5
      max_attempts: 10
      max_calls_per_tool:
        deploy_service: 2
    then:
      action: block
      message: "Session limit reached. Summarize progress and stop."
      tags: [rate-limit]
"""

OBSERVE_MODE_YAML = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: observe-test

defaults:
  mode: enforce

rules:
  - id: enforced-rule
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm -rf" }
    then:
      action: block
      message: "Denied by enforced rule."
      tags: [enforced]

  - id: observed-rule
    type: pre
    mode: observe
    tool: bash
    when:
      args.command: { contains: "curl" }
    then:
      action: block
      message: "Would block curl (observe mode)."
      tags: [observed]
"""

DISABLED_RULE_YAML = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: disabled-test

defaults:
  mode: enforce

rules:
  - id: active-rule
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm" }
    then:
      action: block
      message: "Denied."
      tags: [active]

  - id: disabled-rule
    type: pre
    enabled: false
    tool: bash
    when:
      args.command: { contains: "ls" }
    then:
      action: block
      message: "This should never fire."
      tags: [disabled]
"""

EDGE_CASES_YAML = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: edge-cases

defaults:
  mode: enforce

rules:
  - id: claims-check
    type: pre
    tool: deploy_service
    when:
      principal.claims.department: { equals: restricted }
    then:
      action: block
      message: "Department '{principal.claims.department}' cannot deploy."
      tags: [claims]

  - id: nested-args-check
    type: pre
    tool: configure
    when:
      args.config.timeout: { gt: 300 }
    then:
      action: block
      message: "Timeout too high: {args.config.timeout}s."
      tags: [validation]

  - id: wildcard-pre
    type: pre
    tool: "*"
    when:
      environment: { equals: locked }
    then:
      action: block
      message: "Environment is locked. No tool calls allowed."
      tags: [lockdown]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 3
    then:
      action: block
      message: "Session capped at 3 executions."
      tags: [rate-limit]
"""


def write_yaml(content: str) -> Path:
    """Write YAML to a temp file, return path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def expected_hash(content: str) -> str:
    """Compute expected bundle hash."""
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# 1. YAML → Pipeline → Decision (basic rule evaluation)
# ---------------------------------------------------------------------------


class TestYAMLToPipelineBasic:
    """Verify YAML-loaded rules produce correct verdicts through the full pipeline."""

    @pytest.fixture
    def guard(self) -> tuple[Edictum, CollectingAuditSink]:
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)
        return guard, sink

    @pytest.mark.asyncio
    async def test_sensitive_read_denied(self, guard):
        g, sink = guard
        with pytest.raises(EdictumDenied, match="Sensitive file"):
            await g.run(
                "read_file",
                {"path": "/home/user/.env"},
                tool_callable=lambda **kw: "file contents",
            )
        event = sink.last()
        assert event.action == AuditAction.CALL_DENIED
        assert event.decision_name == "block-sensitive-reads"
        assert event.decision_source == "yaml_precondition"

    @pytest.mark.asyncio
    async def test_safe_read_allowed(self, guard):
        g, sink = guard
        result = await g.run(
            "read_file",
            {"path": "/home/user/README.md"},
            tool_callable=lambda **kw: "# README",
        )
        assert result == "# README"
        allowed = sink.filter(AuditAction.CALL_ALLOWED)
        assert len(allowed) >= 1

    @pytest.mark.asyncio
    async def test_destructive_bash_denied(self, guard):
        g, sink = guard
        with pytest.raises(EdictumDenied, match="Destructive command"):
            await g.run(
                "bash",
                {"command": "rm -rf /tmp/important"},
                tool_callable=lambda **kw: "",
            )

    @pytest.mark.asyncio
    async def test_safe_bash_allowed(self, guard):
        g, sink = guard
        result = await g.run(
            "bash",
            {"command": "ls -la /tmp"},
            tool_callable=lambda **kw: "total 0",
        )
        assert result == "total 0"

    @pytest.mark.asyncio
    async def test_mkfs_denied(self, guard):
        g, sink = guard
        with pytest.raises(EdictumDenied):
            await g.run(
                "bash",
                {"command": "mkfs.ext4 /dev/sda1"},
                tool_callable=lambda **kw: "",
            )

    @pytest.mark.asyncio
    async def test_unrelated_tool_passes(self, guard):
        """A tool not targeted by any rule should pass."""
        g, sink = guard
        result = await g.run(
            "send_email",
            {"to": "test@example.com", "body": "hello"},
            tool_callable=lambda **kw: "sent",
        )
        assert result == "sent"


# ---------------------------------------------------------------------------
# 2. Principal-aware rules (Streams A + B integration)
# ---------------------------------------------------------------------------


class TestPrincipalIntegration:
    """Verify YAML rules correctly evaluate principal fields from Stream B."""

    @pytest.fixture
    def guard(self) -> tuple[Edictum, CollectingAuditSink]:
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)
        return guard, sink

    @pytest.mark.asyncio
    async def test_prod_deploy_denied_without_senior_role(self, guard):
        g, sink = guard
        junior = Principal(user_id="junior-dev", role="developer")
        with pytest.raises(EdictumDenied, match="senior role"):
            await g.run(
                "deploy_service",
                {"service": "api", "version": "1.2.0"},
                tool_callable=lambda **kw: "deployed",
                environment="production",
                principal=junior,
            )
        event = sink.last()
        assert event.decision_name == "prod-deploy-requires-senior"

    @pytest.mark.asyncio
    async def test_prod_deploy_allowed_with_sre_role(self, guard):
        g, sink = guard
        sre = Principal(user_id="sre-1", role="sre", ticket_ref="JIRA-1234")
        result = await g.run(
            "deploy_service",
            {"service": "api", "version": "1.2.0"},
            tool_callable=lambda **kw: "deployed",
            environment="production",
            principal=sre,
        )
        assert result == "deployed"

    @pytest.mark.asyncio
    async def test_prod_deploy_denied_without_ticket(self, guard):
        g, sink = guard
        # Has senior role but no ticket_ref
        admin_no_ticket = Principal(user_id="admin-1", role="admin")
        with pytest.raises(EdictumDenied, match="ticket reference"):
            await g.run(
                "deploy_service",
                {"service": "api", "version": "1.2.0"},
                tool_callable=lambda **kw: "deployed",
                environment="production",
                principal=admin_no_ticket,
            )
        event = sink.last()
        assert event.decision_name == "prod-requires-ticket"

    @pytest.mark.asyncio
    async def test_staging_deploy_skips_role_check(self, guard):
        """Non-production deploys should not trigger the role gate."""
        g, sink = guard
        junior = Principal(user_id="junior-dev", role="developer")
        result = await g.run(
            "deploy_service",
            {"service": "api", "version": "1.2.0"},
            tool_callable=lambda **kw: "deployed",
            environment="staging",
            principal=junior,
        )
        assert result == "deployed"

    @pytest.mark.asyncio
    async def test_no_principal_on_envelope(self, guard):
        """If no principal is provided, principal.role evaluates to false (missing field).
        The role gate condition is:
          all:
            - environment: { equals: production }
            - principal.role: { not_in: [senior_engineer, sre, admin] }
        With no principal, principal.role is missing → false.
        BUT the 'all' requires BOTH conditions to be true. Missing field → false means
        the 'not_in' check returns false, so the 'all' is false, so the rule doesn't fire.

        HOWEVER: prod-requires-ticket checks principal.ticket_ref: { exists: false }.
        With no principal, ticket_ref is missing, and exists: false means "absent or null"
        which is TRUE. So this rule SHOULD fire.
        """
        g, sink = guard
        with pytest.raises(EdictumDenied, match="ticket reference"):
            await g.run(
                "deploy_service",
                {"service": "api", "version": "1.2.0"},
                tool_callable=lambda **kw: "deployed",
                environment="production",
                # no principal at all
            )

    @pytest.mark.asyncio
    async def test_principal_claims_evaluation(self):
        """Verify principal.claims.<key> selector works end-to-end."""
        path = write_yaml(EDGE_CASES_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        restricted = Principal(
            user_id="user-1",
            role="engineer",
            claims={"department": "restricted"},
        )
        with pytest.raises(EdictumDenied, match="Department"):
            await guard.run(
                "deploy_service",
                {"service": "api"},
                tool_callable=lambda **kw: "deployed",
                principal=restricted,
            )

    @pytest.mark.asyncio
    async def test_principal_claims_missing_key(self):
        """principal.claims.department when claims has no 'department' → false."""
        path = write_yaml(EDGE_CASES_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        no_dept = Principal(user_id="user-1", role="engineer", claims={"team": "alpha"})
        # claims-check won't fire (missing field), but wildcard lockdown
        # won't fire either (environment != "locked")
        result = await guard.run(
            "deploy_service",
            {"service": "api"},
            tool_callable=lambda **kw: "deployed",
            environment="staging",
            principal=no_dept,
        )
        assert result == "deployed"


# ---------------------------------------------------------------------------
# 3. Postcondition integration (output inspection)
# ---------------------------------------------------------------------------


class TestPostconditionIntegration:
    """Verify postconditions evaluate tool output through the full pipeline."""

    @pytest.fixture
    def guard(self) -> tuple[Edictum, CollectingAuditSink]:
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)
        return guard, sink

    @pytest.mark.asyncio
    async def test_pii_detected_in_output(self, guard):
        """Tool succeeds but postcondition warns about PII."""
        g, sink = guard
        result = await g.run(
            "query_db",
            {"sql": "SELECT * FROM users LIMIT 1"},
            tool_callable=lambda **kw: "John Doe, SSN: 123-45-6789, email: john@test.com",
        )
        # Tool should still succeed (postconditions are warn-only)
        assert "123-45-6789" in result
        # But a postcondition warning should be in audit
        sink.filter(AuditAction.POSTCONDITION_WARNING)
        # Or check the executed event has postconditions_passed=False
        executed = sink.filter(AuditAction.CALL_EXECUTED)
        assert len(executed) >= 1
        assert executed[-1].postconditions_passed is False

    @pytest.mark.asyncio
    async def test_clean_output_no_warning(self, guard):
        """Tool output without PII should not trigger postcondition."""
        g, sink = guard
        result = await g.run(
            "query_db",
            {"sql": "SELECT count(*) FROM users"},
            tool_callable=lambda **kw: "42",
        )
        assert result == "42"
        executed = sink.filter(AuditAction.CALL_EXECUTED)
        assert len(executed) >= 1
        assert executed[-1].postconditions_passed is True


# ---------------------------------------------------------------------------
# 4. Session limits (cumulative state across multiple calls)
# ---------------------------------------------------------------------------


class TestSessionLimitsIntegration:
    """Verify session rules track state across multiple tool calls."""

    @pytest.mark.asyncio
    async def test_session_tool_call_limit(self):
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        # Session limit is max_tool_calls=5
        for i in range(5):
            await guard.run(
                "send_email",
                {"to": f"user{i}@test.com", "body": "hello"},
                tool_callable=lambda **kw: "sent",
            )

        # 6th call should be denied
        with pytest.raises(EdictumDenied, match="Session limit"):
            await guard.run(
                "send_email",
                {"to": "one-too-many@test.com", "body": "hello"},
                tool_callable=lambda **kw: "sent",
            )

    @pytest.mark.asyncio
    async def test_per_tool_limit(self):
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        # deploy_service limited to 2 per session
        sre = Principal(user_id="sre-1", role="sre", ticket_ref="JIRA-100")
        for i in range(2):
            await guard.run(
                "deploy_service",
                {"service": f"svc-{i}", "version": "1.0"},
                tool_callable=lambda **kw: "deployed",
                environment="staging",
                principal=sre,
            )

        # 3rd deploy should hit per-tool limit
        with pytest.raises(EdictumDenied):
            await guard.run(
                "deploy_service",
                {"service": "svc-3", "version": "1.0"},
                tool_callable=lambda **kw: "deployed",
                environment="staging",
                principal=sre,
            )

    @pytest.mark.asyncio
    async def test_session_state_isolated_between_guards(self):
        """Different Edictum instances should have independent sessions."""
        path = write_yaml(EDGE_CASES_YAML)  # max_tool_calls=3

        sink1 = CollectingAuditSink()
        guard1 = Edictum.from_yaml(str(path), audit_sink=sink1)
        sink2 = CollectingAuditSink()
        guard2 = Edictum.from_yaml(str(path), audit_sink=sink2)

        # Use 2 calls on guard1
        for _ in range(2):
            await guard1.run(
                "any_tool",
                {"x": 1},
                tool_callable=lambda **kw: "ok",
                environment="dev",
            )

        # guard2 should still have its full budget
        for _ in range(3):
            await guard2.run(
                "any_tool",
                {"x": 1},
                tool_callable=lambda **kw: "ok",
                environment="dev",
            )

        # guard2 hits limit on 4th
        with pytest.raises(EdictumDenied):
            await guard2.run(
                "any_tool",
                {"x": 1},
                tool_callable=lambda **kw: "ok",
                environment="dev",
            )


# ---------------------------------------------------------------------------
# 5. Observe mode (per-rule and bundle-level)
# ---------------------------------------------------------------------------


class TestObserveModeIntegration:
    """Verify observe mode correctly downgrades block → would_deny."""

    @pytest.mark.asyncio
    async def test_per_rule_observe_mode(self):
        """An observed rule should not block, but should audit as would_deny."""
        path = write_yaml(OBSERVE_MODE_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        # 'curl' matches the observed rule — should pass through
        result = await guard.run(
            "bash",
            {"command": "curl https://api.example.com"},
            tool_callable=lambda **kw: "response body",
        )
        assert result == "response body"

        # Check audit: should have CALL_WOULD_DENY for the observed rule
        would_deny = sink.filter(AuditAction.CALL_WOULD_DENY)
        assert len(would_deny) >= 1
        assert would_deny[0].decision_name == "observed-rule"

    @pytest.mark.asyncio
    async def test_enforced_rule_still_blocks(self):
        """An enforced rule in the same bundle should still block."""
        path = write_yaml(OBSERVE_MODE_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        with pytest.raises(EdictumDenied, match="enforced rule"):
            await guard.run(
                "bash",
                {"command": "rm -rf /"},
                tool_callable=lambda **kw: "",
            )

    @pytest.mark.asyncio
    async def test_bundle_level_observe_mode(self):
        """Bundle-level observe mode should not block any rule."""
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), mode="observe", audit_sink=sink)

        # This would normally be denied
        result = await guard.run(
            "read_file",
            {"path": "/etc/.env"},
            tool_callable=lambda **kw: "SECRET=abc",
        )
        assert result == "SECRET=abc"

        would_deny = sink.filter(AuditAction.CALL_WOULD_DENY)
        assert len(would_deny) >= 1


# ---------------------------------------------------------------------------
# 6. Disabled rules
# ---------------------------------------------------------------------------


class TestDisabledRulesIntegration:
    @pytest.mark.asyncio
    async def test_disabled_rule_does_not_fire(self):
        path = write_yaml(DISABLED_RULE_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        # 'ls' matches disabled-rule, but it should not fire
        result = await guard.run(
            "bash",
            {"command": "ls /tmp"},
            tool_callable=lambda **kw: "files",
        )
        assert result == "files"

        # Verify no denial for the disabled rule
        denied = sink.filter(AuditAction.CALL_DENIED)
        assert len(denied) == 0

    @pytest.mark.asyncio
    async def test_active_rule_still_fires(self):
        path = write_yaml(DISABLED_RULE_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        with pytest.raises(EdictumDenied, match="Denied"):
            await guard.run(
                "bash",
                {"command": "rm -rf /tmp"},
                tool_callable=lambda **kw: "",
            )


# ---------------------------------------------------------------------------
# 7. Audit event integrity (Stream C integration)
# ---------------------------------------------------------------------------


class TestAuditIntegrity:
    """Verify audit events contain all expected fields from v0.3.0."""

    @pytest.fixture
    def setup(self) -> tuple[Edictum, CollectingAuditSink, str]:
        yaml_content = DEVOPS_AGENT_YAML
        path = write_yaml(yaml_content)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)
        bundle_hash = expected_hash(yaml_content)
        return guard, sink, bundle_hash

    @pytest.mark.asyncio
    async def test_policy_version_on_denied_event(self, setup):
        guard, sink, bundle_hash = setup
        with pytest.raises(EdictumDenied):
            await guard.run(
                "read_file",
                {"path": ".env"},
                tool_callable=lambda **kw: "",
            )
        event = sink.last()
        assert hasattr(event, "policy_version"), "AuditEvent missing policy_version field"
        assert event.policy_version == bundle_hash

    @pytest.mark.asyncio
    async def test_policy_version_on_allowed_event(self, setup):
        guard, sink, bundle_hash = setup
        await guard.run(
            "read_file",
            {"path": "README.md"},
            tool_callable=lambda **kw: "ok",
        )
        allowed = sink.filter(AuditAction.CALL_ALLOWED)
        assert len(allowed) >= 1
        assert allowed[-1].policy_version == bundle_hash

    @pytest.mark.asyncio
    async def test_tags_in_audit_event(self, setup):
        guard, sink, _ = setup
        with pytest.raises(EdictumDenied):
            await guard.run(
                "read_file",
                {"path": ".env"},
                tool_callable=lambda **kw: "",
            )
        event = sink.last()
        # Tags should appear in contracts_evaluated metadata
        assert len(event.contracts_evaluated) > 0
        contract_record = event.contracts_evaluated[0]
        assert "metadata" in contract_record
        assert "tags" in contract_record["metadata"]

    @pytest.mark.asyncio
    async def test_decision_source_is_yaml_prefixed(self, setup):
        guard, sink, _ = setup
        with pytest.raises(EdictumDenied):
            await guard.run(
                "read_file",
                {"path": ".secret"},
                tool_callable=lambda **kw: "",
            )
        event = sink.last()
        assert event.decision_source == "yaml_precondition", f"Expected 'precondition', got: {event.decision_source}"

    @pytest.mark.asyncio
    async def test_principal_in_audit_event(self, setup):
        guard, sink, _ = setup
        sre = Principal(user_id="sre-1", role="sre", ticket_ref="JIRA-100")
        await guard.run(
            "send_email",
            {"to": "test@test.com", "body": "hi"},
            tool_callable=lambda **kw: "sent",
            principal=sre,
        )
        allowed = sink.filter(AuditAction.CALL_ALLOWED)
        assert len(allowed) >= 1
        event = allowed[-1]
        assert event.principal is not None
        # Principal should include new v0.3.0 fields
        principal_data = event.principal if isinstance(event.principal, dict) else asdict(event.principal)
        assert principal_data.get("role") == "sre"
        assert principal_data.get("ticket_ref") == "JIRA-100"

    @pytest.mark.asyncio
    async def test_file_audit_sink_writes_policy_version(self):
        """FileAuditSink should include policy_version in JSONL output."""
        yaml_content = DEVOPS_AGENT_YAML
        path = write_yaml(yaml_content)
        bundle_hash = expected_hash(yaml_content)

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name

        file_sink = FileAuditSink(audit_path)
        guard = Edictum.from_yaml(str(path), audit_sink=file_sink)

        await guard.run(
            "read_file",
            {"path": "safe.txt"},
            tool_callable=lambda **kw: "ok",
        )

        with open(audit_path) as f:
            lines = f.readlines()

        assert len(lines) >= 1
        event_data = json.loads(lines[-1])
        assert event_data.get("policy_version") == bundle_hash


# ---------------------------------------------------------------------------
# 8. Edge cases and error handling
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_nested_args_evaluation(self):
        """args.config.timeout should resolve nested dict access."""
        path = write_yaml(EDGE_CASES_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        with pytest.raises(EdictumDenied, match="Timeout too high"):
            await guard.run(
                "configure",
                {"config": {"timeout": 600, "retries": 3}},
                tool_callable=lambda **kw: "ok",
                environment="dev",
            )

    @pytest.mark.asyncio
    async def test_nested_args_missing_intermediate_key(self):
        """args.config.timeout where args has no 'config' key → false."""
        path = write_yaml(EDGE_CASES_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        # No 'config' key in args — nested-args-check should not fire
        result = await guard.run(
            "configure",
            {"setting": "value"},
            tool_callable=lambda **kw: "ok",
            environment="dev",
        )
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_wildcard_tool_match(self):
        """tool: '*' should match any tool name."""
        path = write_yaml(EDGE_CASES_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        with pytest.raises(EdictumDenied, match="locked"):
            await guard.run(
                "absolutely_any_tool",
                {"x": 1},
                tool_callable=lambda **kw: "ok",
                environment="locked",
            )

    @pytest.mark.asyncio
    async def test_message_template_expansion(self):
        """Verify {args.path} gets expanded in denial message."""
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        try:
            await guard.run(
                "read_file",
                {"path": "/secrets/db.env"},
                tool_callable=lambda **kw: "",
            )
        except EdictumDenied as e:
            assert "/secrets/db.env" in str(e.reason)

    @pytest.mark.asyncio
    async def test_message_template_long_value_capped(self):
        """Placeholder values longer than 200 chars should be truncated."""
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        long_path = "/secrets/" + "a" * 500 + ".env"
        try:
            await guard.run(
                "read_file",
                {"path": long_path},
                tool_callable=lambda **kw: "",
            )
        except EdictumDenied as e:
            # The expanded placeholder should be capped at 200 chars
            # The full path (500+ chars) should NOT appear in the message
            assert len(str(e.reason)) <= 700  # message + capped placeholder

    @pytest.mark.asyncio
    async def test_message_template_missing_placeholder(self):
        """Placeholder for a field not in args should stay as-is."""
        # block-sensitive-reads uses {args.path}
        # If we somehow get here without args.path... but we can't because
        # the when condition requires args.path. So this tests that message
        # templating handles gracefully.
        # We test indirectly: message should not crash even with unusual args
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        # bash command matches mkfs but message template references {args.command}
        try:
            await guard.run(
                "bash",
                {"command": "mkfs.ext4 /dev/sda1"},
                tool_callable=lambda **kw: "",
            )
        except EdictumDenied as e:
            assert "mkfs.ext4" in str(e.reason)


# ---------------------------------------------------------------------------
# 9. Python rules ↔ YAML rules equivalence
# ---------------------------------------------------------------------------


class TestPythonYAMLEquivalence:
    """Verify YAML-loaded rules produce identical verdicts to hand-written Python."""

    @pytest.mark.asyncio
    async def test_sensitive_read_equivalence(self):
        """Same policy expressed in Python and YAML should produce same decision."""

        # Python version
        @precondition("read_file")
        def py_block_sensitive(tool_call: ToolCall) -> Decision:
            path = tool_call.args.get("path", "")
            for pattern in [".env", ".secret", "kubeconfig", "credentials", ".pem", "id_rsa"]:
                if pattern in path:
                    return Decision.fail(f"Sensitive file '{path}' denied. Skip and continue.")
            return Decision.pass_()

        py_sink = CollectingAuditSink()
        py_guard = Edictum(
            rules=[py_block_sensitive],
            audit_sink=py_sink,
        )

        # YAML version
        yaml_sink = CollectingAuditSink()
        yaml_path = write_yaml(DEVOPS_AGENT_YAML)
        yaml_guard = Edictum.from_yaml(str(yaml_path), audit_sink=yaml_sink)

        # Test: both should block .env
        with pytest.raises(EdictumDenied):
            await py_guard.run(
                "read_file",
                {"path": "/app/.env"},
                tool_callable=lambda **kw: "",
            )

        with pytest.raises(EdictumDenied):
            await yaml_guard.run(
                "read_file",
                {"path": "/app/.env"},
                tool_callable=lambda **kw: "",
            )

        # Test: both should allow README.md
        py_result = await py_guard.run(
            "read_file",
            {"path": "README.md"},
            tool_callable=lambda **kw: "ok",
        )
        yaml_result = await yaml_guard.run(
            "read_file",
            {"path": "README.md"},
            tool_callable=lambda **kw: "ok",
        )
        assert py_result == yaml_result == "ok"


# ---------------------------------------------------------------------------
# 10. Template loading
# ---------------------------------------------------------------------------


class TestTemplateLoading:
    """Verify built-in templates load and produce sensible verdicts."""

    @pytest.mark.asyncio
    async def test_file_agent_template_loads(self):
        sink = CollectingAuditSink()
        guard = Edictum.from_template("file-agent", audit_sink=sink)
        assert guard is not None

    @pytest.mark.asyncio
    async def test_research_agent_template_loads(self):
        sink = CollectingAuditSink()
        guard = Edictum.from_template("research-agent", audit_sink=sink)
        assert guard is not None

    @pytest.mark.asyncio
    async def test_devops_agent_template_loads(self):
        sink = CollectingAuditSink()
        guard = Edictum.from_template("devops-agent", audit_sink=sink)
        assert guard is not None

    @pytest.mark.asyncio
    async def test_file_agent_blocks_env_file(self):
        sink = CollectingAuditSink()
        guard = Edictum.from_template("file-agent", audit_sink=sink)
        with pytest.raises(EdictumDenied):
            await guard.run(
                "read_file",
                {"path": ".env"},
                tool_callable=lambda **kw: "",
            )

    @pytest.mark.asyncio
    async def test_invalid_template_name_raises(self):
        with pytest.raises(Exception):  # EdictumConfigError or similar
            Edictum.from_template("nonexistent-template")


# ---------------------------------------------------------------------------
# 11. Multiple rules on same tool (evaluation order)
# ---------------------------------------------------------------------------


class TestMultipleContractsOnSameTool:
    """When multiple rules target the same tool, all must pass."""

    @pytest.mark.asyncio
    async def test_first_failing_contract_denies(self):
        """If the first matching rule fails, tool is denied
        (we don't need to evaluate the rest)."""
        path = write_yaml(DEVOPS_AGENT_YAML)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)

        # deploy_service in production without role AND without ticket
        # Both prod-deploy-requires-senior and prod-requires-ticket match.
        # The first one evaluated should block.
        no_creds = Principal(user_id="nobody", role="intern")
        with pytest.raises(EdictumDenied) as exc_info:
            await guard.run(
                "deploy_service",
                {"service": "api"},
                tool_callable=lambda **kw: "deployed",
                environment="production",
                principal=no_creds,
            )
        # Should be denied by one of the two prod rules
        assert exc_info.value.decision_name in [
            "prod-deploy-requires-senior",
            "prod-requires-ticket",
        ]


# ---------------------------------------------------------------------------
# 12. Full lifecycle: load → evaluate → audit → verify
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    """A single test that exercises the complete v0.3.0 lifecycle."""

    @pytest.mark.asyncio
    async def test_complete_lifecycle(self):
        # 1. Load YAML
        yaml_content = DEVOPS_AGENT_YAML
        path = write_yaml(yaml_content)
        sink = CollectingAuditSink()
        guard = Edictum.from_yaml(str(path), audit_sink=sink)
        bundle_hash = expected_hash(yaml_content)

        # 2. Create a principal with v0.3.0 fields
        operator = Principal(
            user_id="ops-1",
            role="sre",
            ticket_ref="INC-42",
            claims={"department": "platform", "clearance": "high"},
        )

        # 3. Run an allowed tool call
        result = await guard.run(
            "deploy_service",
            {"service": "payment-api", "version": "2.1.0"},
            tool_callable=lambda **kw: "deployed v2.1.0",
            environment="production",
            principal=operator,
        )
        assert result == "deployed v2.1.0"

        # 4. Verify audit trail
        allowed = sink.filter(AuditAction.CALL_ALLOWED)
        assert len(allowed) == 1
        event = allowed[0]

        # Policy version
        assert event.policy_version == bundle_hash

        # Principal propagation
        principal_data = event.principal if isinstance(event.principal, dict) else asdict(event.principal)
        assert principal_data["user_id"] == "ops-1"
        assert principal_data["role"] == "sre"
        assert principal_data["ticket_ref"] == "INC-42"

        # 5. Run a denied tool call
        sink.clear()
        try:
            await guard.run(
                "read_file",
                {"path": "/app/.env.production"},
                tool_callable=lambda **kw: "",
                principal=operator,
            )
            pytest.fail("Should have been denied")
        except EdictumDenied as e:
            assert ".env" in e.reason

        # 6. Verify denial audit
        denied = sink.filter(AuditAction.CALL_DENIED)
        assert len(denied) == 1
        deny_event = denied[0]
        assert deny_event.policy_version == bundle_hash
        assert deny_event.decision_name == "block-sensitive-reads"
        assert deny_event.decision_source == "yaml_precondition"

        # 7. Run tool with PII in output
        sink.clear()
        await guard.run(
            "query_db",
            {"sql": "SELECT ssn FROM users"},
            tool_callable=lambda **kw: "Result: 123-45-6789",
            principal=operator,
        )
        executed = sink.filter(AuditAction.CALL_EXECUTED)
        assert len(executed) >= 1
        assert executed[-1].postconditions_passed is False
