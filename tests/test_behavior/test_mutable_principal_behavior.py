"""Behavior tests for mutable principal (set_principal + principal_resolver).

Each test proves an observable action of the mutable principal feature:
- set_principal() changes enforcement for subsequent calls
- principal_resolver overrides the static principal per tool call
- principal_resolver receives correct (tool_name, tool_input)
- set_principal() preserves session state (attempt counters)
- Edictum.run() honors set_principal and principal_resolver
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from edictum import Edictum, EdictumDenied, Principal
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

REQUIRE_ADMIN_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: require-admin-bundle
defaults:
  mode: enforce
rules:
  - id: require-admin
    type: pre
    tool: "*"
    when:
      principal.role:
        not_equals: "admin"
    then:
      action: block
      message: "Only admin role allowed"
"""


def _make_guard(**overrides):
    defaults = dict(audit_sink=NullAuditSink(), backend=MemoryBackend())
    defaults.update(overrides)
    return Edictum.from_yaml_string(REQUIRE_ADMIN_YAML, **defaults)


def _make_adapter(*, principal=None, principal_resolver=None):
    guard = _make_guard()
    return ClaudeAgentSDKAdapter(
        guard,
        principal=principal,
        principal_resolver=principal_resolver,
    )


def _is_denied(result: dict) -> bool:
    hook = result.get("hookSpecificOutput", {})
    return hook.get("permissionDecision") == "block"


class TestSetPrincipalChangesEnforcement:
    """set_principal() must change enforcement for subsequent calls."""

    async def test_set_principal_changes_enforcement(self):
        """Viewer is denied, then set_principal(admin) allows the next call."""
        adapter = _make_adapter(principal=Principal(role="viewer"))

        # Viewer -> denied
        result = await adapter._pre_tool_use("TestTool", {}, "tc-1")
        assert _is_denied(result), "Viewer should be denied"

        # Switch to admin
        adapter.set_principal(Principal(role="admin"))

        # Admin -> allowed
        result = await adapter._pre_tool_use("TestTool", {}, "tc-2")
        assert not _is_denied(result), "Admin should be allowed after set_principal"


class TestPrincipalResolverOverridesStatic:
    """principal_resolver takes precedence over the static principal."""

    async def test_principal_resolver_overrides_static(self):
        """Static principal is viewer (denied), but resolver returns admin (allowed)."""

        def resolver(tool_name, tool_input):
            return Principal(role="admin")

        adapter = _make_adapter(
            principal=Principal(role="viewer"),
            principal_resolver=resolver,
        )

        result = await adapter._pre_tool_use("TestTool", {}, "tc-1")
        assert not _is_denied(result), "Resolver returning admin should override static viewer principal"


class TestPrincipalResolverReceivesToolContext:
    """principal_resolver must receive (tool_name, tool_input) arguments."""

    async def test_principal_resolver_receives_tool_context(self):
        """The resolver callable receives the correct tool_name and tool_input."""
        spy = MagicMock(return_value=Principal(role="admin"))
        adapter = _make_adapter(principal_resolver=spy)

        tool_input = {"path": "/etc/secrets"}
        await adapter._pre_tool_use("ReadFile", tool_input, "tc-1")

        spy.assert_called_once_with("ReadFile", tool_input)


class TestSetPrincipalPreservesSessionState:
    """set_principal() must not reset session counters."""

    async def test_set_principal_preserves_session_state(self):
        """After 2 calls, set_principal does not reset the attempt counter."""
        adapter = _make_adapter(principal=Principal(role="admin"))

        # Two allowed calls
        await adapter._pre_tool_use("Tool1", {}, "tc-1")
        await adapter._pre_tool_use("Tool2", {}, "tc-2")

        count_before = await adapter._session.attempt_count()
        assert count_before == 2

        # Mutate principal
        adapter.set_principal(Principal(role="admin", user_id="new-user"))

        # Third call
        await adapter._pre_tool_use("Tool3", {}, "tc-3")

        count_after = await adapter._session.attempt_count()
        assert count_after == 3, (
            f"Expected 3 attempts after set_principal, got {count_after}. set_principal must not reset session state."
        )


class TestEdictumSetPrincipal:
    """Edictum.run() must use the updated principal after set_principal()."""

    async def test_edictum_set_principal(self):
        """run() denies viewer, then allows admin after set_principal."""
        guard = _make_guard()
        guard._principal = Principal(role="viewer")

        async def noop(**kwargs):
            return "ok"

        # Viewer -> denied
        with pytest.raises(EdictumDenied):
            await guard.run("TestTool", {}, noop)

        # Switch to admin
        guard.set_principal(Principal(role="admin"))

        # Admin -> allowed
        result = await guard.run("TestTool", {}, noop)
        assert result == "ok"


class TestEdictumPrincipalResolver:
    """Edictum.run() must use principal_resolver when set."""

    async def test_edictum_principal_resolver(self):
        """Resolver returning admin allows the call despite viewer static principal."""

        def resolver(tool_name, tool_input):
            return Principal(role="admin")

        guard = _make_guard()
        guard._principal = Principal(role="viewer")
        guard._principal_resolver = resolver

        async def noop(**kwargs):
            return "ok"

        result = await guard.run("TestTool", {}, noop)
        assert result == "ok", "Resolver returning admin should allow the call"

    async def test_edictum_resolver_deny(self):
        """Resolver returning viewer causes denial despite admin static principal."""

        def resolver(tool_name, tool_input):
            return Principal(role="viewer")

        guard = _make_guard()
        guard._principal = Principal(role="admin")
        guard._principal_resolver = resolver

        async def noop(**kwargs):
            return "ok"

        with pytest.raises(EdictumDenied):
            await guard.run("TestTool", {}, noop)
