"""Behavior tests for Edictum._guard reload() observe-mode handling.

Covers bug #80: reload() did not reset observe-mode rule lists,
leaving stale observe-mode rules from the previous bundle.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from edictum import Edictum
from edictum.envelope import ToolCall
from edictum.rules import Decision

# -- Valid YAML fixtures (pass schema validation) ----------------------------

_BUNDLE_A = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bundle-a
defaults:
  mode: enforce
rules:
  - id: enforced-pre-a
    type: pre
    tool: "*"
    when:
      args.forbidden: {equals: true}
    then:
      action: block
      message: "Denied by bundle A precondition."
"""

_BUNDLE_B = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: bundle-b
defaults:
  mode: enforce
rules:
  - id: enforced-pre-b
    type: pre
    tool: "read_file"
    when:
      args.path: {contains: "/etc"}
    then:
      action: block
      message: "Denied by bundle B precondition."
"""


def _envelope(tool: str = "test_tool", **args) -> ToolCall:
    return ToolCall(tool_name=tool, args=args)


def _make_observe_precondition(rule_id: str) -> object:
    """Create a minimal observe-mode precondition callable with edictum metadata."""

    def fn(tool_call: ToolCall) -> Decision:
        return Decision.pass_()

    fn.__name__ = rule_id
    fn._edictum_type = "precondition"
    fn._edictum_tool = "*"
    fn._edictum_when = None
    fn._edictum_mode = "observe"
    fn._edictum_id = rule_id
    fn._edictum_source = "yaml_precondition"
    fn._edictum_effect = "block"
    fn._edictum_observe = True
    return fn


def _make_observe_postcondition(rule_id: str) -> object:
    """Create a minimal observe-mode postcondition callable with edictum metadata."""

    def fn(tool_call: ToolCall, response) -> Decision:
        return Decision.pass_()

    fn.__name__ = rule_id
    fn._edictum_type = "postcondition"
    fn._edictum_tool = "*"
    fn._edictum_when = None
    fn._edictum_mode = "observe"
    fn._edictum_id = rule_id
    fn._edictum_source = "yaml_postcondition"
    fn._edictum_effect = "warn"
    fn._edictum_observe = True
    return fn


def _make_observe_session_contract(rule_id: str) -> object:
    """Create a minimal observe-mode session rule callable with edictum metadata."""

    async def fn(session) -> Decision:
        return Decision.pass_()

    fn.__name__ = rule_id
    fn._edictum_type = "session_contract"
    fn._edictum_mode = "observe"
    fn._edictum_id = rule_id
    fn._edictum_source = "yaml_session"
    fn._edictum_observe = True
    return fn


def _make_observe_sandbox(rule_id: str) -> object:
    """Create a minimal observe-mode sandbox callable with edictum metadata."""

    def fn(tool_call: ToolCall) -> Decision:
        return Decision.pass_()

    fn.__name__ = rule_id
    fn._edictum_type = "sandbox"
    fn._edictum_tools = ["*"]
    fn._edictum_mode = "observe"
    fn._edictum_id = rule_id
    fn._edictum_source = "yaml_sandbox"
    fn._edictum_effect = "block"
    fn._edictum_observe = True
    return fn


@pytest.mark.asyncio
async def test_reload_clears_stale_observe_preconditions():
    """Observe-mode preconditions from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    # Inject observe-mode preconditions as if set by the composer/server
    observe = _make_observe_precondition("old-observe-pre")
    guard._state = replace(
        guard._state,
        observe_preconditions=guard._state.observe_preconditions + (observe,),
    )
    assert len(guard.get_observe_preconditions(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_observe_preconditions(env) == []


@pytest.mark.asyncio
async def test_reload_clears_stale_observe_postconditions():
    """Observe-mode postconditions from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    observe = _make_observe_postcondition("old-observe-post")
    guard._state = replace(
        guard._state,
        observe_postconditions=guard._state.observe_postconditions + (observe,),
    )
    assert len(guard.get_observe_postconditions(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_observe_postconditions(env) == []


@pytest.mark.asyncio
async def test_reload_clears_stale_observe_session_contracts():
    """Observe-mode session rules from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)

    observe = _make_observe_session_contract("old-observe-session")
    guard._state = replace(
        guard._state,
        observe_session_contracts=guard._state.observe_session_contracts + (observe,),
    )
    assert len(guard.get_observe_session_contracts()) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_observe_session_contracts() == []


@pytest.mark.asyncio
async def test_reload_clears_stale_observe_sandbox_contracts():
    """Observe-mode sandbox rules from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    observe = _make_observe_sandbox("old-observe-sandbox")
    guard._state = replace(
        guard._state,
        observe_sandbox_contracts=guard._state.observe_sandbox_contracts + (observe,),
    )
    assert len(guard.get_observe_sandbox_contracts(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_observe_sandbox_contracts(env) == []


@pytest.mark.asyncio
async def test_reload_clears_all_four_observe_lists_simultaneously():
    """All four observe-mode lists must be cleared in a single reload() call."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    # Populate all four observe-mode lists via frozen state replacement
    guard._state = replace(
        guard._state,
        observe_preconditions=guard._state.observe_preconditions + (_make_observe_precondition("sp"),),
        observe_postconditions=guard._state.observe_postconditions + (_make_observe_postcondition("spo"),),
        observe_session_contracts=guard._state.observe_session_contracts + (_make_observe_session_contract("ss"),),
        observe_sandbox_contracts=guard._state.observe_sandbox_contracts + (_make_observe_sandbox("ssb"),),
    )

    assert len(guard.get_observe_preconditions(env)) == 1
    assert len(guard.get_observe_postconditions(env)) == 1
    assert len(guard.get_observe_session_contracts()) == 1
    assert len(guard.get_observe_sandbox_contracts(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_observe_preconditions(env) == []
    assert guard.get_observe_postconditions(env) == []
    assert guard.get_observe_session_contracts() == []
    assert guard.get_observe_sandbox_contracts(env) == []


@pytest.mark.asyncio
async def test_reload_enforced_lists_updated_correctly():
    """Enforced rules must reflect the new bundle after reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    # Verify initial enforced state
    assert len(guard.get_preconditions(env)) == 1
    assert guard.get_preconditions(env)[0]._edictum_id == "enforced-pre-a"

    await guard.reload(_BUNDLE_B)

    # Wildcard tool_call should not match the tool-specific rule
    assert len(guard.get_preconditions(env)) == 0

    # Tool-specific tool_call should match
    rf_env = _envelope(tool="read_file")
    pre = guard.get_preconditions(rf_env)
    assert len(pre) == 1
    assert pre[0]._edictum_id == "enforced-pre-b"
