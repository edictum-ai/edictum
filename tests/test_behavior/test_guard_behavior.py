"""Behavior tests for Edictum._guard reload() observe-mode handling.

Covers bug #80: reload() did not reset observe-mode (shadow) contract lists,
leaving stale shadow contracts from the previous bundle.
"""

from __future__ import annotations

import pytest

from edictum import Edictum
from edictum.contracts import Verdict
from edictum.envelope import ToolEnvelope

# -- Valid YAML fixtures (pass schema validation) ----------------------------

_BUNDLE_A = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: bundle-a
defaults:
  mode: enforce
contracts:
  - id: enforced-pre-a
    type: pre
    tool: "*"
    when:
      args.forbidden: {equals: true}
    then:
      effect: deny
      message: "Denied by bundle A precondition."
"""

_BUNDLE_B = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: bundle-b
defaults:
  mode: enforce
contracts:
  - id: enforced-pre-b
    type: pre
    tool: "read_file"
    when:
      args.path: {contains: "/etc"}
    then:
      effect: deny
      message: "Denied by bundle B precondition."
"""


def _envelope(tool: str = "test_tool", **args) -> ToolEnvelope:
    return ToolEnvelope(tool_name=tool, args=args)


def _make_shadow_precondition(contract_id: str) -> object:
    """Create a minimal shadow precondition callable with edictum metadata."""

    def fn(envelope: ToolEnvelope) -> Verdict:
        return Verdict.pass_()

    fn.__name__ = contract_id
    fn._edictum_type = "precondition"
    fn._edictum_tool = "*"
    fn._edictum_when = None
    fn._edictum_mode = "observe"
    fn._edictum_id = contract_id
    fn._edictum_source = "yaml_precondition"
    fn._edictum_effect = "deny"
    fn._edictum_shadow = True
    return fn


def _make_shadow_postcondition(contract_id: str) -> object:
    """Create a minimal shadow postcondition callable with edictum metadata."""

    def fn(envelope: ToolEnvelope, response) -> Verdict:
        return Verdict.pass_()

    fn.__name__ = contract_id
    fn._edictum_type = "postcondition"
    fn._edictum_tool = "*"
    fn._edictum_when = None
    fn._edictum_mode = "observe"
    fn._edictum_id = contract_id
    fn._edictum_source = "yaml_postcondition"
    fn._edictum_effect = "warn"
    fn._edictum_shadow = True
    return fn


def _make_shadow_session_contract(contract_id: str) -> object:
    """Create a minimal shadow session contract callable with edictum metadata."""

    async def fn(session) -> Verdict:
        return Verdict.pass_()

    fn.__name__ = contract_id
    fn._edictum_type = "session_contract"
    fn._edictum_mode = "observe"
    fn._edictum_id = contract_id
    fn._edictum_source = "yaml_session"
    fn._edictum_shadow = True
    return fn


def _make_shadow_sandbox(contract_id: str) -> object:
    """Create a minimal shadow sandbox callable with edictum metadata."""

    def fn(envelope: ToolEnvelope) -> Verdict:
        return Verdict.pass_()

    fn.__name__ = contract_id
    fn._edictum_type = "sandbox"
    fn._edictum_tools = ["*"]
    fn._edictum_mode = "observe"
    fn._edictum_id = contract_id
    fn._edictum_source = "yaml_sandbox"
    fn._edictum_effect = "deny"
    fn._edictum_shadow = True
    return fn


@pytest.mark.asyncio
async def test_reload_clears_stale_shadow_preconditions():
    """Shadow preconditions from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    # Inject shadow preconditions as if set by the composer/server
    guard._shadow_preconditions.append(_make_shadow_precondition("old-shadow-pre"))
    assert len(guard.get_shadow_preconditions(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_shadow_preconditions(env) == []


@pytest.mark.asyncio
async def test_reload_clears_stale_shadow_postconditions():
    """Shadow postconditions from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    guard._shadow_postconditions.append(_make_shadow_postcondition("old-shadow-post"))
    assert len(guard.get_shadow_postconditions(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_shadow_postconditions(env) == []


@pytest.mark.asyncio
async def test_reload_clears_stale_shadow_session_contracts():
    """Shadow session contracts from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)

    guard._shadow_session_contracts.append(_make_shadow_session_contract("old-shadow-session"))
    assert len(guard.get_shadow_session_contracts()) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_shadow_session_contracts() == []


@pytest.mark.asyncio
async def test_reload_clears_stale_shadow_sandbox_contracts():
    """Shadow sandbox contracts from the previous bundle must not survive reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    guard._shadow_sandbox_contracts.append(_make_shadow_sandbox("old-shadow-sandbox"))
    assert len(guard.get_shadow_sandbox_contracts(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_shadow_sandbox_contracts(env) == []


@pytest.mark.asyncio
async def test_reload_clears_all_four_shadow_lists_simultaneously():
    """All four shadow lists must be cleared in a single reload() call."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    # Populate all four shadow lists
    guard._shadow_preconditions.append(_make_shadow_precondition("sp"))
    guard._shadow_postconditions.append(_make_shadow_postcondition("spo"))
    guard._shadow_session_contracts.append(_make_shadow_session_contract("ss"))
    guard._shadow_sandbox_contracts.append(_make_shadow_sandbox("ssb"))

    assert len(guard.get_shadow_preconditions(env)) == 1
    assert len(guard.get_shadow_postconditions(env)) == 1
    assert len(guard.get_shadow_session_contracts()) == 1
    assert len(guard.get_shadow_sandbox_contracts(env)) == 1

    await guard.reload(_BUNDLE_B)

    assert guard.get_shadow_preconditions(env) == []
    assert guard.get_shadow_postconditions(env) == []
    assert guard.get_shadow_session_contracts() == []
    assert guard.get_shadow_sandbox_contracts(env) == []


@pytest.mark.asyncio
async def test_reload_enforced_lists_updated_correctly():
    """Enforced contracts must reflect the new bundle after reload()."""
    guard = Edictum.from_yaml_string(_BUNDLE_A)
    env = _envelope()

    # Verify initial enforced state
    assert len(guard.get_preconditions(env)) == 1
    assert guard.get_preconditions(env)[0]._edictum_id == "enforced-pre-a"

    await guard.reload(_BUNDLE_B)

    # Wildcard envelope should not match the tool-specific contract
    assert len(guard.get_preconditions(env)) == 0

    # Tool-specific envelope should match
    rf_env = _envelope(tool="read_file")
    pre = guard.get_preconditions(rf_env)
    assert len(pre) == 1
    assert pre[0]._edictum_id == "enforced-pre-b"
