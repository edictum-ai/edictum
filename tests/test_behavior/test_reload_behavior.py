"""Behavior tests for reload() atomicity and frozen _CompiledState."""

from __future__ import annotations

import pytest

from edictum import Edictum, EdictumConfigError
from edictum._guard import _CompiledState

BUNDLE_V1 = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-v1
defaults:
  mode: enforce
contracts:
  - id: deny-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      effect: deny
      message: "Destructive command denied."
"""

BUNDLE_V2 = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-v2
defaults:
  mode: enforce
contracts:
  - id: deny-curl
    type: pre
    tool: bash
    when:
      args.command:
        contains: "curl"
    then:
      effect: deny
      message: "Network access denied."
  - id: deny-wget
    type: pre
    tool: bash
    when:
      args.command:
        contains: "wget"
    then:
      effect: deny
      message: "Network access denied."
  - id: check-sandbox
    type: sandbox
    tools: ["bash"]
    within: ["/tmp"]
    message: "Outside sandbox."
"""

BUNDLE_WITH_SESSION = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-session
defaults:
  mode: enforce
contracts:
  - id: max-calls
    type: session
    limits:
      max_tool_calls: 42
    then:
      effect: deny
      message: "Session limit reached."
"""

INVALID_YAML = "not: valid: yaml: ["


class _NullSink:
    async def emit(self, event):
        pass


class TestReloadReplacesContracts:
    """reload() with new YAML replaces active contracts."""

    @pytest.mark.asyncio
    async def test_reload_replaces_contracts(self):
        guard = Edictum.from_yaml_string(BUNDLE_V1, audit_sink=_NullSink())

        assert len(guard._state.preconditions) == 1
        old_version = guard.policy_version

        await guard.reload(BUNDLE_V2)

        assert len(guard._state.preconditions) == 2
        assert guard.policy_version != old_version


class TestReloadPreservesStateOnFailure:
    """reload() with invalid YAML preserves old contracts (fail-closed)."""

    @pytest.mark.asyncio
    async def test_reload_preserves_state_on_failure(self):
        guard = Edictum.from_yaml_string(BUNDLE_V1, audit_sink=_NullSink())
        original_state = guard._state
        original_version = guard.policy_version

        with pytest.raises(EdictumConfigError):
            await guard.reload(INVALID_YAML)

        # Entire _state object is unchanged
        assert guard._state is original_state
        assert guard.policy_version == original_version


class TestReloadStateIsConsistent:
    """After reload, all contract lists come from the same bundle."""

    @pytest.mark.asyncio
    async def test_reload_state_is_consistent(self):
        guard = Edictum.from_yaml_string(BUNDLE_V1, audit_sink=_NullSink())

        # V1 has only a precondition, no sandbox
        assert len(guard._state.preconditions) == 1
        assert len(guard._state.sandbox_contracts) == 0

        await guard.reload(BUNDLE_V2)

        # V2 has 2 preconditions and 1 sandbox — both from same bundle
        assert len(guard._state.preconditions) == 2
        assert len(guard._state.sandbox_contracts) == 1

        # Verify they share the same _state object
        state = guard._state
        assert len(state.preconditions) == 2
        assert len(state.sandbox_contracts) == 1


class TestReloadWipesInitShadowContracts:
    """reload() replaces _state entirely — init-time Python contracts are not preserved."""

    @pytest.mark.asyncio
    async def test_reload_wipes_init_shadow_contracts(self):
        from edictum.contracts import Verdict, precondition

        @precondition("bash")
        def shadow_pre(envelope):
            return Verdict.fail("Shadow deny.")

        # Mark it as a shadow contract (as the composer does)
        shadow_pre._edictum_shadow = True

        guard = Edictum(
            mode="enforce",
            contracts=[shadow_pre],
            audit_sink=_NullSink(),
        )

        assert len(guard._state.shadow_preconditions) == 1
        assert len(guard._state.preconditions) == 0

        await guard.reload(BUNDLE_V1)

        # reload() replaces _state entirely — init-time Python contracts are wiped
        assert len(guard._state.shadow_preconditions) == 0
        # Enforce contracts come from the new bundle
        assert len(guard._state.preconditions) == 1


class TestPolicyVersionUpdatedOnReload:
    """policy_version reflects new bundle hash after reload."""

    @pytest.mark.asyncio
    async def test_policy_version_updated_on_reload(self):
        guard = Edictum.from_yaml_string(BUNDLE_V1, audit_sink=_NullSink())
        v1_version = guard.policy_version

        await guard.reload(BUNDLE_V2)
        v2_version = guard.policy_version

        assert v1_version != v2_version
        assert v2_version is not None


class TestLimitsUpdatedOnReload:
    """Limits from new bundle are active after reload."""

    @pytest.mark.asyncio
    async def test_limits_updated_on_reload(self):
        guard = Edictum.from_yaml_string(BUNDLE_V1, audit_sink=_NullSink())

        # Default limits
        assert guard.limits.max_tool_calls == 200

        await guard.reload(BUNDLE_WITH_SESSION)

        # New limits from the session contract
        assert guard.limits.max_tool_calls == 42


class TestCompiledStateIsFrozen:
    """_CompiledState instances are immutable."""

    def test_compiled_state_is_frozen(self):
        state = _CompiledState()

        with pytest.raises(AttributeError):
            state.preconditions = (1, 2, 3)

        with pytest.raises(AttributeError):
            state.limits = None

        with pytest.raises(AttributeError):
            state.policy_version = "new"
