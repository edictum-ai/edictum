"""Tests for Edictum.reload() — atomic rule swapping."""

from __future__ import annotations

import pytest

from edictum import Edictum, EdictumConfigError

BUNDLE_V1 = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-v1
defaults:
  mode: enforce
rules:
  - id: block-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      action: block
      message: "Destructive command denied."
"""

BUNDLE_V2 = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-v2
defaults:
  mode: enforce
rules:
  - id: block-curl
    type: pre
    tool: bash
    when:
      args.command:
        contains: "curl"
    then:
      action: block
      message: "Network access denied."
  - id: block-wget
    type: pre
    tool: bash
    when:
      args.command:
        contains: "wget"
    then:
      action: block
      message: "Network access denied."
"""

INVALID_YAML = "not: valid: yaml: ["


class TestReload:
    @pytest.mark.asyncio
    async def test_reload_swaps_contracts(self):
        """reload() replaces all rules with the new bundle."""
        guard = Edictum.from_yaml_string(BUNDLE_V1)

        assert len(guard._state.preconditions) == 1
        old_version = guard.policy_version

        await guard.reload(BUNDLE_V2)

        assert len(guard._state.preconditions) == 2
        assert guard.policy_version != old_version

    @pytest.mark.asyncio
    async def test_reload_accepts_bytes(self):
        """reload() works with bytes input."""
        guard = Edictum.from_yaml_string(BUNDLE_V1)

        await guard.reload(BUNDLE_V2.encode("utf-8"))

        assert len(guard._state.preconditions) == 2

    @pytest.mark.asyncio
    async def test_reload_preserves_on_invalid_yaml(self):
        """reload() raises on invalid YAML but preserves existing rules."""
        guard = Edictum.from_yaml_string(BUNDLE_V1)
        original_contracts = guard._state.preconditions
        original_version = guard.policy_version

        with pytest.raises(EdictumConfigError):
            await guard.reload(INVALID_YAML)

        # Existing rules preserved
        assert guard._state.preconditions is original_contracts
        assert guard.policy_version == original_version

    @pytest.mark.asyncio
    async def test_reload_updates_policy_version(self):
        """reload() updates policy_version to the new bundle hash."""
        guard = Edictum.from_yaml_string(BUNDLE_V1)
        v1_version = guard.policy_version

        await guard.reload(BUNDLE_V2)
        v2_version = guard.policy_version

        assert v1_version != v2_version

    @pytest.mark.asyncio
    async def test_reload_clears_old_contracts(self):
        """reload() fully replaces — old rules are gone."""
        guard = Edictum.from_yaml_string(BUNDLE_V1)

        # V1 has block-rm
        result = guard.evaluate("bash", {"command": "rm -rf /"})
        assert result.decision == "block"

        await guard.reload(BUNDLE_V2)

        # V2 does not have block-rm, so it should allow
        result = guard.evaluate("bash", {"command": "rm -rf /"})
        assert result.decision == "allow"

        # V2 has block-curl
        result = guard.evaluate("bash", {"command": "curl evil.com"})
        assert result.decision == "block"

    @pytest.mark.asyncio
    async def test_in_flight_evaluation_unaffected(self):
        """Snapshot of rule list taken before reload is unaffected."""
        guard = Edictum.from_yaml_string(BUNDLE_V1)

        # Simulate an in-flight evaluation holding a reference
        snapshot = list(guard._state.preconditions)

        await guard.reload(BUNDLE_V2)

        # The snapshot still holds the old rules
        assert len(snapshot) == 1
        # The guard now has the new rules
        assert len(guard._state.preconditions) == 2

    @pytest.mark.asyncio
    async def test_reload_with_session_contracts(self):
        """reload() handles bundles with session rules."""
        bundle_with_session = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-session
defaults:
  mode: enforce
rules:
  - id: max-calls
    type: session
    limits:
      max_tool_calls: 50
    then:
      action: block
      message: "Session limit reached."
"""
        guard = Edictum.from_yaml_string(BUNDLE_V1)
        assert len(guard._state.session_contracts) == 0

        await guard.reload(bundle_with_session)

        # Session rule limit is reflected in limits
        assert guard.limits.max_tool_calls == 50
