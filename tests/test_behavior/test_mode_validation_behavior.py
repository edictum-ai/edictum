"""Behavior tests for guard mode validation.

Proves that an unrecognized mode string is rejected at construction instead of
reaching enforcement paths that branch on exact mode equality (where it would
silently skip the deny raise while auditing call_denied).
"""

from __future__ import annotations

import pytest

from edictum import Edictum, EdictumConfigError

_RULES = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: mode-validation
defaults:
  mode: enforce
rules:
  - id: block-rm
    type: pre
    tool: Bash
    when:
      args.command: {contains: rm}
    then:
      action: block
      message: no rm
"""


class TestModeValidation:
    def test_valid_modes_accepted(self):
        assert Edictum(mode="enforce").mode == "enforce"
        assert Edictum(mode="observe").mode == "observe"

    @pytest.mark.parametrize("bad", ["Enforce", "enforcing", "enforce ", "production", "", "OFF"])
    def test_invalid_modes_rejected_at_construction(self, bad):
        with pytest.raises(EdictumConfigError, match="Invalid mode"):
            Edictum(mode=bad)

    @pytest.mark.parametrize("bad", ["Enforce", "enforcing", "production"])
    def test_invalid_modes_rejected_via_from_yaml_string(self, bad):
        with pytest.raises(EdictumConfigError, match="Invalid mode"):
            Edictum.from_yaml_string(_RULES, mode=bad)

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_typo_cannot_fail_open(self):
        """A mode typo must fail at boot, not execute blocked calls."""
        with pytest.raises(EdictumConfigError):
            Edictum.from_yaml_string(_RULES, mode="Enforce")
