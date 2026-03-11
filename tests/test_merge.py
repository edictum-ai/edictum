"""Tests for Edictum.from_multiple() guard merging API."""

from __future__ import annotations

import logging

import pytest

from edictum import Edictum, EdictumConfigError, EdictumDenied

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _NullSink:
    async def emit(self, event):
        pass


def _make_guard_with_yaml(tmp_path, name, contracts_yaml):
    path = tmp_path / f"{name}.yaml"
    path.write_text(contracts_yaml)
    return Edictum.from_yaml(path, audit_sink=_NullSink())


# ---------------------------------------------------------------------------
# YAML fixtures
# ---------------------------------------------------------------------------

GUARD_A_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-a
defaults:
  mode: enforce
contracts:
  - id: block-bash
    type: pre
    tool: Bash
    when:
      args.command:
        exists: true
    then:
      effect: deny
      message: "Bash denied by guard A."
"""

GUARD_B_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-b
defaults:
  mode: enforce
contracts:
  - id: block-write
    type: pre
    tool: Write
    when:
      args.path:
        exists: true
    then:
      effect: deny
      message: "Write denied by guard B."
"""

GUARD_C_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-c
defaults:
  mode: enforce
contracts:
  - id: block-delete
    type: pre
    tool: Delete
    when:
      args.path:
        exists: true
    then:
      effect: deny
      message: "Delete denied by guard C."
"""

GUARD_DUP_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-dup
defaults:
  mode: enforce
contracts:
  - id: block-bash
    type: pre
    tool: Bash
    when:
      args.command:
        matches: '\\brm\\b'
    then:
      effect: deny
      message: "Bash denied by guard-dup (should be skipped)."
"""

GUARD_POST_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-post
defaults:
  mode: enforce
contracts:
  - id: post-check-a
    type: post
    tool: read_file
    when:
      output:
        contains: "SECRET"
    then:
      effect: warn
      message: "Output contains SECRET."
"""

GUARD_POST_B_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-post-b
defaults:
  mode: enforce
contracts:
  - id: post-check-b
    type: post
    tool: read_file
    when:
      output:
        contains: "PASSWORD"
    then:
      effect: warn
      message: "Output contains PASSWORD."
"""

GUARD_OBSERVE_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-observe
defaults:
  mode: observe
contracts:
  - id: observe-bash
    type: pre
    tool: Bash
    when:
      args.command:
        exists: true
    then:
      effect: deny
      message: "Bash observed."
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFromMultiple:
    def test_merge_two_guards(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_b = _make_guard_with_yaml(tmp_path, "b", GUARD_B_YAML)

        merged = Edictum.from_multiple([guard_a, guard_b])

        assert len(merged._state.preconditions) == 2
        ids = [getattr(c, "_edictum_id", None) for c in merged._state.preconditions]
        assert "block-bash" in ids
        assert "block-write" in ids

    def test_merge_three_guards(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_b = _make_guard_with_yaml(tmp_path, "b", GUARD_B_YAML)
        guard_c = _make_guard_with_yaml(tmp_path, "c", GUARD_C_YAML)

        merged = Edictum.from_multiple([guard_a, guard_b, guard_c])

        assert len(merged._state.preconditions) == 3
        ids = [getattr(c, "_edictum_id", None) for c in merged._state.preconditions]
        assert ids == ["block-bash", "block-write", "block-delete"]

    def test_empty_list_raises(self):
        with pytest.raises(EdictumConfigError, match="from_multiple\\(\\) requires at least one guard"):
            Edictum.from_multiple([])

    def test_single_guard(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)

        merged = Edictum.from_multiple([guard_a])

        assert merged is not guard_a
        assert len(merged._state.preconditions) == 1
        assert getattr(merged._state.preconditions[0], "_edictum_id", None) == "block-bash"

    def test_duplicate_ids_warns(self, tmp_path, caplog):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_dup = _make_guard_with_yaml(tmp_path, "dup", GUARD_DUP_YAML)

        with caplog.at_level(logging.WARNING, logger="edictum"):
            merged = Edictum.from_multiple([guard_a, guard_dup])

        assert len(merged._state.preconditions) == 1
        assert "Duplicate contract id 'block-bash'" in caplog.text
        # First wins: message should be from guard A
        result = merged.evaluate("Bash", {"command": "rm -rf /"})
        assert result.deny_reasons[0] == "Bash denied by guard A."

    def test_contract_ordering_preserved(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_b = _make_guard_with_yaml(tmp_path, "b", GUARD_B_YAML)

        merged = Edictum.from_multiple([guard_a, guard_b])

        ids = [getattr(c, "_edictum_id", None) for c in merged._state.preconditions]
        assert ids[0] == "block-bash"
        assert ids[1] == "block-write"

    def test_merged_guard_evaluate(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_b = _make_guard_with_yaml(tmp_path, "b", GUARD_B_YAML)

        merged = Edictum.from_multiple([guard_a, guard_b])

        # Bash denied
        result = merged.evaluate("Bash", {"command": "ls"})
        assert result.verdict == "deny"

        # Write denied
        result = merged.evaluate("Write", {"path": "/tmp/test.txt"})
        assert result.verdict == "deny"

        # Read allowed (no matching contract)
        result = merged.evaluate("Read", {"path": "/tmp/test.txt"})
        assert result.verdict == "allow"

    @pytest.mark.asyncio
    async def test_merged_guard_run(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_b = _make_guard_with_yaml(tmp_path, "b", GUARD_B_YAML)

        merged = Edictum.from_multiple([guard_a, guard_b])

        with pytest.raises(EdictumDenied, match="Bash denied by guard A"):
            await merged.run("Bash", {"command": "ls"}, lambda **kw: "ok")

    def test_merge_postconditions(self, tmp_path):
        guard_post_a = _make_guard_with_yaml(tmp_path, "post_a", GUARD_POST_YAML)
        guard_post_b = _make_guard_with_yaml(tmp_path, "post_b", GUARD_POST_B_YAML)

        merged = Edictum.from_multiple([guard_post_a, guard_post_b])

        assert len(merged._state.postconditions) == 2
        ids = [getattr(c, "_edictum_id", None) for c in merged._state.postconditions]
        assert ids == ["post-check-a", "post-check-b"]

    def test_no_mutation_of_input_guards(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_b = _make_guard_with_yaml(tmp_path, "b", GUARD_B_YAML)

        original_a_count = len(guard_a._state.preconditions)
        original_b_count = len(guard_b._state.preconditions)

        Edictum.from_multiple([guard_a, guard_b])

        assert len(guard_a._state.preconditions) == original_a_count
        assert len(guard_b._state.preconditions) == original_b_count

    def test_uses_first_guard_config(self, tmp_path):
        guard_a = _make_guard_with_yaml(tmp_path, "a", GUARD_A_YAML)
        guard_observe = _make_guard_with_yaml(tmp_path, "observe", GUARD_OBSERVE_YAML)

        merged = Edictum.from_multiple([guard_a, guard_observe])

        assert merged.environment == guard_a.environment
        assert merged.mode == guard_a.mode

    def test_merge_session_contracts(self, tmp_path):
        """Session contracts from multiple guards are merged."""
        session_yaml = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-session
defaults:
  mode: enforce
contracts:
  - id: session-limit
    type: session
    limits:
      max_tool_calls: 10
    then:
      effect: deny
      message: "Session limit reached"
"""
        session_yaml_b = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-session-b
defaults:
  mode: enforce
contracts:
  - id: session-limit-b
    type: session
    limits:
      max_attempts: 20
    then:
      effect: deny
      message: "Attempt limit reached"
"""
        guard_s1 = _make_guard_with_yaml(tmp_path, "s1", session_yaml)
        guard_s2 = _make_guard_with_yaml(tmp_path, "s2", session_yaml_b)

        merged = Edictum.from_multiple([guard_s1, guard_s2])
        assert len(merged._state.session_contracts) == 2
        ids = [getattr(c, "_edictum_id", None) for c in merged._state.session_contracts]
        assert ids == ["session-limit", "session-limit-b"]

    def test_cross_type_duplicate_id_deduplicates(self, tmp_path):
        """Same ID on a precondition and postcondition: first wins, second skipped."""
        pre_yaml = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-pre
defaults:
  mode: enforce
contracts:
  - id: shared-id
    type: pre
    tool: Bash
    when:
      args.command: { exists: true }
    then:
      effect: deny
      message: "Pre wins"
"""
        post_yaml = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: guard-post
defaults:
  mode: enforce
contracts:
  - id: shared-id
    type: post
    tool: "*"
    when:
      output.text: { contains: "secret" }
    then:
      effect: warn
      message: "Post loses"
"""
        guard_pre = _make_guard_with_yaml(tmp_path, "pre", pre_yaml)
        guard_post = _make_guard_with_yaml(tmp_path, "post", post_yaml)

        merged = Edictum.from_multiple([guard_pre, guard_post])

        # Precondition kept (first), postcondition skipped (duplicate ID)
        assert len(merged._state.preconditions) == 1
        assert len(merged._state.postconditions) == 0

    def test_merge_python_decorator_contracts(self):
        """from_multiple() works with Python decorator-based contracts too."""
        from edictum.contracts import Verdict, postcondition, precondition

        @precondition("Bash")
        def block_bash(envelope):
            return Verdict.fail("No bash")

        @postcondition("*")
        def check_output(envelope, response):
            if "secret" in str(response):
                return Verdict.fail("Secret in output")
            return Verdict.pass_()

        g1 = Edictum(
            mode="enforce",
            contracts=[block_bash],
            audit_sink=_NullSink(),
        )
        g2 = Edictum(
            mode="enforce",
            contracts=[check_output],
            audit_sink=_NullSink(),
        )

        merged = Edictum.from_multiple([g1, g2])
        assert len(merged._state.preconditions) == 1
        assert len(merged._state.postconditions) == 1

        # Verify evaluation works
        result = merged.evaluate("Bash", {"command": "ls"})
        assert result.verdict == "deny"

    def test_hooks_not_merged(self, tmp_path):
        """Hooks from non-first guards are not carried over (by design)."""
        from edictum.hooks import HookDecision
        from edictum.types import HookRegistration

        def my_hook(envelope):
            return HookDecision.allow()

        hook_reg = HookRegistration(
            callback=my_hook,
            phase="before",
            tool="*",
        )

        g1 = Edictum(mode="enforce", audit_sink=_NullSink())
        g2 = Edictum(mode="enforce", hooks=[hook_reg], audit_sink=_NullSink())

        merged = Edictum.from_multiple([g1, g2])
        # Hooks are not part of the merge — only contracts
        assert len(merged._before_hooks) == 0
