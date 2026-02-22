"""Behavior tests for wildcard (glob) tool matching.

Verifies that tool selectors support glob patterns via fnmatch,
preserving exact-match and '*' semantics.
"""

from __future__ import annotations

from edictum import Edictum, Verdict, precondition
from edictum.envelope import create_envelope
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


class TestWildcardBehavior:
    """Glob pattern tool matching through the public API."""

    def test_glob_pattern_matches_tool(self):
        """tool: 'mcp_*' in YAML matches mcp_anything."""
        yaml_content = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-wildcard
defaults:
  mode: enforce
contracts:
  - id: deny-mcp
    type: pre
    tool: "mcp_*"
    when:
      args.query:
        exists: true
    then:
      effect: deny
      message: "MCP tools denied"
"""
        guard = Edictum.from_yaml_string(yaml_content, audit_sink=NullAuditSink())

        envelope = create_envelope("mcp_postgres_query", {"query": "SELECT 1"})
        preconditions = guard.get_preconditions(envelope)
        assert len(preconditions) == 1

    def test_exact_match_preserved(self):
        """tool: 'run' still matches only 'run'."""

        @precondition("run")
        def deny_run(envelope):
            return Verdict.fail("run denied")

        guard = Edictum(
            environment="test",
            contracts=[deny_run],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )

        # Matches
        assert len(guard.get_preconditions(create_envelope("run", {}))) == 1
        # Does not match
        assert len(guard.get_preconditions(create_envelope("runner", {}))) == 0
        assert len(guard.get_preconditions(create_envelope("run_tool", {}))) == 0

    def test_star_matches_everything(self):
        """tool: '*' matches all tools (existing behavior preserved)."""

        @precondition("*")
        def deny_all(envelope):
            return Verdict.fail("all denied")

        guard = Edictum(
            environment="test",
            contracts=[deny_all],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )

        assert len(guard.get_preconditions(create_envelope("any_tool", {}))) == 1
        assert len(guard.get_preconditions(create_envelope("another_tool", {}))) == 1
