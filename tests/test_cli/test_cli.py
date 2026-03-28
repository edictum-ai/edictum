"""Edictum CLI — Stream D implementation spec and tests.

This file serves two purposes:
1. Documents the exact CLI behavior (read the docstrings)
2. Provides the test suite the agent should make pass

Dependencies: click>=8.0, rich>=13.0 (under [cli] optional extra)
Entry point: edictum (via pyproject.toml [project.scripts])

Architecture:
- edictum/cli/__init__.py — empty
- edictum/cli/main.py — click group + 4 commands
- Each command is a thin wrapper around library functions
- Exit codes: 0 = success, 1 = validation/policy error, 2 = usage error

Run with: pytest tests/test_cli/ -v
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

# ---------------------------------------------------------------------------
# Test fixtures — YAML bundles
# ---------------------------------------------------------------------------

VALID_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: test-bundle
  description: "Valid test bundle."

defaults:
  mode: enforce

rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret"]
    then:
      action: block
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets]

  - id: bash-safety
    type: pre
    tool: bash
    when:
      args.command:
        matches: '\\brm\\s+-rf\\b'
    then:
      action: block
      message: "Destructive command denied."
      tags: [safety]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 50
    then:
      action: block
      message: "Session limit reached."
      tags: [rate-limit]
"""

INVALID_WRONG_EFFECT = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: bad-action

defaults:
  mode: enforce

rules:
  - id: bad-rule
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm" }
    then:
      action: warn
      message: "Wrong action for pre."
"""

INVALID_DUPLICATE_ID = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: dupe-ids

defaults:
  mode: enforce

rules:
  - id: same-id
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm" }
    then:
      action: block
      message: "First rule."

  - id: same-id
    type: pre
    tool: read_file
    when:
      args.path: { contains: ".env" }
    then:
      action: block
      message: "Duplicate."
"""

INVALID_BAD_REGEX = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: bad-regex

defaults:
  mode: enforce

rules:
  - id: bad-regex-rule
    type: pre
    tool: bash
    when:
      args.command:
        matches: '[invalid(regex'
    then:
      action: block
      message: "Bad regex."
"""

INVALID_YAML_SYNTAX = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: broken
defaults:
  mode: enforce
rules:
  - id: rule1
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm"
    then:
      action: block
      message: "Broken YAML."
"""

INVALID_MISSING_WHEN = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: no-when

defaults:
  mode: enforce

rules:
  - id: no-when-rule
    type: pre
    tool: bash
    then:
      action: block
      message: "Missing when."
"""

BUNDLE_V2 = """\
apiVersion: edictum/v1
kind: Ruleset

metadata:
  name: test-bundle-v2
  description: "Updated bundle."

defaults:
  mode: enforce

rules:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", ".pem"]
    then:
      action: block
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets]

  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      principal.ticket_ref: { exists: false }
    then:
      action: block
      message: "Ticket required."
      tags: [compliance]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      action: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 100
    then:
      action: block
      message: "Session limit reached."
      tags: [rate-limit]
"""


def write_file(content: str, suffix: str = ".yaml") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# Import the CLI — agent implements this
# ---------------------------------------------------------------------------

# The agent should create edictum/cli/main.py with a click group:
#
#   import click
#
#   @click.group()
#   def cli():
#       """Edictum — Runtime rules for AI agents."""
#       pass
#
#   @cli.command()
#   @click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
#   def validate(files): ...
#
#   @cli.command()
#   @click.argument("file", type=click.Path(exists=True))
#   @click.option("--tool", required=True)
#   @click.option("--args", "tool_args", required=True)
#   @click.option("--environment", default="production")
#   @click.option("--principal-role", default=None)
#   @click.option("--principal-user", default=None)
#   @click.option("--principal-ticket", default=None)
#   def check(file, tool, tool_args, environment, principal_role, principal_user, principal_ticket): ...
#
#   @cli.command()
#   @click.argument("old_file", type=click.Path(exists=True))
#   @click.argument("new_file", type=click.Path(exists=True))
#   def diff(old_file, new_file): ...
#
#   @cli.command()
#   @click.argument("file", type=click.Path(exists=True))
#   @click.option("--audit-log", required=True, type=click.Path(exists=True))
#   @click.option("--output", default=None, type=click.Path())
#   def replay(file, audit_log, output): ...
#
# Entry point in pyproject.toml:
#   [project.scripts]
#   edictum = "edictum.cli.main:cli"


# This import will fail until the agent creates the module.
# The agent should make it work.
from edictum.cli.main import cli  # noqa: E402

# ---------------------------------------------------------------------------
# 1. edictum validate
# ---------------------------------------------------------------------------


class TestValidateCommand:
    """
    SPEC: edictum validate <file.yaml> [file2.yaml ...]

    Validates one or more rule bundle files.
    For each file:
    - Parse YAML (report syntax errors)
    - Validate against JSON Schema (report structural errors)
    - Check unique rule IDs
    - Compile all regexes and report invalid ones
    - Report rule summary (count by type)

    Exit code 0: all files valid
    Exit code 1: any file has errors

    Output format:
    ✓ rules.yaml — 4 rules (2 pre, 1 post, 1 session)
    ✗ bad.yaml:14 — error description
    """

    def test_valid_bundle(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 0
        assert "4 rule" in result.output
        # Should show type breakdown
        assert "pre" in result.output
        assert "post" in result.output
        assert "session" in result.output

    def test_multiple_valid_files(self):
        path1 = write_file(VALID_BUNDLE)
        path2 = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path1, path2])
        assert result.exit_code == 0

    def test_invalid_effect_reports_error(self):
        path = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        # Should mention what's wrong
        assert "action" in result.output.lower() or "warn" in result.output.lower()

    def test_duplicate_id_reports_error(self):
        path = write_file(INVALID_DUPLICATE_ID)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        assert "same-id" in result.output or "duplicate" in result.output.lower()

    def test_bad_regex_reports_error(self):
        path = write_file(INVALID_BAD_REGEX)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        assert "regex" in result.output.lower() or "pattern" in result.output.lower()

    def test_yaml_syntax_error(self):
        path = write_file(INVALID_YAML_SYNTAX)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1
        # Should indicate it's a parse error
        assert "yaml" in result.output.lower() or "parse" in result.output.lower() or "syntax" in result.output.lower()

    def test_missing_when_reports_error(self):
        path = write_file(INVALID_MISSING_WHEN)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path])
        assert result.exit_code == 1

    def test_nonexistent_file(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "/nonexistent/file.yaml"])
        assert result.exit_code != 0

    def test_mixed_valid_and_invalid(self):
        """If one file is valid and another invalid, exit code should be 1."""
        valid_path = write_file(VALID_BUNDLE)
        invalid_path = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", valid_path, invalid_path])
        assert result.exit_code == 1
        # But valid file should still show success
        assert "4 rule" in result.output


# ---------------------------------------------------------------------------
# 2. edictum check
# ---------------------------------------------------------------------------


class TestCheckCommand:
    """
    SPEC: edictum check <file.yaml> --tool <name> --args '<json>'
                          [--environment <env>]
                          [--principal-role <role>]
                          [--principal-user <user>]
                          [--principal-ticket <ticket>]

    Dry-run: create a synthetic tool_call and evaluate it against the rules.
    Show which rules matched, which passed, which would block/warn.

    Exit code 0: tool call would be ALLOWED
    Exit code 1: tool call would be DENIED

    Output should show:
    - Decision (ALLOWED / DENIED)
    - Which rule denied (if denied): id, message, tags
    - How many rules were evaluated
    """

    def test_denied_sensitive_read(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "read_file",
                "--args",
                '{"path": "/app/.env"}',
            ],
        )
        assert result.exit_code == 1
        assert "denied" in result.output.lower() or "DENIED" in result.output
        assert "block-env-reads" in result.output

    def test_allowed_safe_read(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "read_file",
                "--args",
                '{"path": "README.md"}',
            ],
        )
        assert result.exit_code == 0
        assert "allowed" in result.output.lower() or "ALLOWED" in result.output

    def test_denied_destructive_bash(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "bash",
                "--args",
                '{"command": "rm -rf /tmp/data"}',
            ],
        )
        assert result.exit_code == 1
        assert "bash-safety" in result.output

    def test_allowed_safe_bash(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "bash",
                "--args",
                '{"command": "ls -la"}',
            ],
        )
        assert result.exit_code == 0

    def test_check_with_principal_role(self):
        path = write_file(BUNDLE_V2)
        runner = CliRunner()
        # BUNDLE_V2 has require-ticket which checks principal.ticket_ref exists: false
        # Providing a ticket should pass
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "deploy_service",
                "--args",
                '{"service": "api"}',
                "--principal-role",
                "sre",
                "--principal-ticket",
                "JIRA-123",
            ],
        )
        assert result.exit_code == 0

    def test_check_without_ticket_denied(self):
        path = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "deploy_service",
                "--args",
                '{"service": "api"}',
                "--principal-role",
                "sre",
                # no ticket
            ],
        )
        assert result.exit_code == 1
        assert "require-ticket" in result.output or "ticket" in result.output.lower()

    def test_check_with_environment(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "read_file",
                "--args",
                '{"path": "safe.txt"}',
                "--environment",
                "staging",
            ],
        )
        assert result.exit_code == 0

    def test_check_invalid_json_args(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "read_file",
                "--args",
                "not valid json",
            ],
        )
        assert result.exit_code == 2 or result.exit_code == 1
        assert "json" in result.output.lower() or "invalid" in result.output.lower()

    def test_check_shows_evaluated_count(self):
        """Output should indicate how many rules were evaluated."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "read_file",
                "--args",
                '{"path": "safe.txt"}',
            ],
        )
        assert result.exit_code == 0
        # Should mention number of rules evaluated
        assert "rule" in result.output.lower() or "rule" in result.output.lower()

    def test_unrelated_tool_passes(self):
        """Tool not targeted by any pre rule should pass."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "check",
                path,
                "--tool",
                "send_email",
                "--args",
                '{"to": "test@test.com"}',
            ],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 3. edictum diff
# ---------------------------------------------------------------------------


class TestDiffCommand:
    """
    SPEC: edictum diff <old.yaml> <new.yaml>

    Compare two rule bundles and show what changed.
    Output categories:
    - Added: rules in new but not in old (by id)
    - Removed: rules in old but not in new (by id)
    - Changed: rules with same id but different content
    - Unchanged: rules identical in both

    Exit code 0: no changes (bundles identical)
    Exit code 1: changes detected

    This is designed for PR reviews and CI gates.
    """

    def test_identical_bundles(self):
        path1 = write_file(VALID_BUNDLE)
        path2 = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", path1, path2])
        assert result.exit_code == 0
        assert "no change" in result.output.lower() or "identical" in result.output.lower()

    def test_added_contract(self):
        """BUNDLE_V2 adds 'require-ticket' that's not in VALID_BUNDLE."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert result.exit_code == 1
        assert "require-ticket" in result.output
        assert "add" in result.output.lower()

    def test_removed_contract(self):
        """Reverse: VALID_BUNDLE has 'bash-safety' that's not in BUNDLE_V2."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert result.exit_code == 1
        assert "bash-safety" in result.output
        assert "remove" in result.output.lower()

    def test_changed_contract(self):
        """'block-env-reads' exists in both but BUNDLE_V2 adds '.pem' to contains_any."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert result.exit_code == 1
        assert "block-env-reads" in result.output
        assert "change" in result.output.lower() or "modif" in result.output.lower()

    def test_changed_session_limits(self):
        """session-cap changes max_tool_calls from 50 to 100."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        assert "session-cap" in result.output

    def test_diff_shows_summary(self):
        """Should show a summary line like '1 added, 1 removed, 2 changed, 1 unchanged'."""
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new])
        # Should have some kind of summary
        output_lower = result.output.lower()
        assert "added" in output_lower or "removed" in output_lower or "changed" in output_lower

    def test_diff_invalid_file(self):
        valid = write_file(VALID_BUNDLE)
        invalid = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", valid, invalid])
        # Should fail gracefully — can't diff an invalid bundle
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# 4. edictum replay
# ---------------------------------------------------------------------------


class TestReplayCommand:
    """
    SPEC: edictum replay <file.yaml> --audit-log <events.jsonl>
                           [--output <report.jsonl>]

    Replay an audit log against a (potentially different) rule bundle.
    For each event in the log:
    - Reconstruct the tool_call (tool_name, tool_args, environment, principal)
    - Evaluate against the provided rules
    - Compare: would the new rules produce a different decision?

    Output:
    - Summary: N events replayed, M would change
    - Changed events: old decision → new decision, which rule, why
    - If --output specified, write detailed report as JSONL

    Exit code 0: no changes (new rules produce same verdicts)
    Exit code 1: changes detected

    Use case: "If we deploy this new rule bundle, which past tool calls
    would have been affected?"
    """

    @pytest.fixture
    def audit_log(self) -> str:
        """Create a sample audit log with events that match/don't match rules."""
        events = [
            # Event 1: read_file on .env — was allowed (no rules before)
            {
                "action": "call_allowed",
                "tool_name": "read_file",
                "tool_args": {"path": "/app/.env"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 2: read_file on README — was allowed
            {
                "action": "call_allowed",
                "tool_name": "read_file",
                "tool_args": {"path": "README.md"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 3: bash rm -rf — was allowed (no rules before)
            {
                "action": "call_allowed",
                "tool_name": "bash",
                "tool_args": {"command": "rm -rf /tmp/cache"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 4: safe bash — was allowed
            {
                "action": "call_allowed",
                "tool_name": "bash",
                "tool_args": {"command": "ls -la"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
            # Event 5: was denied by some old rule — should stay denied or change
            {
                "action": "call_denied",
                "tool_name": "deploy_service",
                "tool_args": {"service": "api"},
                "environment": "production",
                "principal": {"user_id": "dev-1", "role": "developer"},
            },
        ]
        path = write_file(
            "\n".join(json.dumps(e) for e in events),
            suffix=".jsonl",
        )
        return path

    def test_replay_detects_changes(self, audit_log):
        """Events 1 and 3 were allowed but would now be denied by VALID_BUNDLE."""
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", rules, "--audit-log", audit_log])
        assert result.exit_code == 1  # changes detected
        # Should report that some events would change
        assert "change" in result.output.lower() or "would" in result.output.lower()
        # Should mention the count
        assert "5" in result.output or "event" in result.output.lower()

    def test_replay_with_output_file(self, audit_log):
        rules = write_file(VALID_BUNDLE)
        output_path = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
        runner = CliRunner()
        runner.invoke(
            cli,
            [
                "replay",
                rules,
                "--audit-log",
                audit_log,
                "--output",
                output_path,
            ],
        )
        # Output file should be created with details
        output = Path(output_path)
        assert output.exists()
        lines = output.read_text().strip().split("\n")
        assert len(lines) >= 1
        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "tool_name" in data
            assert "original_action" in data or "new_verdict" in data

    def test_replay_no_changes(self):
        """If the audit log only has events that match current rules, no changes."""
        events = [
            {
                "action": "call_allowed",
                "tool_name": "send_email",
                "tool_args": {"to": "test@test.com"},
                "environment": "production",
                "principal": {"user_id": "dev-1"},
            },
        ]
        log_path = write_file(
            "\n".join(json.dumps(e) for e in events),
            suffix=".jsonl",
        )
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", rules, "--audit-log", log_path])
        assert result.exit_code == 0
        assert "no change" in result.output.lower() or "0" in result.output

    def test_replay_empty_log(self):
        log_path = write_file("", suffix=".jsonl")
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", rules, "--audit-log", log_path])
        assert result.exit_code == 0
        assert "0" in result.output

    def test_replay_invalid_contracts(self, audit_log):
        """Replay with invalid rules should fail gracefully."""
        rules = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", rules, "--audit-log", audit_log])
        assert result.exit_code != 0

    def test_replay_malformed_log_line(self):
        """Malformed JSONL lines should be skipped with a warning, not crash."""
        log_content = (
            '{"action":"call_allowed","tool_name":"bash","tool_args":{"command":"ls"}}\n'
            "not json\n"
            '{"action":"call_allowed","tool_name":"bash","tool_args":{"command":"pwd"}}'
        )
        log_path = write_file(log_content, suffix=".jsonl")
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["replay", rules, "--audit-log", log_path])
        # Should process 2 valid events and warn about 1 bad line
        assert "skip" in result.output.lower() or "warn" in result.output.lower() or "invalid" in result.output.lower()


# ---------------------------------------------------------------------------
# 5. General CLI behavior
# ---------------------------------------------------------------------------


class TestCLIGeneral:
    """Cross-cutting CLI concerns."""

    def test_help_text(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "validate" in result.output
        assert "check" in result.output
        assert "diff" in result.output
        assert "replay" in result.output
        assert "test" in result.output

    def test_validate_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "--help"])
        assert result.exit_code == 0

    def test_check_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["check", "--help"])
        assert result.exit_code == 0

    def test_check_missing_required_args(self):
        """check without --tool should fail."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["check", path])
        assert result.exit_code != 0

    def test_no_command(self):
        runner = CliRunner()
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        # Should show help/usage
        assert "Usage" in result.output or "validate" in result.output

    def test_test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["test", "--help"])
        assert result.exit_code == 0
        assert "precondition" in result.output.lower() or "test case" in result.output.lower()


# ---------------------------------------------------------------------------
# 6. edictum test
# ---------------------------------------------------------------------------

PASSING_CASES = """\
cases:
  - id: test-block-env
    tool: read_file
    args:
      path: "/app/.env"
    expect: block
    match_contract: block-env-reads
  - id: test-allow-normal
    tool: read_file
    args:
      path: "report.txt"
    expect: allow
"""

FAILING_CASES = """\
cases:
  - id: test-should-fail
    tool: read_file
    args:
      path: "report.txt"
    expect: block
"""

CASES_WITH_PRINCIPAL = """\
cases:
  - id: test-no-ticket-denied
    tool: deploy_service
    args:
      service: api
    principal:
      role: sre
    expect: block
    match_contract: require-ticket
  - id: test-with-ticket-allowed
    tool: deploy_service
    args:
      service: api
    principal:
      role: sre
      ticket_ref: JIRA-123
    expect: allow
"""

CASES_WITH_CLAIMS = """\
cases:
  - id: test-with-claims
    tool: read_file
    args:
      path: "report.txt"
    principal:
      role: developer
      claims:
        department: platform
        clearance: high
    expect: allow
"""

CASES_WRONG_CONTRACT = """\
cases:
  - id: test-wrong-match
    tool: read_file
    args:
      path: "/app/.env"
    expect: block
    match_contract: nonexistent-rule
"""


class TestTestCommand:
    """
    SPEC: edictum test <file.yaml> --cases <cases.yaml>

    Validate rules against YAML test cases (preconditions only).
    For each test case:
    - Build an tool_call from tool, args, principal
    - Evaluate preconditions
    - Compare result to expected decision (allow/block)
    - Optionally verify that the correct rule triggered

    Exit code 0: all cases pass
    Exit code 1: any case fails

    Output: pass/fail per case, summary line.
    """

    def test_all_pass(self):
        """edictum test should exit 0 when all cases pass."""
        rules = write_file(VALID_BUNDLE)
        cases = write_file(PASSING_CASES)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code == 0
        assert "2/2 passed" in result.output
        assert "0 failed" in result.output

    def test_with_failure(self):
        """edictum test should exit non-zero when cases fail."""
        rules = write_file(VALID_BUNDLE)
        cases = write_file(FAILING_CASES)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code != 0
        assert "failed" in result.output
        assert "0/1 passed" in result.output or "1 failed" in result.output

    def test_match_contract(self):
        """edictum test should verify match_contract when specified."""
        rules = write_file(VALID_BUNDLE)
        cases = write_file(PASSING_CASES)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code == 0
        # The output should show the matching rule for block cases
        assert "block-env-reads" in result.output

    def test_match_contract_wrong_id(self):
        """edictum test should fail when match_contract doesn't match the firing rule."""
        rules = write_file(VALID_BUNDLE)
        cases = write_file(CASES_WRONG_CONTRACT)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code != 0
        assert "1 failed" in result.output

    def test_principal_with_ticket(self):
        """edictum test should support principal fields in test cases."""
        rules = write_file(BUNDLE_V2)
        cases = write_file(CASES_WITH_PRINCIPAL)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code == 0
        assert "2/2 passed" in result.output

    def test_principal_with_claims(self):
        """edictum test should support principal claims in test cases."""
        rules = write_file(VALID_BUNDLE)
        cases = write_file(CASES_WITH_CLAIMS)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code == 0
        assert "1/1 passed" in result.output

    def test_invalid_contracts(self):
        """edictum test should fail gracefully on invalid rule YAML."""
        rules = write_file(INVALID_WRONG_EFFECT)
        cases = write_file(PASSING_CASES)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code != 0

    def test_invalid_cases_no_cases_key(self):
        """edictum test should fail gracefully on malformed test cases."""
        rules = write_file(VALID_BUNDLE)
        bad_cases = write_file("not_cases:\n  - foo: bar\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", bad_cases])
        assert result.exit_code != 0
        assert "cases" in result.output.lower()

    def test_invalid_cases_not_a_list(self):
        """edictum test should fail when cases is not a list."""
        rules = write_file(VALID_BUNDLE)
        bad_cases = write_file("cases: not-a-list\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", bad_cases])
        assert result.exit_code != 0

    def test_missing_tool_field(self):
        """edictum test should reject cases missing the 'tool' field."""
        bad = write_file("cases:\n  - id: no-tool\n    expect: bogus\n")
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", bad])
        assert result.exit_code == 2
        assert "missing" in result.output.lower()
        assert "tool" in result.output

    def test_missing_expect_field(self):
        """edictum test should reject cases missing the 'expect' field."""
        bad = write_file("cases:\n  - id: no-expect\n    tool: read_file\n    args:\n      path: x\n")
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", bad])
        assert result.exit_code == 2
        assert "missing" in result.output.lower()
        assert "expect" in result.output

    def test_invalid_expect_value(self):
        """edictum test should reject invalid expect values like 'warn' or 'block'."""
        bad = write_file(
            "cases:\n  - id: bad-expect\n    tool: read_file\n    args:\n      path: x\n    expect: warn\n"
        )
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", bad])
        assert result.exit_code == 2
        assert "invalid" in result.output.lower()
        assert "warn" in result.output

    def test_invalid_expect_value_deny(self):
        """edictum test should reject 'deny' as an expect value (old terminology)."""
        bad = write_file("cases:\n  - id: bad\n    tool: bash\n    args:\n      command: ls\n    expect: bogus\n")
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", bad])
        assert result.exit_code == 2
        assert "bogus" in result.output

    def test_mixed_pass_and_fail(self):
        """Mixed results should report correct counts."""
        mixed_cases = """\
cases:
  - id: test-block-env
    tool: read_file
    args:
      path: "/app/.env"
    expect: block
  - id: test-wrong-expect
    tool: read_file
    args:
      path: "safe.txt"
    expect: block
"""
        rules = write_file(VALID_BUNDLE)
        cases = write_file(mixed_cases)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases])
        assert result.exit_code != 0
        assert "1/2 passed" in result.output
        assert "1 failed" in result.output


# ---------------------------------------------------------------------------
# 7. edictum test --calls
# ---------------------------------------------------------------------------

SAFE_CALLS = json.dumps(
    [
        {"tool": "read_file", "args": {"path": "README.md"}},
        {"tool": "bash", "args": {"command": "ls -la"}},
    ]
)

DENY_CALLS = json.dumps(
    [
        {"tool": "read_file", "args": {"path": "/app/.env"}},
        {"tool": "bash", "args": {"command": "rm -rf /tmp"}},
    ]
)

CALLS_WITH_OUTPUT = json.dumps(
    [
        {"tool": "read_file", "args": {"path": "data.txt"}, "output": "SSN: 123-45-6789"},
    ]
)


class TestCallsCommand:
    """
    SPEC: edictum test <file.yaml> --calls <calls.json> [--json]

    Evaluate JSON tool calls against rules using guard.evaluate_batch().
    Supports both preconditions and postconditions (via output field).

    Exit code 0: no denials.
    Exit code 1: one or more denials.
    Exit code 2: usage error (invalid JSON, both flags, etc.).
    """

    def test_safe_calls_exit_0(self):
        rules = write_file(VALID_BUNDLE)
        calls = write_file(SAFE_CALLS, suffix=".json")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--calls", calls])
        assert result.exit_code == 0

    def test_denied_calls_exit_1(self):
        rules = write_file(VALID_BUNDLE)
        calls = write_file(DENY_CALLS, suffix=".json")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--calls", calls])
        assert result.exit_code == 1

    def test_json_flag(self):
        rules = write_file(VALID_BUNDLE)
        calls = write_file(SAFE_CALLS, suffix=".json")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--calls", calls, "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0]["decision"] == "allow"

    def test_with_output_field(self):
        rules = write_file(VALID_BUNDLE)
        calls = write_file(CALLS_WITH_OUTPUT, suffix=".json")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--calls", calls, "--json"])
        assert result.exit_code == 0  # postconditions warn, don't block
        parsed = json.loads(result.output)
        assert parsed[0]["decision"] == "warn"
        assert len(parsed[0]["warn_reasons"]) > 0

    def test_invalid_json_exit_2(self):
        rules = write_file(VALID_BUNDLE)
        calls = write_file("not valid json {{{", suffix=".json")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--calls", calls])
        assert result.exit_code == 2

    def test_non_array_json_exit_2(self):
        rules = write_file(VALID_BUNDLE)
        calls = write_file('{"tool": "bash"}', suffix=".json")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--calls", calls])
        assert result.exit_code == 2
        assert "array" in result.output.lower()

    def test_both_cases_and_calls_exit_2(self):
        rules = write_file(VALID_BUNDLE)
        cases = write_file(PASSING_CASES)
        calls = write_file(SAFE_CALLS, suffix=".json")
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules, "--cases", cases, "--calls", calls])
        assert result.exit_code == 2

    def test_neither_cases_nor_calls_exit_2(self):
        rules = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["test", rules])
        assert result.exit_code == 2
