"""CLI --json flag tests for check, validate, and diff commands."""

from __future__ import annotations

import json
import tempfile

from click.testing import CliRunner

from edictum.cli.main import cli

# ---------------------------------------------------------------------------
# Test fixtures — YAML bundles
# ---------------------------------------------------------------------------

VALID_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: test-bundle
  description: "Valid test bundle."

defaults:
  mode: enforce

contracts:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets]

  - id: bash-safety
    type: pre
    tool: bash
    when:
      args.command:
        matches: '\\brm\\s+-rf\\b'
    then:
      effect: deny
      message: "Destructive command denied."
      tags: [safety]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 50
    then:
      effect: deny
      message: "Session limit reached."
      tags: [rate-limit]
"""

BUNDLE_V2 = """\
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: test-bundle-v2
  description: "Updated bundle."

defaults:
  mode: enforce

contracts:
  - id: block-env-reads
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".env", ".secret", ".pem"]
    then:
      effect: deny
      message: "Sensitive file '{args.path}' denied."
      tags: [secrets]

  - id: require-ticket
    type: pre
    tool: deploy_service
    when:
      principal.ticket_ref: { exists: false }
    then:
      effect: deny
      message: "Ticket required."
      tags: [compliance]

  - id: pii-check
    type: post
    tool: "*"
    when:
      output.text:
        matches: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    then:
      effect: warn
      message: "PII detected."
      tags: [pii]

  - id: session-cap
    type: session
    limits:
      max_tool_calls: 100
    then:
      effect: deny
      message: "Session limit reached."
      tags: [rate-limit]
"""

INVALID_WRONG_EFFECT = """\
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: bad-effect

defaults:
  mode: enforce

contracts:
  - id: bad-rule
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm" }
    then:
      effect: warn
      message: "Wrong effect for pre."
"""


def write_file(content: str, suffix: str = ".yaml") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# 1. edictum check --json
# ---------------------------------------------------------------------------


class TestCheckJson:
    """Test check command with --json flag."""

    def test_allowed_json_output(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", path, "--tool", "read_file", "--args", '{"path": "safe.txt"}', "--json"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["tool"] == "read_file"
        assert parsed["args"] == {"path": "safe.txt"}
        assert parsed["verdict"] == "allow"
        assert parsed["reason"] is None
        assert parsed["contracts_evaluated"] >= 1
        assert parsed["environment"] == "production"

    def test_denied_json_output(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", path, "--tool", "read_file", "--args", '{"path": "/app/.env"}', "--json"],
        )
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["tool"] == "read_file"
        assert parsed["args"] == {"path": "/app/.env"}
        assert parsed["verdict"] == "deny"
        assert parsed["reason"] is not None
        assert parsed["contract_id"] == "block-env-reads"
        assert parsed["contracts_evaluated"] >= 1
        assert parsed["environment"] == "production"

    def test_custom_environment_in_json(self):
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
                "--json",
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["environment"] == "staging"

    def test_invalid_json_args_with_json_flag(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", path, "--tool", "read_file", "--args", "not-json", "--json"],
        )
        assert result.exit_code == 2
        parsed = json.loads(result.output)
        assert "error" in parsed

    def test_json_output_is_parseable(self):
        """JSON output must be valid JSON, not Rich-formatted text."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", path, "--tool", "bash", "--args", '{"command": "rm -rf /"}', "--json"],
        )
        # Must not contain Rich markup
        assert "[red" not in result.output
        assert "[green" not in result.output
        assert "[bold" not in result.output
        # Must be valid JSON
        parsed = json.loads(result.output)
        assert isinstance(parsed, dict)

    def test_json_has_all_required_keys(self):
        """JSON output must contain all specified keys."""
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["check", path, "--tool", "send_email", "--args", '{"to": "x@y.com"}', "--json"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        required_keys = {"tool", "args", "verdict", "reason", "contracts_evaluated", "environment"}
        assert required_keys.issubset(parsed.keys())


# ---------------------------------------------------------------------------
# 2. edictum validate --json
# ---------------------------------------------------------------------------


class TestValidateJson:
    """Test validate command with --json flag."""

    def test_valid_bundle_json(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path, "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["valid"] is True
        assert len(parsed["files"]) == 1
        f = parsed["files"][0]
        assert f["valid"] is True
        assert f["contracts"] == 4
        assert "pre" in f["breakdown"]

    def test_invalid_bundle_json(self):
        path = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path, "--json"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["valid"] is False
        assert len(parsed["files"]) == 1
        assert parsed["files"][0]["valid"] is False
        assert "error" in parsed["files"][0]

    def test_mixed_valid_invalid_json(self):
        valid = write_file(VALID_BUNDLE)
        invalid = write_file(INVALID_WRONG_EFFECT)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", valid, invalid, "--json"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["valid"] is False
        # One valid, one invalid
        valids = [f for f in parsed["files"] if f["valid"]]
        invalids = [f for f in parsed["files"] if not f["valid"]]
        assert len(valids) == 1
        assert len(invalids) == 1

    def test_composition_json(self):
        path1 = write_file(VALID_BUNDLE)
        path2 = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path1, path2, "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "composed" in parsed
        assert parsed["composed"]["contracts"] > 0
        assert "breakdown" in parsed["composed"]

    def test_nonexistent_file_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "/nonexistent/file.yaml", "--json"])
        assert result.exit_code != 0
        parsed = json.loads(result.output)
        assert parsed["valid"] is False
        assert parsed["files"][0]["valid"] is False
        assert "not found" in parsed["files"][0]["error"]

    def test_json_output_no_rich_markup(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", path, "--json"])
        assert "[green" not in result.output
        assert "[red" not in result.output
        json.loads(result.output)  # must parse


# ---------------------------------------------------------------------------
# 3. edictum diff --json
# ---------------------------------------------------------------------------


class TestDiffJson:
    """Test diff command with --json flag."""

    def test_identical_bundles_json(self):
        path1 = write_file(VALID_BUNDLE)
        path2 = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", path1, path2, "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["has_changes"] is False
        assert parsed["added"] == []
        assert parsed["removed"] == []
        assert parsed["changed"] == []
        assert len(parsed["unchanged"]) == 4

    def test_changes_detected_json(self):
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new, "--json"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["has_changes"] is True
        # require-ticket added
        added_ids = [a["id"] for a in parsed["added"]]
        assert "require-ticket" in added_ids
        # bash-safety removed
        removed_ids = [r["id"] for r in parsed["removed"]]
        assert "bash-safety" in removed_ids
        # block-env-reads and session-cap changed
        assert "block-env-reads" in parsed["changed"]

    def test_added_contracts_have_type(self):
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new, "--json"])
        parsed = json.loads(result.output)
        for entry in parsed["added"]:
            assert "id" in entry
            assert "type" in entry

    def test_removed_contracts_have_type(self):
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new, "--json"])
        parsed = json.loads(result.output)
        for entry in parsed["removed"]:
            assert "id" in entry
            assert "type" in entry

    def test_diff_json_no_rich_markup(self):
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new, "--json"])
        assert "[green" not in result.output
        assert "[red" not in result.output
        assert "[yellow" not in result.output
        json.loads(result.output)

    def test_diff_too_few_files_json(self):
        path = write_file(VALID_BUNDLE)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", path, "--json"])
        assert result.exit_code == 2
        parsed = json.loads(result.output)
        assert "error" in parsed

    def test_composition_report_in_json(self):
        old = write_file(VALID_BUNDLE)
        new = write_file(BUNDLE_V2)
        runner = CliRunner()
        result = runner.invoke(cli, ["diff", old, new, "--json"])
        parsed = json.loads(result.output)
        # Composition report should be present since bundles share contract IDs
        if "composition" in parsed:
            assert "overrides" in parsed["composition"]
            assert "observe_contracts" in parsed["composition"]
            # Backward compat: "shadows" alias still present
            assert "shadows" in parsed["composition"]
            assert parsed["composition"]["shadows"] == parsed["composition"]["observe_contracts"]
