"""CLI composition tests — validate + diff with multi-file composition."""

from __future__ import annotations

from click.testing import CliRunner

from edictum.cli.main import cli

# ---------------------------------------------------------------------------
# Test fixtures — YAML bundles
# ---------------------------------------------------------------------------

BASE_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-base
defaults:
  mode: enforce
rules:
  - id: rule-a
    type: pre
    tool: read_file
    when:
      args.path:
        contains: ".secret"
    then:
      action: block
      message: "Denied by rule-a"
  - id: rule-b
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm"
    then:
      action: block
      message: "Denied by rule-b"
"""

OVERRIDE_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-override
defaults:
  mode: enforce
rules:
  - id: rule-a
    type: pre
    tool: read_file
    when:
      args.path:
        contains_any: [".secret", ".pem"]
    then:
      action: block
      message: "Denied by overridden rule-a"
  - id: rule-c
    type: post
    tool: "*"
    when:
      output.text:
        contains: "password"
    then:
      action: warn
      message: "Password detected"
"""

THIRD_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-third
defaults:
  mode: enforce
rules:
  - id: rule-b
    type: pre
    tool: bash
    when:
      args.command:
        contains: "sudo"
    then:
      action: block
      message: "Denied by overridden rule-b"
  - id: rule-d
    type: session
    limits:
      max_tool_calls: 100
    then:
      action: block
      message: "Session limit"
"""

INVALID_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: broken
defaults:
  mode: enforce
rules:
  - id: rule-x
    type: pre
    tool: bash
    when:
      args.command: { contains: "rm"
    then:
      action: block
      message: "Broken YAML."
"""


# ---------------------------------------------------------------------------
# 1. edictum validate — composition
# ---------------------------------------------------------------------------


class TestValidateComposition:
    """Test validate command with multi-file composition."""

    def test_validate_composed_result(self, tmp_path):
        """edictum validate base.yaml override.yaml — validates composed result."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)
        override = tmp_path / "override.yaml"
        override.write_text(OVERRIDE_BUNDLE)

        runner = CliRunner()
        result = runner.invoke(cli, ["validate", str(base), str(override)])
        assert result.exit_code == 0
        assert "Composed" in result.output
        # Composed: rule-a (overridden), rule-b (from base), rule-c (from override) = 3
        assert "3 rules" in result.output

    def test_validate_shows_overrides(self, tmp_path):
        """edictum validate with rule ID conflicts shows override info."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)
        override = tmp_path / "override.yaml"
        override.write_text(OVERRIDE_BUNDLE)

        runner = CliRunner()
        result = runner.invoke(cli, ["validate", str(base), str(override)])
        assert result.exit_code == 0
        assert "rule-a" in result.output
        assert "overridden" in result.output.lower()

    def test_validate_invalid_file_still_reports_error(self, tmp_path):
        """Invalid YAML in one file still reports the error."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)
        invalid = tmp_path / "invalid.yaml"
        invalid.write_text(INVALID_YAML)

        runner = CliRunner()
        result = runner.invoke(cli, ["validate", str(base), str(invalid)])
        assert result.exit_code == 1

    def test_validate_single_file_no_composition(self, tmp_path):
        """Single file should not show composition info."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)

        runner = CliRunner()
        result = runner.invoke(cli, ["validate", str(base)])
        assert result.exit_code == 0
        assert "Composed" not in result.output


# ---------------------------------------------------------------------------
# 2. edictum diff — composition
# ---------------------------------------------------------------------------


class TestDiffComposition:
    """Test diff command with multi-file composition."""

    def test_diff_two_files_shows_composition(self, tmp_path):
        """edictum diff base.yaml override.yaml shows both diff and composition report."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)
        override = tmp_path / "override.yaml"
        override.write_text(OVERRIDE_BUNDLE)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(base), str(override)])
        assert result.exit_code == 1
        # Standard diff: rule-c added, rule-b removed, rule-a changed
        assert "rule-c" in result.output
        # Composition report
        assert "overridden" in result.output.lower()
        assert "rule-a" in result.output

    def test_diff_three_files_shows_composition(self, tmp_path):
        """edictum diff base.yaml override.yaml third.yaml shows composition report."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)
        override = tmp_path / "override.yaml"
        override.write_text(OVERRIDE_BUNDLE)
        third = tmp_path / "third.yaml"
        third.write_text(THIRD_BUNDLE)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(base), str(override), str(third)])
        assert result.exit_code == 1
        # Composition report: rule-a overridden by override, rule-b overridden by third
        assert "overridden" in result.output.lower()
        assert "rule-a" in result.output
        assert "rule-b" in result.output

    def test_diff_invalid_file_reports_error(self, tmp_path):
        """Invalid YAML in one of the diff files reports error."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)
        invalid = tmp_path / "invalid.yaml"
        invalid.write_text(INVALID_YAML)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(base), str(invalid)])
        assert result.exit_code != 0

    def test_diff_requires_at_least_two_files(self, tmp_path):
        """diff with only 1 file should error."""
        base = tmp_path / "base.yaml"
        base.write_text(BASE_BUNDLE)

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(base)])
        assert result.exit_code != 0
