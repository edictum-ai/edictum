"""CLI integration tests for `edictum skill scan`."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from edictum.cli.main import cli

FIXTURES = Path(__file__).parent.parent / "fixtures" / "skills"


class TestSkillScanCLI:
    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_scan_single_skill_human_output(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "bird-ch")])
        assert result.exit_code == 1  # has findings
        assert "CRITICAL" in result.output

    def test_scan_clean_skill_exit_0(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "clean-weather")])
        # clean-weather is CLEAN, but still has no_contracts → depends on threshold
        # Default threshold is MEDIUM, CLEAN < MEDIUM, so exit 0
        assert result.exit_code == 0

    def test_scan_directory_finds_all(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES)])
        assert result.exit_code == 1  # CRITICAL findings exist
        assert "skills found" in result.output

    def test_json_output_is_valid(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES), "--json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "scanner_version" in data
        assert "findings" in data
        assert "stats" in data
        assert data["total_scanned"] == 8
        assert data["stats"]["critical"] >= 1

    def test_json_findings_have_risk_level(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "bird-ch"), "--json"])
        data = json.loads(result.output)
        assert len(data["findings"]) >= 1
        assert data["findings"][0]["risk_level"] == "CRITICAL"

    def test_threshold_critical_ignores_high(self) -> None:
        """--threshold CRITICAL means HIGH findings don't cause exit 1."""
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "ssh-setup"), "--threshold", "CRITICAL"])
        # ssh-setup is HIGH, threshold is CRITICAL → exit 0
        assert result.exit_code == 0

    def test_threshold_critical_catches_critical(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "bird-ch"), "--threshold", "CRITICAL"])
        assert result.exit_code == 1

    def test_structural_only(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES), "--structural-only"])
        assert "contracts.yaml" in result.output

    def test_structural_only_json(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES), "--structural-only", "--json"])
        data = json.loads(result.output)
        assert "with_contracts" in data
        assert "without_contracts" in data

    def test_verbose_shows_clean(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "clean-weather"), "--verbose"])
        assert result.exit_code == 0
        # In verbose mode, even CLEAN skills appear
        assert "weather-lookup" in result.output or "CLEAN" in result.output

    def test_nonexistent_path_fails(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_invalid_workers(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES), "--workers", "0"])
        assert result.exit_code == 2

    def test_help_text(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", "--help"])
        assert result.exit_code == 0
        assert "Scan skill directories" in result.output

    def test_skill_group_help(self) -> None:
        result = self.runner.invoke(cli, ["skill", "--help"])
        assert result.exit_code == 0
        assert "scan" in result.output


class TestSkillScanExitCodes:
    """Verify exit code semantics per spec."""

    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_exit_0_clean_skills(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "clean-weather")])
        assert result.exit_code == 0

    def test_exit_1_findings(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "bird-ch")])
        assert result.exit_code == 1

    def test_exit_1_with_json(self) -> None:
        result = self.runner.invoke(cli, ["skill", "scan", str(FIXTURES / "bird-ch"), "--json"])
        assert result.exit_code == 1
