"""Tests for postcondition violations interface."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from edictum.findings import Finding, PostCallResult, build_findings, classify_finding


class TestFinding:
    def test_creation(self):
        f = Finding(
            type="pii_detected",
            rule_id="pii-in-output",
            field="output.text",
            message="SSN pattern found",
        )
        assert f.type == "pii_detected"
        assert f.rule_id == "pii-in-output"
        assert f.field == "output.text"
        assert f.message == "SSN pattern found"
        assert f.metadata == {}

    def test_frozen(self):
        f = Finding(type="pii", rule_id="x", field="y", message="z")
        with pytest.raises(AttributeError):
            f.type = "other"

    def test_with_metadata(self):
        f = Finding(
            type="pii_detected",
            rule_id="pii-check",
            field="output.text",
            message="SSN found",
            metadata={"pattern": r"\d{3}-\d{2}-\d{4}", "match_count": 2},
        )
        assert f.metadata["match_count"] == 2

    def test_equality(self):
        f1 = Finding(type="pii", rule_id="c1", field="output", message="m")
        f2 = Finding(type="pii", rule_id="c1", field="output", message="m")
        assert f1 == f2


class TestPostCallResult:
    def test_default_passed(self):
        r = PostCallResult(result="hello")
        assert r.postconditions_passed is True
        assert r.violations == []

    def test_with_findings(self):
        violations = [
            Finding(type="pii_detected", rule_id="c1", field="output", message="SSN"),
            Finding(type="secret_detected", rule_id="c2", field="output", message="API key"),
        ]
        r = PostCallResult(result="raw output", postconditions_passed=False, violations=violations)
        assert not r.postconditions_passed
        assert len(r.violations) == 2
        assert r.violations[0].type == "pii_detected"

    def test_result_preserved(self):
        obj = {"data": [1, 2, 3]}
        r = PostCallResult(result=obj)
        assert r.result is obj


class TestClassifyFinding:
    def test_pii(self):
        assert classify_finding("pii-in-output", "SSN detected") == "pii_detected"
        assert classify_finding("check-patient-data", "found patient ID") == "pii_detected"

    def test_secret(self):
        assert classify_finding("no-secrets", "API key in output") == "secret_detected"
        assert classify_finding("credential-check", "") == "secret_detected"

    def test_limit(self):
        assert classify_finding("session-limit", "max calls exceeded") == "limit_exceeded"

    def test_default(self):
        assert classify_finding("some-rule", "something happened") == "policy_violation"

    def test_case_insensitive(self):
        assert classify_finding("PII-Check", "Found SSN") == "pii_detected"
        assert classify_finding("SECRET-SCAN", "Token found") == "secret_detected"


@dataclass
class FakePostDecision:
    """Minimal stand-in for PostDecision in tests."""

    postconditions_passed: bool = True
    contracts_evaluated: list = field(default_factory=list)


class TestBuildFindings:
    def test_field_defaults_to_output(self):
        """When no field in metadata, defaults to 'output'."""
        decision = FakePostDecision(
            postconditions_passed=False,
            contracts_evaluated=[
                {"name": "pii-check", "passed": False, "message": "SSN found"},
            ],
        )
        violations = build_findings(decision)
        assert len(violations) == 1
        assert violations[0].field == "output"

    def test_field_extracted_from_metadata(self):
        """When metadata contains 'field', it's used instead of default."""
        decision = FakePostDecision(
            postconditions_passed=False,
            contracts_evaluated=[
                {
                    "name": "pii-check",
                    "passed": False,
                    "message": "SSN found",
                    "metadata": {"field": "output.text"},
                },
            ],
        )
        violations = build_findings(decision)
        assert len(violations) == 1
        assert violations[0].field == "output.text"

    def test_skips_passed_contracts(self):
        """Only failed rules produce violations."""
        decision = FakePostDecision(
            postconditions_passed=True,
            contracts_evaluated=[
                {"name": "ok-check", "passed": True, "message": None},
            ],
        )
        violations = build_findings(decision)
        assert violations == []

    def test_metadata_preserved_in_finding(self):
        """Metadata from rule record is passed through to Finding."""
        decision = FakePostDecision(
            postconditions_passed=False,
            contracts_evaluated=[
                {
                    "name": "pii-check",
                    "passed": False,
                    "message": "SSN found",
                    "metadata": {"field": "output.text", "match_count": 3},
                },
            ],
        )
        violations = build_findings(decision)
        assert violations[0].metadata["match_count"] == 3
        assert violations[0].metadata["field"] == "output.text"
