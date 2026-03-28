"""Behavior tests for custom_operators parameter."""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from edictum import Edictum, EdictumConfigError, EdictumDenied

# ---------------------------------------------------------------------------
# YAML templates
# ---------------------------------------------------------------------------

YAML_IBAN_CHECK = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: iban-check
defaults:
  mode: enforce
rules:
  - id: reject-invalid-iban
    type: pre
    tool: wire_transfer
    when:
      args.destination_account: { is_invalid_iban: true }
    then:
      action: block
      message: "Invalid IBAN: {args.destination_account}"
"""

YAML_POST_PII = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: pii-check
defaults:
  mode: enforce
rules:
  - id: detect-pii
    type: post
    tool: lookup_customer
    when:
      output.text: { has_pii_pattern: true }
    then:
      action: warn
      message: "PII detected in output"
"""

YAML_UNKNOWN_OP = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: unknown-op
defaults:
  mode: enforce
rules:
  - id: uses-unknown
    type: pre
    tool: some_tool
    when:
      args.value: { totally_unknown_op: true }
    then:
      action: block
      message: "Should not compile"
"""

YAML_ALL_COMBINATOR = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: combinator-test
defaults:
  mode: enforce
rules:
  - id: all-combined
    type: pre
    tool: deploy
    when:
      all:
        - args.region: { is_restricted_region: true }
        - args.service: { contains: "prod" }
    then:
      action: block
      message: "Cannot deploy to restricted region in prod"
"""

YAML_ANY_COMBINATOR = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: any-combinator
defaults:
  mode: enforce
rules:
  - id: any-combined
    type: pre
    tool: execute
    when:
      any:
        - args.cmd: { is_dangerous_command: true }
        - args.cmd: { contains: "rm -rf" }
    then:
      action: block
      message: "Dangerous command denied"
"""

YAML_DISALLOWED_HOST = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: host-check
defaults:
  mode: enforce
rules:
  - id: disallowed-host
    type: pre
    tool: api_call
    when:
      args.url: { is_disallowed_host: true }
    then:
      action: block
      message: "Host not allowed"
"""

YAML_MISSING_FIELD = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: missing-field
defaults:
  mode: enforce
rules:
  - id: check-missing
    type: pre
    tool: some_tool
    when:
      args.nonexistent_field: { custom_check: true }
    then:
      action: block
      message: "Should not fire for missing fields"
"""

YAML_MULTI_CUSTOM = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: multi-custom
defaults:
  mode: enforce
rules:
  - id: check-cidr
    type: pre
    tool: connect
    when:
      args.ip: { is_private_cidr: true }
    then:
      action: block
      message: "Private CIDR denied"
  - id: check-semver
    type: pre
    tool: install
    when:
      args.version: { is_prerelease: true }
    then:
      action: block
      message: "Pre-release version denied"
"""


# ---------------------------------------------------------------------------
# Operator implementations for tests
# ---------------------------------------------------------------------------

_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}$")


def _is_invalid_iban(field_value: str, op_value: bool) -> bool:
    """Returns True when the IBAN is invalid (the block condition)."""
    valid = bool(_IBAN_RE.match(field_value))
    return (not valid) == op_value


def _has_pii_pattern(field_value: str, op_value: bool) -> bool:
    """Returns True when SSN-like patterns are found."""
    found = bool(re.search(r"\d{3}-\d{2}-\d{4}", field_value))
    return found == op_value


def _is_restricted_region(field_value: str, op_value: bool) -> bool:
    restricted = field_value in {"cn-north-1", "ru-central-1"}
    return restricted == op_value


def _is_dangerous_command(field_value: str, op_value: bool) -> bool:
    dangerous = any(k in field_value for k in ["shutdown", "format"])
    return dangerous == op_value


def _is_disallowed_host(field_value: str, op_value: bool) -> bool:
    disallowed = not field_value.startswith("https://api.example.com")
    return disallowed == op_value


def _custom_check(field_value, op_value) -> bool:
    return True  # pragma: no cover — should never be called for missing fields


def _is_private_cidr(field_value: str, op_value: bool) -> bool:
    private = field_value.startswith("10.") or field_value.startswith("192.168.")
    return private == op_value


def _is_prerelease(field_value: str, op_value: bool) -> bool:
    pre = "-" in field_value  # e.g. "1.0.0-beta"
    return pre == op_value


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestCustomOperatorDeniesMatching:
    """Custom operator returns True for the block condition and the call is denied."""

    @pytest.mark.asyncio
    async def test_invalid_iban_denied(self):
        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": _is_invalid_iban},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Invalid IBAN"):
            await guard.run("wire_transfer", {"destination_account": "BOGUS"}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_valid_iban_allowed(self):
        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": _is_invalid_iban},
            audit_sink=_null_sink(),
        )
        result = await guard.run(
            "wire_transfer",
            {"destination_account": "DE89370400440532013000"},
            _dummy_tool,
        )
        assert result == "ok"


class TestCustomOperatorPostcondition:
    """Custom operator works in postcondition rules."""

    @pytest.mark.asyncio
    async def test_pii_in_output_warns(self):
        guard = Edictum.from_yaml_string(
            YAML_POST_PII,
            custom_operators={"has_pii_pattern": _has_pii_pattern},
            audit_sink=_null_sink(),
        )

        async def _tool_with_pii(**kwargs):
            return "Customer SSN: 123-45-6789"

        result = await guard.run("lookup_customer", {}, _tool_with_pii)
        # Warn action does not raise, but postcondition fires
        assert result is not None

    @pytest.mark.asyncio
    async def test_no_pii_clean(self):
        guard = Edictum.from_yaml_string(
            YAML_POST_PII,
            custom_operators={"has_pii_pattern": _has_pii_pattern},
            audit_sink=_null_sink(),
        )

        async def _clean_tool(**kwargs):
            return "Customer name: Alice"

        result = await guard.run("lookup_customer", {}, _clean_tool)
        assert result == "Customer name: Alice"


class TestFromYamlFilePath:
    """Custom operators work with from_yaml() loading from a file path."""

    @pytest.mark.asyncio
    async def test_from_yaml_with_custom_operators(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text(YAML_IBAN_CHECK)

        guard = Edictum.from_yaml(
            yaml_file,
            custom_operators={"is_invalid_iban": _is_invalid_iban},
            audit_sink=_null_sink(),
        )

        with pytest.raises(EdictumDenied, match="Invalid IBAN"):
            await guard.run("wire_transfer", {"destination_account": "BAD"}, _dummy_tool)


class TestFromTemplate:
    """from_template() accepts the custom_operators parameter."""

    def test_from_template_accepts_custom_operators(self):
        guard = Edictum.from_template(
            "file-agent",
            custom_operators={"my_noop": lambda fv, ov: False},
        )
        assert guard is not None


class TestCustomOperatorNameClash:
    """Passing a built-in operator name raises EdictumConfigError."""

    @pytest.mark.parametrize(
        "builtin_name",
        [
            "exists",
            "equals",
            "not_equals",
            "in",
            "not_in",
            "contains",
            "contains_any",
            "starts_with",
            "ends_with",
            "matches",
            "matches_any",
            "gt",
            "gte",
            "lt",
            "lte",
        ],
    )
    def test_each_builtin_clashes(self, builtin_name):
        with pytest.raises(EdictumConfigError, match="clash with built-in operators"):
            Edictum.from_yaml_string(
                YAML_IBAN_CHECK,
                custom_operators={builtin_name: lambda fv, ov: False},
            )


class TestNonCallableValidation:
    """Non-callable values in custom_operators raise EdictumConfigError."""

    def test_string_value_rejected(self):
        with pytest.raises(EdictumConfigError, match="not callable"):
            Edictum.from_yaml_string(
                YAML_IBAN_CHECK,
                custom_operators={"my_op": "not_a_function"},
            )

    def test_int_value_rejected(self):
        with pytest.raises(EdictumConfigError, match="not callable"):
            Edictum.from_yaml_string(
                YAML_IBAN_CHECK,
                custom_operators={"my_op": 42},
            )


class TestUnknownOperatorAtCompileTime:
    """Unknown operators in YAML raise EdictumConfigError at compile time."""

    def test_unknown_op_raises(self):
        with pytest.raises(EdictumConfigError, match="unknown operator 'totally_unknown_op'"):
            Edictum.from_yaml_string(YAML_UNKNOWN_OP)

    def test_registering_makes_it_compile(self):
        guard = Edictum.from_yaml_string(
            YAML_UNKNOWN_OP,
            custom_operators={"totally_unknown_op": lambda fv, ov: False},
        )
        assert guard is not None


class TestCustomOperatorArguments:
    """Custom operator receives the correct (field_value, operator_value) pair."""

    @pytest.mark.asyncio
    async def test_receives_correct_args(self):
        spy = MagicMock(return_value=True)

        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": spy},
            audit_sink=_null_sink(),
        )

        with pytest.raises(EdictumDenied):
            await guard.run(
                "wire_transfer",
                {"destination_account": "TEST123"},
                _dummy_tool,
            )

        spy.assert_called_once_with("TEST123", True)


class TestReturnValueCoercion:
    """Truthy non-bool returns are coerced to bool via bool()."""

    @pytest.mark.asyncio
    async def test_integer_one_treated_as_true(self):
        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": lambda fv, ov: 1},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied):
            await guard.run("wire_transfer", {"destination_account": "X"}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_zero_treated_as_false(self):
        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": lambda fv, ov: 0},
            audit_sink=_null_sink(),
        )
        result = await guard.run("wire_transfer", {"destination_account": "X"}, _dummy_tool)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_nonempty_string_treated_as_true(self):
        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": lambda fv, ov: "yes"},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied):
            await guard.run("wire_transfer", {"destination_account": "X"}, _dummy_tool)


class TestBooleanCombinators:
    """Custom operators compose correctly inside all/any/not expressions."""

    @pytest.mark.asyncio
    async def test_all_both_true_denies(self):
        guard = Edictum.from_yaml_string(
            YAML_ALL_COMBINATOR,
            custom_operators={"is_restricted_region": _is_restricted_region},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="restricted region"):
            await guard.run(
                "deploy",
                {"region": "cn-north-1", "service": "prod-api"},
                _dummy_tool,
            )

    @pytest.mark.asyncio
    async def test_all_one_false_allows(self):
        guard = Edictum.from_yaml_string(
            YAML_ALL_COMBINATOR,
            custom_operators={"is_restricted_region": _is_restricted_region},
            audit_sink=_null_sink(),
        )
        result = await guard.run(
            "deploy",
            {"region": "us-east-1", "service": "prod-api"},
            _dummy_tool,
        )
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_any_first_true_denies(self):
        guard = Edictum.from_yaml_string(
            YAML_ANY_COMBINATOR,
            custom_operators={"is_dangerous_command": _is_dangerous_command},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Dangerous command"):
            await guard.run("execute", {"cmd": "shutdown -h now"}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_any_second_true_denies(self):
        guard = Edictum.from_yaml_string(
            YAML_ANY_COMBINATOR,
            custom_operators={"is_dangerous_command": _is_dangerous_command},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Dangerous command"):
            await guard.run("execute", {"cmd": "rm -rf /"}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_any_neither_true_allows(self):
        guard = Edictum.from_yaml_string(
            YAML_ANY_COMBINATOR,
            custom_operators={"is_dangerous_command": _is_dangerous_command},
            audit_sink=_null_sink(),
        )
        result = await guard.run("execute", {"cmd": "echo hello"}, _dummy_tool)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_disallowed_host_denied(self):
        guard = Edictum.from_yaml_string(
            YAML_DISALLOWED_HOST,
            custom_operators={"is_disallowed_host": _is_disallowed_host},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Host not allowed"):
            await guard.run(
                "api_call",
                {"url": "https://evil.example.com/steal"},
                _dummy_tool,
            )

    @pytest.mark.asyncio
    async def test_allowed_host_passes(self):
        guard = Edictum.from_yaml_string(
            YAML_DISALLOWED_HOST,
            custom_operators={"is_disallowed_host": _is_disallowed_host},
            audit_sink=_null_sink(),
        )
        result = await guard.run(
            "api_call",
            {"url": "https://api.example.com/data"},
            _dummy_tool,
        )
        assert result == "ok"

    def test_not_combinator_via_evaluator(self):
        """Verify not: combinator works with custom operators at the evaluator level."""
        from edictum.envelope import create_envelope
        from edictum.yaml_engine.evaluator import evaluate_expression

        env = create_envelope("api_call", {"url": "https://evil.example.com"})
        custom_ops = {"is_safe_url": lambda fv, ov: fv.startswith("https://api.example.com") == ov}

        # not(is_safe_url: true) on unsafe URL -> not(False) -> True
        expr = {"not": {"args.url": {"is_safe_url": True}}}
        assert evaluate_expression(expr, env, custom_operators=custom_ops) is True

        # not(is_safe_url: true) on safe URL -> not(True) -> False
        safe_env = create_envelope("api_call", {"url": "https://api.example.com/data"})
        assert evaluate_expression(expr, safe_env, custom_operators=custom_ops) is False


class TestMissingFieldSkipsCustomOperator:
    """When the selector field is missing, the custom operator is NOT called."""

    @pytest.mark.asyncio
    async def test_missing_field_allows(self):
        spy = MagicMock(return_value=True)
        guard = Edictum.from_yaml_string(
            YAML_MISSING_FIELD,
            custom_operators={"custom_check": spy},
            audit_sink=_null_sink(),
        )
        result = await guard.run("some_tool", {}, _dummy_tool)
        assert result == "ok"
        spy.assert_not_called()


class TestCustomOperatorTypeError:
    """TypeError from a custom operator is treated as a policy_error (fail-closed)."""

    @pytest.mark.asyncio
    async def test_type_error_causes_deny(self):
        def _bad_op(field_value, op_value):
            raise TypeError("cannot compare")

        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": _bad_op},
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied):
            await guard.run("wire_transfer", {"destination_account": "X"}, _dummy_tool)

    def test_type_error_sets_policy_error_in_evaluate(self):
        def _bad_op(field_value, op_value):
            raise TypeError("cannot compare")

        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": _bad_op},
        )
        result = guard.evaluate("wire_transfer", {"destination_account": "X"})
        assert result.decision == "block"
        assert result.policy_error is True


class TestDryRunEvaluation:
    """guard.evaluate() (dry-run API) works with custom operators."""

    def test_evaluate_denies_with_custom_op(self):
        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": _is_invalid_iban},
        )
        result = guard.evaluate("wire_transfer", {"destination_account": "INVALID"})
        assert result.decision == "block"

    def test_evaluate_allows_with_custom_op(self):
        guard = Edictum.from_yaml_string(
            YAML_IBAN_CHECK,
            custom_operators={"is_invalid_iban": _is_invalid_iban},
        )
        result = guard.evaluate("wire_transfer", {"destination_account": "DE89370400440532013000"})
        assert result.decision == "allow"

    def test_evaluate_post_with_custom_op(self):
        guard = Edictum.from_yaml_string(
            YAML_POST_PII,
            custom_operators={"has_pii_pattern": _has_pii_pattern},
        )
        result = guard.evaluate("lookup_customer", {}, output="SSN: 123-45-6789")
        assert result.decision == "warn"


class TestMultipleCustomOperators:
    """Multiple custom operators registered simultaneously all work."""

    @pytest.mark.asyncio
    async def test_first_operator_denies(self):
        guard = Edictum.from_yaml_string(
            YAML_MULTI_CUSTOM,
            custom_operators={
                "is_private_cidr": _is_private_cidr,
                "is_prerelease": _is_prerelease,
            },
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Private CIDR"):
            await guard.run("connect", {"ip": "10.0.0.1"}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_second_operator_denies(self):
        guard = Edictum.from_yaml_string(
            YAML_MULTI_CUSTOM,
            custom_operators={
                "is_private_cidr": _is_private_cidr,
                "is_prerelease": _is_prerelease,
            },
            audit_sink=_null_sink(),
        )
        with pytest.raises(EdictumDenied, match="Pre-release version"):
            await guard.run("install", {"version": "1.0.0-beta"}, _dummy_tool)

    @pytest.mark.asyncio
    async def test_both_pass_allows(self):
        guard = Edictum.from_yaml_string(
            YAML_MULTI_CUSTOM,
            custom_operators={
                "is_private_cidr": _is_private_cidr,
                "is_prerelease": _is_prerelease,
            },
            audit_sink=_null_sink(),
        )
        result = await guard.run("connect", {"ip": "8.8.8.8"}, _dummy_tool)
        assert result == "ok"
        result2 = await guard.run("install", {"version": "1.0.0"}, _dummy_tool)
        assert result2 == "ok"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _dummy_tool(**kwargs):
    return "ok"


def _null_sink():
    class _Sink:
        async def emit(self, event):
            pass

    return _Sink()
