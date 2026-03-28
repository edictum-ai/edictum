"""Tests for the YAML rule compiler."""

from __future__ import annotations

from pathlib import Path

from edictum.envelope import Principal, create_envelope
from edictum.yaml_engine.compiler import CompiledBundle, _expand_message, compile_contracts
from edictum.yaml_engine.loader import load_bundle

FIXTURES = Path(__file__).parent / "fixtures"


def _load_and_compile(fixture: str) -> CompiledBundle:
    data, _ = load_bundle(FIXTURES / fixture)
    return compile_contracts(data)


def _envelope(tool_name="read_file", args=None, environment="production", principal=None):
    return create_envelope(
        tool_name=tool_name,
        tool_input=args or {},
        environment=environment,
        principal=principal,
    )


class TestCompilePreConditions:
    def test_pre_contracts_compiled(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        assert len(bundle.preconditions) == 1

    def test_pre_contract_metadata(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.preconditions[0]
        assert fn.__name__ == "block-sensitive-reads"
        assert fn._edictum_type == "precondition"
        assert fn._edictum_tool == "read_file"
        assert fn._edictum_id == "block-sensitive-reads"

    def test_pre_contract_denies_matching(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.preconditions[0]
        env = _envelope(args={"path": "/home/user/.env"})
        decision = fn(env)
        assert not decision.passed
        assert "denied" in decision.message.lower() or ".env" in decision.message

    def test_pre_contract_passes_non_matching(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.preconditions[0]
        env = _envelope(args={"path": "/home/user/readme.md"})
        decision = fn(env)
        assert decision.passed

    def test_pre_contract_tags_in_metadata(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.preconditions[0]
        env = _envelope(args={"path": ".env"})
        decision = fn(env)
        assert decision.metadata.get("tags") == ["secrets", "dlp"]

    def test_pre_contract_passes_when_field_missing(self):
        """Missing field evaluates to false — rule doesn't fire."""
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.preconditions[0]
        env = _envelope(args={})
        decision = fn(env)
        assert decision.passed


class TestCompilePostConditions:
    def test_post_contracts_compiled(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        assert len(bundle.postconditions) == 1

    def test_post_contract_metadata(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.postconditions[0]
        assert fn.__name__ == "pii-in-output"
        assert fn._edictum_type == "postcondition"
        assert fn._edictum_tool == "*"

    def test_post_contract_warns_on_match(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.postconditions[0]
        env = _envelope()
        decision = fn(env, "SSN: 123-45-6789")
        assert not decision.passed
        assert decision.metadata.get("tags") == ["pii"]

    def test_post_contract_passes_no_match(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        fn = bundle.postconditions[0]
        env = _envelope()
        decision = fn(env, "No PII here")
        assert decision.passed


class TestCompileSessionContracts:
    def test_session_contracts_compiled(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        assert len(bundle.session_contracts) == 1

    def test_session_limits_merged(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        assert bundle.limits.max_tool_calls == 50
        assert bundle.limits.max_attempts == 120


class TestDisabledContracts:
    def test_disabled_contract_skipped(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "disabled-rule",
                    "type": "pre",
                    "enabled": False,
                    "tool": "read_file",
                    "when": {"args.path": {"contains": ".env"}},
                    "then": {"action": "block", "message": "denied"},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        assert len(compiled.preconditions) == 0

    def test_enabled_contract_included(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "enabled-rule",
                    "type": "pre",
                    "enabled": True,
                    "tool": "read_file",
                    "when": {"args.path": {"contains": ".env"}},
                    "then": {"action": "block", "message": "denied"},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        assert len(compiled.preconditions) == 1


class TestModeOverride:
    def test_default_mode_used(self):
        bundle = _load_and_compile("valid_bundle.yaml")
        assert bundle.default_mode == "enforce"
        # Rule without mode override inherits default
        fn = bundle.preconditions[0]
        assert fn._edictum_mode == "enforce"

    def test_per_rule_mode_override(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "observe-rule",
                    "type": "pre",
                    "mode": "observe",
                    "tool": "read_file",
                    "when": {"args.path": {"contains": ".env"}},
                    "then": {"action": "block", "message": "denied"},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        fn = compiled.preconditions[0]
        assert fn._edictum_mode == "observe"


class TestMessageTemplating:
    def test_simple_placeholder(self):
        env = _envelope(args={"path": "/etc/passwd"})
        msg = _expand_message("File '{args.path}' denied.", env)
        assert msg == "File '/etc/passwd' denied."

    def test_tool_name_placeholder(self):
        env = _envelope(tool_name="bash")
        msg = _expand_message("Tool {tool.name} denied.", env)
        assert msg == "Tool bash denied."

    def test_missing_placeholder_kept(self):
        env = _envelope(args={})
        msg = _expand_message("File '{args.path}' denied.", env)
        assert msg == "File '{args.path}' denied."

    def test_placeholder_capped_at_200(self):
        long_path = "x" * 300
        env = _envelope(args={"path": long_path})
        msg = _expand_message("{args.path}", env)
        assert len(msg) == 200
        assert msg.endswith("...")

    def test_multiple_placeholders(self):
        env = _envelope(tool_name="read_file", args={"path": "/tmp"})
        msg = _expand_message("{tool.name}: {args.path}", env)
        assert msg == "read_file: /tmp"

    def test_environment_placeholder(self):
        env = _envelope(environment="staging")
        msg = _expand_message("Env: {environment}", env)
        assert msg == "Env: staging"

    def test_principal_placeholder(self):
        env = _envelope(principal=Principal(user_id="alice"))
        msg = _expand_message("User: {principal.user_id}", env)
        assert msg == "User: alice"


class TestThenMetadata:
    def test_then_metadata_in_verdict(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "meta-rule",
                    "type": "pre",
                    "tool": "read_file",
                    "when": {"args.path": {"contains": ".env"}},
                    "then": {
                        "action": "block",
                        "message": "denied",
                        "tags": ["secrets"],
                        "metadata": {"severity": "high", "category": "dlp"},
                    },
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        fn = compiled.preconditions[0]
        env = _envelope(args={"path": ".env"})
        decision = fn(env)
        assert not decision.passed
        assert decision.metadata.get("tags") == ["secrets"]
        assert decision.metadata.get("severity") == "high"
        assert decision.metadata.get("category") == "dlp"


class TestPolicyError:
    def test_type_mismatch_sets_policy_error(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "type-mismatch",
                    "type": "pre",
                    "tool": "*",
                    "when": {"args.count": {"gt": 5}},
                    "then": {"action": "block", "message": "Count too high."},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        fn = compiled.preconditions[0]
        env = _envelope(args={"count": "not_a_number"})
        decision = fn(env)
        assert not decision.passed
        assert decision.metadata.get("policy_error") is True


class TestPostconditionEffectMetadata:
    """Tests that _edictum_effect and _edictum_redact_patterns are stamped on compiled post functions."""

    def test_effect_stamped_on_post_function(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "redact-secrets",
                    "type": "post",
                    "tool": "*",
                    "when": {"output.text": {"matches_any": ["sk-[a-z0-9]+"]}},
                    "then": {"action": "redact", "message": "Secrets found."},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        fn = compiled.postconditions[0]
        assert fn._edictum_effect == "redact"

    def test_default_effect_is_warn(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "pii-check",
                    "type": "post",
                    "tool": "*",
                    "when": {"output.text": {"matches": "\\d{3}-\\d{2}-\\d{4}"}},
                    "then": {"message": "PII detected."},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        fn = compiled.postconditions[0]
        assert fn._edictum_effect == "warn"

    def test_redact_patterns_extracted(self):
        import re

        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "redact-keys",
                    "type": "post",
                    "tool": "*",
                    "when": {"output.text": {"matches_any": ["sk-prod-[a-z0-9]{8}", "AKIA-PROD-[A-Z]{12}"]}},
                    "then": {"action": "redact", "message": "Keys found."},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        fn = compiled.postconditions[0]
        patterns = fn._edictum_redact_patterns
        assert len(patterns) == 2
        assert all(isinstance(p, re.Pattern) for p in patterns)
        # Verify they actually match expected strings
        assert patterns[0].search("sk-prod-abcd1234")
        assert patterns[1].search("AKIA-PROD-ABCDEFGHIJKL")

    def test_no_patterns_for_contains_operator(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "contains-check",
                    "type": "post",
                    "tool": "*",
                    "when": {"output.text": {"contains": "secret"}},
                    "then": {"action": "redact", "message": "Secret found."},
                }
            ],
        }
        compiled = compile_contracts(bundle_data)
        fn = compiled.postconditions[0]
        assert fn._edictum_redact_patterns == []


class TestSessionLimitsMerging:
    def test_multiple_session_contracts_merge(self):
        bundle_data = {
            "apiVersion": "edictum/v1",
            "kind": "Ruleset",
            "metadata": {"name": "test"},
            "defaults": {"mode": "enforce"},
            "rules": [
                {
                    "id": "limits-1",
                    "type": "session",
                    "limits": {"max_tool_calls": 100, "max_attempts": 200},
                    "then": {"action": "block", "message": "limit 1"},
                },
                {
                    "id": "limits-2",
                    "type": "session",
                    "limits": {
                        "max_tool_calls": 50,
                        "max_calls_per_tool": {"bash": 10},
                    },
                    "then": {"action": "block", "message": "limit 2"},
                },
            ],
        }
        compiled = compile_contracts(bundle_data)
        # Should take the more restrictive (lower) value
        assert compiled.limits.max_tool_calls == 50
        assert compiled.limits.max_attempts == 200
        assert compiled.limits.max_calls_per_tool == {"bash": 10}
