"""Behavior tests for value-level secret detection on safe-listed keys.

Proves that safe-listed keys (max_tokens, sort_keys, etc.) bypass key-name
detection but SECRET_VALUE_PATTERNS still catch secret values through
redact_args recursion — defense-in-depth against accidental credential leaks.
"""

from __future__ import annotations

import pytest

from edictum.audit import RedactionPolicy


@pytest.mark.security
class TestSafeListedKeysValueDetection:
    """Safe-listed keys bypass key-name detection but value-level detection still applies."""

    def test_safe_key_with_openai_key_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"max_tokens": "sk-reallyLongSecretKeyForTesting123"})
        assert result["max_tokens"] == "[REDACTED]"

    def test_safe_key_with_aws_key_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"num_tokens": "AKIAIOSFODNN7EXAMPLE"})
        assert result["num_tokens"] == "[REDACTED]"

    def test_safe_key_with_jwt_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"output_tokens": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload"})
        assert result["output_tokens"] == "[REDACTED]"

    def test_safe_key_with_github_token_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"sort_keys": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"})
        assert result["sort_keys"] == "[REDACTED]"

    def test_safe_key_with_slack_token_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"index_keys": "xoxb-1234567890-abcdefghij"})
        assert result["index_keys"] == "[REDACTED]"

    def test_safe_key_with_numeric_value_not_redacted(self):
        """Normal numeric values on safe-listed keys are not redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"max_tokens": 1024})
        assert result["max_tokens"] == 1024

    def test_safe_key_with_normal_string_not_redacted(self):
        """Normal string values on safe-listed keys are not redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"sort_keys": "name,date"})
        assert result["sort_keys"] == "name,date"
