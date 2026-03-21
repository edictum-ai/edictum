"""Behavior tests for plural sensitive key matching.

Proves that plural forms (tokens, keys, secrets, passwords, credentials)
are caught both as compound keys and as standalone word parts.
"""

from __future__ import annotations

import pytest

from edictum.audit import RedactionPolicy


@pytest.mark.security
class TestSensitiveKeyPluralForms:
    """Specific plural compound keys in DEFAULT_SENSITIVE_KEYS must be caught."""

    def test_user_credentials_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"user_credentials": "secret"})
        assert result["user_credentials"] == "[REDACTED]"

    def test_api_tokens_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"api_tokens": "secret"})
        assert result["api_tokens"] == "[REDACTED]"

    def test_db_passwords_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"db_passwords": "secret"})
        assert result["db_passwords"] == "[REDACTED]"

    def test_oauth_secrets_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"oauth_secrets": "secret"})
        assert result["oauth_secrets"] == "[REDACTED]"

    def test_encryption_keys_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"encryption_keys": "secret"})
        assert result["encryption_keys"] == "[REDACTED]"


@pytest.mark.security
class TestSensitiveKeyGenericPlurals:
    """Plural sensitive word parts must be caught generically (#139)."""

    def test_aws_secrets_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"aws_secrets": "val"})
        assert result["aws_secrets"] == "[REDACTED]"

    def test_stored_passwords_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"stored_passwords": "val"})
        assert result["stored_passwords"] == "[REDACTED]"

    def test_service_credentials_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"service_credentials": "val"})
        assert result["service_credentials"] == "[REDACTED]"

    def test_auth_tokens_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"auth-tokens": "val"})
        assert result["auth-tokens"] == "[REDACTED]"

    def test_signing_keys_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"signing_keys": "val"})
        assert result["signing_keys"] == "[REDACTED]"
