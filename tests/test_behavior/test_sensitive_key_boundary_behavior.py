"""Behavior tests for _is_sensitive_key word-boundary matching.

Proves that whole-word matching prevents false positives on fields
like 'monkey' and 'hockey' while still catching 'api_key' and 'auth-token'.
"""

from __future__ import annotations

import pytest

from edictum.audit import RedactionPolicy


@pytest.mark.security
class TestSensitiveKeyFalsePositives:
    """Words containing 'key' as a substring must NOT be redacted."""

    def test_monkey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"monkey": "banana"})
        assert result["monkey"] == "banana"

    def test_hockey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"hockey": "puck"})
        assert result["hockey"] == "puck"

    def test_donkey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"donkey": "shrek"})
        assert result["donkey"] == "shrek"

    def test_jockey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"jockey": "rider"})
        assert result["jockey"] == "rider"

    def test_turkey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"turkey": "gobble"})
        assert result["turkey"] == "gobble"


@pytest.mark.security
class TestSensitiveKeyTruePositives:
    """Real sensitive keys must still be caught."""

    def test_api_key_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"api_key": "secret"})
        assert result["api_key"] == "[REDACTED]"

    def test_auth_token_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"auth-token": "secret"})
        assert result["auth-token"] == "[REDACTED]"

    def test_user_password_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"user_password": "secret"})
        assert result["user_password"] == "[REDACTED]"

    def test_client_secret_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"client_secret": "secret"})
        assert result["client_secret"] == "[REDACTED]"

    def test_access_credential_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"access-credential": "secret"})
        assert result["access-credential"] == "[REDACTED]"

    def test_exact_match_still_works(self):
        """Keys in DEFAULT_SENSITIVE_KEYS still match (e.g., 'apikey')."""
        policy = RedactionPolicy()
        result = policy.redact_args({"apikey": "secret"})
        assert result["apikey"] == "[REDACTED]"

    def test_bare_key_redacted(self):
        """The word 'key' alone should be redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"key": "secret"})
        assert result["key"] == "[REDACTED]"

    def test_bare_keys_redacted(self):
        """The word 'keys' alone should be redacted (plural in _SENSITIVE_PARTS)."""
        policy = RedactionPolicy()
        result = policy.redact_args({"keys": "secret"})
        assert result["keys"] == "[REDACTED]"

    def test_bare_tokens_redacted(self):
        """The word 'tokens' alone should be redacted (plural in _SENSITIVE_PARTS)."""
        policy = RedactionPolicy()
        result = policy.redact_args({"tokens": "secret"})
        assert result["tokens"] == "[REDACTED]"


@pytest.mark.security
class TestSensitiveKeyNoFalsePositivesOnCommonFields:
    """Common LLM/agent fields must NOT be redacted."""

    def test_max_tokens_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"max_tokens": 1024})
        assert result["max_tokens"] == 1024

    def test_num_tokens_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"num_tokens": 512})
        assert result["num_tokens"] == 512

    def test_input_tokens_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"input_tokens": 100})
        assert result["input_tokens"] == 100

    def test_output_tokens_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"output_tokens": 200})
        assert result["output_tokens"] == 200

    def test_sort_keys_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"sort_keys": True})
        assert result["sort_keys"] is True

    def test_index_keys_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"index_keys": ["id", "name"]})
        assert result["index_keys"] == ["id", "name"]

    def test_total_tokens_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"total_tokens": 2048})
        assert result["total_tokens"] == 2048

    def test_completion_tokens_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"completion_tokens": 300})
        assert result["completion_tokens"] == 300

    def test_prompt_tokens_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"prompt_tokens": 150})
        assert result["prompt_tokens"] == 150

    def test_webhook_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"webhook": "https://example.com"})
        assert result["webhook"] == "https://example.com"

    def test_bucket_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"bucket": "my-bucket"})
        assert result["bucket"] == "my-bucket"

    def test_socket_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"socket": "/var/run/app.sock"})
        assert result["socket"] == "/var/run/app.sock"

    def test_market_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"market": "US"})
        assert result["market"] == "US"

    def test_max_tokens_hyphen_variant_not_redacted(self):
        """Hyphenated safe keys (max-tokens) must also be safe (#157 review)."""
        policy = RedactionPolicy()
        result = policy.redact_args({"max-tokens": 1024})
        assert result["max-tokens"] == 1024

    def test_sort_keys_hyphen_variant_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"sort-keys": True})
        assert result["sort-keys"] is True
