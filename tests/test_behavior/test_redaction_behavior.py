"""Behavior tests for RedactionPolicy.

Tests that constructor parameters produce observable, correct behavior.
Catches replace-vs-merge semantics bugs.
"""

from __future__ import annotations

from edictum.audit import RedactionPolicy


class TestRedactionPolicySensitiveKeysMerge:
    """Custom sensitive_keys must EXTEND defaults, not replace them."""

    def test_custom_sensitive_keys_extend_defaults(self):
        """Passing sensitive_keys must add to defaults, not replace them.

        This catches the replace-vs-merge bug: if custom keys replace
        DEFAULT_SENSITIVE_KEYS, standard secrets like 'password' leak through.
        """
        policy = RedactionPolicy(sensitive_keys={"my_custom_field"})

        # Custom key must be redacted
        custom_result = policy.redact_args({"my_custom_field": "secret"})
        assert custom_result["my_custom_field"] == "[REDACTED]"

        # DEFAULT keys must ALSO still be redacted
        default_result = policy.redact_args({"password": "secret123"})
        assert default_result["password"] == "[REDACTED]", (
            "Custom sensitive_keys replaced defaults instead of extending them. "
            "'password' should still be redacted when custom keys are provided."
        )

    def test_default_authorization_key_preserved_with_custom(self):
        """The 'authorization' key must still be redacted with custom keys."""
        policy = RedactionPolicy(sensitive_keys={"x_internal_token"})
        result = policy.redact_args({"authorization": "Bearer abc123"})
        assert result["authorization"] == "[REDACTED]", (
            "'authorization' must be redacted even when custom keys are provided."
        )

    def test_default_api_key_preserved_with_custom(self):
        """The 'api_key' key must still be redacted with custom keys."""
        policy = RedactionPolicy(sensitive_keys={"x_internal_token"})
        result = policy.redact_args({"api_key": "sk-abc123"})
        assert result["api_key"] == "[REDACTED]", "'api_key' must be redacted even when custom keys are provided."

    def test_none_sensitive_keys_uses_full_defaults(self):
        """Passing None for sensitive_keys should use all defaults."""
        policy = RedactionPolicy(sensitive_keys=None)
        for key in ("password", "secret", "token", "api_key", "authorization"):
            result = policy.redact_args({key: "secret_value"})
            assert result[key] == "[REDACTED]", f"Default key '{key}' must be redacted with None"


class TestRedactionPolicyBashPatternsMerge:
    """Custom bash patterns must EXTEND defaults, not replace them."""

    def test_custom_bash_patterns_extend_defaults(self):
        """Custom patterns must work alongside default bash patterns."""
        custom_pattern = (r"(MY_CUSTOM_VAR=)\S+", r"\1[REDACTED]")
        policy = RedactionPolicy(custom_patterns=[custom_pattern])

        # Custom pattern must work
        assert "[REDACTED]" in policy.redact_bash_command("MY_CUSTOM_VAR=secret123")

        # Default bash patterns must ALSO still work
        result = policy.redact_bash_command("export MY_SECRET_KEY=abc123")
        assert "[REDACTED]" in result, (
            "Custom patterns replaced default BASH_REDACTION_PATTERNS. "
            "Standard credential patterns should still be caught."
        )


class TestRedactionPolicySecretDetection:
    """detect_secret_values parameter must have observable effect."""

    def test_detect_secret_values_true_catches_api_keys(self):
        """With detection on, API key patterns must be redacted in values."""
        policy = RedactionPolicy(detect_secret_values=True)
        result = policy.redact_args({"data": "sk-abc123def456ghi789jkl012"})
        assert result["data"] == "[REDACTED]"

    def test_detect_secret_values_false_passes_api_keys(self):
        """With detection off, API key patterns must pass through."""
        policy = RedactionPolicy(detect_secret_values=False)
        result = policy.redact_args({"data": "sk-abc123def456ghi789jkl012"})
        assert result["data"] != "[REDACTED]"


class TestRedactionPolicyBashPatternsInStringArgs:
    """redact_args() must apply bash redaction patterns to string values.

    Without this, credentials in shell commands passed as string args
    (e.g., args={"command": "mysql --password hunter2"}) leak into audit events.
    """

    def test_password_flag_redacted_in_string_arg(self):
        """--password flag values must be redacted in string args."""
        policy = RedactionPolicy()
        result = policy.redact_args({"command": "mysql --password hunter2"})
        assert "hunter2" not in result["command"]
        assert "[REDACTED]" in result["command"]

    def test_url_credentials_redacted_in_string_arg(self):
        """Embedded URL credentials must be redacted in string args."""
        policy = RedactionPolicy()
        result = policy.redact_args({"url": "https://admin:secret123@db.example.com"})
        assert "secret123" not in result["url"]
        assert "[REDACTED]" in result["url"]

    def test_export_env_var_redacted_in_string_arg(self):
        """Export statements with sensitive env vars must be redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"script": "export API_KEY=sk-abc123"})
        assert "sk-abc123" not in result["script"]
        assert "[REDACTED]" in result["script"]

    def test_bare_string_arg_applies_bash_patterns(self):
        """Bash patterns must apply even when args is a bare string, not a dict."""
        policy = RedactionPolicy()
        result = policy.redact_args("mysql -p secret123")
        assert "secret123" not in result
        assert "[REDACTED]" in result

    def test_string_without_credentials_unchanged(self):
        """Strings without credential patterns must pass through unchanged."""
        policy = RedactionPolicy()
        result = policy.redact_args({"command": "ls -la /tmp"})
        assert result["command"] == "ls -la /tmp"
