"""Security tests for sandbox parser shell-awareness.

Verifies fixes for:
- #98: Quoted paths and redirection bypass _extract_paths()
- #100: Domain allowlist bypass for command-based tools in _extract_urls()

Root cause: naive str.split() for shell command tokenization.
Fix: shlex.split() via _tokenize_command() helper.
"""

from __future__ import annotations

import pytest

from edictum import Edictum, create_envelope
from edictum.storage import MemoryBackend
from edictum.yaml_engine.sandbox_compiler import _extract_paths, _extract_urls

pytestmark = pytest.mark.security


class NullSink:
    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


def _guard(yaml: str) -> Edictum:
    return Edictum.from_yaml_string(yaml, audit_sink=NullSink(), backend=MemoryBackend())


# --- YAML fixtures ---

WITHIN_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: parser-path-test
defaults:
  mode: enforce
rules:
  - id: exec-sandbox
    type: sandbox
    tools: [exec]
    allows:
      commands: [cat, echo, cmd, head]
    within: [/workspace]
    outside: block
    message: "Path outside sandbox"
"""

DOMAIN_ALLOW_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: parser-domain-test
defaults:
  mode: enforce
rules:
  - id: exec-sandbox
    type: sandbox
    tools: [exec]
    allows:
      commands: [curl, wget]
      domains: [github.com, example.com]
    outside: block
    message: "Domain not allowed"
"""

DOMAIN_BLOCK_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: parser-domain-block-test
defaults:
  mode: enforce
rules:
  - id: exec-sandbox
    type: sandbox
    tools: [exec]
    allows:
      commands: [curl, wget]
      domains: ['*']
    not_allows:
      domains: [evil.com]
    outside: block
    message: "Domain denied"
"""

COMBINED_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: parser-combined-test
defaults:
  mode: enforce
rules:
  - id: exec-sandbox
    type: sandbox
    tools: [exec]
    allows:
      commands: [curl]
      domains: [github.com]
    within: [/workspace]
    outside: block
    message: "Outside sandbox"
"""


# =============================================================================
# Issue #98: Quoted paths and redirection bypass _extract_paths()
# =============================================================================


class TestQuotedPathBypass:
    """Quoted paths in commands must be extracted and checked by sandbox."""

    def test_quoted_single_path_denied(self):
        """cat '/etc/shadow' -- single-quoted path must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "cat '/etc/shadow'"})
        assert result.decision == "block"

    def test_quoted_double_path_denied(self):
        """cat "/etc/shadow" -- double-quoted path must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": 'cat "/etc/shadow"'})
        assert result.decision == "block"

    def test_legitimate_quoted_path_in_workspace_allowed(self):
        """cat '/workspace/file.txt' -- quoted path within sandbox is allowed."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "cat '/workspace/file.txt'"})
        assert result.decision == "allow"

    def test_legitimate_unquoted_path_still_works(self):
        """cat /workspace/file.txt -- regression: unquoted paths still work."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "cat /workspace/file.txt"})
        assert result.decision == "allow"


class TestRedirectionPathBypass:
    """Shell redirections must not hide paths from sandbox checks."""

    def test_redirection_input_path_denied(self):
        """cat </etc/shadow -- input redirection path must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "cat </etc/shadow"})
        assert result.decision == "block"

    def test_redirection_output_path_denied(self):
        """echo x >/etc/passwd -- output redirection path must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "echo x >/etc/passwd"})
        assert result.decision == "block"

    def test_redirection_append_path_denied(self):
        """echo x >>/etc/passwd -- append redirection path must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "echo x >>/etc/passwd"})
        assert result.decision == "block"

    def test_fd_redirection_path_denied(self):
        """cmd 2>/etc/log -- fd redirection path must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "cmd 2>/etc/log"})
        assert result.decision == "block"


class TestLeadingRedirectBypass:
    """Command strings starting with a redirect operator must not match allowed commands."""

    def test_leading_redirect_command_denied(self):
        """> echo bad_cmd -- redirect target 'echo' must not match allowed command 'echo'."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "> echo /workspace/file"})
        assert result.decision == "block"

    def test_leading_double_redirect_command_denied(self):
        """>> echo bad_cmd -- append redirect target must also be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": ">> echo /workspace/file"})
        assert result.decision == "block"

    def test_leading_input_redirect_command_denied(self):
        """< cat /workspace/file -- input redirect prefix must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "< cat /workspace/file"})
        assert result.decision == "block"

    def test_leading_fd_redirect_command_denied(self):
        """2> echo /workspace/file -- fd redirect prefix must be denied."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "2> echo /workspace/file"})
        assert result.decision == "block"


class TestMixedBypassVectors:
    """Multiple bypass vectors combined in a single command."""

    def test_mixed_quoting_and_redirection(self):
        """cat '/workspace/ok' >/etc/shadow -- quoted OK path + redirect to bad path."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "cat '/workspace/ok' >/etc/shadow"})
        assert result.decision == "block"

    def test_unclosed_quote_fails_closed(self):
        """cat '/etc/shadow -- unclosed quote must still be denied (fail-closed)."""
        guard = _guard(WITHIN_YAML)
        result = guard.evaluate("exec", {"command": "cat '/etc/shadow"})
        assert result.decision == "block"


class TestExtractPathsShellAwareness:
    """Unit tests for _extract_paths with shell-aware tokenization."""

    def test_single_quoted_path_extracted(self):
        """shlex.split strips single quotes, exposing the path."""
        tool_call = create_envelope("exec", {"command": "cat '/etc/shadow'"})
        paths = _extract_paths(tool_call)
        resolved = [p for p in paths if p.endswith("/etc/shadow") or "shadow" in p]
        assert len(resolved) > 0

    def test_double_quoted_path_extracted(self):
        """shlex.split strips double quotes, exposing the path."""
        tool_call = create_envelope("exec", {"command": 'cat "/etc/shadow"'})
        paths = _extract_paths(tool_call)
        resolved = [p for p in paths if p.endswith("/etc/shadow") or "shadow" in p]
        assert len(resolved) > 0

    def test_redirection_path_extracted(self):
        """shlex.split separates < from the path."""
        tool_call = create_envelope("exec", {"command": "cat </etc/shadow"})
        paths = _extract_paths(tool_call)
        resolved = [p for p in paths if p.endswith("/etc/shadow") or "shadow" in p]
        assert len(resolved) > 0

    def test_output_redirection_path_extracted(self):
        """shlex.split separates > from path or the path is extracted from >/path."""
        tool_call = create_envelope("exec", {"command": "echo x >/etc/passwd"})
        paths = _extract_paths(tool_call)
        resolved = [p for p in paths if "passwd" in p]
        assert len(resolved) > 0


# =============================================================================
# Issue #100: Domain allowlist bypass for command-based tools
# =============================================================================


class TestCommandDomainBypass:
    """URLs embedded in command strings must be extracted for domain checks."""

    def test_curl_url_domain_enforced(self):
        """curl https://evil.com -- domain must be checked against allowlist."""
        guard = _guard(DOMAIN_ALLOW_YAML)
        result = guard.evaluate("exec", {"command": "curl https://evil.com"})
        assert result.decision == "block"

    def test_curl_flagged_url_domain_enforced(self):
        """curl -L https://evil.com/path -- flags before URL must not hide it."""
        guard = _guard(DOMAIN_ALLOW_YAML)
        result = guard.evaluate("exec", {"command": "curl -L https://evil.com/path"})
        assert result.decision == "block"

    def test_wget_url_domain_enforced(self):
        """wget https://evil.com -- wget URL must also be checked."""
        guard = _guard(DOMAIN_ALLOW_YAML)
        result = guard.evaluate("exec", {"command": "wget https://evil.com"})
        assert result.decision == "block"

    def test_curl_allowed_domain_passes(self):
        """curl https://github.com -- allowed domain must pass."""
        guard = _guard(DOMAIN_ALLOW_YAML)
        result = guard.evaluate("exec", {"command": "curl https://github.com"})
        assert result.decision == "allow"

    def test_quoted_url_in_command_enforced(self):
        """curl 'https://evil.com' -- quoted URL must also be checked."""
        guard = _guard(DOMAIN_ALLOW_YAML)
        result = guard.evaluate("exec", {"command": "curl 'https://evil.com'"})
        assert result.decision == "block"

    def test_direct_url_arg_still_works(self):
        """args={"url": "https://evil.com"} -- regression: direct URL args still checked."""
        guard = _guard(DOMAIN_ALLOW_YAML)
        result = guard.evaluate("exec", {"url": "https://evil.com"})
        assert result.decision == "block"

    def test_blocked_domain_in_command(self):
        """curl https://evil.com with not_allows.domains=[evil.com] -- must be denied."""
        guard = _guard(DOMAIN_BLOCK_YAML)
        result = guard.evaluate("exec", {"command": "curl https://evil.com"})
        assert result.decision == "block"


class TestExtractUrlsShellAwareness:
    """Unit tests for _extract_urls with shell-aware tokenization."""

    def test_command_string_url_extracted(self):
        """'curl https://evil.com' is tokenized; URL extracted from token."""
        tool_call = create_envelope("exec", {"command": "curl https://evil.com"})
        urls = _extract_urls(tool_call)
        assert any("evil.com" in u for u in urls)

    def test_bare_url_still_extracted(self):
        """Direct URL value is still extracted (regression)."""
        tool_call = create_envelope("web_fetch", {"url": "https://github.com/repo"})
        urls = _extract_urls(tool_call)
        assert "https://github.com/repo" in urls

    def test_non_url_string_with_protocol_ignored(self):
        """String with :// but no valid hostname is not returned as URL."""
        tool_call = create_envelope("exec", {"command": "echo '://' something"})
        urls = _extract_urls(tool_call)
        assert len(urls) == 0


class TestCombinedPathAndDomain:
    """Both path and domain enforcement work together in a single sandbox."""

    def test_command_with_both_path_and_url(self):
        """curl with path and URL -- both checks apply."""
        guard = _guard(COMBINED_YAML)
        result = guard.evaluate("exec", {"command": "curl https://evil.com -o /workspace/file"})
        assert result.decision == "block"

    def test_no_command_arg_unchanged(self):
        """Non-command tools are unaffected by shell tokenization."""
        guard = _guard(COMBINED_YAML)
        result = guard.evaluate("read_file", {"path": "/workspace/file.txt"})
        assert result.decision == "allow"
