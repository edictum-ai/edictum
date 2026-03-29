"""Sandbox rule compiler -- extract/classify tool call resources and compile sandbox rules."""

from __future__ import annotations

import os
import re
import shlex
from typing import Any

from edictum.envelope import ToolCall
from edictum.rules import Decision

# Pattern for shell redirection operators at token start.
# Matches: >>, >, <<, <, or fd-prefixed variants like 2>, 2>>.
_REDIRECT_PREFIX_RE = re.compile(r"^(?:\d*>>|>>|\d*>|>|<<|<)")

# Shell command separators that allow chaining multiple commands.
# If ANY of these appear anywhere in the raw command string, _extract_command()
# returns a sentinel value that never matches any allowlist — failing closed.
# The sandbox unconditionally denies sentinel results, even for path-only
# sandboxes without allows.commands.
# Covers: ;  |  &  &&  ||  \n  \r  `  $()  ${}  $'  <()  >()  <<<  <<
_SHELL_SEPARATOR_RE = re.compile(
    r"[;|&\n\r`]"  # bare separators
    r"|\$\("  # $( command substitution
    r"|\$\{"  # ${ variable expansion
    r"|\$'"  # $'...' ANSI-C quoting (can encode any separator)
    r"|\<\("  # <( read process substitution
    r"|>\("  # >( write process substitution
    r"|<<<|<<(?!<)"  # herestring / heredoc
)


def _tokenize_command(cmd: str) -> list[str]:
    """Shell-aware tokenization of a command string.

    Uses shlex.split() for proper quote handling, then strips shell
    redirection operators from token prefixes so paths after redirects
    (e.g. ``>/etc/passwd``, ``</etc/shadow``) are exposed.

    Falls back to basic split with quote stripping on parse error
    (fail-closed: quoted paths are still extracted).
    """
    try:
        raw_tokens = shlex.split(cmd)
    except ValueError:
        # Unclosed quotes — fall back with quote stripping
        raw_tokens = [t.strip("'\"") for t in cmd.split()]

    tokens: list[str] = []
    for t in raw_tokens:
        stripped = _REDIRECT_PREFIX_RE.sub("", t)
        if stripped:
            tokens.append(stripped)
        # If stripping leaves nothing (bare < or >), skip it
    return tokens


_PATH_ARG_KEYS = frozenset(
    {
        "path",
        "file_path",
        "filePath",
        "directory",
        "dir",
        "folder",
        "target",
        "destination",
        "source",
        "src",
        "dst",
    }
)


def _extract_paths(tool_call: ToolCall) -> list[str]:
    """Extract file paths from an tool_call for sandbox evaluation.

    Strategy (priority order):
    1. tool_call.file_path (bonus for Claude Code tools)
    2. Args values with path-like keys
    3. Args string values starting with /
    4. Parse command string for /-prefixed tokens

    Note: paths are resolved via ``os.path.realpath()`` which handles both
    ``..`` traversals AND symlinks.  TOCTOU caveat: a symlink created after
    evaluation but before tool execution is not caught; full mitigation
    requires OS-level enforcement.
    """
    paths: list[str] = []
    seen: set[str] = set()

    def _add(p: str) -> None:
        if p:
            p = os.path.realpath(p)
            if p not in seen:
                seen.add(p)
                paths.append(p)

    # 1. Envelope convenience field
    if tool_call.file_path:
        _add(tool_call.file_path)

    # 2. Path-like arg keys
    for key, value in tool_call.args.items():
        if isinstance(value, str) and key in _PATH_ARG_KEYS:
            _add(value)

    # 3. Any arg value starting with /
    for key, value in tool_call.args.items():
        if isinstance(value, str) and value.startswith("/") and key not in _PATH_ARG_KEYS:
            _add(value)

    # 4. Parse command string for path tokens (shell-aware)
    cmd = tool_call.bash_command or tool_call.args.get("command", "")
    if cmd:
        for token in _tokenize_command(cmd):
            if token.startswith("/"):
                _add(token)

    return paths


def _extract_command(tool_call: ToolCall) -> str | None:
    """Extract the first command token from an tool_call (shell-aware).

    Returns the sentinel ``\\x00`` (which never matches any allowlist) if:
    - The command contains shell separators/metacharacters that could chain
      multiple commands (;  |  &&  ||  \\n  \\r  ``  $()  ${}  $'  <()  >()  <<  <<<)
    - The command begins with a shell redirect operator (> >> < <<)

    This ensures command allowlists fail closed on any form of command
    chaining, even if the first token is allowlisted.
    """
    cmd = tool_call.bash_command or tool_call.args.get("command")
    if not cmd or not isinstance(cmd, str):
        return None
    stripped = cmd.strip()
    if not stripped:
        return None
    # Check for shell command separators/metacharacters BEFORE extracting.
    # If any are present, the shell would execute multiple commands — return
    # sentinel value that never matches any allowlist.
    if _SHELL_SEPARATOR_RE.search(stripped):
        return "\x00"
    # If the raw first whitespace-token starts with a redirect operator,
    # the "command" is actually a redirect target (filename).  We cannot
    # recover the real command, so fail closed with a sentinel value that
    # will never appear in any allowed_commands list.
    raw_first = stripped.split(maxsplit=1)[0]
    if _REDIRECT_PREFIX_RE.match(raw_first):
        return "\x00"
    tokens = _tokenize_command(stripped)
    if not tokens:
        return None
    return tokens[0]


def _extract_urls(tool_call: ToolCall) -> list[str]:
    """Extract URL strings from tool_call args (shell-aware).

    For values that contain ``://`` but are not bare URLs (e.g. command
    strings like ``curl https://evil.com``), tokenizes the value and
    extracts individual URL tokens.
    """
    urls: list[str] = []
    seen: set[str] = set()

    def _add_url(u: str) -> None:
        if u not in seen:
            seen.add(u)
            urls.append(u)

    for value in tool_call.args.values():
        if isinstance(value, str) and "://" in value:
            # Try as a bare URL first
            if _extract_hostname(value) is not None:
                _add_url(value)
            else:
                # Not a bare URL — tokenize and scan for embedded URLs
                for token in _tokenize_command(value):
                    if "://" in token and _extract_hostname(token) is not None:
                        _add_url(token)
    return urls


def _extract_hostname(url: str) -> str | None:
    """Extract hostname from a URL string."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def _domain_matches(hostname: str, patterns: list[str]) -> bool:
    """Check if hostname matches any domain pattern (supports wildcards)."""
    from fnmatch import fnmatch

    return any(fnmatch(hostname, p) for p in patterns)


def _compile_sandbox(rule: dict, mode: str) -> Any:
    """Compile a sandbox rule into a sandbox callable."""
    from edictum.yaml_engine.compiler import _expand_message

    rule_id = rule["id"]

    # Normalize tool/tools to a list
    if "tools" in rule:
        tool_patterns = rule["tools"]
    else:
        tool_patterns = [rule["tool"]]

    within = [os.path.realpath(p) for p in rule.get("within", [])]
    not_within = [os.path.realpath(p) for p in rule.get("not_within", [])]
    allows = rule.get("allows", {})
    not_allows = rule.get("not_allows", {})
    allowed_commands = allows.get("commands", [])
    allowed_domains = allows.get("domains", [])
    blocked_domains = not_allows.get("domains", [])
    outside = rule.get("outside", "block")
    message_template = rule.get("message", "Tool call outside sandbox boundary.")
    timeout = rule.get("timeout", 300)
    timeout_action = rule.get("timeout_action", "block")

    def sandbox_fn(tool_call: ToolCall) -> Decision:
        # Path checks
        if within or not_within:
            paths = _extract_paths(tool_call)
            if paths:
                # not_within: block if any path matches an exclusion
                for path in paths:
                    for excluded in not_within:
                        if path == excluded or path.startswith(excluded.rstrip("/") + "/"):
                            msg = _expand_message(message_template, tool_call)
                            return Decision.fail(msg)

                # within: every path must be within at least one allowed prefix
                if within:
                    for path in paths:
                        if not any(path == allowed or path.startswith(allowed.rstrip("/") + "/") for allowed in within):
                            msg = _expand_message(message_template, tool_call)
                            return Decision.fail(msg)

        # Command checks
        cmd_token = _extract_command(tool_call)
        # Sentinel means shell separators detected — always block,
        # even without allowed_commands (path-only sandboxes).
        if cmd_token == "\x00":
            msg = _expand_message(message_template, tool_call)
            return Decision.fail(msg)
        if allowed_commands and cmd_token is not None:
            if cmd_token not in allowed_commands:
                msg = _expand_message(message_template, tool_call)
                return Decision.fail(msg)

        # Domain checks
        urls = _extract_urls(tool_call)
        if urls:
            for url in urls:
                hostname = _extract_hostname(url)
                if hostname:
                    # not_allows.domains: block if hostname matches excluded domain
                    if blocked_domains and _domain_matches(hostname, blocked_domains):
                        msg = _expand_message(message_template, tool_call)
                        return Decision.fail(msg)
                    # allows.domains: block if hostname doesn't match any allowed domain
                    if allowed_domains and not _domain_matches(hostname, allowed_domains):
                        msg = _expand_message(message_template, tool_call)
                        return Decision.fail(msg)

        return Decision.pass_()

    # Stamp metadata for pipeline routing
    sandbox_fn.__name__ = rule_id
    sandbox_fn._edictum_type = "sandbox"
    sandbox_fn._edictum_tools = tool_patterns
    sandbox_fn._edictum_mode = mode
    sandbox_fn._edictum_id = rule_id
    sandbox_fn._edictum_source = "yaml_sandbox"
    sandbox_fn._edictum_effect = outside
    sandbox_fn._edictum_timeout = timeout
    sandbox_fn._edictum_timeout_action = timeout_action
    if rule.get("_observe"):
        sandbox_fn._edictum_observe = True

    return sandbox_fn
