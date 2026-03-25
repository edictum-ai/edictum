"""Code block and frontmatter analysis for skill scanning.

Deterministic feature extraction from individual code blocks and
YAML frontmatter. All functions operate on string content — no
filesystem access.
"""

from __future__ import annotations

import base64
import math
import re
from typing import Any

from edictum.skill._types import Base64BlobInfo, CodeBlockFeatures, FrontmatterFeatures
from edictum.skill.patterns import (
    BASE64_RE,
    CREDENTIAL_PATH_PATTERNS,
    DANGEROUS_COMMAND_PATTERNS,
    ENV_VAR_RE,
    FILE_PATH_RE,
    FRONTMATTER_RE,
    IP_RE,
    OBFUSCATION_SIGNALS,
    PASSWORD_ARCHIVE_RE,
    PIPE_TO_SHELL_RE,
    SHELL_LANGUAGES,
    URL_RE,
    is_exfil_domain,
)

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_domain(url: str) -> str:
    """Extract the domain (host) from a URL string.

    Uses .hostname (not .netloc) to strip userinfo and port correctly.
    This prevents bypass via URLs like ``https://x@webhook.site/``
    where .netloc would return ``x@webhook.site``.
    """
    import urllib.parse

    try:
        parsed = urllib.parse.urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def get_line_number(content: str, char_offset: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return content[:char_offset].count("\n") + 1


# ---------------------------------------------------------------------------
# Base64 classification — NO raw content in output
# ---------------------------------------------------------------------------


def classify_base64_blob(raw: str) -> Base64BlobInfo | None:
    """Decode and classify a base64 blob without leaking raw content.

    Returns classification with entropy and optional danger signal,
    but never the decoded content itself.
    """
    try:
        decoded_bytes = base64.b64decode(raw, validate=True)
    except Exception:
        return None

    length = len(decoded_bytes)
    if length == 0:
        return None

    try:
        decoded_text = decoded_bytes.decode("utf-8", errors="strict")
        is_text = True
    except UnicodeDecodeError:
        is_text = False
        decoded_text = ""

    entropy = shannon_entropy(raw)

    if not is_text:
        return Base64BlobInfo(length=length, classification="binary", entropy=round(entropy, 2))

    danger: str | None = None
    classification = "text"

    for pat, label in DANGEROUS_COMMAND_PATTERNS:
        if pat.search(decoded_text):
            danger = label
            classification = "shell_command"
            break

    if classification == "text":
        if URL_RE.search(decoded_text):
            classification = "url"
        elif re.search(r"^#!.*(?:sh|python|ruby|perl|node)", decoded_text):
            classification = "shell_command"
        elif PIPE_TO_SHELL_RE.search(decoded_text):
            classification = "shell_command"
            danger = "pipe_to_shell"

    return Base64BlobInfo(
        length=length, classification=classification, entropy=round(entropy, 2), dangerous_pattern=danger
    )


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------


def parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
    """Parse YAML frontmatter from a SKILL.md file.

    Uses yaml.safe_load to prevent arbitrary deserialization of untrusted input.
    Returns (parsed_dict, body_without_frontmatter).
    """
    match = FRONTMATTER_RE.match(content)
    if not match:
        return {}, content

    yaml_text = match.group(1)
    body = content[match.end() :]

    if not _HAS_YAML:
        return {}, body

    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return {}, body

    if not isinstance(parsed, dict):
        return {}, body

    return parsed, body


def extract_frontmatter_features(fm: dict[str, Any]) -> FrontmatterFeatures:
    """Extract security-relevant features from parsed frontmatter."""
    raw_keys = tuple(sorted(str(k) for k in fm.keys()))

    bins_raw = fm.get("requires_bins") or fm.get("requires", {})
    if isinstance(bins_raw, dict):
        bins_raw = bins_raw.get("bins", [])
    if isinstance(bins_raw, list):
        requires_bins = tuple(str(b) for b in bins_raw)
    elif isinstance(bins_raw, str):
        requires_bins = (bins_raw,)
    else:
        requires_bins = ()

    env_raw = fm.get("requires_env") or []
    if isinstance(env_raw, dict):
        env_raw = list(env_raw.keys())
    if isinstance(env_raw, list):
        requires_env = tuple(str(e) for e in env_raw)
    elif isinstance(env_raw, str):
        requires_env = (env_raw,)
    else:
        requires_env = ()

    net = fm.get("requires_network")
    if isinstance(net, bool):
        requires_network = net
    elif isinstance(net, str):
        requires_network = net.lower() in ("true", "yes", "1")
    else:
        requires_network = False

    return FrontmatterFeatures(
        requires_bins=requires_bins,
        requires_env=requires_env,
        requires_network=requires_network,
        raw_keys=raw_keys,
    )


# ---------------------------------------------------------------------------
# Code block analysis
# ---------------------------------------------------------------------------


def analyze_code_block(language: str, code: str, start_line: int, end_line: int) -> CodeBlockFeatures:
    """Analyze a single code block for security-relevant features."""
    urls = sorted(set(URL_RE.findall(code)))
    domains = sorted({extract_domain(u) for u in urls} - {""})
    exfil_doms = sorted({d for d in domains if is_exfil_domain(d)})
    ip_addresses = sorted(set(IP_RE.findall(code)))
    env_vars = sorted(set(ENV_VAR_RE.findall(code)))
    file_paths = sorted(set(FILE_PATH_RE.findall(code)))
    pipe_to_shell = bool(PIPE_TO_SHELL_RE.search(code))

    dangerous: set[str] = set()
    for pat, label in DANGEROUS_COMMAND_PATTERNS:
        if pat.search(code):
            dangerous.add(label)

    commands: tuple[str, ...] = ()
    if language in SHELL_LANGUAGES:
        cmd_re = re.compile(r"^\s*(?:\$\s+)?(\w[\w.-]*)")
        cmds: set[str] = set()
        for line in code.splitlines():
            m = cmd_re.match(line.strip())
            if m:
                cmds.add(m.group(1))
        commands = tuple(sorted(cmds))

    cred_paths: set[str] = set()
    for cred_re in CREDENTIAL_PATH_PATTERNS:
        cred_paths.update(cred_re.findall(code))

    password_archives = bool(PASSWORD_ARCHIVE_RE.search(code))

    blobs: list[Base64BlobInfo] = []
    for b64_match in BASE64_RE.finditer(code):
        blob_info = classify_base64_blob(b64_match.group())
        if blob_info is not None:
            blobs.append(blob_info)

    entropy_score = round(shannon_entropy(code), 2)

    obfuscation: set[str] = set()
    for pattern, signal_name in OBFUSCATION_SIGNALS:
        if pattern.search(code):
            obfuscation.add(signal_name)

    return CodeBlockFeatures(
        language=language,
        line_range=(start_line, end_line),
        commands_found=commands,
        urls_found=tuple(urls),
        unique_domains=tuple(domains),
        ip_addresses_found=tuple(ip_addresses),
        env_var_references=tuple(env_vars),
        file_path_references=tuple(file_paths),
        pipe_to_shell=pipe_to_shell,
        base64_blobs=tuple(blobs),
        password_protected_archives=password_archives,
        dangerous_commands=tuple(sorted(dangerous)),
        credential_paths=tuple(sorted(cred_paths)),
        exfil_domains=tuple(exfil_doms),
        entropy_score=entropy_score,
        obfuscation_signals=tuple(sorted(obfuscation)),
    )
