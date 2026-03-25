"""Compiled regex patterns and constants for skill security scanning.

All patterns are compiled at module load time for O(1) match performance.
Patterns are tested against untrusted input — no unbounded quantifiers.
"""

from __future__ import annotations

import ipaddress
import re

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_FILE_SIZE: int = 1_048_576  # 1 MB
MAX_CODE_BLOCKS: int = 50
SKILL_TIMEOUT_SECONDS: int = 5

# High entropy threshold (Shannon entropy per character, log2).
# English prose ~4.0, random base64 ~5.9, compressed/encrypted ~7.5+
HIGH_ENTROPY_THRESHOLD: float = 5.5

# ---------------------------------------------------------------------------
# Dangerous command patterns
# ---------------------------------------------------------------------------

# Each tuple: (compiled_pattern, label).
# Non-greedy .*? used to mitigate ReDoS on long lines from untrusted input.
DANGEROUS_COMMAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bcurl\b.*?\|\s*(?:ba)?sh\b"), "curl_pipe_shell"),
    (re.compile(r"\bwget\b.*?\|\s*(?:ba)?sh\b"), "wget_pipe_shell"),
    (re.compile(r"\bnc\s+-[^|]*-e\b"), "netcat_reverse_shell"),
    (re.compile(r"\bncat\b.*?-e\b"), "ncat_reverse_shell"),
    (re.compile(r"\bpython[23]?\s+-c\s+['\"].*?socket"), "python_reverse_shell"),
    (re.compile(r"/dev/tcp/"), "dev_tcp_reverse_shell"),
    (re.compile(r"\brm\s+-rf\s+/(?:\s|$)"), "destructive_rm_root"),
    (re.compile(r"\bchmod\s+(?:777|[+]s)\b"), "chmod_dangerous"),
    (re.compile(r"\bdd\s+.*?of=/dev/"), "dd_device_write"),
    (re.compile(r"\bmkfs\b"), "mkfs_format"),
    (re.compile(r"\b(?:eval|exec)\s*\("), "eval_exec"),
    (re.compile(r"(?:subprocess|os\.system|os\.popen)\s*\("), "python_shell_exec"),
    (re.compile(r"\bBase64\.decode"), "base64_decode_runtime"),
    (re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}"), "hex_shellcode"),
    (re.compile(r"String\.fromCharCode\s*\("), "js_char_construction"),
    (re.compile(r"\bsudo\s+"), "sudo_usage"),
    (re.compile(r"\bpasswd\b"), "passwd_access"),
    (re.compile(r"\b/etc/shadow\b"), "shadow_access"),
    (re.compile(r"~/.ssh/"), "ssh_key_access"),
    (re.compile(r"\bDNS_EXFIL\b|\bexfiltrat"), "exfiltration_keyword"),
]

# Reverse-shell specific labels (subset of dangerous commands).
REVERSE_SHELL_LABELS: frozenset[str] = frozenset(
    {
        "netcat_reverse_shell",
        "ncat_reverse_shell",
        "python_reverse_shell",
        "dev_tcp_reverse_shell",
    }
)

# ---------------------------------------------------------------------------
# Pipe-to-shell
# ---------------------------------------------------------------------------

PIPE_TO_SHELL_RE: re.Pattern[str] = re.compile(r"\|\s*(?:ba)?sh\b|\|\s*(?:python[23]?|ruby|perl|node)\b")

# ---------------------------------------------------------------------------
# Credential paths
# ---------------------------------------------------------------------------

CREDENTIAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p)
    for p in [
        r"~?/\.aws/credentials",
        r"~?/\.ssh/(?:id_rsa|id_ed25519|authorized_keys)",
        r"~?/\.gnupg/",
        r"~?/\.npmrc",
        r"~?/\.pypirc",
        r"~?/\.docker/config\.json",
        r"~?/\.kube/config",
        r"~?/\.git-credentials",
        r"~?/\.netrc",
        r"/etc/shadow",
        r"/etc/passwd",
        r"~?/\.env(?:\.|$)",
    ]
]

# ---------------------------------------------------------------------------
# Exfiltration domains
# ---------------------------------------------------------------------------

EXFIL_DOMAIN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"(?:^|\.)ngrok\.io$",
        r"(?:^|\.)burpcollaborator\.net$",
        r"(?:^|\.)requestbin\.(?:com|net)$",
        r"(?:^|\.)pipedream\.net$",
        r"(?:^|\.)webhook\.site$",
        r"(?:^|\.)oastify\.com$",
        r"(?:^|\.)interact\.sh$",
        r"(?:^|\.)canarytokens\.com$",
        r"(?:^|\.)dnslog\.cn$",
        r"(?:^|\.)ceye\.io$",
    ]
]

# ---------------------------------------------------------------------------
# Extraction patterns
# ---------------------------------------------------------------------------

URL_RE: re.Pattern[str] = re.compile(r"https?://[^\s\"'`)<>\]]+")
IP_RE: re.Pattern[str] = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
ENV_VAR_RE: re.Pattern[str] = re.compile(r"\$\{?([A-Z_][A-Z0-9_]*)\}?")
FILE_PATH_RE: re.Pattern[str] = re.compile(r"(?:/[\w.~-]+){2,}")
BASE64_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
FRONTMATTER_RE: re.Pattern[str] = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
CODE_BLOCK_RE: re.Pattern[str] = re.compile(r"^```(\w*)\s*\n(.*?)^```", re.MULTILINE | re.DOTALL)

# ---------------------------------------------------------------------------
# Obfuscation signal patterns
# ---------------------------------------------------------------------------

HEX_PAYLOAD_RE: re.Pattern[str] = re.compile(r"(?:0x[0-9a-fA-F]{2}[,\s]*){8,}")
CHAR_CODE_RE: re.Pattern[str] = re.compile(r"(?:String\.fromCharCode|chr|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})")
PASSWORD_ARCHIVE_RE: re.Pattern[str] = re.compile(r"-(?:P|password|passwd)\s+\S+|--password\s*=?\s*\S+", re.IGNORECASE)

OBFUSCATION_SIGNALS: list[tuple[re.Pattern[str], str]] = [
    (HEX_PAYLOAD_RE, "hex_encoded"),
    (CHAR_CODE_RE, "char_code_construction"),
    (re.compile(r"\\[0-7]{3}(?:\\[0-7]{3}){3,}"), "octal_encoded"),
    (re.compile(r"(?:atob|btoa)\s*\("), "js_base64_runtime"),
    (
        re.compile(r"(?:exec|eval)\s*\(\s*(?:compile|__import__)"),
        "python_dynamic_exec",
    ),
    (re.compile(r"\$\(\s*echo\s.*?\|\s*base64\s+-d"), "bash_base64_decode"),
    (re.compile(r"rev\s*<<<|rev\s*\|"), "string_reversal"),
]

# ---------------------------------------------------------------------------
# Script file extensions
# ---------------------------------------------------------------------------

SCRIPT_EXTENSIONS: frozenset[str] = frozenset({".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl"})

SHELL_LANGUAGES: frozenset[str] = frozenset({"sh", "bash", "zsh", "shell", "console", ""})

# ---------------------------------------------------------------------------
# RFC1918 / private IP detection
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is RFC1918 / loopback / link-local."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)


def is_exfil_domain(domain: str) -> bool:
    """Check if a domain matches known exfiltration service patterns."""
    return any(pat.search(domain) for pat in EXFIL_DOMAIN_PATTERNS)
