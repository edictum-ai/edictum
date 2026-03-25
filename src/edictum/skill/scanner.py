"""Core extraction logic for skill security scanning.

Deterministic feature extractor: parses SKILL.md files and extracts
security-relevant features (code blocks, base64 blobs, credential paths,
exfil domains, obfuscation signals) without any LLM involvement.

Ported from clawhub-scanner/extract_features.py with adaptations for
the Edictum CLI: frozen dataclasses, no HMAC, no batch output.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from edictum.skill.patterns import (
    BASE64_RE,
    CODE_BLOCK_RE,
    CREDENTIAL_PATH_PATTERNS,
    DANGEROUS_COMMAND_PATTERNS,
    ENV_VAR_RE,
    FILE_PATH_RE,
    FRONTMATTER_RE,
    HIGH_ENTROPY_THRESHOLD,
    IP_RE,
    MAX_CODE_BLOCKS,
    MAX_FILE_SIZE,
    OBFUSCATION_SIGNALS,
    PASSWORD_ARCHIVE_RE,
    PIPE_TO_SHELL_RE,
    SCRIPT_EXTENSIONS,
    SHELL_LANGUAGES,
    SKILL_TIMEOUT_SECONDS,
    URL_RE,
    is_exfil_domain,
)

# ---------------------------------------------------------------------------
# YAML import (available via edictum[cli] → edictum[yaml])
# ---------------------------------------------------------------------------

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

# ---------------------------------------------------------------------------
# Data classes — frozen for immutable scan output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Base64BlobInfo:
    """Classification of a decoded base64 blob (no raw content exposed)."""

    length: int
    classification: str  # shell_command, url, text, binary
    entropy: float
    dangerous_pattern: str | None = None


@dataclass(frozen=True)
class CodeBlockFeatures:
    """Security-relevant features from a single code block."""

    language: str
    line_range: tuple[int, int]
    commands_found: tuple[str, ...] = ()
    urls_found: tuple[str, ...] = ()
    unique_domains: tuple[str, ...] = ()
    ip_addresses_found: tuple[str, ...] = ()
    env_var_references: tuple[str, ...] = ()
    file_path_references: tuple[str, ...] = ()
    pipe_to_shell: bool = False
    base64_blobs: tuple[Base64BlobInfo, ...] = ()
    password_protected_archives: bool = False
    dangerous_commands: tuple[str, ...] = ()
    credential_paths: tuple[str, ...] = ()
    exfil_domains: tuple[str, ...] = ()
    entropy_score: float = 0.0
    obfuscation_signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class FrontmatterFeatures:
    """Features from YAML frontmatter."""

    requires_bins: tuple[str, ...] = ()
    requires_env: tuple[str, ...] = ()
    requires_network: bool = False
    raw_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class StructuralFeatures:
    """Structural features of the skill directory."""

    has_contracts_yaml: bool = False
    contracts_valid: bool | None = None  # None = no contracts.yaml, True/False = validation result
    contracts_error: str | None = None
    file_count: int = 0
    has_scripts: bool = False
    script_languages: tuple[str, ...] = ()
    total_size_bytes: int = 0


@dataclass(frozen=True)
class RiskSignals:
    """Aggregated risk signals across all code blocks."""

    no_contracts: bool = True
    high_entropy_blocks: int = 0
    external_domain_count: int = 0
    pipe_to_shell_count: int = 0
    credential_access_count: int = 0
    exfil_domain_count: int = 0


@dataclass(frozen=True)
class SkillScanResult:
    """Complete scan result for a single skill."""

    skill_name: str
    author: str
    content_hash: str
    description: str
    code_blocks: tuple[CodeBlockFeatures, ...]
    frontmatter: FrontmatterFeatures
    structural: StructuralFeatures
    risk_signals: RiskSignals
    skill_dir: Path  # kept for reference, not serialized by default


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


def _extract_domain(url: str) -> str:
    """Extract the domain (host) from a URL string."""
    import urllib.parse

    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(":")[0].lower()
    except Exception:
        return ""


def _get_line_number(content: str, char_offset: int) -> int:
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

    # Try to decode as text
    try:
        decoded_text = decoded_bytes.decode("utf-8", errors="strict")
        is_text = True
    except UnicodeDecodeError:
        is_text = False
        decoded_text = ""

    entropy = shannon_entropy(raw)

    if not is_text:
        return Base64BlobInfo(
            length=length,
            classification="binary",
            entropy=round(entropy, 2),
        )

    # Classify text content without passing raw text through
    danger: str | None = None
    classification = "text"

    # Check for dangerous patterns in decoded text
    for pattern_str, label in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern_str, decoded_text):
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
        length=length,
        classification=classification,
        entropy=round(entropy, 2),
        dangerous_pattern=danger,
    )


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------


def _parse_frontmatter(content: str) -> tuple[dict[str, Any], str]:
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
        # Without PyYAML, return raw keys as signal
        return {}, body

    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return {}, body

    if not isinstance(parsed, dict):
        return {}, body

    return parsed, body


def _extract_frontmatter_features(fm: dict[str, Any]) -> FrontmatterFeatures:
    """Extract security-relevant features from parsed frontmatter."""
    raw_keys = tuple(sorted(str(k) for k in fm.keys()))

    # requires_bins
    bins_raw = fm.get("requires_bins") or fm.get("requires", {})
    if isinstance(bins_raw, dict):
        bins_raw = bins_raw.get("bins", [])
    if isinstance(bins_raw, list):
        requires_bins = tuple(str(b) for b in bins_raw)
    elif isinstance(bins_raw, str):
        requires_bins = (bins_raw,)
    else:
        requires_bins = ()

    # requires_env
    env_raw = fm.get("requires_env") or []
    if isinstance(env_raw, dict):
        env_raw = list(env_raw.keys())
    if isinstance(env_raw, list):
        requires_env = tuple(str(e) for e in env_raw)
    elif isinstance(env_raw, str):
        requires_env = (env_raw,)
    else:
        requires_env = ()

    # requires_network
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
    # URLs and domains
    urls = sorted(set(URL_RE.findall(code)))
    domains = sorted({_extract_domain(u) for u in urls} - {""})
    exfil_doms = sorted({d for d in domains if is_exfil_domain(d)})

    # IP addresses
    ip_addresses = sorted(set(IP_RE.findall(code)))

    # Environment variables
    env_vars = sorted(set(ENV_VAR_RE.findall(code)))

    # File paths
    file_paths = sorted(set(FILE_PATH_RE.findall(code)))

    # Pipe to shell
    pipe_to_shell = bool(PIPE_TO_SHELL_RE.search(code))

    # Dangerous commands
    dangerous: set[str] = set()
    for pattern_str, label in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern_str, code):
            dangerous.add(label)

    # Commands found (first word of shell-like lines)
    commands: tuple[str, ...] = ()
    if language in SHELL_LANGUAGES:
        cmd_re = re.compile(r"^\s*(?:\$\s+)?(\w[\w.-]*)")
        cmds: set[str] = set()
        for line in code.splitlines():
            m = cmd_re.match(line.strip())
            if m:
                cmds.add(m.group(1))
        commands = tuple(sorted(cmds))

    # Credential paths
    cred_paths: set[str] = set()
    for cred_re in CREDENTIAL_PATH_PATTERNS:
        cred_paths.update(cred_re.findall(code))

    # Password-protected archives
    password_archives = bool(PASSWORD_ARCHIVE_RE.search(code))

    # Base64 blobs — classify without leaking content
    blobs: list[Base64BlobInfo] = []
    for b64_match in BASE64_RE.finditer(code):
        blob_info = classify_base64_blob(b64_match.group())
        if blob_info is not None:
            blobs.append(blob_info)

    # Entropy
    entropy_score = round(shannon_entropy(code), 2)

    # Obfuscation signals
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


# ---------------------------------------------------------------------------
# Structural analysis
# ---------------------------------------------------------------------------


def _analyze_structural(skill_dir: Path) -> StructuralFeatures:
    """Analyze the directory structure of a skill."""
    if not skill_dir.is_dir():
        return StructuralFeatures()

    # Check for contracts.yaml
    contracts_path = skill_dir / "contracts.yaml"
    if not contracts_path.exists():
        contracts_path = skill_dir / "contracts.yml"
    has_contracts = contracts_path.exists()

    # Validate contracts.yaml if present
    contracts_valid: bool | None = None
    contracts_error: str | None = None
    if has_contracts:
        try:
            from edictum.yaml_engine.loader import load_bundle

            load_bundle(str(contracts_path))
            contracts_valid = True
        except Exception as e:
            contracts_valid = False
            contracts_error = str(e)

    # Scan directory structure
    script_extensions: set[str] = set()
    total_size = 0
    file_count = 0

    try:
        for item in skill_dir.rglob("*"):
            if item.is_file():
                file_count += 1
                try:
                    total_size += item.stat().st_size
                except OSError:
                    pass
                ext = item.suffix.lower()
                if ext in SCRIPT_EXTENSIONS:
                    script_extensions.add(ext)
    except OSError:
        pass

    return StructuralFeatures(
        has_contracts_yaml=has_contracts,
        contracts_valid=contracts_valid,
        contracts_error=contracts_error,
        file_count=file_count,
        has_scripts=bool(script_extensions),
        script_languages=tuple(sorted(script_extensions)),
        total_size_bytes=total_size,
    )


# ---------------------------------------------------------------------------
# Risk signal aggregation
# ---------------------------------------------------------------------------


def _compute_risk_signals(
    code_blocks: list[CodeBlockFeatures],
    structural: StructuralFeatures,
) -> RiskSignals:
    """Aggregate risk signals from code blocks and structural analysis."""
    all_domains: set[str] = set()
    high_entropy = 0
    pipe_count = 0
    cred_count = 0
    exfil_count = 0

    for cb in code_blocks:
        if cb.entropy_score >= HIGH_ENTROPY_THRESHOLD:
            high_entropy += 1
        all_domains.update(cb.unique_domains)
        if cb.pipe_to_shell:
            pipe_count += 1
        cred_count += len(cb.credential_paths)
        exfil_count += len(cb.exfil_domains)

    return RiskSignals(
        no_contracts=not structural.has_contracts_yaml,
        high_entropy_blocks=high_entropy,
        external_domain_count=len(all_domains),
        pipe_to_shell_count=pipe_count,
        credential_access_count=cred_count,
        exfil_domain_count=exfil_count,
    )


# ---------------------------------------------------------------------------
# Core extraction — single skill
# ---------------------------------------------------------------------------


def scan_skill(skill_path: Path) -> SkillScanResult | None:
    """Extract all security features from a single skill.

    Accepts either a directory containing SKILL.md or a direct path to SKILL.md.
    Returns a SkillScanResult, or None if the file should be skipped.
    """
    # Resolve path to SKILL.md
    if skill_path.is_dir():
        skill_md = skill_path / "SKILL.md"
        skill_dir = skill_path
    elif skill_path.is_file() and skill_path.name == "SKILL.md":
        skill_md = skill_path
        skill_dir = skill_path.parent
    else:
        return None

    if not skill_md.exists():
        return None

    # Size check
    try:
        file_size = skill_md.stat().st_size
    except OSError:
        return None

    if file_size > MAX_FILE_SIZE:
        return None

    # Read with encoding fallback
    try:
        raw_bytes = skill_md.read_bytes()
    except OSError:
        return None

    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw_bytes.decode("latin-1")
        except UnicodeDecodeError:
            return None

    content_hash = hashlib.sha256(raw_bytes).hexdigest()

    # Determine author and skill name from path
    skill_name = skill_dir.name
    author = ""
    if len(skill_dir.parts) >= 2:
        grandparent = skill_dir.parent
        if grandparent.name not in ("skills", "hub", "openclaw", "."):
            author = grandparent.name

    # Parse frontmatter
    frontmatter_dict, body = _parse_frontmatter(content)
    fm_features = _extract_frontmatter_features(frontmatter_dict)

    # Override name/author from frontmatter if present
    if "name" in frontmatter_dict:
        skill_name = str(frontmatter_dict["name"])
    if "author" in frontmatter_dict:
        author = str(frontmatter_dict["author"])

    # Description: first 200 chars of body (stripped of first markdown header)
    desc_text = re.sub(r"^#+\s+.*$", "", body, count=1, flags=re.MULTILINE).strip()
    description = desc_text[:200]

    # Extract code blocks
    code_blocks: list[CodeBlockFeatures] = []
    block_count = 0
    for match in CODE_BLOCK_RE.finditer(content):
        block_count += 1
        if block_count > MAX_CODE_BLOCKS:
            break

        language = match.group(1) or ""
        code = match.group(2)
        start_line = _get_line_number(content, match.start())
        end_line = _get_line_number(content, match.end())
        cb_features = analyze_code_block(language, code, start_line, end_line)
        code_blocks.append(cb_features)

    # Structural analysis
    structural = _analyze_structural(skill_dir)

    # Risk signals
    risk = _compute_risk_signals(code_blocks, structural)

    return SkillScanResult(
        skill_name=skill_name,
        author=author,
        content_hash=content_hash,
        description=description,
        code_blocks=tuple(code_blocks),
        frontmatter=fm_features,
        structural=structural,
        risk_signals=risk,
        skill_dir=skill_dir,
    )


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_skills(root: Path) -> list[Path]:
    """Find all SKILL.md files under root directory.

    Returns paths to skill directories (parents of SKILL.md files).
    """
    results: list[Path] = []
    try:
        for skill_md in sorted(root.rglob("SKILL.md")):
            if skill_md.is_file():
                results.append(skill_md.parent)
    except OSError:
        pass
    return results


# ---------------------------------------------------------------------------
# Batch scanning with timeout
# ---------------------------------------------------------------------------


def _scan_skill_with_timeout(skill_dir: Path) -> SkillScanResult | None:
    """Scan a single skill with SIGALRM timeout protection (Unix only)."""
    alarm_supported = hasattr(signal, "SIGALRM")
    old_handler = None

    if alarm_supported:

        def _timeout_handler(signum: int, frame: Any) -> None:
            raise TimeoutError(f"Processing {skill_dir} exceeded {SKILL_TIMEOUT_SECONDS}s")

        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(SKILL_TIMEOUT_SECONDS)

    try:
        return scan_skill(skill_dir)
    except TimeoutError:
        return None
    except Exception:
        return None
    finally:
        if alarm_supported:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)


def scan_directory(
    root: Path,
    *,
    workers: int = 1,
    use_timeout: bool = True,
) -> list[SkillScanResult]:
    """Scan all skills under a directory.

    Args:
        root: Root directory to scan (may contain nested skill directories).
        workers: Number of parallel workers (1 = single-process).
        use_timeout: Whether to use SIGALRM timeout per skill.

    Returns:
        List of scan results for all successfully scanned skills.
    """
    # Check if root itself is a single skill
    if (root / "SKILL.md").exists() and not any(p.name == "SKILL.md" for p in root.rglob("*/SKILL.md")):
        result = _scan_skill_with_timeout(root) if use_timeout else scan_skill(root)
        return [result] if result is not None else []

    skill_dirs = discover_skills(root)
    if not skill_dirs:
        return []

    scan_fn = _scan_skill_with_timeout if use_timeout else scan_skill

    if workers <= 1:
        results: list[SkillScanResult] = []
        for skill_dir in skill_dirs:
            result = scan_fn(skill_dir)
            if result is not None:
                results.append(result)
        return results

    # Multi-worker mode
    from concurrent.futures import ProcessPoolExecutor, as_completed

    results = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_fn, d): d for d in skill_dirs}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                continue
            if result is not None:
                results.append(result)

    return results


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def result_to_dict(result: SkillScanResult) -> dict[str, Any]:
    """Convert a SkillScanResult to a JSON-serializable dict."""
    return {
        "skill_name": result.skill_name,
        "author": result.author,
        "content_hash": result.content_hash,
        "description": result.description,
        "code_blocks": [_code_block_to_dict(cb) for cb in result.code_blocks],
        "frontmatter": {
            "requires_bins": list(result.frontmatter.requires_bins),
            "requires_env": list(result.frontmatter.requires_env),
            "requires_network": result.frontmatter.requires_network,
            "raw_keys": list(result.frontmatter.raw_keys),
        },
        "structural": {
            "has_contracts_yaml": result.structural.has_contracts_yaml,
            "contracts_valid": result.structural.contracts_valid,
            "file_count": result.structural.file_count,
            "has_scripts": result.structural.has_scripts,
            "script_languages": list(result.structural.script_languages),
            "total_size_bytes": result.structural.total_size_bytes,
        },
        "risk_signals": {
            "no_contracts": result.risk_signals.no_contracts,
            "high_entropy_blocks": result.risk_signals.high_entropy_blocks,
            "external_domain_count": result.risk_signals.external_domain_count,
            "pipe_to_shell_count": result.risk_signals.pipe_to_shell_count,
            "credential_access_count": result.risk_signals.credential_access_count,
            "exfil_domain_count": result.risk_signals.exfil_domain_count,
        },
    }


def _code_block_to_dict(cb: CodeBlockFeatures) -> dict[str, Any]:
    """Convert a CodeBlockFeatures to a JSON-serializable dict."""
    return {
        "language": cb.language,
        "line_range": list(cb.line_range),
        "commands_found": list(cb.commands_found),
        "urls_found": list(cb.urls_found),
        "unique_domains": list(cb.unique_domains),
        "ip_addresses_found": list(cb.ip_addresses_found),
        "env_var_references": list(cb.env_var_references),
        "file_path_references": list(cb.file_path_references),
        "pipe_to_shell": cb.pipe_to_shell,
        "base64_blobs": [
            {
                "length": b.length,
                "classification": b.classification,
                "entropy": b.entropy,
                "dangerous_pattern": b.dangerous_pattern,
            }
            for b in cb.base64_blobs
        ],
        "password_protected_archives": cb.password_protected_archives,
        "dangerous_commands": list(cb.dangerous_commands),
        "credential_paths": list(cb.credential_paths),
        "exfil_domains": list(cb.exfil_domains),
        "entropy_score": cb.entropy_score,
        "obfuscation_signals": list(cb.obfuscation_signals),
    }
