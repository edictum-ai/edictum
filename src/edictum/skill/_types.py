"""Frozen dataclasses for skill scan results."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
    contracts_valid: bool | None = None
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
    truncated: bool = False  # True if code blocks exceeded MAX_CODE_BLOCKS
    skill_dir: Path = Path(".")
