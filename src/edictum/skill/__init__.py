"""Edictum Skill Scanner — deterministic security analysis for AI agent skills.

Public API: scan_skill, scan_directory, discover_skills, result_to_dict.
"""

from __future__ import annotations

import signal
from pathlib import Path
from typing import Any

from edictum.skill._types import (
    Base64BlobInfo,
    CodeBlockFeatures,
    FrontmatterFeatures,
    RiskSignals,
    SkillScanResult,
    StructuralFeatures,
)
from edictum.skill.patterns import SKILL_TIMEOUT_SECONDS
from edictum.skill.scanner import scan_skill

__all__ = [
    "Base64BlobInfo",
    "CodeBlockFeatures",
    "FrontmatterFeatures",
    "RiskSignals",
    "SkillScanResult",
    "StructuralFeatures",
    "discover_skills",
    "result_to_dict",
    "scan_directory",
    "scan_skill",
]


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
            if skill_md.is_symlink():
                continue  # reject symlinked SKILL.md — prevents arbitrary file read
            if skill_md.is_file():
                results.append(skill_md.parent)
    except OSError:
        pass
    return results


# ---------------------------------------------------------------------------
# Batch scanning
# ---------------------------------------------------------------------------


def _scan_skill_with_timeout(skill_dir: Path) -> SkillScanResult | None:
    """Scan a single skill with SIGALRM timeout protection (Unix only).

    Only used in single-process mode. SIGALRM is not safe across
    ProcessPoolExecutor spawn boundaries.
    """
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
        use_timeout: Whether to use SIGALRM timeout per skill (single-process only).

    Returns:
        List of scan results for all successfully scanned skills.
    """
    skill_dirs = discover_skills(root)
    if not skill_dirs:
        return []

    if workers <= 1:
        scan_fn = _scan_skill_with_timeout if use_timeout else scan_skill
        results: list[SkillScanResult] = []
        for skill_dir in skill_dirs:
            result = scan_fn(skill_dir)
            if result is not None:
                results.append(result)
        return results

    # Multi-worker: no SIGALRM — subprocess isolation provides containment
    from concurrent.futures import ProcessPoolExecutor, as_completed

    results = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_skill, d): d for d in skill_dirs}
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
