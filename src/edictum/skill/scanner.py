"""Skill scan orchestration — ties analysis, structural checks, and risk signals.

This module provides the top-level ``scan_skill`` entry point.  Code block
analysis lives in ``_analysis.py``; data classes in ``_types.py``.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from edictum.skill._analysis import (
    analyze_code_block,
    classify_base64_blob,
    extract_frontmatter_features,
    get_line_number,
    parse_frontmatter,
    shannon_entropy,
)
from edictum.skill._types import (
    Base64BlobInfo,
    CodeBlockFeatures,
    FrontmatterFeatures,
    RiskSignals,
    SkillScanResult,
    StructuralFeatures,
)
from edictum.skill.patterns import (
    CODE_BLOCK_RE,
    HIGH_ENTROPY_THRESHOLD,
    MAX_CODE_BLOCKS,
    MAX_FILE_SIZE,
    SCRIPT_EXTENSIONS,
)

# Re-export for backward compatibility and public API
__all__ = [
    "Base64BlobInfo",
    "CodeBlockFeatures",
    "FrontmatterFeatures",
    "RiskSignals",
    "SkillScanResult",
    "StructuralFeatures",
    "analyze_code_block",
    "classify_base64_blob",
    "scan_skill",
    "shannon_entropy",
]

# O_NOFOLLOW: atomically reject symlinks at open time (0 on platforms without it).
_O_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)


def _read_no_follow(path: Path, max_size: int) -> bytes | None:
    """Read a file without following symlinks. Returns None on error.

    Uses O_NOFOLLOW to atomically reject symlinks at open time,
    eliminating the TOCTOU window between is_symlink() and read_bytes().
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | _O_NOFOLLOW)
    except OSError:
        return None
    try:
        return os.read(fd, max_size)
    finally:
        os.close(fd)


# Maximum files to enumerate in structural analysis.
# Prevents symlink-tree DoS from attacker-controlled skill directories.
_MAX_STRUCTURAL_FILES: int = 10_000


# ---------------------------------------------------------------------------
# Structural analysis
# ---------------------------------------------------------------------------


def _analyze_structural(skill_dir: Path) -> StructuralFeatures:
    """Analyze the directory structure of a skill."""
    if not skill_dir.is_dir():
        return StructuralFeatures()

    contracts_path = skill_dir / "contracts.yaml"
    if not contracts_path.exists() or contracts_path.is_symlink():
        contracts_path = skill_dir / "contracts.yml"

    # Read with O_NOFOLLOW to atomically reject symlinks (no TOCTOU)
    contracts_bytes = _read_no_follow(contracts_path, MAX_FILE_SIZE)
    has_contracts = contracts_bytes is not None

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

    script_extensions: set[str] = set()
    total_size = 0
    file_count = 0

    try:
        for item in skill_dir.rglob("*"):
            if item.is_symlink():
                continue  # skip symlinks to prevent traversal attacks
            if item.is_file():
                file_count += 1
                if file_count > _MAX_STRUCTURAL_FILES:
                    break  # cap to prevent DoS on large symlink trees
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
    if skill_path.is_dir():
        skill_md = skill_path / "SKILL.md"
        skill_dir = skill_path
    elif skill_path.is_file() and skill_path.name == "SKILL.md":
        skill_md = skill_path
        skill_dir = skill_path.parent
    else:
        return None

    # Atomic symlink-safe read using O_NOFOLLOW — no TOCTOU window.
    # Rejects symlinked SKILL.md that could point to sensitive files.
    raw_bytes = _read_no_follow(skill_md, MAX_FILE_SIZE + 1)
    if raw_bytes is None:
        return None

    if len(raw_bytes) > MAX_FILE_SIZE:
        return None

    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw_bytes.decode("latin-1")
        except UnicodeDecodeError:
            return None

    content_hash = hashlib.sha256(raw_bytes).hexdigest()

    skill_name = skill_dir.name
    author = ""
    if len(skill_dir.parts) >= 2:
        grandparent = skill_dir.parent
        if grandparent.name not in ("skills", "hub", "openclaw", "."):
            author = grandparent.name

    frontmatter_dict, body = parse_frontmatter(content)
    fm_features = extract_frontmatter_features(frontmatter_dict)

    if "name" in frontmatter_dict:
        skill_name = str(frontmatter_dict["name"])
    if "author" in frontmatter_dict:
        author = str(frontmatter_dict["author"])

    desc_text = re.sub(r"^#+\s+.*$", "", body, count=1, flags=re.MULTILINE).strip()
    description = desc_text[:200]

    code_blocks: list[CodeBlockFeatures] = []
    block_count = 0
    for match in CODE_BLOCK_RE.finditer(content):
        block_count += 1
        if block_count > MAX_CODE_BLOCKS:
            break
        language = match.group(1) or ""
        code = match.group(2)
        start_line = get_line_number(content, match.start())
        end_line = get_line_number(content, match.end())
        code_blocks.append(analyze_code_block(language, code, start_line, end_line))

    structural = _analyze_structural(skill_dir)
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
