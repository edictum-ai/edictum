#!/usr/bin/env python3
"""Pre-commit hook: enforce .docs-style-guide.md terminology.

Scans staged files for banned terms and reports violations.
Exit 0 = clean, exit 1 = violations found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Banned patterns: (regex, replacement hint, description)
BANNED_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bshadow mode\b", re.IGNORECASE), "observe mode", "banned phrase"),
    (re.compile(r"\bper-contract\b", re.IGNORECASE), "per-rule", "banned phrase"),
    (re.compile(r"\bContractResult\b"), "RuleResult", "old class name"),
    (re.compile(r"\bcontract_id\b"), "rule_id", "old field name"),
    (re.compile(r"\bcontract_type\b"), "rule_type", "old field name"),
    (re.compile(r'"\brules_evaluated\b"'), '"contracts_evaluated"', "old field name"),
    (re.compile(r"\bby contract\b", re.IGNORECASE), "by rule", "banned phrase"),
    (re.compile(r"\bContracts evaluated\b"), "Rules evaluated", "banned CLI string"),
    (re.compile(r"\ball contracts passed\b", re.IGNORECASE), "all rules passed", "banned CLI string"),
]

# "denied" is a banned prose term; allow existing code identifiers that
# happen to contain the word while flagging user-facing wording.
DENIED_PATTERN = re.compile(r"\bdenied\b", re.IGNORECASE)
DENIED_ALLOWLIST = {
    "ApprovalStatus.DENIED",
    "CALL_DENIED",
    "CALL_APPROVAL_DENIED",
    "AutoDenyBackend",
    "_on_deny",
    "_deny(",
    "denied =",
    " denied,",
    'startswith("DENIED:")',
    'return f"DENIED: {reason}"',
    'governance.action", "denied"',
    'or "denied"',
}

# "shadow" needs special handling — prose should say "observe mode" / "observe-mode".
# All shadow_* code identifiers were renamed to observe_* in v0.15.0.
# Only real filesystem references remain in the allowlist.
SHADOW_PATTERN = re.compile(r"\bshadow\b", re.IGNORECASE)
SHADOW_ALLOWLIST = {
    # Real file path in sandbox tests (with and without leading slash)
    "/etc/shadow",
    '"etc" / "shadow"',
}

# Files/dirs to skip
SKIP_PATHS = {
    ".docs-style-guide.md",
    "scripts/check-terminology.py",
    "CLAUDE.md",  # references banned terms when defining the enforcement rules
}
SKIP_DIRS = {
    "docs/planning",
    ".git",
    "__pycache__",
    "site",
    ".ruff_cache",
}

# Only check these extensions
CHECK_EXTENSIONS = {".py", ".md", ".yaml", ".yml", ".json"}


def should_skip(path: Path) -> bool:
    path_str = str(path)
    if path_str in SKIP_PATHS:
        return True
    for skip_dir in SKIP_DIRS:
        if path_str.startswith(skip_dir):
            return True
    if path.suffix not in CHECK_EXTENSIONS:
        return True
    return False


def check_file(path: Path) -> list[str]:
    violations: list[str] = []
    try:
        lines = path.read_text().splitlines()
    except (OSError, UnicodeDecodeError):
        return []

    is_changelog = path.name == "CHANGELOG.md"

    for i, line in enumerate(lines, 1):
        # Skip CHANGELOG lines that document renames (backtick-quoted old names)
        if is_changelog and "`" in line and "→" in line:
            continue

        # Check banned patterns
        for pattern, fix, desc in BANNED_PATTERNS:
            if pattern.search(line):
                violations.append(f"  {path}:{i}: {desc} — use '{fix}' instead")
                violations.append(f"    {line.strip()}")

        if DENIED_PATTERN.search(line):
            line_stripped = line.strip()
            if not any(allowed in line_stripped for allowed in DENIED_ALLOWLIST):
                violations.append(f"  {path}:{i}: 'denied' — use 'blocked' instead")
                violations.append(f"    {line_stripped}")

        # Check "shadow" with allowlist
        if SHADOW_PATTERN.search(line):
            line_stripped = line.strip()
            if not any(allowed in line_stripped for allowed in SHADOW_ALLOWLIST):
                violations.append(f"  {path}:{i}: 'shadow' — use 'observe mode' / 'observe-mode' instead")
                violations.append(f"    {line_stripped}")

    return violations


def main() -> int:
    # If args are passed, check those files (pre-commit passes staged files)
    # Otherwise, scan src/, tests/, docs/, CHANGELOG.md
    if len(sys.argv) > 1:
        files = [Path(f) for f in sys.argv[1:]]
    else:
        files = []
        for directory in ["src", "tests", "docs"]:
            d = Path(directory)
            if d.exists():
                files.extend(d.rglob("*"))
        changelog = Path("CHANGELOG.md")
        if changelog.exists():
            files.append(changelog)
        readme = Path("README.md")
        if readme.exists():
            files.append(readme)

    all_violations: list[str] = []
    for f in files:
        if not f.is_file() or should_skip(f):
            continue
        violations = check_file(f)
        all_violations.extend(violations)

    if all_violations:
        print("Terminology violations found (see .docs-style-guide.md):\n")
        for v in all_violations:
            print(v)
        print(f"\n{len(all_violations) // 2} violation(s) found.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
