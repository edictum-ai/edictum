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
    (re.compile(r"\bper-rule\b", re.IGNORECASE), "per-contract", "banned phrase"),
    (re.compile(r"\bRuleResult\b"), "ContractResult", "old class name"),
    (re.compile(r"\brule_id\b"), "contract_id", "old field name"),
    (re.compile(r"\brule_type\b"), "contract_type", "old field name"),
    (re.compile(r'"\brules_evaluated\b"'), '"contracts_evaluated"', "old field name"),
    (re.compile(r"\bby rule\b", re.IGNORECASE), "by contract", "banned phrase"),
    (re.compile(r"\bRules evaluated\b"), "Contracts evaluated", "banned CLI string"),
    (re.compile(r"\ball rules passed\b", re.IGNORECASE), "all contracts passed", "banned CLI string"),
]

# "blocked" needs special handling — allow the loop variable in builtins.py
BLOCKED_PATTERN = re.compile(r"\bblocked\b", re.IGNORECASE)
BLOCKED_ALLOWLIST = {
    # builtins.py loop variable: "for blocked in commands:"
    "for blocked in commands",
    "cmd == blocked",
    "cmd.startswith(blocked",
    # f-string references to the loop variable
    "{blocked}",
}

# "shadow" needs special handling — internal code uses shadow_* field names
# in _CompiledState and _edictum_observe attribute, but prose should say
# "observe mode" / "observe-mode".
SHADOW_PATTERN = re.compile(r"\bshadow\b", re.IGNORECASE)
SHADOW_ALLOWLIST = {
    # _CompiledState frozen dataclass fields
    "observe_preconditions",
    "observe_postconditions",
    "observe_session_contracts",
    "observe_sandbox_contracts",
    # Internal attribute on contract callables
    "_edictum_observe",
    # Local variable reading the attribute
    "is_observe",
    # Getter methods on Edictum
    "get_observe_preconditions",
    "get_observe_postconditions",
    "get_observe_sandbox_contracts",
    "get_observe_session_contracts",
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

        # Check "blocked" with allowlist
        if BLOCKED_PATTERN.search(line):
            line_stripped = line.strip()
            if not any(allowed in line_stripped for allowed in BLOCKED_ALLOWLIST):
                violations.append(f"  {path}:{i}: 'blocked' — use 'denied' instead")
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
