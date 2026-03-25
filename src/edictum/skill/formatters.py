"""Output formatters for skill scan results.

Human-readable (Rich) and JSON formatters. All untrusted strings are
escaped before rendering to prevent Rich markup injection.
"""

from __future__ import annotations

import datetime
import json
from typing import Any

from edictum.skill.risk import Finding, RiskClassification, RiskLevel
from edictum.skill.scanner import result_to_dict

# ---------------------------------------------------------------------------
# Rich output helpers (lazy import — only needed for human-readable mode)
# ---------------------------------------------------------------------------

_LEVEL_STYLES: dict[RiskLevel, tuple[str, str]] = {
    RiskLevel.CRITICAL: ("\U0001f6d1", "[red bold]CRITICAL[/red bold]"),
    RiskLevel.HIGH: ("\u26a0\ufe0f ", "[yellow bold]HIGH[/yellow bold]"),
    RiskLevel.MEDIUM: ("\u2139\ufe0f ", "[dim bold]MEDIUM[/dim bold]"),
    RiskLevel.CLEAN: ("\u2705", "[green]CLEAN[/green]"),
}


def _skill_label(classification: RiskClassification) -> str:
    """Build the display label for a skill: author/name or just name."""
    r = classification.result
    if r.author:
        return f"{r.author}/{r.skill_name}"
    return r.skill_name


def _finding_lines(findings: tuple[Finding, ...]) -> list[str]:
    """Format findings as indented tree lines for Rich output."""
    lines: list[str] = []
    for i, f in enumerate(findings):
        connector = "\u2514\u2500" if i == len(findings) - 1 else "\u251c\u2500"
        line_info = f" (line {f.line})" if f.line else ""
        lines.append(f"   {connector} {f.message}{line_info}")
    return lines


# ---------------------------------------------------------------------------
# Human-readable formatter
# ---------------------------------------------------------------------------


def format_human(
    classifications: list[RiskClassification],
    *,
    skills_dir: str,
    verbose: bool = False,
) -> str:
    """Format scan results as human-readable Rich markup.

    Args:
        classifications: Risk classifications for all scanned skills.
        skills_dir: Display path of the scanned directory.
        verbose: If True, show all skills including CLEAN. Otherwise only findings.

    Returns:
        String with Rich markup for console output.
    """
    from rich.markup import escape

    total = len(classifications)
    stats = _compute_stats(classifications)

    lines: list[str] = []

    # Header
    from edictum import __version__

    lines.append(f"[bold]Edictum Skill Scanner v{__version__}[/bold]")
    lines.append(f"Scanning: {escape(skills_dir)} ({total} skills found)")
    lines.append("")

    # Sort by severity (CRITICAL first)
    sorted_cls = sorted(classifications, key=lambda c: -_RISK_ORDER_VAL[c.level])

    for cls in sorted_cls:
        if cls.level == RiskLevel.CLEAN and not verbose:
            continue

        icon, styled_level = _LEVEL_STYLES[cls.level]
        label = escape(_skill_label(cls))
        lines.append(f"{icon} {styled_level}  {label}")

        # Only show non-informational findings for non-CLEAN
        display_findings = cls.findings
        if cls.level == RiskLevel.CLEAN and verbose:
            # Show informational findings only
            display_findings = tuple(f for f in cls.findings if f.message == "no contracts.yaml")

        for finding_line in _finding_lines(display_findings):
            lines.append(escape(finding_line))

        lines.append("")

    # Summary separator
    lines.append("\u2500" * 38)
    lines.append(f"Scanned: {total} skills")
    parts = []
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.CLEAN):
        count = stats.get(level, 0)
        parts.append(f"{level.value}: {count}")
    lines.append("  " + "  |  ".join(parts))

    without_contracts = sum(1 for c in classifications if c.result.risk_signals.no_contracts)
    if without_contracts:
        pct = round(without_contracts / total * 100) if total else 0
        lines.append(f"  Without contracts.yaml: {without_contracts} ({pct}%)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


def format_json(
    classifications: list[RiskClassification],
    *,
    skills_dir: str,
) -> str:
    """Format scan results as JSON.

    Returns:
        JSON string matching the spec's output schema.
    """
    from edictum import __version__

    stats = _compute_stats(classifications)
    total = len(classifications)

    findings_list: list[dict[str, Any]] = []
    for cls in classifications:
        if cls.level == RiskLevel.CLEAN:
            continue

        entry = result_to_dict(cls.result)
        entry["risk_level"] = cls.level.value
        entry["findings"] = [{"message": f.message, "line": f.line} for f in cls.findings]
        findings_list.append(entry)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings_list.sort(key=lambda x: severity_order.get(x.get("risk_level", ""), 99))

    without_contracts = sum(1 for c in classifications if c.result.risk_signals.no_contracts)

    output: dict[str, Any] = {
        "scanner_version": __version__,
        "scan_date": datetime.datetime.now(datetime.UTC).isoformat(),
        "skills_dir": skills_dir,
        "total_scanned": total,
        "findings": findings_list,
        "stats": {
            "critical": stats.get(RiskLevel.CRITICAL, 0),
            "high": stats.get(RiskLevel.HIGH, 0),
            "medium": stats.get(RiskLevel.MEDIUM, 0),
            "clean": stats.get(RiskLevel.CLEAN, 0),
            "without_contracts": without_contracts,
        },
    }

    return json.dumps(output, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RISK_ORDER_VAL: dict[RiskLevel, int] = {
    RiskLevel.CLEAN: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def _compute_stats(classifications: list[RiskClassification]) -> dict[RiskLevel, int]:
    """Count skills by risk level."""
    stats: dict[RiskLevel, int] = {}
    for cls in classifications:
        stats[cls.level] = stats.get(cls.level, 0) + 1
    return stats
