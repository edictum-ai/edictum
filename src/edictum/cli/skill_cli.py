"""CLI commands for the skill scanner."""

from __future__ import annotations

import sys
from pathlib import Path

import click

try:
    from rich.console import Console
    from rich.markup import escape

    _console = Console(highlight=False)
    _err_console = Console(stderr=True, highlight=False)
except ImportError:
    raise ImportError("The CLI requires click and rich. Install them with: pip install edictum[cli]")


@click.group()
def skill() -> None:
    """Manage and audit agent skills."""


@skill.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, default=False, help="Output results as JSON.")
@click.option(
    "--threshold",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM"]),
    default="MEDIUM",
    help="Minimum risk level for non-zero exit code (default: MEDIUM).",
)
@click.option("--structural-only", is_flag=True, default=False, help="Only check contracts.yaml presence.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show all skills, not just findings.")
@click.option("--workers", type=int, default=1, help="Parallel workers for batch scanning.")
@click.option("--server", type=str, default=None, help="Console server URL to send results.")
def scan(
    path: str,
    output_json: bool,
    threshold: str,
    structural_only: bool,
    verbose: bool,
    workers: int,
    server: str | None,
) -> None:
    """Scan skill directories for security issues.

    Scans SKILL.md files for dangerous commands, credential access,
    exfiltration domains, obfuscation patterns, and base64 payloads.

    PATH can be a single skill directory or a parent directory containing
    multiple skills.

    Exit codes:
      0  No findings above threshold.
      1  Findings found above threshold.
      2  Scan error.
    """
    from edictum.skill import scan_directory
    from edictum.skill.risk import RiskLevel, classify_risk

    if workers < 1:
        _err_console.print("[red]--workers must be >= 1[/red]")
        sys.exit(2)

    scan_path = Path(path).resolve()

    # Validate --server URL scheme
    if server:
        if not server.startswith("https://"):
            if server.startswith("http://"):
                _err_console.print(
                    "[yellow]Warning: --server uses HTTP. Scan results may be transmitted in cleartext.[/yellow]"
                )
            else:
                _err_console.print("[red]--server must be an HTTP(S) URL.[/red]")
                sys.exit(2)

    # Scan
    try:
        results = scan_directory(scan_path, workers=workers)
    except Exception as e:
        if output_json:
            import json

            click.echo(json.dumps({"error": str(e)}, indent=2))
        else:
            _err_console.print(f"[red]Scan error: {escape(str(e))}[/red]")
        sys.exit(2)

    if not results:
        if output_json:
            import json

            click.echo(json.dumps({"total_scanned": 0, "findings": [], "stats": {}}, indent=2))
        else:
            _console.print("[dim]No skills found to scan.[/dim]")
        sys.exit(0)

    # Classify
    classifications = [classify_risk(r) for r in results]

    # Structural-only mode: just report contracts.yaml presence
    if structural_only:
        _output_structural_only(classifications, output_json, str(scan_path))
        without = sum(1 for c in classifications if c.result.risk_signals.no_contracts)
        sys.exit(1 if without > 0 else 0)

    # Format output
    if output_json:
        from edictum.skill.formatters import format_json

        click.echo(format_json(classifications, skills_dir=str(scan_path)))
    else:
        from edictum.skill.formatters import format_human

        output = format_human(classifications, skills_dir=str(scan_path), verbose=verbose)
        _console.print(output)

    # Send to server if requested
    if server:
        _send_to_server(classifications, server, str(scan_path))

    # Exit code based on threshold
    threshold_level = RiskLevel(threshold)
    has_above_threshold = any(c.level >= threshold_level for c in classifications)
    sys.exit(1 if has_above_threshold else 0)


def _output_structural_only(
    classifications: list,
    output_json: bool,
    skills_dir: str,
) -> None:
    """Output structural-only report (contracts.yaml presence)."""
    from rich.markup import escape

    total = len(classifications)
    without = sum(1 for c in classifications if c.result.risk_signals.no_contracts)
    with_contracts = total - without

    if output_json:
        import json

        output = {
            "skills_dir": skills_dir,
            "total_scanned": total,
            "with_contracts": with_contracts,
            "without_contracts": without,
            "skills_without_contracts": [
                {
                    "skill_name": c.result.skill_name,
                    "author": c.result.author,
                    "dir": str(c.result.skill_dir),
                }
                for c in classifications
                if c.result.risk_signals.no_contracts
            ],
        }
        click.echo(json.dumps(output, indent=2))
    else:
        _console.print(f"[bold]Structural check:[/bold] {total} skills")
        _console.print(f"  With contracts.yaml: {with_contracts}")
        _console.print(f"  Without contracts.yaml: {without}")
        if without and without <= 20:
            _console.print("")
            for c in classifications:
                if c.result.risk_signals.no_contracts:
                    label = f"{c.result.author}/{c.result.skill_name}" if c.result.author else c.result.skill_name
                    _console.print(f"  \u2717 {escape(label)}")


def _send_to_server(classifications: list, server_url: str, skills_dir: str) -> None:
    """POST scan results to an Edictum Console server."""
    try:
        import httpx
    except ImportError:
        _err_console.print(
            "[yellow]Warning: --server requires httpx. Install with: pip install edictum[server][/yellow]"
        )
        return

    from edictum.skill.formatters import format_json

    payload = format_json(classifications, skills_dir=skills_dir)

    url = server_url.rstrip("/") + "/api/v1/skill-scan"
    try:
        resp = httpx.post(
            url,
            content=payload,
            headers={"Content-Type": "application/json"},
            timeout=30.0,
        )
        if resp.status_code < 300:
            _console.print(f"[green]Results sent to {escape(server_url)}[/green]")
        else:
            _err_console.print(f"[yellow]Warning: server returned {resp.status_code}[/yellow]")
    except httpx.HTTPError as e:
        _err_console.print(f"[yellow]Warning: failed to send results: {e}[/yellow]")
