"""Edictum CLI — validate, check, diff, and replay contract bundles."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

try:
    from rich.console import Console
    from rich.markup import escape

    _console = Console(highlight=False)
    _err_console = Console(stderr=True, highlight=False)
except ImportError:
    raise ImportError("The CLI requires click and rich. " "Install them with: pip install edictum[cli]")

from edictum import EdictumConfigError
from edictum.envelope import Principal, ToolEnvelope, create_envelope
from edictum.yaml_engine.loader import load_bundle

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_composition_report(report: Any) -> None:
    """Print composition report (overrides and shadows)."""
    if not report.overridden_contracts and not report.shadow_contracts:
        return

    _console.print("\n[bold]Composition report:[/bold]")
    for o in report.overridden_contracts:
        _console.print(
            f"  \u21c4 {escape(o.contract_id)} \u2014 overridden by "
            f"{escape(o.overridden_by)} (was in {escape(o.original_source)})"
        )
    for s in report.shadow_contracts:
        _console.print(
            f"  \u2295 {escape(s.contract_id)} \u2014 shadow from "
            f"{escape(s.observed_source)} (enforced in {escape(s.enforced_source)})"
        )


def _load_and_compile(path: str) -> tuple[dict, str, Any]:
    """Load a YAML bundle, return (bundle_data, bundle_hash, compiled).

    Raises EdictumConfigError on invalid bundles.
    """
    from edictum.yaml_engine.compiler import compile_contracts

    bundle_data, bundle_hash = load_bundle(path)
    compiled = compile_contracts(bundle_data)
    return bundle_data, str(bundle_hash), compiled


def _build_envelope(
    tool_name: str,
    tool_args: dict,
    environment: str = "production",
    principal: Principal | None = None,
) -> ToolEnvelope:
    """Build a synthetic ToolEnvelope for dry-run evaluation."""
    return create_envelope(
        tool_name=tool_name,
        tool_input=tool_args,
        environment=environment,
        principal=principal,
    )


def _evaluate_preconditions(
    compiled: Any,
    envelope: ToolEnvelope,
) -> tuple[str, str | None, str | None, list[dict]]:
    """Evaluate compiled preconditions against an envelope.

    Returns (verdict, contract_id, message, evaluated_records).
    verdict is "denied" or "allowed".
    """
    evaluated: list[dict] = []

    for fn in compiled.preconditions:
        tool_filter = getattr(fn, "_edictum_tool", "*")
        if tool_filter != "*" and tool_filter != envelope.tool_name:
            continue

        verdict = fn(envelope)
        record = {
            "id": getattr(fn, "_edictum_id", "unknown"),
            "passed": verdict.passed,
            "message": verdict.message,
        }
        if verdict.metadata:
            record["metadata"] = verdict.metadata
        evaluated.append(record)

        if not verdict.passed:
            return "denied", record["id"], verdict.message, evaluated

    return "allowed", None, None, evaluated


def _evaluate_sandbox_contracts(
    compiled: Any,
    envelope: ToolEnvelope,
) -> tuple[str, str | None, str | None, list[dict]]:
    """Evaluate compiled sandbox contracts against an envelope.

    Returns (verdict, contract_id, message, evaluated_records).
    verdict is "denied" or "allowed".
    """
    from fnmatch import fnmatch

    evaluated: list[dict] = []

    for fn in compiled.sandbox_contracts:
        tools = getattr(fn, "_edictum_tools", ["*"])
        if not any(fnmatch(envelope.tool_name, p) for p in tools):
            continue

        verdict = fn(envelope)
        record = {
            "id": getattr(fn, "_edictum_id", "unknown"),
            "passed": verdict.passed,
            "message": verdict.message,
        }
        if verdict.metadata:
            record["metadata"] = verdict.metadata
        evaluated.append(record)

        if not verdict.passed:
            return "denied", record["id"], verdict.message, evaluated

    return "allowed", None, None, evaluated


def _evaluate_all(
    compiled: Any,
    envelope: ToolEnvelope,
) -> tuple[str, str | None, str | None, list[dict]]:
    """Evaluate preconditions and sandbox contracts against an envelope.

    Runs preconditions first. If all pass, runs sandbox contracts.
    Returns (verdict, contract_id, message, evaluated_records).
    verdict is "denied" or "allowed".
    """
    verdict, contract_id, message, evaluated = _evaluate_preconditions(compiled, envelope)
    if verdict == "allowed":
        sb_verdict, sb_id, sb_msg, sb_evaluated = _evaluate_sandbox_contracts(compiled, envelope)
        evaluated.extend(sb_evaluated)
        if sb_verdict == "denied":
            verdict, contract_id, message = sb_verdict, sb_id, sb_msg
    return verdict, contract_id, message, evaluated


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Edictum — Runtime contracts for AI agents."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command()
def version() -> None:
    """Show the installed edictum version."""
    from edictum import __version__

    click.echo(f"edictum {__version__}")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def _count_contracts(bundle_data: dict) -> dict[str, int]:
    """Count contracts by type in a bundle."""
    counts: dict[str, int] = {}
    for c in bundle_data.get("contracts", []):
        ct = c.get("type", "unknown")
        counts[ct] = counts.get(ct, 0) + 1
    return counts


def _composition_report_to_dict(report: Any) -> dict:
    """Convert a composition report to a JSON-serializable dict."""
    result: dict[str, list] = {"overrides": [], "shadows": []}
    for o in report.overridden_contracts:
        result["overrides"].append(
            {
                "contract_id": o.contract_id,
                "overridden_by": o.overridden_by,
                "original_source": o.original_source,
            }
        )
    for s in report.shadow_contracts:
        result["shadows"].append(
            {
                "contract_id": s.contract_id,
                "observed_source": s.observed_source,
                "enforced_source": s.enforced_source,
            }
        )
    return result


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path())
@click.option("--json", "json_output", is_flag=True, default=False, help="Output results as JSON.")
def validate(files: tuple[str, ...], json_output: bool) -> None:
    """Validate one or more contract bundle files."""
    has_errors = False
    valid_bundles: list[tuple[dict, str]] = []
    json_files: list[dict] = []

    for file_path in files:
        path = Path(file_path)
        if not path.exists():
            if json_output:
                json_files.append({"file": str(path), "valid": False, "error": "file not found"})
            else:
                _err_console.print(f"[red]  {escape(str(path))} — file not found[/red]")
            has_errors = True
            continue

        try:
            bundle_data, _ = load_bundle(file_path)
        except (EdictumConfigError, Exception) as e:
            if json_output:
                json_files.append({"file": path.name, "valid": False, "error": str(e)})
            else:
                _err_console.print(f"[red]  {escape(path.name)} — {escape(str(e))}[/red]")
            has_errors = True
            continue

        counts = _count_contracts(bundle_data)
        total = sum(counts.values())

        if json_output:
            json_files.append(
                {
                    "file": path.name,
                    "valid": True,
                    "contracts": total,
                    "breakdown": counts,
                }
            )
        else:
            breakdown = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
            _console.print(f"[green]  {escape(path.name)}[/green] — {total} contracts ({breakdown})")

        valid_bundles.append((bundle_data, path.name))

    # Compose when 2+ valid bundles
    json_composed: dict | None = None
    if len(valid_bundles) >= 2:
        from edictum.yaml_engine.compiler import compile_contracts
        from edictum.yaml_engine.composer import compose_bundles

        composed = compose_bundles(*valid_bundles)

        try:
            compile_contracts(composed.bundle)
        except EdictumConfigError as e:
            if json_output:
                json_composed = {"error": str(e)}
                has_errors = True
            else:
                _err_console.print(f"[red]Composed bundle failed compilation: {escape(str(e))}[/red]")
                has_errors = True
                sys.exit(1)

        counts = _count_contracts(composed.bundle)
        total = sum(counts.values())

        if json_output:
            json_composed = {
                "contracts": total,
                "breakdown": counts,
                **_composition_report_to_dict(composed.report),
            }
        else:
            breakdown = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
            _console.print(f"\n[bold]Composed:[/bold] {total} contracts ({breakdown})")
            _print_composition_report(composed.report)

    if json_output:
        output: dict[str, Any] = {"files": json_files, "valid": not has_errors}
        if json_composed is not None:
            output["composed"] = json_composed
        click.echo(json.dumps(output, indent=2))

    sys.exit(1 if has_errors else 0)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--tool", required=True, help="Tool name to check.")
@click.option("--args", "tool_args", required=True, help="Tool arguments as JSON.")
@click.option("--environment", default="production", help="Environment name.")
@click.option("--principal-role", default=None, help="Principal role.")
@click.option("--principal-user", default=None, help="Principal user ID.")
@click.option("--principal-ticket", default=None, help="Principal ticket ref.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output results as JSON.")
def check(
    file: str,
    tool: str,
    tool_args: str,
    environment: str,
    principal_role: str | None,
    principal_user: str | None,
    principal_ticket: str | None,
    json_output: bool,
) -> None:
    """Dry-run a tool call against contracts."""
    # Parse JSON args
    try:
        parsed_args = json.loads(tool_args)
    except json.JSONDecodeError as e:
        if json_output:
            click.echo(json.dumps({"error": f"Invalid JSON in --args: {e}"}, indent=2))
        else:
            _err_console.print(f"[red]Invalid JSON in --args: {escape(str(e))}[/red]")
        sys.exit(2)

    # Load contracts
    try:
        _, _, compiled = _load_and_compile(file)
    except EdictumConfigError as e:
        if json_output:
            click.echo(json.dumps({"error": f"Failed to load contracts: {e}"}, indent=2))
        else:
            _err_console.print(f"[red]Failed to load contracts: {escape(str(e))}[/red]")
        sys.exit(1)

    # Build principal
    principal = None
    if principal_role or principal_user or principal_ticket:
        principal = Principal(
            user_id=principal_user,
            role=principal_role,
            ticket_ref=principal_ticket,
        )

    # Build envelope
    envelope = _build_envelope(tool, parsed_args, environment, principal)

    # Evaluate
    verdict, contract_id, message, evaluated = _evaluate_all(compiled, envelope)

    n_evaluated = len(evaluated)
    verdict_label = "deny" if verdict == "denied" else "allow"

    if json_output:
        output: dict[str, Any] = {
            "tool": tool,
            "args": parsed_args,
            "verdict": verdict_label,
            "reason": message,
            "contracts_evaluated": n_evaluated,
            "environment": environment,
        }
        if contract_id:
            output["contract_id"] = contract_id
        click.echo(json.dumps(output, indent=2))
        sys.exit(1 if verdict == "denied" else 0)

    if verdict == "denied":
        _console.print(f"[red bold]DENIED[/red bold] by contract [yellow]{escape(contract_id or '')}[/yellow]")
        _console.print(f"  Message: {escape(message or '')}")
        # Show tags if available
        deny_record = evaluated[-1] if evaluated else {}
        tags = deny_record.get("metadata", {}).get("tags", [])
        if tags:
            _console.print(f"  Tags: {', '.join(str(t) for t in tags)}")
        _console.print(f"  Contracts evaluated: {n_evaluated}")
        sys.exit(1)
    else:
        _console.print("[green bold]ALLOWED[/green bold]")
        _console.print(f"  Contracts evaluated: {n_evaluated}")
        sys.exit(0)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def _contracts_by_id(bundle: dict) -> dict[str, dict]:
    """Index contracts by their id."""
    return {c["id"]: c for c in bundle.get("contracts", [])}


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--json", "json_output", is_flag=True, default=False, help="Output results as JSON.")
def diff(files: tuple[str, ...], json_output: bool) -> None:
    """Compare contract bundles and show changes."""
    if len(files) < 2:
        if json_output:
            click.echo(json.dumps({"error": "diff requires at least 2 files."}, indent=2))
        else:
            _err_console.print("[red]diff requires at least 2 files.[/red]")
        sys.exit(2)

    # Load all bundles
    loaded: list[tuple[dict, str]] = []
    for file_path in files:
        try:
            bundle_data, _, _ = _load_and_compile(file_path)
            loaded.append((bundle_data, file_path))
        except EdictumConfigError as e:
            if json_output:
                click.echo(json.dumps({"error": f"Failed to load {file_path}: {e}"}, indent=2))
            else:
                _err_console.print(f"[red]Failed to load {escape(file_path)}: {escape(str(e))}[/red]")
            sys.exit(1)

    has_changes = False
    json_result: dict[str, Any] = {}

    # Standard diff for exactly 2 files
    if len(files) == 2:
        old_bundle = loaded[0][0]
        new_bundle = loaded[1][0]

        old_contracts = _contracts_by_id(old_bundle)
        new_contracts = _contracts_by_id(new_bundle)

        old_ids = set(old_contracts.keys())
        new_ids = set(new_contracts.keys())

        added = sorted(new_ids - old_ids)
        removed = sorted(old_ids - new_ids)
        common = sorted(old_ids & new_ids)

        changed: list[str] = []
        unchanged: list[str] = []

        for cid in common:
            if old_contracts[cid] != new_contracts[cid]:
                changed.append(cid)
            else:
                unchanged.append(cid)

        has_changes = bool(added or removed or changed)

        if json_output:
            json_result = {
                "added": [{"id": cid, "type": new_contracts[cid].get("type", "?")} for cid in added],
                "removed": [{"id": cid, "type": old_contracts[cid].get("type", "?")} for cid in removed],
                "changed": changed,
                "unchanged": unchanged,
                "has_changes": has_changes,
            }
        else:
            if added:
                _console.print("[green bold]Added:[/green bold]")
                for cid in added:
                    c = new_contracts[cid]
                    _console.print(f"  + {cid} (type: {c.get('type', '?')})")

            if removed:
                _console.print("[red bold]Removed:[/red bold]")
                for cid in removed:
                    c = old_contracts[cid]
                    _console.print(f"  - {cid} (type: {c.get('type', '?')})")

            if changed:
                _console.print("[yellow bold]Changed:[/yellow bold]")
                for cid in changed:
                    _console.print(f"  ~ {cid}")

            if unchanged and not has_changes:
                _console.print("[dim]No changes detected. Bundles are identical.[/dim]")

            # Summary
            parts = []
            if added:
                parts.append(f"{len(added)} added")
            if removed:
                parts.append(f"{len(removed)} removed")
            if changed:
                parts.append(f"{len(changed)} changed")
            if unchanged:
                parts.append(f"{len(unchanged)} unchanged")
            if parts:
                _console.print(f"\nSummary: {', '.join(parts)}")

    # Composition report for 2+ files
    from edictum.yaml_engine.composer import compose_bundles

    composed = compose_bundles(*loaded)
    report = composed.report

    if report.overridden_contracts or report.shadow_contracts:
        # For 3+ files (no standard diff), composition is the primary output
        if len(files) > 2:
            has_changes = True
        if json_output:
            json_result["composition"] = _composition_report_to_dict(report)
            if len(files) > 2:
                json_result["has_changes"] = has_changes
        else:
            _print_composition_report(report)

    if json_output:
        if "has_changes" not in json_result:
            json_result["has_changes"] = has_changes
        click.echo(json.dumps(json_result, indent=2))

    sys.exit(1 if has_changes else 0)


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--audit-log", required=True, type=click.Path(exists=True), help="JSONL audit log.")
@click.option("--output", default=None, type=click.Path(), help="Write detailed report as JSONL.")
def replay(file: str, audit_log: str, output: str | None) -> None:
    """Replay an audit log against contracts and detect verdict changes."""
    # Load contracts
    try:
        _, _, compiled = _load_and_compile(file)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load contracts: {escape(str(e))}[/red]")
        sys.exit(1)

    # Read audit log
    log_path = Path(audit_log)
    raw = log_path.read_text().strip()
    lines = raw.split("\n") if raw else []

    total = 0
    changes = 0
    skipped = 0
    report_lines: list[dict] = []

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            _err_console.print(f"[yellow]Warning: skipped invalid JSON on line {i}[/yellow]")
            skipped += 1
            continue

        total += 1
        original_action = event.get("action", "unknown")
        tool_name = event.get("tool_name", "unknown")
        tool_args = event.get("tool_args", {})
        environment = event.get("environment", "production")

        # Reconstruct principal
        principal = None
        p_data = event.get("principal")
        if p_data and isinstance(p_data, dict):
            principal = Principal(
                user_id=p_data.get("user_id"),
                role=p_data.get("role"),
                ticket_ref=p_data.get("ticket_ref"),
                claims=p_data.get("claims", {}),
            )

        # Build envelope and evaluate
        envelope = _build_envelope(tool_name, tool_args, environment, principal)
        new_verdict, contract_id, message, evaluated = _evaluate_all(compiled, envelope)

        # Map to action strings for comparison
        new_action = "call_denied" if new_verdict == "denied" else "call_allowed"
        changed = original_action != new_action

        if changed:
            changes += 1

        report_entry = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "environment": environment,
            "original_action": original_action,
            "new_verdict": new_verdict,
            "changed": changed,
        }
        if contract_id:
            report_entry["denied_by"] = contract_id
            report_entry["message"] = message
        report_lines.append(report_entry)

    # Write output file if requested
    if output:
        with open(output, "w") as f:
            for entry in report_lines:
                f.write(json.dumps(entry) + "\n")

    # Summary
    _console.print(f"\nReplayed {total} events, {changes} would change")
    if skipped:
        _console.print(f"  ({skipped} lines skipped due to invalid JSON)")

    if changes:
        _console.print("\n[yellow]Changed verdicts:[/yellow]")
        for entry in report_lines:
            if entry["changed"]:
                _console.print(f"  {entry['tool_name']}: " f"{entry['original_action']} -> {entry['new_verdict']}")
                if entry.get("denied_by"):
                    _console.print(f"    Contract: {entry['denied_by']}")
    else:
        _console.print("[green]No changes detected.[/green]")

    sys.exit(1 if changes else 0)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


def _run_cases(file: str, cases: str, environment: str = "production") -> None:
    """Run YAML test cases against contracts (preconditions only)."""
    import yaml

    # Load contracts
    try:
        _, _, compiled = _load_and_compile(file)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load contracts: {escape(str(e))}[/red]")
        sys.exit(1)

    # Load test cases
    try:
        with open(cases) as f:
            cases_data = yaml.safe_load(f)
    except Exception as e:
        _err_console.print(f"[red]Failed to load test cases: {escape(str(e))}[/red]")
        sys.exit(1)

    if not isinstance(cases_data, dict) or "cases" not in cases_data:
        _err_console.print("[red]Test cases file must contain a 'cases' list.[/red]")
        sys.exit(1)

    test_cases = cases_data["cases"]
    if not isinstance(test_cases, list):
        _err_console.print("[red]'cases' must be a list.[/red]")
        sys.exit(1)

    passed = 0
    failed = 0
    total = len(test_cases)

    valid_expects = {"allow", "deny"}

    for i, tc in enumerate(test_cases):
        tc_id = tc.get("id", f"case-{i + 1}")

        # Validate required fields
        missing = [f for f in ("tool", "expect") if f not in tc]
        if missing:
            _err_console.print(f"[red]  {escape(tc_id)}: missing required field(s): {', '.join(missing)}[/red]")
            sys.exit(2)

        tool = tc["tool"]
        args = tc.get("args", {})
        expect = tc["expect"].lower()

        if expect not in valid_expects:
            _err_console.print(
                f"[red]  {escape(tc_id)}: invalid expect value '{escape(tc['expect'])}' "
                f"(must be one of: {', '.join(sorted(valid_expects))})[/red]"
            )
            sys.exit(2)

        match_contract = tc.get("match_contract")

        # Build principal
        principal = None
        principal_data = tc.get("principal")
        if principal_data and isinstance(principal_data, dict):
            principal = Principal(
                role=principal_data.get("role"),
                user_id=principal_data.get("user_id"),
                ticket_ref=principal_data.get("ticket_ref"),
                claims=principal_data.get("claims", {}),
            )

        # Build envelope and evaluate
        case_env = tc.get("environment", environment)
        envelope = _build_envelope(tool, args, environment=case_env, principal=principal)
        verdict, contract_id, message, evaluated = _evaluate_all(compiled, envelope)

        # Map verdict to expected format
        actual = "deny" if verdict == "denied" else "allow"

        # Check match_contract
        contract_match_ok = True
        if match_contract and actual == "deny":
            contract_match_ok = contract_id == match_contract

        if actual == expect and contract_match_ok:
            passed += 1
            detail = f"{tool} {json.dumps(args)}"
            verdict_label = "DENIED" if actual == "deny" else "ALLOWED"
            contract_info = f" ({contract_id})" if contract_id else ""
            _console.print(f"[green]  {escape(tc_id)}:[/green] {escape(detail)} -> {verdict_label}{contract_info}")
        else:
            failed += 1
            detail = f"{tool} {json.dumps(args)}"
            actual_label = "DENIED" if actual == "deny" else "ALLOWED"
            expected_label = expect.upper()
            if not contract_match_ok:
                _console.print(
                    f"[red]  {escape(tc_id)}:[/red] {escape(detail)} -> "
                    f"expected contract {escape(match_contract)}, got {escape(contract_id or 'none')}"
                )
            else:
                _console.print(
                    f"[red]  {escape(tc_id)}:[/red] {escape(detail)} -> "
                    f"expected {expected_label}, got {actual_label}"
                )

    # Summary
    _console.print(f"\n{passed}/{total} passed, {failed} failed")
    sys.exit(1 if failed else 0)


def _run_calls(file: str, calls_path: str, json_output: bool, environment: str = "production") -> None:
    """Evaluate JSON tool calls against contracts using guard.evaluate_batch()."""
    from dataclasses import asdict

    from edictum import Edictum

    class _NullSink:
        async def emit(self, event):
            pass

    # Load guard
    try:
        guard = Edictum.from_yaml(file, audit_sink=_NullSink(), environment=environment)
    except EdictumConfigError as e:
        _err_console.print(f"[red]Failed to load contracts: {escape(str(e))}[/red]")
        sys.exit(1)

    # Load JSON calls
    try:
        calls_data = json.loads(Path(calls_path).read_text())
    except json.JSONDecodeError as e:
        _err_console.print(f"[red]Invalid JSON in --calls file: {escape(str(e))}[/red]")
        sys.exit(2)

    if not isinstance(calls_data, list):
        _err_console.print("[red]--calls file must contain a JSON array.[/red]")
        sys.exit(2)

    results = guard.evaluate_batch(calls_data)

    if json_output:
        output = []
        for r in results:
            output.append(
                {
                    "verdict": r.verdict,
                    "tool_name": r.tool_name,
                    "contracts_evaluated": r.contracts_evaluated,
                    "deny_reasons": list(r.deny_reasons),
                    "warn_reasons": list(r.warn_reasons),
                    "policy_error": r.policy_error,
                    "contracts": [asdict(c) for c in r.contracts],
                }
            )
        _console.print(json.dumps(output, indent=2))
    else:
        from rich.table import Table

        table = Table(show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Tool")
        table.add_column("Verdict")
        table.add_column("Contracts", justify="right")
        table.add_column("Details")

        for i, r in enumerate(results, 1):
            if r.verdict == "deny":
                verdict_styled = "[red bold]DENY[/red bold]"
                details = "; ".join(r.deny_reasons) if r.deny_reasons else ""
            elif r.verdict == "warn":
                verdict_styled = "[yellow bold]WARN[/yellow bold]"
                details = "; ".join(r.warn_reasons) if r.warn_reasons else ""
            else:
                verdict_styled = "[green bold]ALLOW[/green bold]"
                details = "all contracts passed"

            table.add_row(str(i), r.tool_name, verdict_styled, str(r.contracts_evaluated), escape(details))

        _console.print(table)

    has_deny = any(r.verdict == "deny" for r in results)
    sys.exit(1 if has_deny else 0)


@cli.command("test")
@click.argument("file", type=click.Path(exists=True))
@click.option("--cases", default=None, type=click.Path(exists=True), help="YAML file with test cases.")
@click.option("--calls", default=None, type=click.Path(exists=True), help="JSON file with tool calls to evaluate.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output results as JSON.")
@click.option("--environment", default="production", help="Environment name for evaluation.")
def test_cmd(file: str, cases: str | None, calls: str | None, json_output: bool, environment: str) -> None:
    """Test contracts against test cases or evaluate tool calls.

    Two modes:
      --cases: YAML test cases with expected verdicts (preconditions only).
      --calls: JSON tool calls for dry-run evaluation (pre + postconditions).

    Exactly one of --cases or --calls must be provided.

    Exit code 0: all cases pass / no denials.
    Exit code 1: one or more failures / denials.
    Exit code 2: usage error.
    """
    if cases and calls:
        _err_console.print("[red]Cannot use both --cases and --calls. Pick one.[/red]")
        sys.exit(2)
    if not cases and not calls:
        _err_console.print("[red]Must provide either --cases or --calls.[/red]")
        sys.exit(2)

    if cases:
        _run_cases(file, cases, environment)
    else:
        _run_calls(file, calls, json_output, environment)


# ---------------------------------------------------------------------------
# gate subgroup (lazy import — requires edictum[gate])
# ---------------------------------------------------------------------------

try:
    from edictum.cli.gate_cli import gate

    cli.add_command(gate)
except ImportError:
    pass  # edictum[gate] not installed
