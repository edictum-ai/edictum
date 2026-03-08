"""Gate CLI subcommands — edictum gate *."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import click

try:
    from rich.console import Console
    from rich.markup import escape

    _console = Console(highlight=False)
    _err_console = Console(stderr=True, highlight=False)
except ImportError:
    raise ImportError("The CLI requires click and rich. Install with: pip install edictum[cli]")


@click.group()
def gate() -> None:
    """Coding assistant governance via hook interception."""


_ASSISTANT_INFO: list[tuple[str, str, str]] = [
    ("claude-code", "Claude Code", "PreToolUse hook in ~/.claude/settings.json"),
    ("cursor", "Cursor", "preToolUse hook in ~/.cursor/hooks.json"),
    ("copilot", "Copilot CLI", "preToolUse hook in .github/hooks/hooks.json (per-repo)"),
    ("gemini", "Gemini CLI", "BeforeTool hook in .gemini/settings.json (per-repo)"),
    ("opencode", "OpenCode", "Plugin in ~/.opencode/plugins/"),
]


@gate.command("init")
@click.option("--server", default=None, help="Console server URL.")
@click.option("--api-key", default=None, help="Console API key.")
@click.option(
    "--contracts",
    "custom_contracts",
    default=None,
    type=click.Path(exists=True),
    help="Your own ContractBundle YAML.",
)
@click.option("--non-interactive", is_flag=True, default=False, help="Skip prompts, use defaults.")
def gate_init(server: str | None, api_key: str | None, custom_contracts: str | None, non_interactive: bool) -> None:
    """Set up Edictum Gate — governance for coding assistants."""
    from edictum.gate.config import DEFAULT_GATE_DIR

    gate_dir = DEFAULT_GATE_DIR
    config_path = gate_dir / "gate.yaml"

    if config_path.exists() and not non_interactive:
        if not click.confirm(f"{config_path} already exists. Overwrite?"):
            _console.print("[yellow]Aborted.[/yellow]")
            return

    _console.print("\n[bold]Edictum Gate[/bold] — governance for coding assistants\n")

    # --- Step 1: Contracts ---------------------------------------------------
    _console.print("[bold]Step 1:[/bold] Contracts\n")

    contract_path = _init_contracts(gate_dir, custom_contracts, non_interactive)

    # --- Step 2: Assistants --------------------------------------------------
    _console.print("\n[bold]Step 2:[/bold] Which assistants do you want to govern?\n")

    installed_assistants = _init_assistants(non_interactive)

    # --- Step 3: Write config ------------------------------------------------
    (gate_dir / "audit").mkdir(parents=True, exist_ok=True)
    (gate_dir / "cache").mkdir(parents=True, exist_ok=True)

    config_lines = [
        "# Edictum Gate configuration",
        "# Docs: https://edictum.ai/docs/gate",
        "",
        "contracts:",
        f"  - {contract_path}",
        "",
    ]

    if server:
        config_lines.extend(
            [
                "console:",
                f"  url: {server}",
                f"  api_key: {api_key or ''}",
                '  agent_id: "${hostname}-${user}"',
                "",
            ]
        )

    config_lines.extend(
        [
            "audit:",
            "  enabled: true",
            f"  buffer_path: {gate_dir / 'audit' / 'wal.jsonl'}",
            "",
            "redaction:",
            "  enabled: true",
            "",
            "fail_open: false",
        ]
    )

    config_path.write_text("\n".join(config_lines) + "\n")
    _console.print(f"  [green]Created[/green] {config_path}")

    # --- Step 3: What's next -------------------------------------------------
    _console.print("\n[bold]Step 3:[/bold] Try it out\n")
    if installed_assistants:
        first = installed_assistants[0]
        _console.print(f"  1. Open [cyan]{first}[/cyan] and use it normally — tool calls are now being logged.")
    else:
        _console.print("  1. Run [cyan]edictum gate install <assistant>[/cyan] to register a hook.")
    _console.print("  2. Run [cyan]edictum gate audit[/cyan] to see what's being caught.")
    _console.print(f"  3. Edit [cyan]{contract_path}[/cyan] to customize your contracts.")
    _console.print(
        "  4. When ready, change [bold]mode: observe[/bold] to" " [bold]mode: enforce[/bold] to start blocking."
    )
    _console.print("\n  Write your own contracts: [dim]https://edictum.ai/docs/gate/contracts[/dim]")
    _console.print("")


def _init_contracts(gate_dir: Path, custom_contracts: str | None, non_interactive: bool) -> Path:
    """Set up contracts — custom or default. Returns the contract file path."""
    contracts_dir = gate_dir / "contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    template_dst = contracts_dir / "base.yaml"

    if custom_contracts:
        # User provided their own contracts
        shutil.copy2(custom_contracts, str(template_dst))
        _console.print(f"  [green]Copied[/green] {custom_contracts} -> {template_dst}")
        return template_dst

    if non_interactive:
        choice = "1"
    else:
        _console.print("  [bold][1][/bold] Use default contracts (observe mode — logs without blocking)")
        _console.print("      Covers: secret file access, destructive commands, git safety,")
        _console.print("      system modifications, package installations.")
        _console.print("  [bold][2][/bold] Provide your own ContractBundle path\n")
        choice = click.prompt("  Choose", type=click.Choice(["1", "2"]), default="1")

    if choice == "2":
        custom_path = click.prompt("  Path to your ContractBundle YAML", type=click.Path(exists=True))
        shutil.copy2(custom_path, str(template_dst))
        _console.print(f"  [green]Copied[/green] {custom_path} -> {template_dst}")
    else:
        template_src = Path(__file__).parent.parent / "yaml_engine" / "templates" / "coding-assistant-base.yaml"
        if template_src.exists():
            shutil.copy2(str(template_src), str(template_dst))
            _console.print(f"  [green]Created[/green] {template_dst}")
            _console.print("  Mode: [cyan]observe[/cyan] (logs what would be denied, does not block)")
        else:
            minimal = (
                "apiVersion: edictum/v1\nkind: ContractBundle\n\n"
                "metadata:\n  name: base\n  description: Base gate contracts\n\n"
                "defaults:\n  mode: observe\n\ncontracts: []\n"
            )
            template_dst.write_text(minimal)
            _console.print(f"  [yellow]Created[/yellow] {template_dst} (empty — template not found)")

    return template_dst


def _init_assistants(non_interactive: bool) -> list[str]:
    """Prompt user to select assistants, install hooks. Returns list of installed names."""
    from edictum.gate.install import INSTALLER_REGISTRY

    for i, (key, name, desc) in enumerate(_ASSISTANT_INFO, 1):
        _console.print(f"  [bold][{i}][/bold] {name:14s} {desc}")
    _console.print("")

    if non_interactive:
        return []

    raw = click.prompt(
        "  Select (comma-separated numbers, or 'none')",
        default="none",
    )

    if raw.strip().lower() in ("none", "n", ""):
        _console.print("  [dim]Skipped — install later with: edictum gate install <assistant>[/dim]")
        return []

    # Parse selection
    installed = []
    for part in raw.split(","):
        part = part.strip()
        try:
            idx = int(part) - 1
            if 0 <= idx < len(_ASSISTANT_INFO):
                key, name, _ = _ASSISTANT_INFO[idx]
                installer, _ = INSTALLER_REGISTRY[key]
                result = installer()
                _console.print(f"  [green]OK[/green] {name}: {result}")
                installed.append(name)
            else:
                _console.print(f"  [yellow]Skipped[/yellow] invalid selection: {part}")
        except (ValueError, KeyError):
            _console.print(f"  [yellow]Skipped[/yellow] invalid selection: {part}")

    return installed


@gate.command("check")
@click.option(
    "--format",
    "format_name",
    default="claude-code",
    type=click.Choice(["claude-code", "copilot", "cursor", "gemini", "opencode", "raw"]),
    help="Output format (default: claude-code).",
)
@click.option("--contracts", "contracts_path", default=None, type=click.Path(), help="Override contract path.")
@click.option("--json", "json_flag", is_flag=True, default=False, help="Force JSON output.")
def gate_check(format_name: str, contracts_path: str | None, json_flag: bool) -> None:
    """Evaluate a tool call from stdin against contracts."""
    from edictum.gate.check import run_check
    from edictum.gate.config import GateConfig, load_gate_config

    config = load_gate_config()

    if contracts_path:
        config = GateConfig(
            contracts=(contracts_path,),
            console=config.console,
            audit=config.audit,
            redaction=config.redaction,
            cache=config.cache,
            fail_open=config.fail_open,
        )

    stdin_data = sys.stdin.read()
    cwd = os.getcwd()

    stdout_json, exit_code = run_check(stdin_data, format_name, config, cwd)
    sys.stdout.write(stdout_json)
    sys.stdout.write("\n")
    sys.exit(exit_code)


@gate.command("install")
@click.argument("assistant", type=click.Choice(["claude-code", "copilot", "cursor", "gemini", "opencode"]))
def gate_install(assistant: str) -> None:
    """Register the gate hook with a coding assistant."""
    from edictum.gate.config import DEFAULT_CONFIG_PATH
    from edictum.gate.install import INSTALLER_REGISTRY

    if not DEFAULT_CONFIG_PATH.exists():
        _console.print("[yellow]Gate not initialized.[/yellow] Run [cyan]edictum gate init[/cyan] first.")
        _console.print("  This sets up your contracts and configuration.\n")
        if click.confirm("  Run gate init now?"):
            ctx = click.get_current_context()
            ctx.invoke(gate_init, server=None, api_key=None, custom_contracts=None, non_interactive=False)
            # gate init already offered assistant installation in Step 2
            return
        else:
            return

    installer, _ = INSTALLER_REGISTRY[assistant]
    result = installer()
    _console.print(result)


@gate.command("uninstall")
@click.argument("assistant", type=click.Choice(["claude-code", "copilot", "cursor", "gemini", "opencode"]))
def gate_uninstall(assistant: str) -> None:
    """Remove the gate hook from a coding assistant."""
    from edictum.gate.install import INSTALLER_REGISTRY

    _, uninstaller = INSTALLER_REGISTRY[assistant]
    result = uninstaller()
    _console.print(result)


@gate.command("status")
def gate_status() -> None:
    """Show current gate configuration and health."""
    from edictum import __version__
    from edictum.gate.config import load_gate_config

    config = load_gate_config()

    _console.print(f"[bold]Edictum Gate[/bold] v{__version__}")

    # Contracts
    for cp in config.contracts:
        p = Path(cp)
        if p.exists():
            import hashlib

            h = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
            try:
                from edictum.yaml_engine.loader import load_bundle

                bundle, _ = load_bundle(cp)
                count = len(bundle.get("contracts", []))
                _console.print(f"  Contracts: {cp} ({count} contracts, SHA256: {h}...)")
            except Exception:
                _console.print(f"  Contracts: {cp} (SHA256: {h}...)")
        else:
            _console.print(f"  Contracts: [red]{cp} (not found)[/red]")

    # Console
    if config.console and config.console.url:
        _console.print(f"  Console:   {config.console.url}")
    else:
        _console.print("  Console:   not configured")

    # Audit
    wal = Path(config.audit.buffer_path)
    if wal.exists():
        size = wal.stat().st_size
        line_count = sum(1 for _ in open(wal))
        _console.print(f"  Audit:     {line_count} events buffered ({size} bytes)")
    else:
        _console.print("  Audit:     no events")

    # Installed assistants
    home = Path.home()
    installed = []
    settings = home / ".claude" / "settings.json"
    if settings.exists():
        try:
            data = json.loads(settings.read_text())
            for entry in data.get("hooks", {}).get("PreToolUse", []):
                for h in entry.get("hooks", []):
                    if isinstance(h, dict) and "edictum gate check" in h.get("command", ""):
                        installed.append("claude-code")
                        break
        except Exception:
            pass

    cursor_hooks = home / ".cursor" / "hooks.json"
    if cursor_hooks.exists():
        try:
            cdata = json.loads(cursor_hooks.read_text())
            for entry in cdata.get("hooks", {}).get("preToolUse", []):
                if isinstance(entry, dict) and "edictum gate check" in entry.get("command", ""):
                    installed.append("cursor")
                    break
        except Exception:
            pass

    copilot_hooks = Path.cwd() / ".github" / "hooks" / "hooks.json"
    if copilot_hooks.exists():
        try:
            cpdata = json.loads(copilot_hooks.read_text())
            for entry in cpdata.get("hooks", {}).get("preToolUse", []):
                if isinstance(entry, dict) and "edictum gate check" in entry.get("bash", ""):
                    installed.append("copilot")
                    break
        except Exception:
            pass

    gemini_hook = Path.cwd() / ".gemini" / "hooks" / "edictum-gate.sh"
    if gemini_hook.exists():
        installed.append("gemini")

    opencode_plugin = home / ".opencode" / "plugins" / "edictum-gate.ts"
    if opencode_plugin.exists():
        installed.append("opencode")

    if installed:
        _console.print(f"  Installed: {', '.join(installed)}")
    else:
        _console.print("  Installed: none")


@gate.command("audit")
@click.option("--limit", default=20, help="Number of recent events to show.")
@click.option("--tool", default=None, help="Filter by tool name.")
@click.option("--verdict", default=None, type=click.Choice(["allow", "deny"]), help="Filter by verdict.")
def gate_audit(limit: int, tool: str | None, verdict: str | None) -> None:
    """Show recent audit events from the local write-ahead log."""
    from edictum.gate.audit_buffer import AuditBuffer
    from edictum.gate.config import load_gate_config

    config = load_gate_config()
    buffer = AuditBuffer(config.audit, config.redaction)
    events = buffer.read_recent(limit=limit, tool=tool, verdict=verdict)

    if not events:
        _console.print("[dim]No audit events found.[/dim]")
        return

    try:
        from rich.table import Table

        wide = _console.width >= 120

        table = Table(show_header=True, pad_edge=False, box=None)
        table.add_column("Time", style="dim", no_wrap=True)
        if wide:
            table.add_column("User", no_wrap=True)
            table.add_column("Assistant", no_wrap=True)
        table.add_column("Verdict", no_wrap=True)
        table.add_column("Tool", no_wrap=True)
        table.add_column("Detail")

        # How much space is left for the detail column
        fixed_cols = 32 if not wide else 62
        detail_width = max(20, _console.width - fixed_cols)

        for e in events:
            ts_raw = e.get("timestamp", "")
            # Wide: full datetime, narrow: just time
            ts = ts_raw[:19].replace("T", " ") if wide else ts_raw[11:19]
            v = e.get("verdict", "")
            m = e.get("mode", "")
            tool_name = e.get("tool_name", "")
            user = e.get("user", "")
            assistant = e.get("assistant", "")
            contract = e.get("contract_id", "")
            reason = e.get("reason", "")
            preview_len = min(detail_width, 80)
            args = escape(e.get("args_preview", "")[:preview_len])

            # Observed denial: mode=observe + contract matched (allowed through but flagged)
            is_observed_deny = m == "observe" and contract

            if v == "deny" and m == "observe":
                verdict_styled = "[yellow]would deny[/yellow]"
            elif is_observed_deny:
                verdict_styled = "[yellow]would deny[/yellow]"
            elif v == "deny":
                verdict_styled = "[red]deny[/red]"
            else:
                verdict_styled = f"[green]{v}[/green]"

            # Detail: contract+reason for denials/warns, truncated args for allows
            if (v == "deny" or is_observed_deny) and contract:
                detail = contract
                if reason:
                    detail += f" — {reason}"
            else:
                detail = f"[dim]{args}[/dim]"

            row: list[str] = [ts]
            if wide:
                row.extend([user, assistant])
            row.extend([verdict_styled, tool_name, detail])
            table.add_row(*row)
        _console.print(table)
    except ImportError:
        for e in events:
            _console.print(json.dumps(e))


@gate.command("sync")
def gate_sync() -> None:
    """Flush buffered audit events to Console."""
    from edictum.gate.config import load_gate_config

    config = load_gate_config()
    if not config.console or not config.console.url:
        _err_console.print("[red]Console not configured. Run: edictum gate init --server URL[/red]")
        sys.exit(1)

    try:
        from edictum.gate.audit_buffer import AuditBuffer

        buffer = AuditBuffer(config.audit, config.redaction)
        sent = buffer.flush_to_console(config.console)
        _console.print(f"Flushed {sent} audit events to Console")
    except ImportError:
        _err_console.print("[red]Console sync requires httpx. Install with: pip install 'edictum\\[gate]'[/red]")
        sys.exit(1)
