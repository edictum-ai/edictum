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


def _yaml_quote(value: object) -> str:
    """Quote a value for safe interpolation into generated YAML."""
    s = str(value)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


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
    "--rules",
    "custom_contracts",
    default=None,
    type=click.Path(exists=True),
    help="Your own Ruleset YAML.",
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

    # --- Step 3: Console (optional) ------------------------------------------
    console_url = ""
    console_key = ""
    step = 3
    if server:
        _console.print(f"\n[bold]Step {step}:[/bold] Console connection\n")
        console_url, console_key = _init_console(server, api_key, non_interactive)
        step += 1

    # --- Write config --------------------------------------------------------
    (gate_dir / "audit").mkdir(parents=True, exist_ok=True)
    (gate_dir / "cache").mkdir(parents=True, exist_ok=True)

    config_lines = [
        "# Edictum Gate configuration",
        "# Docs: https://edictum.ai/docs/gate",
        "",
        "rules:",
        f"  - {_yaml_quote(contract_path)}",
        "",
    ]

    if console_url:
        config_lines.extend(
            [
                "console:",
                f"  url: {_yaml_quote(console_url)}",
                f"  api_key: {_yaml_quote(console_key)}",
                '  agent_id: "${hostname}-${user}"',
                "",
            ]
        )

    config_lines.extend(
        [
            "audit:",
            "  enabled: true",
            f"  buffer_path: {_yaml_quote(gate_dir / 'audit' / 'wal.jsonl')}",
            "",
            "redaction:",
            "  enabled: true",
            "",
            "fail_open: false",
        ]
    )

    config_path.write_text("\n".join(config_lines) + "\n")
    _console.print(f"  [green]Created[/green] {config_path}")

    # --- What's next ---------------------------------------------------------
    _console.print(f"\n[bold]Step {step}:[/bold] Try it out\n")
    if installed_assistants:
        first = installed_assistants[0]
        _console.print(f"  1. Open [cyan]{first}[/cyan] and use it normally — tool calls are now being logged.")
    else:
        _console.print("  1. Run [cyan]edictum gate install <assistant>[/cyan] to register a hook.")
    _console.print("  2. Run [cyan]edictum gate audit[/cyan] to see what's being caught.")
    _console.print(f"  3. Edit [cyan]{contract_path}[/cyan] to customize your rules.")
    _console.print(
        "  4. When ready, change [bold]mode: observe[/bold] to [bold]mode: enforce[/bold] to start blocking."
    )
    _console.print("\n  Write your own rules: [dim]https://edictum.ai/docs/gate/rules[/dim]")
    _console.print("")


def _init_console(server: str, api_key: str | None, non_interactive: bool) -> tuple[str, str]:
    """Verify console connection and validate API key.

    Returns (url, api_key) — empty strings if verification fails and user opts out.
    """
    try:
        import httpx
    except ImportError:
        _console.print("  [red]httpx not installed.[/red] Install with: pip install 'edictum\\[gate]'")
        return "", ""

    url = server.rstrip("/")

    # Health check
    _console.print(f"  Checking {escape(url)}...")
    try:
        resp = httpx.get(f"{url}/api/v1/health", timeout=10)
        resp.raise_for_status()
        _console.print("  [green]Connected[/green] Console is reachable")
    except httpx.ConnectError:
        _console.print(f"  [red]Connection refused[/red] Is edictum-console running at {escape(url)}?")
        if non_interactive:
            return "", ""
        if not click.confirm("  Continue without console?"):
            raise SystemExit(1)
        return "", ""
    except Exception as exc:
        _console.print(f"  [red]Connection failed[/red] {escape(str(exc))}")
        if non_interactive:
            return "", ""
        if not click.confirm("  Continue without console?"):
            raise SystemExit(1)
        return "", ""

    # API key
    if not api_key and not non_interactive:
        _console.print("")
        _console.print("  Find your API key in Console under Settings > API Keys.")
        api_key = click.prompt("  API key")

    if not api_key:
        _console.print("  [yellow]No API key[/yellow] — events will not sync to Console.")
        _console.print("  Add it later in ~/.edictum/gate.yaml under console.api_key")
        return url, ""

    # Validate API key
    try:
        resp = httpx.get(
            f"{url}/api/v1/events",
            params={"limit": 1},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        resp.raise_for_status()
        _console.print("  [green]Authenticated[/green] API key is valid")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (401, 403):
            _console.print("  [red]Unauthorized[/red] API key is invalid or expired")
        else:
            _console.print(f"  [red]Validation failed[/red] HTTP {exc.response.status_code}")
        if non_interactive:
            return url, ""
        if not click.confirm("  Continue with this key anyway?"):
            raise SystemExit(1)
    except Exception as exc:
        _console.print(f"  [yellow]Could not validate key[/yellow] {escape(str(exc))}")

    _console.print("")
    _console.print("  Events auto-sync to Console every 30 seconds.")
    _console.print("  Manual flush: [cyan]edictum gate sync[/cyan]")

    return url, api_key


def _init_contracts(gate_dir: Path, custom_contracts: str | None, non_interactive: bool) -> Path:
    """Set up rules — custom or default. Returns the rule file path."""
    contracts_dir = gate_dir / "rules"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    template_dst = contracts_dir / "base.yaml"

    if custom_contracts:
        # User provided their own rules
        shutil.copy2(custom_contracts, str(template_dst))
        _console.print(f"  [green]Copied[/green] {custom_contracts} -> {template_dst}")
        return template_dst

    if non_interactive:
        choice = "1"
    else:
        _console.print("  [bold][1][/bold] Use default rules (observe mode — logs without blocking)")
        _console.print("      Covers: secret file access, destructive commands, git safety,")
        _console.print("      system modifications, package installations.")
        _console.print("  [bold][2][/bold] Provide your own Ruleset path\n")
        choice = click.prompt("  Choose", type=click.Choice(["1", "2"]), default="1")

    if choice == "2":
        custom_path = click.prompt("  Path to your Ruleset YAML", type=click.Path(exists=True))
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
                "apiVersion: edictum/v1\nkind: Ruleset\n\n"
                "metadata:\n  name: base\n  description: Base gate rules\n\n"
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
@click.option("--rules", "contracts_path", default=None, type=click.Path(), help="Override rule path.")
@click.option("--json", "json_flag", is_flag=True, default=False, help="Force JSON output.")
def gate_check(format_name: str, contracts_path: str | None, json_flag: bool) -> None:
    """Evaluate a tool call from stdin against rules."""
    from edictum.gate.check import run_check
    from edictum.gate.config import GateConfig, load_gate_config

    config = load_gate_config()

    if contracts_path:
        config = GateConfig(
            rules=(contracts_path,),
            console=config.console,
            audit=config.audit,
            redaction=config.redaction,
            cache=config.cache,
            scope_allowlist=config.scope_allowlist,
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
        _console.print("  This sets up your rules and configuration.\n")
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
    for cp in config.rules:
        p = Path(cp)
        if p.exists():
            import hashlib

            h = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
            try:
                from edictum.yaml_engine.loader import load_bundle

                bundle, _ = load_bundle(cp)
                count = len(bundle.get("rules", []))
                _console.print(f"  Contracts: {cp} ({count} rules, SHA256: {h}...)")
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
        with open(wal) as _f:
            line_count = sum(1 for _ in _f)
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
@click.option("--decision", default=None, type=click.Choice(["allow", "block"]), help="Filter by decision.")
def gate_audit(limit: int, tool: str | None, decision: str | None) -> None:
    """Show recent audit events from the local write-ahead log."""
    from edictum.gate.audit_buffer import AuditBuffer
    from edictum.gate.config import load_gate_config

    config = load_gate_config()
    buffer = AuditBuffer(config.audit, config.redaction)
    events = buffer.read_recent(limit=limit, tool=tool, decision=decision)

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
        table.add_column("Decision", no_wrap=True)
        table.add_column("Tool", no_wrap=True)
        table.add_column("Detail")

        # How much space is left for the detail column
        fixed_cols = 32 if not wide else 62
        detail_width = max(20, _console.width - fixed_cols)

        for e in events:
            ts_raw = e.get("timestamp", "")
            # Wide: full datetime, narrow: just time
            ts = ts_raw[:19].replace("T", " ") if wide else ts_raw[11:19]
            # Support both new (action) and old (decision) field names
            action = e.get("action", e.get("decision", ""))
            tool_name = e.get("tool_name", "")
            user = e.get("user", "")
            assistant = e.get("assistant", "")
            rule = e.get("decision_name", e.get("rule_id", ""))
            reason = e.get("reason", "")
            preview_len = min(detail_width, 80)
            # Support both new (tool_args dict) and old (args_preview string)
            tool_args = e.get("tool_args")
            if isinstance(tool_args, dict):
                args = escape(json.dumps(tool_args, default=str)[:preview_len])
            else:
                args = escape(str(e.get("args_preview", ""))[:preview_len])

            if action == "call_would_deny":
                verdict_styled = "[yellow]would block[/yellow]"
            elif action in ("call_denied", "block"):
                verdict_styled = "[red]block[/red]"
            elif action in ("call_allowed", "allow"):
                verdict_styled = "[green]allow[/green]"
            else:
                verdict_styled = f"[dim]{action}[/dim]"

            # Detail: rule+reason for denials, truncated args for allows
            is_denial = action in ("call_denied", "call_would_deny", "block")
            if is_denial and rule:
                detail = rule
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
