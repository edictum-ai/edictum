"""Gate check — stdin -> ToolEnvelope -> evaluate -> stdout."""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

CATEGORY_MAP: dict[str, str] = {
    "Bash": "shell",
    "Read": "file.read",
    "Write": "file.write",
    "Edit": "file.edit",
    "Glob": "file.search",
    "Grep": "file.search",
    "WebFetch": "browser",
    "WebSearch": "browser",
    "NotebookEdit": "notebook",
    "Task": "task",
}

# Tools subject to scope enforcement (writes/edits outside cwd)
_SCOPE_TOOLS = frozenset({"Write", "Edit", "NotebookEdit"})

# Max stdin size (10 MB)
_MAX_STDIN_SIZE = 10 * 1024 * 1024


def resolve_category(tool_name: str) -> str:
    """Map a tool name to its category string."""
    if tool_name in CATEGORY_MAP:
        return CATEGORY_MAP[tool_name]
    if tool_name.startswith("mcp__"):
        return "mcp"
    return "unknown"


def _check_scope(
    file_path: str | None,
    cwd: str,
    allowlist: tuple[str, ...] = (),
) -> tuple[bool, str]:
    """Check if file_path is within cwd or an allowlisted prefix.

    Returns (is_within, reason).
    """
    if not file_path:
        return True, ""
    try:
        real = os.path.realpath(file_path)
        real_cwd = os.path.realpath(cwd)
        if real == real_cwd or real.startswith(real_cwd + os.sep):
            return True, ""
        # Check allowlisted prefixes (e.g. ~/.claude/ for assistant memory)
        for prefix in allowlist:
            real_prefix = os.path.realpath(prefix.rstrip(os.sep)) + os.sep
            if real == real_prefix.rstrip(os.sep) or real.startswith(real_prefix):
                return True, ""
        return False, f"Denied: file path '{file_path}' is outside the project directory"
    except (OSError, ValueError):
        return False, f"Denied: cannot resolve file path '{file_path}'"


def _validate_stdin(data: Any) -> tuple[str, dict, str] | tuple[None, None, str]:
    """Validate basic stdin structure. Returns (tool_name, tool_input, error)."""
    if not isinstance(data, dict):
        return None, None, "stdin must be a JSON object"

    tool_name = data.get("tool_name")
    tool_input = data.get("tool_input")

    if not tool_name or not isinstance(tool_name, str):
        return None, None, "missing or invalid tool_name"

    if tool_input is not None and not isinstance(tool_input, dict):
        return None, None, "tool_input must be a JSON object"

    return tool_name, tool_input or {}, ""


def run_check(
    stdin_data: str,
    format_name: str,
    config: Any,
    cwd: str,
) -> tuple[str, int]:
    """Core gate check: parse stdin, evaluate contracts, return (stdout_json, exit_code).

    Args:
        stdin_data: Raw JSON string from stdin.
        format_name: Output format name (claude-code, cursor, gemini, opencode, raw).
        config: GateConfig instance.
        cwd: Working directory for scope enforcement.

    Returns:
        Tuple of (JSON string for stdout, exit code).
    """
    from edictum.gate.formats import get_format

    start = time.perf_counter_ns()
    format_handler = get_format(format_name)

    try:
        return _run_check_inner(stdin_data, format_handler, format_name, config, cwd, start)
    except Exception as exc:
        # Fail-closed by default
        if getattr(config, "fail_open", False):
            return format_handler.format_output("allow", None, None, 0)
        reason = f"Gate internal error: {exc}"
        return format_handler.format_output("deny", None, reason, 0)


def _run_check_inner(
    stdin_data: str,
    format_handler: Any,
    format_name: str,
    config: Any,
    cwd: str,
    start: int,
) -> tuple[str, int]:
    """Inner check logic, separated so exceptions propagate to run_check."""
    # Size check
    if len(stdin_data) > _MAX_STDIN_SIZE:
        return format_handler.format_output("deny", None, "Denied: stdin payload too large", 0)

    # Parse JSON
    try:
        parsed = json.loads(stdin_data)
    except (json.JSONDecodeError, ValueError):
        return format_handler.format_output("deny", None, "Denied: invalid JSON in stdin", 0)

    if not isinstance(parsed, dict):
        return format_handler.format_output("deny", None, "Denied: stdin must be a JSON object", 0)

    # Auto-detect Cursor when hook is registered as claude-code but stdin
    # contains Cursor-specific fields (cursor_version, workspace_roots).
    # This handles the case where Cursor reads Claude Code's hook config.
    if format_name == "claude-code":
        if parsed.get("cursor_version") or isinstance(parsed.get("workspace_roots"), list):
            from edictum.gate.formats import get_format as _get_format

            format_name = "cursor"
            format_handler = _get_format(format_name)

    # Parse format-specific fields
    try:
        tool_name, tool_input, parsed_cwd = format_handler.parse_stdin(parsed)
    except Exception:
        return format_handler.format_output("deny", None, "Denied: failed to parse stdin", 0)

    effective_cwd = parsed_cwd or cwd

    # Validate tool_name
    if not tool_name or not isinstance(tool_name, str):
        return format_handler.format_output("deny", None, "Denied: missing or invalid tool_name", 0)

    # Reject control characters in tool_name
    if any(ord(c) < 32 or c == "\x7f" for c in tool_name):
        return format_handler.format_output("deny", None, "Denied: invalid characters in tool_name", 0)

    if not isinstance(tool_input, dict):
        return format_handler.format_output("deny", None, "Denied: tool_input must be a JSON object", 0)

    # Resolve category
    category = resolve_category(tool_name)

    # Load and evaluate contracts
    from edictum import Edictum, EdictumConfigError

    contract_paths = list(getattr(config, "contracts", ()))
    fail_open = getattr(config, "fail_open", False)

    if not contract_paths:
        if fail_open:
            return format_handler.format_output("allow", None, None, 0)
        return format_handler.format_output("deny", None, "Denied: no contract paths configured", 0)

    # Filter to existing paths
    existing_paths = [p for p in contract_paths if os.path.exists(p)]
    if not existing_paths:
        if fail_open:
            return format_handler.format_output("allow", None, None, 0)
        return format_handler.format_output("deny", None, "Denied: no contract files found", 0)

    try:
        guard = Edictum.from_yaml(*existing_paths)
    except (EdictumConfigError, Exception):
        if getattr(config, "fail_open", False):
            return format_handler.format_output("allow", None, None, 0)
        return format_handler.format_output("deny", None, "Denied: failed to load contracts", 0)

    # Write contract manifest for Console coverage reporting
    _write_contract_manifest(existing_paths, guard, config)

    # Evaluate
    result = guard.evaluate(tool_name, tool_input)

    raw_verdict = result.verdict  # "allow", "deny", or "warn"

    # Gate is binary: allow or deny
    if raw_verdict == "deny":
        verdict = "deny"
    else:
        verdict = "allow"  # "allow" and "warn" both pass through

    # Derive mode and decision info from contract results
    mode = "enforce"
    contract_id = None
    reason = None
    decision_source = None
    if result.contracts:
        for c in result.contracts:
            if not c.passed:
                contract_id = c.contract_id
                reason = c.message
                decision_source = f"yaml_{c.contract_type}"
                if c.observed:
                    mode = "observe"
                break

    # Scope enforcement (programmatic, not YAML)
    if verdict == "allow" and tool_name in _SCOPE_TOOLS:
        file_path = tool_input.get("file_path") or tool_input.get("filePath") or tool_input.get("path")
        scope_allowlist = getattr(config, "scope_allowlist", ())
        is_within, scope_reason = _check_scope(file_path, effective_cwd, scope_allowlist)
        if not is_within:
            # Scope enforcement respects the guard's default mode.
            # In observe mode, scope logs (would-deny) but does not block.
            # Self-protection contracts have explicit mode: enforce and fire
            # before scope reaches this point, so they always block.
            verdict = "deny"
            mode = guard.mode
            contract_id = "gate-scope-enforcement"
            reason = scope_reason
            decision_source = "gate_scope"

    duration_ms = (time.perf_counter_ns() - start) // 1_000_000

    # Resolve agent_id: prefer console config, fall back to hostname-user
    console_config = getattr(config, "console", None)
    agent_id = getattr(console_config, "agent_id", "") if console_config else ""
    if not agent_id:
        import socket

        try:
            user = os.getlogin()
        except OSError:
            user = os.getenv("USER", "unknown")
        agent_id = f"{socket.gethostname()}-{user}"

    # Write audit event aligned with core AuditEvent schema
    _write_audit(
        config=config,
        tool_name=tool_name,
        tool_input=tool_input,
        category=category,
        verdict=verdict,
        mode=mode,
        contract_id=contract_id,
        decision_source=decision_source,
        reason=reason,
        cwd=effective_cwd,
        duration_ms=duration_ms,
        assistant=format_name,
        agent_id=agent_id,
        evaluation_result=result,
        policy_version=guard.policy_version,
    )

    # Observe mode: audit records would-deny, but the assistant is told allow
    output_verdict = "allow" if (verdict == "deny" and mode == "observe") else verdict
    return format_handler.format_output(output_verdict, contract_id, reason, result.contracts_evaluated)


def _write_contract_manifest(
    contract_paths: list[str],
    guard: Any,
    config: Any,
) -> None:
    """Write contract manifest for Console coverage reporting.

    Creates a lightweight JSON file with contract IDs, tools, types, and modes.
    flush_to_console() reads this and includes it as agent_manifest in the sync
    payload so Console can populate the coverage dashboard.

    Only rewrites when policy_version changes (cheap string comparison).
    """
    try:
        audit_config = getattr(config, "audit", None)
        if audit_config is None:
            return
        buffer_path = getattr(audit_config, "buffer_path", "")
        if not buffer_path:
            return

        from pathlib import Path

        manifest_path = Path(buffer_path).parent / "manifest.json"

        # Skip if policy_version hasn't changed
        policy_version = getattr(guard, "policy_version", None) or ""
        if manifest_path.exists():
            try:
                existing = json.loads(manifest_path.read_text())
                if existing.get("policy_version") == policy_version:
                    return
            except (json.JSONDecodeError, OSError):
                pass

        # Extract contract metadata from YAML files
        import yaml

        contracts_meta: list[dict] = []
        for path in contract_paths:
            try:
                with open(path) as f:
                    bundle = yaml.safe_load(f)
                if not isinstance(bundle, dict):
                    continue
                defaults_mode = bundle.get("defaults", {}).get("mode", "enforce")
                for c in bundle.get("contracts", []):
                    tool = c.get("tool", c.get("tools", "*"))
                    if isinstance(tool, list):
                        tool = ", ".join(tool)
                    contracts_meta.append(
                        {
                            "id": c.get("id", ""),
                            "type": c.get("type", ""),
                            "tool": tool,
                            "mode": c.get("mode", defaults_mode),
                        }
                    )
            except Exception:
                continue

        manifest = {
            "policy_version": policy_version,
            "contracts": contracts_meta,
        }
        # NOTE: Not atomic — a crash mid-write leaves a partial file. This is
        # acceptable because the read path catches JSONDecodeError and the manifest
        # is regenerated on the next check when policy_version differs.
        manifest_path.write_text(json.dumps(manifest))
    except Exception:
        pass  # Never block the gate check


def _write_audit(
    config: Any,
    tool_name: str,
    tool_input: dict,
    category: str,
    verdict: str,
    mode: str,
    contract_id: str | None,
    decision_source: str | None,
    reason: str | None,
    cwd: str,
    duration_ms: int,
    assistant: str,
    agent_id: str,
    evaluation_result: Any,
    policy_version: str | None,
) -> None:
    """Write audit event to WAL if audit is enabled. Never raises."""
    try:
        audit_config = getattr(config, "audit", None)
        if audit_config is None or not getattr(audit_config, "enabled", True):
            return

        from edictum.gate.audit_buffer import AuditBuffer, build_audit_event

        redaction_config = getattr(config, "redaction", None)
        buffer = AuditBuffer(audit_config, redaction_config)
        event = build_audit_event(
            tool_name=tool_name,
            tool_input=tool_input,
            category=category,
            verdict=verdict,
            mode=mode,
            contract_id=contract_id,
            decision_source=decision_source,
            reason=reason,
            cwd=cwd,
            duration_ms=duration_ms,
            assistant=assistant,
            agent_id=agent_id,
            redaction_config=redaction_config,
            evaluation_result=evaluation_result,
            policy_version=policy_version,
        )
        console_config = getattr(config, "console", None)
        buffer.write(event, console_config=console_config)
    except Exception:
        pass  # Audit failure must never block the gate check


def main() -> None:
    """Entry point for `python -m edictum.gate`."""
    import argparse

    parser = argparse.ArgumentParser(description="Edictum Gate check")
    parser.add_argument(
        "--format",
        dest="format_name",
        default="claude-code",
        choices=["claude-code", "copilot", "cursor", "gemini", "opencode", "raw"],
        help="Output format (default: claude-code)",
    )
    parser.add_argument("--contracts", dest="contracts_path", default=None, help="Override contract path")
    args = parser.parse_args()

    from edictum.gate.config import GateConfig, load_gate_config

    config = load_gate_config()

    if args.contracts_path:
        config = GateConfig(
            contracts=(args.contracts_path,),
            console=config.console,
            audit=config.audit,
            redaction=config.redaction,
            cache=config.cache,
            scope_allowlist=config.scope_allowlist,
            fail_open=config.fail_open,
        )

    stdin_data = sys.stdin.read()
    cwd = os.getcwd()

    stdout_json, exit_code = run_check(stdin_data, args.format_name, config, cwd)
    sys.stdout.write(stdout_json)
    sys.stdout.write("\n")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
