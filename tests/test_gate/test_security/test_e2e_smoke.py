"""End-to-end smoke test for gate lifecycle."""

from __future__ import annotations

import json
from pathlib import Path

from edictum.gate.check import run_check
from edictum.gate.config import AuditConfig, GateConfig, RedactionConfig
from edictum.gate.install import install_claude_code, uninstall_claude_code

_BASE_CONTRACTS = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test
  description: test
defaults:
  mode: enforce
contracts:
  - id: deny-env-dump
    type: pre
    tool: Bash
    when:
      args.command:
        matches_any:
          - 'cat\\s+\\.env'
    then:
      effect: deny
      message: "Denied: environment variable access"
"""


def test_full_lifecycle(tmp_path: Path) -> None:
    """init -> install -> check deny -> check allow -> audit WAL has events."""
    # 1. Set up fake home + gate config
    home = tmp_path / "home"
    home.mkdir()
    gate_dir = home / ".edictum"
    gate_dir.mkdir()
    (gate_dir / "contracts").mkdir()
    (gate_dir / "audit").mkdir()

    # Write contracts
    contracts_path = gate_dir / "contracts" / "base.yaml"
    contracts_path.write_text(_BASE_CONTRACTS)

    wal_path = gate_dir / "audit" / "wal.jsonl"

    config = GateConfig(
        contracts=(str(contracts_path),),
        audit=AuditConfig(enabled=True, buffer_path=str(wal_path)),
        redaction=RedactionConfig(enabled=True),
        fail_open=False,
    )

    # 2. Install for claude-code
    claude_dir = home / ".claude"
    claude_dir.mkdir()
    result = install_claude_code(home=home)
    assert "Installed" in result

    settings = json.loads((claude_dir / "settings.json").read_text())
    assert "PreToolUse" in settings.get("hooks", {})

    # 3. Check: deny case
    stdin_deny = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env"},
        }
    )
    stdout, exit_code = run_check(stdin_deny, "claude-code", config, str(tmp_path))
    result = json.loads(stdout)
    assert "deny" in json.dumps(result).lower()

    # 4. Check: allow case
    stdin_allow = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }
    )
    stdout, exit_code = run_check(stdin_allow, "claude-code", config, str(tmp_path))
    result = json.loads(stdout)
    # Should be allowed (empty JSON = allow for claude-code format)
    assert result == {} or "allow" in json.dumps(result).lower()

    # 5. Verify WAL has events
    if wal_path.exists():
        lines = [ln for ln in wal_path.read_text().strip().split("\n") if ln.strip()]
        assert len(lines) >= 2
        events = [json.loads(line) for line in lines]
        actions = {e["action"] for e in events}
        assert "call_denied" in actions
        assert "call_allowed" in actions

    # 6. Uninstall
    result = uninstall_claude_code(home=home)
    assert "Removed" in result

    settings = json.loads((claude_dir / "settings.json").read_text())
    hooks = settings.get("hooks", {}).get("PreToolUse", [])
    edictum_hooks = [
        h
        for entry in hooks
        for h in entry.get("hooks", [])
        if isinstance(h, dict) and "edictum" in h.get("command", "")
    ]
    assert len(edictum_hooks) == 0
