"""Gate audit buffer — WAL write + batch flush to Console."""

from __future__ import annotations

import json
import os
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edictum.audit import RedactionPolicy


@dataclass(frozen=True)
class GateAuditEvent:
    """Gate-specific audit event for JSONL WAL."""

    # Identity
    call_id: str
    agent_id: str
    user: str
    assistant: str

    # What happened
    tool_name: str
    tool_category: str
    args_preview: str

    # Decision
    verdict: str
    mode: str  # "observe" or "enforce"
    contract_id: str | None
    reason: str | None

    # Context
    cwd: str
    timestamp: str

    # Performance
    duration_ms: int
    contracts_evaluated: int


def _build_redaction_policy(config: Any) -> RedactionPolicy:
    """Build RedactionPolicy from gate RedactionConfig."""
    if config is None:
        return RedactionPolicy()
    patterns = getattr(config, "patterns", ())
    replacement = getattr(config, "replacement", "<REDACTED>")
    custom_patterns = [(p, replacement) for p in patterns] if patterns else []
    return RedactionPolicy(custom_patterns=custom_patterns)


def _resolve_user() -> str:
    """Get the current OS user. Never raises."""
    try:
        return os.getlogin()
    except OSError:
        return os.getenv("USER", "unknown")


def build_audit_event(
    *,
    tool_name: str,
    tool_input: dict,
    category: str,
    verdict: str,
    mode: str,
    contract_id: str | None,
    reason: str | None,
    cwd: str,
    duration_ms: int,
    contracts_evaluated: int,
    assistant: str,
    agent_id: str = "",
    redaction_config: Any = None,
) -> GateAuditEvent:
    """Build a GateAuditEvent with redacted args preview."""
    import re

    policy = _build_redaction_policy(redaction_config)
    redacted_args = policy.redact_args(tool_input)
    args_str = json.dumps(redacted_args, default=str)

    # Apply gate-specific regex patterns to the serialized string
    if redaction_config is not None:
        patterns = getattr(redaction_config, "patterns", ())
        replacement = getattr(redaction_config, "replacement", "<REDACTED>")
        for pattern in patterns:
            try:
                args_str = re.sub(pattern, replacement, args_str)
            except re.error:
                pass

    if len(args_str) > 200:
        args_str = args_str[:197] + "..."

    return GateAuditEvent(
        call_id=str(uuid.uuid4()),
        agent_id=agent_id,
        user=_resolve_user(),
        assistant=assistant,
        tool_name=tool_name,
        tool_category=category,
        args_preview=args_str,
        verdict=verdict,
        mode=mode,
        contract_id=contract_id,
        reason=reason,
        cwd=cwd,
        timestamp=datetime.now(UTC).isoformat(),
        duration_ms=duration_ms,
        contracts_evaluated=contracts_evaluated,
    )


class AuditBuffer:
    """Write-ahead log for gate audit events.

    Events are redacted BEFORE writing to the WAL. Secrets never hit disk.
    """

    def __init__(self, audit_config: Any, redaction_config: Any = None) -> None:
        self._buffer_path = Path(getattr(audit_config, "buffer_path", ""))
        self._max_size_mb = getattr(audit_config, "max_buffer_size_mb", 50)
        self._redaction_config = redaction_config

    def write(self, event: GateAuditEvent) -> None:
        """Append event to WAL. Sync, fast (<5ms target)."""
        try:
            # Ensure directory exists
            self._buffer_path.parent.mkdir(parents=True, exist_ok=True)

            # Safety: refuse to write if WAL path resolves to a symlink target outside expected dir
            real_path = os.path.realpath(self._buffer_path)
            expected_parent = os.path.realpath(self._buffer_path.parent)
            if not real_path.startswith(expected_parent):
                print("Gate audit: WAL path resolves outside expected directory", file=sys.stderr)
                return

            line = json.dumps(asdict(event), default=str) + "\n"
            with open(real_path, "a") as f:
                f.write(line)
        except Exception as exc:
            # Never crash the gate check
            print(f"Gate audit write error: {exc}", file=sys.stderr)

    def rotate_if_needed(self) -> None:
        """Rotate WAL if it exceeds max_buffer_size_mb."""
        try:
            if not self._buffer_path.exists():
                return
            size_mb = self._buffer_path.stat().st_size / (1024 * 1024)
            if size_mb < self._max_size_mb:
                return

            backup = self._buffer_path.with_suffix(".jsonl.1")
            # Remove older backup if exists
            old_backup = self._buffer_path.with_suffix(".jsonl.2")
            if old_backup.exists():
                old_backup.unlink()
            # Rotate current to .1
            if backup.exists():
                backup.unlink()
            os.replace(str(self._buffer_path), str(backup))
        except Exception as exc:
            print(f"Gate audit rotate error: {exc}", file=sys.stderr)

    def read_recent(self, limit: int = 20, tool: str | None = None, verdict: str | None = None) -> list[dict]:
        """Read recent events from WAL with optional filters."""
        if not self._buffer_path.exists():
            return []

        events: list[dict] = []
        try:
            with open(self._buffer_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if tool and event.get("tool_name") != tool:
                        continue
                    if verdict and event.get("verdict") != verdict:
                        continue
                    events.append(event)
        except OSError:
            return []

        return events[-limit:]

    @staticmethod
    def _to_console_event(raw: dict) -> dict:
        """Map a WAL event dict to Console EventPayload schema.

        Console expects top-level: call_id, agent_id, tool_name, verdict, mode,
        timestamp, payload (optional dict).

        The dashboard renders payload fields using core AuditEvent conventions:
        - decision_name (contract id), decision_source, reason, policy_version
        - tool_args (dict of args), duration_ms
        Gate must map its WAL field names to these.
        """
        # Map Gate verdict to core AuditAction values the dashboard understands
        gate_verdict = raw.get("verdict", "allow")
        gate_mode = raw.get("mode", "enforce")
        if gate_verdict == "deny" and gate_mode == "observe":
            verdict = "call_would_deny"
        elif gate_verdict == "deny":
            verdict = "call_denied"
        else:
            verdict = "call_allowed"

        # Build payload using core AuditEvent field names
        payload: dict[str, object] = {}

        # Contract provenance — dashboard reads decision_name, decision_source
        contract_id = raw.get("contract_id")
        if contract_id:
            payload["decision_name"] = contract_id
            if contract_id == "gate-scope-enforcement":
                payload["decision_source"] = "gate_scope"
            else:
                payload["decision_source"] = "yaml_precondition"

        reason = raw.get("reason")
        if reason:
            payload["reason"] = reason

        # Tool args — dashboard reads tool_args as dict for preview
        args_preview = raw.get("args_preview", "")
        if args_preview:
            try:
                payload["tool_args"] = json.loads(args_preview)
            except (json.JSONDecodeError, ValueError):
                payload["tool_args"] = {"_preview": args_preview}

        # Performance and context
        duration_ms = raw.get("duration_ms")
        if duration_ms is not None:
            payload["duration_ms"] = duration_ms

        contracts_evaluated = raw.get("contracts_evaluated")
        if contracts_evaluated is not None:
            payload["contracts_evaluated"] = contracts_evaluated

        # Gate-specific extras (not in core AuditEvent but useful)
        for key in ("assistant", "user", "tool_category", "cwd"):
            val = raw.get(key)
            if val:
                payload[key] = val

        # Default agent_id from user+hostname if not set
        agent_id = raw.get("agent_id", "")
        if not agent_id:
            user = raw.get("user", "")
            if user:
                agent_id = user

        return {
            "call_id": raw.get("call_id", str(uuid.uuid4())),
            "agent_id": agent_id,
            "tool_name": raw.get("tool_name", ""),
            "verdict": verdict,
            "mode": gate_mode,
            "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
            "payload": payload or None,
        }

    def flush_to_console(self, console_config: Any) -> int:
        """Batch POST buffered events to Console. Returns count sent."""
        if not self._buffer_path.exists():
            return 0

        lines = self._buffer_path.read_text().strip().split("\n")
        raw_events = []
        for line in lines:
            if not line.strip():
                continue
            try:
                raw_events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not raw_events:
            return 0

        url = getattr(console_config, "url", "")
        api_key = getattr(console_config, "api_key", "")
        if not url:
            return 0

        # Map WAL events to Console schema
        console_events = [self._to_console_event(e) for e in raw_events]

        import httpx

        client = httpx.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30,
        )
        try:
            response = client.post(
                "/api/v1/events",
                json={"events": console_events},
            )
            response.raise_for_status()
        except Exception as exc:
            print(f"Gate audit flush error: {exc}", file=sys.stderr)
            return 0
        finally:
            client.close()

        # Truncate WAL on success
        try:
            self._buffer_path.write_text("")
        except OSError:
            pass

        return len(console_events)
