"""Gate audit buffer — WAL write + batch flush to Console."""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edictum.audit import RedactionPolicy


@dataclass(frozen=True)
class GateAuditEvent:
    """Audit event aligned with core AuditEvent schema.

    WAL events use the same field names as core AuditEvent so they can be
    sent directly to the console without a translation layer. Fields that
    don't apply to Gate (run_id, principal, session counters) are omitted.
    """

    # Identity
    call_id: str
    timestamp: str
    agent_id: str

    # Tool
    tool_name: str
    tool_args: dict  # redacted args (full dict, not preview string)
    side_effect: str  # tool category as side_effect label

    # Governance decision — same names as core AuditEvent
    action: str  # "call_allowed" | "call_denied" | "call_would_deny"
    decision_source: str | None
    decision_name: str | None  # contract_id
    reason: str | None
    contracts_evaluated: list[dict] = field(default_factory=list)

    # Mode
    mode: str = "enforce"

    # Policy tracking
    policy_version: str | None = None
    policy_error: bool = False

    # Performance
    duration_ms: int = 0

    # Gate-specific context (not in core AuditEvent)
    assistant: str = ""
    user: str = ""
    cwd: str = ""


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


def _verdict_to_action(verdict: str, mode: str) -> str:
    """Map Gate verdict+mode to core AuditAction value."""
    if verdict == "deny" and mode == "observe":
        return "call_would_deny"
    if verdict == "deny":
        return "call_denied"
    return "call_allowed"


def _contracts_to_dicts(evaluation_result: Any) -> list[dict]:
    """Extract contract evaluation details from EvaluationResult.

    Field names match what the console dashboard expects:
    - name (dashboard reads c.name for display)
    - type (dashboard reads c.type for badge)
    """
    if evaluation_result is None:
        return []
    contracts = getattr(evaluation_result, "contracts", [])
    result = []
    for c in contracts:
        result.append(
            {
                "name": c.contract_id,
                "type": c.contract_type,
                "passed": c.passed,
                "message": c.message,
                "observed": c.observed,
                "policy_error": c.policy_error,
            }
        )
    return result


def build_audit_event(
    *,
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
    agent_id: str = "",
    redaction_config: Any = None,
    evaluation_result: Any = None,
    policy_version: str | None = None,
) -> GateAuditEvent:
    """Build a GateAuditEvent with redacted args, aligned with core AuditEvent."""
    import re

    policy = _build_redaction_policy(redaction_config)
    redacted_args = policy.redact_args(tool_input)

    # Apply gate-specific regex patterns to serialized form, then parse back
    if redaction_config is not None:
        args_str = json.dumps(redacted_args, default=str)
        patterns = getattr(redaction_config, "patterns", ())
        replacement = getattr(redaction_config, "replacement", "<REDACTED>")
        for pattern in patterns:
            try:
                args_str = re.sub(pattern, replacement, args_str)
            except re.error:
                pass
        try:
            redacted_args = json.loads(args_str)
        except (json.JSONDecodeError, ValueError):
            pass

    action = _verdict_to_action(verdict, mode)
    contracts = _contracts_to_dicts(evaluation_result)
    pe = getattr(evaluation_result, "policy_error", False) if evaluation_result else False
    evaluated_count = getattr(evaluation_result, "contracts_evaluated", 0) if evaluation_result else 0

    # For backward compat with old WAL readers, include contracts_evaluated as count
    # if no contract details available
    if not contracts and evaluated_count:
        contracts = [{"_count": evaluated_count}]

    return GateAuditEvent(
        call_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
        agent_id=agent_id,
        tool_name=tool_name,
        tool_args=redacted_args,
        side_effect=category,
        action=action,
        decision_source=decision_source,
        decision_name=contract_id,
        reason=reason,
        contracts_evaluated=contracts,
        mode=mode,
        policy_version=policy_version,
        policy_error=pe,
        duration_ms=duration_ms,
        assistant=assistant,
        user=_resolve_user(),
        cwd=cwd,
    )


class AuditBuffer:
    """Write-ahead log for gate audit events.

    Events are redacted BEFORE writing to the WAL. Secrets never hit disk.
    """

    def __init__(self, audit_config: Any, redaction_config: Any = None) -> None:
        self._buffer_path = Path(getattr(audit_config, "buffer_path", ""))
        self._max_size_mb = getattr(audit_config, "max_buffer_size_mb", 50)
        self._redaction_config = redaction_config

    def write(self, event: GateAuditEvent, console_config: Any = None) -> None:
        """Append event to WAL, then auto-flush to console if due. Never raises."""
        try:
            # Ensure directory exists
            self._buffer_path.parent.mkdir(parents=True, exist_ok=True)

            # Safety: refuse to write if WAL path resolves to a symlink target outside expected dir
            real_path = os.path.realpath(self._buffer_path)
            expected_parent = os.path.realpath(self._buffer_path.parent)
            if real_path != expected_parent and not real_path.startswith(expected_parent + os.sep):
                print("Gate audit: WAL path resolves outside expected directory", file=sys.stderr)
                return

            line = json.dumps(asdict(event), default=str) + "\n"
            with open(real_path, "a") as f:
                f.write(line)

            self.rotate_if_needed()
        except Exception as exc:
            # Never crash the gate check
            print(f"Gate audit write error: {exc}", file=sys.stderr)
            return

        # Auto-flush to console if configured and interval has elapsed
        if console_config and getattr(console_config, "url", ""):
            self._maybe_flush_async(console_config)

    def _maybe_flush_async(self, console_config: Any) -> None:
        """Check if flush is due, fork a background process if so. Never raises."""
        try:
            marker = self._buffer_path.parent / ".last_flush"
            now = time.time()

            # Default 30s between flushes — fast enough to feel live, rare enough
            # to avoid hammering the console on busy sessions
            interval = 30

            if marker.exists():
                try:
                    last = float(marker.read_text().strip())
                    if now - last < interval:
                        return
                except (ValueError, OSError):
                    pass

            # Update marker BEFORE forking to prevent concurrent flushes.
            # NOTE: This is not atomic — two concurrent gate checks can both read a
            # stale marker and both fork. This is acceptable because console ingestion
            # is idempotent by call_id, so duplicate flushes are harmless.
            marker.write_text(str(now))

            # Fork a background process so the gate check returns immediately.
            # NOTE: os.fork() is not available on Windows. The except Exception below
            # catches AttributeError, so auto-flush silently degrades — users can
            # still flush manually with `edictum gate sync`.
            pid = os.fork()
            if pid == 0:
                # Child: flush and exit
                try:
                    self.flush_to_console(console_config)
                except Exception:
                    pass
                os._exit(0)
            # Parent: continue immediately (don't wait for child)
        except Exception:
            pass  # Never block the gate check

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

        real_path = self._verify_wal_path()
        if real_path is None:
            return []

        events: list[dict] = []
        try:
            with open(real_path) as f:
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
                    # Support both old (verdict) and new (action) field names
                    event_verdict = event.get("action", event.get("verdict", ""))
                    if verdict:
                        # Map filter to action values
                        if verdict == "deny" and event_verdict not in ("call_denied", "call_would_deny", "deny"):
                            continue
                        if verdict == "allow" and event_verdict not in ("call_allowed", "allow"):
                            continue
                    events.append(event)
        except OSError:
            return []

        return events[-limit:]

    @staticmethod
    def _to_console_event(raw: dict) -> dict:
        """Map a WAL event to Console EventPayload schema.

        WAL events are already aligned with core AuditEvent field names.
        This method just selects the top-level fields the console expects
        and packs everything else into payload.
        """
        # Top-level fields the console expects
        action = raw.get("action", raw.get("verdict", "call_allowed"))
        mode = raw.get("mode", "enforce")

        # Build payload from all remaining fields
        payload: dict[str, object] = {}
        for key in (
            "decision_name",
            "decision_source",
            "reason",
            "tool_args",
            "side_effect",
            "contracts_evaluated",
            "policy_version",
            "policy_error",
            "duration_ms",
            "assistant",
            "user",
            "cwd",
        ):
            val = raw.get(key)
            if val is not None and val != "" and val != [] and val is not False:
                payload[key] = val

        # Backward compat: old WAL events used different field names
        if "contract_id" in raw and "decision_name" not in payload:
            payload["decision_name"] = raw["contract_id"]
        if "tool_category" in raw and "side_effect" not in payload:
            payload["side_effect"] = raw["tool_category"]
        if "args_preview" in raw and "tool_args" not in payload:
            preview = raw["args_preview"]
            try:
                payload["tool_args"] = json.loads(preview)
            except (json.JSONDecodeError, ValueError):
                payload["tool_args"] = {"_preview": preview}

        # Default agent_id from user if not set
        agent_id = raw.get("agent_id", "")
        if not agent_id:
            agent_id = raw.get("user", "")

        return {
            "call_id": raw.get("call_id", str(uuid.uuid4())),
            "agent_id": agent_id,
            "tool_name": raw.get("tool_name", ""),
            "verdict": action,
            "mode": mode,
            "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
            "payload": payload or None,
        }

    def _verify_wal_path(self) -> str | None:
        """Verify WAL path hasn't been replaced by a symlink. Returns real path or None."""
        real_path = os.path.realpath(self._buffer_path)
        expected_parent = os.path.realpath(self._buffer_path.parent)
        if real_path != expected_parent and not real_path.startswith(expected_parent + os.sep):
            print("Gate audit: WAL path resolves outside expected directory", file=sys.stderr)
            return None
        return real_path

    def flush_to_console(self, console_config: Any) -> int:
        """Batch POST buffered events to Console. Returns count sent."""
        if not self._buffer_path.exists():
            return 0

        real_path = self._verify_wal_path()
        if real_path is None:
            return 0

        raw_events = []
        with open(real_path) as f:
            for line in f:
                line = line.strip()
                if not line:
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

        # Read contract manifest for coverage reporting
        payload: dict[str, object] = {"events": console_events}
        manifest_path = self._buffer_path.parent / "manifest.json"
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
                agent_id = getattr(console_config, "agent_id", "") or ""
                if not agent_id and raw_events:
                    agent_id = raw_events[0].get("agent_id", "")
                payload["agent_manifest"] = {
                    "agent_id": agent_id,
                    "policy_version": manifest.get("policy_version", ""),
                    "contracts": manifest.get("contracts", []),
                }
            except (json.JSONDecodeError, OSError):
                pass

        import httpx

        client = httpx.Client(
            base_url=url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30,
        )
        try:
            response = client.post(
                "/api/v1/events",
                json=payload,
            )
            response.raise_for_status()
        except Exception as exc:
            print(f"Gate audit flush error: {exc}", file=sys.stderr)
            return 0
        finally:
            client.close()

        # Truncate WAL on success (use verified real_path, not potentially-symlinked path)
        try:
            with open(real_path, "w") as f:
                f.truncate(0)
        except OSError:
            pass

        return len(console_events)
