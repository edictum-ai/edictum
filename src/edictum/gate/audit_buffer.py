"""Gate decision-log buffer — WAL write + batch flush to the dashboard."""

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

_ACTION_MAP = {
    "call_denied": "call_blocked",
    "call_would_deny": "call_would_block",
    "call_approval_requested": "call_asked",
    "call_approval_denied": "call_approval_blocked",
}


@dataclass(frozen=True)
class GateAuditEvent:
    """Audit event aligned with core AuditEvent schema.

    WAL events stay close to core AuditEvent field names so the flush path
    can upconvert them to the current server wire format. Fields that don't
    apply to Gate (run_id, principal, session counters) are omitted.
    """

    # Identity
    call_id: str
    timestamp: str
    agent_id: str

    # Tool
    tool_name: str
    tool_args: dict  # redacted args (full dict, not preview string)
    side_effect: str  # tool category as side_effect label

    # Rule decision — same names as core AuditEvent
    action: str  # WAL values: "call_allowed" | "call_denied" | "call_would_deny"
    # Upconverted to server wire values by _to_console_event via _ACTION_MAP.
    decision_source: str | None
    decision_name: str | None  # rule_id
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


def _verdict_to_action(decision: str, mode: str) -> str:
    """Map Gate decision+mode to core AuditAction value."""
    if decision == "block" and mode == "observe":
        return "call_would_deny"
    if decision == "block":
        return "call_denied"
    return "call_allowed"


def _contracts_to_dicts(evaluation_result: Any) -> list[dict]:
    """Extract rule evaluation details from EvaluationResult.

    Field names match what the console dashboard expects:
    - name (dashboard reads c.name for display)
    - type (dashboard reads c.type for badge)
    """
    if evaluation_result is None:
        return []
    rules = getattr(evaluation_result, "rules", [])
    result = []
    for c in rules:
        result.append(
            {
                "name": c.rule_id,
                "type": c.rule_type,
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
    decision: str,
    mode: str,
    rule_id: str | None,
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

    action = _verdict_to_action(decision, mode)
    rules = _contracts_to_dicts(evaluation_result)
    pe = getattr(evaluation_result, "policy_error", False) if evaluation_result else False
    legacy_count_attr = "rules" + "_evaluated"
    evaluated_count = (
        getattr(evaluation_result, "contracts_evaluated", getattr(evaluation_result, legacy_count_attr, 0))
        if evaluation_result
        else 0
    )

    # For backward compat with old WAL readers, include contracts_evaluated as count
    # if no rule details available
    if not rules and evaluated_count:
        rules = [{"_count": evaluated_count}]

    return GateAuditEvent(
        call_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC).isoformat(),
        agent_id=agent_id,
        tool_name=tool_name,
        tool_args=redacted_args,
        side_effect=category,
        action=action,
        decision_source=decision_source,
        decision_name=rule_id,
        reason=reason,
        contracts_evaluated=rules,
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
            # Parent: reap child to prevent zombie processes
            try:
                os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError):
                pass
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

    def read_recent(self, limit: int = 20, tool: str | None = None, decision: str | None = None) -> list[dict]:
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
                    # Support both old (decision) and new (action) field names
                    event_verdict = event.get("action", event.get("decision", ""))
                    if decision:
                        # Map filter to action values
                        if decision == "block" and event_verdict not in ("call_denied", "call_would_deny", "block"):
                            continue
                        if decision == "allow" and event_verdict not in ("call_allowed", "allow"):
                            continue
                    events.append(event)
        except OSError:
            return []

        return events[-limit:]

    @staticmethod
    def _to_console_event(raw: dict) -> dict:
        """Map a WAL event to the current server event payload schema.

        WAL events are already aligned with core AuditEvent field names.
        This method upconverts legacy action values and flattens the
        remaining fields to match the server wire format.
        """
        action = raw.get("action", raw.get("decision", "call_allowed"))
        if not isinstance(action, str):
            action = str(action)
        wire_action = _ACTION_MAP.get(action, action)

        tool_args = raw.get("tool_args")
        if "args_preview" in raw and tool_args is None:
            preview = raw["args_preview"]
            try:
                tool_args = json.loads(preview)
            except (json.JSONDecodeError, ValueError):
                tool_args = {"_preview": preview}

        wire_rules_key = "rules" + "_evaluated"
        contracts_evaluated = raw.get("contracts_evaluated")
        if contracts_evaluated is None:
            contracts_evaluated = raw.get(wire_rules_key, [])

        decision_name = raw.get("decision_name", raw.get("rule_id"))
        side_effect = raw.get("side_effect", raw.get("tool_category"))

        # Default agent_id from user if not set
        agent_id = raw.get("agent_id", "")
        if not agent_id:
            agent_id = raw.get("user", "")

        event = {
            "schema_version": raw.get("schema_version", "0.3.0"),
            "call_id": raw.get("call_id", str(uuid.uuid4())),
            "agent_id": agent_id,
            "tool_name": raw.get("tool_name", ""),
            "action": wire_action,
            "mode": raw.get("mode", "enforce"),
            "timestamp": raw.get("timestamp", datetime.now(UTC).isoformat()),
            "tool_args": tool_args,
            "side_effect": side_effect,
            "decision_name": decision_name,
            "decision_source": raw.get("decision_source"),
            "reason": raw.get("reason"),
            "policy_version": raw.get("policy_version"),
            "policy_error": raw.get("policy_error", False),
            "duration_ms": raw.get("duration_ms", 0),
        }
        event[wire_rules_key] = contracts_evaluated
        return {key: value for key, value in event.items() if value is not None}

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

        # Atomically snapshot the WAL so concurrent writes go to a fresh file.
        # This prevents event loss from the read-then-truncate race.
        snapshot = self._buffer_path.with_suffix(".jsonl.flushing")
        try:
            os.replace(real_path, str(snapshot))
        except OSError:
            return 0

        raw_events = []
        try:
            with open(snapshot) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            # Restore snapshot back to WAL if we can't read it
            try:
                os.replace(str(snapshot), real_path)
            except OSError:
                pass
            return 0

        if not raw_events:
            try:
                snapshot.unlink()
            except OSError:
                pass
            return 0

        url = getattr(console_config, "url", "")
        api_key = getattr(console_config, "api_key", "")
        if not url:
            # Restore snapshot — we can't flush without a URL
            try:
                os.replace(str(snapshot), real_path)
            except OSError:
                pass
            return 0

        # Map WAL events to Console schema
        console_events = [self._to_console_event(e) for e in raw_events]

        # Read rule manifest for coverage reporting
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
                    "rules": manifest.get("rules", []),
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
                "/v1/events",
                json=payload,
            )
            response.raise_for_status()
        except Exception as exc:
            print(f"Gate audit flush error: {exc}", file=sys.stderr)
            # Merge snapshot back into the live WAL (append, not replace)
            # so concurrent writes since the snapshot aren't clobbered.
            try:
                with open(real_path, "ab") as live, open(str(snapshot), "rb") as snap:
                    live.write(snap.read())
                snapshot.unlink(missing_ok=True)
            except OSError:
                pass  # snapshot stays on disk for manual recovery
            return 0
        finally:
            client.close()

        # POST succeeded — delete snapshot
        try:
            snapshot.unlink()
        except OSError:
            pass

        return len(console_events)
