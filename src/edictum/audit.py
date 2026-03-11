"""Structured Event Log with Redaction."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuditSink(Protocol):
    """Protocol for audit event consumers."""

    async def emit(self, event: Any) -> None: ...


class AuditAction(StrEnum):
    CALL_DENIED = "call_denied"
    CALL_WOULD_DENY = "call_would_deny"
    CALL_ALLOWED = "call_allowed"
    CALL_EXECUTED = "call_executed"
    CALL_FAILED = "call_failed"
    POSTCONDITION_WARNING = "postcondition_warning"
    CALL_APPROVAL_REQUESTED = "call_approval_requested"
    CALL_APPROVAL_GRANTED = "call_approval_granted"
    CALL_APPROVAL_DENIED = "call_approval_denied"
    CALL_APPROVAL_TIMEOUT = "call_approval_timeout"


@dataclass
class AuditEvent:
    schema_version: str = "0.3.0"

    # Identity
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    run_id: str = ""
    call_id: str = ""
    call_index: int = 0
    parent_call_id: str | None = None

    # Tool
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    side_effect: str = ""
    environment: str = ""

    # Principal
    principal: dict | None = None

    # Governance decision
    action: AuditAction = AuditAction.CALL_DENIED
    decision_source: str | None = None
    decision_name: str | None = None
    reason: str | None = None
    hooks_evaluated: list[dict] = field(default_factory=list)
    contracts_evaluated: list[dict] = field(default_factory=list)

    # Execution (post only)
    tool_success: bool | None = None
    postconditions_passed: bool | None = None
    duration_ms: int = 0
    error: str | None = None
    result_summary: str | None = None

    # Counters
    session_attempt_count: int = 0
    session_execution_count: int = 0

    # Mode
    mode: str = "enforce"

    # Policy tracking
    policy_version: str | None = None
    policy_error: bool = False


class RedactionPolicy:
    """Redact sensitive data from audit events.

    Recurses into dicts AND lists. Normalizes keys to lowercase.
    Caps total payload size. Detects common secret patterns in values.
    """

    DEFAULT_SENSITIVE_KEYS: set[str] = {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "auth",
        "credentials",
        "private_key",
        "privatekey",
        "access_token",
        "refresh_token",
        "client_secret",
        "connection_string",
        "database_url",
        "db_password",
        "ssh_key",
        "passphrase",
    }

    BASH_REDACTION_PATTERNS: list[tuple[str, str]] = [
        (r"(export\s+\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*=)\S+", r"\1[REDACTED]"),
        (r"(-p\s*|--password[= ])\S+", r"\1[REDACTED]"),
        (r"(://\w+:)\S+(@)", r"\1[REDACTED]\2"),
    ]

    SECRET_VALUE_PATTERNS = [
        r"^(sk-[a-zA-Z0-9]{20,})",
        r"^(AKIA[A-Z0-9]{16})",
        r"^(eyJ[a-zA-Z0-9_-]{20,}\.)",
        r"^(ghp_[a-zA-Z0-9]{36})",
        r"^(xox[bpas]-[a-zA-Z0-9-]{10,})",
    ]

    MAX_PAYLOAD_SIZE = 32_768

    def __init__(
        self,
        sensitive_keys: set[str] | None = None,
        custom_patterns: list[tuple[str, str]] | None = None,
        detect_secret_values: bool = True,
    ):
        base_keys = self.DEFAULT_SENSITIVE_KEYS | sensitive_keys if sensitive_keys else self.DEFAULT_SENSITIVE_KEYS
        self._keys = {k.lower() for k in base_keys}
        self._patterns = (custom_patterns or []) + self.BASH_REDACTION_PATTERNS
        self._detect_values = detect_secret_values

    def redact_args(self, args: Any) -> Any:
        """Recursively redact sensitive data from tool arguments."""
        if isinstance(args, dict):
            return {
                key: "[REDACTED]" if self._is_sensitive_key(key) else self.redact_args(value)
                for key, value in args.items()
            }
        elif isinstance(args, list | tuple):
            return [self.redact_args(item) for item in args]
        elif isinstance(args, str):
            if self._detect_values and self._looks_like_secret(args):
                return "[REDACTED]"
            if len(args) > 1000:
                return args[:997] + "..."
            return args
        return args

    def _is_sensitive_key(self, key: str) -> bool:
        k = key.lower()
        return k in self._keys or any(s in k for s in ("token", "key", "secret", "password", "credential"))

    def _looks_like_secret(self, value: str) -> bool:
        for pattern in self.SECRET_VALUE_PATTERNS:
            if re.match(pattern, value):
                return True
        return False

    def redact_bash_command(self, command: str) -> str:
        result = command
        for pattern, replacement in self._patterns:
            result = re.sub(pattern, replacement, result)
        return result

    def redact_result(self, result: str, max_length: int = 500) -> str:
        redacted = result
        for pattern, replacement in self._patterns:
            redacted = re.sub(pattern, replacement, redacted)
        if len(redacted) > max_length:
            redacted = redacted[: max_length - 3] + "..."
        return redacted

    def cap_payload(self, data: dict) -> dict:
        """Cap total serialized size of audit payload."""
        serialized = json.dumps(data, default=str)
        if len(serialized) > self.MAX_PAYLOAD_SIZE:
            data["_truncated"] = True
            data.pop("result_summary", None)
            data.pop("tool_args", None)
            data["tool_args"] = {"_redacted": "payload exceeded 32KB"}
        return data


class CompositeSink:
    """Fan-out sink that emits to multiple sinks sequentially.

    Sinks are called in order. Every sink is attempted even if earlier sinks
    raise. If any sink fails, an ``ExceptionGroup`` is raised after all sinks
    have been tried, containing the individual errors.
    """

    def __init__(self, sinks: list[AuditSink]) -> None:
        if not sinks:
            raise ValueError("CompositeSink requires at least one sink")
        self._sinks: list[AuditSink] = list(sinks)

    @property
    def sinks(self) -> list[AuditSink]:
        """The wrapped sinks, in emission order."""
        return list(self._sinks)

    async def emit(self, event: Any) -> None:
        errors: list[Exception] = []
        for sink in self._sinks:
            try:
                await sink.emit(event)
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise ExceptionGroup("CompositeSink: one or more sinks failed", errors)


class StdoutAuditSink:
    """Emit audit events as JSON to stdout."""

    def __init__(self, redaction: RedactionPolicy | None = None):
        self._redaction = redaction or RedactionPolicy()

    async def emit(self, event: AuditEvent) -> None:
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        data = self._redaction.cap_payload(data)
        print(json.dumps(data, default=str))


class FileAuditSink:
    """Emit audit events as JSON lines to a file."""

    def __init__(self, path: str | Path, redaction: RedactionPolicy | None = None):
        self._path = Path(path)
        self._redaction = redaction or RedactionPolicy()

    async def emit(self, event: AuditEvent) -> None:
        data = asdict(event)
        data["timestamp"] = event.timestamp.isoformat()
        data["action"] = event.action.value
        data = self._redaction.cap_payload(data)
        line = json.dumps(data, default=str) + "\n"
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write_line, line)

    def _write_line(self, line: str) -> None:
        with open(self._path, "a") as f:
            f.write(line)


class MarkEvictedError(Exception):
    """Raised when a mark references events that have been evicted from the buffer."""


class CollectingAuditSink:
    """In-memory audit sink for programmatic inspection.

    Stores emitted events in a bounded ring buffer. Supports mark-based
    windowed queries so callers can ask "what happened since my last check?"

    Marks track absolute positions. If events referenced by a mark have
    been evicted due to buffer overflow, ``since_mark()`` raises
    ``MarkEvictedError`` so callers know they missed events rather than
    silently receiving a partial window.
    """

    def __init__(self, max_events: int = 50_000) -> None:
        if max_events < 1:
            raise ValueError(f"max_events must be >= 1, got {max_events}")
        self._events: list[AuditEvent] = []
        self._max_events = max_events
        self._total_emitted: int = 0  # monotonic counter, never resets

    async def emit(self, event: AuditEvent) -> None:
        self._events.append(event)
        self._total_emitted += 1
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events :]

    @property
    def events(self) -> list[AuditEvent]:
        """All collected events (defensive copy)."""
        return list(self._events)

    def mark(self) -> int:
        """Return a position marker at the current end of the event stream.

        The marker is an absolute offset into the total event stream,
        not an index into the internal buffer.
        """
        return self._total_emitted

    def since_mark(self, m: int) -> list[AuditEvent]:
        """Return events emitted after the given mark.

        Args:
            m: A marker previously returned by ``mark()``.

        Returns:
            Events emitted since the mark.

        Raises:
            MarkEvictedError: If events between the mark and the current
                buffer start have been evicted. Callers should handle
                this by resetting their mark via a fresh ``mark()`` call.
        """
        if m > self._total_emitted:
            raise ValueError(f"Mark {m} is ahead of total emitted ({self._total_emitted})")
        evicted_count = self._total_emitted - len(self._events)
        if m < evicted_count:
            raise MarkEvictedError(
                f"Mark {m} references evicted events "
                f"(buffer starts at {evicted_count}, "
                f"max_events={self._max_events})"
            )
        buffer_offset = m - evicted_count
        return list(self._events[buffer_offset:])

    def last(self) -> AuditEvent:
        """Return the most recent event. Raises IndexError if empty."""
        return self._events[-1]

    def filter(self, action: AuditAction) -> list[AuditEvent]:
        """Return all events matching the given action."""
        return [e for e in self._events if e.action == action]

    def clear(self) -> None:
        """Discard all collected events. Does not reset the total counter.

        Marks taken before clear will raise ``MarkEvictedError`` since the
        referenced events are gone. Marks taken after clear remain valid.
        """
        self._events.clear()
