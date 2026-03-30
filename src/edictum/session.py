"""Session — atomic counters backed by StorageBackend."""

from __future__ import annotations

from edictum.envelope import _validate_tool_name
from edictum.storage import StorageBackend


def _validate_session_id(session_id: str) -> None:
    """Validate session_id: reject empty, control chars, colons, path separators.

    Colons are storage key delimiters (``s:{sid}:attempts``). Allowing them
    in session_id enables key collision attacks.
    """
    if not session_id:
        raise ValueError(f"Invalid session_id: {session_id!r}")
    for ch in session_id:
        if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in ("/", "\\", ":"):
            raise ValueError(f"Invalid session_id: {session_id!r}")


def _validate_key_component(name: str) -> None:
    """Validate a session-scoped key component.

    Session value names intentionally allow ``:`` so namespaces like
    ``workflow:name:state`` can map to one logical value inside the session.
    """
    if not name or len(name) > 10_000:
        raise ValueError(f"Invalid session value name: {name!r}")
    for ch in name:
        if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in ("/", "\\"):
            raise ValueError(f"Invalid session value name: {name!r}")


class Session:
    """Tracks execution state via atomic counters in StorageBackend.

    All methods are ASYNC because StorageBackend is async.

    Counter semantics:
    - attempt_count: every PreToolUse, including denied (pre-execution)
    - execution_count: every PostToolUse (tool actually ran)
    - per_tool_exec_count:{tool}: per-tool execution count
    - consecutive_failures: resets on success, increments on failure
    """

    def __init__(self, session_id: str, backend: StorageBackend):
        _validate_session_id(session_id)
        self._sid = session_id
        self._backend = backend

    @property
    def session_id(self) -> str:
        return self._sid

    def _key(self, suffix: str) -> str:
        return f"s:{self._sid}:{suffix}"

    async def increment_attempts(self) -> int:
        """Increment attempt counter. Called in PreToolUse (before governance)."""
        return int(await self._backend.increment(self._key("attempts")))

    async def attempt_count(self) -> int:
        return int(await self._backend.get(self._key("attempts")) or 0)

    async def record_execution(self, tool_name: str, success: bool) -> None:
        """Record a tool execution. Called in PostToolUse."""
        _validate_tool_name(tool_name)
        await self._backend.increment(self._key("execs"))
        await self._backend.increment(self._key(f"tool:{tool_name}"))

        if success:
            await self._backend.delete(self._key("consec_fail"))
        else:
            await self._backend.increment(self._key("consec_fail"))

    async def execution_count(self) -> int:
        return int(await self._backend.get(self._key("execs")) or 0)

    async def tool_execution_count(self, tool: str) -> int:
        _validate_tool_name(tool)
        return int(await self._backend.get(self._key(f"tool:{tool}")) or 0)

    async def consecutive_failures(self) -> int:
        return int(await self._backend.get(self._key("consec_fail")) or 0)

    async def get_value(self, name: str) -> str | None:
        """Return a namespaced session-scoped value."""
        _validate_key_component(name)
        return await self._backend.get(self._key(name))

    async def set_value(self, name: str, value: str) -> None:
        """Store a namespaced session-scoped value."""
        _validate_key_component(name)
        await self._backend.set(self._key(name), value)

    async def delete_value(self, name: str) -> None:
        """Delete a namespaced session-scoped value."""
        _validate_key_component(name)
        await self._backend.delete(self._key(name))

    async def batch_get_counters(
        self,
        *,
        include_tool: str | None = None,
    ) -> dict[str, int]:
        """Pre-fetch multiple session counters in a single backend call.

        Returns a dict with keys: "attempts", "execs", and optionally
        "tool:{name}" if include_tool is provided.

        Uses batch_get() on the backend when available (single HTTP round
        trip for ServerBackend). Falls back to individual get() calls for
        backends without batch_get support.
        """
        keys = [
            self._key("attempts"),
            self._key("execs"),
        ]
        key_labels = ["attempts", "execs"]

        if include_tool is not None:
            _validate_tool_name(include_tool)
            keys.append(self._key(f"tool:{include_tool}"))
            key_labels.append(f"tool:{include_tool}")

        if hasattr(self._backend, "batch_get"):
            raw = await self._backend.batch_get(keys)
        else:
            raw = {}
            for key in keys:
                raw[key] = await self._backend.get(key)

        result: dict[str, int] = {}
        for key, label in zip(keys, key_labels):
            result[label] = int(raw.get(key) or 0)
        return result
