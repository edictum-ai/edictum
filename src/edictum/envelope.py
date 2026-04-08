"""Tool Invocation Envelope — immutable snapshot of a tool call."""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from edictum.types import ToolConfig


class SideEffect(StrEnum):
    """Classification of tool side effects.

    Determines postcondition behavior and retry safety.

    DEFAULTS:
    - Unregistered tools -> IRREVERSIBLE (conservative)
    - Bash -> IRREVERSIBLE unless strict allowlist match
    - Classification errors always err toward MORE restrictive
    """

    PURE = "pure"
    READ = "read"
    WRITE = "write"
    IRREVERSIBLE = "irreversible"


@dataclass(frozen=True)
class Principal:
    """Identity context for decision-log attribution.

    NOTE: ``claims`` is a mutable dict held inside a frozen dataclass.
    The *reference* is immutable (you cannot reassign ``principal.claims``),
    but the dict contents can still be mutated.  We accept this tradeoff to
    keep Principal frozen for hashability and tool_call immutability.  Callers
    should treat claims as read-only after construction.
    """

    user_id: str | None = None
    service_id: str | None = None
    org_id: str | None = None
    role: str | None = None
    ticket_ref: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)


def _validate_tool_name(tool_name: str) -> None:
    """Validate tool_name: reject empty, control chars, path separators.

    Raises ValueError for:
    - Empty string
    - Any ASCII control character (ord < 0x20 or ord == 0x7f)
    - Forward slash ``/``
    - Backslash ``\\``
    """
    if not tool_name:
        raise ValueError(f"Invalid tool_name: {tool_name!r}")
    for ch in tool_name:
        if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in ("/", "\\"):
            raise ValueError(f"Invalid tool_name: {tool_name!r}")


@dataclass(frozen=True)
class ToolCall:
    """Immutable snapshot of a tool invocation.

    Prefer create_envelope() factory for deep-copy guarantees.
    Direct construction validates tool_name but does NOT deep-copy args.
    """

    # Identity
    tool_name: str
    args: dict[str, Any] = field(default_factory=dict)
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_id: str = ""
    call_index: int = 0

    parent_call_id: str | None = None

    # Classification
    side_effect: SideEffect = SideEffect.IRREVERSIBLE
    idempotent: bool = False

    # Context
    environment: str = "production"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    caller: str = ""
    tool_use_id: str | None = None

    # Principal
    principal: Principal | None = None

    # Extracted convenience fields
    bash_command: str | None = None
    file_path: str | None = None

    # Extensible
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_tool_name(self.tool_name)


class ToolRegistry:
    """Maps tool names to rule-engine properties.

    Unregistered tools default to IRREVERSIBLE.
    """

    def __init__(self):
        self._tools: dict[str, ToolConfig] = {}

    def register(
        self,
        name: str,
        side_effect: SideEffect = SideEffect.WRITE,
        idempotent: bool = False,
    ) -> None:
        self._tools[name] = ToolConfig(name, side_effect, idempotent)

    def classify(self, tool_name: str, args: dict) -> tuple[SideEffect, bool]:
        if tool_name in self._tools:
            cfg = self._tools[tool_name]
            return cfg.side_effect, cfg.idempotent
        return SideEffect.IRREVERSIBLE, False


class BashClassifier:
    """Classify bash commands by side-action level.

    Default is IRREVERSIBLE. Only downgraded to READ via strict
    allowlist AND absence of shell operators.

    This is a heuristic, not a security boundary.
    """

    READ_ALLOWLIST = [
        "ls",
        "cat",
        "head",
        "tail",
        "wc",
        "find",
        "grep",
        "rg",
        "git status",
        "git log",
        "git diff",
        "git show",
        "git branch",
        "git remote",
        "git tag",
        "echo",
        "pwd",
        "whoami",
        "date",
        "which",
        "file",
        "stat",
        "du",
        "df",
        "tree",
        "less",
        "more",
    ]

    SHELL_OPERATORS = ["\n", "\r", "<(", "<<", "$", "${", ">", ">>", "|", ";", "&&", "||", "$(", "`", "#{"]

    @classmethod
    def classify(cls, command: str) -> SideEffect:
        stripped = command.strip()
        if not stripped:
            return SideEffect.READ

        for op in cls.SHELL_OPERATORS:
            if op in stripped:
                return SideEffect.IRREVERSIBLE

        for allowed in cls.READ_ALLOWLIST:
            if stripped == allowed or stripped.startswith(allowed + " "):
                return SideEffect.READ

        return SideEffect.IRREVERSIBLE


def create_envelope(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    run_id: str = "",
    call_index: int = 0,
    **kwargs,
) -> ToolCall:
    """Factory that enforces immutability guarantees.

    Prefer this factory over direct construction — it deep-copies args
    and metadata to ensure the tool_call is a true immutable snapshot.
    Direct construction is permitted but skips the deep-copy.
    """
    _validate_tool_name(tool_name)

    # Deep-copy for immutability
    try:
        safe_args = json.loads(json.dumps(tool_input))
    except (TypeError, ValueError):
        safe_args = copy.deepcopy(tool_input)

    safe_metadata = {}
    if "metadata" in kwargs:
        try:
            safe_metadata = json.loads(json.dumps(kwargs.pop("metadata")))
        except (TypeError, ValueError):
            safe_metadata = copy.deepcopy(kwargs.pop("metadata"))

    # Deep-copy Principal to protect claims dict
    if "principal" in kwargs and kwargs["principal"] is not None:
        p = kwargs.pop("principal")
        kwargs["principal"] = Principal(
            user_id=p.user_id,
            service_id=p.service_id,
            org_id=p.org_id,
            role=p.role,
            ticket_ref=p.ticket_ref,
            claims=copy.deepcopy(p.claims) if p.claims else {},
        )

    # Classification
    registry = kwargs.pop("registry", None)
    side_effect = SideEffect.IRREVERSIBLE
    idempotent = False
    bash_command = None
    file_path = None

    if registry:
        side_effect, idempotent = registry.classify(tool_name, safe_args)

    # Extract convenience fields (handle both snake_case and camelCase keys)
    if tool_name == "Bash":
        bash_command = safe_args.get("command", "")
        # BashClassifier always wins over registry for Bash tools
        side_effect = BashClassifier.classify(bash_command)
    elif tool_name in ("Read", "Glob", "Grep"):
        file_path = safe_args.get("file_path") or safe_args.get("filePath") or safe_args.get("path")
    elif tool_name in ("Write", "Edit"):
        file_path = safe_args.get("file_path") or safe_args.get("filePath") or safe_args.get("path")

    return ToolCall(
        tool_name=tool_name,
        args=safe_args,
        run_id=run_id,
        call_index=call_index,
        side_effect=side_effect,
        idempotent=idempotent,
        bash_command=bash_command,
        file_path=file_path,
        metadata=safe_metadata,
        **kwargs,
    )
