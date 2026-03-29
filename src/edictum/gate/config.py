"""Gate configuration — load gate.yaml, expose GateConfig dataclass."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_GATE_DIR = Path.home() / ".edictum"
DEFAULT_CONFIG_PATH = DEFAULT_GATE_DIR / "gate.yaml"


@dataclass(frozen=True)
class ConsoleConfig:
    url: str = ""
    api_key: str = ""
    agent_id: str = ""


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool = True
    buffer_path: str = str(DEFAULT_GATE_DIR / "audit" / "wal.jsonl")
    flush_interval_seconds: int = 10
    max_buffer_size_mb: int = 50


@dataclass(frozen=True)
class RedactionConfig:
    enabled: bool = True
    patterns: tuple[str, ...] = (
        r"sk_live_\w+",
        r"AKIA\w{16}",
        r"ghp_\w{36}",
        r"-----BEGIN .* PRIVATE KEY-----",
    )
    replacement: str = "<REDACTED>"


@dataclass(frozen=True)
class CacheConfig:
    hash_mtime: bool = True
    ttl_seconds: int = 300


def _default_scope_allowlist() -> tuple[str, ...]:
    """Default paths that bypass scope enforcement.

    These are assistant infrastructure directories that coding assistants
    must be able to write to for normal operation (memory, settings, etc.).
    """
    home = str(Path.home())
    return (os.path.join(home, ".claude") + os.sep,)


@dataclass(frozen=True)
class GateConfig:
    rules: tuple[str, ...] = (str(DEFAULT_GATE_DIR / "rules" / "base.yaml"),)
    console: ConsoleConfig | None = None
    audit: AuditConfig = field(default_factory=AuditConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    scope_allowlist: tuple[str, ...] = field(default_factory=_default_scope_allowlist)
    fail_open: bool = False


def _resolve_agent_id(raw: str) -> str:
    """Resolve ${hostname} and ${user} placeholders."""
    result = raw
    if "${hostname}" in result:
        result = result.replace("${hostname}", socket.gethostname())
    if "${user}" in result:
        try:
            result = result.replace("${user}", os.getlogin())
        except OSError:
            result = result.replace("${user}", os.getenv("USER", "unknown"))
    return result


def load_gate_config(path: Path | None = None) -> GateConfig:
    """Load gate configuration from a YAML file.

    Returns defaults if the file does not exist.
    """
    config_path = path or DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return GateConfig()

    try:
        import yaml
    except ImportError as exc:
        raise ImportError("Gate config requires pyyaml. Install with: pip install edictum[gate]") from exc

    raw = yaml.safe_load(config_path.read_text())
    if not isinstance(raw, dict):
        return GateConfig()

    return _parse_config(raw)


def _parse_config(raw: dict[str, Any]) -> GateConfig:
    """Parse a raw config dict into a GateConfig."""
    # Contracts
    contracts_raw = raw.get("rules", [])
    if not contracts_raw:
        contracts_raw = [str(DEFAULT_GATE_DIR / "rules" / "base.yaml")]
    rules = tuple(str(c) for c in contracts_raw)

    # Console
    console = None
    console_raw = raw.get("console")
    if console_raw and isinstance(console_raw, dict):
        agent_id = _resolve_agent_id(console_raw.get("agent_id", ""))
        console = ConsoleConfig(
            url=console_raw.get("url", ""),
            api_key=console_raw.get("api_key", ""),
            agent_id=agent_id,
        )

    # Audit
    audit_raw = raw.get("audit", {})
    audit = AuditConfig(
        enabled=audit_raw.get("enabled", True),
        buffer_path=audit_raw.get("buffer_path", str(DEFAULT_GATE_DIR / "audit" / "wal.jsonl")),
        flush_interval_seconds=audit_raw.get("flush_interval_seconds", 10),
        max_buffer_size_mb=audit_raw.get("max_buffer_size_mb", 50),
    )

    # Redaction
    redaction_raw = raw.get("redaction", {})
    default_patterns = RedactionConfig().patterns
    patterns_list = redaction_raw.get("patterns", list(default_patterns))
    redaction = RedactionConfig(
        enabled=redaction_raw.get("enabled", True),
        patterns=tuple(patterns_list),
        replacement=redaction_raw.get("replacement", "<REDACTED>"),
    )

    # Cache
    cache_raw = raw.get("cache", {})
    cache = CacheConfig(
        hash_mtime=cache_raw.get("hash_mtime", True),
        ttl_seconds=cache_raw.get("ttl_seconds", 300),
    )

    # Scope allowlist
    scope_raw = raw.get("scope_allowlist")
    if scope_raw and isinstance(scope_raw, list):
        # Expand ~ in user-provided paths and ensure trailing sep
        expanded = []
        for p in scope_raw:
            resolved = os.path.expanduser(str(p))
            if not resolved.endswith(os.sep):
                resolved += os.sep
            expanded.append(resolved)
        scope_allowlist = tuple(expanded)
    else:
        scope_allowlist = _default_scope_allowlist()

    return GateConfig(
        rules=rules,
        console=console,
        audit=audit,
        redaction=redaction,
        cache=cache,
        scope_allowlist=scope_allowlist,
        fail_open=raw.get("fail_open", False),
    )
