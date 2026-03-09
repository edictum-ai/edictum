"""Contract cache — JSON-based hash + mtime cache to avoid re-reading YAML."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

DEFAULT_CACHE_PATH = Path.home() / ".edictum" / "cache" / "contracts.json"


class ContractCache:
    """JSON-based cache storing SHA256 hash + mtime per YAML source file.

    No pickle. No deserialization risk. Cache file is advisory — if
    corrupted, silently rebuild.
    """

    def __init__(self, cache_path: Path | None = None, ttl_seconds: int = 300) -> None:
        self._path = cache_path or DEFAULT_CACHE_PATH
        self._ttl = ttl_seconds
        self._entries: dict[str, dict] = {}
        self._loaded_at: float = 0.0
        self._load()

    def _load(self) -> None:
        """Load cache from disk, silently recovering from corruption."""
        if not self._path.exists():
            self._entries = {}
            return
        try:
            raw = self._path.read_text()
            data = json.loads(raw)
            if isinstance(data, dict):
                self._entries = data
                self._loaded_at = time.monotonic()
            else:
                self._entries = {}
        except (json.JSONDecodeError, OSError):
            self._entries = {}

    def is_valid(self, path: str) -> bool:
        """Check if cached entry matches the file on disk (hash + mtime)."""
        entry = self._entries.get(path)
        if entry is None:
            return False

        # Within TTL, skip mtime check
        if self._ttl > 0 and (time.monotonic() - self._loaded_at) < self._ttl:
            file_path = Path(path)
            if not file_path.exists():
                return False
            try:
                stat = file_path.stat()
                if stat.st_mtime == entry.get("mtime"):
                    return True
            except OSError:
                return False

        # Full check: recompute hash
        file_path = Path(path)
        if not file_path.exists():
            return False
        try:
            stat = file_path.stat()
            if stat.st_mtime != entry.get("mtime"):
                return False
            file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            return file_hash == entry.get("sha256")
        except OSError:
            return False

    def get_all_valid(self, paths: list[str]) -> bool:
        """Check all contract paths at once."""
        return all(self.is_valid(p) for p in paths)

    def update(self, path: str) -> None:
        """Recompute hash + mtime for a file and update the cache."""
        file_path = Path(path)
        if not file_path.exists():
            return
        try:
            stat = file_path.stat()
            file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            self._entries[path] = {
                "path": path,
                "sha256": file_hash,
                "mtime": stat.st_mtime,
            }
            self._write()
        except OSError:
            pass

    def _write(self) -> None:
        """Atomic write: tmp file + os.replace()."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(self._entries, indent=2))
            os.replace(str(tmp), str(self._path))
            self._loaded_at = time.monotonic()
        except OSError:
            # Best effort — cache is advisory
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
