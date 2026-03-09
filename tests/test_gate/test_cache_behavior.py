"""Behavior tests for ContractCache."""

from __future__ import annotations

import json
from pathlib import Path

from edictum.gate.cache import ContractCache


class TestContractCache:
    def test_cache_miss_on_first_call(self, tmp_path: Path) -> None:
        cache = ContractCache(cache_path=tmp_path / "cache.json")
        assert not cache.is_valid("/nonexistent/file.yaml")

    def test_cache_hit_after_update(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "contracts.yaml"
        yaml_file.write_text("test content")
        cache = ContractCache(cache_path=tmp_path / "cache.json")
        cache.update(str(yaml_file))
        assert cache.is_valid(str(yaml_file))

    def test_cache_invalidation_on_content_change(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "contracts.yaml"
        yaml_file.write_text("original content")
        cache = ContractCache(cache_path=tmp_path / "cache.json")
        cache.update(str(yaml_file))
        assert cache.is_valid(str(yaml_file))

        # Change content
        yaml_file.write_text("changed content")
        # Need a new cache instance since mtime changed
        cache2 = ContractCache(cache_path=tmp_path / "cache.json")
        assert not cache2.is_valid(str(yaml_file))

    def test_cache_corruption_recovery(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "cache.json"
        cache_file.write_text("not valid json {{{{")
        cache = ContractCache(cache_path=cache_file)
        # Should not raise — silently rebuild
        assert not cache.is_valid("/some/path")

    def test_atomic_write(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "contracts.yaml"
        yaml_file.write_text("content")
        cache = ContractCache(cache_path=tmp_path / "cache.json")
        cache.update(str(yaml_file))

        # Cache file should exist and be valid JSON
        cache_file = tmp_path / "cache.json"
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert isinstance(data, dict)

    def test_get_all_valid(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.yaml"
        f2 = tmp_path / "b.yaml"
        f1.write_text("a")
        f2.write_text("b")
        cache = ContractCache(cache_path=tmp_path / "cache.json")
        cache.update(str(f1))
        cache.update(str(f2))
        assert cache.get_all_valid([str(f1), str(f2)])

    def test_get_all_valid_one_missing(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.yaml"
        f1.write_text("a")
        cache = ContractCache(cache_path=tmp_path / "cache.json")
        cache.update(str(f1))
        assert not cache.get_all_valid([str(f1), "/nonexistent.yaml"])

    def test_cache_creates_parent_dirs(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "contracts.yaml"
        yaml_file.write_text("content")
        cache_path = tmp_path / "deep" / "nested" / "cache.json"
        cache = ContractCache(cache_path=cache_path)
        cache.update(str(yaml_file))
        assert cache_path.exists()
