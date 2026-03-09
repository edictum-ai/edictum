"""Behavior tests for GateConfig loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from edictum.gate.config import (
    GateConfig,
    _resolve_agent_id,
    load_gate_config,
)


class TestLoadGateConfig:
    def test_load_default_config(self, tmp_path: Path) -> None:
        """When no gate.yaml exists, returns defaults."""
        config = load_gate_config(tmp_path / "nonexistent.yaml")
        assert isinstance(config, GateConfig)
        assert config.fail_open is False

    def test_load_custom_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "gate.yaml"
        config_path.write_text("contracts:\n" "  - /tmp/test.yaml\n" "fail_open: true\n")
        config = load_gate_config(config_path)
        assert config.contracts == ("/tmp/test.yaml",)
        assert config.fail_open is True

    def test_agent_id_resolution(self) -> None:
        result = _resolve_agent_id("${hostname}-${user}")
        assert "${hostname}" not in result
        assert "${user}" not in result
        assert "-" in result

    def test_contracts_path_default(self) -> None:
        config = GateConfig()
        assert len(config.contracts) == 1

    def test_fail_open_default_false(self) -> None:
        config = GateConfig()
        assert config.fail_open is False

    def test_frozen_config(self) -> None:
        config = GateConfig()
        with pytest.raises(AttributeError):
            config.fail_open = True  # type: ignore[misc]

    def test_console_config_optional(self, tmp_path: Path) -> None:
        config_path = tmp_path / "gate.yaml"
        config_path.write_text("contracts:\n  - /tmp/test.yaml\n")
        config = load_gate_config(config_path)
        assert config.console is None

    def test_console_config_present(self, tmp_path: Path) -> None:
        config_path = tmp_path / "gate.yaml"
        config_path.write_text(
            "contracts:\n  - /tmp/test.yaml\n" "console:\n" "  url: https://example.com\n" "  api_key: test-key\n"
        )
        config = load_gate_config(config_path)
        assert config.console is not None
        assert config.console.url == "https://example.com"
        assert config.console.api_key == "test-key"

    def test_redaction_defaults(self) -> None:
        config = GateConfig()
        assert config.redaction.enabled is True
        assert len(config.redaction.patterns) > 0

    def test_cache_defaults(self) -> None:
        config = GateConfig()
        assert config.cache.ttl_seconds == 300
        assert config.cache.hash_mtime is True
