"""Adversarial tests for input validation boundaries."""

from __future__ import annotations

import pytest

from edictum.envelope import create_envelope

pytestmark = pytest.mark.security


class TestToolNameValidation:
    def test_null_byte_rejected(self):
        with pytest.raises(ValueError):
            create_envelope("evil\x00tool", {})

    def test_newline_rejected(self):
        with pytest.raises(ValueError):
            create_envelope("evil\ntool", {})

    def test_path_separator_rejected(self):
        with pytest.raises(ValueError):
            create_envelope("../../etc/passwd", {})

    def test_empty_string_rejected(self):
        with pytest.raises(ValueError):
            create_envelope("", {})

    @pytest.mark.parametrize(
        "name",
        [
            "Bash",
            "Read",
            "file.read",
            "google-search",
            "my_tool",
            "ToolV2",
            "namespace:action",
        ],
    )
    def test_normal_names_accepted(self, name):
        envelope = create_envelope(name, {})
        assert envelope.tool_name == name
