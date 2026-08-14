"""Adversarial behavior tests for sandbox path visibility.

The path sandbox enforces only what its extractor can see. These tests pin
the extractor to the shapes an attacker (the model emitting tool args)
controls: nested args, list args, relative traversals, variable/tilde
expansion, and commands under non-standard arg keys.
"""

from __future__ import annotations

import pytest

from edictum import Edictum
from edictum._exceptions import EdictumDenied
from edictum.storage import MemoryBackend

_RULES = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: sandbox-visibility
defaults:
  mode: enforce
rules:
  - id: zone-sandbox
    type: sandbox
    tools: ["Bash", "read_file", "custom_tool"]
    within:
      - /tmp/safe-zone
    message: path outside sandbox
"""

# (label, tool, args) — every case references /etc/passwd outside the zone
_VISIBILITY_BYPASSES = [
    ("nested-arg", "read_file", {"file": {"path": "/etc/passwd"}}),
    ("list-arg", "read_file", {"paths": ["/etc/passwd", "/tmp/ok"]}),
    ("relative-traversal", "Bash", {"command": "cat ../../etc/passwd"}),
    ("home-expansion", "Bash", {"command": "cat $HOME/.ssh/id_rsa"}),
    ("tilde-expansion", "Bash", {"command": "cat ~/.ssh/id_rsa"}),
    ("command-under-cmd-key", "custom_tool", {"cmd": "cat /etc/passwd"}),
    ("deep-nested", "read_file", {"a": {"b": {"c": {"path": "/etc/passwd"}}}}),
]


class TestSandboxVisibility:
    @pytest.mark.security
    @pytest.mark.parametrize(
        "label,tool,args",
        _VISIBILITY_BYPASSES,
        ids=[case[0] for case in _VISIBILITY_BYPASSES],
    )
    async def test_bypass_variant_is_blocked(self, label, tool, args):
        guard = Edictum.from_yaml_string(_RULES, backend=MemoryBackend())
        with pytest.raises(EdictumDenied, match="path outside sandbox"):
            await guard.run(tool, args, lambda **kw: "ran")

    @pytest.mark.asyncio
    async def test_control_absolute_path_still_blocked(self):
        guard = Edictum.from_yaml_string(_RULES, backend=MemoryBackend())
        with pytest.raises(EdictumDenied):
            await guard.run("Bash", {"command": "cat /etc/passwd"}, lambda **kw: "ran")

    @pytest.mark.asyncio
    async def test_within_zone_still_executes(self):
        guard = Edictum.from_yaml_string(_RULES, backend=MemoryBackend())
        result = await guard.run("Bash", {"command": "cat /tmp/safe-zone/file"}, lambda **kw: "ok")
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_url_token_is_not_a_path(self):
        """URLs in commands belong to domain checks, not path checks."""
        rules = _RULES.replace(
            "    within:\n      - /tmp/safe-zone\n",
            '    within:\n      - /tmp/safe-zone\n    allows:\n      domains: ["example.com"]\n',
        )
        guard = Edictum.from_yaml_string(rules, backend=MemoryBackend())
        result = await guard.run("Bash", {"command": "curl https://example.com/x"}, lambda **kw: "ok")
        assert result == "ok"

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_walker_is_bounded(self):
        """Deep nesting beyond the cap must not raise; the cap is a bound, not a crash."""
        guard = Edictum.from_yaml_string(_RULES, backend=MemoryBackend())
        deep = current = {}
        for _ in range(50):
            current["n"] = {}
            current = current["n"]
        current["path"] = "/etc/passwd"
        # Beyond _MAX_PATH_DEPTH the value is not extracted; the call is
        # allowed because no visible path violates the zone.
        result = await guard.run("read_file", deep, lambda **kw: "ran")
        assert result == "ran"
