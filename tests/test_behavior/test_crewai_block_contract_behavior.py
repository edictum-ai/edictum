"""Behavior tests for the CrewAI adapter's hook return-value contract.

CrewAI's executor (verified against crewai 1.10.1, tool_utils) blocks a tool
only when a before-hook returns exactly ``False``, catches every hook
exception and executes anyway, and replaces the tool result with a non-None
after-hook return. These tests pin the adapter to that contract.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum.adapters.crewai import CrewAIAdapter
from edictum.storage import MemoryBackend

crewai = pytest.importorskip("crewai")

_RULES = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: crewai-contract
defaults:
  mode: enforce
tools:
  reader:
    side_effect: read
rules:
  - id: block-rm
    type: pre
    tool: bash
    when:
      args.command: {contains: rm}
    then:
      action: block
      message: no rm
  - id: redact-secrets
    type: post
    tool: reader
    when:
      output.text: {matches: 'SECRET-[0-9]+'}
    then:
      action: redact
      message: secret in output
"""

_BLOCK_CTX = SimpleNamespace(tool_name="bash", tool_input={"command": "rm -rf /tmp/x"})
_READ_CTX = SimpleNamespace(tool_name="reader", tool_input={}, tool_result="payload SECRET-1")


@pytest.fixture()
def registered_adapter():
    from crewai.hooks.tool_hooks import (
        clear_before_tool_call_hooks,
        get_after_tool_call_hooks,
        get_before_tool_call_hooks,
    )

    guard = Edictum.from_yaml_string(_RULES, backend=MemoryBackend())
    adapter = CrewAIAdapter(guard, session_id="crewai-contract")
    adapter.register()
    before = get_before_tool_call_hooks()[-1]
    after = get_after_tool_call_hooks()[-1]
    yield adapter, before, after
    clear_before_tool_call_hooks()


class TestCrewAIBlockContract:
    @pytest.mark.security
    def test_registered_hook_returns_false_on_block(self, registered_adapter):
        """The value crewai's executor recognizes as a block is exactly False."""
        adapter, before, _ = registered_adapter
        result = before(_BLOCK_CTX)
        assert result is False

    @pytest.mark.security
    def test_registered_hook_returns_false_when_hook_raises(self, registered_adapter):
        """crewai catches hook exceptions and executes the tool — the wrapper
        must convert internal failures to a block."""
        adapter, before, _ = registered_adapter

        async def explode(context):
            raise RuntimeError("backend outage")

        adapter._before_hook = explode
        result = before(SimpleNamespace(tool_name="reader", tool_input={}))
        assert result is False

    @pytest.mark.security
    def test_after_hook_applies_redacted_result(self, registered_adapter):
        """A postcondition redaction must replace the tool result the agent sees."""
        adapter, before, after = registered_adapter
        assert before(SimpleNamespace(tool_name="reader", tool_input={})) is None
        modified = after(_READ_CTX)
        assert modified is not None
        assert "SECRET-1" not in str(modified)

    def test_after_hook_keeps_original_when_no_redaction(self, registered_adapter):
        adapter, before, after = registered_adapter
        assert before(SimpleNamespace(tool_name="reader", tool_input={})) is None
        clean = SimpleNamespace(tool_name="reader", tool_input={}, tool_result="plain output")
        assert after(clean) is None
