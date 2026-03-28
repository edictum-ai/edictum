"""Schema validation tests for sandbox rules."""

from __future__ import annotations

import pytest

from edictum.yaml_engine.loader import load_bundle_string


def _load(yaml: str):
    """Helper to load YAML and return the parsed bundle."""
    return load_bundle_string(yaml)


class TestSandboxSchemaValid:
    """Valid sandbox YAML should load without errors."""

    def test_sandbox_with_within(self):
        _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: file-sandbox
    type: sandbox
    tool: read_file
    within: [/workspace]
    outside: block
    message: "Denied"
""")

    def test_sandbox_with_tools_array(self):
        _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: file-sandbox
    type: sandbox
    tools: [read_file, write_file]
    within: [/workspace]
    outside: block
    message: "Denied"
""")

    def test_sandbox_with_allows_commands(self):
        _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: exec-sandbox
    type: sandbox
    tool: exec
    allows:
      commands: [ls, cat, git]
    outside: block
    message: "Denied"
""")

    def test_sandbox_with_allows_domains(self):
        _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: web-sandbox
    type: sandbox
    tool: web_fetch
    allows:
      domains: [github.com, '*.googleapis.com']
    outside: block
    message: "Denied"
""")

    def test_sandbox_with_not_within_and_not_allows(self):
        _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: full-sandbox
    type: sandbox
    tools: [read_file, exec, web_fetch]
    within: [/workspace, /tmp]
    not_within: [/workspace/.git]
    allows:
      commands: [ls]
      domains: ['*']
    not_allows:
      domains: [evil.com]
    outside: ask
    message: "Sandbox violation"
    timeout: 120
    timeout_action: block
""")

    def test_sandbox_with_observe_mode(self):
        _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: sandbox-observe
    type: sandbox
    mode: observe
    tool: read_file
    within: [/safe]
    outside: block
    message: "Would block"
""")


class TestSandboxSchemaInvalid:
    """Invalid sandbox YAML should fail validation."""

    def test_missing_tool_and_tools(self):
        with pytest.raises(Exception):
            _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: bad-sandbox
    type: sandbox
    within: [/workspace]
    outside: block
    message: "Denied"
""")

    def test_missing_within_and_allows(self):
        with pytest.raises(Exception):
            _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: bad-sandbox
    type: sandbox
    tool: read_file
    outside: block
    message: "Denied"
""")

    def test_invalid_outside_value(self):
        with pytest.raises(Exception):
            _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: bad-sandbox
    type: sandbox
    tool: read_file
    within: [/workspace]
    outside: warn
    message: "Denied"
""")

    def test_not_within_without_within(self):
        """not_within requires within to also be set."""
        with pytest.raises(Exception):
            _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: bad-sandbox
    type: sandbox
    tool: read_file
    not_within: [/workspace/.git]
    allows:
      commands: [ls]
    outside: block
    message: "Denied"
""")

    def test_not_allows_without_allows(self):
        """not_allows requires allows to also be set."""
        with pytest.raises(Exception):
            _load("""\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: bad-sandbox
    type: sandbox
    tool: read_file
    within: [/workspace]
    not_allows:
      domains: [evil.com]
    outside: block
    message: "Denied"
""")
