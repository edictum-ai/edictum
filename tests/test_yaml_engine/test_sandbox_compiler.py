"""Compiler tests for sandbox rules."""

from __future__ import annotations

from edictum import create_envelope
from edictum.yaml_engine.compiler import compile_contracts
from edictum.yaml_engine.loader import load_bundle_string


def _compile(yaml: str):
    data, _ = load_bundle_string(yaml)
    return compile_contracts(data)


class TestSandboxCompilation:
    """Sandbox rules compile to callables with correct metadata."""

    YAML = """\
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
"""

    def test_compiled_bundle_has_sandbox_contracts(self):
        compiled = _compile(self.YAML)
        assert len(compiled.sandbox_contracts) == 1

    def test_sandbox_callable_has_edictum_type(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        assert fn._edictum_type == "sandbox"

    def test_sandbox_callable_has_edictum_id(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        assert fn._edictum_id == "file-sandbox"

    def test_sandbox_callable_has_tools(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        assert fn._edictum_tools == ["read_file"]

    def test_sandbox_callable_has_effect(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        assert fn._edictum_effect == "block"

    def test_sandbox_callable_has_source(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        assert fn._edictum_source == "yaml_sandbox"


class TestSandboxDisabled:
    """Disabled sandbox rules are skipped."""

    YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: disabled-sandbox
    type: sandbox
    enabled: false
    tool: read_file
    within: [/workspace]
    outside: block
    message: "Denied"
"""

    def test_disabled_sandbox_not_in_compiled(self):
        compiled = _compile(self.YAML)
        assert len(compiled.sandbox_contracts) == 0


class TestSandboxToolNormalization:
    """Singular 'tool' and plural 'tools' both normalize to a list."""

    YAML_SINGULAR = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: singular-sandbox
    type: sandbox
    tool: read_file
    within: [/workspace]
    outside: block
    message: "Denied"
"""

    YAML_PLURAL = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test
defaults:
  mode: enforce
rules:
  - id: plural-sandbox
    type: sandbox
    tools: [read_file, write_file]
    within: [/workspace]
    outside: block
    message: "Denied"
"""

    def test_singular_tool_normalizes_to_list(self):
        compiled = _compile(self.YAML_SINGULAR)
        fn = compiled.sandbox_contracts[0]
        assert fn._edictum_tools == ["read_file"]

    def test_plural_tools_preserved(self):
        compiled = _compile(self.YAML_PLURAL)
        fn = compiled.sandbox_contracts[0]
        assert fn._edictum_tools == ["read_file", "write_file"]


class TestSandboxCallableEvaluation:
    """The compiled sandbox callable evaluates correctly."""

    YAML = """\
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
    within: [/workspace, /tmp]
    not_within: [/workspace/.git]
    outside: block
    message: "Outside sandbox"
"""

    def test_allowed_path_passes(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        tool_call = create_envelope("read_file", {"path": "/workspace/file.txt"})
        decision = fn(tool_call)
        assert decision.passed is True

    def test_excluded_path_fails(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        tool_call = create_envelope("read_file", {"path": "/workspace/.git/config"})
        decision = fn(tool_call)
        assert decision.passed is False

    def test_outside_path_fails(self):
        compiled = _compile(self.YAML)
        fn = compiled.sandbox_contracts[0]
        tool_call = create_envelope("read_file", {"path": "/etc/shadow"})
        decision = fn(tool_call)
        assert decision.passed is False
