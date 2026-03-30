"""Behavior tests for explicit workflow loading and dry-run skipping."""

from __future__ import annotations

from pathlib import Path

import pytest

from edictum import Edictum, EdictumConfigError
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowRuntime, load_workflow_string

_BUNDLE = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: empty-bundle
defaults:
  mode: enforce
rules:
  - id: noop-pre
    type: pre
    tool: Noop
    when:
      args.path:
        equals: never
    then:
      action: block
      message: never
"""

_WORKFLOW = """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: explicit-workflow
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: Read spec first
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
"""


class TestWorkflowFactoryBehavior:
    def test_from_yaml_string_workflow_content_constructs_runtime(self):
        guard = Edictum.from_yaml_string(
            _BUNDLE,
            backend=MemoryBackend(),
            workflow_content=_WORKFLOW,
        )

        assert guard._workflow_runtime is not None
        assert guard._workflow_runtime.definition.metadata.name == "explicit-workflow"

    def test_from_yaml_workflow_path_constructs_runtime(self, tmp_path: Path):
        bundle_path = tmp_path / "bundle.yaml"
        workflow_path = tmp_path / "workflow.yaml"
        bundle_path.write_text(_BUNDLE, encoding="utf-8")
        workflow_path.write_text(_WORKFLOW, encoding="utf-8")

        guard = Edictum.from_yaml(
            bundle_path,
            workflow_path=workflow_path,
            backend=MemoryBackend(),
        )

        assert guard._workflow_runtime is not None
        assert guard._workflow_runtime.definition.metadata.name == "explicit-workflow"

    def test_exec_evaluator_flag_changes_factory_behavior(self, tmp_path: Path):
        bundle_path = tmp_path / "bundle.yaml"
        workflow_path = tmp_path / "workflow.yaml"
        bundle_path.write_text(_BUNDLE, encoding="utf-8")
        workflow_path.write_text(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-workflow
stages:
  - id: verify
    tools: [Bash]
    exit:
      - condition: exec("python3 -c \\"raise SystemExit(0)\\"", exit_code=0)
        message: pass
""",
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="exec\\(\\.\\.\\.\\) conditions require exec_evaluator_enabled=True"):
            Edictum.from_yaml(bundle_path, workflow_path=workflow_path, backend=MemoryBackend())

        guard = Edictum.from_yaml(
            bundle_path,
            workflow_path=workflow_path,
            workflow_exec_evaluator_enabled=True,
            backend=MemoryBackend(),
        )
        assert guard._workflow_runtime is not None

    def test_from_multiple_preserves_first_guard_workflow_runtime(self):
        first = Edictum.from_yaml_string(
            _BUNDLE,
            backend=MemoryBackend(),
            workflow_content=_WORKFLOW,
        )
        second = Edictum.from_yaml_string(
            _BUNDLE,
            backend=MemoryBackend(),
        )

        merged = Edictum.from_multiple([first, second])

        assert merged._workflow_runtime is not None
        assert merged._workflow_runtime.definition.metadata.name == "explicit-workflow"

    @pytest.mark.asyncio
    async def test_evaluate_skips_workflow_state_in_m1(self):
        guard = Edictum.from_yaml_string(
            _BUNDLE,
            backend=MemoryBackend(),
            workflow_content=_WORKFLOW,
        )

        dry_run = guard.evaluate("Edit", {"path": "src/app.py"})
        assert dry_run.decision == "allow"

        runtime = guard._workflow_runtime
        assert runtime is not None
        state = await runtime.state(Session(guard._session_id, guard.backend))
        assert state.active_stage == "read-context"


class TestWorkflowSecurityBehavior:
    @pytest.mark.security
    def test_exec_condition_requires_explicit_opt_in(self):
        with pytest.raises(ValueError, match="exec\\(\\.\\.\\.\\) conditions require exec_evaluator_enabled=True"):
            WorkflowRuntime(
                load_workflow_string(
                    """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-security
stages:
  - id: verify
    tools: [Bash]
    exit:
      - condition: exec("python3 -c \\"raise SystemExit(0)\\"", exit_code=0)
        message: pass
"""
                )
            )

    @pytest.mark.security
    def test_workflow_regex_length_limit_rejects_oversized_pattern(self):
        oversized_pattern = "a" * 10_001

        with pytest.raises(EdictumConfigError, match="exceeds 10000 characters"):
            load_workflow_string(
                f"""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: regex-bomb
stages:
  - id: verify
    tools: [Bash]
    checks:
      - command_matches: "{oversized_pattern}"
        message: nope
"""
            )

    @pytest.mark.security
    def test_workflow_name_rejects_storage_key_delimiters(self):
        with pytest.raises(EdictumConfigError, match="metadata.name must match"):
            load_workflow_string(
                """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: bad:name
stages:
  - id: read-context
    tools: [Read]
"""
            )

    @pytest.mark.security
    def test_workflow_stage_id_rejects_path_traversal_tokens(self):
        with pytest.raises(EdictumConfigError, match='stage.id "\\.\\./escape" must match'):
            load_workflow_string(
                """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: valid-name
stages:
  - id: ../escape
    tools: [Read]
"""
            )
