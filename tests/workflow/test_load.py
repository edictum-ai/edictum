from __future__ import annotations

import pytest

from edictum import EdictumConfigError
from edictum.workflow import load_workflow_string


def test_load_workflow_parses_valid_document():
    definition = load_workflow_string(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: read-before-edit
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: Read the spec
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
"""
    )

    assert definition.metadata.name == "read-before-edit"
    assert [stage.id for stage in definition.stages] == ["read-context", "implement"]


def test_load_workflow_rejects_duplicate_stage_ids():
    with pytest.raises(EdictumConfigError, match='workflow: duplicate stage id "repeat"'):
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: duplicate-stage
stages:
  - id: repeat
    tools: [Read]
  - id: repeat
    tools: [Edit]
"""
        )


def test_load_workflow_rejects_invalid_regex():
    with pytest.raises(EdictumConfigError, match="invalid command_matches regex"):
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: bad-regex
stages:
  - id: verify
    tools: [Bash]
    checks:
      - command_matches: "("
        message: nope
"""
        )


def test_load_workflow_rejects_control_characters_in_condition_args():
    with pytest.raises(EdictumConfigError, match="control characters"):
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: bad-gate-arg
stages:
  - id: verify
    tools: [Read]
    exit:
      - condition: file_read("specs/\\nmalicious")
        message: nope
"""
        )
