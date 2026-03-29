"""Behavior tests for explicit workflow loading via from_server()."""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum import Edictum

_BUNDLE = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: server-bundle
defaults:
  mode: enforce
rules:
  - id: block-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      action: block
      message: "Destructive command denied."
"""

_WORKFLOW = """\
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: server-workflow
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

_EXEC_WORKFLOW = """\
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
"""


def _b64(yaml_str: str = _BUNDLE) -> str:
    return base64.b64encode(yaml_str.encode("utf-8")).decode("ascii")


def _make_client_mock() -> MagicMock:
    client = MagicMock()
    client.bundle_name = "default"
    client.env = "production"
    client.tags = None
    client.get = AsyncMock(return_value={"yaml_bytes": _b64()})
    client.close = AsyncMock()
    return client


def _make_source_mock() -> MagicMock:
    source = MagicMock()
    source.connect = AsyncMock()
    source.close = AsyncMock()
    return source


def _server_patches():
    return (
        patch("edictum.server.client.EdictumServerClient"),
        patch("edictum.server.audit_sink.ServerAuditSink"),
        patch("edictum.server.approval_backend.ServerApprovalBackend"),
        patch("edictum.server.backend.ServerBackend"),
        patch("edictum.server.rule_source.ServerContractSource"),
    )


class TestFromServerWorkflowBehavior:
    @pytest.mark.asyncio
    async def test_workflow_content_constructs_runtime(self):
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
                workflow_content=_WORKFLOW,
            )

            assert guard._workflow_runtime is not None
            assert guard._workflow_runtime.definition.metadata.name == "server-workflow"
            await guard.close()

    @pytest.mark.asyncio
    async def test_workflow_path_constructs_runtime(self, tmp_path: Path):
        workflow_path = tmp_path / "workflow.yaml"
        workflow_path.write_text(_WORKFLOW, encoding="utf-8")

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
                workflow_path=workflow_path,
            )

            assert guard._workflow_runtime is not None
            assert guard._workflow_runtime.definition.metadata.name == "server-workflow"
            await guard.close()

    @pytest.mark.asyncio
    async def test_exec_flag_changes_workflow_loading_behavior(self):
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            with pytest.raises(ValueError, match="exec\\(\\.\\.\\.\\) conditions require exec_evaluator_enabled=True"):
                await Edictum.from_server(
                    "https://example.com",
                    "key",
                    "agent-1",
                    bundle_name="default",
                    auto_watch=False,
                    workflow_content=_EXEC_WORKFLOW,
                )

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
                workflow_content=_EXEC_WORKFLOW,
                workflow_exec_evaluator_enabled=True,
            )

            assert guard._workflow_runtime is not None
            await guard.close()
