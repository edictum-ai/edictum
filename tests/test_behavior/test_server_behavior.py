"""Behavior tests for server SDK: from_server(), tags, and server-assigned mode."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum import Edictum

VALID_BUNDLE_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-bundle
defaults:
  mode: enforce
contracts:
  - id: deny-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      effect: deny
      message: "Destructive command denied."
"""


def _b64(yaml_str: str = VALID_BUNDLE_YAML) -> str:
    return base64.b64encode(yaml_str.encode("utf-8")).decode("ascii")


def _make_client_mock(*, bundle_name="default"):
    client = MagicMock()
    client.bundle_name = bundle_name
    client.env = "production"
    client.tags = None
    client.get = AsyncMock(return_value={"yaml_bytes": _b64()})
    client.close = AsyncMock()
    return client


def _make_source_mock():
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
        patch("edictum.server.contract_source.ServerContractSource"),
    )


class TestTagsBehavior:
    """Observable effect: tags change the EdictumServerClient construction."""

    @pytest.mark.asyncio
    async def test_tags_present_changes_client_construction(self):
        """Setting tags= produces a different client than omitting it."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                tags={"role": "finance"},
                auto_watch=False,
            )
            call_with_tags = mock_cls.call_args

            mock_cls.reset_mock()
            mock_cls.return_value = _make_client_mock()

            await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
            )
            call_without_tags = mock_cls.call_args

            # Observable difference: tags kwarg differs
            assert call_with_tags.kwargs["tags"] == {"role": "finance"}
            assert call_without_tags.kwargs["tags"] is None


class TestServerAssignedModeBehavior:
    """Observable effect: bundle_name=None means zero contracts until SSE push."""

    @pytest.mark.asyncio
    async def test_bundle_name_none_starts_with_zero_contracts(self):
        """Agent starts with no contracts and enforces nothing until assignment arrives."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock(bundle_name=None)
            mock_cls.return_value = client

            async def mock_watch():
                yield {"yaml_bytes": _b64()}

            source = _make_source_mock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server("https://example.com", "key", "agent-1", bundle_name=None)

            # Observable: no initial HTTP fetch — contracts came from SSE
            client.get.assert_not_called()
            # Observable: guard has contracts (from SSE push)
            assert len(guard._state.preconditions) == 1
            await guard.close()

    @pytest.mark.asyncio
    async def test_bundle_name_none_without_auto_watch_raises(self):
        """Server-assigned mode without SSE is a configuration error."""
        with pytest.raises(ValueError, match="auto_watch must be True"):
            await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name=None,
                auto_watch=False,
            )

    @pytest.mark.asyncio
    async def test_bundle_name_provided_fetches_immediately(self):
        """When bundle_name is set, contracts are fetched via HTTP (not SSE)."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock(bundle_name="my-bundle")
            mock_cls.return_value = client
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="my-bundle",
                auto_watch=False,
            )

            # Observable: HTTP fetch happened
            client.get.assert_called_once()
            assert guard.policy_version is not None
            assert len(guard._state.preconditions) == 1
            await guard.close()
