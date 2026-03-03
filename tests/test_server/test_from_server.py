"""Tests for Edictum.from_server() constructor."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum import Edictum, EdictumConfigError

# Minimal valid YAML bundle for testing
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


def _b64_yaml(yaml_str: str = VALID_BUNDLE_YAML) -> str:
    """Base64-encode a YAML string, matching the server's yaml_bytes format."""
    return base64.b64encode(yaml_str.encode("utf-8")).decode("ascii")


def _make_client_mock(response=None, side_effect=None):
    """Create a mock EdictumServerClient."""
    client = MagicMock()
    client.bundle_name = "default"
    client.env = "production"
    if side_effect:
        client.get = AsyncMock(side_effect=side_effect)
    else:
        client.get = AsyncMock(return_value=response or {"yaml_bytes": _b64_yaml()})
    client.close = AsyncMock()
    return client


def _make_source_mock():
    """Create a mock ServerContractSource."""
    source = MagicMock()
    source.connect = AsyncMock()
    source.close = AsyncMock()
    return source


def _server_patches():
    """Context manager that patches all server imports for from_server()."""
    return (
        patch("edictum.server.client.EdictumServerClient"),
        patch("edictum.server.audit_sink.ServerAuditSink"),
        patch("edictum.server.approval_backend.ServerApprovalBackend"),
        patch("edictum.server.backend.ServerBackend"),
        patch("edictum.server.contract_source.ServerContractSource"),
    )


class TestFromServer:
    @pytest.mark.asyncio
    async def test_creates_wired_instance(self):
        """from_server() returns an Edictum wired to server components."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock()
            mock_cls.return_value = client

            source = _make_source_mock()
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://console.edictum.dev",
                "test-api-key",
                "agent-1",
                auto_watch=False,
            )

            assert isinstance(guard, Edictum)
            assert guard.policy_version is not None
            assert len(guard._preconditions) == 1

            mock_cls.assert_called_once_with(
                "https://console.edictum.dev",
                "test-api-key",
                agent_id="agent-1",
                env="production",
                bundle_name="default",
            )
            client.get.assert_called_once_with(
                "/api/v1/bundles/default/current",
                env="production",
            )

            await guard.close()

    @pytest.mark.asyncio
    async def test_custom_environment(self):
        """env parameter sets the environment on the guard and is used in the fetch URL."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock()
            client.env = "staging"
            mock_cls.return_value = client
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                env="staging",
                auto_watch=False,
            )

            assert guard.environment == "staging"
            client.get.assert_called_once_with(
                "/api/v1/bundles/default/current",
                env="staging",
            )
            await guard.close()

    @pytest.mark.asyncio
    async def test_override_audit_sink(self):
        """Custom audit_sink overrides the default ServerAuditSink."""
        custom_sink = MagicMock()

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                audit_sink=custom_sink,
                auto_watch=False,
            )

            assert guard.audit_sink is custom_sink
            await guard.close()

    @pytest.mark.asyncio
    async def test_server_unreachable_raises_config_error(self):
        """from_server() raises EdictumConfigError when server is unreachable."""
        with patch("edictum.server.client.EdictumServerClient") as mock_cls:
            client = _make_client_mock(side_effect=ConnectionError("unreachable"))
            mock_cls.return_value = client

            with pytest.raises(EdictumConfigError, match="Failed to fetch contracts"):
                await Edictum.from_server("https://unreachable.example.com", "key", "agent-1")

            client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalid_yaml_raises_config_error(self):
        """from_server() raises EdictumConfigError when server returns invalid YAML."""
        with patch("edictum.server.client.EdictumServerClient") as mock_cls:
            client = _make_client_mock(response={"yaml_bytes": _b64_yaml("not: valid: yaml: [")})
            mock_cls.return_value = client

            with pytest.raises(EdictumConfigError, match="Failed to parse server contracts"):
                await Edictum.from_server("https://example.com", "key", "agent-1")

            client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_bundle_name_forwarded_to_client(self):
        """bundle_name parameter is forwarded to EdictumServerClient and used in fetch URL."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock()
            client.bundle_name = "devops-agent"
            mock_cls.return_value = client
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="devops-agent",
                auto_watch=False,
            )

            mock_cls.assert_called_once_with(
                "https://example.com",
                "key",
                agent_id="agent-1",
                env="production",
                bundle_name="devops-agent",
            )
            client.get.assert_called_once_with(
                "/api/v1/bundles/devops-agent/current",
                env="production",
            )
            await guard.close()

    @pytest.mark.asyncio
    async def test_default_environment_is_production(self):
        """Default environment is 'production' when env is not specified."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock()
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                auto_watch=False,
            )

            assert guard.environment == "production"
            await guard.close()
