"""Tests for EdictumServerClient."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum.server.client import EdictumServerClient, EdictumServerError


class TestEdictumServerClient:
    def test_init_stores_config(self):
        client = EdictumServerClient("https://example.com", "test-key", agent_id="agent-1")
        assert client.base_url == "https://example.com"
        assert client.api_key == "test-key"
        assert client.agent_id == "agent-1"
        assert client.timeout == 30.0
        assert client.max_retries == 3

    def test_init_defaults(self):
        client = EdictumServerClient("https://example.com", "key")
        assert client.agent_id == "default"
        assert client.timeout == 30.0
        assert client.max_retries == 3

    def test_init_strips_trailing_slash(self):
        client = EdictumServerClient("https://example.com/", "key")
        assert client.base_url == "https://example.com"

    @pytest.mark.asyncio
    async def test_context_manager(self):
        client = EdictumServerClient("https://example.com", "key")
        async with client as c:
            assert c is client
            assert c._client is not None
        assert client._client is None

    @pytest.mark.asyncio
    async def test_auth_header(self):
        client = EdictumServerClient("https://example.com", "my-secret-key", agent_id="agent-42")
        http_client = client._ensure_client()
        assert http_client.headers["authorization"] == "Bearer my-secret-key"
        assert http_client.headers["x-edictum-agent-id"] == "agent-42"
        await client.close()

    @pytest.mark.asyncio
    async def test_get_request(self):
        client = EdictumServerClient("https://example.com", "key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ok"}

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http = AsyncMock()
            mock_http.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http

            result = await client.get("/api/v1/test", foo="bar")
            assert result == {"result": "ok"}
            mock_http.request.assert_called_once_with("GET", "/api/v1/test", params={"foo": "bar"})

        await client.close()

    @pytest.mark.asyncio
    async def test_post_request(self):
        client = EdictumServerClient("https://example.com", "key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "123"}

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http = AsyncMock()
            mock_http.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http

            result = await client.post("/api/v1/test", {"data": "value"})
            assert result == {"id": "123"}
            mock_http.request.assert_called_once_with("POST", "/api/v1/test", json={"data": "value"})

        await client.close()

    @pytest.mark.asyncio
    async def test_put_request(self):
        client = EdictumServerClient("https://example.com", "key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"updated": True}

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http = AsyncMock()
            mock_http.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http

            result = await client.put("/api/v1/test", {"value": "new"})
            assert result == {"updated": True}

        await client.close()

    @pytest.mark.asyncio
    async def test_delete_request(self):
        client = EdictumServerClient("https://example.com", "key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"deleted": True}

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http = AsyncMock()
            mock_http.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http

            result = await client.delete("/api/v1/test")
            assert result == {"deleted": True}
            mock_http.request.assert_called_once_with("DELETE", "/api/v1/test")

        await client.close()

    @pytest.mark.asyncio
    async def test_4xx_raises_without_retry(self):
        client = EdictumServerClient("https://example.com", "key", max_retries=3)
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http = AsyncMock()
            mock_http.request = AsyncMock(return_value=mock_response)
            mock_ensure.return_value = mock_http

            with pytest.raises(EdictumServerError, match="HTTP 404"):
                await client.get("/api/v1/missing")

            assert mock_http.request.call_count == 1

        await client.close()

    @pytest.mark.asyncio
    async def test_5xx_retries_then_succeeds(self):
        client = EdictumServerClient("https://example.com", "key", max_retries=2)
        error_response = MagicMock()
        error_response.status_code = 500
        error_response.text = "Internal Server Error"
        ok_response = MagicMock()
        ok_response.status_code = 200
        ok_response.json.return_value = {"ok": True}

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http = AsyncMock()
            mock_http.request = AsyncMock(side_effect=[error_response, ok_response])
            mock_ensure.return_value = mock_http

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await client.get("/api/v1/test")
                assert result == {"ok": True}
                assert mock_http.request.call_count == 2

        await client.close()

    @pytest.mark.asyncio
    async def test_5xx_retries_exhausted(self):
        client = EdictumServerClient("https://example.com", "key", max_retries=2)
        error_response = MagicMock()
        error_response.status_code = 502
        error_response.text = "Bad Gateway"

        with patch.object(client, "_ensure_client") as mock_ensure:
            mock_http = AsyncMock()
            mock_http.request = AsyncMock(return_value=error_response)
            mock_ensure.return_value = mock_http

            with patch("asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(EdictumServerError, match="HTTP 502"):
                    await client.get("/api/v1/test")
                assert mock_http.request.call_count == 2

        await client.close()

    def test_stores_env(self):
        client = EdictumServerClient("https://example.com", "key", env="staging")
        assert client.env == "staging"

    def test_default_env(self):
        client = EdictumServerClient("https://example.com", "key")
        assert client.env == "production"

    def test_stores_bundle_name(self):
        client = EdictumServerClient("https://example.com", "key", bundle_name="devops-agent")
        assert client.bundle_name == "devops-agent"

    def test_default_bundle_name(self):
        client = EdictumServerClient("https://example.com", "key")
        assert client.bundle_name == "default"

    @pytest.mark.asyncio
    async def test_close_when_no_client(self):
        client = EdictumServerClient("https://example.com", "key")
        await client.close()  # Should not raise


class TestClientInputValidation:
    """Validate that bundle_name, env, and agent_id reject unsafe values."""

    @pytest.mark.security
    @pytest.mark.parametrize(
        "field,value",
        [
            ("bundle_name", "../../admin/x"),
            ("bundle_name", "name\x00null"),
            ("bundle_name", "name\ninjection"),
            ("bundle_name", "name\rinjection"),
            ("bundle_name", ""),
            ("bundle_name", "a" * 129),
            ("bundle_name", "has space"),
            ("env", "../etc/passwd"),
            ("env", "env\x00null"),
            ("env", "prod\nX-Injected: true"),
            ("env", ""),
            ("agent_id", "agent/../../admin"),
            ("agent_id", "agent\x00null"),
            ("agent_id", "agent\nHeader: inject"),
            ("agent_id", ""),
        ],
    )
    def test_rejects_unsafe_identifiers(self, field, value):
        kwargs = {field: value}
        with pytest.raises(ValueError, match=f"Invalid {field}"):
            EdictumServerClient("https://example.com", "key", **kwargs)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "value",
        [
            "default",
            "my-agent",
            "devops_agent",
            "prod.v2",
            "Agent-123",
            "a",
            "a" * 128,
        ],
    )
    def test_accepts_safe_identifiers(self, value):
        client = EdictumServerClient(
            "https://example.com",
            "key",
            agent_id=value,
            env=value,
            bundle_name=value,
        )
        assert client.agent_id == value
        assert client.env == value
        assert client.bundle_name == value
