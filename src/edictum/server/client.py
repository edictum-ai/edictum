"""Async HTTP client for edictum-server."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Safe identifier: alphanumeric, hyphens, underscores, dots. No path separators,
# control chars, or whitespace. Matches tool_name validation in envelope.py.
_SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


class EdictumServerError(Exception):
    """Raised when the server returns an error response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class EdictumServerClient:
    """Async HTTP client for the edictum-server API.

    Handles auth (Bearer API key), retries, and connection management.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        agent_id: str = "default",
        env: str = "production",
        bundle_name: str = "default",
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        for name, value in [("agent_id", agent_id), ("env", env), ("bundle_name", bundle_name)]:
            if not _SAFE_IDENTIFIER_RE.match(value):
                raise ValueError(
                    f"Invalid {name}: {value!r}. " "Must be 1-128 alphanumeric chars, hyphens, underscores, or dots."
                )
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.env = env
        self.bundle_name = bundle_name
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> EdictumServerClient:
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers(),
            timeout=self.timeout,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Edictum-Agent-Id": self.agent_id,
            "Content-Type": "application/json",
        }

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers(),
                timeout=self.timeout,
            )
        return self._client

    async def get(self, path: str, **params: Any) -> dict:
        """Send a GET request with retry logic."""
        return await self._request("GET", path, params=params)

    async def post(self, path: str, body: dict) -> dict:
        """Send a POST request with retry logic."""
        return await self._request("POST", path, json=body)

    async def put(self, path: str, body: dict) -> dict:
        """Send a PUT request with retry logic."""
        return await self._request("PUT", path, json=body)

    async def delete(self, path: str) -> dict:
        """Send a DELETE request with retry logic."""
        return await self._request("DELETE", path)

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        """Execute an HTTP request with exponential backoff retry for 5xx errors."""
        client = self._ensure_client()
        last_exc: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                response = await client.request(method, path, **kwargs)
                if response.status_code >= 500:
                    last_exc = EdictumServerError(response.status_code, response.text)
                    if attempt < self.max_retries - 1:
                        delay = 2**attempt * 0.5
                        logger.warning(
                            "Server error %d on %s %s, retrying in %.1fs (attempt %d/%d)",
                            response.status_code,
                            method,
                            path,
                            delay,
                            attempt + 1,
                            self.max_retries,
                        )
                        await asyncio.sleep(delay)
                        continue
                    raise last_exc
                if response.status_code >= 400:
                    raise EdictumServerError(response.status_code, response.text)
                return response.json()
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    delay = 2**attempt * 0.5
                    logger.warning(
                        "Connection error on %s %s, retrying in %.1fs (attempt %d/%d)",
                        method,
                        path,
                        delay,
                        attempt + 1,
                        self.max_retries,
                    )
                    await asyncio.sleep(delay)
                    continue
                raise

        raise last_exc  # type: ignore[misc]

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
