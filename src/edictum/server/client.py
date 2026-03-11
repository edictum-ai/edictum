"""Async HTTP client for edictum-server."""

from __future__ import annotations

import asyncio
import logging
import re
import threading
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
        bundle_name: str | None = None,
        tags: dict[str, str] | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        allow_insecure: bool = False,
    ) -> None:
        for name, value in [("agent_id", agent_id), ("env", env)]:
            if not _SAFE_IDENTIFIER_RE.match(value):
                raise ValueError(
                    f"Invalid {name}: {value!r}. Must be 1-128 alphanumeric chars, hyphens, underscores, or dots."
                )
        if bundle_name is not None and not _SAFE_IDENTIFIER_RE.match(bundle_name):
            raise ValueError(
                f"Invalid bundle_name: {bundle_name!r}. "
                "Must be 1-128 alphanumeric chars, hyphens, underscores, or dots."
            )
        if tags is not None:
            if len(tags) > 64:
                raise ValueError(f"Too many tags ({len(tags)} > 64); maximum is 64 entries")
            for k, v in tags.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise ValueError(f"Tag keys and values must be strings, got {type(k).__name__}={type(v).__name__}")
                if len(k) > 128:
                    raise ValueError(f"Tag key too long ({len(k)} > 128): {k!r}")
                if len(v) > 256:
                    raise ValueError(f"Tag value too long ({len(v)} > 256) for key {k!r}")
        # TLS enforcement: refuse plaintext HTTP to non-loopback hosts
        from urllib.parse import urlparse

        parsed = urlparse(base_url)
        if parsed.scheme == "http":
            host = parsed.hostname or ""
            is_loopback = host in ("localhost", "127.0.0.1", "::1")
            if not is_loopback:
                if not allow_insecure:
                    raise ValueError(
                        f"Refusing plaintext HTTP connection to {host}. "
                        f"Use HTTPS or pass allow_insecure=True for non-production use."
                    )
                logger.warning(
                    "Plaintext HTTP connection to %s — credentials will be transmitted unencrypted. "
                    "Use HTTPS in production.",
                    host,
                )

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.env = env
        self.bundle_name = bundle_name
        self.tags = tags
        self.timeout = timeout
        self.max_retries = max_retries
        self._local = threading.local()

    async def __aenter__(self) -> EdictumServerClient:
        self._local.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers(),
            timeout=self.timeout,
        )
        try:
            self._local.loop = asyncio.get_running_loop()
        except RuntimeError:
            self._local.loop = None
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
        client = getattr(self._local, "client", None)
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        # Compare loop objects directly — id() can be recycled after GC,
        # causing a stale client to be reused on a new loop at the same address.
        if client is not None and getattr(self._local, "loop", None) is current_loop:
            return client
        # Stale client from a dead loop — can't aclose() because the
        # underlying transport's sockets are bound to the closed loop.
        # GC will finalize the transport and close sockets. This may emit
        # ResourceWarning in debug mode; acceptable since sync adapters
        # process tool calls sequentially (bounded number of stale clients).
        client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._headers(),
            timeout=self.timeout,
        )
        self._local.client = client
        self._local.loop = current_loop
        return client

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
        """Close this thread's HTTP client."""
        client = getattr(self._local, "client", None)
        if client is not None:
            await client.aclose()
            self._local.client = None
            self._local.loop = None
