"""Server-backed storage backend for distributed session state.

Fail-closed contract: when the server is unreachable or returns a
non-404 error, methods raise rather than returning defaults.  The
governance pipeline treats unhandled exceptions as deny decisions,
so propagating errors here ensures that session-based rate limits
cannot be silently bypassed by a network outage.
"""

from __future__ import annotations

from edictum.server.client import EdictumServerClient, EdictumServerError


class ServerBackend:
    """Storage backend that delegates session state to edictum-server.

    Implements the StorageBackend protocol, forwarding all operations
    to the server's session state API.
    """

    def __init__(self, client: EdictumServerClient) -> None:
        self._client = client

    async def get(self, key: str) -> str | None:
        """Retrieve a value from the server session store.

        Returns None only when the key genuinely does not exist (HTTP 404).
        All other errors propagate so the pipeline fails closed.
        """
        try:
            response = await self._client.get(f"/api/v1/sessions/{key}")
            return response.get("value")
        except EdictumServerError as exc:
            if exc.status_code == 404:
                return None
            raise

    async def set(self, key: str, value: str) -> None:
        """Set a value in the server session store."""
        await self._client.put(f"/api/v1/sessions/{key}", {"value": value})

    async def delete(self, key: str) -> None:
        """Delete a key from the server session store."""
        try:
            await self._client.delete(f"/api/v1/sessions/{key}")
        except EdictumServerError as exc:
            if exc.status_code != 404:
                raise

    async def increment(self, key: str, amount: float = 1) -> float:
        """Atomically increment a counter on the server."""
        response = await self._client.post(
            f"/api/v1/sessions/{key}/increment",
            {"amount": amount},
        )
        return response["value"]

    async def batch_get(self, keys: list[str]) -> dict[str, str | None]:
        """Retrieve multiple session values in a single HTTP call.

        Falls back to individual get() calls if the server returns 404
        (endpoint not available on older servers).

        Fail-closed: non-404 errors propagate so the pipeline denies
        rather than silently allowing with missing data.
        """
        if not keys:
            return {}
        try:
            response = await self._client.post(
                "/api/v1/sessions/batch",
                {"keys": keys},
            )
            values = response.get("values", {})
            return {key: values.get(key) for key in keys}
        except EdictumServerError as exc:
            if exc.status_code == 404:
                # Server doesn't support batch endpoint -- fall back
                result: dict[str, str | None] = {}
                for key in keys:
                    result[key] = await self.get(key)
                return result
            raise
