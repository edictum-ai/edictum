"""Upload skill scan results to an Edictum Console server.

Lives in edictum.server (requires edictum[server] / httpx) to respect
the tier boundary: networking belongs to the server layer, not core.
"""

from __future__ import annotations

import os

import httpx

from edictum.skill.formatters import format_json


def upload_scan_results(
    classifications: list,
    server_url: str,
    skills_dir: str,
) -> tuple[bool, str]:
    """POST scan results to Console. Returns (success, message).

    Reads ``EDICTUM_CONSOLE_TOKEN`` from the environment for
    authentication. If unset, sends the request without auth
    (server may reject with 401).
    """
    payload = format_json(classifications, skills_dir=skills_dir)
    url = server_url.rstrip("/") + "/api/v1/skill-scan"

    headers: dict[str, str] = {"Content-Type": "application/json"}
    token = os.environ.get("EDICTUM_CONSOLE_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = httpx.post(url, content=payload, headers=headers, timeout=30.0)
        if resp.status_code < 300:
            return True, server_url
        return False, f"server returned {resp.status_code}"
    except httpx.HTTPError as e:
        return False, str(e)
