"""Authenticated transport shared by AgentWall adapters."""
import os

import httpx


def post(url, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    key = os.getenv("AGENTWALL_API_KEY", "")
    if key:
        headers["X-AgentWall-Key"] = key
    try:
        response = httpx.post(url, headers=headers, **kwargs)
        response.raise_for_status()
        return response
    except httpx.HTTPError as exc:
        # Do not allow adapters' legacy RequestError handlers to fail open.
        raise PermissionError("AgentWall could not authorize this request") from exc
