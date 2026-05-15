"""
Authentication middleware for AgentWall.

Two modes:
  1. API Key   — static secret in header X-AgentWall-Key (for agents/services)
  2. JWT Token — short-lived token for dashboard UI

Generate a key:
  python -c "import secrets; print(secrets.token_urlsafe(32))"
"""
import os
import time
import base64
import json
import jwt
from functools import wraps
from typing import Optional

from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ── Config ────────────────────────────────────────────────────────────────────
# Comma-separated list of valid API keys
_RAW_KEYS  = os.getenv("AGENTWALL_API_KEYS", "agentwall_dev_key")
API_KEYS   = set(k.strip() for k in _RAW_KEYS.split(",") if k.strip())

# JWT Configuration
JWT_SECRET = os.getenv("AGENTWALL_JWT_SECRET")
if not JWT_SECRET:
    # Use a stable secret for development to prevent session invalidation on restart.
    # PRODUCTION: Always set AGENTWALL_JWT_SECRET environment variable.
    JWT_SECRET = "agentwall-dev-stable-secret-2024"
    print("[Security] [DEV] Using stable fallback JWT secret.")

JWT_TTL    = int(os.getenv("AGENTWALL_JWT_TTL", "3600"))  # seconds

# If no keys configured, auth is DISABLED unless explicitly forced
# PRODUCTION DEFAULT: Auth is enabled
AUTH_ENABLED = os.getenv("AGENTWALL_AUTH_ENABLED", "1") == "1"

_bearer = HTTPBearer(auto_error=False)


# ── JWT (minimal, no external deps) ──────────────────────────────────────────

def create_jwt(payload: dict) -> str:
    """Standard JWT creation using PyJWT."""
    iat = int(time.time())
    exp = iat + JWT_TTL
    full_payload = {**payload, "iat": iat, "exp": exp}
    return jwt.encode(full_payload, JWT_SECRET, algorithm="HS256")

def verify_jwt(token: str) -> Optional[dict]:
    """Standard JWT verification using PyJWT."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ── FastAPI dependency ────────────────────────────────────────────────────────

def require_auth_token(token: str) -> dict:
    """Non-async helper for WebSocket/parameter-based auth."""
    if not AUTH_ENABLED:
        return {"sub": "anonymous"}
    payload = verify_jwt(token)
    if payload:
        return payload
    # Check if it's a valid API key (fallback for some integrations)
    if token in API_KEYS:
        return {"sub": "api_key", "key_prefix": token[:8]}
    raise HTTPException(status_code=401, detail="Invalid or expired token")


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
):
    """FastAPI dependency — attach to any route that needs auth."""
    if not AUTH_ENABLED:
        return {"sub": "anonymous", "auth": "disabled"}

    # Method 1: API key in header
    api_key = request.headers.get("X-AgentWall-Key")
    if api_key:
        if api_key in API_KEYS:
            return {"sub": "api_key", "key_prefix": api_key[:8]}
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Method 2: Bearer JWT (dashboard)
    if credentials and credentials.scheme.lower() == "bearer":
        payload = verify_jwt(credentials.credentials)
        if payload:
            return payload
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Use X-AgentWall-Key header or Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def optional_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
):
    """Like require_auth but returns None instead of raising."""
    if not AUTH_ENABLED:
        return {"sub": "anonymous"}
    try:
        return await require_auth(request, credentials)
    except HTTPException:
        return None
