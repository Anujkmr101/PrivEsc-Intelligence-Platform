"""
pip/api/auth.py

API Authentication.

Supports three modes:
  jwt    — Bearer token validation via python-jose (default)
  apikey — Static API key in X-API-Key header
  none   — No authentication (development only; logs a warning at startup)

Configure the JWT secret and API keys via environment variables:
    PIP_JWT_SECRET=<secret>
    PIP_API_KEYS=key1,key2,key3
"""

from __future__ import annotations

import os
import logging
from typing import Callable

from fastapi import Header, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger("pip.api")

_JWT_SECRET = os.environ.get("PIP_JWT_SECRET", "changeme-in-production")
_API_KEYS   = set(filter(None, os.environ.get("PIP_API_KEYS", "").split(",")))


def get_auth_dependency(method: str) -> Callable:
    """
    Return the appropriate FastAPI dependency function for the auth method.

    Args:
        method: "jwt" | "apikey" | "none"
    """
    if method == "none":
        logger.warning("PIP API running with NO authentication. Development use only.")
        async def no_auth():
            pass
        return no_auth

    if method == "apikey":
        async def apikey_auth(x_api_key: str = Header(..., alias="X-API-Key")):
            if not _API_KEYS:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="No API keys configured. Set PIP_API_KEYS env variable.",
                )
            if x_api_key not in _API_KEYS:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key.",
                )
        return apikey_auth

    # Default: JWT
    bearer = HTTPBearer()

    async def jwt_auth(credentials: HTTPAuthorizationCredentials = bearer):  # type: ignore[assignment]
        token = credentials.credentials
        try:
            from jose import jwt, JWTError  # type: ignore
            jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    return jwt_auth
