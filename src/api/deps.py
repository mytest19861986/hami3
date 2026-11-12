"""
FastAPI Dependencies & Context Injections
REMEDIATION: HC-T13 (F-04, F-05, T13-AC3, T13-AC5)

Provides database connection pools, Redis ephemeral cache,
authentication context (backed by PostgreSQL session families),
and authoritative `user_roles` RBAC enforcement.
"""

import os
from typing import Any, Dict

import asyncpg
import redis
from fastapi import Depends, Header, HTTPException, Response, status

from src.auth.access_tokens import (
    ACCESS_TOKEN_PREFIX,
    AccessTokenConfigurationError,
    InvalidAccessTokenError,
    RevocationStoreUnavailableError,
    is_family_revoked_in_redis,
    verify_access_token,
)
from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.auth.session_service import SessionService

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

_pool: asyncpg.Pool | None = None
_redis: redis.Redis | None = None


async def init_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        dsn = os.getenv("DATABASE_URL", DATABASE_URL)
        _pool = await asyncpg.create_pool(dsn, min_size=5, max_size=20)
    return _pool


async def close_pool():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def init_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        r_url = os.getenv("REDIS_URL", REDIS_URL)
        _redis = redis.Redis.from_url(r_url, decode_responses=True)
    return _redis


def close_redis():
    global _redis
    if _redis is not None:
        _redis.close()
        _redis = None


async def get_db_pool() -> asyncpg.Pool:
    if _pool is None:
        return await init_pool()
    return _pool


def get_redis() -> redis.Redis:
    if _redis is None:
        return init_redis()
    return _redis


async def get_current_user(
    response: Response,
    authorization: str | None = Header(None),
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis),
) -> Dict[str, Any]:
    """
    Validates short-lived access token (`hc_at_v1.*`) OR legacy Bearer session token against
    fail-closed Redis revocation set + PostgreSQL active session family (SSOT),
    resolves authoritative roles from `user_roles` (F-04), and enforces no-store cache headers (AUTH-013).
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header.",
        )

    raw_token = authorization.split(" ", 1)[1].strip()
    session_svc = SessionService(pool, redis_client=r)
    rbac = RbacEngine(pool)

    if raw_token.startswith(f"{ACCESS_TOKEN_PREFIX}."):
        try:
            claims = verify_access_token(raw_token)
        except AccessTokenConfigurationError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        except InvalidAccessTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token invalid or expired.",
            ) from exc

        try:
            revoked_in_redis = is_family_revoked_in_redis(r, claims["family_id"])
        except RevocationStoreUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc

        if revoked_in_redis:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked.",
            )

        async with pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT id, mobile, status, is_mobile_verified FROM users WHERE id = $1",
                claims["user_id"],
            )
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found.",
                )
            if user["status"] != "ACTIVE":
                try:
                    await session_svc.revoke_session_family(
                        claims["family_id"], reason="ACCOUNT_BLOCKED"
                    )
                except RevocationStoreUnavailableError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=str(exc),
                    ) from exc
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account access unavailable.",
                )

            family_active = await session_svc.verify_active_family(
                claims["family_id"], claims["user_id"]
            )
            if not family_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has expired or was revoked.",
                )

            try:
                authoritative_roles = await rbac.get_user_roles(conn, user["id"])
            except RbacAccessDeniedError as exc:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

            user_dict = dict(user)
            user_dict["roles"] = sorted(list(authoritative_roles))
            user_dict["session_id"] = str(claims["session_id"])
            user_dict["session_family_id"] = claims["family_id"]
            return user_dict

    try:
        session = await session_svc.verify_active_session(raw_token)
    except RevocationStoreUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or was revoked.",
        )

    try:
        if is_family_revoked_in_redis(r, session["family_id"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked.",
            )
    except RevocationStoreUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT id, mobile, status, is_mobile_verified FROM users WHERE id = $1",
            session["user_id"],
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found.",
            )
        if user["status"] != "ACTIVE":
            try:
                await session_svc.revoke_session_family(
                    session["family_id"], reason="ACCOUNT_BLOCKED"
                )
            except RevocationStoreUnavailableError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(exc),
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account access unavailable.",
            )

        try:
            authoritative_roles = await rbac.get_user_roles(conn, user["id"])
        except RbacAccessDeniedError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

        user_dict = dict(user)
        user_dict["roles"] = sorted(list(authoritative_roles))
        user_dict["session_id"] = session["id"]
        user_dict["session_family_id"] = session["family_id"]
        return user_dict


def require_permission(permission_id: str):
    """Factory dependency for fine-grained RBAC permission checks backed by `user_roles`."""
    async def dependency(
        current_user: Dict[str, Any] = Depends(get_current_user),
        pool: asyncpg.Pool = Depends(get_db_pool),
    ):
        rbac = RbacEngine(pool)
        user_id = current_user["id"]
        has_perm = await rbac.has_permission(user_id, permission_id)
        if not has_perm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: Missing required permission '{permission_id}'.",
            )
        return current_user

    return dependency
