"""
FastAPI Dependencies & Context Injections
Provides database connection pools, Redis ephemeral cache,
authentication context, and RBAC security enforcement.
"""

import os
import uuid
from typing import Dict, Any, Optional
import asyncpg
import redis
from fastapi import Header, HTTPException, status, Depends

from src.auth.service import AuthService
from src.auth.session_service import SessionService
from src.auth.rbac import RbacEngine

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Global state holders for app lifespan
_pool: Optional[asyncpg.Pool] = None
_redis: Optional[redis.Redis] = None


async def init_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=5, max_size=20)
    return _pool


async def close_pool():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def init_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)
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
    authorization: Optional[str] = Header(None),
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis)
) -> Dict[str, Any]:
    """
    Extracts authenticated user from Bearer session token.
    Enforces active user and active session state (AC-14).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header."
        )

    raw_token = authorization.split(" ")[1].strip()
    session_svc = SessionService(pool)
    session = await session_svc.verify_active_session(raw_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or was revoked."
        )

    # Fetch user details
    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT id, mobile, status, roles, is_mobile_verified FROM users WHERE id = $1",
            session["user_id"]
        )
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")
        if user["status"] != "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User account is {user['status']}."
            )

        return dict(user)


def require_permission(permission_id: str):
    """Factory dependency for fine-grained RBAC permission checks."""
    async def dependency(
        current_user: Dict[str, Any] = Depends(get_current_user),
        pool: asyncpg.Pool = Depends(get_db_pool)
    ):
        rbac = RbacEngine(pool)
        user_id = current_user["id"]
        has_perm = await rbac.has_permission(user_id, permission_id)
        if not has_perm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: Missing required permission '{permission_id}'."
            )
        return current_user
    return dependency
