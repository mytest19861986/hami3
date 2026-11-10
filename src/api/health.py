"""
Health & Diagnostic Endpoints
"""

import asyncpg
import redis
from fastapi import APIRouter, Depends

from src.api.deps import get_db_pool, get_redis

router = APIRouter(tags=["Health"])


@router.get("/health")
async def healthcheck(
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis)
):
    """Verifies operational status of PostgreSQL and Redis."""
    # Check PostgreSQL
    async with pool.acquire() as conn:
        db_ver = await conn.fetchval("SELECT version()")

    # Check Redis
    redis_ok = r.ping()

    return {
        "status": "healthy",
        "service": "HamiCard API",
        "version": "1.0.0",
        "database": {
            "status": "connected",
            "server": "PostgreSQL 16",
            "active": True
        },
        "redis": {
            "status": "connected",
            "ping": redis_ok
        }
    }
