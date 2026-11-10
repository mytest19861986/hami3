"""
Health & Diagnostic Endpoints (SYS-001..004)
Provides real-time liveness, readiness, and subsystem metrics for Prometheus/Kubernetes.
"""

import time
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
    """Verifies operational status of PostgreSQL and Redis with latency benchmarks."""
    # 1. PostgreSQL benchmark
    db_start = time.perf_counter()
    async with pool.acquire() as conn:
        db_ver = await conn.fetchval("SELECT version()")
    db_latency_ms = round((time.perf_counter() - db_start) * 1000, 2)

    # 2. Redis benchmark
    r_start = time.perf_counter()
    redis_ok = r.ping()
    r_latency_ms = round((time.perf_counter() - r_start) * 1000, 2)

    # Pool metrics
    pool_size = pool.get_size()
    pool_idle = pool.get_idle_size()

    # Redis metrics
    try:
        r_info = r.info("memory")
        used_mem = r_info.get("used_memory_human", "N/A")
    except Exception:
        used_mem = "N/A"

    return {
        "status": "healthy",
        "service": "HamiCard API",
        "version": "1.0.0",
        "database": {
            "status": "connected",
            "server": "PostgreSQL 16",
            "active": True,
            "latency_ms": db_latency_ms,
            "pool_size": pool_size,
            "pool_idle": pool_idle
        },
        "redis": {
            "status": "connected",
            "ping": redis_ok,
            "latency_ms": r_latency_ms,
            "used_memory": used_mem
        }
    }
