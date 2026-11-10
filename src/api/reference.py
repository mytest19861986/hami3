"""
Geography & Reference API Endpoints (PROFILE-004, PROFILE-005)
"""

from typing import List, Optional
import asyncpg
from fastapi import APIRouter, Depends, Query, HTTPException

from src.api.deps import get_db_pool
from src.profiles.service import ReferenceService

router = APIRouter(prefix="/reference", tags=["Geography & Reference"])


@router.get("/provinces")
async def list_provinces(pool: asyncpg.Pool = Depends(get_db_pool)):
    """Returns all 31 Iranian provinces."""
    ref_svc = ReferenceService(pool)
    return await ref_svc.get_all_provinces()


@router.get("/cities")
async def list_cities(
    province_id: Optional[int] = Query(None, description="Filter cities by province ID"),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Returns cities, optionally filtered by province ID."""
    ref_svc = ReferenceService(pool)
    if province_id is not None:
        return await ref_svc.get_cities_by_province(province_id)
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, province_id, name FROM cities ORDER BY id ASC")
        return [dict(r) for r in rows]
