"""
Discount Plans & Storefront API Endpoints (PLAN-001..013)
"""

import uuid
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from src.api.deps import get_db_pool
from src.plans.service import DiscountPlanService, PlanNotFoundError

router = APIRouter(prefix="/plans", tags=["Discount Plans"])


@router.get("")
async def list_active_plans(pool: asyncpg.Pool = Depends(get_db_pool)):
    """Returns active discount plans available for purchase."""
    plan_svc = DiscountPlanService(pool)
    return await plan_svc.get_active_catalog()


@router.get("/{plan_id}")
async def get_plan_details(
    plan_id: uuid.UUID,
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves specific plan details."""
    plan_svc = DiscountPlanService(pool)
    try:
        return await plan_svc.get_plan_by_id(plan_id)
    except PlanNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
