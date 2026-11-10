"""
Sales Cases & Logistics API Endpoints (SALE-001..013, AC-09, AC-10)
Enforces the dual state machine for agent sales:
- Logistic status updates with tracking code validation.
- Financial status finalization with automated commission distribution.
"""

import uuid
from typing import Dict, Any, Optional
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_db_pool, get_current_user, require_permission
from src.sales.service import (
    SalesCaseService,
    InvalidStateTransitionError,
    AgentNotApprovedError,
    SalesCaseError
)

router = APIRouter(prefix="/sales", tags=["Sales Cases & Logistics"])


class CreateSalesCaseSchema(BaseModel):
    agent_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    holder_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    plan_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    notes: Optional[str] = Field(None, example="پرونده ثبت شده توسط نمایندگی تهران")


class UpdateLogisticStatusSchema(BaseModel):
    status: str = Field(..., example="SHIPPED")
    shipping_tracking_code: Optional[str] = Field(None, example="123456789012345678901234")


@router.post("/cases")
async def create_sales_case(
    payload: CreateSalesCaseSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Creates a new sales case initiated by an approved agent."""
    sales_svc = SalesCaseService(pool)
    try:
        created = await sales_svc.create_sales_case(
            agent_id=payload.agent_id,
            holder_id=payload.holder_id,
            plan_id=payload.plan_id,
            notes=payload.notes
        )
        return {"success": True, "case": created}
    except AgentNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except SalesCaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/cases/{case_id}/logistic")
async def update_logistic_status(
    case_id: uuid.UUID,
    payload: UpdateLogisticStatusSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Transitions logistic state with strict invariant validation (AC-09).
    Requires tracking code for SHIPPED status.
    """
    sales_svc = SalesCaseService(pool)
    try:
        updated = await sales_svc.update_logistic_status(
            case_id=case_id,
            new_status=payload.status,
            actor_user_id=current_user["id"],
            shipping_tracking_code=payload.shipping_tracking_code
        )
        return {"success": True, "case": updated}
    except InvalidStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SalesCaseError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/cases/{case_id}/finalize")
async def finalize_financial_status(
    case_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(require_permission("commissions:approve")),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Finalizes sales case financial state, calculates agent commission,
    and atomically credits the agent's wallet (AC-10).
    """
    sales_svc = SalesCaseService(pool)
    try:
        result = await sales_svc.finalize_financial_status(
            case_id=case_id,
            actor_user_id=current_user["id"]
        )
        return {"success": True, **result}
    except InvalidStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SalesCaseError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/cases/{case_id}")
async def get_sales_case(
    case_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves full sales case details."""
    sales_svc = SalesCaseService(pool)
    try:
        return await sales_svc.get_sales_case(case_id)
    except SalesCaseError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
