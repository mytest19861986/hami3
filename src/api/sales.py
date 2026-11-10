"""
Sales Cases & Logistics API Endpoints (SALE-001..013, AC-09, AC-10)
REMEDIATION: HC-T19 (F-12 HIGH, T19-AC1, T19-AC2, T19-AC5)

Enforces ownership, authoritative agent identity binding, admin-only logistics & financial
state transitions, and PII masking for non-admin readers.
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool, require_permission
from src.core.policy import PolicyNotApprovedError
from src.sales.service import (
    AgentNotApprovedError,
    InvalidStateTransitionError,
    SalesAuthorizationError,
    SalesCaseError,
    SalesCaseNotFoundError,
    SalesCaseService,
)

router = APIRouter(prefix="/sales", tags=["Sales Cases & Logistics"])


class CreateSalesCaseSchema(BaseModel):
    agent_id: uuid.UUID | None = Field(None, example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    holder_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    plan_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    notes: str | None = Field(None, example="پرونده ثبت شده توسط نمایندگی تهران")


class UpdateLogisticStatusSchema(BaseModel):
    status: str = Field(..., example="SHIPPED")
    shipping_tracking_code: str | None = Field(None, example="123456789012345678901234")


@router.post("/cases")
async def create_sales_case(
    payload: CreateSalesCaseSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Creates a new sales case bound authoritatively to authenticated APPROVED agent."""
    sales_svc = SalesCaseService(pool)
    try:
        created = await sales_svc.create_sales_case(
            holder_id=payload.holder_id,
            plan_id=payload.plan_id,
            actor_user_id=current_user["id"],
            agent_id=payload.agent_id,
            notes=payload.notes,
        )
        return {"success": True, "case": created}
    except (AgentNotApprovedError, SalesAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except SalesCaseNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SalesCaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/cases/{case_id}/logistic")
async def update_logistic_status(
    case_id: uuid.UUID,
    payload: UpdateLogisticStatusSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Transitions logistic state strictly for ADMIN / SUPER_ADMIN with invariant validation (AC-09).
    Requires tracking code for SHIPPED status.
    """
    sales_svc = SalesCaseService(pool)
    try:
        updated = await sales_svc.update_logistic_status(
            case_id=case_id,
            new_status=payload.status,
            actor_user_id=current_user["id"],
            shipping_tracking_code=payload.shipping_tracking_code,
        )
        return {"success": True, "case": updated}
    except SalesAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SalesCaseNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SalesCaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/cases/{case_id}/finalize")
async def finalize_financial_status(
    case_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(require_permission("commissions:approve")),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Finalizes sales case financial state (`commissions:approve`),
    calculates exact Decimal agent commission, and credits agent wallet atomically (AC-10).
    """
    sales_svc = SalesCaseService(pool)
    try:
        result = await sales_svc.finalize_financial_status(
            case_id=case_id,
            actor_user_id=current_user["id"],
        )
        return {"success": True, **result}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except SalesAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidStateTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SalesCaseNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SalesCaseError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/cases/{case_id}")
async def get_sales_case(
    case_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Retrieves sales case strictly for owning APPROVED agent, ADMIN, or SUPPORT with PII masking."""
    sales_svc = SalesCaseService(pool)
    try:
        return await sales_svc.get_sales_case(
            case_id=case_id,
            actor_user_id=current_user["id"],
        )
    except SalesAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except SalesCaseNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
