"""
Visits API Endpoints (VISIT-001..013, AC-07, AC-08)
Allows authenticated doctors to record visits with atomic quota decrements,
and supports visit cancellation with automatic quota restoration.
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool, require_permission
from src.core.policy import PolicyNotApprovedError
from src.visits.service import (
    MembershipInactiveError,
    QuotaExhaustedError,
    VisitCancellationError,
    VisitError,
    VisitService,
)

router = APIRouter(prefix="/visits", tags=["Visits & Quota Consumption"])


class RecordVisitSchema(BaseModel):
    doctor_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    holder_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    membership_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    service_title: str = Field(..., min_length=2, max_length=255, example="ویزیت تخصصی قلب و عروق")
    total_amount_toman: int = Field(..., ge=0, example=450000)
    discount_percent: float = Field(..., ge=0, le=100, example=30.0)
    private_notes: str | None = Field(None, example="معاینه و نوار قلب انجام شد")


class CancelVisitSchema(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, example="ثبت اشتباه خدمات توسط منشی")


@router.post("/record")
async def record_visit(
    payload: RecordVisitSchema,
    current_user: Dict[str, Any] = Depends(require_permission("visits:record")),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Records a medical visit and atomically decrements remaining membership visits (AC-07).
    Guarantees zero negative visits or overselling under race conditions.
    """
    visit_svc = VisitService(pool)
    try:
        result = await visit_svc.record_visit(
            doctor_id=payload.doctor_id,
            holder_id=payload.holder_id,
            membership_id=payload.membership_id,
            service_title=payload.service_title,
            total_amount_toman=payload.total_amount_toman,
            discount_percent=payload.discount_percent,
            private_notes=payload.private_notes
        )
        return {"success": True, "visit": result}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except QuotaExhaustedError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except MembershipInactiveError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{visit_id}/cancel")
async def cancel_visit(
    visit_id: uuid.UUID,
    payload: CancelVisitSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Cancels a visit, atomically rolls back quota consumption, and logs an audit trail.
    """
    visit_svc = VisitService(pool)
    try:
        cancelled = await visit_svc.cancel_visit(
            visit_id=visit_id,
            canceller_user_id=current_user["id"],
            reason=payload.reason
        )
        return {"success": True, "visit": cancelled}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitCancellationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{visit_id}")
async def get_visit_details(
    visit_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves single visit with detailed financial breakdown."""
    visit_svc = VisitService(pool)
    try:
        return await visit_svc.get_visit_by_id(visit_id)
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/doctor/{doctor_id}")
async def list_doctor_visits(
    doctor_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Lists visits handled by a doctor with pagination."""
    visit_svc = VisitService(pool)
    return await visit_svc.list_doctor_visits(doctor_id, limit=limit, offset=offset)
