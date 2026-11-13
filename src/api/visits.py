"""
Visits API Endpoints (VISIT-001..013, AC-07, AC-08)
REMEDIATION: HC-T18 (F-08, F-09, F-10 HIGH, T18-AC1..AC5), HC-T25 (D-2 VISIT-009, OPEN-02)

Guarantees:
- Derives/validates doctor identity from authenticated actor (`doctor_id` spoofing -> 403).
- Derives effective discount percentage on the server from DB plan/doctor rates & OPEN-02 precedence;
  client-supplied `discount_percent` is non-authoritative and ignored.
- Visit cancellation requires explicit `visits:cancel` RBAC permission at API & service boundaries.
- Detail & doctor listing endpoints enforce strict ownership / privacy filtering and PII masking.
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool, require_permission
from src.core.policy import PolicyNotApprovedError
from src.doctors.service import DoctorService
from src.visits.service import (
    DuplicateVisitError,
    MembershipInactiveError,
    QuotaExhaustedError,
    VisitAuthorizationError,
    VisitCancellationError,
    VisitError,
    VisitNotFoundError,
    VisitService,
)

router = APIRouter(prefix="/visits", tags=["Visits & Quota Consumption"])


class RecordVisitSchema(BaseModel):
    doctor_id: uuid.UUID | None = Field(None, example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    holder_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    membership_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    service_title: str = Field(..., min_length=2, max_length=255, example="ویزیت تخصصی قلب و عروق")
    total_amount_toman: int = Field(..., ge=0, example=450000)
    discount_percent: float | None = Field(
        None,
        description="Deprecated client-side hint ignored by server-derived discount engine (VISIT-009).",
        example=30.0,
    )
    private_notes: str | None = Field(None, example="معاینه و نوار قلب انجام شد")
    idempotency_key: str | None = Field(None, example="idem-uuid-98765")


class InquirePatientSchema(BaseModel):
    membership_id: uuid.UUID | None = Field(None, example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    national_code: str | None = Field(None, example="0012345678")
    card_number: str | None = Field(None, example="HAMI-1405-00012345")


class CancelVisitSchema(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, example="ثبت اشتباه خدمات توسط منشی")


@router.post("/inquire")
async def inquire_patient(
    payload: InquirePatientSchema,
    current_user: Dict[str, Any] = Depends(require_permission("visits:record")),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Inquires patient eligibility, remaining quota, and effective discount rate for an approved doctor.
    Masks patient national code to enforce clinical privacy.
    """
    visit_svc = VisitService(pool)
    try:
        result = await visit_svc.inquire_patient_eligibility(
            actor_user_id=current_user["id"],
            membership_id=payload.membership_id,
            national_code=payload.national_code,
            card_number=payload.card_number,
        )
        return {"success": True, "eligibility": result}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/record")
async def record_visit(
    payload: RecordVisitSchema,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    current_user: Dict[str, Any] = Depends(require_permission("visits:record")),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Records a medical visit for the authenticated APPROVED doctor (or authorized ADMIN override)
    and atomically decrements remaining membership visits (AC-07).
    Guarantees duplicate prevention / idempotency defense.
    """
    visit_svc = VisitService(pool)
    resolved_key = idempotency_key or payload.idempotency_key
    try:
        result = await visit_svc.record_visit(
            holder_id=payload.holder_id,
            membership_id=payload.membership_id,
            service_title=payload.service_title,
            total_amount_toman=payload.total_amount_toman,
            discount_percent=payload.discount_percent,
            actor_user_id=current_user["id"],
            doctor_id=payload.doctor_id,
            private_notes=payload.private_notes,
            idempotency_key=resolved_key,
        )
        return {"success": True, "visit": result}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DuplicateVisitError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except QuotaExhaustedError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except MembershipInactiveError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except VisitNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{visit_id}/cancel")
async def cancel_visit(
    visit_id: uuid.UUID,
    payload: CancelVisitSchema,
    current_user: Dict[str, Any] = Depends(require_permission("visits:cancel")),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Cancels a visit (strictly `visits:cancel` authorized ADMIN/SUPER_ADMIN),
    atomically rolls back quota at most once, and records actual actor in audit logs.
    """
    visit_svc = VisitService(pool)
    try:
        cancelled = await visit_svc.cancel_visit(
            visit_id=visit_id,
            canceller_user_id=current_user["id"],
            reason=payload.reason,
        )
        return {"success": True, "visit": cancelled}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitCancellationError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except VisitNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/my-visits")
async def list_my_doctor_visits(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Retrieves visit records strictly for the authenticated APPROVED doctor.
    Enforces server-side doctor identity derivation and PII masking.
    """
    visit_svc = VisitService(pool)
    doc_svc = DoctorService(pool)
    try:
        doc = await doc_svc.get_doctor_by_user_id(current_user["id"])
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor profile not found for authenticated user.",
            )
        return await visit_svc.list_doctor_visits(
            doctor_id=doc["id"],
            actor_user_id=current_user["id"],
            limit=limit,
            offset=offset,
        )
    except VisitAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{visit_id}")
async def get_visit_details(
    visit_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Retrieves single visit strictly for authorized owner/admin with PII privacy filtering."""
    visit_svc = VisitService(pool)
    try:
        return await visit_svc.get_visit_by_id(
            visit_id=visit_id,
            actor_user_id=current_user["id"],
        )
    except VisitAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/doctor/{doctor_id}")
async def list_doctor_visits(
    doctor_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Lists visits handled by a doctor strictly for the owning APPROVED doctor, ADMIN, or SUPPORT."""
    visit_svc = VisitService(pool)
    try:
        return await visit_svc.list_doctor_visits(
            doctor_id=doctor_id,
            actor_user_id=current_user["id"],
            limit=limit,
            offset=offset,
        )
    except VisitAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VisitNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except VisitError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
