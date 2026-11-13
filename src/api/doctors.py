"""
Doctors Network & Public Directory API Endpoints (DOC-001..014, AC-02)
REMEDIATION: HC-T25 (DOC-012 P0 admin-exclusive custom discount endpoint)
"""

import uuid
from decimal import Decimal
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool
from src.doctors.service import (
    DoctorAuthorizationError,
    DoctorError,
    DoctorNotFoundError,
    DoctorService,
)
from src.reviews.service import DoctorReviewService

router = APIRouter(prefix="/doctors", tags=["Doctors Network"])


class UpdateDoctorCustomDiscountSchema(BaseModel):
    custom_discount_percent: Decimal | None = Field(
        None, ge=Decimal("0"), le=Decimal("100"), example="35.00"
    )
    reason: str = Field(..., min_length=3, max_length=500, example="توافق قرارداد تخفیف اختصاصی مطب")


@router.get("")
async def search_doctors(
    province_id: int | None = Query(None, description="Province ID"),
    city_id: int | None = Query(None, description="City ID"),
    specialty: str | None = Query(None, description="Medical specialty"),
    q: str | None = Query(None, description="Search query by name or clinic"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Searches the approved public doctors network.
    Strictly filters out pending or unapproved doctors (Fail-Closed).
    """
    doc_svc = DoctorService(pool)
    return await doc_svc.search_public_directory(
        province_id=province_id,
        city_id=city_id,
        specialty=specialty,
        query=q,
        limit=limit,
        offset=offset
    )


@router.get("/me/portal")
async def get_doctor_portal(
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Retrieves the authenticated doctor's portal summary (profile, active contracts, metrics, recent visits).
    Strictly restricted to approved doctors (Fail-Closed).
    """
    doc_svc = DoctorService(pool)
    try:
        summary = await doc_svc.get_doctor_portal_summary(actor_user_id=current_user["id"])
        return {"success": True, "portal": summary}
    except DoctorAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DoctorNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DoctorError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/me/contracts")
async def get_my_doctor_contracts(
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Retrieves active authorized service contracts for the authenticated doctor."""
    doc_svc = DoctorService(pool)
    try:
        doc = await doc_svc.get_doctor_by_user_id(current_user["id"])
        if not doc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Doctor profile not found.")
        contracts = await doc_svc.list_doctor_contracts(
            doctor_id=doc["id"], actor_user_id=current_user["id"]
        )
        return {"success": True, "contracts": contracts}
    except DoctorAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DoctorNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DoctorError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{doctor_id}")
async def get_doctor_profile(
    doctor_id: uuid.UUID,
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves doctor details and clinic address."""
    doc_svc = DoctorService(pool)
    try:
        return await doc_svc.get_doctor_by_id(doctor_id)
    except DoctorNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{doctor_id}/custom-discount")
async def update_doctor_custom_discount(
    doctor_id: uuid.UUID,
    payload: UpdateDoctorCustomDiscountSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Sets or clears a doctor's custom discount percentage strictly for ADMIN / SUPER_ADMIN (`DOC-012 P0`).
    Doctors, clinic staff, and regular users are rejected with 403 Forbidden.
    """
    doc_svc = DoctorService(pool)
    try:
        updated = await doc_svc.set_custom_discount_percent(
            doctor_id=doctor_id,
            custom_discount_percent=payload.custom_discount_percent,
            actor_user_id=current_user["id"],
            reason=payload.reason,
        )
        return {"success": True, "doctor": updated}
    except DoctorAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DoctorNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DoctorError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{doctor_id}/reviews")
async def get_doctor_reviews(
    doctor_id: uuid.UUID,
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves approved reviews and average rating score for a doctor."""
    review_svc = DoctorReviewService(pool)
    return await review_svc.get_doctor_reviews(doctor_id, published_only=True)


@router.get("/{doctor_id}/contracts")
async def get_doctor_contracts(
    doctor_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Retrieves service contracts for a specific doctor strictly for owning approved doctor or admin."""
    doc_svc = DoctorService(pool)
    try:
        contracts = await doc_svc.list_doctor_contracts(
            doctor_id=doctor_id, actor_user_id=current_user["id"]
        )
        return {"success": True, "contracts": contracts}
    except DoctorAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DoctorNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DoctorError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

