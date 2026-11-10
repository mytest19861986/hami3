"""
Doctors Network & Public Directory API Endpoints (DOC-001..014, AC-02)
"""

import uuid
from typing import Optional
import asyncpg
from fastapi import APIRouter, Depends, Query, HTTPException, status

from src.api.deps import get_db_pool
from src.doctors.service import DoctorService, DoctorNotFoundError
from src.reviews.service import DoctorReviewService

router = APIRouter(prefix="/doctors", tags=["Doctors Network"])


@router.get("")
async def search_doctors(
    province_id: Optional[int] = Query(None, description="Province ID"),
    city_id: Optional[int] = Query(None, description="City ID"),
    specialty: Optional[str] = Query(None, description="Medical specialty"),
    q: Optional[str] = Query(None, description="Search query by name or clinic"),
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


@router.get("/{doctor_id}/reviews")
async def get_doctor_reviews(
    doctor_id: uuid.UUID,
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves approved reviews and average rating score for a doctor."""
    review_svc = DoctorReviewService(pool)
    return await review_svc.get_doctor_reviews(doctor_id, published_only=True)
