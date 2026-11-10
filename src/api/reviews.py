"""
Doctor Reviews & Ratings API Endpoints (REVIEW-001..004)
Allows verified patients to submit clinical ratings and comments for completed visits.
Supports administrative moderation and aggregate ratings calculation.
"""

import uuid
from typing import Dict, Any, Optional
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_db_pool, get_current_user, require_permission
from src.reviews.service import (
    DoctorReviewService,
    DuplicateReviewError,
    InvalidRatingError,
    ReviewError
)

router = APIRouter(prefix="/reviews", tags=["Doctor Reviews & Ratings"])


class SubmitReviewSchema(BaseModel):
    visit_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    rating: int = Field(..., ge=1, le=5, example=5)
    comment: Optional[str] = Field(None, max_length=1000, example="دکتر بسیار خوش برخورد و حرفه‌ای بودند.")


class ModerateReviewSchema(BaseModel):
    is_published: bool = Field(..., example=True)


@router.post("")
async def submit_review(
    payload: SubmitReviewSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Submits a patient review for a completed medical visit."""
    review_svc = DoctorReviewService(pool)
    try:
        created = await review_svc.submit_review(
            visit_id=payload.visit_id,
            user_id=current_user["id"],
            rating=payload.rating,
            comment=payload.comment
        )
        return {"success": True, "review": created}
    except DuplicateReviewError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except InvalidRatingError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ReviewError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/{review_id}/moderate")
async def moderate_review(
    review_id: uuid.UUID,
    payload: ModerateReviewSchema,
    current_user: Dict[str, Any] = Depends(require_permission("doctors:verify")),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Admin approves or hides review from public directory."""
    review_svc = DoctorReviewService(pool)
    try:
        moderated = await review_svc.moderate_review(
            review_id=review_id,
            is_published=payload.is_published,
            admin_id=current_user["id"]
        )
        return {"success": True, "review": moderated}
    except ReviewError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/doctor/{doctor_id}")
async def get_doctor_reviews(
    doctor_id: uuid.UUID,
    published_only: bool = True,
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Returns reviews and aggregate average rating for a doctor (public endpoint)."""
    review_svc = DoctorReviewService(pool)
    return await review_svc.get_doctor_reviews(doctor_id, published_only=published_only)
