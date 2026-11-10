"""
User Profiles API Endpoints (PROFILE-001..012)
"""

from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool
from src.profiles.service import ProfileService, ProfileValidationError

router = APIRouter(prefix="/profile", tags=["User Profiles"])


class ProfileUpdateSchema(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100, example="علی")
    last_name: str = Field(..., min_length=1, max_length=100, example="محمدی")
    national_code: str | None = Field(None, example="0012345678")
    birth_date: str | None = Field(None, example="1370-05-12")
    gender: str | None = Field(None, example="MALE")
    province_id: int | None = Field(None, example=1)
    city_id: int | None = Field(None, example=1)
    address: str | None = Field(None, example="خیابان ولیعصر، پلاک ۱۰")
    postal_code: str | None = Field(None, example="1234567890")
    bank_card_number: str | None = Field(None, example="6037991812345678")
    bank_sheba_number: str | None = Field(None, example="IR120120000000001234567890")
    bank_account_holder_name: str | None = Field(None, example="علی محمدی")


@router.get("/me")
async def get_my_profile(
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Returns profile of the authenticated user (unmasked for self)."""
    prof_svc = ProfileService(pool)
    # Own profile is viewed with admin override so self-fields are unmasked
    profile = await prof_svc.get_profile(current_user["id"], viewer_roles=["ADMIN"])
    if not profile:
        return {
            "user_id": str(current_user["id"]),
            "mobile": current_user["mobile"],
            "roles": current_user["roles"],
            "has_profile": False
        }
    return {**profile, "has_profile": True}


@router.put("/me")
async def update_my_profile(
    payload: ProfileUpdateSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Updates authenticated user's profile with strict Iranian identity & banking checks."""
    prof_svc = ProfileService(pool)
    try:
        updated = await prof_svc.upsert_profile(
            user_id=current_user["id"],
            first_name=payload.first_name,
            last_name=payload.last_name,
            national_code=payload.national_code,
            birth_date=payload.birth_date,
            gender=payload.gender,
            province_id=payload.province_id,
            city_id=payload.city_id,
            address=payload.address,
            postal_code=payload.postal_code,
            bank_card_number=payload.bank_card_number,
            bank_sheba_number=payload.bank_sheba_number,
            bank_account_holder_name=payload.bank_account_holder_name
        )
        return {"success": True, "profile": updated}
    except ProfileValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
