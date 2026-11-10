"""
Cards API Router (CARD-001..015, BR-13..15)
Provides virtual card details and QR scan verification for clinics.
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool, require_permission
from src.cards.service import CardService, InvalidQrSignatureError, MembershipNotFoundError

router = APIRouter(prefix="/cards", tags=["Digital Membership Cards"])


class VerifyQrSchema(BaseModel):
    qr_payload: str = Field(..., min_length=10, max_length=200, example="HAMICARD:v1:3fa85f64-5717-4562-b3fc-2c963f66afa6:a1b2c3d4e5f60718")


@router.get("/membership/{membership_id}")
async def get_membership_card(
    membership_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Returns virtual membership card with signed QR payload and dynamic PII masking."""
    card_svc = CardService(pool)
    try:
        user_role = current_user.get("roles", ["USER"])[0] if current_user.get("roles") else "USER"
        card = await card_svc.get_virtual_card(membership_id, requesting_role=user_role)
        return {"success": True, "card": card}
    except MembershipNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/verify-qr")
async def verify_card_qr(
    payload: VerifyQrSchema,
    current_user: Dict[str, Any] = Depends(require_permission("visits:record")),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Clinic/Doctor scan verification endpoint.
    Validates QR signature and returns instant eligibility and remaining visit balance.
    """
    card_svc = CardService(pool)
    try:
        result = await card_svc.verify_qr_scan(payload.qr_payload)
        return result
    except InvalidQrSignatureError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except MembershipNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

