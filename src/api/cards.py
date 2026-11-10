"""
Cards API Router (CARD-001..015, BR-13..15)
REMEDIATION: HC-T19 (F-12 HIGH, CARD_QR_STATIC_SECRET_FALLBACK, T19-AC3..AC5)

Provides ownership-enforced virtual card retrieval and APPROVED-doctor QR verification.
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool, require_permission
from src.cards.service import (
    CardAuthorizationError,
    CardConfigurationError,
    CardService,
    InvalidQrSignatureError,
    MembershipNotFoundError,
)

router = APIRouter(prefix="/cards", tags=["Digital Membership Cards"])


class VerifyQrSchema(BaseModel):
    qr_payload: str = Field(
        ...,
        min_length=10,
        max_length=200,
        example="HAMICARD:v1:3fa85f64-5717-4562-b3fc-2c963f66afa6:a1b2c3d4e5f60718901234567890abcd",
    )


def _init_card_service(pool: asyncpg.Pool) -> CardService:
    try:
        return CardService(pool)
    except CardConfigurationError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Card signing service unavailable due to missing secure configuration.",
        ) from e


@router.get("/membership/{membership_id}")
async def get_membership_card(
    membership_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Returns virtual membership card with signed QR payload strictly for owner/admin/support."""
    card_svc = _init_card_service(pool)
    try:
        card = await card_svc.get_virtual_card(
            membership_id=membership_id,
            actor_user_id=current_user["id"],
        )
        return {"success": True, "card": card}
    except CardAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except MembershipNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/verify-qr")
async def verify_card_qr(
    payload: VerifyQrSchema,
    current_user: Dict[str, Any] = Depends(require_permission("visits:record")),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Clinic/Doctor scan verification endpoint (requires APPROVED DOCTOR or ADMIN).
    Validates constant-time QR HMAC signature and returns masked eligibility data.
    """
    card_svc = _init_card_service(pool)
    try:
        result = await card_svc.verify_qr_scan(
            qr_payload=payload.qr_payload,
            actor_user_id=current_user["id"],
        )
        return result
    except CardAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidQrSignatureError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except MembershipNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
