"""
Wallet & Settlement Requests API Endpoints (WALLET-001..010, SETTLE-001..017, AC-12, BR-21)
REMEDIATION: HC-T14 (F-06, F-07, T14-AC1..AC4)

Fixes:
- Removes hardcoded 100,000 Toman request validation in favor of dynamic OPEN-06 policy lookup
  while enforcing strict `gt=0` schema and SQL `amount_toman > 0` check.
- Disables settlement financial requests (HTTP 403) until governing policies
  (`OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN`, `OPEN_18_CURRENCY_AND_ROUNDING`) are APPROVED.
- Executes wallet fund lock AND `INSERT INTO settlements` on the SAME connection & single
  PostgreSQL transaction so SQLSTATE `23505` rolls back BOTH atomically (zero double lock)
  and returns deterministic HTTP `409 Conflict`.
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool
from src.common.validators import validate_iranian_card_number, validate_iranian_shaba
from src.core.policy import PolicyError, PolicyNotApprovedError
from src.wallets.service import (
    InsufficientFundsError,
    SettlementMinimumViolationError,
    WalletError,
    WalletFrozenError,
    WalletService,
)

router = APIRouter(prefix="/wallet", tags=["Wallet & Settlements"])


class SettlementRequestSchema(BaseModel):
    amount_toman: int = Field(
        ...,
        gt=0,
        example=200000,
        description="Positive settlement amount in Toman; minimum governed by approved OPEN-06 policy.",
    )
    bank_card_number: str = Field(..., example="6037991812345678")
    bank_sheba_number: str = Field(..., example="IR120120000000001234567890")
    bank_account_holder_name: str = Field(..., min_length=3, example="علی محمدی")


@router.get("/me")
async def get_my_wallet(
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Returns wallet balance of the authenticated user."""
    wallet_svc = WalletService(pool)
    return await wallet_svc.get_or_create_wallet(current_user["id"])


@router.get("/ledger")
async def get_my_ledger(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Returns immutable financial ledger statement."""
    wallet_svc = WalletService(pool)
    return await wallet_svc.get_ledger_history(current_user["id"], limit=limit, offset=offset)


@router.post("/settle")
async def request_settlement(
    payload: SettlementRequestSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Submits a settlement request for withdrawable balance in ONE atomic DB transaction.
    - Disabled (HTTP 403) if governing OPEN-06 or OPEN-18 policy is PROPOSED/BLOCKED.
    - Enforces dynamic approved OPEN-06 minimum without hardcoded SQL constraints.
    - Maps PostgreSQL 23505 unique open-settlement conflict to HTTP 409 with full rollback
      so balance is NEVER reserved twice.
    """
    clean_card = payload.bank_card_number.replace("-", "").replace(" ", "").strip()
    if not validate_iranian_card_number(clean_card):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 16-digit bank card number (Luhn validation failed).",
        )

    clean_sheba = payload.bank_sheba_number.replace(" ", "").strip().upper()
    if not validate_iranian_shaba(clean_sheba):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Iranian Sheba number (ISO 7064 validation failed).",
        )

    wallet_svc = WalletService(pool)
    user_id = current_user["id"]
    settlement_id = uuid.uuid4()
    idem_key = f"SETTLE-LOCK-{settlement_id}"

    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                wallet = await wallet_svc.get_or_create_wallet(user_id, conn=conn)
                wallet_id = wallet["id"]

                # Execute fund lock on SAME transaction connection (F-07 atomicity fix)
                await wallet_svc.lock_funds_for_settlement(
                    user_id=user_id,
                    amount_toman=payload.amount_toman,
                    settlement_id=settlement_id,
                    idempotency_key=idem_key,
                    conn=conn,
                )

                # Insert settlement record; UniqueViolationError rolls back the ENTIRE transaction above!
                row = await conn.fetchrow(
                    """
                    INSERT INTO settlements (
                        id, user_id, wallet_id, amount_toman, bank_card_number,
                        bank_sheba_number, bank_account_holder_name, status
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING')
                    RETURNING id, user_id, amount_toman, bank_card_number, bank_sheba_number, status, created_at
                    """,
                    settlement_id,
                    user_id,
                    wallet_id,
                    payload.amount_toman,
                    clean_card,
                    clean_sheba,
                    payload.bank_account_holder_name.strip(),
                )
                return dict(row)
        except PolicyNotApprovedError as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
        except PolicyError as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
        except SettlementMinimumViolationError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        except InsufficientFundsError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        except WalletFrozenError as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
        except WalletError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
        except asyncpg.UniqueViolationError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="شما در حال حاضر یک درخواست تسویه باز در سامانه دارید. تا زمان تکمیل یا رد آن، ثبت درخواست جدید مجاز نیست (AC-12).",
            ) from e
