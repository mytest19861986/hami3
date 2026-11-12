"""
Wallet & Settlement Lifecycle API Endpoints (WALLET-001..010, SETTLE-001..017, AC-12, BR-21)
REMEDIATION: HC-T14 (F-06, F-07), HC-T20 (T20-AC1..AC4), HC-T27 (M-2, T27-AC1..AC4)

Hardening:
- Optional `Idempotency-Key` header on settlement request, reject, and mark-paid.
- Explicit HTTP `409 Conflict` mapping for state transition errors, duplicate payout refs,
  `DuplicateFinancialTransactionError`, `IdempotencyConflictError`, and PG `23505`.
- Fail-closed policy gating (`OPEN_04`, `OPEN_06`, `OPEN_18`) returning HTTP `403`.
- Authoritative RBAC (`settlements:process`, `settlements:pay`, `OPEN_04`) blocking
  unauthorized users/SUPPORT/non-SUPER_ADMIN mark-paid (`403`).
- Documented external payout evidence verification (`BasePayoutProofVerifier`) before
  transitioning any approved settlement to `PAID`.
- Masks `bank_card_number` and `bank_sheba_number` across all HTTP settlement responses (`SETTLE-015`).
"""

import hashlib
import uuid
from datetime import datetime
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool
from src.common.pii import mask_card_number, mask_shaba
from src.common.validators import validate_iranian_card_number, validate_iranian_shaba
from src.core.policy import PolicyError, PolicyNotApprovedError, require_approved_policy
from src.wallets.service import (
    BasePayoutProofVerifier,
    DuplicateFinancialTransactionError,
    DuplicatePayoutReferenceError,
    IdempotencyConflictError,
    InsufficientFundsError,
    InvalidSettlementTransitionError,
    PayoutAdapterConfigurationError,
    PayoutVerificationError,
    SettlementAuthorizationError,
    SettlementMinimumViolationError,
    SettlementNotFoundError,
    WalletError,
    WalletFrozenError,
    WalletService,
    _is_production_env,
    get_runtime_payout_verifier,
)

router = APIRouter(prefix="/wallet", tags=["Wallet & Settlements"])


def get_payout_verifier_dep() -> BasePayoutProofVerifier | None:
    """FastAPI dependency returning active fail-closed external payout proof verifier."""
    try:
        if _is_production_env():
            return None
        return get_runtime_payout_verifier()
    except PayoutAdapterConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


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


class ApproveSettlementSchema(BaseModel):
    notes: str | None = Field(None, max_length=500, example="بررسی و تایید اولیه درخواست تسویه")


class RejectSettlementSchema(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, example="مغایرت شماره شبا با مالک حساب")


class MarkSettlementPaidSchema(BaseModel):
    external_payment_ref: str = Field(..., min_length=6, max_length=100, example="PAYA-14050101-889911")
    external_payment_date: datetime
    amount_toman: int | None = Field(None, gt=0, example=200000)
    notes: str | None = Field(None, max_length=500, example="ثبت رسید حواله پایا")


def _serialize_masked_settlement(
    row: Dict[str, Any],
    *,
    idempotent_replay: bool | None = None,
) -> Dict[str, Any]:
    res = {
        "id": row["id"],
        "user_id": row["user_id"],
        "amount_toman": row["amount_toman"],
        "bank_card_number": mask_card_number(row["bank_card_number"]),
        "bank_sheba_number": mask_shaba(row["bank_sheba_number"]),
        "bank_account_holder_name": row.get("bank_account_holder_name"),
        "status": row["status"],
        "rejection_reason": row.get("rejection_reason"),
        "external_payment_ref": row.get("external_payment_ref"),
        "external_payment_date": row.get("external_payment_date"),
        "paid_by": row.get("paid_by"),
        "created_at": row["created_at"],
        "updated_at": row.get("updated_at"),
    }
    if idempotent_replay is not None:
        res["idempotent_replay"] = idempotent_replay
    return res


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


@router.get("/settlements")
async def list_settlements(
    status_filter: str | None = Query(None, alias="status"),
    user_id: uuid.UUID | None = Query(None),
    from_date: datetime | None = Query(None),
    to_date: datetime | None = Query(None),
    search: str | None = Query(None, max_length=100),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Lists settlement requests with strict RBAC and masked banking PII (`SETTLE-013`, `SETTLE-014`, `SETTLE-015`).
    Non-admin callers only see their own settlements; SUPPORT cannot access other users' settlements.
    """
    wallet_svc = WalletService(pool)
    try:
        rows = await wallet_svc.list_settlements(
            actor_user_id=current_user["id"],
            status_filter=status_filter,
            user_id=user_id,
            from_date=from_date,
            to_date=to_date,
            applicant_query=search,
            limit=limit,
            offset=offset,
        )
        return {
            "items": [_serialize_masked_settlement(r) for r in rows],
            "count": len(rows),
        }
    except SettlementAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except WalletError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.get("/settlements/{settlement_id}")
async def get_settlement_detail(
    settlement_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Retrieves masked settlement details strictly for owner or authorized financial admin (`OPEN-10`)."""
    wallet_svc = WalletService(pool)
    try:
        row = await wallet_svc.get_settlement_detail(
            settlement_id=settlement_id,
            actor_user_id=current_user["id"],
        )
        return _serialize_masked_settlement(row)
    except SettlementAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except SettlementNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.post("/settlements/{settlement_id}/approve")
async def approve_settlement(
    settlement_id: uuid.UUID,
    payload: ApproveSettlementSchema | None = Body(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Transitions a PENDING settlement to APPROVED (financial admin `settlements:process` only)."""
    wallet_svc = WalletService(pool)
    try:
        row = await wallet_svc.approve_settlement(
            settlement_id=settlement_id,
            actor_user_id=current_user["id"],
            notes=payload.notes if payload else None,
        )
        return _serialize_masked_settlement(row)
    except (PolicyNotApprovedError, SettlementAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except PolicyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
    except SettlementNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except InvalidSettlementTransitionError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
    except WalletError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/settlements/{settlement_id}/reject")
async def reject_settlement(
    settlement_id: uuid.UUID,
    payload: RejectSettlementSchema,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Rejects an open settlement and atomically unlocks locked_balance_toman back to withdrawable ONCE.
    """
    wallet_svc = WalletService(pool)
    try:
        row = await wallet_svc.reject_settlement(
            settlement_id=settlement_id,
            actor_user_id=current_user["id"],
            reason=payload.reason,
            idempotency_key=idempotency_key,
        )
        return _serialize_masked_settlement(row, idempotent_replay=row.get("idempotent_replay", False))
    except (PolicyNotApprovedError, SettlementAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except PolicyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
    except SettlementNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except (
        InvalidSettlementTransitionError,
        DuplicateFinancialTransactionError,
        IdempotencyConflictError,
    ) as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
    except WalletError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/settlements/{settlement_id}/mark-paid")
async def mark_settlement_paid(
    settlement_id: uuid.UUID,
    payload: MarkSettlementPaidSchema,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
    verifier: BasePayoutProofVerifier | None = Depends(get_payout_verifier_dep),
):
    """
    Marks an APPROVED settlement PAID after verifying authoritative RBAC (`settlements:pay` + `OPEN_04`),
    approved policies (`OPEN_04/06/18`), and documented external bank payout evidence (`T27-AC2`).
    """
    wallet_svc = WalletService(pool)
    try:
        row = await wallet_svc.mark_settlement_paid(
            settlement_id=settlement_id,
            actor_user_id=current_user["id"],
            external_payment_ref=payload.external_payment_ref,
            external_payment_date=payload.external_payment_date,
            amount_toman=payload.amount_toman,
            notes=payload.notes,
            idempotency_key=idempotency_key,
            verifier=verifier,
        )
        return _serialize_masked_settlement(row, idempotent_replay=row.get("idempotent_replay", False))
    except (PolicyNotApprovedError, SettlementAuthorizationError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except PolicyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
    except SettlementNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except (
        InvalidSettlementTransitionError,
        DuplicatePayoutReferenceError,
        DuplicateFinancialTransactionError,
        IdempotencyConflictError,
    ) as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
    except PayoutAdapterConfigurationError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)) from e
    except PayoutVerificationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except WalletError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.post("/settle")
async def request_settlement(
    payload: SettlementRequestSchema,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Submits a settlement request for withdrawable balance in ONE atomic DB transaction.
    - Disabled (HTTP 403) if governing OPEN-06 or OPEN-18 policy is PROPOSED/BLOCKED.
    - Supports optional `Idempotency-Key` header (user-scoped, payload-checked under row lock).
    - Maps DuplicateFinancialTransactionError / IdempotencyConflictError / 23505 to HTTP 409.
    - Masks bank_card_number and bank_sheba_number in HTTP response while storing clean valid values in DB.
    """
    clean_idem: str | None = None
    if idempotency_key is not None:
        clean_idem = idempotency_key.strip()
        if len(clean_idem) < 4 or len(clean_idem) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Idempotency-Key header (must be 4 to 128 non-whitespace characters).",
            )

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

    clean_holder_name = payload.bank_account_holder_name.strip()
    wallet_svc = WalletService(pool)
    user_id = current_user["id"]
    settlement_id = uuid.uuid4()

    if clean_idem is not None:
        key_digest = hashlib.sha256(clean_idem.encode("utf-8")).hexdigest()[:32]
        ledger_idem_key = f"SETTLE-UID:{user_id.hex}:{key_digest}"
    else:
        ledger_idem_key = f"SETTLE-LOCK-{settlement_id}"

    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                # Enforce fail-closed policy gates BEFORE idempotency replay
                await require_approved_policy(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN")
                await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")

                wallet = await wallet_svc.get_or_create_wallet(user_id, conn=conn)
                wallet_id = wallet["id"]

                # Acquire exclusive per-wallet lock to serialize concurrent same-key / open-settle requests
                await conn.fetchrow("SELECT id FROM wallets WHERE id = $1 FOR UPDATE;", wallet_id)

                if clean_idem is not None:
                    existing = await wallet_svc.find_settlement_by_idempotency_key(
                        conn=conn,
                        user_id=user_id,
                        idempotency_key=ledger_idem_key,
                    )
                    if existing is not None:
                        same_payload = (
                            existing["amount_toman"] == payload.amount_toman
                            and existing["bank_card_number"] == clean_card
                            and existing["bank_sheba_number"] == clean_sheba
                            and existing["bank_account_holder_name"] == clean_holder_name
                        )
                        if not same_payload:
                            raise IdempotencyConflictError(
                                "Idempotency-Key was already used with a different settlement payload."
                            )
                        return _serialize_masked_settlement(existing, idempotent_replay=True)

                # Execute fund lock on SAME transaction connection (F-07 atomicity fix)
                await wallet_svc.lock_funds_for_settlement(
                    user_id=user_id,
                    amount_toman=payload.amount_toman,
                    settlement_id=settlement_id,
                    idempotency_key=ledger_idem_key,
                    conn=conn,
                )

                # Insert settlement record; UniqueViolationError rolls back the ENTIRE transaction above!
                row = await conn.fetchrow(
                    """
                    INSERT INTO settlements (
                        id, user_id, wallet_id, amount_toman, bank_card_number,
                        bank_sheba_number, bank_account_holder_name, status
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING')
                    RETURNING id, user_id, wallet_id, amount_toman, bank_card_number,
                              bank_sheba_number, bank_account_holder_name, status,
                              rejection_reason, external_payment_ref, external_payment_date,
                              paid_by, created_at, updated_at
                    """,
                    settlement_id,
                    user_id,
                    wallet_id,
                    payload.amount_toman,
                    clean_card,
                    clean_sheba,
                    clean_holder_name,
                )
                return _serialize_masked_settlement(dict(row), idempotent_replay=False)
        except PolicyNotApprovedError as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
        except PolicyError as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e
        except (DuplicateFinancialTransactionError, IdempotencyConflictError) as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
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
