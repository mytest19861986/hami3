"""
Payments & Subscriptions API Endpoints (PAY-001..011, AC-06, BR-15)
REMEDIATION: HC-T17 (F-11 CRITICAL, F-12 HIGH, T17-AC1..AC5)

Provides:
- POST /payments/orders (ownership & idempotency hardened)
- POST /payments/orders/{order_id}/initiate (gateway authority issuance)
- POST /payments/orders/{order_id}/verify (strict trusted gateway verification only)
- POST /payments/orders/{order_id}/manual-confirm (explicit audited ADMIN/SUPER_ADMIN manual confirm)
- GET  /payments/orders/{order_id} (strict ownership/privileged RBAC & PII masking)
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.adapters.payment import (
    BasePaymentGateway,
    PaymentGatewayError,
    get_runtime_payment_gateway,
)
from src.api.deps import get_current_user, get_db_pool
from src.core.policy import PolicyNotApprovedError
from src.payments.service import (
    DuplicateOrderError,
    DuplicatePaymentProofError,
    InvalidPaymentStateError,
    OrderNotFoundError,
    PaymentAuthorizationError,
    PaymentError,
    PaymentService,
    UnverifiedPaymentError,
)

router = APIRouter(prefix="/payments", tags=["Payments & Orders"])


def get_payment_gateway_dep() -> BasePaymentGateway:
    """FastAPI dependency returning active fail-closed payment gateway adapter."""
    try:
        return get_runtime_payment_gateway()
    except PaymentGatewayError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


class CreateOrderSchema(BaseModel):
    holder_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    plan_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    idempotency_key: str = Field(..., min_length=5, max_length=100, example="ORD-IDEM-001")
    payment_method: str = Field("GATEWAY", example="GATEWAY")
    sales_case_id: uuid.UUID | None = Field(None, example=None)
    gateway_name: str | None = Field("ZARINPAL", example="ZARINPAL")


class InitiatePaymentSchema(BaseModel):
    callback_url: str = Field("https://hamicard.local/payments/callback", min_length=8, max_length=300)


class VerifyPaymentSchema(BaseModel):
    authority: str | None = Field(None, min_length=3, max_length=120, example="MOCK-AUTH-a1b2c3d4e5f6")
    # Retained strictly to detect and reject forged self-asserted requests (T17-AC1); never trusted!
    gateway_transaction_id: str | None = Field(None, max_length=100)
    gateway_tracking_code: str | None = Field(None, max_length=100)
    referral_code: str | None = Field(None, example="HAMI-ABC123")


class ManualConfirmPaymentSchema(BaseModel):
    payment_proof_reference: str = Field(..., min_length=6, max_length=100, example="CARD-SLIP-889911")
    reason: str = Field(..., min_length=5, max_length=500, example="تایید فیش کارت به کارت توسط واحد مالی")
    referral_code: str | None = Field(None, example="HAMI-ABC123")


@router.post("/orders")
async def create_order(
    payload: CreateOrderSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Creates a new pending order for a discount plan with strict ownership & idempotency."""
    payment_svc = PaymentService(pool)
    try:
        order = await payment_svc.create_order(
            buyer_user_id=current_user["id"],
            holder_id=payload.holder_id,
            plan_id=payload.plan_id,
            idempotency_key=payload.idempotency_key,
            payment_method=payload.payment_method,
            sales_case_id=payload.sales_case_id,
            gateway_name=payload.gateway_name,
        )
        return {"success": True, "order": order}
    except PaymentAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except DuplicateOrderError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except PaymentError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/orders/{order_id}/initiate")
async def initiate_payment(
    order_id: uuid.UUID,
    payload: InitiatePaymentSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
    gateway: BasePaymentGateway = Depends(get_payment_gateway_dep),
):
    """Initiates payment with configured gateway and binds authority to the order."""
    payment_svc = PaymentService(pool)
    try:
        res = await payment_svc.initiate_gateway_payment(
            order_id=order_id,
            actor_user_id=current_user["id"],
            callback_url=payload.callback_url,
            gateway=gateway,
        )
        return {"success": True, **res}
    except PaymentAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except OrderNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvalidPaymentStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PaymentGatewayError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except PaymentError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/orders/{order_id}/verify")
async def verify_payment(
    order_id: uuid.UUID,
    payload: VerifyPaymentSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
    gateway: BasePaymentGateway = Depends(get_payment_gateway_dep),
):
    """
    Verifies payment strictly via trusted payment gateway (`authority`),
    activates card holder membership, and distributes referral commission (AC-06).
    Self-asserted transaction identifiers without verified gateway confirmation are rejected.
    """
    payment_svc = PaymentService(pool)
    try:
        result = await payment_svc.verify_and_fulfill_payment(
            order_id=order_id,
            actor_user_id=current_user["id"],
            gateway=gateway,
            authority=payload.authority,
            referral_code=payload.referral_code,
            gateway_transaction_id=payload.gateway_transaction_id,
            gateway_tracking_code=payload.gateway_tracking_code,
        )
        return {"success": True, **result}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except PaymentAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except OrderNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DuplicatePaymentProofError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except UnverifiedPaymentError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except InvalidPaymentStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PaymentGatewayError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except PaymentError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/orders/{order_id}/manual-confirm")
async def manual_confirm_payment(
    order_id: uuid.UUID,
    payload: ManualConfirmPaymentSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Audited ADMIN/SUPER_ADMIN manual payment confirmation governed by OPEN-04 & OPEN-18."""
    payment_svc = PaymentService(pool)
    try:
        result = await payment_svc.manual_confirm_payment(
            order_id=order_id,
            actor_user_id=current_user["id"],
            payment_proof_reference=payload.payment_proof_reference,
            reason=payload.reason,
            referral_code=payload.referral_code,
        )
        return {"success": True, **result}
    except PolicyNotApprovedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except PaymentAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except OrderNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DuplicatePaymentProofError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except InvalidPaymentStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PaymentError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/orders/{order_id}")
async def get_order(
    order_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """Retrieves order details by ID with buyer/admin ownership & PII masking."""
    payment_svc = PaymentService(pool)
    try:
        return await payment_svc.get_order_by_id(
            order_id=order_id,
            actor_user_id=current_user["id"],
        )
    except PaymentAuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except OrderNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
