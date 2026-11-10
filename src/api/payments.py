"""
Payments & Subscriptions API Endpoints (PAY-001..011, AC-06, BR-15)
Provides order creation, payment fulfillment, automatic membership activation,
and affiliate referral commission distribution.
"""

import uuid
from typing import Any, Dict

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.deps import get_current_user, get_db_pool
from src.payments.service import InvalidPaymentStateError, OrderNotFoundError, PaymentError, PaymentService

router = APIRouter(prefix="/payments", tags=["Payments & Orders"])


class CreateOrderSchema(BaseModel):
    holder_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    plan_id: uuid.UUID = Field(..., example="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    idempotency_key: str = Field(..., min_length=5, max_length=100, example="ORD-IDEM-001")
    payment_method: str = Field("GATEWAY", example="GATEWAY")
    sales_case_id: uuid.UUID | None = Field(None, example=None)
    gateway_name: str | None = Field("ZARINPAL", example="ZARINPAL")


class VerifyPaymentSchema(BaseModel):
    gateway_transaction_id: str = Field(..., example="TX-998877")
    gateway_tracking_code: str = Field(..., example="TRK-112233")
    referral_code: str | None = Field(None, example="HAMI-ABC123")


@router.post("/orders")
async def create_order(
    payload: CreateOrderSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Creates a new pending order for a discount plan with strict idempotency."""
    payment_svc = PaymentService(pool)
    try:
        order = await payment_svc.create_order(
            buyer_user_id=current_user["id"],
            holder_id=payload.holder_id,
            plan_id=payload.plan_id,
            idempotency_key=payload.idempotency_key,
            payment_method=payload.payment_method,
            sales_case_id=payload.sales_case_id,
            gateway_name=payload.gateway_name
        )
        return {"success": True, "order": order}
    except PaymentError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/orders/{order_id}/verify")
async def verify_payment(
    order_id: uuid.UUID,
    payload: VerifyPaymentSchema,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Verifies payment success, activates card holder membership,
    and distributes referrer commissions (AC-06).
    """
    payment_svc = PaymentService(pool)
    try:
        result = await payment_svc.verify_and_fulfill_payment(
            order_id=order_id,
            gateway_transaction_id=payload.gateway_transaction_id,
            gateway_tracking_code=payload.gateway_tracking_code,
            verified_by=current_user["id"],
            referral_code=payload.referral_code
        )
        return {"success": True, **result}
    except OrderNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except InvalidPaymentStateError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PaymentError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/orders/{order_id}")
async def get_order(
    order_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves order details by ID."""
    payment_svc = PaymentService(pool)
    try:
        return await payment_svc.get_order_by_id(order_id)
    except OrderNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
