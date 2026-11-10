"""
Orders & Payments Domain Service (PAY-001..011, AC-06, BR-15)
Handles subscription purchases, payment gateway idempotency,
automatic membership activation upon success, and referral commission distribution.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict

import asyncpg

from src.wallets.service import WalletService


class PaymentError(Exception):
    """Base exception for payment operations."""
    pass


class OrderNotFoundError(PaymentError):
    """Raised when order does not exist."""
    pass


class InvalidPaymentStateError(PaymentError):
    """Raised when attempting invalid order transition."""
    pass


class DuplicateOrderError(PaymentError):
    """Raised on idempotency key replay."""
    pass


class PaymentService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.wallet_svc = WalletService(pool)

    async def create_order(
        self,
        buyer_user_id: uuid.UUID,
        holder_id: uuid.UUID,
        plan_id: uuid.UUID,
        idempotency_key: str,
        payment_method: str = "GATEWAY",
        sales_case_id: uuid.UUID | None = None,
        gateway_name: str | None = "ZARINPAL"
    ) -> Dict[str, Any]:
        """Creates a pending order for a discount plan with strict idempotency."""
        async with self.pool.acquire() as conn:
            # 1. Fetch plan
            plan = await conn.fetchrow(
                "SELECT id, price_toman, is_active FROM discount_plans WHERE id = $1", plan_id
            )
            if not plan or not plan["is_active"]:
                raise PaymentError("Selected discount plan is inactive or does not exist.")

            # 2. Check holder
            holder = await conn.fetchrow(
                "SELECT id FROM plan_holders WHERE id = $1", holder_id
            )
            if not holder:
                raise PaymentError(f"Plan holder {holder_id} not found.")

            # 3. Insert pending order
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO orders_payments (
                        buyer_user_id, holder_id, plan_id, sales_case_id,
                        amount_toman, status, payment_method, idempotency_key,
                        gateway_name
                    ) VALUES ($1, $2, $3, $4, $5, 'PENDING', $6, $7, $8)
                    RETURNING *
                    """,
                    buyer_user_id, holder_id, plan_id, sales_case_id,
                    plan["price_toman"], payment_method, idempotency_key, gateway_name
                )
                return dict(row)
            except asyncpg.UniqueViolationError:
                # Idempotent retrieval of existing order
                existing = await conn.fetchrow(
                    "SELECT * FROM orders_payments WHERE idempotency_key = $1", idempotency_key
                )
                return dict(existing)

    async def verify_and_fulfill_payment(
        self,
        order_id: uuid.UUID,
        gateway_transaction_id: str,
        gateway_tracking_code: str,
        verified_by: uuid.UUID | None = None,
        referral_code: str | None = None
    ) -> Dict[str, Any]:
        """
        Verifies payment success, activates card holder membership,
        and distributes referrer commissions (AC-06).
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                order = await conn.fetchrow(
                    """
                    SELECT op.*, dp.validity_days, dp.max_visits, dp.referrer_commission_percent
                    FROM orders_payments op
                    JOIN discount_plans dp ON op.plan_id = dp.id
                    WHERE op.id = $1 FOR UPDATE
                    """, order_id
                )
                if not order:
                    raise OrderNotFoundError(f"Order {order_id} not found.")

                if order["status"] == "SUCCESS":
                    return {"order": dict(order), "already_fulfilled": True}

                if order["status"] not in ("PENDING",):
                    raise InvalidPaymentStateError(f"Order cannot be fulfilled from status '{order['status']}'.")

                # 1. Update order status to SUCCESS
                updated_order = await conn.fetchrow(
                    """
                    UPDATE orders_payments
                    SET status = 'SUCCESS',
                        gateway_transaction_id = $1,
                        gateway_tracking_code = $2,
                        verified_by = $3,
                        verified_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $4
                    RETURNING *
                    """,
                    gateway_transaction_id.strip(), gateway_tracking_code.strip(),
                    verified_by, order_id
                )

                # 2. Activate membership for holder
                validity_days = int(order["validity_days"])
                max_visits = order["max_visits"]
                start_date = datetime.now()
                end_date = start_date + timedelta(days=validity_days)

                mem_row = await conn.fetchrow(
                    """
                    INSERT INTO memberships (
                        holder_id, plan_id, order_id, origin_type,
                        start_date, end_date, max_visits, remaining_visits,
                        used_visits, status
                    ) VALUES ($1, $2, $3, 'DIRECT_PURCHASE', $4, $5, $6, $6, 0, 'ACTIVE')
                    RETURNING id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
                    """,
                    order["holder_id"], order["plan_id"], order_id,
                    start_date, end_date, max_visits
                )

                # 3. Process referral commission if referral code is present
                commission_info = None
                if referral_code:
                    ref_code_clean = referral_code.strip().upper()
                    # Find referrer
                    ref_record = await conn.fetchrow(
                        "SELECT referrer_user_id FROM referrals WHERE referral_code = $1 AND status = 'ACTIVE' LIMIT 1",
                        ref_code_clean
                    )
                    rate = float(order["referrer_commission_percent"])
                    if ref_record and rate > 0:
                        ref_user_id = ref_record["referrer_user_id"]
                        comm_amount = int(round(order["amount_toman"] * (rate / 100.0)))
                        idem_comm = f"COMM-REF-ORD-{order_id}"

                        comm_row = await conn.fetchrow(
                            """
                            INSERT INTO commissions (
                                beneficiary_user_id, commission_type, source_order_id,
                                rate_percent, amount_toman, status, idempotency_key,
                                approved_at
                            ) VALUES ($1, 'REFERRAL', $2, $3, $4, 'APPROVED', $5, NOW())
                            ON CONFLICT (idempotency_key) DO UPDATE SET updated_at = NOW()
                            RETURNING id
                            """, ref_user_id, order_id, rate, comm_amount, idem_comm
                        )

                        # Credit referrer wallet
                        await self.wallet_svc.credit_commission(
                            user_id=ref_user_id,
                            amount_toman=comm_amount,
                            reference_id=str(order_id),
                            idempotency_key=idem_comm,
                            description=f"پورسانت معرفی بابت خرید اشتراک {order_id}"
                        )
                        commission_info = {
                            "referrer_user_id": str(ref_user_id),
                            "commission_id": str(comm_row["id"]),
                            "amount_toman": comm_amount
                        }

                # 4. Audit Log
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        action, entity_name, entity_id, new_values
                    ) VALUES (
                        'ORDER_FULFILLED', 'orders_payments', $1::varchar,
                        jsonb_build_object(
                            'status', 'SUCCESS',
                            'amount_toman', $2::bigint,
                            'membership_id', $3::varchar
                        )
                    )
                    """, str(order_id), order["amount_toman"], str(mem_row["id"])
                )

                return {
                    "order": dict(updated_order),
                    "membership": dict(mem_row),
                    "referral_commission": commission_info
                }

    async def get_order_by_id(self, order_id: uuid.UUID) -> Dict[str, Any]:
        """Retrieves order by ID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT op.*, dp.title as plan_title,
                       ph.first_name as holder_first_name, ph.last_name as holder_last_name
                FROM orders_payments op
                JOIN discount_plans dp ON op.plan_id = dp.id
                JOIN plan_holders ph ON op.holder_id = ph.id
                WHERE op.id = $1
                """, order_id
            )
            if not row:
                raise OrderNotFoundError(f"Order {order_id} not found.")
            return dict(row)
