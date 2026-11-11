"""
Orders & Payments Domain Service (PAY-001..011, AC-06, BR-15)
REMEDIATION: HC-T17 (F-11 CRITICAL, F-12 HIGH, T17-AC1..AC5), HC-T24 (D-1 SALE-008/009/010)

Security & Financial Guarantees:
- Order creation enforces actor permissions (ADMIN_GRANT restricted to ADMIN/SUPER_ADMIN),
  validates linked sales_case ownership/consistency/state, and guards idempotency key cross-user
  collisions or parameter tampering (`DuplicateOrderError` -> 409).
- Ordinary users CANNOT self-confirm payments using fabricated transaction/tracking strings.
  Gateway verification MUST pass trusted provider verification (`BasePaymentGateway.verify_payment`)
  against persisted gateway authority, exact order ID, and exact Toman amount.
- When an order is linked to a `sales_cases` row (`sales_case_id IS NOT NULL`), payment fulfillment
  atomically locks and synchronizes `sales_cases.order_id` and `sales_cases.financial_status` to
  `PAYMENT_RECORDED` under `OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER`, preventing duplicate payments
  or finalization of unpaid sales cases (`D-1`).
- Manual card/transfer confirmation is restricted to explicit audited ADMIN/SUPER_ADMIN flow
  governed by approved `OPEN_04_FINANCIAL_PERMISSIONS_MATRIX` & `OPEN_18_CURRENCY_AND_ROUNDING`.
- Duplicate payment references across orders return `DuplicatePaymentProofError` (409).
- Concurrency serialization (`FOR UPDATE`) + existing membership check prevent duplicate
  memberships, commissions, or wallet credits (`T17-AC3`).
- Exact `Decimal` rounding honors `OPEN_18_CURRENCY_AND_ROUNDING` without IEEE-754 float drift.
"""

import inspect
import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal
from typing import Any, Dict, Set

import asyncpg

from src.adapters.payment import BasePaymentGateway, PaymentGatewayError
from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.common.pii import mask_national_code, mask_phone
from src.core.policy import require_approved_policy
from src.wallets.service import WalletService

ALLOWED_PAYMENT_METHODS = ("GATEWAY", "MANUAL_CARD", "ADMIN_GRANT", "WALLET")


class PaymentError(Exception):
    """Base exception for payment operations."""
    pass


class PaymentAuthorizationError(PaymentError):
    """Raised when an actor attempts unauthorized order access, creation, or confirmation."""
    pass


class OrderNotFoundError(PaymentError):
    """Raised when order does not exist."""
    pass


class InvalidPaymentStateError(PaymentError):
    """Raised when attempting invalid order transition or incompatible payment method."""
    pass


class UnverifiedPaymentError(PaymentError):
    """Raised when gateway proof is missing, unconfirmed, mismatched, or self-asserted."""
    pass


class DuplicatePaymentProofError(PaymentError):
    """Raised when a gateway ref/authority or manual proof reference was already consumed by another order."""
    pass


class DuplicateOrderError(PaymentError):
    """Raised on conflicting or cross-user order idempotency key reuse."""
    pass


def _resolve_actor_role_label(roles: Set[str]) -> str:
    for candidate in ("SUPER_ADMIN", "ADMIN", "SUPPORT", "DOCTOR", "AGENT", "USER"):
        if candidate in roles:
            return candidate
    return "USER"


def _round_percent_toman(
    base_amount_toman: int,
    rate_percent: Decimal | float | int,
    rounding_policy: Dict[str, Any] | None = None,
) -> int:
    raw = (Decimal(int(base_amount_toman)) * Decimal(str(rate_percent))) / Decimal("100")
    mode = (rounding_policy or {}).get("rounding_mode", "FLOOR").strip().upper()
    if mode == "FLOOR":
        return int(raw.to_integral_value(rounding=ROUND_FLOOR))
    if mode == "CEIL":
        return int(raw.to_integral_value(rounding=ROUND_CEILING))
    return int(raw.to_integral_value(rounding=ROUND_HALF_UP))


async def _verify_with_gateway(
    gateway: BasePaymentGateway,
    authority: str,
    amount_toman: int,
    order_id: uuid.UUID,
):
    sig = inspect.signature(gateway.verify_payment)
    if "expected_order_id" in sig.parameters:
        return await gateway.verify_payment(
            authority=authority,
            amount_toman=amount_toman,
            expected_order_id=str(order_id),
        )
    return await gateway.verify_payment(authority=authority, amount_toman=amount_toman)


class PaymentService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.wallet_svc = WalletService(pool)
        self.rbac = RbacEngine(pool)

    async def create_order(
        self,
        buyer_user_id: uuid.UUID,
        holder_id: uuid.UUID,
        plan_id: uuid.UUID,
        idempotency_key: str,
        payment_method: str = "GATEWAY",
        sales_case_id: uuid.UUID | None = None,
        gateway_name: str | None = "ZARINPAL",
    ) -> Dict[str, Any]:
        """Creates a pending order for a discount plan with ownership & idempotency enforcement."""
        idem_clean = (idempotency_key or "").strip()
        if len(idem_clean) < 5:
            raise PaymentError("Idempotency key must be at least 5 characters.")

        method_clean = (payment_method or "GATEWAY").strip().upper()
        if method_clean not in ALLOWED_PAYMENT_METHODS:
            raise PaymentError(f"Unsupported payment method '{payment_method}'.")

        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, buyer_user_id)
            except RbacAccessDeniedError as exc:
                raise PaymentAuthorizationError(str(exc)) from exc

            if method_clean == "ADMIN_GRANT" and not (actor_roles & {"ADMIN", "SUPER_ADMIN"}):
                raise PaymentAuthorizationError(
                    "Only ADMIN or SUPER_ADMIN can initiate ADMIN_GRANT orders."
                )

            if method_clean == "ADMIN_GRANT" and sales_case_id is not None:
                raise InvalidPaymentStateError(
                    "ADMIN_GRANT orders cannot be linked to commissionable sales cases."
                )

            existing = await conn.fetchrow(
                "SELECT * FROM orders_payments WHERE idempotency_key = $1",
                idem_clean,
            )
            if existing:
                if existing["buyer_user_id"] != buyer_user_id:
                    raise DuplicateOrderError("Order idempotency key conflict.")
                if (
                    existing["holder_id"] != holder_id
                    or existing["plan_id"] != plan_id
                    or existing["payment_method"] != method_clean
                    or existing["sales_case_id"] != sales_case_id
                ):
                    raise DuplicateOrderError(
                        "Idempotency key reused with conflicting order payload."
                    )
                return dict(existing)

            plan = await conn.fetchrow(
                "SELECT id, price_toman, is_active FROM discount_plans WHERE id = $1",
                plan_id,
            )
            if not plan or not plan["is_active"]:
                raise PaymentError("Selected discount plan is inactive or does not exist.")

            holder = await conn.fetchrow(
                "SELECT id FROM plan_holders WHERE id = $1",
                holder_id,
            )
            if not holder:
                raise PaymentError(f"Plan holder {holder_id} not found.")

            if sales_case_id is not None:
                sc = await conn.fetchrow(
                    """
                    SELECT sc.id, sc.holder_id, sc.plan_id, sc.order_id,
                           sc.logistic_status, sc.financial_status,
                           a.user_id AS agent_user_id
                    FROM sales_cases sc
                    JOIN agents a ON sc.agent_id = a.id
                    WHERE sc.id = $1
                    """,
                    sales_case_id,
                )
                if not sc:
                    raise PaymentError(f"Sales case {sales_case_id} not found.")
                is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
                if not is_admin and sc["agent_user_id"] != buyer_user_id:
                    raise PaymentAuthorizationError(
                        "Cannot bind an order to another agent's sales case."
                    )
                if sc["holder_id"] != holder_id or sc["plan_id"] != plan_id:
                    raise PaymentError(
                        "Order holder_id and plan_id must match the linked sales case."
                    )
                if sc["logistic_status"] == "RETURNED":
                    raise InvalidPaymentStateError(
                        "Cannot create payment order for a RETURNED sales case."
                    )
                if sc["financial_status"] != "UNPAID" or sc["order_id"] is not None:
                    raise InvalidPaymentStateError(
                        f"Sales case is already in financial_status '{sc['financial_status']}'."
                    )
                paid_for_case = await conn.fetchrow(
                    "SELECT id FROM orders_payments WHERE sales_case_id = $1 AND status = 'SUCCESS' LIMIT 1",
                    sales_case_id,
                )
                if paid_for_case:
                    raise InvalidPaymentStateError(
                        "Linked sales case already has a fulfilled payment order."
                    )

            gw_clean = (
                (gateway_name or "MOCK").strip().upper()
                if method_clean == "GATEWAY"
                else None
            )

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
                    buyer_user_id,
                    holder_id,
                    plan_id,
                    sales_case_id,
                    plan["price_toman"],
                    method_clean,
                    idem_clean,
                    gw_clean,
                )
                return dict(row)
            except asyncpg.UniqueViolationError as exc:
                existing = await conn.fetchrow(
                    "SELECT * FROM orders_payments WHERE idempotency_key = $1",
                    idem_clean,
                )
                if not existing or existing["buyer_user_id"] != buyer_user_id:
                    raise DuplicateOrderError(
                        "Order idempotency key conflict."
                    ) from exc
                if (
                    existing["holder_id"] != holder_id
                    or existing["plan_id"] != plan_id
                    or existing["payment_method"] != method_clean
                    or existing["sales_case_id"] != sales_case_id
                ):
                    raise DuplicateOrderError(
                        "Idempotency key reused with conflicting order payload."
                    ) from exc
                return dict(existing)

    async def initiate_gateway_payment(
        self,
        order_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        callback_url: str,
        gateway: BasePaymentGateway,
    ) -> Dict[str, Any]:
        """Initiates gateway transaction for a PENDING GATEWAY order belonging to actor (or admin)."""
        if actor_user_id is None:
            raise PaymentAuthorizationError("Authenticated user is required.")

        cb_clean = (callback_url or "").strip()
        if not (cb_clean.startswith("http://") or cb_clean.startswith("https://")):
            raise PaymentError("Valid http/https callback_url is required.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise PaymentAuthorizationError(str(exc)) from exc

                order = await conn.fetchrow(
                    """
                    SELECT op.*, u.mobile AS buyer_mobile
                    FROM orders_payments op
                    JOIN users u ON op.buyer_user_id = u.id
                    WHERE op.id = $1 FOR UPDATE OF op
                    """,
                    order_id,
                )
                if not order:
                    raise OrderNotFoundError(f"Order {order_id} not found.")

                is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
                if order["buyer_user_id"] != actor_user_id and not is_admin:
                    raise PaymentAuthorizationError(
                        "Not authorized to initiate payment for this order."
                    )

                if order["status"] != "PENDING":
                    raise InvalidPaymentStateError(
                        f"Cannot initiate payment from status '{order['status']}'."
                    )
                if order["payment_method"] != "GATEWAY":
                    raise InvalidPaymentStateError(
                        "Gateway initiation is only supported for payment_method='GATEWAY'."
                    )

                req_res = await gateway.request_payment(
                    amount_toman=int(order["amount_toman"]),
                    callback_url=cb_clean,
                    description=f"HamiCard Order {order_id}",
                    mobile=order["buyer_mobile"],
                    order_id=str(order_id),
                )

                await conn.execute(
                    """
                    UPDATE orders_payments
                    SET gateway_name = $1,
                        gateway_transaction_id = $2,
                        updated_at = NOW()
                    WHERE id = $3
                    """,
                    req_res.gateway_name,
                    req_res.authority,
                    order_id,
                )

                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, $2, 'ORDER_PAYMENT_INITIATED', 'orders_payments', $3::varchar,
                        jsonb_build_object(
                            'gateway_name', $4::text,
                            'amount_toman', $5::bigint
                        )
                    )
                    """,
                    actor_user_id,
                    _resolve_actor_role_label(actor_roles),
                    str(order_id),
                    req_res.gateway_name,
                    int(order["amount_toman"]),
                )

                return {
                    "order_id": str(order_id),
                    "authority": req_res.authority,
                    "payment_url": req_res.payment_url,
                    "gateway_name": req_res.gateway_name,
                    "amount_toman": int(order["amount_toman"]),
                }

    async def _fulfill_locked_order(
        self,
        conn: asyncpg.Connection,
        order: asyncpg.Record,
        gateway_transaction_id: str,
        gateway_tracking_code: str,
        actor_user_id: uuid.UUID,
        actor_role_label: str,
        rounding_policy: Dict[str, Any],
        referral_code: str | None = None,
        audit_action: str = "ORDER_FULFILLED",
        extra_audit: Dict[str, Any] | None = None,
        open03_policy: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        order_id = order["id"]
        sales_case_id = order["sales_case_id"]

        if sales_case_id is not None and order["payment_method"] == "ADMIN_GRANT":
            raise InvalidPaymentStateError(
                "ADMIN_GRANT orders cannot be fulfilled for a commissionable sales case."
            )

        # Guard against duplicate membership creation on retry or inconsistent DB state (T17-AC3)
        existing_mem = await conn.fetchrow(
            """
            SELECT id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
            FROM memberships
            WHERE order_id = $1
            LIMIT 1
            """,
            order_id,
        )
        if existing_mem:
            return {
                "order": dict(order),
                "membership": dict(existing_mem),
                "already_fulfilled": True,
            }

        # Serialize competing transactions asserting the same bank tracking/proof reference
        tx_clean = gateway_transaction_id.strip()
        trk_clean = gateway_tracking_code.strip()
        await conn.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1));",
            f"pay_proof:{trk_clean}",
        )
        dup_other = await conn.fetchrow(
            """
            SELECT id FROM orders_payments
            WHERE id <> $1
              AND status = 'SUCCESS'
              AND (
                  gateway_tracking_code = $2
                  OR gateway_transaction_id = $2
                  OR gateway_tracking_code = $3
                  OR gateway_transaction_id = $3
              )
            LIMIT 1
            """,
            order_id,
            trk_clean,
            tx_clean,
        )
        if dup_other:
            raise DuplicatePaymentProofError(
                "Payment transaction or tracking reference has already been used for another order."
            )

        locked_sales_case = None
        if sales_case_id is not None:
            if open03_policy is None:
                open03_policy = await require_approved_policy(
                    conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER"
                )
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1));",
                f"sale_pay:{sales_case_id}",
            )
            locked_sales_case = await conn.fetchrow(
                "SELECT * FROM sales_cases WHERE id = $1 FOR UPDATE",
                sales_case_id,
            )
            if not locked_sales_case:
                raise InvalidPaymentStateError(
                    f"Linked sales case {sales_case_id} no longer exists."
                )
            if (
                locked_sales_case["holder_id"] != order["holder_id"]
                or locked_sales_case["plan_id"] != order["plan_id"]
            ):
                raise InvalidPaymentStateError(
                    "Order holder_id/plan_id mismatch with linked sales case."
                )
            if locked_sales_case["logistic_status"] == "RETURNED":
                raise InvalidPaymentStateError(
                    "Cannot record payment for a RETURNED sales case."
                )
            if locked_sales_case["financial_status"] != "UNPAID" or (
                locked_sales_case["order_id"] is not None
                and locked_sales_case["order_id"] != order_id
            ):
                raise InvalidPaymentStateError(
                    f"Linked sales case is in financial_status '{locked_sales_case['financial_status']}' "
                    "and cannot accept another payment."
                )
            other_case_order = await conn.fetchrow(
                """
                SELECT id FROM orders_payments
                WHERE sales_case_id = $1 AND id <> $2 AND status = 'SUCCESS'
                LIMIT 1
                """,
                sales_case_id,
                order_id,
            )
            if other_case_order:
                raise InvalidPaymentStateError(
                    "Another payment order has already been verified for this sales case."
                )

        updated_order = await conn.fetchrow(
            """
            UPDATE orders_payments
            SET status = 'SUCCESS',
                gateway_transaction_id = $1,
                gateway_tracking_code = $2,
                verified_by = $3,
                verified_at = NOW(),
                updated_at = NOW()
            WHERE id = $4 AND status = 'PENDING'
            RETURNING *
            """,
            tx_clean,
            trk_clean,
            actor_user_id,
            order_id,
        )
        if not updated_order:
            raise InvalidPaymentStateError("Order status changed concurrently; cannot fulfill.")

        should_activate_membership = True
        if sales_case_id is not None and open03_policy is not None:
            should_activate_membership = bool(open03_policy.get("auto_activate_membership", True))

        mem_dict = None
        if should_activate_membership:
            validity_days = int(order["validity_days"])
            max_visits = order["max_visits"]
            start_date = datetime.now(UTC)
            end_date = start_date + timedelta(days=validity_days)
            origin_type = (
                "ADMIN_GRANT"
                if order["payment_method"] == "ADMIN_GRANT"
                else ("AGENT_SALE" if sales_case_id is not None else "DIRECT_PURCHASE")
            )

            mem_row = await conn.fetchrow(
                """
                INSERT INTO memberships (
                    holder_id, plan_id, order_id, origin_type,
                    granted_by, start_date, end_date, max_visits, remaining_visits,
                    used_visits, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, 0, 'ACTIVE')
                RETURNING id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
                """,
                order["holder_id"],
                order["plan_id"],
                order_id,
                origin_type,
                actor_user_id if origin_type == "ADMIN_GRANT" else None,
                start_date,
                end_date,
                max_visits,
            )
            mem_dict = dict(mem_row)

        updated_sales_case = None
        if locked_sales_case is not None:
            updated_sc_row = await conn.fetchrow(
                """
                UPDATE sales_cases
                SET financial_status = 'PAYMENT_RECORDED',
                    order_id = $1,
                    updated_at = NOW()
                WHERE id = $2 AND financial_status = 'UNPAID' AND order_id IS NULL
                RETURNING id, agent_id, holder_id, plan_id, order_id, logistic_status, financial_status, updated_at
                """,
                order_id,
                sales_case_id,
            )
            if not updated_sc_row:
                raise InvalidPaymentStateError(
                    "Linked sales case state changed concurrently; cannot synchronize PAYMENT_RECORDED."
                )
            updated_sales_case = dict(updated_sc_row)

            await conn.execute(
                """
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, action, entity_name, entity_id, new_values
                ) VALUES (
                    $1, $2, 'SALE_PAYMENT_RECORDED', 'sales_cases', $3::varchar, $4::jsonb
                )
                """,
                actor_user_id,
                actor_role_label,
                str(sales_case_id),
                json.dumps(
                    {
                        "order_id": str(order_id),
                        "amount_toman": int(order["amount_toman"]),
                        "payment_method": order["payment_method"],
                        "tracking_reference": trk_clean,
                        "membership_activated": mem_dict is not None,
                        "verification_source": (extra_audit or {}).get("verification_source", "GATEWAY"),
                    },
                    ensure_ascii=False,
                ),
            )

        commission_info = None
        if referral_code:
            comb_policy = await require_approved_policy(conn, "OPEN_05_COMBINED_COMMISSION_POLICY")
            ref_code_clean = referral_code.strip().upper()
            ref_record = await conn.fetchrow(
                """
                SELECT r.referrer_user_id, u.status AS referrer_status
                FROM referrals r
                JOIN users u ON r.referrer_user_id = u.id
                WHERE r.referral_code = $1 AND r.status = 'ACTIVE'
                LIMIT 1
                """,
                ref_code_clean,
            )
            rate = Decimal(str(order["referrer_commission_percent"]))
            max_total_pct = Decimal(str(comb_policy.get("max_total_percent", 30.0)))
            allow_combined = bool(comb_policy.get("allow_combined", False))

            if ref_record and ref_record["referrer_status"] == "ACTIVE" and rate > 0:
                ref_user_id = ref_record["referrer_user_id"]
                if ref_user_id != order["buyer_user_id"]:
                    can_credit_ref = True
                    if sales_case_id is not None and not allow_combined:
                        can_credit_ref = False
                    if can_credit_ref:
                        effective_rate = min(rate, max_total_pct)
                        comm_amount = _round_percent_toman(
                            int(order["amount_toman"]), effective_rate, rounding_policy
                        )
                        if comm_amount > 0:
                            idem_comm = f"COMM-REF-ORD-{order_id}"
                            existing_comm = await conn.fetchrow(
                                "SELECT id FROM commissions WHERE idempotency_key = $1",
                                idem_comm,
                            )
                            if existing_comm:
                                comm_id = existing_comm["id"]
                            else:
                                comm_row = await conn.fetchrow(
                                    """
                                    INSERT INTO commissions (
                                        beneficiary_user_id, commission_type, source_order_id,
                                        rate_percent, amount_toman, status, idempotency_key,
                                        approved_by, approved_at
                                    ) VALUES ($1, 'REFERRAL', $2, $3, $4, 'APPROVED', $5, $6, NOW())
                                    RETURNING id
                                    """,
                                    ref_user_id,
                                    order_id,
                                    float(effective_rate),
                                    comm_amount,
                                    idem_comm,
                                    actor_user_id,
                                )
                                comm_id = comm_row["id"]

                            await self.wallet_svc.credit_commission(
                                user_id=ref_user_id,
                                amount_toman=comm_amount,
                                reference_id=str(order_id),
                                idempotency_key=idem_comm,
                                description=f"پورسانت معرفی بابت خرید اشتراک {order_id}",
                                created_by=actor_user_id,
                                conn=conn,
                            )
                            commission_info = {
                                "referrer_user_id": str(ref_user_id),
                                "commission_id": str(comm_id),
                                "amount_toman": comm_amount,
                            }

        audit_meta = {
            "status": "SUCCESS",
            "amount_toman": int(order["amount_toman"]),
            "membership_id": str(mem_dict["id"]) if mem_dict else None,
            "payment_method": order["payment_method"],
            "sales_case_id": str(sales_case_id) if sales_case_id else None,
        }
        if extra_audit:
            audit_meta.update(extra_audit)

        await conn.execute(
            """
            INSERT INTO audit_logs (
                actor_user_id, actor_role, action, entity_name, entity_id, new_values
            ) VALUES (
                $1, $2, $3, 'orders_payments', $4::varchar, $5::jsonb
            )
            """,
            actor_user_id,
            actor_role_label,
            audit_action,
            str(order_id),
            json.dumps(audit_meta, ensure_ascii=False),
        )

        result_payload: Dict[str, Any] = {
            "order": dict(updated_order),
            "membership": mem_dict,
            "referral_commission": commission_info,
        }
        if updated_sales_case is not None:
            result_payload["sales_case"] = updated_sales_case
        return result_payload

    async def verify_and_fulfill_payment(
        self,
        order_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        gateway: BasePaymentGateway,
        authority: str | None = None,
        referral_code: str | None = None,
        gateway_transaction_id: str | None = None,
        gateway_tracking_code: str | None = None,
    ) -> Dict[str, Any]:
        """
        Verifies gateway payment strictly through trusted provider proof (`authority`),
        activates membership atomically, and distributes referral commission idempotently (AC-06, T17-AC1..AC5).
        Caller-provided transaction/tracking IDs are NEVER accepted as payment proof.
        """
        if actor_user_id is None:
            raise PaymentAuthorizationError("Authenticated actor_user_id is required.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise PaymentAuthorizationError(str(exc)) from exc

                order = await conn.fetchrow(
                    """
                    SELECT op.*, dp.validity_days, dp.max_visits, dp.referrer_commission_percent
                    FROM orders_payments op
                    JOIN discount_plans dp ON op.plan_id = dp.id
                    WHERE op.id = $1 FOR UPDATE OF op
                    """,
                    order_id,
                )
                if not order:
                    raise OrderNotFoundError(f"Order {order_id} not found.")

                is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
                if order["buyer_user_id"] != actor_user_id and not is_admin:
                    raise PaymentAuthorizationError(
                        "You are not authorized to verify or modify another user's order."
                    )

                rounding_policy = await require_approved_policy(
                    conn, "OPEN_18_CURRENCY_AND_ROUNDING"
                )
                open03_policy = None
                if order["sales_case_id"] is not None:
                    open03_policy = await require_approved_policy(
                        conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER"
                    )
                if referral_code:
                    await require_approved_policy(conn, "OPEN_05_COMBINED_COMMISSION_POLICY")

                if order["status"] == "SUCCESS":
                    mem = await conn.fetchrow(
                        """
                        SELECT id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
                        FROM memberships
                        WHERE order_id = $1
                        LIMIT 1
                        """,
                        order_id,
                    )
                    return {
                        "order": dict(order),
                        "membership": dict(mem) if mem else None,
                        "already_fulfilled": True,
                    }

                if order["status"] != "PENDING":
                    raise InvalidPaymentStateError(
                        f"Order cannot be fulfilled from status '{order['status']}'."
                    )

                if order["payment_method"] != "GATEWAY":
                    raise InvalidPaymentStateError(
                        f"Payment method '{order['payment_method']}' requires manual/authorized flow instead of gateway verify."
                    )

                auth_clean = (authority or "").strip()
                if not auth_clean:
                    raise UnverifiedPaymentError(
                        "Verified gateway authority is required; self-asserted transaction identifiers are rejected."
                    )

                persisted_authority = (order["gateway_transaction_id"] or "").strip()
                if not persisted_authority or persisted_authority != auth_clean:
                    raise UnverifiedPaymentError(
                        "Gateway authority does not match the initiated payment session for this order."
                    )

                try:
                    ver = await _verify_with_gateway(
                        gateway=gateway,
                        authority=auth_clean,
                        amount_toman=int(order["amount_toman"]),
                        order_id=order_id,
                    )
                except PaymentGatewayError:
                    raise

                if (
                    not ver.success
                    or int(ver.amount_toman) != int(order["amount_toman"])
                    or not (ver.ref_id and ver.ref_id.strip())
                ):
                    raise UnverifiedPaymentError(
                        ver.error_message or "Gateway refused or could not verify payment."
                    )

                return await self._fulfill_locked_order(
                    conn=conn,
                    order=order,
                    gateway_transaction_id=auth_clean,
                    gateway_tracking_code=ver.ref_id.strip(),
                    actor_user_id=actor_user_id,
                    actor_role_label=_resolve_actor_role_label(actor_roles),
                    rounding_policy=rounding_policy,
                    referral_code=referral_code,
                    audit_action="ORDER_FULFILLED",
                    extra_audit={"verification_source": "GATEWAY"},
                    open03_policy=open03_policy,
                )

    async def manual_confirm_payment(
        self,
        order_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        payment_proof_reference: str,
        reason: str,
        referral_code: str | None = None,
    ) -> Dict[str, Any]:
        """
        Explicit audited ADMIN / SUPER_ADMIN manual payment confirmation (`T17-AC2`).
        Governed strictly by `OPEN_04_FINANCIAL_PERMISSIONS_MATRIX` and `OPEN_18_CURRENCY_AND_ROUNDING`.
        """
        if actor_user_id is None:
            raise PaymentAuthorizationError("Authenticated actor_user_id is required.")

        proof_clean = (payment_proof_reference or "").strip()
        if len(proof_clean) < 6:
            raise PaymentError("payment_proof_reference must be at least 6 characters.")
        reason_clean = (reason or "").strip()
        if len(reason_clean) < 5:
            raise PaymentError("Manual confirmation reason must be at least 5 characters.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise PaymentAuthorizationError(str(exc)) from exc

                perm_policy = await require_approved_policy(
                    conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX"
                )
                rounding_policy = await require_approved_policy(
                    conn, "OPEN_18_CURRENCY_AND_ROUNDING"
                )
                if referral_code:
                    await require_approved_policy(conn, "OPEN_05_COMBINED_COMMISSION_POLICY")

                allowed_roles = (
                    set(perm_policy.get("record_sale_payment", ["ADMIN", "SUPER_ADMIN"]))
                    & {"ADMIN", "SUPER_ADMIN"}
                )
                if not (actor_roles & allowed_roles):
                    raise PaymentAuthorizationError(
                        "Only authorized financial administrators (OPEN-04) may manually confirm payments."
                    )

                order = await conn.fetchrow(
                    """
                    SELECT op.*, dp.validity_days, dp.max_visits, dp.referrer_commission_percent
                    FROM orders_payments op
                    JOIN discount_plans dp ON op.plan_id = dp.id
                    WHERE op.id = $1 FOR UPDATE OF op
                    """,
                    order_id,
                )
                if not order:
                    raise OrderNotFoundError(f"Order {order_id} not found.")

                open03_policy = None
                if order["sales_case_id"] is not None:
                    open03_policy = await require_approved_policy(
                        conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER"
                    )

                if order["status"] == "SUCCESS":
                    if (order["gateway_tracking_code"] or "").strip() != proof_clean:
                        raise InvalidPaymentStateError(
                            "Order is already fulfilled with a different payment reference."
                        )
                    mem = await conn.fetchrow(
                        """
                        SELECT id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
                        FROM memberships
                        WHERE order_id = $1
                        LIMIT 1
                        """,
                        order_id,
                    )
                    return {
                        "order": dict(order),
                        "membership": dict(mem) if mem else None,
                        "already_fulfilled": True,
                    }

                if order["status"] != "PENDING":
                    raise InvalidPaymentStateError(
                        f"Order cannot be manually confirmed from status '{order['status']}'."
                    )

                if order["payment_method"] not in ("MANUAL_CARD", "ADMIN_GRANT"):
                    raise InvalidPaymentStateError(
                        "Manual confirmation is permitted only for MANUAL_CARD or ADMIN_GRANT orders."
                    )

                role_label = _resolve_actor_role_label(actor_roles)
                return await self._fulfill_locked_order(
                    conn=conn,
                    order=order,
                    gateway_transaction_id=f"MANUAL-{order_id}",
                    gateway_tracking_code=proof_clean,
                    actor_user_id=actor_user_id,
                    actor_role_label=role_label,
                    rounding_policy=rounding_policy,
                    referral_code=referral_code,
                    audit_action="ORDER_MANUALLY_CONFIRMED",
                    extra_audit={
                        "verification_source": "MANUAL_ADMIN",
                        "reason": reason_clean,
                    },
                    open03_policy=open03_policy,
                )

    async def get_order_by_id(
        self,
        order_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        """Retrieves order by ID with strict buyer/admin ownership enforcement and PII masking."""
        if actor_user_id is None:
            raise PaymentAuthorizationError("Authenticated actor_user_id is required.")

        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise PaymentAuthorizationError(str(exc)) from exc

            row = await conn.fetchrow(
                """
                SELECT op.*, dp.title as plan_title,
                       ph.first_name as holder_first_name, ph.last_name as holder_last_name,
                       ph.national_code as holder_national_code, ph.mobile as holder_mobile
                FROM orders_payments op
                JOIN discount_plans dp ON op.plan_id = dp.id
                JOIN plan_holders ph ON op.holder_id = ph.id
                WHERE op.id = $1
                """,
                order_id,
            )
            if not row:
                raise OrderNotFoundError(f"Order {order_id} not found.")

            is_privileged_reader = bool(actor_roles & {"ADMIN", "SUPER_ADMIN", "SUPPORT"})
            if row["buyer_user_id"] != actor_user_id and not is_privileged_reader:
                raise PaymentAuthorizationError(
                    "Access denied: You are not authorized to view this order."
                )

            result = dict(row)
            is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
            if not is_admin:
                result["holder_national_code"] = mask_national_code(result.get("holder_national_code"))
                result["holder_mobile"] = mask_phone(result.get("holder_mobile"))
            return result
