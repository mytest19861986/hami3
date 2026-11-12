"""
Sales Cases & Agent Logistics Domain Service (SALE-001..013, AC-09, AC-10)
REMEDIATION: HC-T19 (F-12 HIGH, T19-AC1, T19-AC2, T19-AC5), HC-T24 (D-1 SALE-008/009/010)

Security & State Machine Guarantees:
- Agent Binding: Ordinary agents CANNOT create sales cases under another agent's `agent_id`
  without explicit `ADMIN` / `SUPER_ADMIN` override (logged in `audit_logs`). Unapproved
  (`PENDING`, `REJECTED`, `SUSPENDED`) agents fail closed (`403`).
- Logistics Authorization: Only `ADMIN` / `SUPER_ADMIN` may advance logistics states,
  enforcing strict forward state transitions and postal tracking invariants (`AC-09`).
- Verified Payment Synchronization & Audited Manual Payment (`SALE-008/009`):
  - Only verified gateway fulfillment or explicitly authorized ADMIN/SUPER_ADMIN manual
    payment recording (`OPEN_04` `record_sale_payment`) may advance `UNPAID -> PAYMENT_RECORDED`.
  - Unpaid or unverified sales cases (`financial_status != 'PAYMENT_RECORDED'` or missing
    verified `orders_payments`) can NEVER be finalized or credit agent commissions (`T24-AC1`).
- Financial Finalization (`SALE-010`): Strictly gated on `commissions:approve` (`ADMIN`/`SUPER_ADMIN`),
  verified `PAYMENT_RECORDED` payment, dynamic `OPEN_03` trigger & `OPEN_18` rounding,
  non-returned logistics, single idempotent `AGENT_SALE` membership ensure, and single
  `Decimal` commission credit via `WalletService`.
- Ownership & PII Filtering: Case retrieval restricted to owning APPROVED agent, `ADMIN`,
  `SUPER_ADMIN`, or `SUPPORT`, masking holder `national_code` and `mobile` for non-admin viewers.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal
from typing import Any, Dict, Set

import asyncpg

from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.common.pii import mask_national_code, mask_phone
from src.core.policy import (
    InvalidPolicyConfigurationError,
    parse_open03_agent_sale_policy,
    require_approved_policy,
)
from src.wallets.service import WalletService

ALLOWED_LOGISTIC_TRANSITIONS: Dict[str, Set[str]] = {
    "PENDING_REVIEW": {"APPROVED", "RETURNED"},
    "APPROVED": {"CARD_ISSUED", "RETURNED"},
    "CARD_ISSUED": {"SHIPPED", "RETURNED"},
    "SHIPPED": {"DELIVERED", "RETURNED"},
    "DELIVERED": {"RETURNED"},
    "RETURNED": set(),
}

ALLOWED_FINALIZATION_TRIGGERS: Dict[str, Set[str]] = {
    "PAYMENT_RECORDED_AND_CASE_APPROVED": {"APPROVED", "CARD_ISSUED", "SHIPPED", "DELIVERED"},
    "PAYMENT_RECORDED_AND_CARD_ISSUED": {"CARD_ISSUED", "SHIPPED", "DELIVERED"},
    "PAYMENT_RECORDED_AND_DELIVERED": {"DELIVERED"},
}


class SalesCaseError(Exception):
    """Base exception for sales case operations."""
    pass


class SalesAuthorizationError(SalesCaseError):
    """Raised when actor lacks ownership, RBAC role, or permission for sales operations."""
    pass


class SalesCaseNotFoundError(SalesCaseError):
    """Raised when sales case does not exist."""
    pass


class InvalidStateTransitionError(SalesCaseError):
    """Raised on invalid state transitions in the dual state machine."""
    pass


class DuplicateSalePaymentProofError(SalesCaseError):
    """Raised when a sales payment tracking/proof reference has already been consumed."""
    pass


class SalesPaymentValidationError(SalesCaseError):
    """Raised when recorded sale payment payload violates amount, date, or proof invariants."""
    pass


class AgentNotApprovedError(SalesAuthorizationError):
    """Raised when an unapproved agent attempts sales operations."""
    pass


def _resolve_actor_role_label(roles: Set[str]) -> str:
    for candidate in ("SUPER_ADMIN", "ADMIN", "SUPPORT", "AGENT", "DOCTOR", "USER"):
        if candidate in roles:
            return candidate
    return "USER"


def _round_percent_toman(
    price_toman: int,
    rate_percent: float | Decimal | int,
    rounding_policy: Dict[str, Any] | None = None,
) -> int:
    raw = (Decimal(int(price_toman)) * Decimal(str(rate_percent))) / Decimal("100")
    mode = (rounding_policy or {}).get("rounding_mode", "FLOOR").strip().upper()
    if mode == "FLOOR":
        return int(raw.to_integral_value(rounding=ROUND_FLOOR))
    if mode == "CEIL":
        return int(raw.to_integral_value(rounding=ROUND_CEILING))
    return int(raw.to_integral_value(rounding=ROUND_HALF_UP))


class SalesCaseService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.wallet_svc = WalletService(pool)
        self.rbac = RbacEngine(pool)

    async def create_sales_case(
        self,
        holder_id: uuid.UUID,
        plan_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
        agent_id: uuid.UUID | None = None,
        notes: str | None = None,
    ) -> Dict[str, Any]:
        """Creates a new sales case bound authoritatively to authenticated APPROVED agent (or admin override)."""
        if actor_user_id is None:
            raise SalesAuthorizationError("Authenticated actor_user_id is required.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise SalesAuthorizationError(str(exc)) from exc

                is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
                is_agent = "AGENT" in actor_roles
                if not is_admin and not is_agent:
                    raise SalesAuthorizationError(
                        "Only APPROVED sales agents or administrators can register sales cases."
                    )

                actor_agent = await conn.fetchrow(
                    "SELECT id, user_id, verification_status FROM agents WHERE user_id = $1",
                    actor_user_id,
                )

                if is_admin:
                    lookup_agent_id = agent_id or (actor_agent["id"] if actor_agent else None)
                    if lookup_agent_id is None:
                        raise SalesCaseError("Target agent_id is required when creating as admin.")
                    target_agent = await conn.fetchrow(
                        "SELECT id, user_id, verification_status FROM agents WHERE id = $1",
                        lookup_agent_id,
                    )
                    if not target_agent:
                        raise SalesCaseNotFoundError(f"Agent {lookup_agent_id} not found.")
                    if target_agent["verification_status"] != "APPROVED":
                        raise AgentNotApprovedError(
                            "Target agent must be APPROVED before registering sales cases (AC-03)."
                        )
                    resolved_agent_id = target_agent["id"]
                    admin_override = target_agent["user_id"] != actor_user_id
                else:
                    if not actor_agent:
                        raise SalesAuthorizationError("Actor does not have a registered agent profile.")
                    if actor_agent["verification_status"] != "APPROVED":
                        raise AgentNotApprovedError(
                            "Only APPROVED agents can register sales cases (AC-03)."
                        )
                    if agent_id is not None and agent_id != actor_agent["id"]:
                        raise SalesAuthorizationError(
                            "Forbidden: Agent A cannot create sales cases on behalf of Agent B."
                        )
                    resolved_agent_id = actor_agent["id"]
                    admin_override = False

                holder = await conn.fetchrow(
                    "SELECT id FROM plan_holders WHERE id = $1",
                    holder_id,
                )
                if not holder:
                    raise SalesCaseError(f"Plan holder {holder_id} not found.")

                plan = await conn.fetchrow(
                    "SELECT id, price_toman, is_active FROM discount_plans WHERE id = $1",
                    plan_id,
                )
                if not plan or not plan["is_active"]:
                    raise SalesCaseError("Selected discount plan is inactive or not found.")

                row = await conn.fetchrow(
                    """
                    INSERT INTO sales_cases (
                        agent_id, holder_id, plan_id, logistic_status,
                        financial_status, notes
                    ) VALUES ($1, $2, $3, 'PENDING_REVIEW', 'UNPAID', $4)
                    RETURNING *
                    """,
                    resolved_agent_id,
                    holder_id,
                    plan_id,
                    notes,
                )

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, $2, 'SALES_CASE_CREATED', 'sales_cases', $3::varchar, $4::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(row["id"]),
                    json.dumps(
                        {
                            "agent_id": str(resolved_agent_id),
                            "plan_id": str(plan_id),
                            "admin_override": admin_override,
                        }
                    ),
                )

                return dict(row)

    async def update_logistic_status(
        self,
        case_id: uuid.UUID,
        new_status: str,
        actor_user_id: uuid.UUID | None,
        shipping_tracking_code: str | None = None,
    ) -> Dict[str, Any]:
        """
        Transitions logistic state strictly for ADMIN / SUPER_ADMIN (`T19-AC2`):
        - Forward transitions governed by ALLOWED_LOGISTIC_TRANSITIONS
        - CARD_ISSUED requires APPROVED
        - SHIPPED requires non-empty shipping_tracking_code
        - DELIVERED sets delivery_date
        """
        if actor_user_id is None:
            raise SalesAuthorizationError("Authenticated actor_user_id is required.")

        valid_statuses = ("PENDING_REVIEW", "APPROVED", "CARD_ISSUED", "SHIPPED", "DELIVERED", "RETURNED")
        status_clean = (new_status or "").strip().upper()
        if status_clean not in valid_statuses:
            raise InvalidStateTransitionError(f"Invalid logistic status: {new_status}")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise SalesAuthorizationError(str(exc)) from exc

                if not (actor_roles & {"ADMIN", "SUPER_ADMIN"}):
                    raise SalesAuthorizationError(
                        "Only ADMIN or SUPER_ADMIN may update sales logistics status."
                    )

                case = await conn.fetchrow(
                    "SELECT * FROM sales_cases WHERE id = $1 FOR UPDATE",
                    case_id,
                )
                if not case:
                    raise SalesCaseNotFoundError(f"Sales case {case_id} not found.")

                current = case["logistic_status"]
                if status_clean == "CARD_ISSUED" and current not in ("APPROVED", "CARD_ISSUED"):
                    raise InvalidStateTransitionError(
                        "Physical card can only be issued after logistics approval."
                    )

                allowed_next = ALLOWED_LOGISTIC_TRANSITIONS.get(current, set())
                if status_clean != current and status_clean not in allowed_next:
                    raise InvalidStateTransitionError(
                        f"Invalid logistics state transition from '{current}' to '{status_clean}'."
                    )

                if status_clean == "SHIPPED":
                    code = shipping_tracking_code or case["shipping_tracking_code"]
                    if not code or not code.strip():
                        raise InvalidStateTransitionError(
                            "Shipping tracking code is required to transition to SHIPPED."
                        )

                delivery_date = (
                    datetime.now(UTC) if status_clean == "DELIVERED" else case["delivery_date"]
                )
                tracking = (
                    shipping_tracking_code.strip()
                    if shipping_tracking_code and shipping_tracking_code.strip()
                    else case["shipping_tracking_code"]
                )

                updated = await conn.fetchrow(
                    """
                    UPDATE sales_cases
                    SET logistic_status = $1,
                        shipping_tracking_code = $2,
                        delivery_date = $3,
                        reviewed_by = $4,
                        reviewed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $5
                    RETURNING *
                    """,
                    status_clean,
                    tracking,
                    delivery_date,
                    actor_user_id,
                    case_id,
                )

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, $2, 'LOGISTIC_STATUS_UPDATED', 'sales_cases', $3::varchar,
                        jsonb_build_object('old_status', $4::varchar, 'new_status', $5::varchar)
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(case_id),
                    current,
                    status_clean,
                )

                return dict(updated)

    async def record_manual_payment(
        self,
        case_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        amount_toman: int,
        payment_proof_reference: str,
        payment_date: datetime,
        notes: str,
    ) -> Dict[str, Any]:
        """
        Records audited offline/manual payment for a sales case (`SALE-008`, `T24-AC2`):
        - Strictly gated on approved `OPEN_04_FINANCIAL_PERMISSIONS_MATRIX`, `OPEN_18`, `OPEN_03`.
        - Strictly restricted to authorized ADMIN/SUPER_ADMIN roles (ordinary users/agents 403).
        - Validates exact plan price, non-future payment_date, unique tracking/proof ref (`409`).
        - Advances sales case `UNPAID -> PAYMENT_RECORDED` without finalizing or crediting commission (`SALE-009`).
        """
        if actor_user_id is None:
            raise SalesAuthorizationError("Authenticated actor_user_id is required.")

        if int(amount_toman) <= 0:
            raise SalesPaymentValidationError("Recorded payment amount must be positive.")

        proof_clean = (payment_proof_reference or "").strip()
        if len(proof_clean) < 6:
            raise SalesPaymentValidationError(
                "payment_proof_reference must be at least 6 characters."
            )

        notes_clean = (notes or "").strip()
        if len(notes_clean) < 5:
            raise SalesPaymentValidationError("Payment notes/reason must be at least 5 characters.")

        if payment_date is None:
            raise SalesPaymentValidationError("payment_date is required.")
        payment_date_utc = (
            payment_date.replace(tzinfo=UTC)
            if payment_date.tzinfo is None
            else payment_date.astimezone(UTC)
        )
        if payment_date_utc > datetime.now(UTC) + timedelta(minutes=5):
            raise SalesPaymentValidationError("payment_date cannot be in the future.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise SalesAuthorizationError(str(exc)) from exc

                perm_policy = await require_approved_policy(
                    conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX"
                )
                await require_approved_policy(conn, "OPEN_18_CURRENCY_AND_ROUNDING")
                open03 = await require_approved_policy(
                    conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER"
                )
                try:
                    _trigger, auto_activate_membership = parse_open03_agent_sale_policy(open03)
                except InvalidPolicyConfigurationError as exc:
                    raise InvalidStateTransitionError(str(exc)) from exc

                allowed_roles = (
                    set(perm_policy.get("record_sale_payment", ["ADMIN", "SUPER_ADMIN"]))
                    & {"ADMIN", "SUPER_ADMIN"}
                )
                if not (actor_roles & allowed_roles):
                    raise SalesAuthorizationError(
                        "Only authorized financial administrators (OPEN-04) may record sale payments."
                    )

                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext($1));",
                    f"pay_proof:{proof_clean}",
                )

                case = await conn.fetchrow(
                    """
                    SELECT sc.*, dp.price_toman, dp.validity_days, dp.max_visits
                    FROM sales_cases sc
                    JOIN discount_plans dp ON sc.plan_id = dp.id
                    WHERE sc.id = $1 FOR UPDATE OF sc
                    """,
                    case_id,
                )
                if not case:
                    raise SalesCaseNotFoundError(f"Sales case {case_id} not found.")

                if case["logistic_status"] == "RETURNED":
                    raise InvalidStateTransitionError(
                        "Cannot record payment for a RETURNED sales case."
                    )
                if case["financial_status"] != "UNPAID" or case["order_id"] is not None:
                    raise InvalidStateTransitionError(
                        f"Sales case is already in financial_status '{case['financial_status']}'."
                    )

                if int(amount_toman) != int(case["price_toman"]):
                    raise SalesPaymentValidationError(
                        f"Recorded payment amount ({amount_toman}) does not match plan price ({case['price_toman']})."
                    )

                existing_case_order = await conn.fetchrow(
                    """
                    SELECT id FROM orders_payments
                    WHERE sales_case_id = $1 AND status = 'SUCCESS'
                    LIMIT 1
                    """,
                    case_id,
                )
                if existing_case_order:
                    raise InvalidStateTransitionError(
                        "A verified payment order already exists for this sales case."
                    )

                dup_proof = await conn.fetchrow(
                    """
                    SELECT id FROM orders_payments
                    WHERE gateway_tracking_code = $1 OR gateway_transaction_id = $1
                    LIMIT 1
                    """,
                    proof_clean,
                )
                if dup_proof:
                    raise DuplicateSalePaymentProofError(
                        "Payment proof reference has already been used for another payment."
                    )

                idem_key = f"MANUAL-SALE-{case_id}"
                try:
                    order_row = await conn.fetchrow(
                        """
                        INSERT INTO orders_payments (
                            buyer_user_id, holder_id, plan_id, sales_case_id,
                            amount_toman, status, payment_method, idempotency_key,
                            gateway_name, gateway_transaction_id, gateway_tracking_code,
                            verified_by, verified_at
                        ) VALUES (
                            $1, $2, $3, $4,
                            $5, 'SUCCESS', 'MANUAL_CARD', $6,
                            'MANUAL_BANK_RECEIPT', $6, $7,
                            $8, $9
                        )
                        RETURNING *
                        """,
                        actor_user_id,
                        case["holder_id"],
                        case["plan_id"],
                        case_id,
                        int(amount_toman),
                        idem_key,
                        proof_clean,
                        actor_user_id,
                        payment_date_utc,
                    )
                except asyncpg.UniqueViolationError as exc:
                    raise InvalidStateTransitionError(
                        "Payment has already been recorded for this sales case."
                    ) from exc

                mem_row = None
                if auto_activate_membership:
                    start_date = datetime.now(UTC)
                    end_date = start_date + timedelta(days=int(case["validity_days"]))
                    mem_row = await conn.fetchrow(
                        """
                        INSERT INTO memberships (
                            holder_id, plan_id, order_id, origin_type,
                            granted_by, start_date, end_date, max_visits, remaining_visits,
                            used_visits, status
                        ) VALUES (
                            $1, $2, $3, 'AGENT_SALE',
                            NULL, $4, $5, $6, $6, 0, 'ACTIVE'
                        )
                        RETURNING id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
                        """,
                        case["holder_id"],
                        case["plan_id"],
                        order_row["id"],
                        start_date,
                        end_date,
                        case["max_visits"],
                    )

                updated_case = await conn.fetchrow(
                    """
                    UPDATE sales_cases
                    SET financial_status = 'PAYMENT_RECORDED',
                        order_id = $1,
                        reviewed_by = $2,
                        reviewed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $3 AND financial_status = 'UNPAID' AND order_id IS NULL
                    RETURNING *
                    """,
                    order_row["id"],
                    actor_user_id,
                    case_id,
                )
                if not updated_case:
                    raise InvalidStateTransitionError(
                        "Sales case state changed concurrently; cannot record payment."
                    )

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, $2, 'SALE_PAYMENT_RECORDED', 'sales_cases', $3::varchar, $4::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(case_id),
                    json.dumps(
                        {
                            "order_id": str(order_row["id"]),
                            "amount_toman": int(amount_toman),
                            "payment_date": payment_date_utc.isoformat(),
                            "payment_proof_reference": proof_clean,
                            "notes": notes_clean,
                            "membership_id": str(mem_row["id"]) if mem_row else None,
                            "verification_source": "MANUAL_ADMIN",
                        },
                        ensure_ascii=False,
                    ),
                )

                return {
                    "case": dict(updated_case),
                    "order": dict(order_row),
                    "membership": dict(mem_row) if mem_row else None,
                }

    async def finalize_financial_status(
        self,
        case_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
    ) -> Dict[str, Any]:
        """
        Finalizes financial state of an approved sales case (`commissions:approve` / ADMIN),
        enforces verified PAYMENT_RECORDED payment + dynamic OPEN_03 trigger + OPEN_18 rounding,
        ensures at most one AGENT_SALE membership, and credits agent wallet atomically (AC-10, D-1).
        """
        if actor_user_id is None:
            raise SalesAuthorizationError("Authenticated actor_user_id is required.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                    actor_perms = await self.rbac.get_user_permissions(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise SalesAuthorizationError(str(exc)) from exc

                if "SUPER_ADMIN" not in actor_roles and "commissions:approve" not in actor_perms:
                    raise SalesAuthorizationError(
                        "Permission denied: 'commissions:approve' permission required."
                    )

                open03 = await require_approved_policy(
                    conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER"
                )
                try:
                    trigger, _auto_activate_membership = parse_open03_agent_sale_policy(open03)
                except InvalidPolicyConfigurationError as exc:
                    raise InvalidStateTransitionError(str(exc)) from exc
                rounding_policy = await require_approved_policy(
                    conn, "OPEN_18_CURRENCY_AND_ROUNDING"
                )

                case = await conn.fetchrow(
                    """
                    SELECT sc.*, dp.price_toman, dp.validity_days, dp.max_visits,
                           dp.agent_commission_percent, a.user_id AS agent_user_id
                    FROM sales_cases sc
                    JOIN discount_plans dp ON sc.plan_id = dp.id
                    JOIN agents a ON sc.agent_id = a.id
                    WHERE sc.id = $1 FOR UPDATE OF sc
                    """,
                    case_id,
                )
                if not case:
                    raise SalesCaseNotFoundError(f"Sales case {case_id} not found.")

                if case["financial_status"] == "FINALIZED":
                    raise InvalidStateTransitionError("Sales case is already finalized.")
                if case["financial_status"] == "CANCELLED":
                    raise InvalidStateTransitionError("Cancelled sales case cannot be finalized.")
                if case["financial_status"] != "PAYMENT_RECORDED":
                    raise InvalidStateTransitionError(
                        f"Cannot finalize sales case in financial_status '{case['financial_status']}': verified payment must be recorded first."
                    )
                if case["logistic_status"] == "RETURNED":
                    raise InvalidStateTransitionError(
                        "Cannot finalize sales case in logistic_status 'RETURNED'."
                    )

                order_id = case["order_id"]
                if order_id is None:
                    raise InvalidStateTransitionError(
                        "Cannot finalize sales case without a verified linked payment order."
                    )

                ord_row = await conn.fetchrow(
                    "SELECT * FROM orders_payments WHERE id = $1 FOR UPDATE",
                    order_id,
                )
                if not ord_row:
                    raise InvalidStateTransitionError(
                        "Linked payment order does not exist; cannot finalize sales case."
                    )
                if ord_row["status"] != "SUCCESS":
                    raise InvalidStateTransitionError(
                        f"Linked payment order is in status '{ord_row['status']}', expected 'SUCCESS'."
                    )
                if (
                    ord_row["holder_id"] != case["holder_id"]
                    or ord_row["plan_id"] != case["plan_id"]
                    or ord_row["sales_case_id"] != case_id
                ):
                    raise InvalidStateTransitionError(
                        "Linked payment order does not match this sales case."
                    )
                if ord_row["payment_method"] == "ADMIN_GRANT":
                    raise InvalidStateTransitionError(
                        "ADMIN_GRANT orders cannot finalize a commissionable sales case."
                    )
                if int(ord_row["amount_toman"]) != int(case["price_toman"]):
                    raise InvalidStateTransitionError(
                        "Verified payment amount does not match sales case plan price."
                    )
                if (
                    not (ord_row["gateway_tracking_code"] or "").strip()
                    or ord_row["verified_by"] is None
                    or ord_row["verified_at"] is None
                ):
                    raise InvalidStateTransitionError(
                        "Linked payment order lacks verified payment proof or verifier metadata."
                    )

                allowed_logistics = ALLOWED_FINALIZATION_TRIGGERS.get(trigger)
                if allowed_logistics is None:
                    raise InvalidStateTransitionError(
                        f"Unsupported OPEN_03 finalization trigger '{trigger}'."
                    )
                if case["logistic_status"] not in allowed_logistics:
                    raise InvalidStateTransitionError(
                        f"Cannot finalize sales case in logistic_status '{case['logistic_status']}' under OPEN_03 trigger '{trigger}'."
                    )

                mem_row = await conn.fetchrow(
                    """
                    SELECT id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
                    FROM memberships
                    WHERE order_id = $1
                    LIMIT 1
                    """,
                    order_id,
                )
                if not mem_row:
                    start_date = datetime.now(UTC)
                    end_date = start_date + timedelta(days=int(case["validity_days"]))
                    mem_row = await conn.fetchrow(
                        """
                        INSERT INTO memberships (
                            holder_id, plan_id, order_id, origin_type,
                            granted_by, start_date, end_date, max_visits, remaining_visits,
                            used_visits, status
                        ) VALUES (
                            $1, $2, $3, 'AGENT_SALE',
                            NULL, $4, $5, $6, $6, 0, 'ACTIVE'
                        )
                        RETURNING id, holder_id, plan_id, status, start_date, end_date, max_visits, remaining_visits
                        """,
                        case["holder_id"],
                        case["plan_id"],
                        order_id,
                        start_date,
                        end_date,
                        case["max_visits"],
                    )

                rate = Decimal(str(case["agent_commission_percent"]))
                price = int(case["price_toman"])
                commission_amount = _round_percent_toman(price, rate, rounding_policy)
                agent_user_id = case["agent_user_id"]
                idem_key = f"COMM-SALE-{case_id}"

                updated_case = await conn.fetchrow(
                    """
                    UPDATE sales_cases
                    SET financial_status = 'FINALIZED',
                        reviewed_by = $1,
                        reviewed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $2 AND financial_status = 'PAYMENT_RECORDED'
                    RETURNING *
                    """,
                    actor_user_id,
                    case_id,
                )
                if not updated_case:
                    raise InvalidStateTransitionError(
                        "Sales case financial status changed concurrently; cannot finalize."
                    )

                existing_comm = await conn.fetchrow(
                    "SELECT id FROM commissions WHERE idempotency_key = $1 FOR UPDATE",
                    idem_key,
                )
                if existing_comm:
                    comm_row = existing_comm
                else:
                    comm_row = await conn.fetchrow(
                        """
                        INSERT INTO commissions (
                            beneficiary_user_id, commission_type, source_order_id, source_sales_case_id,
                            rate_percent, amount_toman, status, idempotency_key,
                            approved_by, approved_at
                        ) VALUES ($1, 'AGENT_SALE', $2, $3, $4, $5, 'APPROVED', $6, $7, NOW())
                        RETURNING id
                        """,
                        agent_user_id,
                        order_id,
                        case_id,
                        float(rate),
                        commission_amount,
                        idem_key,
                        actor_user_id,
                    )

                    if commission_amount > 0:
                        await self.wallet_svc.credit_commission(
                            user_id=agent_user_id,
                            amount_toman=commission_amount,
                            reference_id=str(case_id),
                            idempotency_key=idem_key,
                            description=f"پورسانت پرونده فروش {case_id}",
                            created_by=actor_user_id,
                            conn=conn,
                        )

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, $2, 'SALE_FINANCIAL_FINALIZED', 'sales_cases', $3::varchar, $4::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(case_id),
                    json.dumps(
                        {
                            "order_id": str(order_id),
                            "membership_id": str(mem_row["id"]),
                            "commission_id": str(comm_row["id"]),
                            "commission_amount_toman": commission_amount,
                            "trigger": trigger,
                        }
                    ),
                )

                return {
                    "case": dict(updated_case),
                    "order_id": order_id,
                    "membership_id": mem_row["id"],
                    "commission_id": comm_row["id"],
                    "commission_amount_toman": commission_amount,
                }

    async def get_sales_case(
        self,
        case_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        """
        Retrieves sales case strictly for owning APPROVED agent, ADMIN, SUPER_ADMIN, or SUPPORT (`T19-AC2`).
        Applies PII masking (`mask_national_code`, `mask_phone`) for non-ADMIN viewers (`T19-AC5`).
        """
        if actor_user_id is None:
            raise SalesAuthorizationError("Authenticated actor_user_id is required.")

        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise SalesAuthorizationError(str(exc)) from exc

            is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
            is_support = "SUPPORT" in actor_roles

            row = await conn.fetchrow(
                """
                SELECT sc.*, dp.title AS plan_title, dp.price_toman,
                       ph.first_name AS holder_first_name, ph.last_name AS holder_last_name,
                       ph.national_code AS holder_national_code, ph.mobile AS holder_mobile,
                       a.business_name AS agent_business_name,
                       a.user_id AS agent_user_id,
                       a.verification_status AS agent_verification_status
                FROM sales_cases sc
                JOIN discount_plans dp ON sc.plan_id = dp.id
                JOIN plan_holders ph ON sc.holder_id = ph.id
                JOIN agents a ON sc.agent_id = a.id
                WHERE sc.id = $1
                """,
                case_id,
            )
            if not row:
                if is_admin or is_support:
                    raise SalesCaseNotFoundError(f"Sales case {case_id} not found.")
                raise SalesAuthorizationError(
                    "Access denied: You are not authorized to access this sales case."
                )

            is_owning_approved_agent = (
                "AGENT" in actor_roles
                and row["agent_user_id"] == actor_user_id
                and row["agent_verification_status"] == "APPROVED"
            )
            if not (is_admin or is_support or is_owning_approved_agent):
                raise SalesAuthorizationError(
                    "Access denied: You are not authorized to view this sales case."
                )

            data = dict(row)
            data.pop("agent_user_id", None)
            data.pop("agent_verification_status", None)

            if not is_admin:
                data["holder_national_code"] = mask_national_code(
                    data.get("holder_national_code")
                )
                data["holder_mobile"] = mask_phone(data.get("holder_mobile"))

            return data
