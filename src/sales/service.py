"""
Sales Cases & Agent Logistics Domain Service (SALE-001..013, AC-09, AC-10)
REMEDIATION: HC-T19 (F-12 HIGH, T19-AC1, T19-AC2, T19-AC5)

Security & State Machine Guarantees:
- Agent Binding: Ordinary agents CANNOT create sales cases under another agent's `agent_id`
  without explicit `ADMIN` / `SUPER_ADMIN` override (logged in `audit_logs`). Unapproved
  (`PENDING`, `REJECTED`, `SUSPENDED`) agents fail closed (`403`).
- Logistics Authorization: Only `ADMIN` / `SUPER_ADMIN` may advance logistics states,
  enforcing strict forward state transitions and postal tracking invariants (`AC-09`).
- Financial Finalization: Strictly gated on `commissions:approve` (`ADMIN`/`SUPER_ADMIN`),
  non-returned/approved logistics status, `OPEN_03` + `OPEN_18` approved policies, and exact
  `Decimal` commission math credited atomically via `WalletService`.
- Ownership & PII Filtering: Case retrieval restricted to owning APPROVED agent, `ADMIN`,
  `SUPER_ADMIN`, or `SUPPORT`, masking holder `national_code` and `mobile` for non-admin viewers.
"""

import json
import uuid
from datetime import UTC, datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal
from typing import Any, Dict, Set

import asyncpg

from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.common.pii import mask_national_code, mask_phone
from src.core.policy import require_approved_policy
from src.wallets.service import WalletService

ALLOWED_LOGISTIC_TRANSITIONS: Dict[str, Set[str]] = {
    "PENDING_REVIEW": {"APPROVED", "RETURNED"},
    "APPROVED": {"CARD_ISSUED", "RETURNED"},
    "CARD_ISSUED": {"SHIPPED", "RETURNED"},
    "SHIPPED": {"DELIVERED", "RETURNED"},
    "DELIVERED": {"RETURNED"},
    "RETURNED": set(),
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

    async def finalize_financial_status(
        self,
        case_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
    ) -> Dict[str, Any]:
        """
        Finalizes financial state of an approved sales case (`commissions:approve` / ADMIN),
        computes exact Decimal agent commission per `OPEN_18`, and credits wallet atomically (AC-10).
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

                await require_approved_policy(conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER")
                rounding_policy = await require_approved_policy(
                    conn, "OPEN_18_CURRENCY_AND_ROUNDING"
                )

                case = await conn.fetchrow(
                    """
                    SELECT sc.*, dp.price_toman, dp.agent_commission_percent, a.user_id AS agent_user_id
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
                if case["logistic_status"] in ("PENDING_REVIEW", "RETURNED"):
                    raise InvalidStateTransitionError(
                        f"Cannot finalize sales case in logistic_status '{case['logistic_status']}'."
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
                    WHERE id = $2
                    RETURNING *
                    """,
                    actor_user_id,
                    case_id,
                )

                comm_row = await conn.fetchrow(
                    """
                    INSERT INTO commissions (
                        beneficiary_user_id, commission_type, source_sales_case_id,
                        rate_percent, amount_toman, status, idempotency_key,
                        approved_by, approved_at
                    ) VALUES ($1, 'AGENT_SALE', $2, $3, $4, 'APPROVED', $5, $6, NOW())
                    ON CONFLICT (idempotency_key) DO UPDATE SET updated_at = NOW()
                    RETURNING id
                    """,
                    agent_user_id,
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
                            "commission_id": str(comm_row["id"]),
                            "commission_amount_toman": commission_amount,
                        }
                    ),
                )

                return {
                    "case": dict(updated_case),
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
