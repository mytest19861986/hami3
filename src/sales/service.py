"""
Sales Cases & Agent Logistics Domain Service (SALE-001..013, AC-09, AC-10)
Enforces the dual state machine for agent sales:
- Logistic: PENDING_REVIEW -> APPROVED -> CARD_ISSUED -> SHIPPED -> DELIVERED (or RETURNED)
- Financial: UNPAID -> PAYMENT_RECORDED -> FINALIZED (or CANCELLED)
Integrates with wallet service for automated commission payout upon finalization.
"""

import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncpg

from src.wallets.service import WalletService


class SalesCaseError(Exception):
    """Base exception for sales case operations."""
    pass


class InvalidStateTransitionError(SalesCaseError):
    """Raised on invalid state transitions in the dual state machine."""
    pass


class AgentNotApprovedError(SalesCaseError):
    """Raised when an unapproved agent attempts sales operations."""
    pass


class SalesCaseService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.wallet_svc = WalletService(pool)

    async def create_sales_case(
        self,
        agent_id: uuid.UUID,
        holder_id: uuid.UUID,
        plan_id: uuid.UUID,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates a new sales case initiated by an approved sales agent."""
        async with self.pool.acquire() as conn:
            # 1. Verify agent is APPROVED
            agent = await conn.fetchrow(
                "SELECT id, user_id, verification_status FROM agents WHERE id = $1",
                agent_id
            )
            if not agent:
                raise SalesCaseError(f"Agent {agent_id} not found.")
            if agent["verification_status"] != "APPROVED":
                raise AgentNotApprovedError("Only APPROVED agents can register sales cases (AC-03).")

            # 2. Verify plan is active
            plan = await conn.fetchrow(
                "SELECT id, price_toman, is_active FROM discount_plans WHERE id = $1",
                plan_id
            )
            if not plan or not plan["is_active"]:
                raise SalesCaseError("Selected discount plan is inactive or not found.")

            # 3. Create sales case with initial dual states
            row = await conn.fetchrow(
                """
                INSERT INTO sales_cases (
                    agent_id, holder_id, plan_id, logistic_status,
                    financial_status, notes
                ) VALUES ($1, $2, $3, 'PENDING_REVIEW', 'UNPAID', $4)
                RETURNING *
                """, agent_id, holder_id, plan_id, notes
            )
            return dict(row)

    async def update_logistic_status(
        self,
        case_id: uuid.UUID,
        new_status: str,
        actor_user_id: uuid.UUID,
        shipping_tracking_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Transitions logistic state with strict invariant validation:
        - CARD_ISSUED requires previous state APPROVED.
        - SHIPPED requires shipping_tracking_code.
        - DELIVERED sets delivery_date.
        """
        valid_statuses = ['PENDING_REVIEW', 'APPROVED', 'CARD_ISSUED', 'SHIPPED', 'DELIVERED', 'RETURNED']
        if new_status not in valid_statuses:
            raise InvalidStateTransitionError(f"Invalid logistic status: {new_status}")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                case = await conn.fetchrow(
                    "SELECT * FROM sales_cases WHERE id = $1 FOR UPDATE", case_id
                )
                if not case:
                    raise SalesCaseError(f"Sales case {case_id} not found.")

                current = case["logistic_status"]

                # Invariant: CARD_ISSUED requires APPROVED
                if new_status == 'CARD_ISSUED' and current not in ('APPROVED', 'CARD_ISSUED'):
                    raise InvalidStateTransitionError("Physical card can only be issued after logistics approval.")

                # Invariant: SHIPPED requires tracking code
                if new_status == 'SHIPPED':
                    code = shipping_tracking_code or case["shipping_tracking_code"]
                    if not code or not code.strip():
                        raise InvalidStateTransitionError("Shipping tracking code is required to transition to SHIPPED.")

                delivery_date = datetime.now() if new_status == 'DELIVERED' else case["delivery_date"]
                tracking = shipping_tracking_code.strip() if shipping_tracking_code else case["shipping_tracking_code"]

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
                    """, new_status, tracking, delivery_date, actor_user_id, case_id
                )

                # Audit log
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, 'LOGISTIC_STATUS_UPDATED', 'sales_cases', $2::varchar,
                        jsonb_build_object('old_status', $3::varchar, 'new_status', $4::varchar)
                    )
                    """, actor_user_id, str(case_id), current, new_status
                )

                return dict(updated)

    async def finalize_financial_status(
        self,
        case_id: uuid.UUID,
        actor_user_id: uuid.UUID
    ) -> Dict[str, Any]:
        """
        Finalizes financial state of sales case:
        - Sets financial_status = 'FINALIZED'.
        - Computes agent commission from discount plan.
        - Inserts record into commissions table.
        - Atomically credits agent wallet via WalletService.
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                case = await conn.fetchrow(
                    """
                    SELECT sc.*, dp.price_toman, dp.agent_commission_percent, a.user_id as agent_user_id
                    FROM sales_cases sc
                    JOIN discount_plans dp ON sc.plan_id = dp.id
                    JOIN agents a ON sc.agent_id = a.id
                    WHERE sc.id = $1 FOR UPDATE
                    """, case_id
                )
                if not case:
                    raise SalesCaseError(f"Sales case {case_id} not found.")

                if case["financial_status"] == 'FINALIZED':
                    raise InvalidStateTransitionError("Sales case is already finalized.")

                # Compute commission
                rate = float(case["agent_commission_percent"])
                price = int(case["price_toman"])
                commission_amount = int(round(price * (rate / 100.0)))
                agent_user_id = case["agent_user_id"]
                idem_key = f"COMM-SALE-{case_id}"

                # Update sales case
                updated_case = await conn.fetchrow(
                    """
                    UPDATE sales_cases
                    SET financial_status = 'FINALIZED',
                        reviewed_by = $1,
                        reviewed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $2
                    RETURNING *
                    """, actor_user_id, case_id
                )

                # Insert commission record
                comm_row = await conn.fetchrow(
                    """
                    INSERT INTO commissions (
                        beneficiary_user_id, commission_type, source_sales_case_id,
                        rate_percent, amount_toman, status, idempotency_key,
                        approved_by, approved_at
                    ) VALUES ($1, 'AGENT_SALE', $2, $3, $4, 'APPROVED', $5, $6, NOW())
                    ON CONFLICT (idempotency_key) DO UPDATE SET updated_at = NOW()
                    RETURNING id
                    """, agent_user_id, case_id, rate, commission_amount, idem_key, actor_user_id
                )

                # Credit agent wallet
                if commission_amount > 0:
                    await self.wallet_svc.credit_commission(
                        user_id=agent_user_id,
                        amount_toman=commission_amount,
                        reference_id=str(case_id),
                        idempotency_key=idem_key,
                        description=f"پورسانت پرونده فروش {case_id}",
                        created_by=actor_user_id
                    )

                return {
                    "case": dict(updated_case),
                    "commission_id": comm_row["id"],
                    "commission_amount_toman": commission_amount
                }

    async def get_sales_case(self, case_id: uuid.UUID) -> Dict[str, Any]:
        """Retrieves sales case by ID with plan and holder details."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT sc.*, dp.title as plan_title, dp.price_toman,
                       ph.first_name as holder_first_name, ph.last_name as holder_last_name,
                       ph.national_code as holder_national_code, ph.mobile as holder_mobile,
                       a.business_name as agent_business_name
                FROM sales_cases sc
                JOIN discount_plans dp ON sc.plan_id = dp.id
                JOIN plan_holders ph ON sc.holder_id = ph.id
                JOIN agents a ON sc.agent_id = a.id
                WHERE sc.id = $1
                """, case_id
            )
            if not row:
                raise SalesCaseError(f"Sales case {case_id} not found.")
            return dict(row)
