"""
Discount Plans Service (PLAN-001..013)
Handles subscription and discount plan catalog, pricing in Toman,
validity durations, visit quotas, and agent/referrer commission rates.
"""

import uuid
from typing import Any, Dict, List

import asyncpg


class PlanError(Exception):
    """Base exception for plan domain errors."""
    pass


class PlanNotFoundError(PlanError):
    """Raised when discount plan is not found."""
    pass


class DiscountPlanService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def create_plan(
        self,
        title: str,
        price_toman: int,
        discount_percent: float,
        validity_days: int,
        max_visits: int | None = None,
        agent_commission_percent: float = 0.0,
        referrer_commission_percent: float = 0.0,
        description: str | None = None,
        created_by: uuid.UUID | None = None,
        is_active: bool = True
    ) -> Dict[str, Any]:
        """Creates a new discount plan with strict domain parameter validation."""
        title_clean = title.strip()
        if not title_clean:
            raise PlanError("Plan title cannot be empty.")
        if price_toman < 0:
            raise PlanError("Price in Toman cannot be negative.")
        if discount_percent < 0 or discount_percent > 100:
            raise PlanError("Discount percent must be between 0 and 100.")
        if validity_days <= 0:
            raise PlanError("Validity days must be positive.")
        if max_visits is not None and max_visits <= 0:
            raise PlanError("Max visits must be greater than zero.")
        if agent_commission_percent < 0 or agent_commission_percent > 100:
            raise PlanError("Agent commission must be between 0 and 100.")
        if referrer_commission_percent < 0 or referrer_commission_percent > 100:
            raise PlanError("Referrer commission must be between 0 and 100.")

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO discount_plans (
                    title, description, price_toman, discount_percent,
                    validity_days, max_visits, agent_commission_percent,
                    referrer_commission_percent, is_active, created_by
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING id, title, description, price_toman, discount_percent,
                          validity_days, max_visits, agent_commission_percent,
                          referrer_commission_percent, is_active, created_by,
                          created_at, updated_at
                """,
                title_clean, description, price_toman, discount_percent,
                validity_days, max_visits, agent_commission_percent,
                referrer_commission_percent, is_active, created_by
            )
            return dict(row)

    async def get_plan_by_id(self, plan_id: uuid.UUID) -> Dict[str, Any]:
        """Retrieves plan by ID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM discount_plans WHERE id = $1", plan_id
            )
            if not row:
                raise PlanNotFoundError(f"Plan {plan_id} not found.")
            return dict(row)

    async def get_active_catalog(self) -> List[Dict[str, Any]]:
        """Returns all currently active plans for public purchase."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, title, description, price_toman, discount_percent,
                       validity_days, max_visits, created_at
                FROM discount_plans
                WHERE is_active = TRUE
                ORDER BY price_toman ASC
                """
            )
            return [dict(r) for r in rows]

    async def toggle_plan_status(
        self,
        plan_id: uuid.UUID,
        is_active: bool,
        admin_id: uuid.UUID
    ) -> Dict[str, Any]:
        """Enables or disables a plan from public purchase."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE discount_plans
                    SET is_active = $1, updated_at = NOW()
                    WHERE id = $2
                    RETURNING id, title, is_active, updated_at
                    """, is_active, plan_id
                )
                if not row:
                    raise PlanNotFoundError(f"Plan {plan_id} not found.")

                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        new_values
                    ) VALUES (
                        $1, 'ADMIN', 'PLAN_STATUS_TOGGLED', 'discount_plans', $2,
                        jsonb_build_object('is_active', $3::boolean)
                    )
                    """, admin_id, str(plan_id), is_active
                )
                return dict(row)
