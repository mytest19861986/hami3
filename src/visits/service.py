"""
Visits Domain Service (VISIT-001..013, AC-07, AC-08)
Executes atomic quota decrement on memberships, calculates financial discounts,
manages doctor visit logs, cancellation rollback, and clinical audit trail.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List

import asyncpg

from src.core.policy import require_approved_policy, round_toman


class VisitError(Exception):
    """Base exception for visit operations."""
    pass


class QuotaExhaustedError(VisitError):
    """Raised when membership quota has 0 remaining visits (AC-07)."""
    pass


class MembershipInactiveError(VisitError):
    """Raised when membership is not in ACTIVE status or expired."""
    pass


class VisitCancellationError(VisitError):
    """Raised on invalid visit cancellation."""
    pass


class VisitService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def record_visit(
        self,
        doctor_id: uuid.UUID,
        holder_id: uuid.UUID,
        membership_id: uuid.UUID,
        service_title: str,
        total_amount_toman: int,
        discount_percent: float,
        private_notes: str | None = None
    ) -> Dict[str, Any]:
        """
        Records a medical visit with atomic quota decrement and financial computation.
        Strictly enforces AC-07: Zero overselling, atomic Row Count check.
        """
        title_clean = service_title.strip()
        if not title_clean:
            raise VisitError("Service title cannot be empty.")
        if total_amount_toman < 0:
            raise VisitError("Total amount cannot be negative.")
        if discount_percent < 0 or discount_percent > 100:
            raise VisitError("Discount percent must be between 0 and 100.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                rounding_policy = await require_approved_policy(
                    conn, "OPEN_18_CURRENCY_AND_ROUNDING"
                )
                med_limit = await require_approved_policy(
                    conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT"
                )
                if private_notes and not med_limit.get("allow_private_notes", True):
                    raise VisitError(
                        "Private clinical notes are disabled by OPEN-16 policy."
                    )

                # Compute monetary breakdown per OPEN-18 policy
                discount_amount = round_toman(
                    total_amount_toman * (discount_percent / 100.0), rounding_policy
                )
                patient_paid_amount = total_amount_toman - discount_amount

                # 1. Fetch membership to check unlimited vs bounded quota
                mem = await conn.fetchrow(
                    """
                    SELECT id, status, end_date, max_visits, remaining_visits, used_visits
                    FROM memberships
                    WHERE id = $1 AND holder_id = $2
                    FOR UPDATE
                    """, membership_id, holder_id
                )
                if not mem:
                    raise MembershipInactiveError("Membership not found for this card holder.")

                if mem["status"] != "ACTIVE":
                    raise MembershipInactiveError(f"Membership is in status '{mem['status']}'. Must be ACTIVE.")

                # Check expiration
                if mem["end_date"] <= datetime.now(mem["end_date"].tzinfo):
                    await conn.execute(
                        "UPDATE memberships SET status = 'EXPIRED' WHERE id = $1", membership_id
                    )
                    raise MembershipInactiveError("Membership has expired.")

                # 2. Atomic Quota Decrement
                if mem["max_visits"] is not None:
                    # Bounded quota: Atomic conditional update
                    res = await conn.fetchrow(
                        """
                        UPDATE memberships
                        SET used_visits = used_visits + 1,
                            remaining_visits = remaining_visits - 1,
                            status = CASE WHEN remaining_visits - 1 = 0 THEN 'EXHAUSTED' ELSE status END,
                            updated_at = NOW()
                        WHERE id = $1 AND status = 'ACTIVE' AND remaining_visits >= 1
                        RETURNING id, remaining_visits, used_visits, status
                        """, membership_id
                    )
                    if not res:
                        raise QuotaExhaustedError("Membership quota exhausted: remaining_visits = 0 (AC-07).")
                else:
                    # Unlimited quota (max_visits IS NULL)
                    await conn.execute(
                        """
                        UPDATE memberships
                        SET used_visits = used_visits + 1,
                            updated_at = NOW()
                        WHERE id = $1 AND status = 'ACTIVE'
                        """, membership_id
                    )

                # 3. Create Visit Record
                visit_row = await conn.fetchrow(
                    """
                    INSERT INTO visits (
                        doctor_id, holder_id, membership_id, service_title,
                        total_amount_toman, discount_percent, discount_amount_toman,
                        patient_paid_amount_toman, status, private_notes
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'COMPLETED', $9)
                    RETURNING id, doctor_id, holder_id, membership_id, service_title,
                              total_amount_toman, discount_percent, discount_amount_toman,
                              patient_paid_amount_toman, status, visit_date, private_notes,
                              created_at
                    """,
                    doctor_id, holder_id, membership_id, title_clean,
                    total_amount_toman, discount_percent, discount_amount,
                    patient_paid_amount, private_notes
                )

                # 4. Audit Log
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        'DOCTOR', 'VISIT_RECORDED', 'visits', $1::varchar,
                        jsonb_build_object(
                            'doctor_id', $2::varchar,
                            'holder_id', $3::varchar,
                            'total_toman', $4::bigint,
                            'discount_toman', $5::bigint
                        )
                    )
                    """, str(visit_row["id"]), str(doctor_id), str(holder_id),
                    total_amount_toman, discount_amount
                )

                return dict(visit_row)

    async def cancel_visit(
        self,
        visit_id: uuid.UUID,
        canceller_user_id: uuid.UUID,
        reason: str
    ) -> Dict[str, Any]:
        """
        Cancels a visit, reverts quota consumption on membership atomically, and logs reason.
        """
        reason_clean = reason.strip()
        if not reason_clean:
            raise VisitError("Cancellation reason cannot be empty.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                refund_policy = await require_approved_policy(
                    conn, "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY"
                )

                # 1. Fetch visit
                visit = await conn.fetchrow(
                    "SELECT * FROM visits WHERE id = $1 FOR UPDATE", visit_id
                )
                if not visit:
                    raise VisitError(f"Visit {visit_id} not found.")

                if visit["status"] == "CANCELLED":
                    raise VisitCancellationError("Visit is already cancelled.")

                # 2. Revert quota on membership if OPEN-07 policy restores quota
                if refund_policy.get("restore_quota", True):
                    await conn.execute(
                        """
                        UPDATE memberships
                        SET used_visits = GREATEST(0, used_visits - 1),
                            remaining_visits = CASE WHEN remaining_visits IS NOT NULL THEN remaining_visits + 1 ELSE NULL END,
                            status = CASE WHEN status = 'EXHAUSTED' THEN 'ACTIVE' ELSE status END,
                            updated_at = NOW()
                        WHERE id = $1
                        """, visit["membership_id"]
                    )

                # 3. Update visit status
                cancelled_row = await conn.fetchrow(
                    """
                    UPDATE visits
                    SET status = 'CANCELLED',
                        cancellation_reason = $1,
                        cancelled_by = $2,
                        cancelled_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $3
                    RETURNING *
                    """, reason_clean, canceller_user_id, visit_id
                )

                # 4. Audit Log
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, 'VISIT_CANCELLED', 'visits', $2::varchar,
                        jsonb_build_object('reason', $3::text)
                    )
                    """, canceller_user_id, str(visit_id), reason_clean
                )

                return dict(cancelled_row)

    async def get_visit_by_id(self, visit_id: uuid.UUID) -> Dict[str, Any]:
        """Retrieves single visit with detailed financial breakdown."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT v.*, d.clinic_name, d.specialty,
                       ph.first_name as patient_first_name, ph.last_name as patient_last_name,
                       ph.national_code as patient_national_code
                FROM visits v
                JOIN doctors d ON v.doctor_id = d.id
                JOIN plan_holders ph ON v.holder_id = ph.id
                WHERE v.id = $1
                """, visit_id
            )
            if not row:
                raise VisitError(f"Visit {visit_id} not found.")
            return dict(row)

    async def list_doctor_visits(
        self,
        doctor_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Lists visits handled by a specific doctor."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT v.*, ph.first_name as patient_first_name, ph.last_name as patient_last_name
                FROM visits v
                JOIN plan_holders ph ON v.holder_id = ph.id
                WHERE v.doctor_id = $1
                ORDER BY v.visit_date DESC
                LIMIT $2 OFFSET $3
                """, doctor_id, limit, offset
            )
            return [dict(r) for r in rows]
