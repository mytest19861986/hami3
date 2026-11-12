"""
Visits Domain Service (VISIT-001..013, AC-07, AC-08)
REMEDIATION: HC-T18 (F-08, F-09, F-10 HIGH, T18-AC1..AC5), HC-T25 (D-2 VISIT-009, OPEN-02)

Security & Concurrency Guarantees:
- Service-boundary authorization via authoritative `user_roles` (`RbacEngine`):
  * Doctors MUST have active `'DOCTOR'` role AND `doctors.verification_status == 'APPROVED'`.
  * Ordinary doctors are strictly bound to their own `doctors.id` (doctor impersonation -> 403).
  * `ADMIN` / `SUPER_ADMIN` overrides require target doctor APPROVED and record actual
    `actor_user_id`, `actor_role`, and `admin_override=True` in `audit_logs`.
- Authoritative Server-Derived Discount (`VISIT-009 P0`, `OPEN-02`, `OPEN-18`):
  * Client-submitted `discount_percent` is NEVER trusted or applied.
  * Effective rate is resolved atomically on the server from DB `discount_plans.discount_percent`
    and `doctors.custom_discount_percent`, governed by approved `OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE`
    (`CUSTOM_FIRST` or `PLAN_FIRST`, fail-closed if unapproved or invalid).
  * All rates validated in `[0, 100]` using `Decimal`, rounded strictly under approved `OPEN_18`,
    and persisted with a traceable audit calculation snapshot before any quota consumption.
- Visit cancellation requires explicit `'visits:cancel'` permission (`ADMIN` / `SUPER_ADMIN`),
  executes an atomic conditional transition (`WHERE status='COMPLETED'`), and restores quota
  at most once (`T18-AC4`).
- Visit read & listing enforce strict IDOR ownership + `mask_national_code` + redaction of
  `private_notes` from unauthorized / non-owning / support viewers.
- Atomic `FOR UPDATE` row locking preserves `AC-07` zero-overselling under parallel bursts.
"""

import json
import uuid
from datetime import datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Dict, List, Set

import asyncpg

from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.common.pii import mask_national_code
from src.core.policy import require_approved_policy

ALLOWED_DISCOUNT_PRECEDENCE_MODES = {"CUSTOM_FIRST", "PLAN_FIRST"}
ALLOWED_ROUNDING_MODES = {"FLOOR", "CEIL", "HALF_UP"}
MAX_TOMAN_AMOUNT = 10_000_000_000_000


class VisitError(Exception):
    """Base exception for visit operations."""
    pass


class VisitAuthorizationError(VisitError):
    """Raised when an actor lacks RBAC permission, ownership, or APPROVED doctor status."""
    pass


class VisitNotFoundError(VisitError):
    """Raised when target visit or doctor does not exist."""
    pass


class QuotaExhaustedError(VisitError):
    """Raised when membership quota has 0 remaining visits (AC-07)."""
    pass


class MembershipInactiveError(VisitError):
    """Raised when membership is not in ACTIVE status or expired."""
    pass


class VisitCancellationError(VisitError):
    """Raised on invalid or repeated visit cancellation."""
    pass


def _resolve_actor_role_label(roles: Set[str]) -> str:
    for candidate in ("SUPER_ADMIN", "ADMIN", "DOCTOR", "SUPPORT", "AGENT", "USER"):
        if candidate in roles:
            return candidate
    return "USER"


def _parse_validated_rate(value: Any, label: str) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise VisitError(f"Invalid boolean type for {label}.")
    try:
        dec = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise VisitError(f"Malformed {label} value.") from exc
    if not dec.is_finite():
        raise VisitError(f"{label} must be finite.")
    if dec < Decimal("0") or dec > Decimal("100"):
        raise VisitError(f"{label} must be between 0 and 100.")
    return dec.quantize(Decimal("0.01"))


def _round_percent_toman(
    total_amount_toman: int,
    discount_percent: Decimal,
    rounding_policy: Dict[str, Any] | None = None,
) -> int:
    raw = (Decimal(int(total_amount_toman)) * discount_percent) / Decimal("100")
    mode = str((rounding_policy or {}).get("rounding_mode", "")).strip().upper()
    if mode not in ALLOWED_ROUNDING_MODES:
        raise VisitError(f"Unsupported OPEN_18 rounding_mode '{mode}'.")
    if mode == "FLOOR":
        return int(raw.to_integral_value(rounding=ROUND_FLOOR))
    if mode == "CEIL":
        return int(raw.to_integral_value(rounding=ROUND_CEILING))
    return int(raw.to_integral_value(rounding=ROUND_HALF_UP))


class VisitService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.rbac = RbacEngine(pool)

    async def record_visit(
        self,
        holder_id: uuid.UUID,
        membership_id: uuid.UUID,
        service_title: str,
        total_amount_toman: int,
        discount_percent: float | None = None,
        actor_user_id: uuid.UUID | None = None,
        doctor_id: uuid.UUID | None = None,
        private_notes: str | None = None,
    ) -> Dict[str, Any]:
        """
        Records a medical visit with strict service-boundary actor/doctor authorization,
        server-derived Decimal discount calculation (`OPEN_02` + `OPEN_18`), and atomic
        quota decrement (`AC-07`, `T18-AC1/AC2/AC5`, `T25-AC1..AC4`).
        Any caller-supplied `discount_percent` is strictly non-authoritative and ignored.
        """
        if actor_user_id is None:
            raise VisitAuthorizationError("Authenticated actor_user_id is required to record visits.")

        title_clean = (service_title or "").strip()
        if not title_clean:
            raise VisitError("Service title cannot be empty.")
        if isinstance(total_amount_toman, bool) or not isinstance(total_amount_toman, int):
            raise VisitError("Total amount must be an integer Toman value.")
        if total_amount_toman < 0 or total_amount_toman > MAX_TOMAN_AMOUNT:
            raise VisitError("Total amount is negative or out of bounds.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise VisitAuthorizationError(str(exc)) from exc

                is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
                is_doctor = "DOCTOR" in actor_roles
                if not is_admin and not is_doctor:
                    raise VisitAuthorizationError(
                        "Only APPROVED doctors or administrators may record medical visits."
                    )

                # Resolve and bind target doctor identity authoritatively
                actor_doc = await conn.fetchrow(
                    "SELECT id, user_id, verification_status, custom_discount_percent FROM doctors WHERE user_id = $1",
                    actor_user_id,
                )

                if is_admin:
                    lookup_doc_id = doctor_id or (actor_doc["id"] if actor_doc else None)
                    if lookup_doc_id is None:
                        raise VisitError("Target doctor_id is required when recording as admin.")
                    target_doc = await conn.fetchrow(
                        "SELECT id, user_id, verification_status, custom_discount_percent FROM doctors WHERE id = $1",
                        lookup_doc_id,
                    )
                    if not target_doc:
                        raise VisitNotFoundError(f"Doctor {lookup_doc_id} not found.")
                    if target_doc["verification_status"] != "APPROVED":
                        raise VisitAuthorizationError(
                            f"Target doctor account is in '{target_doc['verification_status']}' status; must be APPROVED."
                        )
                    resolved_doctor_id = target_doc["id"]
                    doctor_custom_rate_raw = target_doc["custom_discount_percent"]
                    admin_override = target_doc["user_id"] != actor_user_id
                else:
                    if not actor_doc:
                        raise VisitAuthorizationError("Actor does not have a registered doctor profile.")
                    if actor_doc["verification_status"] != "APPROVED":
                        raise VisitAuthorizationError(
                            f"Doctor account is in '{actor_doc['verification_status']}' status; operational visit recording blocked."
                        )
                    if doctor_id is not None and doctor_id != actor_doc["id"]:
                        raise VisitAuthorizationError(
                            "Forbidden: Doctor cannot record visits impersonating another doctor_id."
                        )
                    resolved_doctor_id = actor_doc["id"]
                    doctor_custom_rate_raw = actor_doc["custom_discount_percent"]
                    admin_override = False

                # Fail-closed policy checks BEFORE any membership lock or quota mutation (T25-AC3)
                precedence_policy = await require_approved_policy(
                    conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE"
                )
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

                precedence = str((precedence_policy or {}).get("precedence") or "").strip().upper()
                if precedence not in ALLOWED_DISCOUNT_PRECEDENCE_MODES:
                    raise VisitError(
                        f"Unsupported OPEN_02 precedence policy '{precedence}'."
                    )
                rounding_mode = str((rounding_policy or {}).get("rounding_mode") or "").strip().upper()
                if rounding_mode not in ALLOWED_ROUNDING_MODES:
                    raise VisitError(
                        f"Unsupported OPEN_18 rounding_mode '{rounding_mode}'."
                    )

                # 1. Lock membership row and fetch trusted DB discount_plan rate
                mem = await conn.fetchrow(
                    """
                    SELECT m.id, m.status, m.end_date, m.max_visits, m.remaining_visits, m.used_visits,
                           m.plan_id, dp.discount_percent AS plan_discount_percent
                    FROM memberships m
                    JOIN discount_plans dp ON m.plan_id = dp.id
                    WHERE m.id = $1 AND m.holder_id = $2
                    FOR UPDATE OF m
                    """,
                    membership_id,
                    holder_id,
                )
                if not mem:
                    raise MembershipInactiveError("Membership not found for this card holder.")

                if mem["status"] != "ACTIVE":
                    raise MembershipInactiveError(
                        f"Membership is in status '{mem['status']}'. Must be ACTIVE."
                    )

                if mem["end_date"] <= datetime.now(mem["end_date"].tzinfo):
                    await conn.execute(
                        "UPDATE memberships SET status = 'EXPIRED' WHERE id = $1",
                        membership_id,
                    )
                    raise MembershipInactiveError("Membership has expired.")

                # Validate DB rates & derive authoritative effective discount BEFORE decrementing quota
                plan_rate = _parse_validated_rate(
                    mem["plan_discount_percent"], "plan discount_percent"
                )
                doctor_rate = _parse_validated_rate(
                    doctor_custom_rate_raw, "doctor custom_discount_percent"
                )

                if precedence == "CUSTOM_FIRST":
                    if doctor_rate is not None:
                        effective_rate = doctor_rate
                        applied_source = "DOCTOR_CUSTOM"
                    elif plan_rate is not None:
                        effective_rate = plan_rate
                        applied_source = "PLAN_DEFAULT"
                    else:
                        raise VisitError("No valid server discount rate found for visit.")
                else:  # PLAN_FIRST
                    if plan_rate is not None:
                        effective_rate = plan_rate
                        applied_source = "PLAN_DEFAULT"
                    elif doctor_rate is not None:
                        effective_rate = doctor_rate
                        applied_source = "DOCTOR_CUSTOM"
                    else:
                        raise VisitError("No valid server discount rate found for visit.")

                # Exact Decimal breakdown per OPEN-18 policy (zero float math!)
                discount_amount = _round_percent_toman(
                    total_amount_toman, effective_rate, rounding_policy
                )
                if discount_amount < 0 or discount_amount > total_amount_toman:
                    raise VisitError("Calculated discount amount is out of valid bounds.")
                patient_paid_amount = int(total_amount_toman) - discount_amount

                # 2. Atomic Quota Decrement (AC-07)
                if mem["max_visits"] is not None:
                    res = await conn.fetchrow(
                        """
                        UPDATE memberships
                        SET used_visits = used_visits + 1,
                            remaining_visits = remaining_visits - 1,
                            status = CASE WHEN remaining_visits - 1 = 0 THEN 'EXHAUSTED' ELSE status END,
                            updated_at = NOW()
                        WHERE id = $1 AND status = 'ACTIVE' AND remaining_visits >= 1
                        RETURNING id, remaining_visits, used_visits, status
                        """,
                        membership_id,
                    )
                    if not res:
                        raise QuotaExhaustedError(
                            "Membership quota exhausted: remaining_visits = 0 (AC-07)."
                        )
                else:
                    await conn.execute(
                        """
                        UPDATE memberships
                        SET used_visits = used_visits + 1,
                            updated_at = NOW()
                        WHERE id = $1 AND status = 'ACTIVE'
                        """,
                        membership_id,
                    )

                # 3. Create Visit Record using authoritative server-derived effective_rate
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
                    resolved_doctor_id,
                    holder_id,
                    membership_id,
                    title_clean,
                    total_amount_toman,
                    effective_rate,
                    discount_amount,
                    patient_paid_amount,
                    private_notes,
                )

                # 4. Authoritative Audit Log with traceable pricing snapshot (no clinical notes or patient national code!)
                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, $2, 'VISIT_RECORDED', 'visits', $3::varchar, $4::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(visit_row["id"]),
                    json.dumps(
                        {
                            "doctor_id": str(resolved_doctor_id),
                            "holder_id": str(holder_id),
                            "membership_id": str(membership_id),
                            "plan_id": str(mem["plan_id"]),
                            "total_toman": int(total_amount_toman),
                            "plan_discount_percent": str(plan_rate) if plan_rate is not None else None,
                            "doctor_custom_discount_percent": str(doctor_rate) if doctor_rate is not None else None,
                            "precedence_policy": precedence,
                            "rounding_mode": rounding_mode,
                            "applied_source": applied_source,
                            "effective_discount_percent": str(effective_rate),
                            "discount_toman": int(discount_amount),
                            "patient_paid_amount_toman": int(patient_paid_amount),
                            "client_discount_ignored": discount_percent is not None,
                            "admin_override": admin_override,
                        },
                        ensure_ascii=False,
                    ),
                )

                visit_dict = dict(visit_row)
                visit_dict["applied_discount_source"] = applied_source
                visit_dict["discount_precedence_policy"] = precedence
                return visit_dict

    async def cancel_visit(
        self,
        visit_id: uuid.UUID,
        canceller_user_id: uuid.UUID | None,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Cancels a visit strictly for `visits:cancel`-authorized admins (`ADMIN` / `SUPER_ADMIN`),
        atomically transitions status once (`WHERE status='COMPLETED'`), restores bounded quota
        at most once, and records actual actor + role (`F-09`, `T18-AC4`).
        """
        if canceller_user_id is None:
            raise VisitAuthorizationError("Authenticated canceller_user_id is required.")

        reason_clean = (reason or "").strip()
        if not reason_clean:
            raise VisitError("Cancellation reason cannot be empty.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, canceller_user_id)
                    actor_perms = await self.rbac.get_user_permissions(conn, canceller_user_id)
                except RbacAccessDeniedError as exc:
                    raise VisitAuthorizationError(str(exc)) from exc

                if "SUPER_ADMIN" not in actor_roles and "visits:cancel" not in actor_perms:
                    raise VisitAuthorizationError(
                        "Permission denied: 'visits:cancel' permission required to cancel visits."
                    )

                refund_policy = await require_approved_policy(
                    conn, "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY"
                )
                if refund_policy.get("refund_requires_reason", True) and len(reason_clean) < 3:
                    raise VisitError("Detailed cancellation reason is required by OPEN-07.")

                visit = await conn.fetchrow(
                    "SELECT * FROM visits WHERE id = $1 FOR UPDATE",
                    visit_id,
                )
                if not visit:
                    raise VisitNotFoundError(f"Visit {visit_id} not found.")

                if visit["status"] != "COMPLETED":
                    raise VisitCancellationError("Visit is already cancelled.")

                # Lock membership BEFORE transitioning so quota reversal is serialized
                mem = await conn.fetchrow(
                    "SELECT id, max_visits, status, end_date FROM memberships WHERE id = $1 FOR UPDATE",
                    visit["membership_id"],
                )

                cancelled_row = await conn.fetchrow(
                    """
                    UPDATE visits
                    SET status = 'CANCELLED',
                        cancellation_reason = $1,
                        cancelled_by = $2,
                        cancelled_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $3 AND status = 'COMPLETED'
                    RETURNING *
                    """,
                    reason_clean,
                    canceller_user_id,
                    visit_id,
                )
                if not cancelled_row:
                    raise VisitCancellationError("Visit was already cancelled concurrently.")

                quota_restored = False
                if mem and refund_policy.get("restore_quota", True):
                    await conn.execute(
                        """
                        UPDATE memberships
                        SET used_visits = GREATEST(0, used_visits - 1),
                            remaining_visits = CASE
                                WHEN max_visits IS NOT NULL
                                    THEN LEAST(max_visits, COALESCE(remaining_visits, 0) + 1)
                                ELSE NULL
                            END,
                            status = CASE
                                WHEN status = 'EXHAUSTED' AND end_date > NOW() THEN 'ACTIVE'
                                ELSE status
                            END,
                            updated_at = NOW()
                        WHERE id = $1
                        """,
                        visit["membership_id"],
                    )
                    quota_restored = True

                actor_role = _resolve_actor_role_label(actor_roles)
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        old_values, new_values
                    ) VALUES (
                        $1, $2, 'VISIT_CANCELLED', 'visits', $3::varchar,
                        jsonb_build_object('status', 'COMPLETED'),
                        $4::jsonb
                    )
                    """,
                    canceller_user_id,
                    actor_role,
                    str(visit_id),
                    json.dumps(
                        {
                            "status": "CANCELLED",
                            "reason": reason_clean,
                            "quota_restored": quota_restored,
                        },
                        ensure_ascii=False,
                    ),
                )

                return dict(cancelled_row)

    async def get_visit_by_id(
        self,
        visit_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        """
        Retrieves single visit with strict authorization & privacy filtering (`F-10`, `T18-AC1/AC3`):
        - Owning APPROVED doctor or ADMIN/SUPER_ADMIN: authorized (admins see unmasked national code;
          doctors receive masked national code).
        - Patient/Buyer (`orders_payments.buyer_user_id` or `profiles.national_code`): sees own visit
          with `private_notes = None` and masked `patient_national_code`.
        - SUPPORT: sees masked `patient_national_code` and `private_notes = None`.
        - Unrelated users/doctors or unapproved/suspended doctors: rejected (`403`).
        """
        if actor_user_id is None:
            raise VisitAuthorizationError("Authenticated actor_user_id is required.")

        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise VisitAuthorizationError(str(exc)) from exc

            row = await conn.fetchrow(
                """
                SELECT v.*, d.user_id AS doctor_user_id, d.verification_status AS doctor_verification_status,
                       d.clinic_name, d.specialty,
                       ph.first_name AS patient_first_name, ph.last_name AS patient_last_name,
                       ph.national_code AS patient_national_code,
                       op.buyer_user_id AS order_buyer_user_id,
                       actor_prof.national_code AS actor_profile_national_code
                FROM visits v
                JOIN doctors d ON v.doctor_id = d.id
                JOIN plan_holders ph ON v.holder_id = ph.id
                JOIN memberships m ON v.membership_id = m.id
                LEFT JOIN orders_payments op ON m.order_id = op.id
                LEFT JOIN profiles actor_prof ON actor_prof.user_id = $2
                WHERE v.id = $1
                """,
                visit_id,
                actor_user_id,
            )
            if not row:
                raise VisitNotFoundError(f"Visit {visit_id} not found.")

            is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
            is_support = "SUPPORT" in actor_roles
            is_owning_approved_doctor = (
                "DOCTOR" in actor_roles
                and row["doctor_user_id"] == actor_user_id
                and row["doctor_verification_status"] == "APPROVED"
            )
            is_patient_or_buyer = (
                row["order_buyer_user_id"] == actor_user_id
                or (
                    row["actor_profile_national_code"] is not None
                    and row["actor_profile_national_code"] == row["patient_national_code"]
                )
            )

            if not (is_admin or is_support or is_owning_approved_doctor or is_patient_or_buyer):
                raise VisitAuthorizationError(
                    "Access denied: You are not authorized to view this visit."
                )

            data = dict(row)
            data.pop("doctor_user_id", None)
            data.pop("doctor_verification_status", None)
            data.pop("order_buyer_user_id", None)
            data.pop("actor_profile_national_code", None)

            if not is_admin:
                data["patient_national_code"] = mask_national_code(data.get("patient_national_code"))

            if not (is_admin or is_owning_approved_doctor):
                data["private_notes"] = None

            return data

    async def list_doctor_visits(
        self,
        doctor_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Lists visits handled by `doctor_id` ONLY for the owning APPROVED doctor,
        `ADMIN`/`SUPER_ADMIN`, or `SUPPORT` (`F-10`, `T18-AC1..AC3`).
        """
        if actor_user_id is None:
            raise VisitAuthorizationError("Authenticated actor_user_id is required.")

        limit_clamped = max(1, min(int(limit), 100))
        offset_clamped = max(0, int(offset))

        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise VisitAuthorizationError(str(exc)) from exc

            is_admin = bool(actor_roles & {"ADMIN", "SUPER_ADMIN"})
            is_support = "SUPPORT" in actor_roles

            doc = await conn.fetchrow(
                "SELECT id, user_id, verification_status FROM doctors WHERE id = $1",
                doctor_id,
            )
            if not doc:
                if not (is_admin or is_support):
                    raise VisitAuthorizationError(
                        "Access denied: Cannot enumerate doctor visits."
                    )
                raise VisitNotFoundError(f"Doctor {doctor_id} not found.")

            is_owning_approved_doctor = (
                "DOCTOR" in actor_roles
                and doc["user_id"] == actor_user_id
                and doc["verification_status"] == "APPROVED"
            )

            if not (is_admin or is_support or is_owning_approved_doctor):
                raise VisitAuthorizationError(
                    "Access denied: You can only list visits for your own APPROVED doctor profile."
                )

            rows = await conn.fetch(
                """
                SELECT v.*, ph.first_name AS patient_first_name, ph.last_name AS patient_last_name,
                       ph.national_code AS patient_national_code
                FROM visits v
                JOIN plan_holders ph ON v.holder_id = ph.id
                WHERE v.doctor_id = $1
                ORDER BY v.visit_date DESC
                LIMIT $2 OFFSET $3
                """,
                doctor_id,
                limit_clamped,
                offset_clamped,
            )

            results: List[Dict[str, Any]] = []
            for r in rows:
                item = dict(r)
                if not is_admin:
                    item["patient_national_code"] = mask_national_code(
                        item.get("patient_national_code")
                    )
                if not (is_admin or is_owning_approved_doctor):
                    item["private_notes"] = None
                results.append(item)
            return results
