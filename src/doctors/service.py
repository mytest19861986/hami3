"""
Doctor Domain Service (DOC-001..014, AC-02)
REMEDIATION: HC-T25 (DOC-012 P0 admin-exclusive custom discount control)

Handles doctor profile registration, admin approval lifecycle,
fail-closed operational status, public directory search, contracts,
and strictly admin-controlled custom discount percent overrides.
"""

import json
import uuid
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List

import asyncpg

from src.auth.rbac import RbacAccessDeniedError, RbacEngine


class DoctorError(Exception):
    """Base exception for doctor domain errors."""
    pass


class DoctorAuthorizationError(DoctorError):
    """Raised when actor lacks ADMIN / SUPER_ADMIN authorization for doctor mutations."""
    pass


class DoctorNotFoundError(DoctorError):
    """Raised when doctor profile does not exist."""
    pass


class DuplicateMedicalCouncilCodeError(DoctorError):
    """Raised when medical council code is already registered."""
    pass


class DoctorVerificationError(DoctorError):
    """Raised on invalid verification transitions."""
    pass


class DoctorService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.rbac = RbacEngine(pool)

    async def register_doctor(
        self,
        user_id: uuid.UUID,
        medical_council_code: str,
        specialty: str,
        clinic_name: str,
        province_id: int,
        city_id: int,
        clinic_address: str,
        clinic_phone: str,
        custom_discount_percent: float | None = None
    ) -> Dict[str, Any]:
        """Registers a new doctor profile in PENDING status."""
        code_clean = medical_council_code.strip()
        if not code_clean:
            raise DoctorError("Medical council code cannot be empty.")

        async with self.pool.acquire() as conn:
            # Check if user already has a doctor profile
            existing_user = await conn.fetchrow(
                "SELECT id FROM doctors WHERE user_id = $1", user_id
            )
            if existing_user:
                raise DoctorError("User already has a registered doctor profile.")

            # Check medical council code uniqueness
            existing_code = await conn.fetchrow(
                "SELECT id FROM doctors WHERE medical_council_code = $1", code_clean
            )
            if existing_code:
                raise DuplicateMedicalCouncilCodeError(f"Medical council code {code_clean} is already in use.")

            # Verify province/city hierarchy
            city_row = await conn.fetchrow(
                "SELECT province_id FROM cities WHERE id = $1", city_id
            )
            if not city_row or city_row["province_id"] != province_id:
                raise DoctorError(f"City {city_id} does not belong to province {province_id}.")

            # DOC-012 P0: Self-registration never grants an unapproved custom discount rate;
            # custom_discount_percent may only be assigned by authorized administrators.
            row = await conn.fetchrow(
                """
                INSERT INTO doctors (
                    user_id, medical_council_code, specialty, clinic_name,
                    province_id, city_id, clinic_address, clinic_phone,
                    custom_discount_percent, verification_status, is_public_listed
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 'PENDING', FALSE)
                RETURNING id, user_id, medical_council_code, specialty, clinic_name,
                          province_id, city_id, clinic_address, clinic_phone,
                          custom_discount_percent, verification_status, is_public_listed,
                          created_at, updated_at
                """,
                user_id, code_clean, specialty.strip(), clinic_name.strip(),
                province_id, city_id, clinic_address.strip(), clinic_phone.strip(),
            )
            return dict(row)

    async def get_doctor_by_id(self, doctor_id: uuid.UUID) -> Dict[str, Any]:
        """Retrieves a doctor profile by its primary key ID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT d.*, p.name as province_name, c.name as city_name
                FROM doctors d
                LEFT JOIN provinces p ON d.province_id = p.id
                LEFT JOIN cities c ON d.city_id = c.id
                WHERE d.id = $1
                """, doctor_id
            )
            if not row:
                raise DoctorNotFoundError(f"Doctor {doctor_id} not found.")
            return dict(row)

    async def get_doctor_by_user_id(self, user_id: uuid.UUID) -> Dict[str, Any] | None:
        """Retrieves a doctor profile by associated user ID."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT d.*, p.name as province_name, c.name as city_name
                FROM doctors d
                LEFT JOIN provinces p ON d.province_id = p.id
                LEFT JOIN cities c ON d.city_id = c.id
                WHERE d.user_id = $1
                """, user_id
            )
            return dict(row) if row else None

    async def approve_doctor(
        self,
        doctor_id: uuid.UUID,
        admin_user_id: uuid.UUID
    ) -> Dict[str, Any]:
        """Approves doctor profile, lists them publicly, and logs audit."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE doctors
                    SET verification_status = 'APPROVED',
                        verified_by = $1,
                        verified_at = NOW(),
                        is_public_listed = TRUE,
                        rejection_reason = NULL,
                        updated_at = NOW()
                    WHERE id = $2
                    RETURNING id, user_id, verification_status, is_public_listed, verified_at
                    """, admin_user_id, doctor_id
                )
                if not row:
                    raise DoctorNotFoundError(f"Doctor {doctor_id} not found.")

                # Record security audit
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        new_values
                    ) VALUES (
                        $1, 'ADMIN', 'DOCTOR_APPROVED', 'doctors', $2,
                        jsonb_build_object('status', 'APPROVED', 'is_public_listed', true)
                    )
                    """, admin_user_id, str(doctor_id)
                )

                return dict(row)

    async def reject_doctor(
        self,
        doctor_id: uuid.UUID,
        admin_user_id: uuid.UUID,
        reason: str
    ) -> Dict[str, Any]:
        """Rejects doctor profile with mandatory rejection reason."""
        reason_clean = reason.strip()
        if not reason_clean:
            raise DoctorError("Rejection reason cannot be empty.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE doctors
                    SET verification_status = 'REJECTED',
                        verified_by = $1,
                        verified_at = NOW(),
                        is_public_listed = FALSE,
                        rejection_reason = $3,
                        updated_at = NOW()
                    WHERE id = $2
                    RETURNING id, user_id, verification_status, is_public_listed, rejection_reason
                    """, admin_user_id, doctor_id, reason_clean
                )
                if not row:
                    raise DoctorNotFoundError(f"Doctor {doctor_id} not found.")

                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        new_values
                    ) VALUES (
                        $1, 'ADMIN', 'DOCTOR_REJECTED', 'doctors', $2,
                        jsonb_build_object('status', 'REJECTED', 'reason', $3::text)
                    )
                    """, admin_user_id, str(doctor_id), reason_clean
                )

                return dict(row)

    async def suspend_doctor(
        self,
        doctor_id: uuid.UUID,
        admin_user_id: uuid.UUID,
        reason: str | None = None
    ) -> Dict[str, Any]:
        """Suspends doctor profile and immediately delists from public directory."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE doctors
                    SET verification_status = 'SUSPENDED',
                        is_public_listed = FALSE,
                        rejection_reason = $1,
                        updated_at = NOW()
                    WHERE id = $2
                    RETURNING id, user_id, verification_status, is_public_listed
                    """, reason, doctor_id
                )
                if not row:
                    raise DoctorNotFoundError(f"Doctor {doctor_id} not found.")

                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        new_values
                    ) VALUES (
                        $1, 'ADMIN', 'DOCTOR_SUSPENDED', 'doctors', $2,
                        jsonb_build_object('status', 'SUSPENDED', 'reason', $3::text)
                    )
                    """, admin_user_id, str(doctor_id), reason
                )

                return dict(row)

    async def search_public_directory(
        self,
        province_id: int | None = None,
        city_id: int | None = None,
        specialty: str | None = None,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Public directory search: Strictly filtered by verification_status = 'APPROVED'
        and is_public_listed = TRUE. Supports pagination.
        """
        clauses = ["d.verification_status = 'APPROVED'", "d.is_public_listed = TRUE"]
        params: List[Any] = []
        param_idx = 1

        if province_id:
            clauses.append(f"d.province_id = ${param_idx}")
            params.append(province_id)
            param_idx += 1

        if city_id:
            clauses.append(f"d.city_id = ${param_idx}")
            params.append(city_id)
            param_idx += 1

        if specialty:
            clauses.append(f"d.specialty ILIKE ${param_idx}")
            params.append(f"%{specialty.strip()}%")
            param_idx += 1

        if query:
            clauses.append(f"(d.clinic_name ILIKE ${param_idx} OR d.specialty ILIKE ${param_idx} OR pr.first_name ILIKE ${param_idx} OR pr.last_name ILIKE ${param_idx})")
            params.append(f"%{query.strip()}%")
            param_idx += 1

        where_str = " AND ".join(clauses)

        async with self.pool.acquire() as conn:
            # Count total
            count_sql = f"""
                SELECT COUNT(*)
                FROM doctors d
                LEFT JOIN profiles pr ON d.user_id = pr.user_id
                WHERE {where_str}
            """
            total = await conn.fetchval(count_sql, *params)

            # Query items
            query_sql = f"""
                SELECT d.id, d.medical_council_code, d.specialty, d.clinic_name,
                       d.clinic_address, d.clinic_phone, d.custom_discount_percent,
                       p.name as province_name, c.name as city_name,
                       pr.first_name as doctor_first_name, pr.last_name as doctor_last_name
                FROM doctors d
                LEFT JOIN provinces p ON d.province_id = p.id
                LEFT JOIN cities c ON d.city_id = c.id
                LEFT JOIN profiles pr ON d.user_id = pr.user_id
                WHERE {where_str}
                ORDER BY d.created_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """
            items = await conn.fetch(query_sql, *params, limit, offset)

            return {
                "total": total,
                "limit": limit,
                "offset": offset,
                "items": [dict(r) for r in items]
            }

    async def set_custom_discount_percent(
        self,
        doctor_id: uuid.UUID,
        custom_discount_percent: Decimal | float | int | str | None,
        actor_user_id: uuid.UUID | None,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Sets or clears a doctor's `custom_discount_percent` strictly for ADMIN / SUPER_ADMIN (`DOC-012 P0`).
        Enforces exact Decimal range [0, 100] and records old/new audit trail.
        """
        if actor_user_id is None:
            raise DoctorAuthorizationError("Authenticated actor_user_id is required.")

        reason_clean = (reason or "").strip()
        if len(reason_clean) < 3:
            raise DoctorError("Reason for updating custom discount percent must be at least 3 characters.")

        parsed_rate: Decimal | None
        if custom_discount_percent is None:
            parsed_rate = None
        else:
            if isinstance(custom_discount_percent, bool):
                raise DoctorError("Invalid custom_discount_percent type.")
            try:
                parsed_rate = Decimal(str(custom_discount_percent))
            except (InvalidOperation, ValueError) as exc:
                raise DoctorError("custom_discount_percent must be a valid decimal number.") from exc
            if not parsed_rate.is_finite():
                raise DoctorError("custom_discount_percent must be finite.")
            if parsed_rate < Decimal("0") or parsed_rate > Decimal("100"):
                raise DoctorError("custom_discount_percent must be within 0 to 100.")
            parsed_rate = parsed_rate.quantize(Decimal("0.01"))

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
                except RbacAccessDeniedError as exc:
                    raise DoctorAuthorizationError(str(exc)) from exc

                if not (actor_roles & {"ADMIN", "SUPER_ADMIN"}):
                    raise DoctorAuthorizationError(
                        "Only ADMIN or SUPER_ADMIN may modify doctor custom discount rates (DOC-012)."
                    )

                existing = await conn.fetchrow(
                    "SELECT id, custom_discount_percent FROM doctors WHERE id = $1 FOR UPDATE",
                    doctor_id,
                )
                if not existing:
                    raise DoctorNotFoundError(f"Doctor {doctor_id} not found.")

                old_val = existing["custom_discount_percent"]
                updated = await conn.fetchrow(
                    """
                    UPDATE doctors
                    SET custom_discount_percent = $1,
                        updated_at = NOW()
                    WHERE id = $2
                    RETURNING id, user_id, medical_council_code, specialty, clinic_name,
                              custom_discount_percent, verification_status, is_public_listed,
                              updated_at
                    """,
                    parsed_rate,
                    doctor_id,
                )

                actor_role = "SUPER_ADMIN" if "SUPER_ADMIN" in actor_roles else "ADMIN"
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        old_values, new_values
                    ) VALUES (
                        $1, $2, 'DOCTOR_CUSTOM_DISCOUNT_UPDATED', 'doctors', $3::varchar,
                        $4::jsonb, $5::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role,
                    str(doctor_id),
                    json.dumps(
                        {
                            "custom_discount_percent": str(old_val)
                            if old_val is not None
                            else None
                        }
                    ),
                    json.dumps(
                        {
                            "custom_discount_percent": str(parsed_rate)
                            if parsed_rate is not None
                            else None,
                            "reason": reason_clean,
                        },
                        ensure_ascii=False,
                    ),
                )

                return dict(updated)

    async def create_service_contract(
        self,
        doctor_id: uuid.UUID,
        contract_number: str,
        start_date: date,
        end_date: date,
        agreed_discount_percent: float,
        approved_by: uuid.UUID
    ) -> Dict[str, Any]:
        """Creates a service contract between the system and an approved doctor."""
        if end_date <= start_date:
            raise DoctorError("Contract end_date must be after start_date.")
        if agreed_discount_percent < 0 or agreed_discount_percent > 100:
            raise DoctorError("Discount percent must be between 0 and 100.")

        async with self.pool.acquire() as conn:
            # Doctor must be approved
            doc = await conn.fetchrow(
                "SELECT verification_status FROM doctors WHERE id = $1", doctor_id
            )
            if not doc:
                raise DoctorNotFoundError(f"Doctor {doctor_id} not found.")
            if doc["verification_status"] != "APPROVED":
                raise DoctorVerificationError("Contracts can only be created for APPROVED doctors.")

            row = await conn.fetchrow(
                """
                INSERT INTO service_contracts (
                    doctor_id, contract_number, start_date, end_date,
                    agreed_discount_percent, status, approved_by
                ) VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6)
                RETURNING id, doctor_id, contract_number, start_date, end_date,
                          agreed_discount_percent, status, approved_by, created_at
                """,
                doctor_id, contract_number.strip(), start_date, end_date,
                agreed_discount_percent, approved_by
            )
            return dict(row)

    async def get_active_contract(self, doctor_id: uuid.UUID) -> Dict[str, Any] | None:
        """Returns currently active contract for a doctor if one exists."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM service_contracts
                WHERE doctor_id = $1 AND status = 'ACTIVE'
                  AND start_date <= CURRENT_DATE AND end_date >= CURRENT_DATE
                ORDER BY created_at DESC
                LIMIT 1
                """, doctor_id
            )
            return dict(row) if row else None
