"""
Core Authentication & Profile Lifecycle Service
BASELINE: BL-HAMICARD-PRD-V1 | AUTH-001..017, RBAC-001..009, DOC-001..014, AGENT-001..010
REMEDIATION: HC-T13 (F-02, F-03, F-04, T13-AC1..AC3, T13-AC6)

Features:
- Atomic registration & login via OTP
- Argon2id password management and authentication with lockout enforcement & non-enumerating errors
- Constant-time dummy verification against user-enumeration side-channels
- Authoritative `user_roles` check via RbacEngine (never trusts legacy `users.roles` for authorization)
- Doctor & Agent profile registration with PENDING verification status (Fail-Closed)
"""

import uuid
from typing import Any, Dict

import asyncpg
import redis

from src.adapters.sms import BaseSmsAdapter
from src.auth.otp_service import OtpService, normalize_iranian_mobile
from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.auth.session_service import AccountBlockedError, SessionService
from src.core.security import hash_password, verify_password

# Precomputed dummy Argon2id digest so nonexistent users / passwordless accounts
# consume the same verification CPU path without enabling timing enumeration (F-03, T13-AC2).
_DUMMY_PASSWORD_HASH = hash_password("HamiCard!TimingDefense#2026")
PASSWORD_MAX_FAILED_ATTEMPTS = 5
PASSWORD_LOCKOUT_SECONDS = 900  # 15 minutes (AUTH-007)
GENERIC_AUTH_ERROR_MSG = "Invalid credentials or authentication unavailable."


class AuthError(Exception):
    pass


class InvalidCredentialsError(AuthError):
    pass


class UserAlreadyExistsError(AuthError):
    pass


class AuthService:
    def __init__(
        self,
        db_pool: asyncpg.Pool,
        redis_client: redis.Redis,
        sms_adapter: BaseSmsAdapter | None = None,
    ):
        self.pool = db_pool
        self.redis = redis_client
        self.otp_service = OtpService(redis_client, sms_adapter=sms_adapter)
        self.session_service = SessionService(db_pool)
        self.rbac = RbacEngine(db_pool)

    async def authenticate_via_otp(
        self,
        raw_mobile: str,
        otp_code: str,
        ip_address: str | None = None,
        device_info: str | None = None,
    ) -> Dict[str, Any]:
        """
        Atomically consumes OTP, registers new USER or logs in existing user, and creates session.
        Guarantees: single-use OTP consumption, exactly 1 account per mobile,
        authoritative `user_roles` grant, and 0-balance wallet initialization.
        """
        mobile = normalize_iranian_mobile(raw_mobile)

        # 1. Atomically verify and consume OTP code (Lua script in Redis)
        self.otp_service.verify_otp(mobile, otp_code)

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                user_row = await conn.fetchrow(
                    """
                    SELECT id, status, is_mobile_verified
                    FROM users
                    WHERE mobile = $1
                    FOR UPDATE;
                    """,
                    mobile,
                )

                if user_row:
                    user_id = user_row["id"]
                    if user_row["status"] != "ACTIVE":
                        await conn.execute(
                            """
                            INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                            VALUES ($1, $2, 'OTP', FALSE);
                            """,
                            mobile,
                            ip_address or "127.0.0.1",
                        )
                        raise AccountBlockedError("Authentication unavailable for this account.")
                    is_new = False
                else:
                    user_id = await conn.fetchval(
                        """
                        INSERT INTO users (mobile, status, is_mobile_verified)
                        VALUES ($1, 'ACTIVE', TRUE)
                        RETURNING id;
                        """,
                        mobile,
                    )

                    await conn.execute(
                        """
                        INSERT INTO user_roles (user_id, role_id)
                        VALUES ($1, 'USER')
                        ON CONFLICT DO NOTHING;
                        """,
                        user_id,
                    )

                    await conn.execute(
                        """
                        INSERT INTO wallets (user_id, withdrawable_balance_toman, locked_balance_toman, status)
                        VALUES ($1, 0, 0, 'ACTIVE')
                        ON CONFLICT (user_id) DO NOTHING;
                        """,
                        user_id,
                    )
                    is_new = True

                await conn.execute(
                    """
                    INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                    VALUES ($1, $2, 'OTP', TRUE);
                    """,
                    mobile,
                    ip_address or "127.0.0.1",
                )

        session = await self.session_service.create_session(
            user_id=user_id,
            device_info=device_info,
            ip_address=ip_address,
        )

        return {
            "user_id": str(user_id),
            "mobile": mobile,
            "is_new_user": is_new,
            "session": session,
        }

    async def set_password(self, user_id: uuid.UUID, plain_password: str) -> bool:
        """Hashes password with Argon2id and updates user account."""
        hashed = hash_password(plain_password)
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE users
                SET password_hash = $1, updated_at = NOW()
                WHERE id = $2;
                """,
                hashed,
                user_id,
            )
            return True

    async def authenticate_via_password(
        self,
        raw_mobile: str,
        plain_password: str,
        ip_address: str | None = None,
        device_info: str | None = None,
    ) -> Dict[str, Any]:
        """
        Authenticates user via mobile and Argon2id password hash.
        F-03 / T13-AC2 Remediations:
        - Uniform failure lockout (max 5 failed attempts -> 15 min lockout per mobile).
        - Account-state restrictions (SUSPENDED/BLOCKED/DELETED/locked/passwordless all denied).
        - Non-enumerating error responses across ALL failure causes.
        - Constant-time dummy Argon2 verify when user/password doesn't exist.
        """
        mobile = normalize_iranian_mobile(raw_mobile)
        fail_key = f"pwd:fail:{mobile}"
        lock_key = f"pwd:lock:{mobile}"

        async with self.pool.acquire() as conn:
            # 1. Enforce temporary lockout BEFORE accepting any credentials (even valid ones)
            if self.redis.exists(lock_key):
                verify_password(plain_password, _DUMMY_PASSWORD_HASH)
                await conn.execute(
                    """
                    INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                    VALUES ($1, $2, 'PASSWORD', FALSE);
                    """,
                    mobile,
                    ip_address or "127.0.0.1",
                )
                raise InvalidCredentialsError(GENERIC_AUTH_ERROR_MSG)

            user_row = await conn.fetchrow(
                """
                SELECT id, password_hash, status
                FROM users
                WHERE mobile = $1;
                """,
                mobile,
            )

            if not user_row or not user_row["password_hash"]:
                # Perform dummy hash verification to avoid account enumeration via timing
                verify_password(plain_password, _DUMMY_PASSWORD_HASH)
                fails = self.redis.incr(fail_key)
                if fails == 1:
                    self.redis.expire(fail_key, PASSWORD_LOCKOUT_SECONDS)
                if fails >= PASSWORD_MAX_FAILED_ATTEMPTS:
                    self.redis.set(lock_key, "1", ex=PASSWORD_LOCKOUT_SECONDS)
                await conn.execute(
                    """
                    INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                    VALUES ($1, $2, 'PASSWORD', FALSE);
                    """,
                    mobile,
                    ip_address or "127.0.0.1",
                )
                raise InvalidCredentialsError(GENERIC_AUTH_ERROR_MSG)

            password_valid = verify_password(plain_password, user_row["password_hash"])
            account_active = (user_row["status"] == "ACTIVE")

            if not password_valid or not account_active:
                fails = self.redis.incr(fail_key)
                if fails == 1:
                    self.redis.expire(fail_key, PASSWORD_LOCKOUT_SECONDS)
                if fails >= PASSWORD_MAX_FAILED_ATTEMPTS:
                    self.redis.set(lock_key, "1", ex=PASSWORD_LOCKOUT_SECONDS)
                await conn.execute(
                    """
                    INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                    VALUES ($1, $2, 'PASSWORD', FALSE);
                    """,
                    mobile,
                    ip_address or "127.0.0.1",
                )
                # Generic non-enumerating error: NEVER reveals SUSPENDED vs wrong password vs unknown mobile
                raise InvalidCredentialsError(GENERIC_AUTH_ERROR_MSG)

            # Successful login -> reset failure counter
            self.redis.delete(fail_key)
            await conn.execute(
                """
                INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                VALUES ($1, $2, 'PASSWORD', TRUE);
                """,
                mobile,
                ip_address or "127.0.0.1",
            )
            user_id = user_row["id"]

        session = await self.session_service.create_session(
            user_id=user_id,
            device_info=device_info,
            ip_address=ip_address,
        )

        return {
            "user_id": str(user_id),
            "mobile": mobile,
            "session": session,
        }

    async def register_doctor_profile(
        self,
        user_id: uuid.UUID,
        medical_council_code: str,
        specialty: str,
        clinic_name: str,
        province_id: int,
        city_id: int,
        clinic_address: str,
        clinic_phone: str,
    ) -> uuid.UUID:
        """Registers a doctor profile with verification_status='PENDING' (Fail-Closed default)."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                doc_id = await conn.fetchval(
                    """
                    INSERT INTO doctors (
                        user_id, medical_council_code, specialty, clinic_name,
                        province_id, city_id, clinic_address, clinic_phone,
                        verification_status
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'PENDING')
                    RETURNING id;
                    """,
                    user_id,
                    medical_council_code,
                    specialty,
                    clinic_name,
                    province_id,
                    city_id,
                    clinic_address,
                    clinic_phone,
                )

                # Authoritative role assignment in user_roles only
                await conn.execute(
                    """
                    INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'DOCTOR')
                    ON CONFLICT DO NOTHING;
                    """,
                    user_id,
                )

                return doc_id

    async def approve_doctor_profile(
        self,
        actor_user_id: uuid.UUID,
        doctor_id: uuid.UUID,
    ) -> bool:
        """Approves doctor profile. Checks authoritative `user_roles` via RbacEngine."""
        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise AuthError(str(exc)) from exc

            if not any(r in actor_roles for r in ("ADMIN", "SUPER_ADMIN")):
                raise AuthError(
                    "Unauthorized: Only ADMIN or SUPER_ADMIN can approve doctor profiles."
                )

            actor_role_label = "SUPER_ADMIN" if "SUPER_ADMIN" in actor_roles else "ADMIN"
            res = await conn.execute(
                """
                UPDATE doctors
                SET verification_status = 'APPROVED',
                    verified_by = $1,
                    verified_at = NOW(),
                    is_public_listed = TRUE
                WHERE id = $2;
                """,
                actor_user_id,
                doctor_id,
            )

            await conn.execute(
                """
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, action, entity_name, entity_id, new_values
                ) VALUES (
                    $1, $2, 'DOCTOR_PROFILE_APPROVED', 'doctors', $3,
                    jsonb_build_object('verification_status', 'APPROVED')
                );
                """,
                actor_user_id,
                actor_role_label,
                str(doctor_id),
            )

            return "UPDATE 1" in res

    async def register_agent_profile(
        self,
        user_id: uuid.UUID,
        business_name: str,
        province_id: int,
        city_id: int,
        office_address: str,
        office_phone: str,
    ) -> uuid.UUID:
        """Registers agent profile with verification_status='PENDING' (Fail-Closed default)."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                agent_id = await conn.fetchval(
                    """
                    INSERT INTO agents (
                        user_id, business_name, province_id, city_id,
                        office_address, office_phone, verification_status
                    ) VALUES ($1, $2, $3, $4, $5, $6, 'PENDING')
                    RETURNING id;
                    """,
                    user_id,
                    business_name,
                    province_id,
                    city_id,
                    office_address,
                    office_phone,
                )

                await conn.execute(
                    """
                    INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'AGENT')
                    ON CONFLICT DO NOTHING;
                    """,
                    user_id,
                )

                return agent_id

    async def approve_agent_profile(
        self,
        actor_user_id: uuid.UUID,
        agent_id: uuid.UUID,
    ) -> bool:
        """Approves agent profile. Checks authoritative `user_roles` via RbacEngine."""
        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise AuthError(str(exc)) from exc

            if not any(r in actor_roles for r in ("ADMIN", "SUPER_ADMIN")):
                raise AuthError(
                    "Unauthorized: Only ADMIN or SUPER_ADMIN can approve agent profiles."
                )

            actor_role_label = "SUPER_ADMIN" if "SUPER_ADMIN" in actor_roles else "ADMIN"
            res = await conn.execute(
                """
                UPDATE agents
                SET verification_status = 'APPROVED',
                    verified_by = $1,
                    verified_at = NOW()
                WHERE id = $2;
                """,
                actor_user_id,
                agent_id,
            )

            await conn.execute(
                """
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, action, entity_name, entity_id, new_values
                ) VALUES (
                    $1, $2, 'AGENT_PROFILE_APPROVED', 'agents', $3,
                    jsonb_build_object('verification_status', 'APPROVED')
                );
                """,
                actor_user_id,
                actor_role_label,
                str(agent_id),
            )

            return "UPDATE 1" in res
