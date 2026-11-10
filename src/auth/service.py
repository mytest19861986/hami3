"""
Core Authentication & Profile Lifecycle Service
BASELINE: BL-HAMICARD-PRD-V1 | AUTH-001..017, DOC-001..014, AGENT-001..010

Features:
- Atomic registration & login via OTP
- Argon2id password management and authentication
- Account status lifecycle (ACTIVE, SUSPENDED, BLOCKED, DELETED)
- Doctor & Agent profile registration with PENDING verification status
- Admin approval workflows with irreversible audit logging
"""

import uuid
from typing import Dict, Any, Optional
import asyncpg
import redis

from src.core.security import hash_password, verify_password
from src.auth.otp_service import OtpService, normalize_iranian_mobile
from src.auth.session_service import SessionService, AccountBlockedError

class AuthError(Exception):
    pass

class InvalidCredentialsError(AuthError):
    pass

class UserAlreadyExistsError(AuthError):
    pass

class AuthService:
    def __init__(self, db_pool: asyncpg.Pool, redis_client: redis.Redis):
        self.pool = db_pool
        self.redis = redis_client
        self.otp_service = OtpService(redis_client)
        self.session_service = SessionService(db_pool)

    async def authenticate_via_otp(
        self,
        raw_mobile: str,
        otp_code: str,
        ip_address: Optional[str] = None,
        device_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validates OTP, registers new USER or logs in existing user, and creates session.
        Guarantees: exactly 1 account per mobile, automatically creates wallet.
        """
        mobile = normalize_iranian_mobile(raw_mobile)

        # 1. Verify OTP code
        self.otp_service.verify_otp(mobile, otp_code)

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # Check if user exists
                user_row = await conn.fetchrow("""
                    SELECT id, status, roles, is_mobile_verified 
                    FROM users 
                    WHERE mobile = $1
                    FOR UPDATE;
                """, mobile)

                if user_row:
                    user_id = user_row["id"]
                    status = user_row["status"]
                    if status != "ACTIVE":
                        raise AccountBlockedError(f"Account is {status}. Access forbidden.")
                    is_new = False
                else:
                    # Atomic creation of new user with USER role
                    user_id = await conn.fetchval("""
                        INSERT INTO users (mobile, status, roles, is_mobile_verified)
                        VALUES ($1, 'ACTIVE', '{"USER"}', TRUE)
                        RETURNING id;
                    """, mobile)

                    # Assign USER role in user_roles mapping
                    await conn.execute("""
                        INSERT INTO user_roles (user_id, role_id)
                        VALUES ($1, 'USER')
                        ON CONFLICT DO NOTHING;
                    """, user_id)

                    # Initialize wallet with 0 balance
                    await conn.execute("""
                        INSERT INTO wallets (user_id, withdrawable_balance_toman, locked_balance_toman, status)
                        VALUES ($1, 0, 0, 'ACTIVE')
                        ON CONFLICT (user_id) DO NOTHING;
                    """, user_id)
                    is_new = True

                # Record successful login attempt
                await conn.execute("""
                    INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                    VALUES ($1, $2, 'OTP', TRUE);
                """, mobile, ip_address or "127.0.0.1")

        # Create session
        session = await self.session_service.create_session(
            user_id=user_id,
            device_info=device_info,
            ip_address=ip_address
        )

        return {
            "user_id": str(user_id),
            "mobile": mobile,
            "is_new_user": is_new,
            "session": session
        }

    async def set_password(self, user_id: uuid.UUID, plain_password: str) -> bool:
        """Hashes password with Argon2id and updates user account."""
        hashed = hash_password(plain_password)
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE users 
                SET password_hash = $1, updated_at = NOW() 
                WHERE id = $2;
            """, hashed, user_id)
            return True

    async def authenticate_via_password(
        self,
        raw_mobile: str,
        plain_password: str,
        ip_address: Optional[str] = None,
        device_info: Optional[str] = None
    ) -> Dict[str, Any]:
        """Authenticates user via mobile and Argon2id password hash."""
        mobile = normalize_iranian_mobile(raw_mobile)

        async with self.pool.acquire() as conn:
            user_row = await conn.fetchrow("""
                SELECT id, password_hash, status, roles 
                FROM users 
                WHERE mobile = $1;
            """, mobile)

            if not user_row or not user_row["password_hash"]:
                # Record failed login attempt
                await conn.execute("""
                    INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                    VALUES ($1, $2, 'PASSWORD', FALSE);
                """, mobile, ip_address or "127.0.0.1")
                raise InvalidCredentialsError("Invalid mobile or password.")

            if user_row["status"] != "ACTIVE":
                raise AccountBlockedError(f"Account is {user_row['status']}. Access forbidden.")

            # Argon2id verification
            if not verify_password(plain_password, user_row["password_hash"]):
                await conn.execute("""
                    INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                    VALUES ($1, $2, 'PASSWORD', FALSE);
                """, mobile, ip_address or "127.0.0.1")
                raise InvalidCredentialsError("Invalid mobile or password.")

            # Record success
            await conn.execute("""
                INSERT INTO login_attempts (mobile, ip_address, attempt_type, is_successful)
                VALUES ($1, $2, 'PASSWORD', TRUE);
            """, mobile, ip_address or "127.0.0.1")

            user_id = user_row["id"]

        session = await self.session_service.create_session(
            user_id=user_id,
            device_info=device_info,
            ip_address=ip_address
        )

        return {
            "user_id": str(user_id),
            "mobile": mobile,
            "session": session
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
        clinic_phone: str
    ) -> uuid.UUID:
        """Registers a doctor profile with verification_status='PENDING' (Fail-Closed default)."""
        async with self.pool.acquire() as conn:
            doc_id = await conn.fetchval("""
                INSERT INTO doctors (
                    user_id, medical_council_code, specialty, clinic_name,
                    province_id, city_id, clinic_address, clinic_phone,
                    verification_status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'PENDING')
                RETURNING id;
            """, user_id, medical_council_code, specialty, clinic_name,
               province_id, city_id, clinic_address, clinic_phone)

            # Assign DOCTOR role in user_roles and users table
            await conn.execute("""
                INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'DOCTOR')
                ON CONFLICT DO NOTHING;
            """, user_id)
            await conn.execute("""
                UPDATE users SET roles = array_append(roles, 'DOCTOR')
                WHERE id = $1 AND NOT ('DOCTOR' = ANY(roles));
            """, user_id)

            return doc_id

    async def approve_doctor_profile(
        self,
        actor_user_id: uuid.UUID,
        doctor_id: uuid.UUID
    ) -> bool:
        """Approves doctor profile. Requires ADMIN or SUPER_ADMIN."""
        async with self.pool.acquire() as conn:
            actor_roles = await conn.fetchval("SELECT roles FROM users WHERE id = $1;", actor_user_id)
            if not actor_roles or not any(r in actor_roles for r in ["ADMIN", "SUPER_ADMIN"]):
                raise AuthError("Unauthorized: Only ADMIN or SUPER_ADMIN can approve doctor profiles.")

            res = await conn.execute("""
                UPDATE doctors 
                SET verification_status = 'APPROVED',
                    verified_by = $1,
                    verified_at = NOW(),
                    is_public_listed = TRUE
                WHERE id = $2;
            """, actor_user_id, doctor_id)

            # Record audit log
            await conn.execute("""
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, action, entity_name, entity_id, new_values
                ) VALUES (
                    $1, 'ADMIN', 'DOCTOR_PROFILE_APPROVED', 'doctors', $2,
                    jsonb_build_object('verification_status', 'APPROVED')
                );
            """, actor_user_id, str(doctor_id))

            return "UPDATE 1" in res

    async def register_agent_profile(
        self,
        user_id: uuid.UUID,
        business_name: str,
        province_id: int,
        city_id: int,
        office_address: str,
        office_phone: str
    ) -> uuid.UUID:
        """Registers agent profile with verification_status='PENDING' (Fail-Closed default)."""
        async with self.pool.acquire() as conn:
            agent_id = await conn.fetchval("""
                INSERT INTO agents (
                    user_id, business_name, province_id, city_id,
                    office_address, office_phone, verification_status
                ) VALUES ($1, $2, $3, $4, $5, $6, 'PENDING')
                RETURNING id;
            """, user_id, business_name, province_id, city_id, office_address, office_phone)

            # Assign AGENT role
            await conn.execute("""
                INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'AGENT')
                ON CONFLICT DO NOTHING;
            """, user_id)
            await conn.execute("""
                UPDATE users SET roles = array_append(roles, 'AGENT')
                WHERE id = $1 AND NOT ('AGENT' = ANY(roles));
            """, user_id)

            return agent_id

    async def approve_agent_profile(
        self,
        actor_user_id: uuid.UUID,
        agent_id: uuid.UUID
    ) -> bool:
        """Approves agent profile. Requires ADMIN or SUPER_ADMIN."""
        async with self.pool.acquire() as conn:
            actor_roles = await conn.fetchval("SELECT roles FROM users WHERE id = $1;", actor_user_id)
            if not actor_roles or not any(r in actor_roles for r in ["ADMIN", "SUPER_ADMIN"]):
                raise AuthError("Unauthorized: Only ADMIN or SUPER_ADMIN can approve agent profiles.")

            res = await conn.execute("""
                UPDATE agents 
                SET verification_status = 'APPROVED',
                    verified_by = $1,
                    verified_at = NOW()
                WHERE id = $2;
            """, actor_user_id, agent_id)

            # Record audit log
            await conn.execute("""
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, action, entity_name, entity_id, new_values
                ) VALUES (
                    $1, 'ADMIN', 'AGENT_PROFILE_APPROVED', 'agents', $2,
                    jsonb_build_object('verification_status', 'APPROVED')
                );
            """, actor_user_id, str(agent_id))

            return "UPDATE 1" in res

