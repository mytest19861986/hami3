"""
Session Management & Competitive Refresh Token Rotation (AC-14, AC-15)
BASELINE: BL-HAMICARD-PRD-V1 | AUTH-011, AUTH-012, AC-14, AC-15

Guarantees:
- PostgreSQL as SSOT for session authority and refresh tokens
- Token Families with Replay Detection: reusing an already-rotated token invalidates the ENTIRE token family
- Grace Period (5 seconds): concurrent network retries receive the successor token instead of causing false-positive family revocation
- Row-level locking (SELECT FOR UPDATE) prevents race conditions during token rotation
- Immediate revocation on account suspension, blockage, or logout
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple
import asyncpg

from src.core.security import hash_token, generate_secure_token

class SessionError(Exception):
    pass

class SessionNotFoundError(SessionError):
    pass

class SessionExpiredError(SessionError):
    pass

class AccountBlockedError(SessionError):
    pass

class SecurityReplayAttackError(SessionError):
    """Raised when an already rotated or revoked token is reused (Replay Detection)."""
    pass

class SessionService:
    def __init__(self, db_pool: asyncpg.Pool):
        self.pool = db_pool

    async def create_session(
        self,
        user_id: uuid.UUID,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        refresh_ttl_days: int = 7
    ) -> Dict[str, Any]:
        """Creates a brand new session and token family."""
        raw_refresh_token = generate_secure_token(32)
        token_digest = hash_token(raw_refresh_token)
        family_id = uuid.uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(days=refresh_ttl_days)

        async with self.pool.acquire() as conn:
            # Check user status
            user_status = await conn.fetchval("SELECT status FROM users WHERE id = $1;", user_id)
            if user_status != "ACTIVE":
                raise AccountBlockedError(f"User account is {user_status}. Session creation refused.")

            token_id = await conn.fetchval("""
                INSERT INTO refresh_tokens (
                    user_id, family_id, token_hash, device_info, ip_address, expires_at, status
                ) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')
                RETURNING id;
            """, user_id, family_id, token_digest, device_info, ip_address, expires_at)

        return {
            "session_id": str(token_id),
            "family_id": str(family_id),
            "refresh_token": raw_refresh_token,
            "expires_at": expires_at.isoformat()
        }

    async def rotate_refresh_token(
        self,
        raw_refresh_token: str,
        ip_address: Optional[str] = None,
        device_info: Optional[str] = None,
        grace_period_seconds: int = 5
    ) -> Dict[str, Any]:
        """
        Rotates a refresh token with atomic concurrency locking and replay attack detection (AC-15).
        Returns new credentials on success.
        Raises SecurityReplayAttackError, SessionExpiredError, or SessionNotFoundError.
        """
        token_digest = hash_token(raw_refresh_token)
        err_to_raise = None
        result_payload = None

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # Acquire row lock on presented token
                token_row = await conn.fetchrow("""
                    SELECT id, user_id, family_id, status, expires_at, rotated_at, successor_id
                    FROM refresh_tokens
                    WHERE token_hash = $1
                    FOR UPDATE;
                """, token_digest)

                if not token_row:
                    err_to_raise = SessionNotFoundError("Refresh token not found.")
                else:
                    user_id = token_row["user_id"]
                    family_id = token_row["family_id"]
                    status = token_row["status"]
                    now = datetime.now(timezone.utc)

                    # Check user account status
                    user_status = await conn.fetchval("SELECT status FROM users WHERE id = $1;", user_id)
                    if user_status != "ACTIVE":
                        # Revoke whole family immediately
                        await conn.execute("UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = $1;", family_id)
                        err_to_raise = AccountBlockedError(f"Account is {user_status}. All sessions revoked.")
                    elif status == "ROTATED":
                        rotated_at = token_row["rotated_at"]
                        # Grace period check for benign concurrent network race
                        if rotated_at and (now - rotated_at).total_seconds() <= grace_period_seconds:
                            successor_id = token_row["successor_id"]
                            if successor_id:
                                successor = await conn.fetchrow(
                                    "SELECT id, status, expires_at FROM refresh_tokens WHERE id = $1;",
                                    successor_id
                                )
                                if successor and successor["status"] == "ACTIVE":
                                    result_payload = {
                                        "status": "GRACE_PERIOD_SUCCESSOR",
                                        "session_id": str(successor["id"]),
                                        "family_id": str(family_id),
                                        "message": "Concurrent request resolved within grace window."
                                    }

                        if result_payload is None:
                            # Outside grace window -> MALICIOUS REPLAY ATTACK!
                            # Invalidate ALL tokens in this family immediately
                            await conn.execute("""
                                UPDATE refresh_tokens 
                                SET status = 'REVOKED' 
                                WHERE family_id = $1 AND status != 'REVOKED';
                            """, family_id)

                            # Record security audit log
                            await conn.execute("""
                                INSERT INTO audit_logs (
                                    actor_user_id, actor_role, action, entity_name, entity_id,
                                    old_values, new_values, ip_address
                                ) VALUES (
                                    $1, 'SECURITY_SYSTEM', 'TOKEN_REPLAY_ATTACK_DETECTED', 'refresh_tokens', $2::varchar,
                                    jsonb_build_object('family_id', $2::varchar, 'status', 'ROTATED'),
                                    jsonb_build_object('status', 'REVOKED', 'reason', 'REPLAY_VIOLATION'),
                                    $3
                                );
                            """, user_id, str(family_id), ip_address)

                            err_to_raise = SecurityReplayAttackError(
                                f"CRITICAL: Replay of already rotated token detected! Entire token family {family_id} revoked."
                            )

                    elif status == "REVOKED":
                        # Also invalidate all active tokens in family
                        await conn.execute("UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = $1;", family_id)
                        err_to_raise = SecurityReplayAttackError("Attempted use of explicitly revoked token. Family terminated.")

                    elif token_row["expires_at"] < now:
                        await conn.execute("UPDATE refresh_tokens SET status = 'REVOKED' WHERE id = $1;", token_row["id"])
                        err_to_raise = SessionExpiredError("Refresh token has expired. Re-authentication required.")

                    else:
                        # Valid ACTIVE token -> Perform Atomic Rotation
                        new_raw_token = generate_secure_token(32)
                        new_digest = hash_token(new_raw_token)
                        new_expires_at = now + timedelta(days=7)

                        # 1. Insert new successor token
                        new_token_id = await conn.fetchval("""
                            INSERT INTO refresh_tokens (
                                user_id, family_id, token_hash, device_info, ip_address, expires_at, status
                            ) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')
                            RETURNING id;
                        """, user_id, family_id, new_digest, device_info, ip_address, new_expires_at)

                        # 2. Mark current token as ROTATED and link successor
                        await conn.execute("""
                            UPDATE refresh_tokens
                            SET status = 'ROTATED',
                                rotated_at = $1,
                                successor_id = $2
                            WHERE id = $3;
                        """, now, new_token_id, token_row["id"])

                        result_payload = {
                            "status": "ROTATED",
                            "session_id": str(new_token_id),
                            "family_id": str(family_id),
                            "refresh_token": new_raw_token,
                            "expires_at": new_expires_at.isoformat()
                        }

        if err_to_raise:
            raise err_to_raise

        return result_payload

    async def revoke_session(self, raw_refresh_token: str) -> bool:
        """Revokes a single refresh token (e.g. on client logout)."""
        token_digest = hash_token(raw_refresh_token)
        async with self.pool.acquire() as conn:
            res = await conn.execute("""
                UPDATE refresh_tokens
                SET status = 'REVOKED'
                WHERE token_hash = $1;
            """, token_digest)
            return "UPDATE 1" in res

    async def revoke_all_user_sessions(self, user_id: uuid.UUID) -> int:
        """Revokes all sessions across all families for a given user (e.g. password reset / account lock)."""
        async with self.pool.acquire() as conn:
            res = await conn.execute("""
                UPDATE refresh_tokens
                SET status = 'REVOKED'
                WHERE user_id = $1 AND status != 'REVOKED';
            """, user_id)
            # e.g. "UPDATE 3" -> 3
            try:
                return int(res.split()[1])
            except Exception:
                return 0
