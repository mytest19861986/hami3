"""
Session Management & Competitive Refresh Token Rotation (AC-14, AC-15)
BASELINE: BL-HAMICARD-PRD-V1 | AUTH-010..013, AC-14, AC-15
REMEDIATION: HC-T13 (F-01, F-05, T13-AC4, T13-AC5)

Guarantees:
- PostgreSQL as SSOT for session authority and refresh tokens
- At most ONE usable successor credential produced across concurrent refresh calls (T13-AC4)
- Competing refresh requests within grace window fail safely (ConcurrentRefreshConflictError / HTTP 409)
  WITHOUT disclosing successor credentials (F-01)
- Replay outside grace window immediately revokes the ENTIRE token family and logs security audit
- Session-family logout (F-05, T13-AC5): revoking any token in a session revokes its ENTIRE `family_id`
- Immediate failure on protected requests after logout, replay, suspension, or family revocation
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Dict

import asyncpg
import redis

from src.auth.access_tokens import mark_family_revoked_in_redis
from src.core.security import generate_secure_token, hash_token


class SessionError(Exception):
    pass


class SessionNotFoundError(SessionError):
    pass


class SessionExpiredError(SessionError):
    pass


class AccountBlockedError(SessionError):
    pass


class ConcurrentRefreshConflictError(SessionError):
    """Raised when a competing concurrent refresh hits an already-rotated token inside the safe retry window."""
    pass


class SecurityReplayAttackError(SessionError):
    """Raised when an already rotated (outside window) or revoked token is reused (Replay Detection)."""
    pass


class SessionService:
    def __init__(self, db_pool: asyncpg.Pool, redis_client: redis.Redis | None = None):
        self.pool = db_pool
        self.redis = redis_client

    async def get_refresh_token_meta(self, raw_refresh_token: str) -> Dict[str, Any] | None:
        """Read-only lookup of refresh token metadata without modifying or rotating state."""
        if not raw_refresh_token:
            return None
        token_digest = hash_token(raw_refresh_token)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, user_id, family_id, status, expires_at
                FROM refresh_tokens
                WHERE token_hash = $1;
                """,
                token_digest,
            )
            return dict(row) if row else None

    async def verify_active_family(self, family_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Confirms at least one non-expired ACTIVE refresh token remains in `family_id` (SSOT)."""
        now = datetime.now(UTC)
        async with self.pool.acquire() as conn:
            return bool(
                await conn.fetchval(
                    """
                    SELECT EXISTS (
                        SELECT 1
                        FROM refresh_tokens
                        WHERE family_id = $1
                          AND user_id = $2
                          AND status = 'ACTIVE'
                          AND expires_at > $3
                    );
                    """,
                    family_id,
                    user_id,
                    now,
                )
            )

    async def create_session(
        self,
        user_id: uuid.UUID,
        device_info: str | None = None,
        ip_address: str | None = None,
        refresh_ttl_days: int = 7,
    ) -> Dict[str, Any]:
        """Creates a brand new session and token family."""
        raw_refresh_token = generate_secure_token(32)
        token_digest = hash_token(raw_refresh_token)
        family_id = uuid.uuid4()
        expires_at = datetime.now(UTC) + timedelta(days=refresh_ttl_days)

        async with self.pool.acquire() as conn:
            user_status = await conn.fetchval("SELECT status FROM users WHERE id = $1;", user_id)
            if user_status != "ACTIVE":
                raise AccountBlockedError(f"User account is {user_status}. Session creation refused.")

            token_id = await conn.fetchval(
                """
                INSERT INTO refresh_tokens (
                    user_id, family_id, token_hash, device_info, ip_address, expires_at, status
                ) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')
                RETURNING id;
                """,
                user_id,
                family_id,
                token_digest,
                device_info,
                ip_address,
                expires_at,
            )

        return {
            "session_id": str(token_id),
            "family_id": str(family_id),
            "refresh_token": raw_refresh_token,
            "expires_at": expires_at.isoformat(),
        }

    async def rotate_refresh_token(
        self,
        raw_refresh_token: str,
        ip_address: str | None = None,
        device_info: str | None = None,
        grace_period_seconds: int = 5,
    ) -> Dict[str, Any]:
        """
        Rotates a refresh token with atomic row locking (`FOR UPDATE`) and replay detection (AC-15).
        F-01 / T13-AC4 Fix:
        - At most ONE caller gets a usable successor credential (`status == 'ROTATED'`, `refresh_token` present).
        - Competing callers within `grace_period_seconds` receive ConcurrentRefreshConflictError
          with ZERO successor credential disclosure (never returns a token on reuse).
        - Reuse outside `grace_period_seconds` triggers SecurityReplayAttackError & revokes whole family.
        """
        token_digest = hash_token(raw_refresh_token)
        err_to_raise = None
        result_payload = None
        revoked_family_reason: tuple[uuid.UUID, str] | None = None

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                token_row = await conn.fetchrow(
                    """
                    SELECT id, user_id, family_id, status, expires_at, rotated_at, successor_id
                    FROM refresh_tokens
                    WHERE token_hash = $1
                    FOR UPDATE;
                    """,
                    token_digest,
                )

                if not token_row:
                    err_to_raise = SessionNotFoundError("Refresh token not found.")
                else:
                    user_id = token_row["user_id"]
                    family_id = token_row["family_id"]
                    tok_status = token_row["status"]
                    now = datetime.now(UTC)

                    user_status = await conn.fetchval("SELECT status FROM users WHERE id = $1;", user_id)
                    if user_status != "ACTIVE":
                        await conn.execute(
                            "UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = $1;",
                            family_id,
                        )
                        revoked_family_reason = (family_id, "ACCOUNT_BLOCKED")
                        err_to_raise = AccountBlockedError(
                            f"Account is {user_status}. All sessions revoked."
                        )
                    elif tok_status == "ROTATED":
                        rotated_at = token_row["rotated_at"]
                        if rotated_at and (now - rotated_at).total_seconds() <= grace_period_seconds:
                            # Safe competing-race refusal WITHOUT disclosing any successor credential (T13-AC4)
                            err_to_raise = ConcurrentRefreshConflictError(
                                "Refresh token already rotated in a concurrent request; no credential re-issued."
                            )
                        else:
                            # Outside safe window -> MALICIOUS REPLAY ATTACK!
                            await conn.execute(
                                """
                                UPDATE refresh_tokens
                                SET status = 'REVOKED'
                                WHERE family_id = $1 AND status != 'REVOKED';
                                """,
                                family_id,
                            )

                            await conn.execute(
                                """
                                INSERT INTO audit_logs (
                                    actor_user_id, actor_role, action, entity_name, entity_id,
                                    old_values, new_values, ip_address
                                ) VALUES (
                                    $1, 'SECURITY_SYSTEM', 'TOKEN_REPLAY_ATTACK_DETECTED', 'refresh_tokens', $2::varchar,
                                    jsonb_build_object('family_id', $2::varchar, 'status', 'ROTATED'),
                                    jsonb_build_object('status', 'REVOKED', 'reason', 'REPLAY_VIOLATION'),
                                    $3
                                );
                                """,
                                user_id,
                                str(family_id),
                                ip_address,
                            )

                            revoked_family_reason = (family_id, "REPLAY_ATTACK")
                            err_to_raise = SecurityReplayAttackError(
                                f"CRITICAL: Replay of already rotated token detected! Entire token family {family_id} revoked."
                            )

                    elif tok_status == "REVOKED":
                        await conn.execute(
                            "UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = $1;",
                            family_id,
                        )
                        revoked_family_reason = (family_id, "REVOKED_REUSE")
                        err_to_raise = SecurityReplayAttackError(
                            "Attempted use of explicitly revoked token. Family terminated."
                        )

                    elif token_row["expires_at"] < now:
                        await conn.execute(
                            "UPDATE refresh_tokens SET status = 'REVOKED' WHERE id = $1;",
                            token_row["id"],
                        )
                        err_to_raise = SessionExpiredError(
                            "Refresh token has expired. Re-authentication required."
                        )

                    else:
                        # Valid ACTIVE token -> Perform Atomic Single-Use Rotation
                        new_raw_token = generate_secure_token(32)
                        new_digest = hash_token(new_raw_token)
                        new_expires_at = now + timedelta(days=7)

                        new_token_id = await conn.fetchval(
                            """
                            INSERT INTO refresh_tokens (
                                user_id, family_id, token_hash, device_info, ip_address, expires_at, status
                            ) VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')
                            RETURNING id;
                            """,
                            user_id,
                            family_id,
                            new_digest,
                            device_info,
                            ip_address,
                            new_expires_at,
                        )

                        await conn.execute(
                            """
                            UPDATE refresh_tokens
                            SET status = 'ROTATED',
                                rotated_at = $1,
                                successor_id = $2
                            WHERE id = $3;
                            """,
                            now,
                            new_token_id,
                            token_row["id"],
                        )

                        result_payload = {
                            "status": "ROTATED",
                            "user_id": str(user_id),
                            "session_id": str(new_token_id),
                            "family_id": str(family_id),
                            "refresh_token": new_raw_token,
                            "expires_at": new_expires_at.isoformat(),
                        }

        if revoked_family_reason is not None and self.redis is not None:
            mark_family_revoked_in_redis(
                self.redis,
                revoked_family_reason[0],
                reason=revoked_family_reason[1],
            )

        if err_to_raise:
            raise err_to_raise

        return result_payload

    async def verify_active_session(self, raw_token: str) -> Dict[str, Any] | None:
        """
        Verifies that the provided raw session token corresponds to an ACTIVE,
        non-expired session in PostgreSQL (SSOT).
        """
        token_digest = hash_token(raw_token)
        now = datetime.now(UTC)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT rt.id, rt.user_id, rt.family_id, rt.status, rt.expires_at, u.status AS user_status
                FROM refresh_tokens rt
                JOIN users u ON rt.user_id = u.id
                WHERE rt.token_hash = $1;
                """,
                token_digest,
            )

            if not row or row["status"] != "ACTIVE" or row["expires_at"] < now:
                return None
            if row["user_status"] != "ACTIVE":
                # Proactively terminate family on account suspension/blockage (T13-AC5)
                await conn.execute(
                    "UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = $1 AND status != 'REVOKED';",
                    row["family_id"],
                )
                if self.redis is not None:
                    mark_family_revoked_in_redis(self.redis, row["family_id"], reason="ACCOUNT_BLOCKED")
                return None
            return dict(row)

    async def revoke_session_family(self, family_id: uuid.UUID, reason: str = "LOGOUT") -> int:
        """Revokes every token in a given session family (F-05, T13-AC5)."""
        async with self.pool.acquire() as conn:
            res = await conn.execute(
                """
                UPDATE refresh_tokens
                SET status = 'REVOKED'
                WHERE family_id = $1 AND status != 'REVOKED';
                """,
                family_id,
            )
        if self.redis is not None:
            mark_family_revoked_in_redis(self.redis, family_id, reason=reason)
        try:
            return int(res.split()[1])
        except Exception:
            return 0

    async def revoke_session(self, raw_refresh_token: str, reason: str = "LOGOUT") -> bool:
        """
        Revokes the ENTIRE session family associated with `raw_refresh_token` (F-05, T13-AC5).
        Prevents session survival via previously rotated tokens or sibling tokens in the same family.
        """
        token_digest = hash_token(raw_refresh_token)
        revoked_fid = None
        rowcount = 0
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT family_id FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE;",
                    token_digest,
                )
                if not row:
                    return False
                revoked_fid = row["family_id"]
                res = await conn.execute(
                    """
                    UPDATE refresh_tokens
                    SET status = 'REVOKED'
                    WHERE family_id = $1 AND status != 'REVOKED';
                    """,
                    revoked_fid,
                )
                try:
                    rowcount = int(res.split()[1])
                except Exception:
                    rowcount = 0
        if revoked_fid is not None and self.redis is not None:
            mark_family_revoked_in_redis(self.redis, revoked_fid, reason=reason)
        return rowcount >= 1

    async def revoke_all_user_sessions(
        self, user_id: uuid.UUID, reason: str = "USER_REVOKED"
    ) -> int:
        """Revokes all sessions across all families for a given user."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                UPDATE refresh_tokens
                SET status = 'REVOKED'
                WHERE user_id = $1 AND status != 'REVOKED'
                RETURNING family_id;
                """,
                user_id,
            )
        if self.redis is not None:
            for fid in {r["family_id"] for r in rows}:
                mark_family_revoked_in_redis(self.redis, fid, reason=reason)
        return len(rows)
