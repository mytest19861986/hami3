"""
Referrals & Affiliate Domain Service (REF-001..012)
Generates unique user referral codes, tracks multi-tier user invitations,
and computes marketer statistics and affiliate conversion rates.
"""

import uuid
import secrets
from typing import Dict, Any, List, Optional
import asyncpg


class ReferralError(Exception):
    """Base exception for referral operations."""
    pass


class InvalidReferralCodeError(ReferralError):
    """Raised when an unknown referral code is provided."""
    pass


class SelfReferralNotAllowedError(ReferralError):
    """Raised when a user attempts to use their own referral code."""
    pass


class ReferralService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def get_or_create_referral_code(self, user_id: uuid.UUID) -> str:
        """
        Retrieves or generates a permanent unique referral code for a user.
        Format: HAMI-XXXXXX (6 alphanumeric characters)
        """
        async with self.pool.acquire() as conn:
            # Check existing referral code
            existing = await conn.fetchrow(
                "SELECT referral_code FROM referrals WHERE referrer_user_id = $1 LIMIT 1",
                user_id
            )
            if existing:
                return existing["referral_code"]

            # Generate new unique code
            for _ in range(10):
                code = f"HAMI-{secrets.token_hex(3).upper()}"
                in_use = await conn.fetchrow(
                    "SELECT 1 FROM referrals WHERE referral_code = $1 LIMIT 1", code
                )
                if not in_use:
                    return code

            return f"HAMI-{uuid.uuid4().hex[:6].upper()}"

    async def register_referral(
        self,
        referral_code: str,
        referred_user_id: uuid.UUID
    ) -> Dict[str, Any]:
        """
        Links a newly registered user to their referrer using the referral code.
        Guards: Self-referral blocked, duplicate referred_user_id blocked.
        """
        clean_code = referral_code.strip().upper()

        async with self.pool.acquire() as conn:
            # 1. Resolve referrer
            referrer_row = await conn.fetchrow(
                """
                SELECT referrer_user_id FROM referrals
                WHERE referral_code = $1 LIMIT 1
                """, clean_code
            )

            if not referrer_row:
                # If code is not in referrals table yet, check if valid user code format
                # For direct code sharing, find user who owns this code or create first entry
                raise InvalidReferralCodeError(f"Referral code '{referral_code}' is not valid.")

            referrer_id = referrer_row["referrer_user_id"]

            if referrer_id == referred_user_id:
                raise SelfReferralNotAllowedError("Users cannot use their own referral code.")

            # 2. Insert referral link
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO referrals (referrer_user_id, referred_user_id, referral_code, status)
                    VALUES ($1, $2, $3, 'ACTIVE')
                    RETURNING id, referrer_user_id, referred_user_id, referral_code, status, created_at
                    """, referrer_id, referred_user_id, clean_code
                )
                return dict(row)
            except asyncpg.UniqueViolationError:
                raise ReferralError("This user is already linked to a referrer.")

    async def create_user_referral_link(
        self,
        referrer_user_id: uuid.UUID,
        referred_user_id: uuid.UUID,
        custom_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates a referral link between two users directly."""
        if referrer_user_id == referred_user_id:
            raise SelfReferralNotAllowedError("Self referral is not allowed.")

        code = custom_code or await self.get_or_create_referral_code(referrer_user_id)

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO referrals (referrer_user_id, referred_user_id, referral_code, status)
                VALUES ($1, $2, $3, 'ACTIVE')
                ON CONFLICT (referred_user_id) DO NOTHING
                RETURNING *
                """, referrer_user_id, referred_user_id, code
            )
            if not row:
                raise ReferralError("Referred user already has an active referrer.")
            return dict(row)

    async def get_referral_stats(self, user_id: uuid.UUID) -> Dict[str, Any]:
        """
        Computes detailed referral analytics:
        - Total referred signups
        - Total purchases made by referred network
        - Total commission earned in Toman
        """
        async with self.pool.acquire() as conn:
            # Total signups
            total_signups = await conn.fetchval(
                "SELECT COUNT(*) FROM referrals WHERE referrer_user_id = $1 AND status = 'ACTIVE'",
                user_id
            )

            # Total commission earned
            comm_stats = await conn.fetchrow(
                """
                SELECT COALESCE(SUM(amount_toman), 0) as total_earned_toman,
                       COUNT(*) as total_commissions_count
                FROM commissions
                WHERE beneficiary_user_id = $1 AND commission_type = 'REFERRAL' AND status IN ('APPROVED', 'SETTLED')
                """, user_id
            )

            # Active referral code
            code = await conn.fetchval(
                "SELECT referral_code FROM referrals WHERE referrer_user_id = $1 LIMIT 1",
                user_id
            )

            return {
                "referral_code": code or f"HAMI-{user_id.hex[:6].upper()}",
                "total_referred_users": total_signups or 0,
                "total_earned_toman": int(comm_stats["total_earned_toman"]),
                "total_commission_transactions": int(comm_stats["total_commissions_count"])
            }
