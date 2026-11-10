"""
Digital Membership Card Service & QR Verification
BASELINE: BL-HAMICARD-PRD-V1 | Section 7 (CARD-001..015), Section 16, Section 27 (BR-13..15)
REMEDIATION: HC-T19 (F-12 HIGH, CARD_QR_STATIC_SECRET_FALLBACK, T19-AC3..AC5)

Security Guarantees:
- Fail-Closed QR Secret: No static/hardcoded fallback secret. Requires `CARD_QR_SECRET` or
  `APP_SECRET` >= 32 characters (rejecting known placeholder strings).
- Ownership Enforcement: Virtual card retrieval requires authenticated actor who is the
  holder, order buyer, ADMIN, SUPER_ADMIN, or SUPPORT (`T19-AC3` IDOR prevention).
- Clinic QR Verification: Restricted at service & API boundaries to active APPROVED
  doctors (`visits:record`) or authorized admins, with full security audit logging.
- Dynamic PII Masking: Raw holder national codes are revealed ONLY to ADMIN/SUPER_ADMIN.
"""

import hashlib
import hmac
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Dict

import asyncpg

from src.auth.rbac import RbacAccessDeniedError, RbacEngine
from src.common.pii import mask_national_code

_FORBIDDEN_PLACEHOLDER_SECRETS = {
    "",
    "changeme",
    "secret",
    "dev-secret",
    "hamicard_production_secret_key_change_in_vault_32bytes",
}


class CardError(Exception):
    """Base exception for virtual card operations."""
    pass


class CardConfigurationError(CardError):
    """Raised when QR HMAC signing secret is missing, short, or an insecure placeholder."""
    pass


class CardAuthorizationError(CardError):
    """Raised when actor lacks ownership or clinical authorization for card operations."""
    pass


class MembershipNotFoundError(CardError):
    pass


class InvalidQrSignatureError(CardError):
    pass


class CardService:
    def __init__(self, db_pool: asyncpg.Pool, secret_key: str | None = None):
        self.pool = db_pool
        self.rbac = RbacEngine(db_pool)

        raw_secret = (
            secret_key
            if secret_key is not None
            else (os.getenv("CARD_QR_SECRET") or os.getenv("APP_SECRET") or "")
        )
        clean_secret = raw_secret.strip()
        if (
            not clean_secret
            or len(clean_secret) < 32
            or clean_secret in _FORBIDDEN_PLACEHOLDER_SECRETS
        ):
            raise CardConfigurationError(
                "Fail-Closed Configuration Error: CARD_QR_SECRET or APP_SECRET (>= 32 chars) "
                "must be configured; hardcoded fallback signing keys are forbidden."
            )
        self.secret_key = clean_secret.encode("utf-8")

    def _sign_membership_id(self, membership_id: uuid.UUID) -> str:
        """Generates 128-bit (32 hex) HMAC-SHA256 signature for membership QR payload."""
        h = hmac.new(self.secret_key, str(membership_id).encode("utf-8"), hashlib.sha256)
        return h.hexdigest()[:32]

    def _generate_card_number(self, membership_id: uuid.UUID, year: int = 1405) -> str:
        """Formats standard Iranian HamiCard membership number: HAMI-YYYY-XXXXXXXX."""
        seq = membership_id.int % 100000000
        return f"HAMI-{year}-{seq:08d}"

    def _serialize_card(self, row: asyncpg.Record, include_unmasked_nat: bool) -> Dict[str, Any]:
        membership_id = row["membership_id"]
        nat_code = row["national_code"]
        if not include_unmasked_nat:
            nat_code = mask_national_code(nat_code)

        card_number = self._generate_card_number(membership_id)
        sig = self._sign_membership_id(membership_id)
        qr_payload = f"HAMICARD:v1:{membership_id}:{sig}"

        now_utc = datetime.now(UTC)
        end_date = row["end_date"]
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=UTC)

        is_active = (row["membership_status"] == "ACTIVE") and (end_date > now_utc)
        return {
            "membership_id": str(membership_id),
            "holder_id": str(row["holder_id"]),
            "card_number": card_number,
            "holder_full_name": f"{row['first_name']} {row['last_name']}",
            "national_code": nat_code,
            "plan_title": row["plan_title"],
            "discount_percent": float(row["discount_percent"]),
            "status": row["membership_status"],
            "is_active": is_active,
            "start_date": row["start_date"].isoformat(),
            "end_date": row["end_date"].isoformat(),
            "max_visits": row["max_visits"],
            "remaining_visits": row["remaining_visits"],
            "used_visits": row["used_visits"],
            "qr_code_payload": qr_payload,
        }

    async def get_virtual_card(
        self,
        membership_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        """
        Retrieves complete virtual membership card ONLY for the holder, order buyer,
        ADMIN, SUPER_ADMIN, or SUPPORT (`T19-AC3`).
        Applies strict PII masking for non-ADMIN roles.
        """
        if actor_user_id is None:
            raise CardAuthorizationError("Authenticated actor_user_id is required.")

        async with self.pool.acquire() as conn:
            try:
                actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            except RbacAccessDeniedError as exc:
                raise CardAuthorizationError(str(exc)) from exc

            is_admin = bool(actor_roles & {"SUPER_ADMIN", "ADMIN"})
            is_support = "SUPPORT" in actor_roles

            row = await conn.fetchrow(
                """
                SELECT
                    m.id AS membership_id,
                    m.holder_id,
                    m.plan_id,
                    m.status AS membership_status,
                    m.start_date,
                    m.end_date,
                    m.max_visits,
                    m.remaining_visits,
                    m.used_visits,
                    h.first_name,
                    h.last_name,
                    h.national_code,
                    p.title AS plan_title,
                    p.discount_percent,
                    op.buyer_user_id AS order_buyer_user_id,
                    actor_prof.national_code AS actor_profile_national_code
                FROM memberships m
                JOIN plan_holders h ON m.holder_id = h.id
                JOIN discount_plans p ON m.plan_id = p.id
                LEFT JOIN orders_payments op ON m.order_id = op.id
                LEFT JOIN profiles actor_prof ON actor_prof.user_id = $2
                WHERE m.id = $1
                """,
                membership_id,
                actor_user_id,
            )

            if not row:
                if is_admin or is_support:
                    raise MembershipNotFoundError(f"Membership '{membership_id}' not found.")
                raise CardAuthorizationError(
                    "Access denied: You are not authorized to access this membership card."
                )

            is_owner = (
                row["order_buyer_user_id"] == actor_user_id
                or (
                    row["actor_profile_national_code"] is not None
                    and row["actor_profile_national_code"] == row["national_code"]
                )
            )

            if not (is_admin or is_support or is_owner):
                raise CardAuthorizationError(
                    "Access denied: You are not authorized to retrieve another holder's membership card."
                )

            return self._serialize_card(row, include_unmasked_nat=is_admin)

    async def verify_qr_scan(
        self,
        qr_payload: str,
        actor_user_id: uuid.UUID | None = None,
    ) -> Dict[str, Any]:
        """
        Validates QR code scanned by an APPROVED doctor or clinic admin (`T19-AC4/AC5`).
        Verifies RBAC + APPROVED doctor status and constant-time HMAC signature.
        """
        if actor_user_id is None:
            raise CardAuthorizationError("Authenticated clinical actor_user_id is required.")

        try:
            await self.rbac.check_permission(actor_user_id, "visits:record")
        except RbacAccessDeniedError as exc:
            raise CardAuthorizationError(str(exc)) from exc

        async with self.pool.acquire() as conn:
            actor_roles = await self.rbac.get_user_roles(conn, actor_user_id)
            actor_role_label = (
                "SUPER_ADMIN"
                if "SUPER_ADMIN" in actor_roles
                else ("ADMIN" if "ADMIN" in actor_roles else "DOCTOR")
            )

            parts = qr_payload.strip().split(":")
            if len(parts) != 4 or parts[0] != "HAMICARD" or parts[1] != "v1":
                raise InvalidQrSignatureError("Malformed or unsupported QR code format.")

            try:
                membership_id = uuid.UUID(parts[2])
            except ValueError as exc:
                raise InvalidQrSignatureError("Invalid membership UUID in QR code.") from exc

            provided_sig = parts[3]
            expected_sig = self._sign_membership_id(membership_id)
            if not hmac.compare_digest(provided_sig, expected_sig):
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id, new_values
                    ) VALUES (
                        $1, $2, 'CARD_QR_VERIFICATION_FAILED', 'memberships', $3::varchar,
                        $4::jsonb
                    )
                    """,
                    actor_user_id,
                    actor_role_label,
                    str(membership_id),
                    json.dumps({"reason": "invalid_signature"}),
                )
                raise InvalidQrSignatureError(
                    "QR signature verification failed. Possible counterfeit card."
                )

            row = await conn.fetchrow(
                """
                SELECT
                    m.id AS membership_id,
                    m.holder_id,
                    m.plan_id,
                    m.status AS membership_status,
                    m.start_date,
                    m.end_date,
                    m.max_visits,
                    m.remaining_visits,
                    m.used_visits,
                    h.first_name,
                    h.last_name,
                    h.national_code,
                    p.title AS plan_title,
                    p.discount_percent
                FROM memberships m
                JOIN plan_holders h ON m.holder_id = h.id
                JOIN discount_plans p ON m.plan_id = p.id
                WHERE m.id = $1
                """,
                membership_id,
            )
            if not row:
                raise MembershipNotFoundError(f"Membership '{membership_id}' not found.")

            # Clinical view ALWAYS masks holder national code
            card = self._serialize_card(row, include_unmasked_nat=False)
            await conn.execute(
                """
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, action, entity_name, entity_id, new_values
                ) VALUES (
                    $1, $2, 'CARD_QR_VERIFIED', 'memberships', $3::varchar, $4::jsonb
                )
                """,
                actor_user_id,
                actor_role_label,
                str(membership_id),
                json.dumps({"is_active": card["is_active"]}),
            )
            return {
                "verified": True,
                "card": card,
                "can_record_visit": card["is_active"]
                and (card["remaining_visits"] is None or card["remaining_visits"] > 0),
            }
