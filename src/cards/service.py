"""
Digital Membership Card Service & QR Verification
BASELINE: BL-HAMICARD-PRD-V1 | Section 7 (CARD-001..015), Section 16, Section 27 (BR-13..15)

Features:
- Instant virtual card generation from active memberships
- Cryptographically signed QR code payload for zero-trust clinical scan verification
- Dynamic PII masking of cardholder national code
- Doctor/Clinic scan validation endpoint
"""

import hashlib
import hmac
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Dict

import asyncpg

from src.common.pii import mask_national_code


class CardError(Exception):
    """Base exception for virtual card operations."""
    pass


class MembershipNotFoundError(CardError):
    pass


class InvalidQrSignatureError(CardError):
    pass


class CardService:
    def __init__(self, db_pool: asyncpg.Pool):
        self.pool = db_pool
        self.secret_key = os.getenv("APP_SECRET", "hamicard_production_secret_key_change_in_vault_32bytes").encode("utf-8")

    def _sign_membership_id(self, membership_id: uuid.UUID) -> str:
        """Generates HMAC-SHA256 signature for membership QR payload."""
        h = hmac.new(self.secret_key, str(membership_id).encode("utf-8"), hashlib.sha256)
        return h.hexdigest()[:16]

    def _generate_card_number(self, membership_id: uuid.UUID, year: int = 1405) -> str:
        """Formats standard Iranian HamiCard membership number: HAMI-YYYY-XXXXXXXX."""
        seq = membership_id.int % 100000000
        return f"HAMI-{year}-{seq:08d}"

    async def get_virtual_card(
        self,
        membership_id: uuid.UUID,
        requesting_role: str = "USER"
    ) -> Dict[str, Any]:
        """
        Retrieves complete virtual membership card for digital wallet rendering.
        Applies role-based dynamic PII masking to national code.
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
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
                    h.mobile,
                    p.title AS plan_title,
                    p.discount_percent
                FROM memberships m
                JOIN plan_holders h ON m.holder_id = h.id
                JOIN discount_plans p ON m.plan_id = p.id
                WHERE m.id = $1
            """, membership_id)

            if not row:
                raise MembershipNotFoundError(f"Membership '{membership_id}' not found.")

            # Dynamic PII masking
            nat_code = row["national_code"]
            if requesting_role not in ("SUPER_ADMIN", "ADMIN"):
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
                "membership_id": str(row["membership_id"]),
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

    async def verify_qr_scan(self, qr_payload: str) -> Dict[str, Any]:
        """
        Validates QR code scanned by a doctor or clinic receptionist.
        Verifies cryptographic HMAC signature to prevent barcode forgery.
        """
        parts = qr_payload.strip().split(":")
        if len(parts) != 4 or parts[0] != "HAMICARD" or parts[1] != "v1":
            raise InvalidQrSignatureError("Malformed or unsupported QR code format.")

        try:
            membership_id = uuid.UUID(parts[2])
        except ValueError:
            raise InvalidQrSignatureError("Invalid membership UUID in QR code.")

        provided_sig = parts[3]
        expected_sig = self._sign_membership_id(membership_id)
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise InvalidQrSignatureError("QR signature verification failed. Possible counterfeit card.")

        # Return live card status
        card = await self.get_virtual_card(membership_id, requesting_role="DOCTOR")
        return {
            "verified": True,
            "card": card,
            "can_record_visit": card["is_active"] and (card["remaining_visits"] is None or card["remaining_visits"] > 0),
        }
