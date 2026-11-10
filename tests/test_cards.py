"""
Unit & Integration Tests for Digital Membership Cards & QR Verification
BASELINE: BL-HAMICARD-PRD-V1 | Section 7 (CARD-001..015), Section 16, Section 27 (BR-13..15)
REMEDIATION: HC-T19 (F-12 HIGH, CARD_QR_STATIC_SECRET_FALLBACK, T19-AC3..AC5)
"""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.cards.service import (
    CardAuthorizationError,
    CardConfigurationError,
    CardService,
    InvalidQrSignatureError,
    MembershipNotFoundError,
)

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)
TEST_QR_SECRET = "hc_t19_unit_test_card_qr_signing_secret_minimum_32_chars"


@pytest.mark.asyncio
async def test_virtual_card_generation_ownership_and_fail_closed_secret(monkeypatch):
    monkeypatch.delenv("CARD_QR_SECRET", raising=False)
    monkeypatch.delenv("APP_SECRET", raising=False)

    pool = await asyncpg.create_pool(PG_URI, min_size=1, max_size=5)

    # 1. Fail-Closed Secret Verification (no static fallback allowed)
    with pytest.raises(CardConfigurationError):
        CardService(pool)

    with pytest.raises(CardConfigurationError):
        CardService(pool, secret_key="hamicard_production_secret_key_change_in_vault_32bytes")

    card_svc = CardService(pool, secret_key=TEST_QR_SECRET)

    try:
        async with pool.acquire() as conn:
            # 2. Seed buyer USER, unrelated USER, ADMIN, and APPROVED DOCTOR (authoritative user_roles)
            buyer_uid = await conn.fetchval(
                "INSERT INTO users (mobile, status, is_mobile_verified) VALUES ($1, 'ACTIVE', TRUE) RETURNING id",
                f"0912{uuid.uuid4().int % 10000000:07d}",
            )
            await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'USER') ON CONFLICT DO NOTHING", buyer_uid)

            other_uid = await conn.fetchval(
                "INSERT INTO users (mobile, status, is_mobile_verified) VALUES ($1, 'ACTIVE', TRUE) RETURNING id",
                f"0913{uuid.uuid4().int % 10000000:07d}",
            )
            await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'USER') ON CONFLICT DO NOTHING", other_uid)

            admin_uid = await conn.fetchval(
                "INSERT INTO users (mobile, status, is_mobile_verified) VALUES ($1, 'ACTIVE', TRUE) RETURNING id",
                f"0914{uuid.uuid4().int % 10000000:07d}",
            )
            await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'ADMIN') ON CONFLICT DO NOTHING", admin_uid)

            doc_uid = await conn.fetchval(
                "INSERT INTO users (mobile, status, is_mobile_verified) VALUES ($1, 'ACTIVE', TRUE) RETURNING id",
                f"0915{uuid.uuid4().int % 10000000:07d}",
            )
            await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'DOCTOR') ON CONFLICT DO NOTHING", doc_uid)
            await conn.execute(
                """
                INSERT INTO doctors (
                    user_id, medical_council_code, specialty, clinic_name,
                    province_id, city_id, clinic_address, clinic_phone, verification_status, is_public_listed
                ) VALUES ($1, $2, 'General', 'Unit Clinic', 1, 1, 'Tehran', '0212222', 'APPROVED', TRUE)
                """,
                doc_uid,
                f"T19U-{uuid.uuid4().hex[:6]}",
            )

            # 3. Setup plan holder + discount plan + order + membership
            nat_code = f"00{uuid.uuid4().int % 100000000:08d}"
            holder_id = await conn.fetchval(
                """
                INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
                VALUES ('مریم', 'صادقی', $1, '09123334455')
                RETURNING id
                """,
                nat_code,
            )
            plan_id = await conn.fetchval(
                """
                INSERT INTO discount_plans (
                    title, description, price_toman, validity_days,
                    discount_percent, max_visits, is_active
                ) VALUES ('طرح خانواده سلامت', 'شامل ویزیت پزشکان', 300000, 365, 30.0, 10, TRUE)
                RETURNING id
                """
            )
            order_id = await conn.fetchval(
                """
                INSERT INTO orders_payments (buyer_user_id, holder_id, plan_id, amount_toman, status, idempotency_key)
                VALUES ($1, $2, $3, 300000, 'SUCCESS', $4)
                RETURNING id
                """,
                buyer_uid,
                holder_id,
                plan_id,
                f"CARD-UNIT-{uuid.uuid4().hex}",
            )
            start_date = datetime.now(UTC)
            end_date = start_date + timedelta(days=365)
            mem_id = await conn.fetchval(
                """
                INSERT INTO memberships (
                    holder_id, plan_id, order_id, origin_type, start_date, end_date,
                    max_visits, remaining_visits, used_visits, status
                ) VALUES ($1, $2, $3, 'DIRECT_PURCHASE', $4, $5, 10, 10, 0, 'ACTIVE')
                RETURNING id
                """,
                holder_id,
                plan_id,
                order_id,
                start_date,
                end_date,
            )

        # 4. Buyer owner view (PII masked)
        user_card = await card_svc.get_virtual_card(mem_id, actor_user_id=buyer_uid)
        assert user_card["card_number"].startswith("HAMI-1405-")
        assert user_card["holder_full_name"] == "مریم صادقی"
        assert "****" in user_card["national_code"]
        assert user_card["national_code"] != nat_code
        assert user_card["is_active"] is True
        assert user_card["remaining_visits"] == 10
        assert user_card["qr_code_payload"].startswith(f"HAMICARD:v1:{mem_id}:")

        # 5. Unrelated USER B blocked (IDOR prevention)
        with pytest.raises(CardAuthorizationError):
            await card_svc.get_virtual_card(mem_id, actor_user_id=other_uid)

        # 6. ADMIN view (PII unmasked)
        admin_card = await card_svc.get_virtual_card(mem_id, actor_user_id=admin_uid)
        assert admin_card["national_code"] == nat_code

        # 7. QR Scan Verification by APPROVED doctor only
        with pytest.raises(CardAuthorizationError):
            await card_svc.verify_qr_scan(user_card["qr_code_payload"], actor_user_id=other_uid)

        scan_res = await card_svc.verify_qr_scan(user_card["qr_code_payload"], actor_user_id=doc_uid)
        assert scan_res["verified"] is True
        assert scan_res["can_record_visit"] is True
        assert scan_res["card"]["holder_full_name"] == "مریم صادقی"
        assert scan_res["card"]["national_code"] != nat_code

        # 8. Tampered QR Payload
        tampered_qr = user_card["qr_code_payload"][:-3] + "xyz"
        with pytest.raises(InvalidQrSignatureError, match="signature verification failed"):
            await card_svc.verify_qr_scan(tampered_qr, actor_user_id=doc_uid)

        # 9. Malformed QR
        with pytest.raises(InvalidQrSignatureError, match="Malformed"):
            await card_svc.verify_qr_scan("INVALID-QR-STRING", actor_user_id=doc_uid)

        # 10. Non-existent membership for ADMIN -> MembershipNotFoundError
        with pytest.raises(MembershipNotFoundError):
            await card_svc.get_virtual_card(uuid.uuid4(), actor_user_id=admin_uid)

    finally:
        await pool.close()
