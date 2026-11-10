"""
Unit & Integration Tests for Digital Membership Cards & QR Verification
BASELINE: BL-HAMICARD-PRD-V1 | Section 7 (CARD-001..015), Section 16, Section 27 (BR-13..15)
"""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.cards.service import CardService, InvalidQrSignatureError, MembershipNotFoundError

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


@pytest.mark.asyncio
async def test_virtual_card_generation_and_pii_masking():
    pool = await asyncpg.create_pool(PG_URI, min_size=1, max_size=5)
    card_svc = CardService(pool)

    try:
        async with pool.acquire() as conn:
            # 1. Setup plan holder
            nat_code = f"00{uuid.uuid4().int % 100000000:08d}"
            holder = await conn.fetchrow("""
                INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
                VALUES ('مریم', 'صادقی', $1, '09123334455')
                RETURNING id
            """, nat_code)
            holder_id = holder["id"]

            # 2. Setup discount plan
            plan = await conn.fetchrow("""
                INSERT INTO discount_plans (
                    title, description, price_toman, validity_days,
                    discount_percent, max_visits, is_active
                ) VALUES ('طرح خانواده سلامت', 'شامل ویزیت پزشکان', 300000, 365, 30.0, 10, TRUE)
                RETURNING id
            """)
            plan_id = plan["id"]

            # 3. Setup active membership
            start_date = datetime.now(UTC)
            end_date = start_date + timedelta(days=365)
            mem = await conn.fetchrow("""
                INSERT INTO memberships (
                    holder_id, plan_id, origin_type, start_date, end_date,
                    max_visits, remaining_visits, used_visits, status
                ) VALUES ($1, $2, 'DIRECT_PURCHASE', $3, $4, 10, 10, 0, 'ACTIVE')
                RETURNING id
            """, holder_id, plan_id, start_date, end_date)
            mem_id = mem["id"]

        # Test USER view (PII masked)
        user_card = await card_svc.get_virtual_card(mem_id, requesting_role="USER")
        assert user_card["card_number"].startswith("HAMI-1405-")
        assert user_card["holder_full_name"] == "مریم صادقی"
        assert "****" in user_card["national_code"]
        assert user_card["is_active"] is True
        assert user_card["remaining_visits"] == 10
        assert user_card["qr_code_payload"].startswith(f"HAMICARD:v1:{mem_id}:")

        # Test ADMIN view (PII unmasked)
        admin_card = await card_svc.get_virtual_card(mem_id, requesting_role="ADMIN")
        assert admin_card["national_code"] == nat_code

        # Test QR Scan Verification
        scan_res = await card_svc.verify_qr_scan(user_card["qr_code_payload"])
        assert scan_res["verified"] is True
        assert scan_res["can_record_visit"] is True
        assert scan_res["card"]["holder_full_name"] == "مریم صادقی"

        # Test Tampered QR Payload
        tampered_qr = user_card["qr_code_payload"][:-3] + "xyz"
        with pytest.raises(InvalidQrSignatureError, match="signature verification failed"):
            await card_svc.verify_qr_scan(tampered_qr)

        # Test Malformed QR
        with pytest.raises(InvalidQrSignatureError, match="Malformed"):
            await card_svc.verify_qr_scan("INVALID-QR-STRING")

        # Test Non-existent membership
        with pytest.raises(MembershipNotFoundError):
            await card_svc.get_virtual_card(uuid.uuid4())

    finally:
        await pool.close()


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_virtual_card_generation_and_pii_masking())
    print("All virtual card tests passed successfully!")
