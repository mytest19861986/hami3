"""Integration and unit tests for ProfileService & ReferenceService (Phase 3)."""
import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncpg

from src.profiles.service import ProfileService, ProfileValidationError, ReferenceService

DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)


async def setup_test_pool():
    return await asyncpg.create_pool(DB_URL, min_size=1, max_size=5)


def gen_valid_test_national_code():
    prefix = f"{uuid.uuid4().int % 1000000000:09d}"
    s = sum(int(prefix[i]) * (10 - i) for i in range(9))
    r = s % 11
    c = r if r < 2 else (11 - r)
    return prefix + str(c)


async def test_reference_service_provinces_and_cities():
    print("\n[PROFILE TEST 1/4] Testing Provinces & Cities Reference Hierarchy...")
    pool = await setup_test_pool()
    ref_svc = ReferenceService(pool)

    # 1. All 31 provinces must exist
    provinces = await ref_svc.get_all_provinces()
    assert len(provinces) == 31, f"Expected 31 provinces, got {len(provinces)}"
    tehran = next(p for p in provinces if p["name"] == "تهران")
    assert tehran["id"] == 1, f"Expected Tehran province ID 1, got {tehran['id']}"

    # 2. Cities for Tehran province
    cities = await ref_svc.get_cities_by_province(tehran["id"])
    assert len(cities) >= 1
    tehran_city = next(c for c in cities if c["name"] == "تهران")
    assert tehran_city["province_id"] == tehran["id"]

    # 3. Hierarchy validation: valid pair
    valid = await ref_svc.validate_province_and_city(tehran["id"], tehran_city["id"])
    assert valid is True

    # 4. Hierarchy validation: invalid pair (mismatch province and city)
    # City 7 is Isfahan (province_id=2), pairing with Tehran (1) must fail
    mismatch_failed = False
    try:
        await ref_svc.validate_province_and_city(province_id=1, city_id=7)
    except ProfileValidationError as e:
        mismatch_failed = True
        assert "does not belong" in str(e)
    assert mismatch_failed, "Mismatch province-city did not raise ProfileValidationError!"

    print("  ✓ Reference Service PASS: All 31 provinces and parent-child city constraints verified.")
    await pool.close()


async def test_profile_upsert_and_validation():
    print("\n[PROFILE TEST 2/4] Testing Profile Upsert & Input Validation...")
    pool = await setup_test_pool()
    prof_svc = ProfileService(pool)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

    # Valid National Code: 0010350829
    # Valid Luhn Card: 6037991199999990
    # Valid Sheba: IR630170000000100412345678
    test_nc = gen_valid_test_national_code()
    res = await prof_svc.upsert_profile(
        user_id=user_id,
        first_name="علی",
        last_name="رضایی",
        national_code=test_nc,
        province_id=1,
        city_id=1, # Tehran
        bank_card_number="6037-9911-9999-9990",
        bank_sheba_number="IR630170000000100412345678",
    )
    assert res["id"] is not None
    assert res["national_code"] == test_nc

    # Test invalid National Code rejection
    invalid_nc_caught = False
    try:
        await prof_svc.upsert_profile(
            user_id=user_id,
            first_name="علی",
            last_name="رضایی",
            national_code="1111111111", # repeating
        )
    except ProfileValidationError as e:
        invalid_nc_caught = True
        assert "Invalid Iranian National Code" in str(e)
    assert invalid_nc_caught, "Invalid national code passed validation!"

    # Test invalid Luhn Card rejection
    invalid_card_caught = False
    try:
        await prof_svc.upsert_profile(
            user_id=user_id,
            first_name="علی",
            last_name="رضایی",
            bank_card_number="6037991199999995", # wrong Luhn
        )
    except ProfileValidationError as e:
        invalid_card_caught = True
        assert "Luhn failure" in str(e)
    assert invalid_card_caught, "Invalid card number passed Luhn validation!"

    print("  ✓ Profile Upsert PASS: Valid profile persisted; invalid National Code and Card rejected.")
    await pool.close()


async def test_national_code_uniqueness():
    print("\n[PROFILE TEST 3/4] Testing National Code Uniqueness across Users...")
    pool = await setup_test_pool()
    prof_svc = ProfileService(pool)

    # Create User 1
    async with pool.acquire() as conn:
        u1 = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")
        u2 = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

    shared_nc = gen_valid_test_national_code()
    # Register national code for User 1
    await prof_svc.upsert_profile(user_id=u1, first_name="کاربر", last_name="اول", national_code=shared_nc)

    # Attempting to assign same national code to User 2 must fail
    dup_blocked = False
    try:
        await prof_svc.upsert_profile(user_id=u2, first_name="کاربر", last_name="دوم", national_code=shared_nc)
    except ProfileValidationError as e:
        dup_blocked = True
        assert "already registered" in str(e)
    assert dup_blocked, "Duplicate national code registration allowed!"

    print("  ✓ National Code Uniqueness PASS: Duplicate national code across accounts blocked.")
    await pool.close()


async def test_role_based_pii_masking():
    print("\n[PROFILE TEST 4/4] Testing Role-Based PII Masking (PROFILE-006 & PROFILE-009)...")
    pool = await setup_test_pool()
    prof_svc = ProfileService(pool)

    nc = gen_valid_test_national_code()
    mobile = f"0912{uuid.uuid4().int % 10000000:07d}"

    async with pool.acquire() as conn:
        user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, mobile)

    await prof_svc.upsert_profile(
        user_id=user_id,
        first_name="سارا",
        last_name="احمدی",
        national_code=nc,
        bank_card_number="5022291012345672",
        bank_sheba_number="IR100560000000100412345678",
    )

    # 1. Non-admin viewer (USER or SUPPORT) must receive masked PII
    masked_profile = await prof_svc.get_profile(user_id, viewer_roles=["USER"])
    assert masked_profile is not None
    assert masked_profile["national_code"] == f"******{nc[-4:]}"
    assert masked_profile["bank_card_number"] == "5022********5672"
    assert masked_profile["bank_sheba_number"].startswith("IR**")
    assert masked_profile["bank_sheba_number"].endswith("78")
    assert masked_profile["mobile"] == f"{mobile[:4]}***{mobile[-4:]}"

    # 2. Administrative viewer (ADMIN or SUPER_ADMIN) receives unmasked data
    unmasked_profile = await prof_svc.get_profile(user_id, viewer_roles=["ADMIN"])
    assert unmasked_profile is not None
    assert unmasked_profile["national_code"] == nc
    assert unmasked_profile["bank_card_number"] == "5022291012345672"
    assert unmasked_profile["bank_sheba_number"] == "IR100560000000100412345678"
    assert unmasked_profile["mobile"] == mobile

    print("  ✓ Role-Based PII Masking PASS: Financial and PII fields strictly masked for non-admin viewers.")
    await pool.close()


async def main():
    await test_reference_service_provinces_and_cities()
    await test_profile_upsert_and_validation()
    await test_national_code_uniqueness()
    await test_role_based_pii_masking()
    print("\n" + "="*70)
    print("ALL 4 PROFILE & REFERENCE TESTS PASSED WITH 100% SUCCESS!")
    print("="*70)


if __name__ == "__main__":
    asyncio.run(main())
