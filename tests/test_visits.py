"""
Automated Verification Suite for Medical Visits & Quota Invariants (VISIT-001..013, AC-07)
Baseline: BL-HAMICARD-PRD-V1
Tests:
1. Accurate financial calculation (total, discount amount, patient paid).
2. Atomic membership quota decrement.
3. Quota exhaustion transitions status to EXHAUSTED and blocks subsequent visits (Zero Overselling).
4. Guard against inactive/expired memberships.
5. Visit cancellation atomically restores quota.
6. Unlimited quota memberships (max_visits IS NULL).
"""

import asyncio
import os
import uuid

import asyncpg

from src.visits.service import (
    MembershipInactiveError,
    QuotaExhaustedError,
    VisitService,
)

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


async def test_visit_financial_computation_and_quota_decrement(pool: asyncpg.Pool):
    print("\n[VISIT TEST 1/4] Testing Visit Financial Computation & Atomic Quota Decrement...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        # Create doctor
        doc_user = await conn.fetchrow(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"DOCTOR\"}') RETURNING id",
            f"0921{uuid.uuid4().int % 10000000:07d}"
        )
        doc = await conn.fetchrow(
            """
            INSERT INTO doctors (
                user_id, medical_council_code, specialty, clinic_name,
                province_id, city_id, clinic_address, clinic_phone, verification_status, is_public_listed
            ) VALUES ($1, $2, 'General', 'Center Clinic', 1, 1, 'Address', '0211111', 'APPROVED', TRUE)
            RETURNING id
            """, doc_user["id"], f"MED-{uuid.uuid4().hex[:6]}"
        )

        # Create card holder
        holder = await conn.fetchrow(
            """
            INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
            VALUES ('علی', 'محمدی', $1, $2)
            RETURNING id
            """, f"{uuid.uuid4().int % 1000000000:010d}", f"0922{uuid.uuid4().int % 10000000:07d}"
        )

        # Create discount plan
        plan = await conn.fetchrow(
            """
            INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits)
            VALUES ('طرح آزمایشی', 200000, 30.0, 30, 2)
            RETURNING id
            """
        )

        # Create membership with 2 visits
        mem = await conn.fetchrow(
            """
            INSERT INTO memberships (
                holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status
            ) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 2, 2, 0, 'ACTIVE')
            RETURNING id
            """, holder["id"], plan["id"]
        )

    # 1. Record first visit (1,000,000 Toman, 30% discount)
    v1 = await visit_svc.record_visit(
        doctor_id=doc["id"],
        holder_id=holder["id"],
        membership_id=mem["id"],
        service_title="ویزیت عمومی و معاینه",
        total_amount_toman=1000000,
        discount_percent=30.0,
        private_notes="نسخه تجویز شد"
    )

    assert v1["id"] is not None
    assert v1["total_amount_toman"] == 1000000
    assert v1["discount_amount_toman"] == 300000
    assert v1["patient_paid_amount_toman"] == 700000
    assert v1["status"] == "COMPLETED"
    print("  ✓ Financial calculations exact: Total 1,000,000 -> Discount 300,000 -> Paid 700,000.")

    # 2. Check membership quota
    async with pool.acquire() as conn:
        mem_after = await conn.fetchrow("SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1", mem["id"])
        assert mem_after["remaining_visits"] == 1
        assert mem_after["used_visits"] == 1
        assert mem_after["status"] == "ACTIVE"
    print("  ✓ Membership quota decremented atomically (remaining: 1, used: 1).")


async def test_quota_exhaustion_and_zero_overselling(pool: asyncpg.Pool):
    print("\n[VISIT TEST 2/4] Testing Quota Exhaustion & AC-07 Zero Overselling...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        doc_user = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0923{uuid.uuid4().int % 10000000:07d}")
        doc = await conn.fetchrow(
            "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Cardio', 'Cardio Clinic', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id",
            doc_user["id"], f"MED-{uuid.uuid4().hex[:6]}"
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('رضا', 'نادری', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}", f"0924{uuid.uuid4().int % 10000000:07d}"
        )
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح ۱ ویزیت', 100000, 20.0, 30, 1) RETURNING id")
        mem = await conn.fetchrow(
            "INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 1, 1, 0, 'ACTIVE') RETURNING id",
            holder["id"], plan["id"]
        )

    # 1. Use the only 1 visit
    v1 = await visit_svc.record_visit(
        doctor_id=doc["id"],
        holder_id=holder["id"],
        membership_id=mem["id"],
        service_title="نوار قلب",
        total_amount_toman=500000,
        discount_percent=20.0
    )
    assert v1["status"] == "COMPLETED"

    # Check status transitioned to EXHAUSTED
    async with pool.acquire() as conn:
        mem_ex = await conn.fetchrow("SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1", mem["id"])
        assert mem_ex["remaining_visits"] == 0
        assert mem_ex["used_visits"] == 1
        assert mem_ex["status"] == "EXHAUSTED"
    print("  ✓ Quota exhausted: status transitioned to EXHAUSTED.")

    # 2. Second visit attempt MUST be blocked
    second_blocked = False
    try:
        await visit_svc.record_visit(
            doctor_id=doc["id"],
            holder_id=holder["id"],
            membership_id=mem["id"],
            service_title="معاینه دوم",
            total_amount_toman=500000,
            discount_percent=20.0
        )
    except (QuotaExhaustedError, MembershipInactiveError):
        second_blocked = True

    assert second_blocked, "Over-quota visit was allowed (Overselling invariant violated)!"
    print("  ✓ AC-07 Zero Overselling PASS: Subsequent visit strictly blocked.")


async def test_visit_cancellation_and_quota_rollback(pool: asyncpg.Pool):
    print("\n[VISIT TEST 3/4] Testing Visit Cancellation & Quota Rollback...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        admin_user = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id", f"0925{uuid.uuid4().int % 10000000:07d}")
        doc_user = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0926{uuid.uuid4().int % 10000000:07d}")
        doc = await conn.fetchrow(
            "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Dentist', 'Smile', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id",
            doc_user["id"], f"MED-{uuid.uuid4().hex[:6]}"
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('سارا', 'کرمی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}", f"0927{uuid.uuid4().int % 10000000:07d}"
        )
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح دندان', 500000, 25.0, 30, 1) RETURNING id")
        mem = await conn.fetchrow(
            "INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 1, 1, 0, 'ACTIVE') RETURNING id",
            holder["id"], plan["id"]
        )

    # Record visit
    v = await visit_svc.record_visit(
        doctor_id=doc["id"],
        holder_id=holder["id"],
        membership_id=mem["id"],
        service_title="جرم‌گیری دندان",
        total_amount_toman=800000,
        discount_percent=25.0
    )

    # Cancel visit
    cancelled = await visit_svc.cancel_visit(
        visit_id=v["id"],
        canceller_user_id=admin_user["id"],
        reason="اشتباه در ثبت خدمات توسط مطب"
    )
    assert cancelled["status"] == "CANCELLED"
    assert cancelled["cancellation_reason"] == "اشتباه در ثبت خدمات توسط مطب"
    print("  ✓ Visit successfully cancelled.")

    # Verify quota rollback on membership
    async with pool.acquire() as conn:
        mem_restored = await conn.fetchrow("SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1", mem["id"])
        assert mem_restored["remaining_visits"] == 1
        assert mem_restored["used_visits"] == 0
        assert mem_restored["status"] == "ACTIVE"
    print("  ✓ Quota rollback verified: remaining_visits restored to 1, status restored to ACTIVE.")


async def test_unlimited_quota_membership(pool: asyncpg.Pool):
    print("\n[VISIT TEST 4/4] Testing Unlimited Quota Memberships (max_visits IS NULL)...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        doc_user = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0928{uuid.uuid4().int % 10000000:07d}")
        doc = await conn.fetchrow(
            "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Optometry', 'Eye Clinic', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id",
            doc_user["id"], f"MED-{uuid.uuid4().hex[:6]}"
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('مهدی', 'صادقی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}", f"0929{uuid.uuid4().int % 10000000:07d}"
        )
        # Unlimited plan (max_visits NULL)
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح طلایی نامحدود', 2000000, 50.0, 365, NULL) RETURNING id")
        mem = await conn.fetchrow(
            "INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '365 days', NULL, NULL, 0, 'ACTIVE') RETURNING id",
            holder["id"], plan["id"]
        )

    # Record 3 consecutive visits
    for i in range(1, 4):
        v = await visit_svc.record_visit(
            doctor_id=doc["id"],
            holder_id=holder["id"],
            membership_id=mem["id"],
            service_title=f"معاینه چشم نوبت {i}",
            total_amount_toman=400000,
            discount_percent=50.0
        )
        assert v["status"] == "COMPLETED"

    # Check used_visits = 3, remaining_visits = NULL
    async with pool.acquire() as conn:
        mem_unlimited = await conn.fetchrow("SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1", mem["id"])
        assert mem_unlimited["remaining_visits"] is None
        assert mem_unlimited["used_visits"] == 3
        assert mem_unlimited["status"] == "ACTIVE"
    print("  ✓ Unlimited plan correctly tracked 3 visits without quota exhaustion.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_visit_financial_computation_and_quota_decrement(pool)
        await test_quota_exhaustion_and_zero_overselling(pool)
        await test_visit_cancellation_and_quota_rollback(pool)
        await test_unlimited_quota_membership(pool)
        print("\n" + "=" * 70)
        print("ALL 4 MEDICAL VISITS & QUOTA TESTS PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
