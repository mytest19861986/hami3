"""
Automated Verification Suite for Medical Visits & Quota Invariants (VISIT-001..013, AC-07)
Baseline: BL-HAMICARD-PRD-V1 | Updated for HC-T18 service-boundary RBAC & actor binding
Tests:
1. Accurate financial calculation (Decimal exact) & atomic membership quota decrement.
2. Quota exhaustion transitions status to EXHAUSTED and blocks subsequent visits (Zero Overselling).
3. Visit cancellation strictly authorized (`ADMIN`/`visits:cancel`) and atomically restores quota.
4. Unlimited quota memberships (`max_visits IS NULL`).
"""

import asyncio
import os
import pathlib
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import asyncpg  # noqa: E402

from src.core.policy import PolicyNotApprovedError, set_policy_approval  # noqa: E402
from src.visits.service import (  # noqa: E402
    MembershipInactiveError,
    QuotaExhaustedError,
    VisitAuthorizationError,
    VisitService,
)

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t18",
)


async def _create_role_user(conn: asyncpg.Connection, mobile: str, role: str) -> uuid.UUID:
    uid = await conn.fetchval(
        "INSERT INTO users (mobile, roles) VALUES ($1, $2) RETURNING id",
        mobile,
        [role],
    )
    await conn.execute(
        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        uid,
        role,
    )
    return uid


async def test_visit_financial_computation_and_quota_decrement(pool: asyncpg.Pool):
    print("\n[VISIT TEST 1/4] Testing Visit Financial Computation & Atomic Quota Decrement...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        doc_user_id = await _create_role_user(
            conn, f"0921{uuid.uuid4().int % 10000000:07d}", "DOCTOR"
        )
        doc = await conn.fetchrow(
            """
            INSERT INTO doctors (
                user_id, medical_council_code, specialty, clinic_name,
                province_id, city_id, clinic_address, clinic_phone, verification_status, is_public_listed
            ) VALUES ($1, $2, 'General', 'Center Clinic', 1, 1, 'Address', '0211111', 'APPROVED', TRUE)
            RETURNING id
            """,
            doc_user_id,
            f"MED-{uuid.uuid4().hex[:6]}",
        )
        holder = await conn.fetchrow(
            """
            INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
            VALUES ('علی', 'محمدی', $1, $2)
            RETURNING id
            """,
            f"{uuid.uuid4().int % 1000000000:010d}",
            f"0922{uuid.uuid4().int % 10000000:07d}",
        )
        plan = await conn.fetchrow(
            """
            INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits)
            VALUES ('طرح آزمایشی', 200000, 30.0, 30, 2)
            RETURNING id
            """
        )
        mem = await conn.fetchrow(
            """
            INSERT INTO memberships (
                holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status
            ) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 2, 2, 0, 'ACTIVE')
            RETURNING id
            """,
            holder["id"],
            plan["id"],
        )

    # Service-layer fails closed if actor_user_id is omitted
    missing_actor_blocked = False
    try:
        await visit_svc.record_visit(
            doctor_id=doc["id"],
            holder_id=holder["id"],
            membership_id=mem["id"],
            service_title="ویزیت بدون احراز هویت",
            total_amount_toman=100000,
            discount_percent=29.0,
        )
    except VisitAuthorizationError:
        missing_actor_blocked = True
    assert missing_actor_blocked, "record_visit must fail closed without actor_user_id"

    v1 = await visit_svc.record_visit(
        actor_user_id=doc_user_id,
        doctor_id=doc["id"],
        holder_id=holder["id"],
        membership_id=mem["id"],
        service_title="ویزیت عمومی و معاینه",
        total_amount_toman=1000000,
        discount_percent=30.0,
        private_notes="نسخه تجویز شد",
    )

    assert v1["id"] is not None
    assert v1["total_amount_toman"] == 1000000
    assert v1["discount_amount_toman"] == 300000
    assert v1["patient_paid_amount_toman"] == 700000
    assert v1["status"] == "COMPLETED"

    async with pool.acquire() as conn:
        mem_after = await conn.fetchrow(
            "SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1",
            mem["id"],
        )
        assert mem_after["remaining_visits"] == 1
        assert mem_after["used_visits"] == 1
        assert mem_after["status"] == "ACTIVE"
    print("  ✓ Financial calc & quota decrement PASS.")


async def test_quota_exhaustion_and_zero_overselling(pool: asyncpg.Pool):
    print("\n[VISIT TEST 2/4] Testing Quota Exhaustion & AC-07 Zero Overselling...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        doc_user_id = await _create_role_user(
            conn, f"0923{uuid.uuid4().int % 10000000:07d}", "DOCTOR"
        )
        doc = await conn.fetchrow(
            "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Cardio', 'Cardio Clinic', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id",
            doc_user_id,
            f"MED-{uuid.uuid4().hex[:6]}",
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('رضا', 'نادری', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}",
            f"0924{uuid.uuid4().int % 10000000:07d}",
        )
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح ۱ ویزیت', 100000, 20.0, 30, 1) RETURNING id"
        )
        mem = await conn.fetchrow(
            "INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 1, 1, 0, 'ACTIVE') RETURNING id",
            holder["id"],
            plan["id"],
        )

    v1 = await visit_svc.record_visit(
        actor_user_id=doc_user_id,
        doctor_id=doc["id"],
        holder_id=holder["id"],
        membership_id=mem["id"],
        service_title="نوار قلب",
        total_amount_toman=500000,
        discount_percent=20.0,
    )
    assert v1["status"] == "COMPLETED"

    async with pool.acquire() as conn:
        mem_ex = await conn.fetchrow(
            "SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1",
            mem["id"],
        )
        assert mem_ex["remaining_visits"] == 0
        assert mem_ex["used_visits"] == 1
        assert mem_ex["status"] == "EXHAUSTED"

    second_blocked = False
    try:
        await visit_svc.record_visit(
            actor_user_id=doc_user_id,
            doctor_id=doc["id"],
            holder_id=holder["id"],
            membership_id=mem["id"],
            service_title="معاینه دوم",
            total_amount_toman=500000,
            discount_percent=20.0,
        )
    except (QuotaExhaustedError, MembershipInactiveError):
        second_blocked = True
    assert second_blocked, "Over-quota visit was allowed!"
    print("  ✓ Zero Overselling PASS.")


async def test_visit_cancellation_and_quota_rollback(pool: asyncpg.Pool):
    print("\n[VISIT TEST 3/4] Testing Visit Cancellation & Quota Rollback...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        admin_user_id = await _create_role_user(
            conn, f"0925{uuid.uuid4().int % 10000000:07d}", "ADMIN"
        )
        doc_user_id = await _create_role_user(
            conn, f"0926{uuid.uuid4().int % 10000000:07d}", "DOCTOR"
        )
        doc = await conn.fetchrow(
            "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Dentist', 'Smile', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id",
            doc_user_id,
            f"MED-{uuid.uuid4().hex[:6]}",
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('سارا', 'کرمی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}",
            f"0927{uuid.uuid4().int % 10000000:07d}",
        )
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح دندان', 500000, 25.0, 30, 1) RETURNING id"
        )
        mem = await conn.fetchrow(
            "INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 1, 1, 0, 'ACTIVE') RETURNING id",
            holder["id"],
            plan["id"],
        )

    v = await visit_svc.record_visit(
        actor_user_id=doc_user_id,
        doctor_id=doc["id"],
        holder_id=holder["id"],
        membership_id=mem["id"],
        service_title="جرم‌گیری دندان",
        total_amount_toman=800000,
        discount_percent=25.0,
    )

    cancelled = await visit_svc.cancel_visit(
        visit_id=v["id"],
        canceller_user_id=admin_user_id,
        reason="اشتباه در ثبت خدمات توسط مطب",
    )
    assert cancelled["status"] == "CANCELLED"
    assert cancelled["cancellation_reason"] == "اشتباه در ثبت خدمات توسط مطب"

    async with pool.acquire() as conn:
        mem_restored = await conn.fetchrow(
            "SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1",
            mem["id"],
        )
        assert mem_restored["remaining_visits"] == 1
        assert mem_restored["used_visits"] == 0
        assert mem_restored["status"] == "ACTIVE"
    print("  ✓ Cancellation & Quota Rollback PASS.")


async def test_unlimited_quota_membership(pool: asyncpg.Pool):
    print("\n[VISIT TEST 4/4] Testing Unlimited Quota Memberships...")
    visit_svc = VisitService(pool)

    async with pool.acquire() as conn:
        doc_user_id = await _create_role_user(
            conn, f"0928{uuid.uuid4().int % 10000000:07d}", "DOCTOR"
        )
        doc = await conn.fetchrow(
            "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Optometry', 'Eye Clinic', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id",
            doc_user_id,
            f"MED-{uuid.uuid4().hex[:6]}",
        )
        holder = await conn.fetchrow(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('مهدی', 'صادقی', $1, $2) RETURNING id",
            f"{uuid.uuid4().int % 1000000000:010d}",
            f"0929{uuid.uuid4().int % 10000000:07d}",
        )
        plan = await conn.fetchrow(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits) VALUES ('طرح طلایی نامحدود', 2000000, 50.0, 365, NULL) RETURNING id"
        )
        mem = await conn.fetchrow(
            "INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '365 days', NULL, NULL, 0, 'ACTIVE') RETURNING id",
            holder["id"],
            plan["id"],
        )

    for i in range(1, 4):
        v = await visit_svc.record_visit(
            actor_user_id=doc_user_id,
            doctor_id=doc["id"],
            holder_id=holder["id"],
            membership_id=mem["id"],
            service_title=f"معاینه چشم نوبت {i}",
            total_amount_toman=400000,
            discount_percent=50.0,
        )
        assert v["status"] == "COMPLETED"

    async with pool.acquire() as conn:
        mem_unlimited = await conn.fetchrow(
            "SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1",
            mem["id"],
        )
        assert mem_unlimited["remaining_visits"] is None
        assert mem_unlimited["used_visits"] == 3
        assert mem_unlimited["status"] == "ACTIVE"
    print("  ✓ Unlimited quota tracked PASS.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        visit_svc = VisitService(pool)
        async with pool.acquire() as conn:
            doc_uid = await _create_role_user(
                conn, f"0920{uuid.uuid4().int % 10000000:07d}", "DOCTOR"
            )
            doc_id = await conn.fetchval(
                "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'General', 'Gate', 1, 1, 'A', '1', 'APPROVED') RETURNING id",
                doc_uid,
                f"MED-{uuid.uuid4().hex[:6]}",
            )

        blocked_visit = False
        try:
            await visit_svc.record_visit(
                actor_user_id=doc_uid,
                doctor_id=doc_id,
                holder_id=uuid.uuid4(),
                membership_id=uuid.uuid4(),
                service_title="ویزیت آزمایشی",
                total_amount_toman=100000,
                discount_percent=10.0,
            )
        except PolicyNotApprovedError:
            blocked_visit = True
        assert blocked_visit, "record_visit must fail closed while OPEN-18/OPEN-16 are PROPOSED"

        async with pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "APPROVED")
            await set_policy_approval(conn, "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY", "APPROVED")
            await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

        await test_visit_financial_computation_and_quota_decrement(pool)
        await test_quota_exhaustion_and_zero_overselling(pool)
        await test_visit_cancellation_and_quota_rollback(pool)
        await test_unlimited_quota_membership(pool)
        print("\nALL 4 MEDICAL VISITS & QUOTA TESTS PASSED!")
    finally:
        async with pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "PROPOSED")
            await set_policy_approval(conn, "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY", "PROPOSED")
            await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "PROPOSED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "PROPOSED")
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
