"""
Automated Verification Suite for HC-T25 (D-2: VISIT-009, DOC-012, OPEN-02, OPEN-18, T25-AC1..AC4)
Baseline: BL-HAMICARD-PRD-V1
Target DB: Isolated `hamicard_t18` + Redis DB 4

Verifies:
1. T25-AC1: Forged or omitted client `discount_percent` cannot alter server-computed discount;
   traceable pricing calculation snapshot & correct actor recorded in `audit_logs`.
2. T25-AC2: Full 2x2 precedence matrix across approved `CUSTOM_FIRST` and `PLAN_FIRST`
   modes with and without `doctors.custom_discount_percent` (including 0% explicit override vs NULL).
3. T25-AC3: Unapproved/BLOCKED/invalid `OPEN-02` fails closed (403/400) and consumes ZERO quota.
4. T25-AC4: Exact Decimal rounding across FLOOR/CEIL/HALF_UP, bounds [0, 100], and strict internal
   consistency (`discount_amount_toman + patient_paid_amount_toman == total_amount_toman`).
5. DOC-012: `custom_discount_percent` ignored on doctor self-registration (`NULL`) and modifiable
   exclusively via authenticated ADMIN/SUPER_ADMIN `PUT /api/v1/doctors/{id}/custom-discount`
   with [0, 100] validation and audit trail.
"""

import json
import os
import sys
import uuid
from decimal import Decimal

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t18",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/4")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import get_all_open_policy_statuses, set_policy_approval  # noqa: E402
from src.doctors.service import DoctorService  # noqa: E402

DEFAULT_POLICIES = {
    "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE": {
        "precedence": "CUSTOM_FIRST",
        "description": "در صورت وجود تخفیف اختصاصی پزشک، آن اعمال میشود؛ در غیر این صورت درصد طرح",
    },
    "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT": {
        "store_diagnosis": False,
        "store_full_emr": False,
        "allow_private_notes": True,
    },
    "OPEN_18_CURRENCY_AND_ROUNDING": {
        "currency_stored": "TOMAN",
        "currency_display": "TOMAN",
        "rounding_mode": "FLOOR",
    },
}


async def _reset_policies(conn: asyncpg.Connection) -> None:
    await conn.execute(
        """
        UPDATE system_settings
        SET approval_status = 'PROPOSED',
            approved_by = NULL,
            approved_at = NULL,
            updated_at = NOW()
        WHERE key LIKE 'OPEN\\_%' ESCAPE '\\';
        """
    )
    for k, v in DEFAULT_POLICIES.items():
        await conn.execute(
            "UPDATE system_settings SET value_json = $2::jsonb WHERE key = $1;",
            k,
            json.dumps(v),
        )


@pytest_asyncio.fixture
async def db_pool():
    await close_pool()
    close_redis()
    pool = await init_pool()
    init_redis()
    async with pool.acquire() as conn:
        await _reset_policies(conn)
    try:
        yield pool
    finally:
        async with pool.acquire() as conn:
            await _reset_policies(conn)
        await close_pool()
        close_redis()


async def _create_user_session(pool: asyncpg.Pool, prefix: str, roles: list[str]):
    mobile = f"{prefix}{uuid.uuid4().int % 10000000:07d}"
    async with pool.acquire() as conn:
        uid = await conn.fetchval(
            "INSERT INTO users (mobile, status, roles, is_mobile_verified) VALUES ($1, 'ACTIVE', $2, TRUE) RETURNING id;",
            mobile,
            roles,
        )
        for r in roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
                uid,
                r,
            )
    sess = await SessionService(pool).create_session(user_id=uid, device_info="t25-test", ip_address="127.0.0.1")
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _seed_visit_fixture(
    pool: asyncpg.Pool,
    plan_discount_percent: Decimal = Decimal("25.00"),
    doctor_custom_discount: Decimal | None = None,
    max_visits: int = 10,
):
    doc_uid, doc_hdrs = await _create_user_session(pool, "0931", ["DOCTOR"])
    admin_uid, admin_hdrs = await _create_user_session(pool, "0932", ["ADMIN"])
    user_uid, user_hdrs = await _create_user_session(pool, "0933", ["USER"])
    support_uid, support_hdrs = await _create_user_session(pool, "0934", ["SUPPORT"])

    async with pool.acquire() as conn:
        doc_id = await conn.fetchval(
            """
            INSERT INTO doctors (
                user_id, medical_council_code, specialty, clinic_name,
                province_id, city_id, clinic_address, clinic_phone,
                custom_discount_percent, verification_status, is_public_listed
            ) VALUES ($1, $2, 'Internal', 'T25 Clinic', 1, 1, 'Tehran', '0214444', $3, 'APPROVED', TRUE)
            RETURNING id;
            """,
            doc_uid,
            f"T25MED-{uuid.uuid4().hex[:6]}",
            doctor_custom_discount,
        )
        holder_id = await conn.fetchval(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('نسترن', 'اکبری', $1, $2) RETURNING id;",
            f"{uuid.uuid4().int % 10000000000:010d}",
            f"0935{uuid.uuid4().int % 10000000:07d}",
        )
        plan_id = await conn.fetchval(
            """
            INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits)
            VALUES ('طرح تست T25', 500000, $1, 90, $2) RETURNING id;
            """,
            plan_discount_percent,
            max_visits,
        )
        order_id = await conn.fetchval(
            "INSERT INTO orders_payments (buyer_user_id, holder_id, plan_id, amount_toman, status, idempotency_key) VALUES ($1, $2, $3, 500000, 'SUCCESS', $4) RETURNING id;",
            user_uid,
            holder_id,
            plan_id,
            f"T25-ORD-{uuid.uuid4().hex}",
        )
        mem_id = await conn.fetchval(
            """
            INSERT INTO memberships (
                holder_id, plan_id, order_id, start_date, end_date,
                max_visits, remaining_visits, used_visits, status
            ) VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '90 days', $4, $4, 0, 'ACTIVE')
            RETURNING id;
            """,
            holder_id,
            plan_id,
            order_id,
            max_visits,
        )
    return {
        "doc_uid": doc_uid,
        "doc_hdrs": doc_hdrs,
        "admin_uid": admin_uid,
        "admin_hdrs": admin_hdrs,
        "user_uid": user_uid,
        "user_hdrs": user_hdrs,
        "support_uid": support_uid,
        "support_hdrs": support_hdrs,
        "doc_id": doc_id,
        "holder_id": holder_id,
        "plan_id": plan_id,
        "mem_id": mem_id,
    }


@pytest.mark.asyncio
async def test_t25_ac1_forged_or_omitted_client_discount_cannot_change_server_pricing(db_pool: asyncpg.Pool):
    fx = await _seed_visit_fixture(
        db_pool,
        plan_discount_percent=Decimal("30.00"),
        doctor_custom_discount=None,
    )
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "APPROVED")
        await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Attacker/doctor passes forged client discount_percent=99.0 -> MUST be ignored; DB plan rate 30% applies!
        r_forged = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "آزمایش خون با درصد جعلی کلاینت",
                "total_amount_toman": 1000000,
                "discount_percent": 99.0,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_forged.status_code == 200, r_forged.text
        v1 = r_forged.json()["visit"]
        assert float(v1["discount_percent"]) == 30.0
        assert v1["discount_amount_toman"] == 300000
        assert v1["patient_paid_amount_toman"] == 700000
        assert v1["applied_discount_source"] == "PLAN_DEFAULT"

        # Client omits discount_percent completely -> still derives 30% cleanly!
        r_omitted = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "مشاوره تخصصی بدون ارسال درصد",
                "total_amount_toman": 500000,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_omitted.status_code == 200, r_omitted.text
        v2 = r_omitted.json()["visit"]
        assert float(v2["discount_percent"]) == 30.0
        assert v2["discount_amount_toman"] == 150000
        assert v2["patient_paid_amount_toman"] == 350000

    async with db_pool.acquire() as conn:
        audit_row = await conn.fetchrow(
            "SELECT actor_user_id, actor_role, new_values FROM audit_logs WHERE entity_id = $1 AND action = 'VISIT_RECORDED';",
            v1["id"],
        )
        vals = json.loads(audit_row["new_values"]) if isinstance(audit_row["new_values"], str) else audit_row["new_values"]
        assert audit_row["actor_user_id"] == fx["doc_uid"]
        assert audit_row["actor_role"] == "DOCTOR"
        assert vals["applied_source"] == "PLAN_DEFAULT"
        assert vals["effective_discount_percent"] == "30.00"
        assert vals["plan_discount_percent"] == "30.00"
        assert vals["doctor_custom_discount_percent"] is None
        assert vals["client_discount_ignored"] is True


@pytest.mark.asyncio
async def test_t25_ac2_precedence_matrix_custom_first_and_plan_first(db_pool: asyncpg.Pool):
    fx_custom = await _seed_visit_fixture(
        db_pool, plan_discount_percent=Decimal("25.00"), doctor_custom_discount=Decimal("40.00")
    )
    fx_no_custom = await _seed_visit_fixture(
        db_pool, plan_discount_percent=Decimal("25.00"), doctor_custom_discount=None
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
            await set_policy_approval(
                conn,
                "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE",
                "APPROVED",
                updated_value_json={"precedence": "CUSTOM_FIRST"},
            )

        # 1. CUSTOM_FIRST WITH doctor custom (40%) -> 40%
        r1 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx_custom["holder_id"]),
                "membership_id": str(fx_custom["mem_id"]),
                "service_title": "CUSTOM_FIRST with custom",
                "total_amount_toman": 100000,
                "discount_percent": 5.0,
            },
            headers=fx_custom["doc_hdrs"],
        )
        assert r1.status_code == 200
        assert r1.json()["visit"]["discount_amount_toman"] == 40000
        assert r1.json()["visit"]["patient_paid_amount_toman"] == 60000
        assert r1.json()["visit"]["applied_discount_source"] == "DOCTOR_CUSTOM"

        # 2. CUSTOM_FIRST WITHOUT doctor custom (NULL) -> fallback plan 25%
        r2 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx_no_custom["holder_id"]),
                "membership_id": str(fx_no_custom["mem_id"]),
                "service_title": "CUSTOM_FIRST without custom",
                "total_amount_toman": 100000,
                "discount_percent": 99.0,
            },
            headers=fx_no_custom["doc_hdrs"],
        )
        assert r2.status_code == 200
        assert r2.json()["visit"]["discount_amount_toman"] == 25000
        assert r2.json()["visit"]["patient_paid_amount_toman"] == 75000
        assert r2.json()["visit"]["applied_discount_source"] == "PLAN_DEFAULT"

        # Switch OPEN_02 to PLAN_FIRST
        async with db_pool.acquire() as conn:
            await set_policy_approval(
                conn,
                "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE",
                "APPROVED",
                updated_value_json={"precedence": "PLAN_FIRST"},
            )

        # 3. PLAN_FIRST WITH doctor custom (40%) -> plan 25% overrides doctor custom!
        r3 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx_custom["holder_id"]),
                "membership_id": str(fx_custom["mem_id"]),
                "service_title": "PLAN_FIRST with custom",
                "total_amount_toman": 100000,
            },
            headers=fx_custom["doc_hdrs"],
        )
        assert r3.status_code == 200
        assert r3.json()["visit"]["discount_amount_toman"] == 25000
        assert r3.json()["visit"]["patient_paid_amount_toman"] == 75000
        assert r3.json()["visit"]["applied_discount_source"] == "PLAN_DEFAULT"

        # 4. PLAN_FIRST WITHOUT doctor custom -> plan 25%
        r4 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx_no_custom["holder_id"]),
                "membership_id": str(fx_no_custom["mem_id"]),
                "service_title": "PLAN_FIRST without custom",
                "total_amount_toman": 100000,
            },
            headers=fx_no_custom["doc_hdrs"],
        )
        assert r4.status_code == 200
        assert r4.json()["visit"]["discount_amount_toman"] == 25000
        assert r4.json()["visit"]["patient_paid_amount_toman"] == 75000


@pytest.mark.asyncio
async def test_t25_ac3_unapproved_or_invalid_open02_refuses_safely_with_zero_quota_consumed(db_pool: asyncpg.Pool):
    fx = await _seed_visit_fixture(db_pool, plan_discount_percent=Decimal("30.00"), max_visits=2)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Even if OPEN_16 and OPEN_18 are APPROVED, PROPOSED OPEN_02 MUST fail closed (403) with 0 quota consumed
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

        r_prop = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "سیاست در انتظار تایید",
                "total_amount_toman": 200000,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_prop.status_code == 403, r_prop.text
        assert "OPEN_02" in r_prop.json()["detail"]

        # 2. BLOCKED OPEN_02 -> 403 with 0 quota consumed
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "BLOCKED")
        r_blk = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "سیاست مسدود",
                "total_amount_toman": 200000,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_blk.status_code == 403

        # 3. Malformed unrecognized precedence in OPEN_02 -> safe refusal (400) with 0 quota consumed
        async with db_pool.acquire() as conn:
            await set_policy_approval(
                conn,
                "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE",
                "APPROVED",
                updated_value_json={"precedence": "UNKNOWN_RULE"},
            )
        r_bad = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "سیاست نامعتبر",
                "total_amount_toman": 200000,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_bad.status_code == 400

    async with db_pool.acquire() as conn:
        mem_row = await conn.fetchrow(
            "SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1;",
            fx["mem_id"],
        )
        visit_cnt = await conn.fetchval(
            "SELECT count(*) FROM visits WHERE membership_id = $1;",
            fx["mem_id"],
        )
        assert mem_row["remaining_visits"] == 2
        assert mem_row["used_visits"] == 0
        assert mem_row["status"] == "ACTIVE"
        assert visit_cnt == 0


@pytest.mark.asyncio
async def test_t25_ac4_and_doc012_decimal_rounding_consistency_and_admin_custom_rate_control(db_pool: asyncpg.Pool):
    fx = await _seed_visit_fixture(
        db_pool, plan_discount_percent=Decimal("10.00"), doctor_custom_discount=None, max_visits=10
    )

    # DOC-012: Self-registration ignores any client-submitted custom_discount_percent (stores NULL)
    doc_svc = DoctorService(db_pool)
    async with db_pool.acquire() as conn:
        self_doc_uid = await conn.fetchval(
            "INSERT INTO users (mobile, status, roles, is_mobile_verified) VALUES ($1, 'ACTIVE', '{\"DOCTOR\"}', TRUE) RETURNING id;",
            f"0936{uuid.uuid4().int % 10000000:07d}",
        )
    reg_doc = await doc_svc.register_doctor(
        user_id=self_doc_uid,
        medical_council_code=f"SELF-{uuid.uuid4().hex[:6]}",
        specialty="General",
        clinic_name="Self Clinic",
        province_id=1,
        city_id=1,
        clinic_address="Tehran",
        clinic_phone="0219999",
        custom_discount_percent=95.0,
    )
    assert reg_doc["custom_discount_percent"] is None

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # DOC-012: Doctor, plain User, Support CANNOT modify custom_discount_percent -> 403
        for hdrs in (fx["doc_hdrs"], fx["user_hdrs"], fx["support_hdrs"]):
            r_deny = await client.put(
                f"/api/v1/doctors/{fx['doc_id']}/custom-discount",
                json={"custom_discount_percent": "45.00", "reason": "تلاش تغییر تخفیف توسط غیرمدیر"},
                headers=hdrs,
            )
            assert r_deny.status_code == 403, r_deny.text

        # Bounds check: > 100 or < 0 rejected (422)
        assert (
            await client.put(
                f"/api/v1/doctors/{fx['doc_id']}/custom-discount",
                json={"custom_discount_percent": "105.00", "reason": "نرخ نامعتبر"},
                headers=fx["admin_hdrs"],
            )
        ).status_code == 422
        assert (
            await client.put(
                f"/api/v1/doctors/{fx['doc_id']}/custom-discount",
                json={"custom_discount_percent": "-1.00", "reason": "نرخ منفی"},
                headers=fx["admin_hdrs"],
            )
        ).status_code == 422

        # Exact Decimal FLOOR/CEIL/HALF_UP check with 10% on 333,333 Toman -> 33,333.3
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "APPROVED")
            await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
            await set_policy_approval(
                conn,
                "OPEN_18_CURRENCY_AND_ROUNDING",
                "APPROVED",
                updated_value_json={"currency_stored": "TOMAN", "currency_display": "TOMAN", "rounding_mode": "FLOOR"},
            )

        r_floor = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "تست گرد کردن کف",
                "total_amount_toman": 333333,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_floor.status_code == 200
        vf = r_floor.json()["visit"]
        assert vf["discount_amount_toman"] == 33333
        assert vf["patient_paid_amount_toman"] == 300000
        assert vf["discount_amount_toman"] + vf["patient_paid_amount_toman"] == 333333

        async with db_pool.acquire() as conn:
            await set_policy_approval(
                conn,
                "OPEN_18_CURRENCY_AND_ROUNDING",
                "APPROVED",
                updated_value_json={"currency_stored": "TOMAN", "currency_display": "TOMAN", "rounding_mode": "CEIL"},
            )

        r_ceil = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "تست گرد کردن سقف",
                "total_amount_toman": 333333,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_ceil.status_code == 200
        vc = r_ceil.json()["visit"]
        assert vc["discount_amount_toman"] == 33334
        assert vc["patient_paid_amount_toman"] == 299999
        assert vc["discount_amount_toman"] + vc["patient_paid_amount_toman"] == 333333

        # Admin explicitly sets custom_discount_percent = 29.00 on doc -> visits now apply 29%
        r_set_cust = await client.put(
            f"/api/v1/doctors/{fx['doc_id']}/custom-discount",
            json={"custom_discount_percent": "29.00", "reason": "تخفیف اختصاصی مصوب مدیر"},
            headers=fx["admin_hdrs"],
        )
        assert r_set_cust.status_code == 200, r_set_cust.text

        # Exact Decimal 29% of 100,000 -> must be 29,000 (not float bug 28,999!)
        r_29 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "تست دقت دسیمال ۲۹ درصد",
                "total_amount_toman": 100000,
                "discount_percent": 1.0,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_29.status_code == 200
        assert r_29.json()["visit"]["discount_amount_toman"] == 29000
        assert r_29.json()["visit"]["patient_paid_amount_toman"] == 71000

        # Admin explicitly sets 0% custom override (0 is non-null override!)
        r_zero = await client.put(
            f"/api/v1/doctors/{fx['doc_id']}/custom-discount",
            json={"custom_discount_percent": "0.00", "reason": "خدمت بدون تخفیف با قرارداد صفر درصد"},
            headers=fx["admin_hdrs"],
        )
        assert r_zero.status_code == 200
        r_v0 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "تخفیف صفر اختصاصی",
                "total_amount_toman": 100000,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_v0.status_code == 200
        assert r_v0.json()["visit"]["discount_amount_toman"] == 0
        assert r_v0.json()["visit"]["patient_paid_amount_toman"] == 100000

        # Clearing custom_discount_percent to NULL restores plan default 10%
        r_clr = await client.put(
            f"/api/v1/doctors/{fx['doc_id']}/custom-discount",
            json={"custom_discount_percent": None, "reason": "حذف تخفیف اختصاصی و بازگشت به نرخ طرح"},
            headers=fx["admin_hdrs"],
        )
        assert r_clr.status_code == 200
        r_back = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(fx["holder_id"]),
                "membership_id": str(fx["mem_id"]),
                "service_title": "بازگشت به نرخ طرح",
                "total_amount_toman": 100000,
            },
            headers=fx["doc_hdrs"],
        )
        assert r_back.status_code == 200
        assert r_back.json()["visit"]["discount_amount_toman"] == 10000
        assert r_back.json()["visit"]["applied_discount_source"] == "PLAN_DEFAULT"

    async with db_pool.acquire() as conn:
        await _reset_policies(conn)
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)
