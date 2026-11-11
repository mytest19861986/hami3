"""
Security, Privacy & Concurrency Verification Suite for HC-T18 (F-08, F-09, F-10 HIGH, T18-AC1..AC5)
Baseline: BL-HAMICARD-PRD-V1 | VISIT-001..013, RBAC-001..009, AC-07, AC-08
Target DB: Isolated `hamicard_t18` + Redis DB 4
"""

import asyncio
import json
import os
import sys
import uuid

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
from src.core.policy import set_policy_approval  # noqa: E402

DEFAULT_POLICIES = {
    "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE": {
        "precedence": "CUSTOM_FIRST",
        "description": "در صورت وجود تخفیف اختصاصی پزشک، آن اعمال میشود؛ در غیر این صورت درصد طرح",
    },
    "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY": {"restore_quota": True, "refund_requires_reason": True},
    "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT": {"store_diagnosis": False, "store_full_emr": False, "allow_private_notes": True},
    "OPEN_18_CURRENCY_AND_ROUNDING": {"currency_stored": "TOMAN", "currency_display": "TOMAN", "rounding_mode": "FLOOR"},
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
    sess = await SessionService(pool).create_session(user_id=uid, device_info="t18-test", ip_address="127.0.0.1")
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _create_doctor_row(conn: asyncpg.Connection, user_id: uuid.UUID, status_val: str = "APPROVED") -> uuid.UUID:
    return await conn.fetchval(
        """
        INSERT INTO doctors (
            user_id, medical_council_code, specialty, clinic_name,
            province_id, city_id, clinic_address, clinic_phone, verification_status, is_public_listed
        ) VALUES ($1, $2, 'Cardiology', 'T18 Clinic', 1, 1, 'Tehran', '0214444', $3, TRUE)
        RETURNING id;
        """,
        user_id,
        f"T18MED-{uuid.uuid4().hex[:6]}",
        status_val,
    )


async def _create_patient_membership(pool: asyncpg.Pool, buyer_user_id: uuid.UUID, max_visits: int = 4):
    raw_nat = f"{uuid.uuid4().int % 10000000000:010d}"
    async with pool.acquire() as conn:
        holder_id = await conn.fetchval(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('بیمار', 'نمونه', $1, $2) RETURNING id;",
            raw_nat,
            f"0972{uuid.uuid4().int % 10000000:07d}",
        )
        plan_id = await conn.fetchval("SELECT id FROM discount_plans LIMIT 1;")
        order_id = await conn.fetchval(
            "INSERT INTO orders_payments (buyer_user_id, holder_id, plan_id, amount_toman, status, idempotency_key) VALUES ($1, $2, $3, 350000, 'SUCCESS', $4) RETURNING id;",
            buyer_user_id,
            holder_id,
            plan_id,
            f"T18-ORD-{uuid.uuid4().hex}",
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
    return holder_id, mem_id, raw_nat


@pytest.mark.asyncio
async def test_t18_ac1_ac2_doctor_impersonation_and_unapproved_status_blocked(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "APPROVED")
        await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    doc_a_uid, doc_a_hdrs = await _create_user_session(db_pool, "0930", ["DOCTOR"])
    doc_b_uid, doc_b_hdrs = await _create_user_session(db_pool, "0931", ["DOCTOR"])
    doc_susp_uid, doc_susp_hdrs = await _create_user_session(db_pool, "0932", ["DOCTOR"])
    buyer_uid, _ = await _create_user_session(db_pool, "0933", ["USER"])
    admin_uid, admin_hdrs = await _create_user_session(db_pool, "0934", ["ADMIN"])

    async with db_pool.acquire() as conn:
        doc_a_id = await _create_doctor_row(conn, doc_a_uid, "APPROVED")
        await conn.execute("UPDATE doctors SET custom_discount_percent = 29.00 WHERE id = $1;", doc_a_id)
        doc_b_id = await _create_doctor_row(conn, doc_b_uid, "APPROVED")
        doc_susp_id = await _create_doctor_row(conn, doc_susp_uid, "SUSPENDED")

    holder_id, mem_id, _ = await _create_patient_membership(db_pool, buyer_uid, max_visits=5)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Doctor A attempting to impersonate Doctor B -> 403 Forbidden (T18-AC1)
        r_imp = await client.post(
            "/api/v1/visits/record",
            json={
                "doctor_id": str(doc_b_id),
                "holder_id": str(holder_id),
                "membership_id": str(mem_id),
                "service_title": "جعل هویت پزشک",
                "total_amount_toman": 100000,
                "discount_percent": 29.0,
            },
            headers=doc_a_hdrs,
        )
        assert r_imp.status_code == 403, r_imp.text

        # 2. Suspended Doctor blocked from recording or listing visits -> 403 Forbidden (T18-AC2)
        r_susp_rec = await client.post(
            "/api/v1/visits/record",
            json={
                "doctor_id": str(doc_susp_id),
                "holder_id": str(holder_id),
                "membership_id": str(mem_id),
                "service_title": "ویزیت پزشک تعلیق شده",
                "total_amount_toman": 100000,
                "discount_percent": 20.0,
            },
            headers=doc_susp_hdrs,
        )
        assert r_susp_rec.status_code == 403, r_susp_rec.text

        r_susp_list = await client.get(f"/api/v1/visits/doctor/{doc_susp_id}", headers=doc_susp_hdrs)
        assert r_susp_list.status_code == 403, r_susp_list.text

        # 3. Admin override CANNOT target a suspended doctor -> 403
        r_adm_susp = await client.post(
            "/api/v1/visits/record",
            json={
                "doctor_id": str(doc_susp_id),
                "holder_id": str(holder_id),
                "membership_id": str(mem_id),
                "service_title": "تست تعلیق",
                "total_amount_toman": 100000,
                "discount_percent": 20.0,
            },
            headers=admin_hdrs,
        )
        assert r_adm_susp.status_code == 403

        # 4. Doctor A records own visit (auto-derived doctor_id + exact Decimal 29% of 100,000 = 29,000)
        r_ok = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(holder_id),
                "membership_id": str(mem_id),
                "service_title": "ویزیت قلب و عروق",
                "total_amount_toman": 100000,
                "discount_percent": 29.0,
                "private_notes": "یادداشت محرمانه بالینی بیمار",
            },
            headers=doc_a_hdrs,
        )
        assert r_ok.status_code == 200, r_ok.text
        v_data = r_ok.json()["visit"]
        assert v_data["doctor_id"] == str(doc_a_id)
        assert v_data["discount_amount_toman"] == 29000, "Decimal exact 29% failed!"
        assert v_data["patient_paid_amount_toman"] == 71000

        # 5. Legitimate Admin override targeting APPROVED Doctor A logs real actor_user_id & admin_override=True
        r_adm_ok = await client.post(
            "/api/v1/visits/record",
            json={
                "doctor_id": str(doc_a_id),
                "holder_id": str(holder_id),
                "membership_id": str(mem_id),
                "service_title": "ثبت با دسترسی مدیر",
                "total_amount_toman": 200000,
                "discount_percent": 10.0,
            },
            headers=admin_hdrs,
        )
        assert r_adm_ok.status_code == 200, r_adm_ok.text
        adm_visit_id = r_adm_ok.json()["visit"]["id"]

    async with db_pool.acquire() as conn:
        audit = await conn.fetchrow(
            "SELECT actor_user_id, actor_role, new_values FROM audit_logs WHERE entity_id = $1 AND action = 'VISIT_RECORDED';",
            adm_visit_id,
        )
        assert audit["actor_user_id"] == admin_uid
        assert audit["actor_role"] == "ADMIN"
        vals = json.loads(audit["new_values"]) if isinstance(audit["new_values"], str) else audit["new_values"]
        assert vals["admin_override"] is True


@pytest.mark.asyncio
async def test_t18_ac3_ac4_visit_idor_privacy_and_idempotent_cancellation(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "APPROVED")
        await set_policy_approval(conn, "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY", "APPROVED")
        await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    doc_a_uid, doc_a_hdrs = await _create_user_session(db_pool, "0935", ["DOCTOR"])
    doc_b_uid, doc_b_hdrs = await _create_user_session(db_pool, "0936", ["DOCTOR"])
    buyer_uid, buyer_hdrs = await _create_user_session(db_pool, "0937", ["USER"])
    other_uid, other_hdrs = await _create_user_session(db_pool, "0938", ["USER"])
    support_uid, support_hdrs = await _create_user_session(db_pool, "0939", ["SUPPORT"])
    admin_uid, admin_hdrs = await _create_user_session(db_pool, "0940", ["ADMIN"])

    async with db_pool.acquire() as conn:
        doc_a_id = await _create_doctor_row(conn, doc_a_uid, "APPROVED")
        await _create_doctor_row(conn, doc_b_uid, "APPROVED")

    holder_id, mem_id, raw_nat = await _create_patient_membership(db_pool, buyer_uid, max_visits=1)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_rec = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(holder_id),
                "membership_id": str(mem_id),
                "service_title": "اکوکاردیوگرافی",
                "total_amount_toman": 500000,
                "discount_percent": 30.0,
                "private_notes": "نکته محرمانه پزشک الف",
            },
            headers=doc_a_hdrs,
        )
        assert r_rec.status_code == 200
        visit_id = r_rec.json()["visit"]["id"]

        # IDOR: Doctor B, Unrelated User cannot read visit detail or list Doctor A visits (403)
        assert (await client.get(f"/api/v1/visits/{visit_id}", headers=doc_b_hdrs)).status_code == 403
        assert (await client.get(f"/api/v1/visits/{visit_id}", headers=other_hdrs)).status_code == 403
        assert (await client.get(f"/api/v1/visits/doctor/{doc_a_id}", headers=doc_b_hdrs)).status_code == 403
        assert (await client.get(f"/api/v1/visits/doctor/{doc_a_id}", headers=other_hdrs)).status_code == 403

        # Privacy Filtering:
        # - Buyer sees visit but NEVER sees doctor's private_notes and national code is masked
        r_buyer_get = await client.get(f"/api/v1/visits/{visit_id}", headers=buyer_hdrs)
        assert r_buyer_get.status_code == 200
        b_json = r_buyer_get.json()
        assert b_json["private_notes"] is None
        assert b_json["patient_national_code"].startswith("******")
        assert b_json["patient_national_code"] != raw_nat

        # - SUPPORT sees masked national code and private_notes stripped
        r_sup_get = await client.get(f"/api/v1/visits/{visit_id}", headers=support_hdrs)
        assert r_sup_get.status_code == 200
        assert r_sup_get.json()["private_notes"] is None
        assert r_sup_get.json()["patient_national_code"] != raw_nat

        r_sup_list = await client.get(f"/api/v1/visits/doctor/{doc_a_id}", headers=support_hdrs)
        assert r_sup_list.status_code == 200
        assert r_sup_list.json()[0]["private_notes"] is None
        assert r_sup_list.json()[0]["patient_national_code"] != raw_nat

        # - Owning Doctor A sees masked national code + own private_notes
        r_doc_get = await client.get(f"/api/v1/visits/{visit_id}", headers=doc_a_hdrs)
        assert r_doc_get.status_code == 200
        assert r_doc_get.json()["private_notes"] == "نکته محرمانه پزشک الف"
        assert r_doc_get.json()["patient_national_code"] != raw_nat

        # Cancellation authorization (T18-AC4): Doctors & Users CANNOT cancel -> 403
        assert (
            await client.post(
                f"/api/v1/visits/{visit_id}/cancel",
                json={"reason": "تلاش لغو توسط پزشک الف"},
                headers=doc_a_hdrs,
            )
        ).status_code == 403
        assert (
            await client.post(
                f"/api/v1/visits/{visit_id}/cancel",
                json={"reason": "تلاش لغو توسط پزشک ب"},
                headers=doc_b_hdrs,
            )
        ).status_code == 403

        # Concurrent double cancel by ADMIN -> EXACTLY ONE succeeds (200), second fails safely (409), quota restored AT MOST ONCE!
        cancel_resps = await asyncio.gather(
            client.post(f"/api/v1/visits/{visit_id}/cancel", json={"reason": "اصلاح خطای ثبت"}, headers=admin_hdrs),
            client.post(f"/api/v1/visits/{visit_id}/cancel", json={"reason": "اصلاح خطای ثبت"}, headers=admin_hdrs),
        )
        codes = [r.status_code for r in cancel_resps]
        assert codes.count(200) == 1, f"Expected exact 1 cancel 200, got {codes}"
        assert codes.count(409) == 1, f"Expected exact 1 cancel 409, got {codes}"

    async with db_pool.acquire() as conn:
        mem_row = await conn.fetchrow("SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1;", mem_id)
        assert mem_row["remaining_visits"] == 1
        assert mem_row["used_visits"] == 0
        assert mem_row["status"] == "ACTIVE"
        cancel_audit = await conn.fetchrow(
            "SELECT actor_user_id, actor_role FROM audit_logs WHERE entity_id = $1 AND action = 'VISIT_CANCELLED';",
            visit_id,
        )
        assert cancel_audit["actor_user_id"] == admin_uid
        assert cancel_audit["actor_role"] == "ADMIN"


@pytest.mark.asyncio
async def test_t18_ac5_parallel_quota_consumption_preserves_ac07_invariant(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "APPROVED")
        await set_policy_approval(conn, "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    doc_uid, doc_hdrs = await _create_user_session(db_pool, "0941", ["DOCTOR"])
    buyer_uid, _ = await _create_user_session(db_pool, "0942", ["USER"])
    async with db_pool.acquire() as conn:
        await _create_doctor_row(conn, doc_uid, "APPROVED")

    holder_id, mem_id, _ = await _create_patient_membership(db_pool, buyer_uid, max_visits=2)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        async def _fire_visit(idx: int):
            return await client.post(
                "/api/v1/visits/record",
                json={
                    "holder_id": str(holder_id),
                    "membership_id": str(mem_id),
                    "service_title": f"ویزیت همزمان {idx}",
                    "total_amount_toman": 100000,
                    "discount_percent": 10.0,
                },
                headers=doc_hdrs,
            )

        resps = await asyncio.gather(*[_fire_visit(i) for i in range(10)])

    codes = [r.status_code for r in resps]
    assert codes.count(200) == 2, f"Expected exact 2 HTTP 200, got {codes}"
    assert codes.count(409) + codes.count(400) == 8, f"Expected 8 rejections, got {codes}"

    async with db_pool.acquire() as conn:
        mem = await conn.fetchrow("SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1;", mem_id)
        visit_cnt = await conn.fetchval("SELECT count(*) FROM visits WHERE membership_id = $1;", mem_id)
        assert mem["remaining_visits"] == 0
        assert mem["used_visits"] == 2
        assert mem["status"] == "EXHAUSTED"
        assert visit_cnt == 2
