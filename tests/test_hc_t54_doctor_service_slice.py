"""
Automated Verification Suite for HC-T54: Doctor Service Vertical Slice
Directive: HC-COMMANDER-017 (OPTION_A_APPROVED_WITH_SECURITY_GATES)
Target DB: Isolated `hamicard_t54_isolated` + Redis DB 15

Verifies:
1. Scope 1: Display doctor's authorized services / active contracts (`service_contracts`)
2. Scope 2: Display required patient eligibility information for registration within actual authorization scope
   (masked national code, remaining visits, plan details)
3. Scope 3: Register a test discounted medical service (`POST /visits/record`) with atomic quota decrement
4. Scope 4: View registration status in doctor's portal/visit list (`GET /visits/my-visits`)
5. Scope 5: Server-side doctor identity verification (`DOCTOR` role + `verification_status == 'APPROVED'`)
6. Scope 6: Ownership and scope control (prevent IDOR: doctor cannot access other doctors' visits/records)
7. Scope 7: Negative access tests (unauthorized, non-doctor, and pending/suspended doctor rejected with 403)
8. Scope 8: Duplicate registration prevention (Idempotency / rapid replay defense -> 409 Conflict)
9. Scope 9: 100% synthetic mock test data
10. Fail-Closed behavior under unapproved `OPEN-02` policy
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

os.environ["DATABASE_URL"] = (
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t54_isolated"
)
os.environ["REDIS_URL"] = "redis://localhost:6379/15"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import set_policy_approval  # noqa: E402

TEST_POLICIES = {
    "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE": {
        "precedence": "CUSTOM_FIRST",
        "description": "در صورت وجود تخفیف اختصاصی پزشک، آن اعمال میشود؛ در غیر این صورت درصد طرح",
    },
    "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY": {
        "restore_quota": True,
        "refund_requires_reason": True,
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


async def _approve_test_policies(conn: asyncpg.Connection, admin_id: uuid.UUID) -> None:
    for key, val in TEST_POLICIES.items():
        await conn.execute(
            """
            INSERT INTO system_settings (key, value_json, description, approval_status, approved_by, approved_at, updated_at)
            VALUES ($1, $2::jsonb, 'Test policy', 'APPROVED', $3, NOW(), NOW())
            ON CONFLICT (key) DO UPDATE
            SET value_json = EXCLUDED.value_json,
                approval_status = 'APPROVED',
                approved_by = EXCLUDED.approved_by,
                approved_at = NOW(),
                updated_at = NOW();
            """,
            key,
            json.dumps(val),
            admin_id,
        )


async def _reset_test_policies(conn: asyncpg.Connection) -> None:
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


@pytest_asyncio.fixture
async def db_pool():
    await close_pool()
    close_redis()
    pool = await init_pool()
    init_redis()
    yield pool
    await close_pool()
    close_redis()


async def _create_test_user_session(pool: asyncpg.Pool, prefix: str, roles: list[str]):
    """Creates a synthetic user, assigns authoritative roles, and returns an active bearer header."""
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
    sess = await SessionService(pool).create_session(
        user_id=uid, device_info="t54-test", ip_address="127.0.0.1"
    )
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _create_test_doctor(
    conn: asyncpg.Connection,
    user_id: uuid.UUID,
    status_val: str = "APPROVED",
    clinic_name: str = "کلینیک تخصصی حامی",
    custom_discount_percent: Decimal | None = None,
) -> uuid.UUID:
    mc_code = f"MC-{uuid.uuid4().hex[:8].upper()}"
    return await conn.fetchval(
        """
        INSERT INTO doctors (
            user_id, medical_council_code, specialty, clinic_name,
            province_id, city_id, clinic_address, clinic_phone,
            custom_discount_percent, verification_status, is_public_listed
        ) VALUES ($1, $2, 'دندانپزشکی', $3, 1, 1, 'تهران، خیابان ولیعصر', '02188889999', $4, $5, TRUE)
        RETURNING id;
        """,
        user_id,
        mc_code,
        clinic_name,
        custom_discount_percent,
        status_val,
    )


async def _create_test_service_contract(
    conn: asyncpg.Connection,
    doctor_id: uuid.UUID,
    admin_id: uuid.UUID,
    discount_percent: Decimal = Decimal("30.00"),
    status_val: str = "ACTIVE",
) -> uuid.UUID:
    contract_num = f"CTR-1405-{uuid.uuid4().hex[:6].upper()}"
    today = date.today()
    return await conn.fetchval(
        """
        INSERT INTO service_contracts (
            doctor_id, contract_number, start_date, end_date, agreed_discount_percent, status, approved_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id;
        """,
        doctor_id,
        contract_num,
        today - timedelta(days=30),
        today + timedelta(days=335),
        discount_percent,
        status_val,
        admin_id,
    )


async def _create_test_patient_membership(
    conn: asyncpg.Connection,
    max_visits: int | None = 5,
    remaining_visits: int | None = 5,
    membership_status: str = "ACTIVE",
    is_expired: bool = False,
    plan_discount_percent: Decimal = Decimal("25.00"),
):
    """Creates synthetic patient holder, discount plan, and active membership."""
    raw_nat = f"{uuid.uuid4().int % 10000000000:010d}"
    holder_id = await conn.fetchval(
        """
        INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
        VALUES ('سارا', 'احمدی', $1, $2) RETURNING id;
        """,
        raw_nat,
        f"0912{uuid.uuid4().int % 10000000:07d}",
    )

    plan_id = await conn.fetchval(
        """
        INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, max_visits, is_active)
        VALUES ('طرح سلامت طلایی', 1200000, $1, 365, $2, TRUE)
        RETURNING id;
        """,
        plan_discount_percent,
        max_visits,
    )

    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=10)
    end_date = now - timedelta(days=1) if is_expired else now + timedelta(days=355)

    mem_id = await conn.fetchval(
        """
        INSERT INTO memberships (
            holder_id, plan_id, origin_type, start_date, end_date,
            max_visits, used_visits, remaining_visits, status
        ) VALUES ($1, $2, 'DIRECT_PURCHASE', $3, $4, $5, 0, $6, $7)
        RETURNING id;
        """,
        holder_id,
        plan_id,
        start_date,
        end_date,
        max_visits,
        remaining_visits,
        membership_status,
    )

    return {
        "holder_id": holder_id,
        "membership_id": mem_id,
        "plan_id": plan_id,
        "raw_national_code": raw_nat,
    }


# ==============================================================================
# TEST CASES: HC-T54 DOCTOR SERVICE VERTICAL SLICE
# ==============================================================================


@pytest.mark.asyncio
async def test_doctor_portal_view_active_contracts(db_pool):
    """
    Scope 1 & 5: Verified approved doctor can view their portal summary and active contracts.
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        doc_uid, doc_auth = await _create_test_user_session(db_pool, "0911", ["DOCTOR"])
        doc_id = await _create_test_doctor(conn, doc_uid, status_val="APPROVED", clinic_name="مطب دکتر بهرامی")
        ctr_id = await _create_test_service_contract(conn, doc_id, admin_uid, discount_percent=Decimal("35.00"))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # 1. Fetch portal summary
        portal_res = await client.get("/api/v1/doctors/me/portal", headers=doc_auth)
        assert portal_res.status_code == 200, portal_res.text
        data = portal_res.json()
        assert data["success"] is True
        portal = data["portal"]
        assert portal["doctor"]["clinic_name"] == "مطب دکتر بهرامی"
        assert portal["doctor"]["verification_status"] == "APPROVED"
        assert len(portal["contracts"]) >= 1
        assert portal["contracts"][0]["agreed_discount_percent"] == 35.0

        # 2. Fetch contracts directly
        ctr_res = await client.get("/api/v1/doctors/me/contracts", headers=doc_auth)
        assert ctr_res.status_code == 200
        contracts_data = ctr_res.json()["contracts"]
        assert len(contracts_data) >= 1
        assert str(contracts_data[0]["id"]) == str(ctr_id)


@pytest.mark.asyncio
async def test_patient_eligibility_inquiry_active_and_eligible(db_pool):
    """
    Scope 2: Doctor inquiries patient eligibility by national code.
    Verifies masked national code, accurate remaining quota, plan info, and effective discount.
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        doc_uid, doc_auth = await _create_test_user_session(db_pool, "0912", ["DOCTOR"])
        doc_id = await _create_test_doctor(
            conn, doc_uid, status_val="APPROVED", custom_discount_percent=Decimal("40.00")
        )

        patient = await _create_test_patient_membership(
            conn, max_visits=6, remaining_visits=6, plan_discount_percent=Decimal("20.00")
        )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Inquire by national code
        res = await client.post(
            "/api/v1/visits/inquire",
            json={"national_code": patient["raw_national_code"]},
            headers=doc_auth,
        )
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["success"] is True
        el = data["eligibility"]

        # Scope 2 verifications:
        assert el["is_eligible"] is True
        assert el["ineligibility_reason"] is None
        assert el["remaining_visits"] == 6
        assert el["max_visits"] == 6
        assert el["plan_title"] == "طرح سلامت طلایی"
        # Masked national code verification (e.g., 001****789)
        assert el["patient_national_code"] != patient["raw_national_code"]
        assert "*" in el["patient_national_code"]
        # Effective discount: doctor custom discount 40% takes precedence under CUSTOM_FIRST
        assert el["effective_discount_percent"] == 40.0
        assert el["discount_source"] == "DOCTOR_CUSTOM"


@pytest.mark.asyncio
async def test_patient_eligibility_inquiry_exhausted_or_expired(db_pool):
    """
    Scope 2: Inquiry for exhausted quota or expired membership returns is_eligible=False.
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        doc_uid, doc_auth = await _create_test_user_session(db_pool, "0913", ["DOCTOR"])
        await _create_test_doctor(conn, doc_uid, status_val="APPROVED")

        exhausted_pat = await _create_test_patient_membership(
            conn, max_visits=3, remaining_visits=0, membership_status="EXHAUSTED"
        )
        expired_pat = await _create_test_patient_membership(
            conn, max_visits=3, remaining_visits=2, membership_status="ACTIVE", is_expired=True
        )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # 1. Exhausted inquiry
        res1 = await client.post(
            "/api/v1/visits/inquire",
            json={"membership_id": str(exhausted_pat["membership_id"])},
            headers=doc_auth,
        )
        assert res1.status_code == 200
        el1 = res1.json()["eligibility"]
        assert el1["is_eligible"] is False
        assert "EXHAUSTED" in el1["ineligibility_reason"]

        # 2. Expired inquiry
        res2 = await client.post(
            "/api/v1/visits/inquire",
            json={"membership_id": str(expired_pat["membership_id"])},
            headers=doc_auth,
        )
        assert res2.status_code == 200
        el2 = res2.json()["eligibility"]
        assert el2["is_eligible"] is False
        assert el2["ineligibility_reason"] == "MEMBERSHIP_EXPIRED"


@pytest.mark.asyncio
async def test_record_visit_success_decrements_quota(db_pool):
    """
    Scope 3 & 4: Register medical service, verify server-derived discount, atomic quota decrement,
    and appearance in doctor's recent visit history.
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        doc_uid, doc_auth = await _create_test_user_session(db_pool, "0914", ["DOCTOR"])
        doc_id = await _create_test_doctor(
            conn, doc_uid, status_val="APPROVED", custom_discount_percent=Decimal("30.00")
        )

        patient = await _create_test_patient_membership(
            conn, max_visits=4, remaining_visits=4, plan_discount_percent=Decimal("20.00")
        )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        record_res = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(patient["holder_id"]),
                "membership_id": str(patient["membership_id"]),
                "service_title": "ویزیت تخصصی دندانپزشکی و جرم‌گیری",
                "total_amount_toman": 1000000,
                "private_notes": "معاینه کامل و جرم‌گیری فک بالا",
            },
            headers=doc_auth,
        )
        assert record_res.status_code == 200, record_res.text
        visit_data = record_res.json()["visit"]

        # 30% discount on 1,000,000 = 300,000 discount, patient pays 700,000
        assert visit_data["discount_amount_toman"] == 300000
        assert visit_data["patient_paid_amount_toman"] == 700000
        assert visit_data["status"] == "COMPLETED"
        assert visit_data["doctor_id"] == str(doc_id)

        # Verify DB quota decremented atomically from 4 to 3
        async with db_pool.acquire() as conn:
            mem_row = await conn.fetchrow(
                "SELECT remaining_visits, used_visits, status FROM memberships WHERE id = $1",
                patient["membership_id"],
            )
            assert mem_row["remaining_visits"] == 3
            assert mem_row["used_visits"] == 1
            assert mem_row["status"] == "ACTIVE"

        # Scope 4: View registration status in doctor's portal and my-visits list
        my_visits_res = await client.get("/api/v1/visits/my-visits", headers=doc_auth)
        assert my_visits_res.status_code == 200
        visits_list = my_visits_res.json()
        assert len(visits_list) >= 1
        assert visits_list[0]["service_title"] == "ویزیت تخصصی دندانپزشکی و جرم‌گیری"
        # Masked national code in doctor listing
        assert "*" in visits_list[0]["patient_national_code"]

        # Also appears in portal dashboard metrics
        portal_res = await client.get("/api/v1/doctors/me/portal", headers=doc_auth)
        assert portal_res.status_code == 200
        metrics = portal_res.json()["portal"]["metrics"]
        assert metrics["total_visits_count"] >= 1
        assert metrics["total_discount_toman"] >= 300000


@pytest.mark.asyncio
async def test_duplicate_visit_rapid_replay_defense(db_pool):
    """
    Scope 8: Duplicate submission prevention (Rapid Replay within 30s -> 409 Conflict).
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        doc_uid, doc_auth = await _create_test_user_session(db_pool, "0915", ["DOCTOR"])
        await _create_test_doctor(conn, doc_uid, status_val="APPROVED")

        patient = await _create_test_patient_membership(conn, max_visits=5, remaining_visits=5)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        payload = {
            "holder_id": str(patient["holder_id"]),
            "membership_id": str(patient["membership_id"]),
            "service_title": "ویزیت عمومی و کنترل فشار خون",
            "total_amount_toman": 400000,
        }

        # First submission: success
        res1 = await client.post("/api/v1/visits/record", json=payload, headers=doc_auth)
        assert res1.status_code == 200

        # Rapid duplicate submission: 409 Conflict
        res2 = await client.post("/api/v1/visits/record", json=payload, headers=doc_auth)
        assert res2.status_code == 409
        assert "Duplicate" in res2.json()["detail"] or "Rapid replay" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_idempotency_key_duplicate_defense(db_pool):
    """
    Scope 8: Duplicate submission prevention via Idempotency-Key header -> 409 Conflict.
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        doc_uid, doc_auth = await _create_test_user_session(db_pool, "0916", ["DOCTOR"])
        await _create_test_doctor(conn, doc_uid, status_val="APPROVED")

        patient = await _create_test_patient_membership(conn, max_visits=5, remaining_visits=5)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        idem_key = f"idem-{uuid.uuid4()}"
        headers_with_idem = {**doc_auth, "Idempotency-Key": idem_key}

        # First attempt
        res1 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(patient["holder_id"]),
                "membership_id": str(patient["membership_id"]),
                "service_title": "مشاوره تغذیه",
                "total_amount_toman": 300000,
            },
            headers=headers_with_idem,
        )
        assert res1.status_code == 200

        # Second attempt with same key but different title: rejected by idempotency key check
        res2 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(patient["holder_id"]),
                "membership_id": str(patient["membership_id"]),
                "service_title": "مشاوره تغذیه تکمیلی",
                "total_amount_toman": 350000,
            },
            headers=headers_with_idem,
        )
        assert res2.status_code == 409
        assert idem_key in res2.json()["detail"] or "Duplicate" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_doctor_idor_prevented(db_pool):
    """
    Scope 6: Doctor A cannot enumerate Doctor B's visits, contracts, or record visits impersonating Doctor B.
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        # Doctor A
        docA_uid, docA_auth = await _create_test_user_session(db_pool, "0917", ["DOCTOR"])
        docA_id = await _create_test_doctor(conn, docA_uid, status_val="APPROVED", clinic_name="مطب پزشک الف")

        # Doctor B
        docB_uid, _ = await _create_test_user_session(db_pool, "0918", ["DOCTOR"])
        docB_id = await _create_test_doctor(conn, docB_uid, status_val="APPROVED", clinic_name="مطب پزشک ب")
        await _create_test_service_contract(conn, docB_id, admin_uid)

        patient = await _create_test_patient_membership(conn)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # IDOR Attempt 1: Doctor A attempts to view Doctor B's contracts
        res_contracts = await client.get(f"/api/v1/doctors/{docB_id}/contracts", headers=docA_auth)
        assert res_contracts.status_code == 403

        # IDOR Attempt 2: Doctor A attempts to view Doctor B's visits
        res_visits = await client.get(f"/api/v1/visits/doctor/{docB_id}", headers=docA_auth)
        assert res_visits.status_code == 403

        # IDOR Attempt 3: Doctor A attempts to record visit claiming doctor_id = Doctor B
        res_record = await client.post(
            "/api/v1/visits/record",
            json={
                "doctor_id": str(docB_id),
                "holder_id": str(patient["holder_id"]),
                "membership_id": str(patient["membership_id"]),
                "service_title": "تست نفوذ شناسه پزشک",
                "total_amount_toman": 200000,
            },
            headers=docA_auth,
        )
        assert res_record.status_code == 403


@pytest.mark.asyncio
async def test_negative_access_pending_or_unapproved_doctor_rejected(db_pool):
    """
    Scope 5 & 7: Doctor account in PENDING, REJECTED, or SUSPENDED status is rejected with 403 (Fail-Closed).
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        await _approve_test_policies(conn, admin_uid)

        # Pending doctor
        pend_uid, pend_auth = await _create_test_user_session(db_pool, "0919", ["DOCTOR"])
        await _create_test_doctor(conn, pend_uid, status_val="PENDING")

        # Suspended doctor
        susp_uid, susp_auth = await _create_test_user_session(db_pool, "0920", ["DOCTOR"])
        await _create_test_doctor(conn, susp_uid, status_val="SUSPENDED")

        # Non-doctor regular user
        user_uid, user_auth = await _create_test_user_session(db_pool, "0921", ["USER"])

        patient = await _create_test_patient_membership(conn)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # 1. Pending doctor rejected on portal
        res1 = await client.get("/api/v1/doctors/me/portal", headers=pend_auth)
        assert res1.status_code == 403

        # 2. Suspended doctor rejected on visit record
        res2 = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(patient["holder_id"]),
                "membership_id": str(patient["membership_id"]),
                "service_title": "ویزیت توسط پزشک تعلیق شده",
                "total_amount_toman": 150000,
            },
            headers=susp_auth,
        )
        assert res2.status_code == 403

        # 3. Regular non-doctor user rejected on doctor portal
        res3 = await client.get("/api/v1/doctors/me/portal", headers=user_auth)
        assert res3.status_code == 403

        # 4. Unauthenticated request rejected with 401
        res4 = await client.get("/api/v1/doctors/me/portal")
        assert res4.status_code == 401


@pytest.mark.asyncio
async def test_unapproved_open_policy_fails_closed(db_pool):
    """
    Scope 10: Strict Fail-Closed behavior: unapproved OPEN_02 policy blocks visit recording with 403.
    """
    async with db_pool.acquire() as conn:
        admin_uid, _ = await _create_test_user_session(db_pool, "0910", ["ADMIN"])
        # Unapprove all OPEN policies
        await _reset_test_policies(conn)

        doc_uid, doc_auth = await _create_test_user_session(db_pool, "0922", ["DOCTOR"])
        await _create_test_doctor(conn, doc_uid, status_val="APPROVED")

        patient = await _create_test_patient_membership(conn)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/visits/record",
            json={
                "holder_id": str(patient["holder_id"]),
                "membership_id": str(patient["membership_id"]),
                "service_title": "ویزیت با خط مشی تایید نشده",
                "total_amount_toman": 250000,
            },
            headers=doc_auth,
        )
        assert res.status_code == 403
        assert "OPEN_02" in res.json()["detail"] or "policy" in res.json()["detail"].lower()
