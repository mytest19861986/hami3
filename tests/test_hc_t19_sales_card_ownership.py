"""
Security, Ownership & Fail-Closed Configuration Verification Suite for HC-T19
Scope: F-12 HIGH & CARD_QR_STATIC_SECRET_FALLBACK (T19-AC1..AC5)
Target DB: Isolated `hamicard_t19` + Redis DB 5
"""

import json
import os
import sys
import uuid

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t19",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/5")
os.environ.setdefault("CARD_QR_SECRET", "test_hamicard_t19_qr_signing_secret_minimum_32_bytes")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.adapters.payment import get_runtime_payment_gateway, reset_runtime_sandbox_gateway  # noqa: E402
from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.cards.service import CardConfigurationError, CardService  # noqa: E402
from src.core.policy import set_policy_approval  # noqa: E402

DEFAULT_POLICIES = {
    "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER": {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": True},
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
    sess = await SessionService(pool).create_session(user_id=uid, device_info="t19-test", ip_address="127.0.0.1")
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _create_agent_row(conn: asyncpg.Connection, user_id: uuid.UUID, status_val: str = "APPROVED") -> uuid.UUID:
    return await conn.fetchval(
        """
        INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status)
        VALUES ($1, $2, 1, 1, $3)
        RETURNING id;
        """,
        user_id,
        f"نمایندگی {uuid.uuid4().hex[:6]}",
        status_val,
    )


async def _create_doctor_row(conn: asyncpg.Connection, user_id: uuid.UUID, status_val: str = "APPROVED") -> uuid.UUID:
    return await conn.fetchval(
        """
        INSERT INTO doctors (
            user_id, medical_council_code, specialty, clinic_name,
            province_id, city_id, clinic_address, clinic_phone, verification_status, is_public_listed
        ) VALUES ($1, $2, 'Internal', 'T19 Clinic', 1, 1, 'Tehran', '0215555', $3, TRUE)
        RETURNING id;
        """,
        user_id,
        f"T19MED-{uuid.uuid4().hex[:6]}",
        status_val,
    )


@pytest.mark.asyncio
async def test_t19_ac1_ac2_ac5_sales_agent_binding_logistics_rbac_and_pii_masking(db_pool: asyncpg.Pool):
    agent_a_uid, agent_a_hdrs = await _create_user_session(db_pool, "0950", ["AGENT"])
    agent_b_uid, agent_b_hdrs = await _create_user_session(db_pool, "0951", ["AGENT"])
    pend_uid, pend_hdrs = await _create_user_session(db_pool, "0952", ["AGENT"])
    susp_uid, susp_hdrs = await _create_user_session(db_pool, "0953", ["AGENT"])
    other_uid, other_hdrs = await _create_user_session(db_pool, "0954", ["USER"])
    support_uid, support_hdrs = await _create_user_session(db_pool, "0955", ["SUPPORT"])
    admin_uid, admin_hdrs = await _create_user_session(db_pool, "0956", ["ADMIN"])

    raw_nat = f"{uuid.uuid4().int % 10000000000:010d}"
    raw_mob = f"0957{uuid.uuid4().int % 10000000:07d}"

    async with db_pool.acquire() as conn:
        agent_a_id = await _create_agent_row(conn, agent_a_uid, "APPROVED")
        agent_b_id = await _create_agent_row(conn, agent_b_uid, "APPROVED")
        await _create_agent_row(conn, pend_uid, "PENDING")
        await _create_agent_row(conn, susp_uid, "SUSPENDED")
        holder_id = await conn.fetchval(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('رضا', 'محمدی', $1, $2) RETURNING id;",
            raw_nat,
            raw_mob,
        )
        # Plan price = 1,000,000 Toman, agent_commission_percent = 12.75% -> raw 127,500
        # Or price = 333,333 Toman, rate = 15% -> raw 49,999.95 -> FLOOR = 49,999 (checks exact Decimal floor!)
        plan_id = await conn.fetchval(
            "INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days, agent_commission_percent) VALUES ('طرح تست T19', 333333, 25.0, 365, 15.0) RETURNING id;"
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Agent A cannot create for Agent B -> 403 Forbidden (T19-AC1)
        r_spoof = await client.post(
            "/api/v1/sales/cases",
            json={"agent_id": str(agent_b_id), "holder_id": str(holder_id), "plan_id": str(plan_id)},
            headers=agent_a_hdrs,
        )
        assert r_spoof.status_code == 403, r_spoof.text

        # 2. PENDING / SUSPENDED agent & plain USER blocked -> 403 Forbidden (T19-AC1)
        for hdrs in (pend_hdrs, susp_hdrs, other_hdrs):
            r_blk = await client.post(
                "/api/v1/sales/cases",
                json={"holder_id": str(holder_id), "plan_id": str(plan_id)},
                headers=hdrs,
            )
            assert r_blk.status_code == 403

        # 3. Agent A creates own sales case (without agent_id in payload -> bound to Agent A)
        r_create = await client.post(
            "/api/v1/sales/cases",
            json={"holder_id": str(holder_id), "plan_id": str(plan_id), "notes": "ثبت پرونده نماینده"},
            headers=agent_a_hdrs,
        )
        assert r_create.status_code == 200, r_create.text
        case_a_id = r_create.json()["case"]["id"]
        assert r_create.json()["case"]["agent_id"] == str(agent_a_id)

        # 4. ADMIN override creating case on behalf of APPROVED Agent B succeeds & audits admin_override=True
        r_adm_create = await client.post(
            "/api/v1/sales/cases",
            json={"agent_id": str(agent_b_id), "holder_id": str(holder_id), "plan_id": str(plan_id)},
            headers=admin_hdrs,
        )
        assert r_adm_create.status_code == 200, r_adm_create.text
        adm_case_id = r_adm_create.json()["case"]["id"]

        # 5. IDOR on GET /sales/cases/{id}: Agent B & unrelated User denied (403); non-existent UUID denied (403)
        assert (await client.get(f"/api/v1/sales/cases/{case_a_id}", headers=agent_b_hdrs)).status_code == 403
        assert (await client.get(f"/api/v1/sales/cases/{case_a_id}", headers=other_hdrs)).status_code == 403
        assert (await client.get(f"/api/v1/sales/cases/{uuid.uuid4()}", headers=other_hdrs)).status_code == 403

        # 6. PII masking on GET /sales/cases/{id} (T19-AC5)
        r_get_agent = await client.get(f"/api/v1/sales/cases/{case_a_id}", headers=agent_a_hdrs)
        assert r_get_agent.status_code == 200
        assert r_get_agent.json()["holder_national_code"].startswith("******")
        assert r_get_agent.json()["holder_national_code"] != raw_nat
        assert "***" in r_get_agent.json()["holder_mobile"]
        assert r_get_agent.json()["holder_mobile"] != raw_mob

        r_get_sup = await client.get(f"/api/v1/sales/cases/{case_a_id}", headers=support_hdrs)
        assert r_get_sup.status_code == 200
        assert r_get_sup.json()["holder_national_code"] != raw_nat
        assert r_get_sup.json()["holder_mobile"] != raw_mob

        r_get_adm = await client.get(f"/api/v1/sales/cases/{case_a_id}", headers=admin_hdrs)
        assert r_get_adm.status_code == 200
        assert r_get_adm.json()["holder_national_code"] == raw_nat
        assert r_get_adm.json()["holder_mobile"] == raw_mob

        # 7. Logistics RBAC & state machine (T19-AC2)
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "APPROVED"},
                headers=agent_a_hdrs,
            )
        ).status_code == 403
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "APPROVED"},
                headers=support_hdrs,
            )
        ).status_code == 403

        # Invalid skip PENDING_REVIEW -> CARD_ISSUED (400)
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "CARD_ISSUED"},
                headers=admin_hdrs,
            )
        ).status_code == 400

        # Cannot finalize while PENDING_REVIEW (403 OPEN_03 gate first, then approve policies & still 400 on PENDING_REVIEW)
        assert (
            await client.post(f"/api/v1/sales/cases/{case_a_id}/finalize", headers=admin_hdrs)
        ).status_code == 403

        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER", "APPROVED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

        assert (
            await client.post(f"/api/v1/sales/cases/{case_a_id}/finalize", headers=admin_hdrs)
        ).status_code == 400

        # Advance APPROVED -> CARD_ISSUED -> SHIPPED (without code=400, with code=200) -> DELIVERED
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "APPROVED"},
                headers=admin_hdrs,
            )
        ).status_code == 200
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "CARD_ISSUED"},
                headers=admin_hdrs,
            )
        ).status_code == 200
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "SHIPPED"},
                headers=admin_hdrs,
            )
        ).status_code == 400
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "SHIPPED", "shipping_tracking_code": "IRPOST-123456"},
                headers=admin_hdrs,
            )
        ).status_code == 200
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "DELIVERED"},
                headers=admin_hdrs,
            )
        ).status_code == 200
        # Backward transition DELIVERED -> APPROVED rejected (400)
        assert (
            await client.put(
                f"/api/v1/sales/cases/{case_a_id}/logistic",
                json={"status": "APPROVED"},
                headers=admin_hdrs,
            )
        ).status_code == 400

        # SUPPORT / AGENT cannot finalize financials (403)
        assert (
            await client.post(f"/api/v1/sales/cases/{case_a_id}/finalize", headers=agent_a_hdrs)
        ).status_code == 403
        assert (
            await client.post(f"/api/v1/sales/cases/{case_a_id}/finalize", headers=support_hdrs)
        ).status_code == 403

        # ADMIN cannot finalize UNPAID sales case -> 400 (D-1)
        assert (
            await client.post(f"/api/v1/sales/cases/{case_a_id}/finalize", headers=admin_hdrs)
        ).status_code == 400

        # Record verified gateway payment linked to case_a_id -> PAYMENT_RECORDED
        reset_runtime_sandbox_gateway()
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "sales_case_id": case_a_id,
                "idempotency_key": f"T19-PAY-{uuid.uuid4().hex}",
            },
            headers=agent_a_hdrs,
        )
        assert r_ord.status_code == 200, r_ord.text
        sc_order_id = r_ord.json()["order"]["id"]
        r_init = await client.post(
            f"/api/v1/payments/orders/{sc_order_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=agent_a_hdrs,
        )
        assert r_init.status_code == 200, r_init.text
        authority = r_init.json()["authority"]
        get_runtime_payment_gateway().confirm_payment(authority)
        r_ver = await client.post(
            f"/api/v1/payments/orders/{sc_order_id}/verify",
            json={"authority": authority},
            headers=agent_a_hdrs,
        )
        assert r_ver.status_code == 200, r_ver.text
        assert r_ver.json()["sales_case"]["financial_status"] == "PAYMENT_RECORDED"

        # ADMIN finalizes -> exact Decimal floor 333,333 * 15% = 49,999.95 -> 49,999
        r_fin = await client.post(f"/api/v1/sales/cases/{case_a_id}/finalize", headers=admin_hdrs)
        assert r_fin.status_code == 200, r_fin.text
        assert r_fin.json()["commission_amount_toman"] == 49999

    async with db_pool.acquire() as conn:
        audit = await conn.fetchrow(
            "SELECT actor_user_id, actor_role, new_values FROM audit_logs WHERE entity_id = $1 AND action = 'SALES_CASE_CREATED';",
            adm_case_id,
        )
        assert audit["actor_user_id"] == admin_uid
        assert audit["actor_role"] == "ADMIN"
        vals = json.loads(audit["new_values"]) if isinstance(audit["new_values"], str) else audit["new_values"]
        assert vals["admin_override"] is True


@pytest.mark.asyncio
async def test_t19_ac3_ac4_card_idor_fail_closed_qr_secret_and_doctor_qr_verification(
    db_pool: asyncpg.Pool, monkeypatch
):
    buyer_uid, buyer_hdrs = await _create_user_session(db_pool, "0960", ["USER"])
    holder_uid, holder_hdrs = await _create_user_session(db_pool, "0961", ["USER"])
    other_uid, other_hdrs = await _create_user_session(db_pool, "0962", ["USER"])
    support_uid, support_hdrs = await _create_user_session(db_pool, "0963", ["SUPPORT"])
    admin_uid, admin_hdrs = await _create_user_session(db_pool, "0964", ["ADMIN"])
    doc_app_uid, doc_app_hdrs = await _create_user_session(db_pool, "0965", ["DOCTOR"])
    doc_pend_uid, doc_pend_hdrs = await _create_user_session(db_pool, "0966", ["DOCTOR"])
    doc_susp_uid, doc_susp_hdrs = await _create_user_session(db_pool, "0967", ["DOCTOR"])

    holder_nat = f"00{uuid.uuid4().int % 100000000:08d}"
    async with db_pool.acquire() as conn:
        await _create_doctor_row(conn, doc_app_uid, "APPROVED")
        await _create_doctor_row(conn, doc_pend_uid, "PENDING")
        await _create_doctor_row(conn, doc_susp_uid, "SUSPENDED")

        await conn.execute(
            "INSERT INTO profiles (user_id, first_name, last_name, national_code) VALUES ($1, 'دارنده', 'کارت', $2);",
            holder_uid,
            holder_nat,
        )
        holder_id = await conn.fetchval(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('دارنده', 'کارت', $1, $2) RETURNING id;",
            holder_nat,
            f"0968{uuid.uuid4().int % 10000000:07d}",
        )
        plan_id = await conn.fetchval("SELECT id FROM discount_plans LIMIT 1;")
        order_id = await conn.fetchval(
            "INSERT INTO orders_payments (buyer_user_id, holder_id, plan_id, amount_toman, status, idempotency_key) VALUES ($1, $2, $3, 350000, 'SUCCESS', $4) RETURNING id;",
            buyer_uid,
            holder_id,
            plan_id,
            f"T19-ORD-{uuid.uuid4().hex}",
        )
        mem_id = await conn.fetchval(
            """
            INSERT INTO memberships (
                holder_id, plan_id, order_id, start_date, end_date,
                max_visits, remaining_visits, used_visits, status
            ) VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '90 days', 5, 5, 0, 'ACTIVE')
            RETURNING id;
            """,
            holder_id,
            plan_id,
            order_id,
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Fail-Closed Secret Configuration (T19-AC4)
        with pytest.raises(CardConfigurationError):
            CardService(db_pool, secret_key="")
        with pytest.raises(CardConfigurationError):
            CardService(db_pool, secret_key="short-secret")
        with pytest.raises(CardConfigurationError):
            CardService(
                db_pool,
                secret_key="hamicard_production_secret_key_change_in_vault_32bytes",
            )

        monkeypatch.delenv("CARD_QR_SECRET", raising=False)
        monkeypatch.delenv("APP_SECRET", raising=False)
        r_unconf = await client.get(f"/api/v1/cards/membership/{mem_id}", headers=buyer_hdrs)
        assert r_unconf.status_code == 503
        assert "hamicard_production" not in r_unconf.text

        # Restore strong secret for functional & ownership tests
        monkeypatch.setenv("CARD_QR_SECRET", "test_hamicard_t19_qr_signing_secret_minimum_32_bytes")

        # 2. Card Ownership IDOR check (T19-AC3)
        assert (await client.get(f"/api/v1/cards/membership/{mem_id}", headers=other_hdrs)).status_code == 403
        assert (await client.get(f"/api/v1/cards/membership/{mem_id}", headers=doc_app_hdrs)).status_code == 403
        assert (await client.get(f"/api/v1/cards/membership/{uuid.uuid4()}", headers=other_hdrs)).status_code == 403

        # Buyer, Holder (matched by national_code), SUPPORT -> 200 with masked national_code
        for hdrs in (buyer_hdrs, holder_hdrs, support_hdrs):
            r_ok = await client.get(f"/api/v1/cards/membership/{mem_id}", headers=hdrs)
            assert r_ok.status_code == 200, r_ok.text
            assert r_ok.json()["card"]["national_code"].startswith("******")
            assert r_ok.json()["card"]["national_code"] != holder_nat

        # ADMIN -> 200 with unmasked national_code
        r_adm = await client.get(f"/api/v1/cards/membership/{mem_id}", headers=admin_hdrs)
        assert r_adm.status_code == 200
        assert r_adm.json()["card"]["national_code"] == holder_nat
        qr_payload = r_adm.json()["card"]["qr_code_payload"]

        # 3. QR Verification RBAC & tamper detection (T19-AC4)
        for hdrs in (other_hdrs, buyer_hdrs, support_hdrs, doc_pend_hdrs, doc_susp_hdrs):
            r_blk = await client.post("/api/v1/cards/verify-qr", json={"qr_payload": qr_payload}, headers=hdrs)
            assert r_blk.status_code == 403, f"Expected 403, got {r_blk.status_code}: {r_blk.text}"

        r_scan_ok = await client.post(
            "/api/v1/cards/verify-qr",
            json={"qr_payload": qr_payload},
            headers=doc_app_hdrs,
        )
        assert r_scan_ok.status_code == 200, r_scan_ok.text
        assert r_scan_ok.json()["verified"] is True
        assert r_scan_ok.json()["can_record_visit"] is True
        assert r_scan_ok.json()["card"]["national_code"] != holder_nat

        tampered = qr_payload[:-4] + "0000"
        r_tamper = await client.post(
            "/api/v1/cards/verify-qr",
            json={"qr_payload": tampered},
            headers=doc_app_hdrs,
        )
        assert r_tamper.status_code == 400

    async with db_pool.acquire() as conn:
        ok_log = await conn.fetchrow(
            "SELECT actor_user_id, actor_role FROM audit_logs WHERE entity_id = $1 AND action = 'CARD_QR_VERIFIED';",
            str(mem_id),
        )
        fail_log = await conn.fetchrow(
            "SELECT actor_user_id, actor_role FROM audit_logs WHERE entity_id = $1 AND action = 'CARD_QR_VERIFICATION_FAILED';",
            str(mem_id),
        )
        assert ok_log["actor_user_id"] == doc_app_uid
        assert ok_log["actor_role"] == "DOCTOR"
        assert fail_log["actor_user_id"] == doc_app_uid
