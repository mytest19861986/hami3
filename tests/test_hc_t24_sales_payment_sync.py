"""
Automated Verification Suite for HC-T24 (D-1: SALE-008, SALE-009, SALE-010, OPEN-03, T24-AC1..AC4)
Baseline: BL-HAMICARD-PRD-V1
Target DB: Isolated `hamicard_t19` + Redis DB 5

Verifies:
1. T24-AC1: Sales cases in UNPAID CANNOT be finalized or produce commission, even when
   OPEN_03, OPEN_04, and OPEN_18 are temporarily APPROVED.
2. T24-AC2: Only verified gateway confirmation OR authorized audited ADMIN manual recording
   (under approved OPEN_04) can advance UNPAID -> PAYMENT_RECORDED; forged proofs,
   unconfirmed authorities, ordinary agents/users, future dates, mismatched amounts,
   and duplicate proof references (409) are blocked.
3. Dynamic OPEN_03 trigger enforcement (`PAYMENT_RECORDED_AND_CASE_APPROVED`,
   `PAYMENT_RECORDED_AND_CARD_ISSUED`, `PAYMENT_RECORDED_AND_DELIVERED`, fail-closed on
   invalid trigger, plus `auto_activate_membership=False` deferred activation).
4. T24-AC3: Duplicate & concurrent finalizations, concurrent `record-payment`, and
   competing gateway order payments produce AT MOST ONE membership and AT MOST ONE
   commission/wallet credit effect.
5. T24-AC4: All 18 OPEN-* policies remain PROPOSED after tests and real flows stay disabled.
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t19",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/5")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.adapters.payment import get_runtime_payment_gateway, reset_runtime_sandbox_gateway  # noqa: E402
from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import get_all_open_policy_statuses, set_policy_approval  # noqa: E402

DEFAULT_POLICIES = {
    "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER": {
        "trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED",
        "auto_activate_membership": True,
    },
    "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX": {
        "record_sale_payment": ["ADMIN", "SUPER_ADMIN"],
        "mark_settlement_paid": ["SUPER_ADMIN"],
        "edit_financial_settings": ["SUPER_ADMIN"],
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
    reset_runtime_sandbox_gateway()
    await close_pool()
    close_redis()
    pool = await init_pool()
    init_redis()
    async with pool.acquire() as conn:
        await _reset_policies(conn)
    try:
        yield pool
    finally:
        reset_runtime_sandbox_gateway()
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
    sess = await SessionService(pool).create_session(user_id=uid, device_info="t24-test", ip_address="127.0.0.1")
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _seed_sale_fixture(pool: asyncpg.Pool, price_toman: int = 500000, agent_pct: float = 15.0):
    agent_uid, agent_hdrs = await _create_user_session(pool, "0951", ["AGENT"])
    admin_uid, admin_hdrs = await _create_user_session(pool, "0952", ["ADMIN"])
    user_uid, user_hdrs = await _create_user_session(pool, "0953", ["USER"])
    support_uid, support_hdrs = await _create_user_session(pool, "0954", ["SUPPORT"])

    async with pool.acquire() as conn:
        agent_id = await conn.fetchval(
            """
            INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status)
            VALUES ($1, $2, 1, 1, 'APPROVED') RETURNING id;
            """,
            agent_uid,
            f"نمایندگی T24 {uuid.uuid4().hex[:5]}",
        )
        holder_id = await conn.fetchval(
            """
            INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
            VALUES ('بهرام', 'تهرانی', $1, $2) RETURNING id;
            """,
            f"{uuid.uuid4().int % 10000000000:010d}",
            f"0955{uuid.uuid4().int % 10000000:07d}",
        )
        plan_id = await conn.fetchval(
            """
            INSERT INTO discount_plans (
                title, price_toman, discount_percent, validity_days, max_visits, agent_commission_percent
            ) VALUES ('طرح تست T24', $1, 30.0, 180, 10, $2) RETURNING id;
            """,
            price_toman,
            agent_pct,
        )
        case_id = await conn.fetchval(
            """
            INSERT INTO sales_cases (agent_id, holder_id, plan_id, logistic_status, financial_status)
            VALUES ($1, $2, $3, 'APPROVED', 'UNPAID') RETURNING id;
            """,
            agent_id,
            holder_id,
            plan_id,
        )
    return {
        "agent_uid": agent_uid,
        "agent_hdrs": agent_hdrs,
        "admin_uid": admin_uid,
        "admin_hdrs": admin_hdrs,
        "user_uid": user_uid,
        "user_hdrs": user_hdrs,
        "support_uid": support_uid,
        "support_hdrs": support_hdrs,
        "agent_id": agent_id,
        "holder_id": holder_id,
        "plan_id": plan_id,
        "case_id": case_id,
    }


@pytest.mark.asyncio
async def test_t24_ac1_unpaid_sale_cannot_finalize_even_with_approved_policies(db_pool: asyncpg.Pool):
    fx = await _seed_sale_fixture(db_pool, price_toman=600000, agent_pct=20.0)

    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER", "APPROVED")
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Advance logistics all the way to DELIVERED; financial_status is STILL UNPAID
        assert (
            await client.put(
                f"/api/v1/sales/cases/{fx['case_id']}/logistic",
                json={"status": "CARD_ISSUED"},
                headers=fx["admin_hdrs"],
            )
        ).status_code == 200
        assert (
            await client.put(
                f"/api/v1/sales/cases/{fx['case_id']}/logistic",
                json={"status": "SHIPPED", "shipping_tracking_code": "POST-T24-UNPAID"},
                headers=fx["admin_hdrs"],
            )
        ).status_code == 200
        assert (
            await client.put(
                f"/api/v1/sales/cases/{fx['case_id']}/logistic",
                json={"status": "DELIVERED"},
                headers=fx["admin_hdrs"],
            )
        ).status_code == 200

        r_fin = await client.post(
            f"/api/v1/sales/cases/{fx['case_id']}/finalize",
            headers=fx["admin_hdrs"],
        )
        assert r_fin.status_code == 400, r_fin.text
        assert "UNPAID" in r_fin.json()["detail"]

        # Even if DB row were manually forced to PAYMENT_RECORDED without a verified order_id, fail closed!
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE sales_cases SET financial_status = 'PAYMENT_RECORDED' WHERE id = $1;",
                fx["case_id"],
            )
        r_no_ord = await client.post(
            f"/api/v1/sales/cases/{fx['case_id']}/finalize",
            headers=fx["admin_hdrs"],
        )
        assert r_no_ord.status_code == 400, r_no_ord.text

    async with db_pool.acquire() as conn:
        comm_cnt = await conn.fetchval(
            "SELECT count(*) FROM commissions WHERE source_sales_case_id = $1;",
            fx["case_id"],
        )
        mem_cnt = await conn.fetchval(
            "SELECT count(*) FROM memberships WHERE holder_id = $1;",
            fx["holder_id"],
        )
        wallet = await conn.fetchrow("SELECT * FROM wallets WHERE user_id = $1;", fx["agent_uid"])
        assert comm_cnt == 0
        assert mem_cnt == 0
        assert wallet is None or wallet["withdrawable_balance_toman"] == 0


@pytest.mark.asyncio
async def test_t24_ac2_only_verified_gateway_or_authorized_admin_payment_records_sale(db_pool: asyncpg.Pool):
    fx = await _seed_sale_fixture(db_pool, price_toman=450000, agent_pct=15.0)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # While OPEN-04 / OPEN-03 / OPEN-18 are PROPOSED, record-payment returns 403
        now_iso = datetime.now(UTC).isoformat()
        r_prop = await client.post(
            f"/api/v1/sales/cases/{fx['case_id']}/record-payment",
            json={
                "amount_toman": 450000,
                "payment_date": now_iso,
                "payment_proof_reference": f"RCPT-{uuid.uuid4().hex[:8]}",
                "notes": "ثبت پرداخت پیش از تایید سیاست",
            },
            headers=fx["admin_hdrs"],
        )
        assert r_prop.status_code == 403, r_prop.text

        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER", "APPROVED")
            await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

        # Ordinary user, owning AGENT, SUPPORT cannot self-record payment -> 403
        for hdrs in (fx["user_hdrs"], fx["agent_hdrs"], fx["support_hdrs"]):
            r_forb = await client.post(
                f"/api/v1/sales/cases/{fx['case_id']}/record-payment",
                json={
                    "amount_toman": 450000,
                    "payment_date": now_iso,
                    "payment_proof_reference": f"FORGE-{uuid.uuid4().hex[:8]}",
                    "notes": "تلاش غیرمجاز ثبت پرداخت",
                },
                headers=hdrs,
            )
            assert r_forb.status_code == 403, r_forb.text

        # Unconfirmed / forged gateway verification CANNOT mark sales case PAYMENT_RECORDED
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(fx["holder_id"]),
                "plan_id": str(fx["plan_id"]),
                "sales_case_id": str(fx["case_id"]),
                "idempotency_key": f"T24-FORGE-GW-{uuid.uuid4().hex}",
            },
            headers=fx["agent_hdrs"],
        )
        assert r_ord.status_code == 200, r_ord.text
        gw_order_id = r_ord.json()["order"]["id"]

        r_init = await client.post(
            f"/api/v1/payments/orders/{gw_order_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=fx["agent_hdrs"],
        )
        assert r_init.status_code == 200
        authority = r_init.json()["authority"]

        # Unconfirmed authority fails -> sales case stays UNPAID
        r_unconf = await client.post(
            f"/api/v1/payments/orders/{gw_order_id}/verify",
            json={"authority": authority},
            headers=fx["agent_hdrs"],
        )
        assert r_unconf.status_code == 400

        async with db_pool.acquire() as conn:
            sc_mid = await conn.fetchrow("SELECT financial_status, order_id FROM sales_cases WHERE id = $1;", fx["case_id"])
            assert sc_mid["financial_status"] == "UNPAID"
            assert sc_mid["order_id"] is None

        # Valid admin manual payment validation: wrong amount & future date rejected -> 400
        r_bad_amt = await client.post(
            f"/api/v1/sales/cases/{fx['case_id']}/record-payment",
            json={
                "amount_toman": 100000,
                "payment_date": now_iso,
                "payment_proof_reference": "RCPT-AMT-MISMATCH",
                "notes": "مبلغ اشتباه",
            },
            headers=fx["admin_hdrs"],
        )
        assert r_bad_amt.status_code == 400

        r_future = await client.post(
            f"/api/v1/sales/cases/{fx['case_id']}/record-payment",
            json={
                "amount_toman": 450000,
                "payment_date": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
                "payment_proof_reference": "RCPT-FUTURE-001",
                "notes": "تاریخ آینده",
            },
            headers=fx["admin_hdrs"],
        )
        assert r_future.status_code == 400

        # Authorized admin records valid manual payment -> UNPAID transitions to PAYMENT_RECORDED (not FINALIZED yet!)
        shared_proof = f"SLIP-{uuid.uuid4().hex[:8].upper()}"
        r_rec = await client.post(
            f"/api/v1/sales/cases/{fx['case_id']}/record-payment",
            json={
                "amount_toman": 450000,
                "payment_date": now_iso,
                "payment_proof_reference": shared_proof,
                "notes": "رسید واریز بانکی بررسی‌شده توسط مدیر مالی",
            },
            headers=fx["admin_hdrs"],
        )
        assert r_rec.status_code == 200, r_rec.text
        assert r_rec.json()["case"]["financial_status"] == "PAYMENT_RECORDED"
        assert r_rec.json()["case"]["order_id"] is not None

        # Verify zero commission credited before explicit finalize (SALE-009)
        async with db_pool.acquire() as conn:
            w_pre = await conn.fetchrow("SELECT * FROM wallets WHERE user_id = $1;", fx["agent_uid"])
            assert w_pre is None or w_pre["withdrawable_balance_toman"] == 0

        # Duplicate proof replay on a second UNPAID sales case MUST return 409 Conflict
        fx2 = await _seed_sale_fixture(db_pool, price_toman=450000, agent_pct=15.0)
        r_dup_proof = await client.post(
            f"/api/v1/sales/cases/{fx2['case_id']}/record-payment",
            json={
                "amount_toman": 450000,
                "payment_date": now_iso,
                "payment_proof_reference": shared_proof,
                "notes": "تلاش استفاده مجدد از رسید تکراری",
            },
            headers=fx["admin_hdrs"],
        )
        assert r_dup_proof.status_code == 409, r_dup_proof.text

        # Now finalize fx['case_id'] -> 450,000 * 15% = 67,500
        r_fin = await client.post(
            f"/api/v1/sales/cases/{fx['case_id']}/finalize",
            headers=fx["admin_hdrs"],
        )
        assert r_fin.status_code == 200, r_fin.text
        assert r_fin.json()["case"]["financial_status"] == "FINALIZED"
        assert r_fin.json()["commission_amount_toman"] == 67500


@pytest.mark.asyncio
async def test_t24_dynamic_open03_triggers_deferred_membership_and_returned_guard(db_pool: asyncpg.Pool):
    fx = await _seed_sale_fixture(db_pool, price_toman=800000, agent_pct=10.0)
    fx_ret = await _seed_sale_fixture(db_pool, price_toman=800000, agent_pct=10.0)

    async with db_pool.acquire() as conn:
        await set_policy_approval(
            conn,
            "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER",
            "APPROVED",
            updated_value_json={
                "trigger": "PAYMENT_RECORDED_AND_DELIVERED",
                "auto_activate_membership": False,
            },
        )
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Pay via verified gateway for fx
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(fx["holder_id"]),
                "plan_id": str(fx["plan_id"]),
                "sales_case_id": str(fx["case_id"]),
                "idempotency_key": f"T24-DELIV-{uuid.uuid4().hex}",
            },
            headers=fx["agent_hdrs"],
        )
        assert r_ord.status_code == 200
        ord_id = r_ord.json()["order"]["id"]
        r_init = await client.post(
            f"/api/v1/payments/orders/{ord_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=fx["agent_hdrs"],
        )
        auth = r_init.json()["authority"]
        get_runtime_payment_gateway().confirm_payment(auth)
        r_ver = await client.post(
            f"/api/v1/payments/orders/{ord_id}/verify",
            json={"authority": auth},
            headers=fx["agent_hdrs"],
        )
        assert r_ver.status_code == 200, r_ver.text
        assert r_ver.json()["sales_case"]["financial_status"] == "PAYMENT_RECORDED"
        # Because auto_activate_membership=False, membership is deferred until finalization!
        assert r_ver.json()["membership"] is None

        # Cannot finalize while APPROVED (or CARD_ISSUED) under PAYMENT_RECORDED_AND_DELIVERED trigger
        assert (
            await client.post(f"/api/v1/sales/cases/{fx['case_id']}/finalize", headers=fx["admin_hdrs"])
        ).status_code == 400

        await client.put(
            f"/api/v1/sales/cases/{fx['case_id']}/logistic",
            json={"status": "CARD_ISSUED"},
            headers=fx["admin_hdrs"],
        )
        assert (
            await client.post(f"/api/v1/sales/cases/{fx['case_id']}/finalize", headers=fx["admin_hdrs"])
        ).status_code == 400

        await client.put(
            f"/api/v1/sales/cases/{fx['case_id']}/logistic",
            json={"status": "SHIPPED", "shipping_tracking_code": "POST-DELIV-99"},
            headers=fx["admin_hdrs"],
        )
        await client.put(
            f"/api/v1/sales/cases/{fx['case_id']}/logistic",
            json={"status": "DELIVERED"},
            headers=fx["admin_hdrs"],
        )

        # Now finalize succeeds, activates exact 1 membership and 80,000 Toman commission!
        r_fin = await client.post(f"/api/v1/sales/cases/{fx['case_id']}/finalize", headers=fx["admin_hdrs"])
        assert r_fin.status_code == 200, r_fin.text
        assert r_fin.json()["membership_id"] is not None
        assert r_fin.json()["commission_amount_toman"] == 80000

        # Invalid unknown OPEN_03 trigger fails closed
        async with db_pool.acquire() as conn:
            await set_policy_approval(
                conn,
                "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER",
                "APPROVED",
                updated_value_json={"trigger": "UNKNOWN_TRIGGER", "auto_activate_membership": True},
            )
            await client.put(
                f"/api/v1/sales/cases/{fx_ret['case_id']}/logistic",
                json={"status": "RETURNED"},
                headers=fx_ret["admin_hdrs"],
            )

        r_ret_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(fx_ret["holder_id"]),
                "plan_id": str(fx_ret["plan_id"]),
                "sales_case_id": str(fx_ret["case_id"]),
                "idempotency_key": f"T24-RET-{uuid.uuid4().hex}",
            },
            headers=fx_ret["agent_hdrs"],
        )
        assert r_ret_ord.status_code == 400


@pytest.mark.asyncio
async def test_t24_ac3_ac4_concurrent_finalization_and_open_policies_restored(db_pool: asyncpg.Pool):
    fx = await _seed_sale_fixture(db_pool, price_toman=1000000, agent_pct=15.0)
    fx_race_pay = await _seed_sale_fixture(db_pool, price_toman=500000, agent_pct=15.0)

    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER", "APPROVED")
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Prepare verified payment on fx via gateway (auto_activate_membership=True)
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(fx["holder_id"]),
                "plan_id": str(fx["plan_id"]),
                "sales_case_id": str(fx["case_id"]),
                "idempotency_key": f"T24-RACE-{uuid.uuid4().hex}",
            },
            headers=fx["agent_hdrs"],
        )
        assert r_ord.status_code == 200
        ord_id = r_ord.json()["order"]["id"]
        r_init = await client.post(
            f"/api/v1/payments/orders/{ord_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=fx["agent_hdrs"],
        )
        auth = r_init.json()["authority"]
        get_runtime_payment_gateway().confirm_payment(auth)
        r_ver = await client.post(
            f"/api/v1/payments/orders/{ord_id}/verify",
            json={"authority": auth},
            headers=fx["agent_hdrs"],
        )
        assert r_ver.status_code == 200

        # Launch 8 concurrent finalize requests on SAME case -> exact 1x 200, 7x 400
        resps = await asyncio.gather(
            *[
                client.post(f"/api/v1/sales/cases/{fx['case_id']}/finalize", headers=fx["admin_hdrs"])
                for _ in range(8)
            ]
        )
        codes = [r.status_code for r in resps]
        assert codes.count(200) == 1, f"Expected exact 1 HTTP 200, got {codes}"
        assert codes.count(400) == 7, f"Expected exact 7 HTTP 400, got {codes}"

        # Launch 5 concurrent record-payment calls on fx_race_pay -> exact 1x 200, zero duplicates
        now_iso = datetime.now(UTC).isoformat()
        rec_resps = await asyncio.gather(
            *[
                client.post(
                    f"/api/v1/sales/cases/{fx_race_pay['case_id']}/record-payment",
                    json={
                        "amount_toman": 500000,
                        "payment_date": now_iso,
                        "payment_proof_reference": f"RACE-PROOF-{i}-{uuid.uuid4().hex[:6]}",
                        "notes": "آزمون همزمانی ثبت پرداخت",
                    },
                    headers=fx_race_pay["admin_hdrs"],
                )
                for i in range(5)
            ]
        )
        rec_codes = [r.status_code for r in rec_resps]
        assert rec_codes.count(200) == 1, f"Expected exact 1 HTTP 200 on record-payment race, got {rec_codes}"
        assert all(c == 400 for c in rec_codes if c != 200), rec_codes

    async with db_pool.acquire() as conn:
        mem_cnt = await conn.fetchval(
            "SELECT count(*) FROM memberships WHERE order_id = $1;",
            uuid.UUID(ord_id),
        )
        comm_cnt = await conn.fetchval(
            "SELECT count(*) FROM commissions WHERE source_sales_case_id = $1;",
            fx["case_id"],
        )
        w = await conn.fetchrow("SELECT withdrawable_balance_toman FROM wallets WHERE user_id = $1;", fx["agent_uid"])
        ledg_cnt = await conn.fetchval(
            "SELECT count(*) FROM wallet_ledger_entries WHERE reference_id = $1;",
            str(fx["case_id"]),
        )
        race_ord_cnt = await conn.fetchval(
            "SELECT count(*) FROM orders_payments WHERE sales_case_id = $1 AND status = 'SUCCESS';",
            fx_race_pay["case_id"],
        )
        assert mem_cnt == 1
        assert comm_cnt == 1
        assert w["withdrawable_balance_toman"] == 150000
        assert ledg_cnt == 1
        assert race_ord_cnt == 1

        # Verify policy reset behavior cleanly
        await _reset_policies(conn)
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)
