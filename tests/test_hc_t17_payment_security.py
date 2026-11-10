"""
Security & Concurrency Verification Suite for HC-T17 (F-11 CRITICAL, F-12 HIGH, T17-AC1..AC5)
Baseline: BL-HAMICARD-PRD-V1 | PAY-001..011, SEC-001..017, AC-05, AC-06
Target DB: Isolated `hamicard_t17` + Redis DB 3
"""

import asyncio
import json
import os
import sys
import uuid

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t17",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/3")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.adapters.payment import (  # noqa: E402
    MockPaymentGateway,
    PaymentGatewayError,
    get_payment_gateway,
    get_runtime_payment_gateway,
    reset_runtime_sandbox_gateway,
)
from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import set_policy_approval  # noqa: E402

DEFAULT_VALUES = {
    "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX": {
        "record_sale_payment": ["ADMIN", "SUPER_ADMIN"],
        "mark_settlement_paid": ["SUPER_ADMIN"],
        "edit_financial_settings": ["SUPER_ADMIN"],
    },
    "OPEN_05_COMBINED_COMMISSION_POLICY": {"allow_combined": False, "max_total_percent": 30.0},
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
    for key, val in DEFAULT_VALUES.items():
        await conn.execute(
            "UPDATE system_settings SET value_json = $2::jsonb WHERE key = $1;",
            key,
            json.dumps(val),
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
        user_id = await conn.fetchval(
            "INSERT INTO users (mobile, status, roles, is_mobile_verified) VALUES ($1, 'ACTIVE', $2, TRUE) RETURNING id;",
            mobile,
            roles,
        )
        for role in roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
                user_id,
                role,
            )
    sess = await SessionService(pool).create_session(user_id=user_id, device_info="t17-test", ip_address="127.0.0.1")
    return user_id, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _create_holder_and_plan(pool: asyncpg.Pool, price_toman: int = 100000, ref_pct: float = 29.0):
    async with pool.acquire() as conn:
        nat = f"{uuid.uuid4().int % 10000000000:010d}"
        holder_id = await conn.fetchval(
            "INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('تست', 'پرداخت', $1, $2) RETURNING id;",
            nat,
            f"0971{uuid.uuid4().int % 10000000:07d}",
        )
        plan_id = await conn.fetchval(
            """
            INSERT INTO discount_plans (
                title, price_toman, discount_percent, validity_days, max_visits, referrer_commission_percent
            ) VALUES ('طرح آزمایشی T17', $1, 20.0, 90, 5, $2)
            RETURNING id;
            """,
            price_toman,
            ref_pct,
        )
    return holder_id, plan_id, nat


@pytest.mark.asyncio
async def test_t17_production_gateway_fails_closed(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PAYMENT_PROVIDER", "mock")
    with pytest.raises(PaymentGatewayError, match="production"):
        MockPaymentGateway()
    with pytest.raises(PaymentGatewayError, match="production"):
        get_payment_gateway("mock")
    with pytest.raises(PaymentGatewayError, match="production"):
        get_runtime_payment_gateway("mock")

    monkeypatch.setenv("PAYMENT_PROVIDER", "zarinpal")
    monkeypatch.delenv("ZARINPAL_MERCHANT_ID", raising=False)
    with pytest.raises(PaymentGatewayError, match="ZARINPAL_MERCHANT_ID"):
        get_runtime_payment_gateway("zarinpal")


@pytest.mark.asyncio
async def test_t17_ac1_user_cannot_self_confirm_with_forged_or_unconfirmed_tokens(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    user_a, headers_a = await _create_user_session(db_pool, "0960", ["USER"])
    holder_id, plan_id, _ = await _create_holder_and_plan(db_pool, price_toman=350000)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": f"T17-FORGE-{uuid.uuid4().hex}",
                "payment_method": "GATEWAY",
            },
            headers=headers_a,
        )
        assert r_ord.status_code == 200, r_ord.text
        order_id = r_ord.json()["order"]["id"]

        # Attempt 1: Forged self-asserted transaction/tracking IDs (classic F-11 exploit)
        r_forged = await client.post(
            f"/api/v1/payments/orders/{order_id}/verify",
            json={
                "gateway_transaction_id": "FORGED-TX-99999",
                "gateway_tracking_code": "FORGED-TRK-99999",
            },
            headers=headers_a,
        )
        assert r_forged.status_code == 400, r_forged.text

        # Attempt 2: Fabricated authority never issued by gateway
        r_fake_auth = await client.post(
            f"/api/v1/payments/orders/{order_id}/verify",
            json={"authority": "MOCK-AUTH-deadbeef1234"},
            headers=headers_a,
        )
        assert r_fake_auth.status_code == 400, r_fake_auth.text

        # Attempt 3: Real initiated authority, but bank NEVER confirmed payment
        r_init = await client.post(
            f"/api/v1/payments/orders/{order_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=headers_a,
        )
        assert r_init.status_code == 200, r_init.text
        authority = r_init.json()["authority"]

        r_unpaid = await client.post(
            f"/api/v1/payments/orders/{order_id}/verify",
            json={"authority": authority},
            headers=headers_a,
        )
        assert r_unpaid.status_code == 400, r_unpaid.text
        assert "not been confirmed" in r_unpaid.json()["detail"]

    async with db_pool.acquire() as conn:
        status_db = await conn.fetchval("SELECT status FROM orders_payments WHERE id = $1;", uuid.UUID(order_id))
        mem_cnt = await conn.fetchval("SELECT count(*) FROM memberships WHERE order_id = $1;", uuid.UUID(order_id))
        assert status_db == "PENDING"
        assert mem_cnt == 0


@pytest.mark.asyncio
async def test_t17_ac4_cross_user_order_idor_and_idempotency_collision_blocked(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    user_a, headers_a = await _create_user_session(db_pool, "0961", ["USER"])
    user_b, headers_b = await _create_user_session(db_pool, "0962", ["USER"])
    holder_id, plan_id, raw_nat = await _create_holder_and_plan(db_pool, price_toman=450000)

    shared_idem = f"T17-IDEM-{uuid.uuid4().hex}"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": shared_idem,
            },
            headers=headers_a,
        )
        assert r_ord.status_code == 200
        order_id = r_ord.json()["order"]["id"]

        # Owner gets masked holder national code; unrelated user B is denied (403)
        r_owner_get = await client.get(f"/api/v1/payments/orders/{order_id}", headers=headers_a)
        assert r_owner_get.status_code == 200
        assert r_owner_get.json()["holder_national_code"] != raw_nat
        assert r_owner_get.json()["holder_national_code"].startswith("******")

        r_b_get = await client.get(f"/api/v1/payments/orders/{order_id}", headers=headers_b)
        assert r_b_get.status_code == 403

        r_b_init = await client.post(
            f"/api/v1/payments/orders/{order_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=headers_b,
        )
        assert r_b_init.status_code == 403

        r_b_ver = await client.post(
            f"/api/v1/payments/orders/{order_id}/verify",
            json={"authority": "MOCK-AUTH-anything"},
            headers=headers_b,
        )
        assert r_b_ver.status_code == 403

        # User B trying to replay User A's idempotency key gets 409 conflict without seeing order A
        r_b_idem = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": shared_idem,
            },
            headers=headers_b,
        )
        assert r_b_idem.status_code == 409

        # Ordinary user cannot create ADMIN_GRANT order
        r_grant = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": f"T17-GRANT-{uuid.uuid4().hex}",
                "payment_method": "ADMIN_GRANT",
            },
            headers=headers_a,
        )
        assert r_grant.status_code == 403

        # User B cannot bind an order to Agent A's sales_case_id
        async with db_pool.acquire() as conn:
            ag_id = await conn.fetchval(
                """
                INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status)
                VALUES ($1, 'نمایندگی تست ۱۷', 1, 1, 'APPROVED')
                RETURNING id;
                """,
                user_a,
            )
            sc_id = await conn.fetchval(
                "INSERT INTO sales_cases (agent_id, holder_id, plan_id) VALUES ($1, $2, $3) RETURNING id;",
                ag_id,
                holder_id,
                plan_id,
            )
        r_sc_hijack = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "sales_case_id": str(sc_id),
                "idempotency_key": f"T17-SC-{uuid.uuid4().hex}",
            },
            headers=headers_b,
        )
        assert r_sc_hijack.status_code == 403


@pytest.mark.asyncio
async def test_t17_ac2_ac3_ac5_verified_gateway_concurrent_replay_and_decimal_rounding(db_pool: asyncpg.Pool):
    ref_user_id, _ = await _create_user_session(db_pool, "0963", ["USER"])
    buyer_id, headers_buyer = await _create_user_session(db_pool, "0964", ["USER"])
    # 100,000 * 29.0% MUST equal exact 29,000 (not float bug 28,999!)
    holder_id, plan_id, _ = await _create_holder_and_plan(db_pool, price_toman=100000, ref_pct=29.0)

    ref_code = f"HAMI-{uuid.uuid4().hex[:6].upper()}"
    async with db_pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO referrals (referrer_user_id, referred_user_id, referral_code, status) VALUES ($1, $2, $3, 'ACTIVE');",
            ref_user_id,
            buyer_id,
            ref_code,
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": f"T17-CONC-{uuid.uuid4().hex}",
                "payment_method": "GATEWAY",
            },
            headers=headers_buyer,
        )
        assert r_ord.status_code == 200
        order_id = r_ord.json()["order"]["id"]

        r_init = await client.post(
            f"/api/v1/payments/orders/{order_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=headers_buyer,
        )
        assert r_init.status_code == 200
        authority = r_init.json()["authority"]

        # Confirm on isolated sandbox gateway, but OPEN-18 STILL PROPOSED -> 403 fail-closed (T17-AC5)
        gateway = get_runtime_payment_gateway()
        gateway.confirm_payment(authority)
        r_prop = await client.post(
            f"/api/v1/payments/orders/{order_id}/verify",
            json={"authority": authority, "referral_code": ref_code},
            headers=headers_buyer,
        )
        assert r_prop.status_code == 403
        assert "OPEN_18" in r_prop.json()["detail"]

        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
            await set_policy_approval(conn, "OPEN_05_COMBINED_COMMISSION_POLICY", "APPROVED")

        # Launch 6 simultaneous verification calls for SAME order (T17-AC3 concurrency invariant)
        async def _verify_call():
            return await client.post(
                f"/api/v1/payments/orders/{order_id}/verify",
                json={"authority": authority, "referral_code": ref_code},
                headers=headers_buyer,
            )

        resps = await asyncio.gather(*[_verify_call() for _ in range(6)])
        assert all(r.status_code == 200 for r in resps), [r.text for r in resps]
        fulfilled_count = sum(1 for r in resps if not r.json().get("already_fulfilled", False))
        assert fulfilled_count == 1, f"Expected exact 1 initial fulfillment, got {fulfilled_count}"

        # Replay order #1's authority against a NEW Order #2 -> blocked by order_id & ref replay
        r_ord2 = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": f"T17-ORD2-{uuid.uuid4().hex}",
            },
            headers=headers_buyer,
        )
        order2_id = r_ord2.json()["order"]["id"]
        await client.post(
            f"/api/v1/payments/orders/{order2_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=headers_buyer,
        )
        r_cross_auth = await client.post(
            f"/api/v1/payments/orders/{order2_id}/verify",
            json={"authority": authority},
            headers=headers_buyer,
        )
        assert r_cross_auth.status_code == 400

    async with db_pool.acquire() as conn:
        oid = uuid.UUID(order_id)
        mems = await conn.fetchval("SELECT count(*) FROM memberships WHERE order_id = $1;", oid)
        comms = await conn.fetch("SELECT amount_toman FROM commissions WHERE source_order_id = $1;", oid)
        w_bal = await conn.fetchval("SELECT withdrawable_balance_toman FROM wallets WHERE user_id = $1;", ref_user_id)
        audit_row = await conn.fetchrow(
            "SELECT actor_user_id, actor_role FROM audit_logs WHERE entity_id = $1 AND action = 'ORDER_FULFILLED';",
            order_id,
        )
        assert mems == 1
        assert len(comms) == 1
        assert comms[0]["amount_toman"] == 29000, f"Exact Decimal 29% of 100000 failed: got {comms[0]['amount_toman']}"
        assert w_bal == 29000
        assert audit_row["actor_user_id"] == buyer_id
        assert audit_row["actor_role"] == "USER"


@pytest.mark.asyncio
async def test_t17_ac2_ac5_manual_confirm_requires_open04_and_admin_role(db_pool: asyncpg.Pool):
    user_id, user_headers = await _create_user_session(db_pool, "0965", ["USER"])
    admin_id, admin_headers = await _create_user_session(db_pool, "0966", ["ADMIN"])
    holder_id, plan_id, _ = await _create_holder_and_plan(db_pool, price_toman=250000)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": f"T17-MAN-{uuid.uuid4().hex}",
                "payment_method": "MANUAL_CARD",
            },
            headers=user_headers,
        )
        assert r_ord.status_code == 200
        order_id = r_ord.json()["order"]["id"]

        # Ordinary user CANNOT manually confirm even with policy approved
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
            # OPEN_04 STILL PROPOSED -> Admin also blocked with 403!
        r_open04_blocked = await client.post(
            f"/api/v1/payments/orders/{order_id}/manual-confirm",
            json={"payment_proof_reference": "SLIP-778899", "reason": "تایید مدیر پیش از سیاست"},
            headers=admin_headers,
        )
        assert r_open04_blocked.status_code == 403
        assert "OPEN_04" in r_open04_blocked.json()["detail"]

        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")

        r_user_denied = await client.post(
            f"/api/v1/payments/orders/{order_id}/manual-confirm",
            json={"payment_proof_reference": "SLIP-778899", "reason": "تایید جعلی توسط کاربر"},
            headers=user_headers,
        )
        assert r_user_denied.status_code == 403

        proof_ref = f"SLIP-{uuid.uuid4().hex[:8]}"
        r_admin_ok = await client.post(
            f"/api/v1/payments/orders/{order_id}/manual-confirm",
            json={"payment_proof_reference": proof_ref, "reason": "فیش بانکی تایید شده توسط مالی"},
            headers=admin_headers,
        )
        assert r_admin_ok.status_code == 200, r_admin_ok.text
        assert r_admin_ok.json()["order"]["status"] == "SUCCESS"
        assert r_admin_ok.json()["membership"]["status"] == "ACTIVE"

        # Duplicate proof_ref on a second manual order -> 409 Conflict
        r_ord2 = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(holder_id),
                "plan_id": str(plan_id),
                "idempotency_key": f"T17-MAN2-{uuid.uuid4().hex}",
                "payment_method": "MANUAL_CARD",
            },
            headers=user_headers,
        )
        order2_id = r_ord2.json()["order"]["id"]
        r_dup_proof = await client.post(
            f"/api/v1/payments/orders/{order2_id}/manual-confirm",
            json={"payment_proof_reference": proof_ref, "reason": "تلاش استفاده مجدد از فیش قبلی"},
            headers=admin_headers,
        )
        assert r_dup_proof.status_code == 409, r_dup_proof.text

    async with db_pool.acquire() as conn:
        audit_row = await conn.fetchrow(
            "SELECT actor_user_id, actor_role FROM audit_logs WHERE entity_id = $1 AND action = 'ORDER_MANUALLY_CONFIRMED';",
            order_id,
        )
        assert audit_row["actor_user_id"] == admin_id
        assert audit_row["actor_role"] == "ADMIN"
