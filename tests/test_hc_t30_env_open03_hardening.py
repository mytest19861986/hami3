"""
Automated Verification Suite for HC-T30 (R-01 & R-02: Unified Fail-Closed Env + Strict OPEN-03 Boolean)
Baseline: BL-HAMICARD-PRD-V1 | HC-CMD-031
Target DB: Isolated `hamicard_t30` + Redis DB 7

Verifies:
- T30-AC1: `ENVIRONMENT=production` alone, `staging`/`stage`, conflicting runtime env vars,
  and unrecognized env values fail closed across CORS, payment gateway, payout verifier, and SMS/OTP
  (both unit-level resolvers and live HTTP 503 endpoints).
- T30-AC2: Missing or non-boolean `OPEN-03` `auto_activate_membership` (`None`, `"true"`, `"false"`,
  `1`, `0`) fails closed (HTTP 400) with zero silent membership activation, zero order mutation,
  and zero sales case mutation.
- T30-AC3: Approved explicit `auto_activate_membership=True` and `auto_activate_membership=False`
  both behave as specified across gateway verify & manual record-payment + finalize.
- T30-AC4: Existing controls stay intact and all 18 `OPEN-*` policies restore cleanly to `PROPOSED`.
"""

import json
import os
import sys
import uuid
from datetime import UTC, datetime

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t30",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/7")

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
from src.adapters.sms import (  # noqa: E402
    MockSmsAdapter,
    SmsAdapterError,
    get_sms_adapter,
)
from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app, create_app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.cors import CorsConfigurationError, resolve_cors_settings  # noqa: E402
from src.core.env import (  # noqa: E402
    EnvironmentConfigurationError,
    is_restricted_environment,
    resolve_runtime_environment,
)
from src.core.policy import (  # noqa: E402
    InvalidPolicyConfigurationError,
    get_all_open_policy_statuses,
    parse_open03_agent_sale_policy,
    set_policy_approval,
)
from src.wallets.service import (  # noqa: E402
    PayoutAdapterConfigurationError,
    SandboxPayoutProofVerifier,
    WalletService,
    get_runtime_payout_verifier,
    reset_runtime_payout_verifier,
)

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
    "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN": {"min_amount_toman": 100000, "lock_on_request": True},
    "OPEN_18_CURRENCY_AND_ROUNDING": {
        "currency_stored": "TOMAN",
        "currency_display": "TOMAN",
        "rounding_mode": "FLOOR",
    },
}

VALID_CARD = "6037991199999990"
VALID_SHEBA = "IR630170000000100412345678"


def _clear_runtime_env(monkeypatch) -> None:
    for var in (
        "APP_ENV",
        "ENVIRONMENT",
        "NODE_ENV",
        "CORS_ALLOWED_ORIGINS",
        "ALLOWED_CORS_ORIGINS",
        "PAYMENT_PROVIDER",
        "ZARINPAL_MERCHANT_ID",
        "SMS_PROVIDER",
        "KAVENEGAR_API_KEY",
        "GHASEDAK_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


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
async def db_env():
    reset_runtime_sandbox_gateway()
    reset_runtime_payout_verifier()
    await close_pool()
    close_redis()
    pool = await init_pool()
    rd = init_redis()
    async with pool.acquire() as conn:
        await _reset_policies(conn)
    try:
        yield pool, rd
    finally:
        reset_runtime_sandbox_gateway()
        reset_runtime_payout_verifier()
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
    sess = await SessionService(pool).create_session(
        user_id=uid, device_info="t30-test", ip_address="127.0.0.1"
    )
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


async def _seed_sale_fixture(pool: asyncpg.Pool, price_toman: int = 600000, agent_pct: float = 15.0):
    agent_uid, agent_hdrs = await _create_user_session(pool, "0981", ["AGENT"])
    admin_uid, admin_hdrs = await _create_user_session(pool, "0982", ["ADMIN"])

    async with pool.acquire() as conn:
        agent_id = await conn.fetchval(
            """
            INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status)
            VALUES ($1, $2, 1, 1, 'APPROVED') RETURNING id;
            """,
            agent_uid,
            f"نمایندگی T30 {uuid.uuid4().hex[:5]}",
        )
        holder_id = await conn.fetchval(
            """
            INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
            VALUES ('نوید', 'کریمی', $1, $2) RETURNING id;
            """,
            f"{uuid.uuid4().int % 10000000000:010d}",
            f"0983{uuid.uuid4().int % 10000000:07d}",
        )
        plan_id = await conn.fetchval(
            """
            INSERT INTO discount_plans (
                title, price_toman, discount_percent, validity_days, max_visits, agent_commission_percent
            ) VALUES ('طرح تست T30', $1, 25.0, 180, 8, $2) RETURNING id;
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
        "agent_id": agent_id,
        "holder_id": holder_id,
        "plan_id": plan_id,
        "case_id": case_id,
    }


@pytest.mark.parametrize(
    "env_vars,expected_canonical",
    [
        ({"ENVIRONMENT": "production"}, "production"),
        ({"ENVIRONMENT": "prod"}, "production"),
        ({"APP_ENV": "prod"}, "production"),
        ({"NODE_ENV": "production"}, "production"),
        ({"ENVIRONMENT": "staging"}, "staging"),
        ({"APP_ENV": "staging"}, "staging"),
        ({"NODE_ENV": "stage"}, "staging"),
        ({"APP_ENV": "production", "ENVIRONMENT": "prod"}, "production"),
        ({"APP_ENV": "staging", "ENVIRONMENT": "stage"}, "staging"),
    ],
)
@pytest.mark.asyncio
async def test_t30_ac1_restricted_env_matrix_blocks_all_sandboxes_and_dev_cors(
    monkeypatch, env_vars, expected_canonical
):
    _clear_runtime_env(monkeypatch)
    for k, v in env_vars.items():
        monkeypatch.setenv(k, v)

    assert resolve_runtime_environment() == expected_canonical
    assert is_restricted_environment() is True

    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()
    with pytest.raises(CorsConfigurationError):
        create_app()

    with pytest.raises(PaymentGatewayError):
        MockPaymentGateway()
    with pytest.raises(PaymentGatewayError):
        get_payment_gateway("mock")
    with pytest.raises(PaymentGatewayError):
        get_runtime_payment_gateway("mock")

    with pytest.raises(PayoutAdapterConfigurationError):
        SandboxPayoutProofVerifier()
    with pytest.raises(PayoutAdapterConfigurationError):
        get_runtime_payout_verifier()

    with pytest.raises(SmsAdapterError):
        get_sms_adapter("mock")
    with pytest.raises(SmsAdapterError):
        await MockSmsAdapter().send_otp("09120000000", "123456")


@pytest.mark.parametrize(
    "env_vars",
    [
        {"APP_ENV": "development", "ENVIRONMENT": "production"},
        {"APP_ENV": "development", "ENVIRONMENT": "staging"},
        {"APP_ENV": "production", "NODE_ENV": "staging"},
        {"APP_ENV": "test", "NODE_ENV": "development"},
        {"APP_ENV": "canary"},
        {"ENVIRONMENT": "unknown_env"},
        {"NODE_ENV": "prd-typo"},
    ],
)
@pytest.mark.asyncio
async def test_t30_ac1_conflicting_or_invalid_envs_fail_closed_everywhere(monkeypatch, env_vars):
    _clear_runtime_env(monkeypatch)
    for k, v in env_vars.items():
        monkeypatch.setenv(k, v)
    # Even if CORS_ALLOWED_ORIGINS is valid, conflicting runtime envs MUST still fail closed!
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.hamicard.example")

    with pytest.raises(EnvironmentConfigurationError):
        resolve_runtime_environment()
    with pytest.raises(EnvironmentConfigurationError):
        is_restricted_environment()

    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()
    with pytest.raises(CorsConfigurationError):
        create_app()
    with pytest.raises(PaymentGatewayError):
        MockPaymentGateway()
    with pytest.raises(PaymentGatewayError):
        get_payment_gateway("zarinpal")
    with pytest.raises(PaymentGatewayError):
        get_runtime_payment_gateway("mock")
    with pytest.raises(PayoutAdapterConfigurationError):
        SandboxPayoutProofVerifier()
    with pytest.raises(PayoutAdapterConfigurationError):
        get_runtime_payout_verifier()
    with pytest.raises(SmsAdapterError):
        get_sms_adapter("kavenegar")
    with pytest.raises(SmsAdapterError):
        await MockSmsAdapter().send_otp("09120000000", "123456")


@pytest.mark.asyncio
async def test_t30_ac1_http_endpoints_fail_closed_with_503_under_env_staging_and_conflict(
    db_env, monkeypatch
):
    pool, rd = db_env
    async with pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    fx = await _seed_sale_fixture(pool, price_toman=400000)
    super_uid, super_hdrs = await _create_user_session(pool, "0984", ["SUPER_ADMIN"])
    admin_uid, admin_hdrs = fx["admin_uid"], fx["admin_hdrs"]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Prepare a pending order and an APPROVED settlement while in non-prod test mode
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(fx["holder_id"]),
                "plan_id": str(fx["plan_id"]),
                "idempotency_key": f"T30-HTTP-GATE-{uuid.uuid4().hex}",
            },
            headers=fx["agent_hdrs"],
        )
        assert r_ord.status_code == 200, r_ord.text
        order_id = r_ord.json()["order"]["id"]

        await WalletService(pool).credit_commission(
            user_id=fx["agent_uid"],
            amount_toman=500000,
            reference_id=f"T30-CRED-{uuid.uuid4().hex[:8]}",
            idempotency_key=f"T30-CRED-{uuid.uuid4().hex}",
            description="تست موجودی تسویه T30",
        )
        r_settle = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 200000,
                "bank_card_number": VALID_CARD,
                "bank_sheba_number": VALID_SHEBA,
                "bank_account_holder_name": "نوید کریمی",
            },
            headers=fx["agent_hdrs"],
        )
        assert r_settle.status_code == 200, r_settle.text
        settlement_id = r_settle.json()["id"]
        assert (
            await client.post(
                f"/api/v1/wallet/settlements/{settlement_id}/approve",
                headers=admin_hdrs,
            )
        ).status_code == 200

        # Test across ENVIRONMENT=production, ENVIRONMENT=staging, and conflicting APP_ENV/ENVIRONMENT
        for bad_env in (
            {"ENVIRONMENT": "production"},
            {"ENVIRONMENT": "staging"},
            {"APP_ENV": "development", "ENVIRONMENT": "production"},
        ):
            _clear_runtime_env(monkeypatch)
            for k, v in bad_env.items():
                monkeypatch.setenv(k, v)

            r_init = await client.post(
                f"/api/v1/payments/orders/{order_id}/initiate",
                json={"callback_url": "https://hamicard.local/cb"},
                headers=fx["agent_hdrs"],
            )
            assert r_init.status_code == 503, f"Expected 503 for {bad_env}, got {r_init.status_code}: {r_init.text}"

            r_ver = await client.post(
                f"/api/v1/payments/orders/{order_id}/verify",
                json={"authority": "MOCK-AUTH-deadbeef1234"},
                headers=fx["agent_hdrs"],
            )
            assert r_ver.status_code == 503, f"Expected 503 for {bad_env}, got {r_ver.status_code}: {r_ver.text}"

            r_paid = await client.post(
                f"/api/v1/wallet/settlements/{settlement_id}/mark-paid",
                json={
                    "external_payment_ref": "PAYA-T30-BLOCKED-1",
                    "external_payment_date": datetime.now(UTC).isoformat(),
                    "amount_toman": 200000,
                },
                headers=super_hdrs,
            )
            assert r_paid.status_code == 503, f"Expected 503 for {bad_env}, got {r_paid.status_code}: {r_paid.text}"

            m_otp = f"0985{uuid.uuid4().int % 10000000:07d}"
            r_otp = await client.post("/api/v1/auth/otp/request", json={"mobile": m_otp})
            assert r_otp.status_code == 503, f"Expected 503 for {bad_env}, got {r_otp.status_code}: {r_otp.text}"
            assert rd.get(f"otp:code:{m_otp}") is None

        _clear_runtime_env(monkeypatch)

    async with pool.acquire() as conn:
        assert (await conn.fetchval("SELECT status FROM orders_payments WHERE id = $1;", uuid.UUID(order_id))) == "PENDING"
        assert (await conn.fetchval("SELECT status FROM settlements WHERE id = $1;", uuid.UUID(settlement_id))) == "APPROVED"


@pytest.mark.parametrize(
    "bad_policy",
    [
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED"},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": None},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": "true"},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": "false"},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": 1},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": 0},
        {"auto_activate_membership": True},
        {"trigger": "INVALID_TRIGGER", "auto_activate_membership": False},
    ],
)
def test_t30_ac2_parse_open03_rejects_missing_or_non_boolean(bad_policy):
    with pytest.raises(InvalidPolicyConfigurationError):
        parse_open03_agent_sale_policy(bad_policy)


@pytest.mark.parametrize(
    "bad_policy",
    [
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED"},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": None},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": "true"},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": "false"},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": 1},
        {"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": 0},
    ],
)
@pytest.mark.asyncio
async def test_t30_ac2_missing_or_malformed_open03_cannot_activate_membership_via_gateway_or_manual(
    db_env, monkeypatch, bad_policy
):
    _clear_runtime_env(monkeypatch)
    pool, _ = db_env

    async with pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
        await set_policy_approval(
            conn,
            "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER",
            "APPROVED",
            updated_value_json=bad_policy,
        )

    fx_gw = await _seed_sale_fixture(pool, price_toman=500000)
    fx_man = await _seed_sale_fixture(pool, price_toman=500000)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Path 1: Gateway order linked to sales_case_id
        r_ord = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(fx_gw["holder_id"]),
                "plan_id": str(fx_gw["plan_id"]),
                "sales_case_id": str(fx_gw["case_id"]),
                "idempotency_key": f"T30-BAD-OPEN03-{uuid.uuid4().hex}",
            },
            headers=fx_gw["agent_hdrs"],
        )
        assert r_ord.status_code == 200, r_ord.text
        ord_id = r_ord.json()["order"]["id"]

        r_init = await client.post(
            f"/api/v1/payments/orders/{ord_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=fx_gw["agent_hdrs"],
        )
        assert r_init.status_code == 200
        auth = r_init.json()["authority"]
        get_runtime_payment_gateway().confirm_payment(auth)

        r_ver = await client.post(
            f"/api/v1/payments/orders/{ord_id}/verify",
            json={"authority": auth},
            headers=fx_gw["agent_hdrs"],
        )
        assert r_ver.status_code == 400, f"Expected 400 fail-closed, got {r_ver.status_code}: {r_ver.text}"

        # Path 2: Admin manual record-payment on sales_case
        r_man = await client.post(
            f"/api/v1/sales/cases/{fx_man['case_id']}/record-payment",
            json={
                "amount_toman": 500000,
                "payment_date": datetime.now(UTC).isoformat(),
                "payment_proof_reference": f"BANK-T30-{uuid.uuid4().hex[:8].upper()}",
                "notes": "تست رد کردن تنظیمات ناقص OPEN-03",
            },
            headers=fx_man["admin_hdrs"],
        )
        assert r_man.status_code == 400, f"Expected 400 fail-closed, got {r_man.status_code}: {r_man.text}"

    async with pool.acquire() as conn:
        assert (await conn.fetchval("SELECT status FROM orders_payments WHERE id = $1;", uuid.UUID(ord_id))) == "PENDING"
        assert (await conn.fetchval("SELECT count(*) FROM memberships WHERE holder_id = $1;", fx_gw["holder_id"])) == 0
        assert (await conn.fetchval("SELECT financial_status FROM sales_cases WHERE id = $1;", fx_gw["case_id"])) == "UNPAID"

        assert (await conn.fetchval("SELECT count(*) FROM orders_payments WHERE sales_case_id = $1;", fx_man["case_id"])) == 0
        assert (await conn.fetchval("SELECT count(*) FROM memberships WHERE holder_id = $1;", fx_man["holder_id"])) == 0
        assert (await conn.fetchval("SELECT financial_status FROM sales_cases WHERE id = $1;", fx_man["case_id"])) == "UNPAID"


@pytest.mark.asyncio
async def test_t30_ac3_ac4_explicit_open03_booleans_behave_accurately_and_restore_proposed(
    db_env, monkeypatch
):
    _clear_runtime_env(monkeypatch)
    pool, _ = db_env

    # Scenario A: Explicit True -> immediate membership activation upon payment recorded (manual + gateway)
    async with pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
        await set_policy_approval(
            conn,
            "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER",
            "APPROVED",
            updated_value_json={
                "trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED",
                "auto_activate_membership": True,
            },
        )

    fx_true = await _seed_sale_fixture(pool, price_toman=700000, agent_pct=10.0)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_true = await client.post(
            f"/api/v1/sales/cases/{fx_true['case_id']}/record-payment",
            json={
                "amount_toman": 700000,
                "payment_date": datetime.now(UTC).isoformat(),
                "payment_proof_reference": f"BANK-T30-T-{uuid.uuid4().hex[:8].upper()}",
                "notes": "ثبت پرداخت با auto_activate_membership=true",
            },
            headers=fx_true["admin_hdrs"],
        )
        assert r_true.status_code == 200, r_true.text
        assert r_true.json()["membership"] is not None
        assert r_true.json()["membership"]["status"] == "ACTIVE"
        assert r_true.json()["case"]["financial_status"] == "PAYMENT_RECORDED"

        # Scenario B: Explicit False -> defers membership creation until finalize (manual + gateway)
        async with pool.acquire() as conn:
            await set_policy_approval(
                conn,
                "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER",
                "APPROVED",
                updated_value_json={
                    "trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED",
                    "auto_activate_membership": False,
                },
            )

        fx_false = await _seed_sale_fixture(pool, price_toman=900000, agent_pct=10.0)
        r_false = await client.post(
            f"/api/v1/sales/cases/{fx_false['case_id']}/record-payment",
            json={
                "amount_toman": 900000,
                "payment_date": datetime.now(UTC).isoformat(),
                "payment_proof_reference": f"BANK-T30-F-{uuid.uuid4().hex[:8].upper()}",
                "notes": "ثبت پرداخت با auto_activate_membership=false",
            },
            headers=fx_false["admin_hdrs"],
        )
        assert r_false.status_code == 200, r_false.text
        assert r_false.json()["membership"] is None
        assert r_false.json()["case"]["financial_status"] == "PAYMENT_RECORDED"

        # Also verify explicit False via gateway verify
        fx_gw_false = await _seed_sale_fixture(pool, price_toman=800000, agent_pct=10.0)
        r_ord_f = await client.post(
            "/api/v1/payments/orders",
            json={
                "holder_id": str(fx_gw_false["holder_id"]),
                "plan_id": str(fx_gw_false["plan_id"]),
                "sales_case_id": str(fx_gw_false["case_id"]),
                "idempotency_key": f"T30-GW-F-{uuid.uuid4().hex}",
            },
            headers=fx_gw_false["agent_hdrs"],
        )
        assert r_ord_f.status_code == 200
        ord_f_id = r_ord_f.json()["order"]["id"]
        r_init_f = await client.post(
            f"/api/v1/payments/orders/{ord_f_id}/initiate",
            json={"callback_url": "https://hamicard.local/cb"},
            headers=fx_gw_false["agent_hdrs"],
        )
        assert r_init_f.status_code == 200
        get_runtime_payment_gateway().confirm_payment(r_init_f.json()["authority"])
        r_ver_f = await client.post(
            f"/api/v1/payments/orders/{ord_f_id}/verify",
            json={"authority": r_init_f.json()["authority"]},
            headers=fx_gw_false["agent_hdrs"],
        )
        assert r_ver_f.status_code == 200, r_ver_f.text
        assert r_ver_f.json()["membership"] is None
        assert r_ver_f.json()["sales_case"]["financial_status"] == "PAYMENT_RECORDED"

        async with pool.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM memberships WHERE holder_id = $1;",
                    fx_false["holder_id"],
                )
            ) == 0
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM memberships WHERE holder_id = $1;",
                    fx_gw_false["holder_id"],
                )
            ) == 0

        r_fin = await client.post(
            f"/api/v1/sales/cases/{fx_false['case_id']}/finalize",
            headers=fx_false["admin_hdrs"],
        )
        assert r_fin.status_code == 200, r_fin.text
        assert r_fin.json()["membership_id"] is not None
        assert r_fin.json()["commission_amount_toman"] == 90000

        r_fin_gw = await client.post(
            f"/api/v1/sales/cases/{fx_gw_false['case_id']}/finalize",
            headers=fx_gw_false["admin_hdrs"],
        )
        assert r_fin_gw.status_code == 200, r_fin_gw.text
        assert r_fin_gw.json()["membership_id"] is not None
        assert r_fin_gw.json()["commission_amount_toman"] == 80000

        async with pool.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM memberships WHERE holder_id = $1;",
                    fx_false["holder_id"],
                )
            ) == 1
            assert (
                await conn.fetchval(
                    "SELECT count(*) FROM memberships WHERE holder_id = $1;",
                    fx_gw_false["holder_id"],
                )
            ) == 1

    # Verify T30-AC4: clean reset restores all 18 OPEN-* policies to PROPOSED
    async with pool.acquire() as conn:
        await _reset_policies(conn)
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)
