"""
Automated Verification Suite for HC-T14 (F-06, F-07, T14-AC1..AC4)
Baseline: BL-HAMICARD-PRD-V1 | Section 28 (OPEN-01..18) & AC-12

Verifies against isolated PostgreSQL test DB (`hamicard_t14`) + Redis DB 2:
1. T14-AC1: All 18 OPEN-01..18 settings exist and start in 'PROPOSED' state,
   separated into proposed / approved / blocked runtime partitions, with
   independent per-key transitions and audit trails.
2. T14-AC1: Financial & policy-sensitive operations (`POST /api/v1/wallet/settle`,
   `POST /api/v1/payments/orders/{id}/verify`, `POST /api/v1/sales/cases/{id}/finalize`,
   `POST /api/v1/visits/record`) remain disabled (HTTP 403) while their required
   OPEN-* policies are 'PROPOSED' or 'BLOCKED'.
3. T14-AC2: Hardcoded SQL/API 100,000 Toman settlement minimum is gone; changing
   OPEN-06 `min_amount_toman` (e.g. 50,000 or 250,000) dynamically governs HTTP
   settlement acceptance while SQL `chk_settlements_amount_positive CHECK (amount_toman > 0)`
   and non-negative wallet balance invariants stay enforced.
4. T14-AC3 & T14-AC4: Sequential duplicate and 10x concurrent HTTP
   `POST /api/v1/wallet/settle` requests produce AT MOST ONE HTTP 200 and
   deterministic HTTP 409 Conflict (PostgreSQL 23505) with ZERO double fund
   locking, ZERO duplicate ledger debits, and full transactional rollback.
"""

import asyncio
import os
import sys
import uuid

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t14",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/2")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import (  # noqa: E402
    get_all_open_policy_statuses,
    get_policy_record,
    set_policy_approval,
)
from src.core.settings import EXPECTED_OPEN_KEYS, load_runtime_policy_partition  # noqa: E402
from src.wallets.service import WalletService  # noqa: E402

DEFAULT_VALUES = {
    "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN": {"min_amount_toman": 100000, "lock_on_request": True},
    "OPEN_08_MULTI_ACTIVE_PLANS_PER_HOLDER": {
        "allow_multiple_active_plans": False,
        "extension_adds_to_end_date": True,
    },
}


async def _reset_all_open_policies(conn: asyncpg.Connection) -> None:
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
    for k, val in DEFAULT_VALUES.items():
        import json

        await conn.execute(
            "UPDATE system_settings SET value_json = $2::jsonb WHERE key = $1;",
            k,
            json.dumps(val),
        )


@pytest_asyncio.fixture
async def db_pool():
    await close_pool()
    close_redis()
    pool = await init_pool()
    init_redis()
    async with pool.acquire() as conn:
        await _reset_all_open_policies(conn)
    try:
        yield pool
    finally:
        async with pool.acquire() as conn:
            await _reset_all_open_policies(conn)
        await close_pool()
        close_redis()


async def _create_user_with_session(
    pool: asyncpg.Pool,
    mobile_prefix: str = "0981",
    roles: list[str] | None = None,
):
    roles = roles or ["USER"]
    mobile = f"{mobile_prefix}{uuid.uuid4().int % 10000000:07d}"
    async with pool.acquire() as conn:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', $2, TRUE)
            RETURNING id;
            """,
            mobile,
            roles,
        )
        for r in roles:
            await conn.execute(
                """
                INSERT INTO user_roles (user_id, role_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING;
                """,
                user_id,
                r,
            )
    sess = await SessionService(pool).create_session(
        user_id=user_id,
        device_info="hc-t14-pytest",
        ip_address="127.0.0.1",
    )
    return user_id, {"Authorization": f"Bearer {sess['refresh_token']}"}


@pytest.mark.asyncio
async def test_t14_ac1_open_01_to_18_independent_traceability(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        keys = [s["key"] for s in statuses]
        assert sorted(keys) == sorted(EXPECTED_OPEN_KEYS)
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)

        partition = await load_runtime_policy_partition(conn)
        assert len(partition["proposed"]) == 18
        assert len(partition["approved"]) == 0
        assert len(partition["blocked"]) == 0

        owner_id = await conn.fetchval(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"SUPER_ADMIN\"}') RETURNING id;",
            f"0980{uuid.uuid4().int % 10000000:07d}",
        )

        # Independently approve OPEN_02 and block OPEN_08 without affecting others
        rec_open2 = await set_policy_approval(
            conn, "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE", "APPROVED", actor_user_id=owner_id
        )
        rec_open8 = await set_policy_approval(
            conn, "OPEN_08_MULTI_ACTIVE_PLANS_PER_HOLDER", "BLOCKED", actor_user_id=owner_id
        )
        assert rec_open2["approval_status"] == "APPROVED"
        assert rec_open2["approved_by"] == str(owner_id)
        assert rec_open2["approved_at"] is not None
        assert rec_open8["approval_status"] == "BLOCKED"
        assert rec_open8["approved_by"] is None

        partition_after = await load_runtime_policy_partition(conn)
        assert list(partition_after["approved"].keys()) == ["OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE"]
        assert list(partition_after["blocked"].keys()) == ["OPEN_08_MULTI_ACTIVE_PLANS_PER_HOLDER"]
        assert len(partition_after["proposed"]) == 16

        audit_count = await conn.fetchval(
            """
            SELECT count(*) FROM audit_logs
            WHERE action = 'POLICY_APPROVAL_UPDATED'
              AND entity_id IN ('OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE', 'OPEN_08_MULTI_ACTIVE_PLANS_PER_HOLDER');
            """
        )
        assert audit_count >= 2


@pytest.mark.asyncio
async def test_t14_ac1_financial_endpoints_disabled_until_policy_approved(db_pool: asyncpg.Pool):
    user_id, user_headers = await _create_user_with_session(db_pool, "0981", ["USER"])
    admin_id, admin_headers = await _create_user_with_session(db_pool, "0982", ["ADMIN"])
    doc_user_id, doc_headers = await _create_user_with_session(db_pool, "0983", ["DOCTOR"])
    agent_user_id, _ = await _create_user_with_session(db_pool, "0984", ["AGENT"])

    async with db_pool.acquire() as conn:
        holder_id = await conn.fetchval(
            """
            INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
            VALUES ('نگار', 'پارسا', $1, $2) RETURNING id;
            """,
            f"{uuid.uuid4().int % 10000000000:010d}",
            f"0985{uuid.uuid4().int % 10000000:07d}",
        )
        plan_id = await conn.fetchval("SELECT id FROM discount_plans LIMIT 1;")
        doc_id = await conn.fetchval(
            """
            INSERT INTO doctors (
                user_id, medical_council_code, specialty, clinic_name,
                province_id, city_id, clinic_address, clinic_phone,
                verification_status, is_public_listed
            ) VALUES ($1, $2, 'General', 'T14 Clinic', 1, 1, 'Tehran', '0212222', 'APPROVED', TRUE)
            RETURNING id;
            """,
            doc_user_id,
            f"T14MED-{uuid.uuid4().hex[:6]}",
        )
        mem_id = await conn.fetchval(
            """
            INSERT INTO memberships (
                holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status
            ) VALUES ($1, $2, NOW(), NOW() + INTERVAL '30 days', 3, 3, 0, 'ACTIVE')
            RETURNING id;
            """,
            holder_id,
            plan_id,
        )
        agent_id = await conn.fetchval(
            """
            INSERT INTO agents (user_id, business_name, province_id, city_id, verification_status)
            VALUES ($1, 'نمایندگی تست ۱۴', 1, 1, 'APPROVED') RETURNING id;
            """,
            agent_user_id,
        )
        case_id = await conn.fetchval(
            """
            INSERT INTO sales_cases (agent_id, holder_id, plan_id, logistic_status, financial_status)
            VALUES ($1, $2, $3, 'APPROVED', 'PAYMENT_RECORDED') RETURNING id;
            """,
            agent_id,
            holder_id,
            plan_id,
        )
        order_id = await conn.fetchval(
            """
            INSERT INTO orders_payments (
                buyer_user_id, holder_id, plan_id, amount_toman, status, idempotency_key
            ) VALUES ($1, $2, $3, 350000, 'PENDING', $4) RETURNING id;
            """,
            user_id,
            holder_id,
            plan_id,
            f"T14-ORD-{uuid.uuid4().hex}",
        )
        await conn.execute(
            "INSERT INTO wallets (user_id, withdrawable_balance_toman) VALUES ($1, 500000);",
            user_id,
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Wallet settle while OPEN_06 & OPEN_18 are PROPOSED -> 403 Forbidden
        r_settle = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 150000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "نگار پارسا",
            },
            headers=user_headers,
        )
        assert r_settle.status_code == 403, r_settle.text
        assert "PROPOSED" in r_settle.json()["detail"]

        # 2. Payment fulfill while OPEN_18 is PROPOSED -> 403 Forbidden
        r_pay = await client.post(
            f"/api/v1/payments/orders/{order_id}/verify",
            json={"gateway_transaction_id": "TX-1", "gateway_tracking_code": "TRK-1"},
            headers=user_headers,
        )
        assert r_pay.status_code == 403, r_pay.text
        assert "OPEN_18" in r_pay.json()["detail"]

        # 3. Sales finalization while OPEN_03 / OPEN_18 are PROPOSED -> 403 Forbidden
        r_sale = await client.post(
            f"/api/v1/sales/cases/{case_id}/finalize",
            headers=admin_headers,
        )
        assert r_sale.status_code == 403, r_sale.text
        assert "PROPOSED" in r_sale.json()["detail"]

        # 4. Visit record while OPEN_18 / OPEN_16 are PROPOSED -> 403 Forbidden
        r_visit = await client.post(
            "/api/v1/visits/record",
            json={
                "doctor_id": str(doc_id),
                "holder_id": str(holder_id),
                "membership_id": str(mem_id),
                "service_title": "معاینه",
                "total_amount_toman": 200000,
                "discount_percent": 20.0,
            },
            headers=doc_headers,
        )
        assert r_visit.status_code == 403, r_visit.text

        # 5. BLOCKED state must also stay disabled (403)
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "BLOCKED")
            await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
        r_settle_blocked = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 150000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "نگار پارسا",
            },
            headers=user_headers,
        )
        assert r_settle_blocked.status_code == 403, r_settle_blocked.text
        assert "BLOCKED" in r_settle_blocked.json()["detail"]

    # Confirm zero financial side effects occurred
    async with db_pool.acquire() as conn:
        w = await conn.fetchrow(
            "SELECT withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1;",
            user_id,
        )
        assert w["withdrawable_balance_toman"] == 500000
        assert w["locked_balance_toman"] == 0
        settle_cnt = await conn.fetchval(
            "SELECT count(*) FROM settlements WHERE user_id = $1;", user_id
        )
        assert settle_cnt == 0
        ord_status = await conn.fetchval(
            "SELECT status FROM orders_payments WHERE id = $1;", order_id
        )
        assert ord_status == "PENDING"
        sale_fin = await conn.fetchval(
            "SELECT financial_status FROM sales_cases WHERE id = $1;", case_id
        )
        assert sale_fin == "PAYMENT_RECORDED"


@pytest.mark.asyncio
async def test_t14_ac2_dynamic_settlement_minimum_without_hardcoded_sql(db_pool: asyncpg.Pool):
    user_id, user_headers = await _create_user_with_session(db_pool, "0986", ["USER"])
    wallet_svc = WalletService(db_pool)

    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
        # Dynamically lower minimum to 50,000 Toman (below old hardcoded 100,000 SQL check!)
        await set_policy_approval(
            conn,
            "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN",
            "APPROVED",
            updated_value_json={"min_amount_toman": 50000, "lock_on_request": True},
        )

    await wallet_svc.credit_commission(
        user_id=user_id,
        amount_toman=500000,
        reference_id="T14-DYN-MIN",
        idempotency_key=f"T14-CRED-{uuid.uuid4().hex}",
        description="تست حداقل تسویه پویا",
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 60,000 Toman previously failed old SQL `amount_toman >= 100000` check! Now MUST SUCCEED.
        r_low_ok = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 60000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "تست حداقل",
            },
            headers=user_headers,
        )
        assert r_low_ok.status_code == 200, r_low_ok.text
        settle_id = r_low_ok.json()["id"]
        assert r_low_ok.json()["amount_toman"] == 60000

        # Resolve first settlement cleanly and test dynamically raised minimum = 250,000 Toman
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE settlements SET status = 'REJECTED', rejection_reason = 'test' WHERE id = $1;",
                uuid.UUID(settle_id),
            )
            await set_policy_approval(
                conn,
                "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN",
                "APPROVED",
                updated_value_json={"min_amount_toman": 250000, "lock_on_request": True},
            )
        await wallet_svc.refund_locked_settlement(
            user_id=user_id,
            amount_toman=60000,
            settlement_id=uuid.UUID(settle_id),
            idempotency_key=f"REF-{uuid.uuid4().hex}",
            reason="re-open for high min test",
        )

        # 150,000 Toman was valid under old 100k rule, but now rejected dynamically under 250k!
        r_high_reject = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 150000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "تست حداقل",
            },
            headers=user_headers,
        )
        assert r_high_reject.status_code == 400, r_high_reject.text
        assert "250000" in r_high_reject.json()["detail"]

        # Positive-only schema validation blocks <= 0
        r_zero = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 0,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "تست صفر",
            },
            headers=user_headers,
        )
        assert r_zero.status_code == 422

    # Verify SQL invariants directly: negative settlement amount and negative wallet balance blocked
    async with db_pool.acquire() as conn:
        wallet_id = await conn.fetchval(
            "SELECT id FROM wallets WHERE user_id = $1;", user_id
        )
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO settlements (
                    user_id, wallet_id, amount_toman, bank_card_number,
                    bank_sheba_number, bank_account_holder_name, status
                ) VALUES ($1, $2, -500, '6037991199999990', 'IR630170000000100412345678', 'x', 'PENDING');
                """,
                user_id,
                wallet_id,
            )
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                "UPDATE wallets SET withdrawable_balance_toman = -1 WHERE id = $1;",
                wallet_id,
            )


@pytest.mark.asyncio
async def test_t14_ac3_ac4_http_settle_23505_atomic_sequential_and_concurrent(db_pool: asyncpg.Pool):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    # Part A: Sequential duplicate HTTP POST /api/v1/wallet/settle
    user_seq_id, seq_headers = await _create_user_with_session(db_pool, "0987", ["USER"])
    wallet_svc = WalletService(db_pool)
    await wallet_svc.credit_commission(
        user_id=user_seq_id,
        amount_toman=1000000,
        reference_id="T14-SEQ",
        idempotency_key=f"SEQ-{uuid.uuid4().hex}",
        description="Sequential settlement test",
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r1 = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 300000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "کاربر ترتیبی",
            },
            headers=seq_headers,
        )
        assert r1.status_code == 200, r1.text

        r2 = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 200000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "کاربر ترتیبی",
            },
            headers=seq_headers,
        )
        assert r2.status_code == 409, r2.text

    async with db_pool.acquire() as conn:
        w_seq = await conn.fetchrow(
            "SELECT id, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1;",
            user_seq_id,
        )
        assert w_seq["withdrawable_balance_toman"] == 700000
        assert w_seq["locked_balance_toman"] == 300000
        lock_rows = await conn.fetchval(
            "SELECT count(*) FROM wallet_ledger_entries WHERE wallet_id = $1 AND entry_type = 'SETTLEMENT_LOCK';",
            w_seq["id"],
        )
        assert lock_rows == 1, f"Expected 1 lock ledger entry, got {lock_rows}"
        settle_rows = await conn.fetchval(
            "SELECT count(*) FROM settlements WHERE user_id = $1;",
            user_seq_id,
        )
        assert settle_rows == 1

    # Part B: 10x concurrent HTTP POST /api/v1/wallet/settle race
    user_race_id, race_headers = await _create_user_with_session(db_pool, "0988", ["USER"])
    await wallet_svc.credit_commission(
        user_id=user_race_id,
        amount_toman=2000000,
        reference_id="T14-RACE",
        idempotency_key=f"RACE-{uuid.uuid4().hex}",
        description="Concurrent HTTP settlement race",
    )

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        async def _fire_settle(idx: int):
            return await client.post(
                "/api/v1/wallet/settle",
                json={
                    "amount_toman": 400000,
                    "bank_card_number": "6037991199999990",
                    "bank_sheba_number": "IR630170000000100412345678",
                    "bank_account_holder_name": f"مسابقه {idx}",
                },
                headers=race_headers,
            )

        responses = await asyncio.gather(*[_fire_settle(i) for i in range(10)])

    codes = [resp.status_code for resp in responses]
    assert codes.count(200) == 1, f"Expected exact 1 HTTP 200, got codes={codes}"
    assert codes.count(409) == 9, f"Expected exact 9 HTTP 409, got codes={codes}"

    async with db_pool.acquire() as conn:
        w_race = await conn.fetchrow(
            "SELECT id, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1;",
            user_race_id,
        )
        assert w_race["withdrawable_balance_toman"] == 1600000
        assert w_race["locked_balance_toman"] == 400000
        race_locks = await conn.fetchval(
            "SELECT count(*) FROM wallet_ledger_entries WHERE wallet_id = $1 AND entry_type = 'SETTLEMENT_LOCK';",
            w_race["id"],
        )
        assert race_locks == 1, f"Expected exactly 1 SETTLEMENT_LOCK ledger row, got {race_locks}"
        race_settles = await conn.fetchval(
            "SELECT count(*) FROM settlements WHERE user_id = $1;", user_race_id
        )
        assert race_settles == 1


@pytest.mark.asyncio
async def test_t14_approved_commission_floor_rounding_and_policy_record(db_pool: asyncpg.Pool):
    user_id, user_headers = await _create_user_with_session(db_pool, "0989", ["USER"])
    ref_user_id, _ = await _create_user_with_session(db_pool, "0990", ["USER"])

    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_05_COMBINED_COMMISSION_POLICY", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")
        rec = await get_policy_record(conn, "OPEN_18_CURRENCY_AND_ROUNDING")
        assert rec["approval_status"] == "APPROVED"

        holder_id = await conn.fetchval(
            """
            INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
            VALUES ('بهرام', 'کاظمی', $1, $2) RETURNING id;
            """,
            f"{uuid.uuid4().int % 10000000000:010d}",
            f"0991{uuid.uuid4().int % 10000000:07d}",
        )
        # 333,333 Toman * 10% = 33,333.3 -> FLOOR must yield 33,333
        plan_id = await conn.fetchval(
            """
            INSERT INTO discount_plans (
                title, price_toman, discount_percent, validity_days, referrer_commission_percent
            ) VALUES ('طرح تست رند کف', 333333, 25.0, 90, 10.0) RETURNING id;
            """
        )
        ref_code = f"HAMI-{uuid.uuid4().hex[:6].upper()}"
        await conn.execute(
            """
            INSERT INTO referrals (referrer_user_id, referred_user_id, referral_code, status)
            VALUES ($1, $2, $3, 'ACTIVE');
            """,
            ref_user_id,
            user_id,
            ref_code,
        )
        order_id = await conn.fetchval(
            """
            INSERT INTO orders_payments (
                buyer_user_id, holder_id, plan_id, amount_toman, status, idempotency_key
            ) VALUES ($1, $2, $3, 333333, 'PENDING', $4) RETURNING id;
            """,
            user_id,
            holder_id,
            plan_id,
            f"T14-FLR-{uuid.uuid4().hex}",
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_ok = await client.post(
            f"/api/v1/payments/orders/{order_id}/verify",
            json={
                "gateway_transaction_id": "TX-FLR",
                "gateway_tracking_code": "TRK-FLR",
                "referral_code": ref_code,
            },
            headers=user_headers,
        )
        assert r_ok.status_code == 200, r_ok.text
        data = r_ok.json()
        assert data["referral_commission"]["amount_toman"] == 33333
