"""
Financial Idempotency, PII Masking & Migration Dry-Run Verification Suite for HC-T20
Scope: T20-AC1..AC4 | SETTLE-001..017, WALLET-001..010, AC-12, BR-15/21
Target DB: Isolated `hamicard_t20` + Redis DB 6 (plus throwaway mig DBs cleaned in finally)
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t20",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/6")

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from src.api.deps import close_pool, close_redis, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import set_policy_approval  # noqa: E402
from src.wallets.service import DuplicateFinancialTransactionError, WalletService  # noqa: E402

DEFAULT_POLICIES = {
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


async def _create_user_session(pool: asyncpg.Pool, prefix: str, roles: list[str] | None = None):
    roles = roles or ["USER"]
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
    sess = await SessionService(pool).create_session(user_id=uid, device_info="t20-test", ip_address="127.0.0.1")
    return uid, {"Authorization": f"Bearer {sess['refresh_token']}"}


def _run_psql_sql(db_name: str, sql_text: str) -> None:
    pg_url = os.getenv(
        "DATABASE_URL",
        "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t20",
    )
    psql_bin = shutil.which("psql")
    if psql_bin:
        base_prefix = pg_url.rsplit("/", 1)[0]
        cmd = [psql_bin, f"{base_prefix}/{db_name}", "-v", "ON_ERROR_STOP=1"]
    else:
        container = os.getenv("HAMICARD_PG_CONTAINER", "hamicard_postgres_dev")
        cmd = [
            "docker",
            "exec",
            "-i",
            container,
            "psql",
            "-U",
            "hamicard",
            "-d",
            db_name,
            "-v",
            "ON_ERROR_STOP=1",
        ]
    proc = subprocess.run(
        cmd,
        input=sql_text.encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"psql execution failed on {db_name} (rc={proc.returncode}):\n"
            f"STDOUT: {proc.stdout.decode('utf-8', errors='replace')}\n"
            f"STDERR: {proc.stderr.decode('utf-8', errors='replace')}"
        )


@pytest.mark.asyncio
async def test_t20_ac1_ac2_idempotency_key_replay_concurrency_conflict_and_masking(
    db_pool: asyncpg.Pool,
):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    user_a, hdrs_a = await _create_user_session(db_pool, "0970", ["USER"])
    user_b, hdrs_b = await _create_user_session(db_pool, "0971", ["USER"])
    wallet_svc = WalletService(db_pool)

    await wallet_svc.credit_commission(
        user_id=user_a,
        amount_toman=1500000,
        reference_id="T20-CRED-A",
        idempotency_key=f"T20-A-{uuid.uuid4().hex}",
        description="تست موجودی تسویه کاربر الف",
    )
    await wallet_svc.credit_commission(
        user_id=user_b,
        amount_toman=1500000,
        reference_id="T20-CRED-B",
        idempotency_key=f"T20-B-{uuid.uuid4().hex}",
        description="تست موجودی تسویه کاربر ب",
    )

    valid_card = "6037991199999990"
    valid_sheba = "IR630170000000100412345678"
    payload_a = {
        "amount_toman": 250000,
        "bank_card_number": valid_card,
        "bank_sheba_number": valid_sheba,
        "bank_account_holder_name": "کاربر تستی الف",
    }
    shared_key = f"client-settle-{uuid.uuid4().hex}"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 0. Invalid short/whitespace Idempotency-Key -> 400
        r_bad_key = await client.post(
            "/api/v1/wallet/settle",
            json=payload_a,
            headers={**hdrs_a, "Idempotency-Key": "   "},
        )
        assert r_bad_key.status_code == 400

        # 1. Concurrent identical requests with same Idempotency-Key -> ALL 200 returning SAME settlement ID, locked ONCE!
        concurrent_resps = await asyncio.gather(
            *[
                client.post(
                    "/api/v1/wallet/settle",
                    json=payload_a,
                    headers={**hdrs_a, "Idempotency-Key": shared_key},
                )
                for _ in range(8)
            ]
        )
        assert all(r.status_code == 200 for r in concurrent_resps), [
            (r.status_code, r.text) for r in concurrent_resps
        ]
        returned_ids = {r.json()["id"] for r in concurrent_resps}
        assert len(returned_ids) == 1
        settlement_id = next(iter(returned_ids))
        replay_flags = [r.json()["idempotent_replay"] for r in concurrent_resps]
        assert replay_flags.count(False) == 1
        assert replay_flags.count(True) == 7

        # PII masking in HTTP response (SETTLE-015)
        sample = concurrent_resps[0].json()
        assert sample["bank_card_number"] == "6037********9990"
        assert sample["bank_card_number"] != valid_card
        assert sample["bank_sheba_number"] == "IR** **** **** **** **** **78"
        assert sample["bank_sheba_number"] != valid_sheba

        # 2. Sequential replay with identical payload -> 200, idempotent_replay=True
        r_seq = await client.post(
            "/api/v1/wallet/settle",
            json=payload_a,
            headers={**hdrs_a, "Idempotency-Key": shared_key},
        )
        assert r_seq.status_code == 200
        assert r_seq.json()["id"] == settlement_id
        assert r_seq.json()["idempotent_replay"] is True

        # 3. Payload conflict on reused Idempotency-Key -> 409 Conflict (T20-AC2)
        for mutated in (
            {**payload_a, "amount_toman": 260000},
            {**payload_a, "bank_card_number": "6037991199999982"},
            {**payload_a, "bank_sheba_number": "IR062960000000100324200001"},
            {**payload_a, "bank_account_holder_name": "شخص دیگر"},
        ):
            r_conf = await client.post(
                "/api/v1/wallet/settle",
                json=mutated,
                headers={**hdrs_a, "Idempotency-Key": shared_key},
            )
            assert r_conf.status_code == 409, f"Expected 409 for {mutated}, got {r_conf.status_code}: {r_conf.text}"

        # 4. Fail-closed still wins over idempotent replay when OPEN_06 reverts to PROPOSED -> 403
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "PROPOSED")
        r_prop = await client.post(
            "/api/v1/wallet/settle",
            json=payload_a,
            headers={**hdrs_a, "Idempotency-Key": shared_key},
        )
        assert r_prop.status_code == 403
        async with db_pool.acquire() as conn:
            await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")

        # 5. Cross-user key isolation: User B using exact same raw Idempotency-Key succeeds independently
        r_b = await client.post(
            "/api/v1/wallet/settle",
            json={**payload_a, "amount_toman": 300000},
            headers={**hdrs_b, "Idempotency-Key": shared_key},
        )
        assert r_b.status_code == 200, r_b.text
        assert r_b.json()["id"] != settlement_id
        assert r_b.json()["idempotent_replay"] is False

    # DB invariant verification: User A locked 250,000 ONCE & raw bank fields stored in DB
    async with db_pool.acquire() as conn:
        w_a = await conn.fetchrow(
            "SELECT id, withdrawable_balance_toman, locked_balance_toman FROM wallets WHERE user_id = $1;",
            user_a,
        )
        assert w_a["withdrawable_balance_toman"] == 1250000
        assert w_a["locked_balance_toman"] == 250000
        lock_cnt_a = await conn.fetchval(
            "SELECT count(*) FROM wallet_ledger_entries WHERE wallet_id = $1 AND entry_type = 'SETTLEMENT_LOCK';",
            w_a["id"],
        )
        assert lock_cnt_a == 1
        db_settle = await conn.fetchrow(
            "SELECT bank_card_number, bank_sheba_number FROM settlements WHERE id = $1;",
            uuid.UUID(settlement_id),
        )
        assert db_settle["bank_card_number"] == valid_card
        assert db_settle["bank_sheba_number"] == valid_sheba


@pytest.mark.asyncio
async def test_t20_ac3_duplicate_financial_tx_409_and_concurrent_ledger_serialization(
    db_pool: asyncpg.Pool, monkeypatch
):
    async with db_pool.acquire() as conn:
        await set_policy_approval(conn, "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX", "APPROVED")
        await set_policy_approval(conn, "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN", "APPROVED")
        await set_policy_approval(conn, "OPEN_18_CURRENCY_AND_ROUNDING", "APPROVED")

    uid, hdrs = await _create_user_session(db_pool, "0972", ["USER"])
    admin_uid, _ = await _create_user_session(db_pool, "0973", ["SUPER_ADMIN"])
    wallet_svc = WalletService(db_pool)

    # 1. Concurrent identical credit_commission -> serialized by FOR UPDATE, credited ONCE without raising 500/UniqueViolation
    shared_cred_key = f"CONC-CRED-{uuid.uuid4().hex}"
    await asyncio.gather(
        *[
            wallet_svc.credit_commission(
                user_id=uid,
                amount_toman=400000,
                reference_id="CONC-REF",
                idempotency_key=shared_cred_key,
                description="تست واریز همزمان",
            )
            for _ in range(8)
        ]
    )
    w = await wallet_svc.get_wallet_by_user_id(uid)
    assert w["withdrawable_balance_toman"] == 400000

    # 2. Duplicate payout / refund idempotency keys raise DuplicateFinancialTransactionError (never double-debit/refund)
    s_id = uuid.uuid4()
    await wallet_svc.lock_funds_for_settlement(uid, 200000, s_id, f"LCK-{uuid.uuid4().hex}")
    pay_key = f"PAY-{uuid.uuid4().hex}"
    await wallet_svc.finalize_settlement_payout(uid, 200000, s_id, pay_key, admin_uid)
    with pytest.raises(DuplicateFinancialTransactionError):
        await wallet_svc.finalize_settlement_payout(uid, 200000, s_id, pay_key, admin_uid)

    s_id_2 = uuid.uuid4()
    await wallet_svc.lock_funds_for_settlement(uid, 150000, s_id_2, f"LCK2-{uuid.uuid4().hex}")
    ref_key = f"REF-{uuid.uuid4().hex}"
    await wallet_svc.refund_locked_settlement(uid, 150000, s_id_2, ref_key, "لغو آزمایشی")
    with pytest.raises(DuplicateFinancialTransactionError):
        await wallet_svc.refund_locked_settlement(uid, 150000, s_id_2, ref_key, "لغو تکراری")

    # 3. Direct DuplicateFinancialTransactionError triggered in POST /api/v1/wallet/settle maps to HTTP 409 Conflict (NOT 400)
    async def _raise_dup(*args, **kwargs):
        raise DuplicateFinancialTransactionError("Injected duplicate ledger key")

    monkeypatch.setattr(WalletService, "lock_funds_for_settlement", _raise_dup)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_dup = await client.post(
            "/api/v1/wallet/settle",
            json={
                "amount_toman": 120000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "تست خطای تکراری",
            },
            headers=hdrs,
        )
        assert r_dup.status_code == 409, f"Expected HTTP 409, got {r_dup.status_code}: {r_dup.text}"


@pytest.mark.asyncio
async def test_t20_ac4_migration_002_and_rollback_dry_run_fresh_and_legacy():
    pg_url = os.getenv(
        "DATABASE_URL",
        "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t20",
    )
    admin_url = pg_url.rsplit("/", 1)[0] + "/postgres"
    fresh_db = f"hamicard_mig_fresh_{uuid.uuid4().hex[:8]}"
    legacy_db = f"hamicard_mig_legacy_{uuid.uuid4().hex[:8]}"

    init_sql = (REPO_ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    mig_002_sql = (
        REPO_ROOT / "db" / "migrations" / "002_policy_approval_and_settlement_min.sql"
    ).read_text(encoding="utf-8")
    rollback_002_sql = (REPO_ROOT / "db" / "migrations" / "002_rollback.sql").read_text(
        encoding="utf-8"
    )
    legacy_proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", "9fdaa66:db/init.sql"],
        capture_output=True,
        check=True,
    )
    legacy_init_sql = legacy_proc.stdout.decode("utf-8")

    admin_conn = await asyncpg.connect(admin_url)
    try:
        await admin_conn.execute(f'CREATE DATABASE "{fresh_db}";')
        await admin_conn.execute(f'CREATE DATABASE "{legacy_db}";')
    finally:
        await admin_conn.close()

    try:
        # Path A: Fresh schema (init.sql + migration 002 with ON_ERROR_STOP=1)
        _run_psql_sql(fresh_db, init_sql)
        _run_psql_sql(fresh_db, mig_002_sql)

        fresh_conn = await asyncpg.connect(pg_url.rsplit("/", 1)[0] + f"/{fresh_db}")
        try:
            open_stats = await fresh_conn.fetchrow(
                "SELECT count(*) AS total, count(*) FILTER (WHERE approval_status = 'PROPOSED') AS proposed FROM system_settings WHERE key LIKE 'OPEN\\_%' ESCAPE '\\';"
            )
            assert open_stats["total"] == 18 and open_stats["proposed"] == 18
            has_idx = await fresh_conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = 'idx_one_open_settlement_per_user');"
            )
            has_chk = await fresh_conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname = 'chk_settlements_amount_positive');"
            )
            assert has_idx and has_chk
        finally:
            await fresh_conn.close()

        # Path B: Legacy schema upgrade (9fdaa66 -> 002 -> idempotent re-run 002 -> rollback 002 -> re-apply 002)
        _run_psql_sql(legacy_db, legacy_init_sql)
        _run_psql_sql(legacy_db, mig_002_sql)
        _run_psql_sql(legacy_db, mig_002_sql)  # Must be idempotent!

        leg_conn = await asyncpg.connect(pg_url.rsplit("/", 1)[0] + f"/{legacy_db}")
        try:
            open_stats_leg = await leg_conn.fetchrow(
                "SELECT count(*) AS total, count(*) FILTER (WHERE approval_status = 'PROPOSED') AS proposed FROM system_settings WHERE key LIKE 'OPEN\\_%' ESCAPE '\\';"
            )
            assert open_stats_leg["total"] == 18 and open_stats_leg["proposed"] == 18
            assert await leg_conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname = 'chk_settlements_amount_positive');"
            )
        finally:
            await leg_conn.close()

        # Rollback 002 cleanly
        _run_psql_sql(legacy_db, rollback_002_sql)
        leg_conn_rb = await asyncpg.connect(pg_url.rsplit("/", 1)[0] + f"/{legacy_db}")
        try:
            has_col = await leg_conn_rb.fetchval(
                "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = 'system_settings' AND column_name = 'approval_status');"
            )
            has_old_chk = await leg_conn_rb.fetchval(
                "SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname = 'settlements_amount_toman_check');"
            )
            assert not has_col and has_old_chk
        finally:
            await leg_conn_rb.close()

        # Re-apply 002 cleanly after rollback
        _run_psql_sql(legacy_db, mig_002_sql)
        leg_conn_re = await asyncpg.connect(pg_url.rsplit("/", 1)[0] + f"/{legacy_db}")
        try:
            re_stats = await leg_conn_re.fetchrow(
                "SELECT count(*) AS total, count(*) FILTER (WHERE approval_status = 'PROPOSED') AS proposed FROM system_settings WHERE key LIKE 'OPEN\\_%' ESCAPE '\\';"
            )
            assert re_stats["total"] == 18 and re_stats["proposed"] == 18
        finally:
            await leg_conn_re.close()
    finally:
        cleanup_conn = await asyncpg.connect(admin_url)
        try:
            await cleanup_conn.execute(
                f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ('{fresh_db}', '{legacy_db}') AND pid <> pg_backend_pid();"
            )
            await cleanup_conn.execute(f'DROP DATABASE IF EXISTS "{fresh_db}";')
            await cleanup_conn.execute(f'DROP DATABASE IF EXISTS "{legacy_db}";')
        finally:
            await cleanup_conn.close()
