"""
Automated Security & Isolation Guard Tests for HC-T40 (HC-CMD-041 / P3-01)
Verifies scripts/run_phase3_t39_demo.py fails closed before any SQL write on:
1. Production/staging/conflicting environment variables
2. Inherited ambient DATABASE_URL / missing explicit HAMICARD_DEMO_DATABASE_URL
3. Production, non-local, or shared (hamicard_dev) DSNs
4. Missing or mismatched positive DB isolation marker (`shobj_description`)
5. Existing non-demo account collision (refuses to silently replace password or roles)
6. Reproducible isolated seeding + marker-gated safe `--cleanup-demo` leaving zero non-demo changes
"""

import pathlib
import uuid

import asyncpg
import pytest

from scripts.run_phase3_t39_demo import (
    ISOLATION_MARKER_PREFIX,
    cleanup_isolated_demo_users,
    seed_isolated_demo_users,
    validate_demo_dsn_inputs,
)
from src.core.policy import get_all_open_policy_statuses
from src.core.security import hash_password

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
INIT_SQL = (ROOT_DIR / "db" / "init.sql").read_text(encoding="utf-8")

ADMIN_PG_DSN = "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/postgres"
SHARED_DEV_DSN = "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
ISOLATED_REDIS_URL = "redis://localhost:6379/0"


@pytest.mark.asyncio
async def test_t40_demo_db_guards_and_safe_cleanup(monkeypatch):
    # 1. Negative: inherited DATABASE_URL without explicit HAMICARD_DEMO_DATABASE_URL MUST fail
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("NODE_ENV", raising=False)
    monkeypatch.setenv("DATABASE_URL", SHARED_DEV_DSN)
    monkeypatch.delenv("HAMICARD_DEMO_DATABASE_URL", raising=False)
    monkeypatch.setenv("HAMICARD_DEMO_REDIS_URL", ISOLATED_REDIS_URL)
    monkeypatch.setenv("HAMICARD_DEMO_ISOLATION_MARKER", "t40-isolated-marker-1234")

    with pytest.raises(Exception, match="HAMICARD_DEMO_DATABASE_URL"):
        validate_demo_dsn_inputs(None, None, None)

    # 2. Negative: conflicting inherited DATABASE_URL vs explicit HAMICARD_DEMO_DATABASE_URL
    isolated_db_name = f"hamicard_t40_{uuid.uuid4().hex[:8]}_demo"
    isolated_dsn = f"postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/{isolated_db_name}"
    monkeypatch.setenv("HAMICARD_DEMO_DATABASE_URL", isolated_dsn)
    monkeypatch.setenv("REDIS_URL", ISOLATED_REDIS_URL)
    with pytest.raises(Exception, match="Ambient DATABASE_URL differs"):
        validate_demo_dsn_inputs(None, None, None)

    monkeypatch.delenv("DATABASE_URL", raising=False)

    # 3. Negative: production / staging / conflicting environment variables
    for bad_env in ("production", "staging", "invalid_env"):
        monkeypatch.setenv("ENVIRONMENT", bad_env)
        with pytest.raises(Exception, match="FAIL-CLOSED"):
            validate_demo_dsn_inputs(None, None, None)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("APP_ENV", "development")
    with pytest.raises(Exception, match="FAIL-CLOSED"):
        validate_demo_dsn_inputs(None, None, None)
    monkeypatch.delenv("APP_ENV", raising=False)

    # 4. Negative: production host, remote host, and shared hamicard_dev rejected
    for bad_dsn in (
        "postgresql://user:pass@rds.amazonaws.com:5432/hamicard_demo",
        "postgresql://hamicard:pass@localhost:5432/hamicard_prod",
        SHARED_DEV_DSN,
    ):
        with pytest.raises(Exception, match="FAIL-CLOSED DEMO"):
            validate_demo_dsn_inputs(bad_dsn, ISOLATED_REDIS_URL, "valid-marker-999999")

    # 5. Negative: weak or missing isolation marker rejected
    with pytest.raises(Exception, match="ISOLATION_MARKER"):
        validate_demo_dsn_inputs(isolated_dsn, ISOLATED_REDIS_URL, "short")

    # Provision a real isolated disposable PostgreSQL DB for positive + existing-user + marker tests
    admin_conn = await asyncpg.connect(ADMIN_PG_DSN)
    try:
        await admin_conn.execute(f'CREATE DATABASE "{isolated_db_name}";')
    finally:
        await admin_conn.close()

    try:
        iso_conn = await asyncpg.connect(isolated_dsn)
        try:
            await iso_conn.execute(INIT_SQL)
        finally:
            await iso_conn.close()

        # 6. Negative: DB exists and has schema, but NO positive pg_database isolation marker yet -> MUST FAIL
        with pytest.raises(Exception, match="missing the required positive isolation marker"):
            await seed_isolated_demo_users(isolated_dsn, ISOLATED_REDIS_URL, "t40-isolated-marker-1234")

        # Tag DB positively with expected marker comment
        marker = "t40-isolated-marker-1234"
        tag_conn = await asyncpg.connect(isolated_dsn)
        try:
            comment_sql = f"COMMENT ON DATABASE \"{isolated_db_name}\" IS '{ISOLATION_MARKER_PREFIX}{marker}';"
            await tag_conn.execute(comment_sql)
            # Also insert a non-demo sentinel user that MUST NEVER be touched by seed or cleanup
            sentinel_id = await tag_conn.fetchval(
                """
                INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
                VALUES ('09129998877', $1, 'ACTIVE', TRUE)
                RETURNING id;
                """,
                hash_password("KeepMeUntouched!1"),
            )
            # And pre-insert ONE overlapping mobile to prove seed refuses silent password/role overwrite!
            await tag_conn.execute(
                """
                INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
                VALUES ('09999000001', $1, 'ACTIVE', TRUE);
                """,
                hash_password("ExistingUserOriginalPwd!1"),
            )
        finally:
            await tag_conn.close()

        # 7. Negative: pre-existing user on '09999000001' must block overwrite
        with pytest.raises(Exception, match="Refusing to silently overwrite existing user account"):
            await seed_isolated_demo_users(isolated_dsn, ISOLATED_REDIS_URL, marker)

        # Clean that pre-existing collision cleanly and seed fresh isolated demo
        clr_conn = await asyncpg.connect(isolated_dsn)
        try:
            await clr_conn.execute("DELETE FROM users WHERE mobile = '09999000001';")
        finally:
            await clr_conn.close()

        # 8. Positive: isolated DB + valid marker + fresh deterministic disposable accounts succeed
        seeded = await seed_isolated_demo_users(isolated_dsn, ISOLATED_REDIS_URL, marker)
        assert seeded["USER"] == "09999000001"
        assert seeded["DOCTOR"] == "09999000002"
        assert seeded["ADMIN"] == "09999000003"
        assert seeded["password"].startswith("Demo-")

        # Re-running without cleanup refuses overwrite!
        with pytest.raises(Exception, match="Refusing to silently overwrite"):
            await seed_isolated_demo_users(isolated_dsn, ISOLATED_REDIS_URL, marker)

        # 9. Wrong marker refuses cleanup too!
        with pytest.raises(Exception, match="missing the required positive isolation marker"):
            await cleanup_isolated_demo_users(isolated_dsn, "wrong-marker-000000")

        # 10. Safe cleanup deletes ONLY the 3 disposable accounts; sentinel user & 18 OPEN-* PROPOSED stay untouched!
        removed = await cleanup_isolated_demo_users(isolated_dsn, marker)
        assert removed == 3

        chk_conn = await asyncpg.connect(isolated_dsn)
        try:
            still_sentinel = await chk_conn.fetchval("SELECT id FROM users WHERE mobile = '09129998877';")
            assert still_sentinel == sentinel_id
            statuses = await get_all_open_policy_statuses(chk_conn)
            assert len(statuses) == 18
            assert all(s["approval_status"] == "PROPOSED" for s in statuses)
        finally:
            await chk_conn.close()
    finally:
        drop_conn = await asyncpg.connect(ADMIN_PG_DSN)
        try:
            await drop_conn.execute(f'DROP DATABASE IF EXISTS "{isolated_db_name}" WITH (FORCE);')
        finally:
            await drop_conn.close()
