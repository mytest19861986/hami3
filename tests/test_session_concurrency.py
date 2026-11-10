#!/usr/bin/env python3
"""
Session Security and Concurrency Test Suite (HC-T11 + HC-T13)
BASELINE: BL-HAMICARD-PRD-V1 | T11-AC1..AC4, T13-AC4..AC5, AC-14, AC-15

Verifies:
1. T13-AC4: Concurrent Refresh Race Condition (20 simultaneous rotation requests -> at most 1 successor,
   19 competing requests fail cleanly with ConcurrentRefreshConflictError and ZERO credential disclosure).
2. T11-AC2: Malicious token replay attack detection outside window triggers WHOLE-FAMILY REVOCATION + audit log.
3. T13-AC5: Session-family logout revokes ALL tokens in the family (including rotated ancestors & siblings).
4. T11-AC3: Account suspension immediately invalidates active session family across verify & rotation.
"""

import asyncio
import os
import sys
import uuid

import asyncpg

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.auth.session_service import (
    AccountBlockedError,
    ConcurrentRefreshConflictError,
    SecurityReplayAttackError,
    SessionService,
)

PG_DSN = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)


async def test_t13_ac4_concurrent_refresh_rotation(pool: asyncpg.Pool):
    """
    Validates T13-AC4 / F-01:
    20 concurrent tasks attempt to rotate the exact same refresh token simultaneously.
    Guarantees:
    - At most ONE valid successor credential is issued (`status == 'ROTATED'`).
    - All other 19 competing callers receive ConcurrentRefreshConflictError with ZERO token leakage.
    """
    print("\n[SESSION TEST 1/4] Testing T13-AC4: 20 Concurrent Refresh Calls Without Credential Disclosure...")
    session_svc = SessionService(pool)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
            """,
            f"0912{uuid.uuid4().int % 10000000:07d}",
        )

    initial_session = await session_svc.create_session(user_id=user_id)
    initial_refresh_token = initial_session["refresh_token"]
    family_id = uuid.UUID(initial_session["family_id"])

    async def attempt_refresh(worker_id: int):
        try:
            res = await session_svc.rotate_refresh_token(
                raw_refresh_token=initial_refresh_token,
                ip_address=f"192.168.1.{worker_id}",
                grace_period_seconds=5,
            )
            return {"worker_id": worker_id, "result": res, "error": None}
        except Exception as e:
            return {"worker_id": worker_id, "result": None, "error": type(e).__name__}

    results = await asyncio.gather(*(attempt_refresh(i) for i in range(20)))

    rotated_successors = [
        r for r in results if r["result"] and r["result"].get("status") == "ROTATED" and r["result"].get("refresh_token")
    ]
    conflict_failures = [r for r in results if r["error"] == ConcurrentRefreshConflictError.__name__]
    unexpected = [
        r for r in results
        if r not in rotated_successors and r not in conflict_failures
    ]

    print(
        f"  ✓ 20 simultaneous rotations finished: {len(rotated_successors)} ROTATED, "
        f"{len(conflict_failures)} SAFE_CONFLICT_409, {len(unexpected)} unexpected."
    )
    assert len(rotated_successors) == 1, f"Expected exactly 1 ROTATED successor, got {len(rotated_successors)}"
    assert len(conflict_failures) == 19, f"Expected 19 ConcurrentRefreshConflictError, got {len(conflict_failures)}"
    assert len(unexpected) == 0, f"Unexpected results: {unexpected}"

    async with pool.acquire() as conn:
        active_tokens = await conn.fetch(
            "SELECT id, status FROM refresh_tokens WHERE family_id = $1 AND status = 'ACTIVE';",
            family_id,
        )
        assert len(active_tokens) == 1, f"Expected exactly 1 ACTIVE token in family, found {len(active_tokens)}"

        rotated_tokens = await conn.fetch(
            "SELECT id, status FROM refresh_tokens WHERE family_id = $1 AND status = 'ROTATED';",
            family_id,
        )
        assert len(rotated_tokens) == 1, f"Expected exactly 1 ROTATED token in family, found {len(rotated_tokens)}"

    print("  ✓ T13-AC4 PASS: Exactly 1 usable successor created; zero successor disclosure on competing calls.")


async def test_t11_ac2_malicious_replay_detection(pool: asyncpg.Pool):
    """Validates replay attack detection outside safe window revokes entire session family."""
    print("\n[SESSION TEST 2/4] Testing AC-15 / T11-AC2: Token Family Replay Attack Detection...")
    session_svc = SessionService(pool)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
            """,
            f"0912{uuid.uuid4().int % 10000000:07d}",
        )

    sess1 = await session_svc.create_session(user_id=user_id)
    token_gen1 = sess1["refresh_token"]
    family_id = uuid.UUID(sess1["family_id"])

    sess2 = await session_svc.rotate_refresh_token(token_gen1)
    token_gen2 = sess2["refresh_token"]
    assert sess2["status"] == "ROTATED"

    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE refresh_tokens
            SET rotated_at = NOW() - INTERVAL '15 seconds'
            WHERE family_id = $1 AND status = 'ROTATED';
            """,
            family_id,
        )

    replay_detected = False
    try:
        await session_svc.rotate_refresh_token(token_gen1, ip_address="198.51.100.25")
    except SecurityReplayAttackError as e:
        replay_detected = True
        assert "Replay of already rotated token detected" in str(e)
    assert replay_detected, "Replay attack failed to trigger SecurityReplayAttackError!"

    async with pool.acquire() as conn:
        statuses = await conn.fetch("SELECT status FROM refresh_tokens WHERE family_id = $1;", family_id)
        for s in statuses:
            assert s["status"] == "REVOKED"

        audit_row = await conn.fetchrow(
            """
            SELECT action, entity_name, ip_address
            FROM audit_logs
            WHERE entity_id = $1 AND action = 'TOKEN_REPLAY_ATTACK_DETECTED';
            """,
            str(family_id),
        )
        assert audit_row is not None
        assert audit_row["ip_address"] == "198.51.100.25"

    assert await session_svc.verify_active_session(token_gen2) is None

    gen2_blocked = False
    try:
        await session_svc.rotate_refresh_token(token_gen2)
    except SecurityReplayAttackError:
        gen2_blocked = True
    assert gen2_blocked
    print("  ✓ T11-AC2 PASS: Replay attack terminated entire session lineage.")


async def test_t13_ac5_logout_revokes_entire_session_family(pool: asyncpg.Pool):
    """
    Validates T13-AC5 / F-05:
    Explicit logout revokes the ENTIRE session family (ancestor rotated + current active tokens),
    without disrupting independent sessions on other devices, and global logout revokes all.
    """
    print("\n[SESSION TEST 3/4] Testing T13-AC5: Session-Family Logout & Multi-Device Revocation...")
    session_svc = SessionService(pool)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
            """,
            f"0912{uuid.uuid4().int % 10000000:07d}",
        )

    sess_a1 = await session_svc.create_session(user_id=user_id, device_info="Chrome on Windows")
    sess_a2 = await session_svc.rotate_refresh_token(sess_a1["refresh_token"])
    sess_b = await session_svc.create_session(user_id=user_id, device_info="Safari on iPhone")
    sess_c = await session_svc.create_session(user_id=user_id, device_info="Firefox on Android")

    # Logout using active token on Device A -> must revoke BOTH A1 and A2
    revoked = await session_svc.revoke_session(sess_a2["refresh_token"])
    assert revoked is True

    async with pool.acquire() as conn:
        a_statuses = await conn.fetch(
            "SELECT status FROM refresh_tokens WHERE family_id = $1;",
            uuid.UUID(sess_a1["family_id"]),
        )
        assert len(a_statuses) == 2
        assert all(s["status"] == "REVOKED" for s in a_statuses)

    assert await session_svc.verify_active_session(sess_a2["refresh_token"]) is None

    dev_a_blocked = False
    try:
        await session_svc.rotate_refresh_token(sess_a2["refresh_token"])
    except SecurityReplayAttackError:
        dev_a_blocked = True
    assert dev_a_blocked
    print("  ✓ Single device logout revoked entire Family A lineage without affecting Device B.")

    res_b = await session_svc.rotate_refresh_token(sess_b["refresh_token"])
    assert res_b["status"] == "ROTATED"

    total_revoked = await session_svc.revoke_all_user_sessions(user_id)
    assert total_revoked >= 2

    for tok in (res_b["refresh_token"], sess_c["refresh_token"]):
        assert await session_svc.verify_active_session(tok) is None
        blocked = False
        try:
            await session_svc.rotate_refresh_token(tok)
        except SecurityReplayAttackError:
            blocked = True
        assert blocked

    print("  ✓ T13-AC5 PASS: Family logout & global logout immediately revoke session authority.")


async def test_account_suspension_revokes_active_session(pool: asyncpg.Pool):
    """Validates that suspending an account immediately invalidates active protected checks & rotation."""
    print("\n[SESSION TEST 4/4] Testing Session Invalidation upon Account Suspension...")
    session_svc = SessionService(pool)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
            """,
            f"0912{uuid.uuid4().int % 10000000:07d}",
        )

    sess = await session_svc.create_session(user_id=user_id)
    tok = sess["refresh_token"]

    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET status = 'SUSPENDED' WHERE id = $1;", user_id)

    # verify_active_session (used by protected endpoints) immediately fails & revokes family
    assert await session_svc.verify_active_session(tok) is None

    suspended_blocked = False
    try:
        await session_svc.rotate_refresh_token(tok)
    except (AccountBlockedError, SecurityReplayAttackError):
        suspended_blocked = True
    assert suspended_blocked
    print("  ✓ Suspended account immediately denied on protected session verification & rotation.")


async def main():
    print("=" * 75)
    print("HAMICARD SESSION SECURITY & CONCURRENCY VERIFICATION SUITE (HC-T11 + HC-T13)")
    print("=" * 75)

    pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=25)
    try:
        await test_t13_ac4_concurrent_refresh_rotation(pool)
        await test_t11_ac2_malicious_replay_detection(pool)
        await test_t13_ac5_logout_revokes_entire_session_family(pool)
        await test_account_suspension_revokes_active_session(pool)

        print("\n" + "=" * 75)
        print("ALL 4 HC-T11/T13 SESSION CONCURRENCY SUITES PASSED WITH 100% SUCCESS!")
        print("=" * 75)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
