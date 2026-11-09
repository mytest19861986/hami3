#!/usr/bin/env python3
"""
Session Security and Concurrency Test Suite (HC-T11)
BASELINE: BL-HAMICARD-PRD-V1 | T11-AC1..AC4, AC-14, AC-15

Verifies:
1. T11-AC1: Concurrent Refresh Race Condition (20 simultaneous rotation requests with same token -> exactly one successor)
2. T11-AC4: Benign simultaneous network race resolves via grace window without false-positive family destruction
3. T11-AC2: Malicious token replay attack detection outside grace window triggers IMMEDIATE WHOLE-FAMILY REVOCATION and audit log
4. T11-AC3: Logout & Account Suspension immediately terminate session authority in PostgreSQL SSOT
"""

import asyncio
import uuid
import sys
import os
import asyncpg

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.auth.session_service import (
    SessionService, SecurityReplayAttackError, SessionExpiredError,
    SessionNotFoundError, AccountBlockedError
)

PG_DSN = "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"

async def test_t11_ac1_and_ac4_concurrent_refresh_rotation(pool: asyncpg.Pool):
    """
    Validates T11-AC1 and T11-AC4:
    20 concurrent tasks attempt to rotate the exact same refresh token simultaneously.
    Guarantees:
    - At most ONE valid successor token is created.
    - Concurrent callers resolve cleanly via grace period without race crashes or family destruction.
    """
    print("\n[SESSION TEST 1/4] Testing AC-15 / T11-AC1: Concurrent Refresh Token Rotation Race...")
    session_svc = SessionService(pool)

    # 1. Create a user and active session
    async with pool.acquire() as conn:
        user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

    initial_session = await session_svc.create_session(user_id=user_id)
    initial_refresh_token = initial_session["refresh_token"]
    family_id = uuid.UUID(initial_session["family_id"])

    # 2. Fire 20 concurrent refresh attempts using the same token
    async def attempt_refresh(worker_id: int):
        try:
            res = await session_svc.rotate_refresh_token(
                raw_refresh_token=initial_refresh_token,
                ip_address=f"192.168.1.{worker_id}",
                grace_period_seconds=5
            )
            return {"worker_id": worker_id, "result": res, "error": None}
        except Exception as e:
            return {"worker_id": worker_id, "result": None, "error": type(e).__name__}

    tasks = [attempt_refresh(i) for i in range(20)]
    results = await asyncio.gather(*tasks)

    rotated_successors = [r for r in results if r["result"] and r["result"].get("status") == "ROTATED"]
    grace_successors = [r for r in results if r["result"] and r["result"].get("status") == "GRACE_PERIOD_SUCCESSOR"]

    print(f"  ✓ 20 simultaneous rotations finished: {len(rotated_successors)} ROTATED, {len(grace_successors)} GRACE_PERIOD_SUCCESSORS.")
    # Invariant: EXACTLY ONE caller gets the primary rotation
    assert len(rotated_successors) == 1, f"Expected exactly 1 ROTATED successor, got {len(rotated_successors)}"
    assert len(grace_successors) == 19, f"Expected 19 grace successors, got {len(grace_successors)}"

    # Invariant: Database has exactly 1 ACTIVE token in this family
    async with pool.acquire() as conn:
        active_tokens = await conn.fetch("""
            SELECT id, status FROM refresh_tokens 
            WHERE family_id = $1 AND status = 'ACTIVE';
        """, family_id)
        assert len(active_tokens) == 1, f"Expected exactly 1 ACTIVE token in family, found {len(active_tokens)}"
        
        rotated_tokens = await conn.fetch("""
            SELECT id, status FROM refresh_tokens 
            WHERE family_id = $1 AND status = 'ROTATED';
        """, family_id)
        assert len(rotated_tokens) == 1, f"Expected exactly 1 ROTATED token in family, found {len(rotated_tokens)}"

    print("  ✓ T11-AC1 & T11-AC4 PASS: Single-use rotation invariant preserved under concurrent load.")

async def test_t11_ac2_malicious_replay_detection(pool: asyncpg.Pool):
    """
    Validates T11-AC2:
    Simulates a token theft / replay attack where an old rotated token is submitted after grace period.
    Guarantees:
    - Entire token family is IMMEDIATELY REVOKED.
    - Security audit log is generated.
    - Subsequent refresh with any token in that family fails.
    """
    print("\n[SESSION TEST 2/4] Testing AC-15 / T11-AC2: Token Family Replay Attack Detection...")
    session_svc = SessionService(pool)

    # 1. Create session and perform normal rotation
    async with pool.acquire() as conn:
        user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

    sess1 = await session_svc.create_session(user_id=user_id)
    token_gen1 = sess1["refresh_token"]
    family_id = uuid.UUID(sess1["family_id"])

    # Rotate to gen2
    sess2 = await session_svc.rotate_refresh_token(token_gen1)
    token_gen2 = sess2["refresh_token"]
    assert sess2["status"] == "ROTATED"

    # Simulate expiration of grace period by backdating rotated_at in DB
    async with pool.acquire() as conn:
        await conn.execute("""
            UPDATE refresh_tokens 
            SET rotated_at = NOW() - INTERVAL '15 seconds' 
            WHERE family_id = $1 AND status = 'ROTATED';
        """, family_id)

    # 2. MALICIOUS ATTACK: Re-submit token_gen1 (which was already rotated)
    replay_detected = False
    try:
        await session_svc.rotate_refresh_token(token_gen1, ip_address="198.51.100.25")
    except SecurityReplayAttackError as e:
        replay_detected = True
        assert "Replay of already rotated token detected" in str(e)
    assert replay_detected, "Replay attack failed to trigger SecurityReplayAttackError!"
    print("  ✓ Replay attack detected: SecurityReplayAttackError raised.")

    # 3. Invariant: ALL tokens in family must now be REVOKED
    async with pool.acquire() as conn:
        statuses = await conn.fetch("SELECT status FROM refresh_tokens WHERE family_id = $1;", family_id)
        for s in statuses:
            assert s["status"] == "REVOKED", f"Token found with non-revoked status: {s['status']}"

        # Check security audit log
        audit_row = await conn.fetchrow("""
            SELECT action, entity_name, ip_address 
            FROM audit_logs 
            WHERE entity_id = $1 AND action = 'TOKEN_REPLAY_ATTACK_DETECTED';
        """, str(family_id))
        assert audit_row is not None
        assert audit_row["ip_address"] == "198.51.100.25"
    print("  ✓ Whole-family revoked: all tokens in compromised family terminated.")
    print("  ✓ Security audit log recorded with attacker IP and compromised family ID.")

    # 4. Legitimate user trying to use token_gen2 will now be rejected
    gen2_blocked = False
    try:
        await session_svc.rotate_refresh_token(token_gen2)
    except SecurityReplayAttackError:
        gen2_blocked = True
    assert gen2_blocked, "Compromised family allowed subsequent token rotation!"
    print("  ✓ T11-AC2 PASS: Replay attack terminated entire session lineage.")

async def test_t11_ac3_logout_and_session_revocation(pool: asyncpg.Pool):
    """
    Validates T11-AC3:
    Explicit logout revokes the specific session, preventing further refresh.
    Global user logout revokes all sessions across all families.
    """
    print("\n[SESSION TEST 3/4] Testing AC-14 / T11-AC3: Logout & Multi-Device Revocation...")
    session_svc = SessionService(pool)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

    # Create 3 sessions on different devices (Family A, B, C)
    sess_a = await session_svc.create_session(user_id=user_id, device_info="Chrome on Windows")
    sess_b = await session_svc.create_session(user_id=user_id, device_info="Safari on iPhone")
    sess_c = await session_svc.create_session(user_id=user_id, device_info="Firefox on Android")

    # 1. Single session logout (Device A)
    revoked = await session_svc.revoke_session(sess_a["refresh_token"])
    assert revoked is True

    # Device A cannot refresh
    dev_a_blocked = False
    try:
        await session_svc.rotate_refresh_token(sess_a["refresh_token"])
    except SecurityReplayAttackError:
        dev_a_blocked = True
    assert dev_a_blocked, "Revoked session allowed refresh!"
    print("  ✓ Single device logout successfully revoked Device A.")

    # Device B can still refresh
    res_b = await session_svc.rotate_refresh_token(sess_b["refresh_token"])
    assert res_b["status"] == "ROTATED"
    print("  ✓ Device B unaffected by Device A logout.")

    # 2. Global account logout (all devices)
    total_revoked = await session_svc.revoke_all_user_sessions(user_id)
    assert total_revoked >= 2
    print(f"  ✓ Global logout revoked {total_revoked} remaining active sessions.")

    # Neither B nor C can refresh now
    b_blocked = False
    try:
        await session_svc.rotate_refresh_token(res_b["refresh_token"])
    except SecurityReplayAttackError:
        b_blocked = True
    assert b_blocked

    c_blocked = False
    try:
        await session_svc.rotate_refresh_token(sess_c["refresh_token"])
    except SecurityReplayAttackError:
        c_blocked = True
    assert c_blocked

    print("  ✓ T11-AC3 PASS: Global logout immediately invalidates all active device sessions.")

async def test_account_suspension_revokes_active_session(pool: asyncpg.Pool):
    """Validates that suspending an account in PostgreSQL immediately halts session refresh."""
    print("\n[SESSION TEST 4/4] Testing Session Invalidation upon Account Suspension...")
    session_svc = SessionService(pool)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"USER"}', TRUE) RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

    sess = await session_svc.create_session(user_id=user_id)
    tok = sess["refresh_token"]

    # Suspend user
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET status = 'SUSPENDED' WHERE id = $1;", user_id)

    # Attempt rotation -> must fail with AccountBlockedError
    suspended_blocked = False
    try:
        await session_svc.rotate_refresh_token(tok)
    except AccountBlockedError:
        suspended_blocked = True
    assert suspended_blocked, "Suspended account allowed refresh rotation!"
    print("  ✓ Suspended account immediately blocked from session rotation.")

async def main():
    print("=" * 75)
    print("HAMICARD SESSION SECURITY & CONCURRENCY VERIFICATION SUITE (HC-T11)")
    print("=" * 75)

    pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=25)
    try:
        await test_t11_ac1_and_ac4_concurrent_refresh_rotation(pool)
        await test_t11_ac2_malicious_replay_detection(pool)
        await test_t11_ac3_logout_and_session_revocation(pool)
        await test_account_suspension_revokes_active_session(pool)

        print("\n" + "=" * 75)
        print("ALL 4 HC-T11 SESSION CONCURRENCY SUITES PASSED WITH 100% SUCCESS!")
        print("Single-use rotation, replay detection, grace period, and revocation verified.")
        print("=" * 75)
    finally:
        await pool.close()

if __name__ == "__main__":
    asyncio.run(main())
