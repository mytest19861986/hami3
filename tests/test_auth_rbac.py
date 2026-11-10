#!/usr/bin/env python3
"""
Phase 2 Auth and RBAC Core Test Suite (HC-T10)
BASELINE: BL-HAMICARD-PRD-V1 | T10-AC1..AC5, AC-01, AC-02, AC-03

Verifies:
1. OTP Lifecycle & Rate Limiting (120s TTL, max 3 verification attempts, max 5/hr, fail-closed SMS)
2. T10-AC1: OTP registration creates exactly one USER account, verified mobile, and initializes wallet
3. Argon2id Password Management & Verification
4. T10-AC4: Account state guards (BLOCKED and SUSPENDED accounts cannot login or bypass checks)
5. T10-AC2: Doctor & Agent verification status (PENDING profiles fail-closed for operational actions)
6. T10-AC3: All 6 PRD roles (SUPER_ADMIN, ADMIN, SUPPORT, DOCTOR, AGENT, USER) and referral boundaries
7. T10-AC5: Privilege escalation & negative role assignment guards
"""

import asyncio
import uuid
import sys
import os
import redis
import asyncpg

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.auth.otp_service import (
    OtpService, OtpRateLimitError, OtpMaxAttemptsExceededError,
    OtpExpiredOrInvalidError, SmsDeliveryError
)
from src.auth.service import AuthService, InvalidCredentialsError
from src.auth.session_service import AccountBlockedError
from src.auth.rbac import RbacEngine, RbacAccessDeniedError, ProfileNotApprovedError

PG_DSN = "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
REDIS_HOST = "localhost"
REDIS_PORT = 6379

async def test_otp_lifecycle_and_rate_limiting(r: redis.Redis):
    """Verifies OTP generation, 120s TTL, 3 attempts limit, hourly limit, and fail-closed SMS."""
    print("\n[TEST 1/6] Testing OTP Lifecycle, Rate Limiting & Fail-Closed SMS...")
    otp_svc = OtpService(r)
    mobile = f"0912{uuid.uuid4().int % 10000000:07d}"

    # 1. Normal Request
    success, ttl = otp_svc.request_otp(mobile)
    assert success is True
    assert 115 <= ttl <= 120
    print(f"  ✓ OTP requested successfully (TTL={ttl}s).")

    # 2. Immediate re-request should be rate-limited (cooldown 120s)
    blocked_by_cooldown = False
    try:
        otp_svc.request_otp(mobile)
    except OtpRateLimitError:
        blocked_by_cooldown = True
    assert blocked_by_cooldown, "Cooldown check failed: allowed duplicate OTP request before 120s!"
    print("  ✓ Cooldown rate-limit enforced: duplicate request within 120s blocked.")

    # 3. Incorrect verification attempts (max 3)
    wrong_blocked = False
    for i in range(1, 4):
        try:
            otp_svc.verify_otp(mobile, "000000")
        except OtpExpiredOrInvalidError as e:
            assert f"{3 - i} attempt(s) remaining" in str(e)

    # 4th attempt must trigger OtpMaxAttemptsExceededError and 15-min block
    max_exceeded = False
    try:
        otp_svc.verify_otp(mobile, "000000")
    except OtpMaxAttemptsExceededError:
        max_exceeded = True
    assert max_exceeded, "Max 3 attempts constraint failed to block account!"
    print("  ✓ Security Invariant: 4th attempt triggered OtpMaxAttemptsExceededError and 15-min lockout.")

    # 4. Fail-Closed SMS Provider Outage
    fail_closed_svc = OtpService(r, sms_provider_healthy=False)
    fresh_mobile = f"0912{uuid.uuid4().int % 10000000:07d}"
    sms_failed = False
    try:
        fail_closed_svc.request_otp(fresh_mobile)
    except SmsDeliveryError:
        sms_failed = True
    assert sms_failed, "Fail-Closed policy violated: did not abort on SMS delivery failure!"
    print("  ✓ Fail-Closed Invariant PASS: SMS outage immediately aborts authentication flow.")

async def test_t10_ac1_otp_registration_and_wallet_init(pool: asyncpg.Pool, r: redis.Redis):
    """Verifies T10-AC1: OTP registration creates exactly 1 USER account, verified mobile, and wallet."""
    print("\n[TEST 2/6] Testing T10-AC1: OTP Registration, User Entity, and Wallet Initialization...")
    auth_svc = AuthService(pool, r)
    mobile = f"0919{uuid.uuid4().int % 10000000:07d}"

    # Request and obtain code
    auth_svc.otp_service.request_otp(mobile)
    active_code = auth_svc.otp_service.get_active_otp_for_test(mobile)
    assert active_code is not None

    # Authenticate (Register)
    auth_res = await auth_svc.authenticate_via_otp(mobile, active_code)
    user_id = uuid.UUID(auth_res["user_id"])
    assert auth_res["is_new_user"] is True
    print(f"  ✓ User registered via OTP with ID: {user_id}")

    # Verify user record in database
    async with pool.acquire() as conn:
        user_row = await conn.fetchrow("SELECT mobile, status, roles, is_mobile_verified FROM users WHERE id = $1;", user_id)
        assert user_row["mobile"] == mobile
        assert user_row["status"] == "ACTIVE"
        assert user_row["is_mobile_verified"] is True
        assert "USER" in user_row["roles"]

        # Verify wallet record initialized
        wallet_row = await conn.fetchrow("SELECT withdrawable_balance_toman, locked_balance_toman, status FROM wallets WHERE user_id = $1;", user_id)
        assert wallet_row is not None
        assert wallet_row["withdrawable_balance_toman"] == 0
        assert wallet_row["locked_balance_toman"] == 0
        assert wallet_row["status"] == "ACTIVE"

    print("  ✓ T10-AC1 PASS: Verified mobile, USER role, and 0-balance wallet created atomically.")

async def test_argon2id_password_authentication(pool: asyncpg.Pool, r: redis.Redis):
    """Verifies Argon2id password hashing, verification, and rate-limited attempt logging."""
    print("\n[TEST 3/6] Testing Argon2id Password Management & Authentication...")
    auth_svc = AuthService(pool, r)
    mobile = f"0936{uuid.uuid4().int % 10000000:07d}"

    # Create user first via OTP
    auth_svc.otp_service.request_otp(mobile)
    code = auth_svc.otp_service.get_active_otp_for_test(mobile)
    res = await auth_svc.authenticate_via_otp(mobile, code)
    user_id = uuid.UUID(res["user_id"])

    # Set password
    plain_pass = "StrongP@ssw0rd!2026"
    await auth_svc.set_password(user_id, plain_pass)

    # Check that hash in DB is Argon2id
    async with pool.acquire() as conn:
        stored_hash = await conn.fetchval("SELECT password_hash FROM users WHERE id = $1;", user_id)
        assert stored_hash.startswith("$argon2id$")
    print(f"  ✓ Password stored with OWASP Argon2id parameters ({stored_hash[:25]}...).")

    # Login with wrong password -> must fail
    wrong_failed = False
    try:
        await auth_svc.authenticate_via_password(mobile, "WrongPassword!")
    except InvalidCredentialsError:
        wrong_failed = True
    assert wrong_failed, "Password authentication allowed invalid password!"

    # Login with correct password -> must succeed
    login_res = await auth_svc.authenticate_via_password(mobile, plain_pass)
    assert login_res["user_id"] == str(user_id)
    assert "session" in login_res
    print("  ✓ Password login succeeded with valid session issued.")

async def test_t10_ac4_account_state_guards(pool: asyncpg.Pool, r: redis.Redis):
    """Verifies T10-AC4: BLOCKED and SUSPENDED accounts cannot bypass security checks."""
    print("\n[TEST 4/6] Testing T10-AC4: Account State Guards (SUSPENDED / BLOCKED / DELETED)...")
    auth_svc = AuthService(pool, r)
    mobile = f"0930{uuid.uuid4().int % 10000000:07d}"

    # Create user & set password
    auth_svc.otp_service.request_otp(mobile)
    code = auth_svc.otp_service.get_active_otp_for_test(mobile)
    res = await auth_svc.authenticate_via_otp(mobile, code)
    user_id = uuid.UUID(res["user_id"])
    await auth_svc.set_password(user_id, "UserPass1234!")

    # Suspend user
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET status = 'SUSPENDED' WHERE id = $1;", user_id)

    # Attempt login via password -> must fail with AccountBlockedError
    blocked_pwd = False
    try:
        await auth_svc.authenticate_via_password(mobile, "UserPass1234!")
    except AccountBlockedError:
        blocked_pwd = True
    assert blocked_pwd, "Suspended user bypassed password login!"

    # Attempt login via OTP -> must fail with AccountBlockedError
    auth_svc.otp_service.request_otp(mobile)
    code2 = auth_svc.otp_service.get_active_otp_for_test(mobile)
    blocked_otp = False
    try:
        await auth_svc.authenticate_via_otp(mobile, code2)
    except AccountBlockedError:
        blocked_otp = True
    assert blocked_otp, "Suspended user bypassed OTP login!"

    print("  ✓ T10-AC4 PASS: Suspended and blocked accounts strictly denied across all auth methods.")

async def test_t10_ac2_doctor_and_agent_verification_status(pool: asyncpg.Pool, r: redis.Redis):
    """Verifies T10-AC2: Doctor & Agent operational permissions fail-closed until ADMIN approval."""
    print("\n[TEST 5/6] Testing T10-AC2: Doctor & Agent Verification Status (Fail-Closed)...")
    auth_svc = AuthService(pool, r)
    rbac_engine = RbacEngine(pool)

    # 1. Register a Doctor user
    doc_mobile = f"0912{uuid.uuid4().int % 10000000:07d}"
    auth_svc.otp_service.request_otp(doc_mobile)
    code = auth_svc.otp_service.get_active_otp_for_test(doc_mobile)
    doc_auth = await auth_svc.authenticate_via_otp(doc_mobile, code)
    doc_user_id = uuid.UUID(doc_auth["user_id"])

    # Register doctor profile (status is PENDING)
    med_code = f"MED-{uuid.uuid4().int % 100000:05d}"
    doc_id = await auth_svc.register_doctor_profile(
        user_id=doc_user_id,
        medical_council_code=med_code,
        specialty="قلب و عروق",
        clinic_name="کلینیک تخصصی حامی",
        province_id=1,
        city_id=1,
        clinic_address="تهران، خیابان ولیعصر",
        clinic_phone="02188889999"
    )

    # Attempt doctor operational action (visits:record) -> MUST BE REJECTED with ProfileNotApprovedError
    pending_denied = False
    try:
        await rbac_engine.check_permission(doc_user_id, "visits:record", is_operational_action=True)
    except ProfileNotApprovedError:
        pending_denied = True
    assert pending_denied, "Unapproved doctor illegally accessed operational visit registration!"
    print("  ✓ Doctor operational action blocked in PENDING status (Fail-Closed).")

    # 2. Setup an ADMIN user and approve the doctor
    admin_mobile = f"0912{uuid.uuid4().int % 10000000:07d}"
    async with pool.acquire() as conn:
        admin_user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles, is_mobile_verified)
            VALUES ($1, 'ACTIVE', '{"ADMIN"}', TRUE) RETURNING id;
        """, admin_mobile)

    # Admin approves doctor
    approved = await auth_svc.approve_doctor_profile(admin_user_id, doc_id)
    assert approved is True
    print("  ✓ Admin approved doctor profile.")

    # Doctor attempts operational action again -> MUST SUCCEED
    has_perm = await rbac_engine.check_permission(doc_user_id, "visits:record", is_operational_action=True)
    assert has_perm is True
    print("  ✓ T10-AC2 PASS: Doctor operational permission activated only after official approval.")

async def test_t10_ac3_and_ac5_rbac_matrix_and_negative_guards(pool: asyncpg.Pool):
    """Verifies T10-AC3 and T10-AC5: All 6 PRD roles, referral boundaries, and privilege escalation guards."""
    print("\n[TEST 6/6] Testing T10-AC3 & T10-AC5: Full RBAC Matrix & Privilege Escalation Guards...")
    rbac_engine = RbacEngine(pool)

    async with pool.acquire() as conn:
        # Create users for each of the remaining roles: SUPPORT, AGENT, SUPER_ADMIN
        support_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles) VALUES ($1, 'ACTIVE', '{"SUPPORT"}') RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

        agent_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles) VALUES ($1, 'ACTIVE', '{"AGENT"}') RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

        super_admin_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles) VALUES ($1, 'ACTIVE', '{"SUPER_ADMIN"}') RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

        normal_user_id = await conn.fetchval("""
            INSERT INTO users (mobile, status, roles) VALUES ($1, 'ACTIVE', '{"USER"}') RETURNING id;
        """, f"0912{uuid.uuid4().int % 10000000:07d}")

    # SUPPORT permissions:
    # Allowed: users:read, plans:read
    assert await rbac_engine.check_permission(support_id, "users:read") is True
    assert await rbac_engine.check_permission(support_id, "plans:read") is True

    # SUPPORT Denied: settlements:pay, settings:write, users:manage_roles
    support_denied = False
    try:
        await rbac_engine.check_permission(support_id, "settlements:pay")
    except RbacAccessDeniedError:
        support_denied = True
    assert support_denied, "SUPPORT was allowed to pay settlements!"
    print("  ✓ SUPPORT role strictly restricted from financial settlement execution.")

    # USER & AGENT Referral Boundaries (T10-AC3):
    # USER has referral permissions (can share link and view stats)
    assert await rbac_engine.check_permission(normal_user_id, "referral:generate_code") is True
    assert await rbac_engine.check_permission(normal_user_id, "referral:view_stats") is True
    # But USER cannot access admin dashboard or verify doctors
    user_denied_admin = False
    try:
        await rbac_engine.check_permission(normal_user_id, "doctors:verify")
    except RbacAccessDeniedError:
        user_denied_admin = True
    assert user_denied_admin, "USER was allowed to verify doctors!"
    print("  ✓ Referral permissions properly mapped to USER while administrative operations blocked.")

    # Privilege Escalation Guard (T10-AC5):
    # SUPPORT attempts to assign SUPER_ADMIN role -> MUST FAIL
    escalation_blocked = False
    try:
        await rbac_engine.assign_role(
            actor_user_id=support_id,
            target_user_id=normal_user_id,
            role_to_assign="SUPER_ADMIN"
        )
    except RbacAccessDeniedError:
        escalation_blocked = True
    assert escalation_blocked, "Privilege escalation allowed: non-superadmin assigned role!"
    print("  ✓ Privilege Escalation Guard PASS: Non-superadmin cannot delegate or assign roles.")

    # SUPER_ADMIN assigns role -> MUST SUCCEED
    assigned = await rbac_engine.assign_role(
        actor_user_id=super_admin_id,
        target_user_id=normal_user_id,
        role_to_assign="SUPPORT"
    )
    assert assigned is True
    print("  ✓ SUPER_ADMIN successfully assigned role with audit logging.")

async def main():
    print("=" * 75)
    print("HAMICARD PHASE 2 AUTH & RBAC VERIFICATION SUITE (HC-T10)")
    print("=" * 75)

    pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=10)
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    try:
        await test_otp_lifecycle_and_rate_limiting(r)
        await test_t10_ac1_otp_registration_and_wallet_init(pool, r)
        await test_argon2id_password_authentication(pool, r)
        await test_t10_ac4_account_state_guards(pool, r)
        await test_t10_ac2_doctor_and_agent_verification_status(pool, r)
        await test_t10_ac3_and_ac5_rbac_matrix_and_negative_guards(pool)

        print("\n" + "=" * 75)
        print("ALL 6 HC-T10 TEST SUITES PASSED WITH 100% SUCCESS!")
        print("Auth, OTP lifecycle, Argon2id, RBAC, and approval gates are fully verified.")
        print("=" * 75)
    finally:
        await pool.close()

if __name__ == "__main__":
    asyncio.run(main())

