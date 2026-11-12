"""
HC-T13 Security Remediation Verification Suite (pytest)
BASELINE: BL-HAMICARD-PRD-V1 | T13-AC1..T13-AC6 | Findings F-01..F-05

Tests run against isolated PostgreSQL test DB (`DATABASE_URL`) and Redis DB (`REDIS_URL`).
Covers BOTH service-level concurrency invariants AND real FastAPI HTTP endpoint contracts:
- T13-AC1: Concurrent OTP verification cannot authenticate more than once
- T13-AC2: Password auth lockout (5 failures -> 15 min block), account-state restrictions, & non-enumerating HTTP 401
- T13-AC3: Authoritative `user_roles` & immediate privilege revocation ignoring legacy `users.roles` on protected HTTP routes
- T13-AC4: 20 concurrent HTTP /auth/refresh calls -> <=1 usable successor, HTTP 409 without credential disclosure + client single-flight check
- T13-AC5: Protected HTTP request behavior after logout (family-wide), replay detection, and suspension
- T13-AC6: Fail-closed SMS adapter (HTTP 503 on outage, no Redis OTP persistence, MockSmsAdapter blocked in production, no prod OTP backdoor)
"""

import asyncio
import os
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

import src.api.deps as deps
from src.adapters.sms import BaseSmsAdapter, SmsAdapterError
from src.api.main import app
from src.auth.otp_service import OtpService, SmsDeliveryError
from src.auth.rbac import RbacEngine
from src.auth.service import GENERIC_AUTH_ERROR_MSG, AuthService
from src.auth.session_service import SessionService

ROOT_DIR = Path(__file__).resolve().parent.parent


@pytest_asyncio.fixture
async def isolated_env(monkeypatch):
    db_url = os.getenv(
        "DATABASE_URL",
        "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t13",
    )
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("REDIS_URL", redis_url)

    await deps.close_pool()
    deps.close_redis()

    pool = await deps.init_pool()
    rd = deps.init_redis()
    yield pool, rd

    await deps.close_pool()
    deps.close_redis()


class _FailingSmsAdapter(BaseSmsAdapter):
    async def send_otp(self, mobile: str, code: str, template: str | None = None) -> bool:
        raise SmsAdapterError("Simulated upstream Kavenegar 502 Bad Gateway")

    async def send_notification(self, mobile: str, message: str) -> bool:
        return False


class _UnconfirmedSmsAdapter(BaseSmsAdapter):
    async def send_otp(self, mobile: str, code: str, template: str | None = None) -> bool:
        return False

    async def send_notification(self, mobile: str, message: str) -> bool:
        return False


@pytest.mark.asyncio
async def test_t13_ac1_concurrent_otp_verify_single_use_http(isolated_env):
    """T13-AC1: 20 simultaneous HTTP /auth/otp/verify requests with same valid OTP authenticate at most ONCE."""
    pool, rd = isolated_env
    mobile = f"0912{uuid.uuid4().int % 10000000:07d}"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        req_resp = await client.post("/api/v1/auth/otp/request", json={"mobile": mobile})
        assert req_resp.status_code == 200
        code = rd.get(f"otp:code:{mobile}")
        assert code is not None

        async def _try_verify():
            return await client.post("/api/v1/auth/otp/verify", json={"mobile": mobile, "code": code})

        responses = await asyncio.gather(*(_try_verify() for _ in range(20)))

    success_resps = [r for r in responses if r.status_code == 200]
    rejected_resps = [r for r in responses if r.status_code != 200]

    assert len(success_resps) == 1, f"Expected exactly 1 OTP auth success, got {len(success_resps)}"
    assert len(rejected_resps) == 19
    assert rd.get(f"otp:code:{mobile}") is None

    async with pool.acquire() as conn:
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users WHERE mobile = $1;", mobile)
        assert user_count == 1
        uid = await conn.fetchval("SELECT id FROM users WHERE mobile = $1;", mobile)
        sess_count = await conn.fetchval("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1;", uid)
        assert sess_count == 1


@pytest.mark.asyncio
async def test_t13_ac2_password_lockout_and_non_enumerating_errors_http(isolated_env):
    """T13-AC2: Password lockout (5 fails), SUSPENDED block, & identical non-enumerating HTTP 401 errors."""
    pool, rd = isolated_env
    auth_svc = AuthService(pool, rd)

    # Create active user with password
    active_mobile = f"0912{uuid.uuid4().int % 10000000:07d}"
    await auth_svc.otp_service.request_otp(active_mobile)
    active_code = rd.get(f"otp:code:{active_mobile}")
    reg = await auth_svc.authenticate_via_otp(active_mobile, active_code)
    active_uid = uuid.UUID(reg["user_id"])
    await auth_svc.set_password(active_uid, "StrongPass!2026")

    # Create passwordless user
    nopwd_mobile = f"0913{uuid.uuid4().int % 10000000:07d}"
    await auth_svc.otp_service.request_otp(nopwd_mobile)
    nopwd_code = rd.get(f"otp:code:{nopwd_mobile}")
    await auth_svc.authenticate_via_otp(nopwd_mobile, nopwd_code)

    # Create suspended user WITH valid password
    susp_mobile = f"0914{uuid.uuid4().int % 10000000:07d}"
    await auth_svc.otp_service.request_otp(susp_mobile)
    susp_code = rd.get(f"otp:code:{susp_mobile}")
    susp_reg = await auth_svc.authenticate_via_otp(susp_mobile, susp_code)
    susp_uid = uuid.UUID(susp_reg["user_id"])
    await auth_svc.set_password(susp_uid, "SuspendedPass!2026")
    async with pool.acquire() as conn:
        await conn.execute("UPDATE users SET status = 'SUSPENDED' WHERE id = $1;", susp_uid)

    unknown_mobile = f"0915{uuid.uuid4().int % 10000000:07d}"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Wrong password vs unknown mobile vs passwordless vs suspended (even with right password) -> IDENTICAL HTTP 401
        r_wrong = await client.post("/api/v1/auth/password/login", json={"mobile": active_mobile, "password": "BadPassword!"})
        r_unknown = await client.post("/api/v1/auth/password/login", json={"mobile": unknown_mobile, "password": "BadPassword!"})
        r_nopwd = await client.post("/api/v1/auth/password/login", json={"mobile": nopwd_mobile, "password": "AnyPassword!"})
        r_susp = await client.post("/api/v1/auth/password/login", json={"mobile": susp_mobile, "password": "SuspendedPass!2026"})

        for r in (r_wrong, r_unknown, r_nopwd, r_susp):
            assert r.status_code == 401
            assert r.json()["detail"] == GENERIC_AUTH_ERROR_MSG

        # 2. Trigger lockout after 5 wrong attempts on active_mobile (attempt #1 already happened above -> do 4 more)
        for _ in range(4):
            r_fail = await client.post("/api/v1/auth/password/login", json={"mobile": active_mobile, "password": "BadPassword!"})
            assert r_fail.status_code == 401
            assert r_fail.json()["detail"] == GENERIC_AUTH_ERROR_MSG

        # 3. Attempt #6 with the CORRECT password MUST still fail with identical non-enumerating 401!
        r_locked_valid = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": active_mobile, "password": "StrongPass!2026"},
        )
        assert r_locked_valid.status_code == 401
        assert r_locked_valid.json()["detail"] == GENERIC_AUTH_ERROR_MSG

        # 4. Separate un-locked active account succeeds with valid password
        fresh_mobile = f"0916{uuid.uuid4().int % 10000000:07d}"
        await auth_svc.otp_service.request_otp(fresh_mobile)
        f_reg = await auth_svc.authenticate_via_otp(fresh_mobile, rd.get(f"otp:code:{fresh_mobile}"))
        await auth_svc.set_password(uuid.UUID(f_reg["user_id"]), "ValidPass!2026")
        r_ok = await client.post("/api/v1/auth/password/login", json={"mobile": fresh_mobile, "password": "ValidPass!2026"})
        assert r_ok.status_code == 200
        assert "session" in r_ok.json()
        assert "no-store" in r_ok.headers.get("cache-control", "").lower()


@pytest.mark.asyncio
async def test_t13_ac3_authoritative_rbac_and_immediate_revocation_http(isolated_env):
    """T13-AC3: Revoking ADMIN role from `user_roles` immediately returns HTTP 403 even if legacy `users.roles` retains ADMIN."""
    pool, rd = isolated_env
    rbac = RbacEngine(pool)
    sess_svc = SessionService(pool)

    async with pool.acquire() as conn:
        super_admin_id = await conn.fetchval(
            "INSERT INTO users (mobile, status, roles) VALUES ($1, 'ACTIVE', '{\"SUPER_ADMIN\"}') RETURNING id;",
            f"0912{uuid.uuid4().int % 10000000:07d}",
        )
        await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'SUPER_ADMIN');", super_admin_id)

        # Target user starts as plain USER in user_roles, EVEN THOUGH legacy users.roles falsely claims ADMIN
        target_uid = await conn.fetchval(
            "INSERT INTO users (mobile, status, roles) VALUES ($1, 'ACTIVE', '{\"USER\", \"ADMIN\"}') RETURNING id;",
            f"0912{uuid.uuid4().int % 10000000:07d}",
        )
        await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'USER');", target_uid)

    sess = await sess_svc.create_session(user_id=target_uid)
    headers = {"Authorization": f"Bearer {sess['refresh_token']}"}
    missing_review_id = str(uuid.uuid4())

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Legacy users.roles={'ADMIN'} alone MUST NOT grant permission -> HTTP 403
        r_denied_legacy = await client.put(
            f"/api/v1/reviews/{missing_review_id}/moderate",
            json={"is_published": True},
            headers=headers,
        )
        assert r_denied_legacy.status_code == 403

        # Verify profile/me also exposes ONLY authoritative roles (`["USER"]`)
        r_prof1 = await client.get("/api/v1/profile/me", headers=headers)
        assert r_prof1.status_code == 200
        assert r_prof1.json()["roles"] == ["USER"]

        # 2. Authoritatively grant ADMIN via SUPER_ADMIN -> passes RBAC (hits 404 on missing review UUID, NOT 403)
        await rbac.assign_role(super_admin_id, target_uid, "ADMIN")
        r_allowed = await client.put(
            f"/api/v1/reviews/{missing_review_id}/moderate",
            json={"is_published": True},
            headers=headers,
        )
        assert r_allowed.status_code == 404

        # 3. Revoke ADMIN from `user_roles` while legacy `users.roles` still contains ADMIN -> IMMEDIATELY HTTP 403!
        revoked = await rbac.revoke_role(super_admin_id, target_uid, "ADMIN")
        assert revoked is True
        r_revoked = await client.put(
            f"/api/v1/reviews/{missing_review_id}/moderate",
            json={"is_published": True},
            headers=headers,
        )
        assert r_revoked.status_code == 403


@pytest.mark.asyncio
async def test_t13_ac4_20_concurrent_refresh_http_and_single_flight_client(isolated_env):
    """T13-AC4: 20 concurrent HTTP /auth/refresh calls yield at most 1 usable credential and ZERO credential disclosure on collisions."""
    pool, _rd = isolated_env
    sess_svc = SessionService(pool)

    async with pool.acquire() as conn:
        uid = await conn.fetchval(
            "INSERT INTO users (mobile, status, is_mobile_verified) VALUES ($1, 'ACTIVE', TRUE) RETURNING id;",
            f"0917{uuid.uuid4().int % 10000000:07d}",
        )
        await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'USER');", uid)

    sess = await sess_svc.create_session(user_id=uid)
    raw_tok = sess["refresh_token"]
    family_id = uuid.UUID(sess["family_id"])

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        async def _call_refresh():
            return await client.post("/api/v1/auth/refresh", json={"refresh_token": raw_tok})

        resps = await asyncio.gather(*(_call_refresh() for _ in range(20)))

    winners = [r for r in resps if r.status_code == 200]
    conflicts = [r for r in resps if r.status_code == 409]

    assert len(winners) == 1, f"Expected 1 winner on 20 concurrent refreshes, got {len(winners)}"
    assert len(conflicts) == 19, f"Expected 19 HTTP 409 safe conflicts, got {[r.status_code for r in resps if r.status_code != 200]}"
    assert winners[0].json().get("refresh_token")

    for r_conf in conflicts:
        body = r_conf.json()
        assert "refresh_token" not in body
        assert winners[0].json()["refresh_token"] not in r_conf.text

    # Verify winning successor works on protected /profile/me
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_prof = await client.get(
            "/api/v1/profile/me",
            headers={"Authorization": f"Bearer {winners[0].json()['refresh_token']}"},
        )
        assert r_prof.status_code == 200

    # Verify DB lineage integrity
    async with pool.acquire() as conn:
        active_cnt = await conn.fetchval(
            "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND status = 'ACTIVE';",
            family_id,
        )
        assert active_cnt == 1

    # Verify client portal implements single-flight refresh & server-side family logout
    index_html = (ROOT_DIR / "src" / "static" / "index.html").read_text(encoding="utf-8")
    assert "refreshSessionSingleFlight" in index_html
    assert "/auth/logout" in index_html


@pytest.mark.asyncio
async def test_t13_ac5_protected_requests_fail_after_logout_replay_and_suspension(isolated_env):
    """T13-AC5: Protected HTTP endpoints immediately return HTTP 401 after logout, replay, suspension, or family revocation."""
    pool, _rd = isolated_env
    sess_svc = SessionService(pool)

    async def _mk_user():
        async with pool.acquire() as conn:
            uid = await conn.fetchval(
                "INSERT INTO users (mobile, status, is_mobile_verified) VALUES ($1, 'ACTIVE', TRUE) RETURNING id;",
                f"0918{uuid.uuid4().int % 10000000:07d}",
            )
            await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'USER');", uid)
            return uid

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Scenario A: Logout revokes ENTIRE session family (both current token AND ancestor rotated token)
        uid_a = await _mk_user()
        s_a1 = await sess_svc.create_session(uid_a)
        r_rot = await client.post("/api/v1/auth/refresh", json={"refresh_token": s_a1["refresh_token"]})
        assert r_rot.status_code == 200
        tok_a2 = r_rot.json()["refresh_token"]

        assert (await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_a2}"})).status_code == 200
        r_out = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {tok_a2}"})
        assert r_out.status_code == 200
        assert (await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_a2}"})).status_code == 401
        assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": s_a1["refresh_token"]})).status_code == 401
        assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": tok_a2})).status_code == 401

        # Scenario B: Replay outside grace window revokes active successor on protected endpoint
        uid_b = await _mk_user()
        s_b1 = await sess_svc.create_session(uid_b)
        s_b2 = await sess_svc.rotate_refresh_token(s_b1["refresh_token"])
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE refresh_tokens SET rotated_at = NOW() - INTERVAL '20 seconds' WHERE family_id = $1 AND status = 'ROTATED';",
                uuid.UUID(s_b1["family_id"]),
            )
        r_rep = await client.post("/api/v1/auth/refresh", json={"refresh_token": s_b1["refresh_token"]})
        assert r_rep.status_code == 401
        assert (await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {s_b2['refresh_token']}"})).status_code == 401

        # Scenario C: Account suspension immediately rejects active bearer on protected route
        uid_c = await _mk_user()
        s_c = await sess_svc.create_session(uid_c)
        assert (await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {s_c['refresh_token']}"})).status_code == 200
        async with pool.acquire() as conn:
            await conn.execute("UPDATE users SET status = 'SUSPENDED' WHERE id = $1;", uid_c)
        assert (await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {s_c['refresh_token']}"})).status_code == 401


@pytest.mark.asyncio
async def test_t13_ac6_sms_fail_closed_and_prod_bypass_blocked(isolated_env, monkeypatch):
    """T13-AC6: SMS outages & MockSmsAdapter in production fail closed (HTTP 503), zero OTP persisted, zero test backdoors."""
    _pool, rd = isolated_env
    assert not hasattr(OtpService, "get_active_otp_for_test")

    # 1. Production env + mock provider -> HTTP 503 on /otp/request, zero Redis key saved
    m_prod = f"0919{uuid.uuid4().int % 10000000:07d}"
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SMS_PROVIDER", "mock")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_prod = await client.post("/api/v1/auth/otp/request", json={"mobile": m_prod})
        assert r_prod.status_code == 503
        assert rd.get(f"otp:code:{m_prod}") is None

    monkeypatch.setenv("APP_ENV", "development")

    # 2. Adapter exception -> SmsDeliveryError, zero Redis key, hourly count rolled back
    m_err = f"0919{uuid.uuid4().int % 10000000:07d}"
    svc_err = OtpService(rd, sms_adapter=_FailingSmsAdapter())
    with pytest.raises(SmsDeliveryError):
        await svc_err.request_otp(m_err)
    assert rd.get(f"otp:code:{m_err}") is None
    assert int(rd.get(f"otp:hourly:{m_err}") or 0) == 0

    # 3. Adapter returns False -> SmsDeliveryError, zero Redis key, hourly count rolled back
    m_false = f"0919{uuid.uuid4().int % 10000000:07d}"
    svc_false = OtpService(rd, sms_adapter=_UnconfirmedSmsAdapter())
    with pytest.raises(SmsDeliveryError):
        await svc_false.request_otp(m_false)
    assert rd.get(f"otp:code:{m_false}") is None
    assert int(rd.get(f"otp:hourly:{m_false}") or 0) == 0
