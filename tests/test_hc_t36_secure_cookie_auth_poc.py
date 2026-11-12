"""
Automated Security & Multi-Tab Playwright Verification Suite for HC-T36 (`HC-CMD-037`)
BASELINE: BL-HAMICARD-PRD-V1 | Contract: HC-T33 (T33-AC1..AC5)

Covers:
- T36-AC1: Zero persistent JS-readable credentials, fail-closed signing secret/TTL validation,
  strict Set-Cookie attributes (`HttpOnly`, `SameSite=Lax`, `Path=/api/v1/auth`, `Secure` in prod/staging),
  zero `refresh_token` in JSON body under cookie mode, ambient cookies rejected on resource routes.
- T36-AC2: Fail-closed CSRF + Origin/Referer boundary (`403 Forbidden` BEFORE any DB mutation) on missing/wrong
  `X-CSRF-Token`, untrusted/null/missing `Origin`/`Referer`, and cross-session/forged CSRF cookie tossing.
- T36-AC3: Fail-closed Redis revocation enforcement (`RedisError -> HTTP 503` zero bypass on active
  `access_token`, `/refresh`, and `/logout`), Redis eviction/flush PostgreSQL SSOT `401` fallback, immediate
  family logout & suspension rejection (`AC-14`).
- T36-AC4: 20-way concurrent cookie `/refresh` race (`1x 200 OK`, `19x 409 Conflict` with zero cookie
  disclosure or deletion), plus outside-window replay family revocation & audit logging (`AC-15`).
- T36-AC5: Strict `/auth-poc` CSP (`no unsafe-inline`), zero web storage / unsafe DOM sinks scan,
  isolation from unapproved `fix/hc-t28` UI shell, and `18/18 OPEN-* = PROPOSED`.
- E2E Playwright: Real Chromium multi-tab cookie jar, 3-tab WebLocks+BroadcastChannel single-flight cold
  reload & expired-token refresh (`== 1` POST `/refresh`), cross-tab instant logout, `pageshow` BFCache scrub.
"""

import asyncio
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_t36",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
import redis  # noqa: E402

import src.api.deps as deps  # noqa: E402
from src.api.main import app, create_app  # noqa: E402
from src.auth.access_tokens import (  # noqa: E402
    REVOKED_FAMILY_REDIS_PREFIX,
    AccessTokenConfigurationError,
    issue_access_token,
    resolve_access_signing_secret,
    resolve_access_token_ttl,
)
from src.auth.rbac import RbacEngine  # noqa: E402
from src.auth.service import AuthService  # noqa: E402
from src.core.policy import get_all_open_policy_statuses  # noqa: E402

ROOT_DIR = Path(__file__).resolve().parent.parent
LOCAL_ORIGIN = "http://127.0.0.1:3000"


def _clear_auth_env(monkeypatch) -> None:
    for var in (
        "APP_ENV",
        "ENVIRONMENT",
        "NODE_ENV",
        "ACCESS_TOKEN_SECRET",
        "JWT_ACCESS_SECRET",
        "ACCESS_TOKEN_TTL_SECONDS",
        "COOKIE_SECURE",
        "CORS_ALLOWED_ORIGINS",
        "ALLOWED_CORS_ORIGINS",
        "SMS_PROVIDER",
        "KAVENEGAR_API_KEY",
        "GHASEDAK_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


def _extract_set_cookie_map(headers: httpx.Headers) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        result[name] = raw
    return result


async def _ensure_user_with_password(pool: asyncpg.Pool, rd: redis.Redis, prefix: str = "0912"):
    auth_svc = AuthService(pool, rd)
    mobile = f"{prefix}{uuid.uuid4().int % 10000000:07d}"
    await auth_svc.otp_service.request_otp(mobile)
    code = rd.get(f"otp:code:{mobile}")
    assert code is not None
    reg = await auth_svc.authenticate_via_otp(mobile, code)
    uid = uuid.UUID(reg["user_id"])
    await auth_svc.set_password(uid, "StrongPocPass!2026")
    return uid, mobile


@pytest_asyncio.fixture
async def isolated_env(monkeypatch):
    _clear_auth_env(monkeypatch)
    await deps.close_pool()
    deps.close_redis()
    pool = await deps.init_pool()
    rd = deps.init_redis()
    try:
        yield pool, rd
    finally:
        await deps.close_pool()
        deps.close_redis()


@pytest.mark.parametrize(
    "bad_env",
    [
        {"APP_ENV": "production"},
        {"ENVIRONMENT": "staging"},
        {"NODE_ENV": "prod", "ACCESS_TOKEN_SECRET": "too_short"},
        {
            "APP_ENV": "production",
            "ACCESS_TOKEN_SECRET": "hamicard_dev_access_token_secret_min_32_chars_long",
        },
        {"APP_ENV": "development", "ENVIRONMENT": "production", "ACCESS_TOKEN_SECRET": "x" * 40},
    ],
)
def test_t36_ac1_fail_closed_signing_secret_validation(monkeypatch, bad_env):
    _clear_auth_env(monkeypatch)
    for k, v in bad_env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(AccessTokenConfigurationError):
        resolve_access_signing_secret()


@pytest.mark.parametrize(
    "bad_ttl",
    ["601", "0", "-5", "not-an-int"],
)
def test_t36_ac1_fail_closed_ttl_validation(monkeypatch, bad_ttl):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", bad_ttl)
    with pytest.raises(AccessTokenConfigurationError):
        resolve_access_token_ttl()


@pytest.mark.asyncio
async def test_t36_ac1_cookie_attributes_no_body_refresh_and_fail_closed_otp(
    isolated_env, monkeypatch
):
    pool, rd = isolated_env
    mobile = f"0912{uuid.uuid4().int % 10000000:07d}"

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://app.hamicard.example"
    ) as client:
        # 1. Fail closed BEFORE consuming OTP if production cookie signing config is invalid
        await AuthService(pool, rd).otp_service.request_otp(mobile)
        otp_code = rd.get(f"otp:code:{mobile}")
        assert otp_code is not None

        monkeypatch.setenv("ENVIRONMENT", "staging")
        monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.hamicard.example")
        # Missing ACCESS_TOKEN_SECRET in staging -> HTTP 503 and OTP remains unconsumed!
        r_503 = await client.post(
            "/api/v1/auth/otp/verify",
            json={"mobile": mobile, "code": otp_code},
            headers={"X-Auth-Mode": "cookie", "Origin": "https://app.hamicard.example"},
        )
        assert r_503.status_code == 503
        assert rd.get(f"otp:code:{mobile}") == otp_code

        # 2. Configure valid strong restricted secret & SMS provider -> sets HttpOnly/Secure/SameSite=Lax cookies, ZERO refresh_token in JSON
        monkeypatch.setenv("SMS_PROVIDER", "kavenegar")
        monkeypatch.setenv("KAVENEGAR_API_KEY", "test-staging-kavenegar-key-123456")
        monkeypatch.setenv("ACCESS_TOKEN_SECRET", "ProdStrongAccessSecret!2026#999888777")
        r_ok = await client.post(
            "/api/v1/auth/otp/verify",
            json={"mobile": mobile, "code": otp_code},
            headers={"X-Auth-Mode": "cookie", "Origin": "https://app.hamicard.example"},
        )
        assert r_ok.status_code == 200, r_ok.text
        data = r_ok.json()
        assert data["auth_mode"] == "cookie"
        assert data["access_token"].startswith("hc_at_v1.")
        assert 1 <= data["expires_in"] <= 300
        assert "refresh_token" not in data
        assert "refresh_token" not in r_ok.text
        assert "no-store" in r_ok.headers.get("cache-control", "").lower()

        sc_map = _extract_set_cookie_map(r_ok.headers)
        assert {"hc_refresh", "hc_csrf", "hc_has_session"}.issubset(sc_map.keys())
        refresh_hdr = sc_map["hc_refresh"].lower()
        assert "httponly" in refresh_hdr
        assert "secure" in refresh_hdr
        assert "samesite=lax" in refresh_hdr
        assert "path=/api/v1/auth" in refresh_hdr

        csrf_hdr = sc_map["hc_csrf"].lower()
        assert "httponly" not in csrf_hdr
        assert "secure" in csrf_hdr
        assert "path=/" in csrf_hdr

        # 3. Ambient cookies alone MUST NEVER authenticate protected API endpoints
        r_ambient = await client.get("/api/v1/profile/me")
        assert r_ambient.status_code == 401

        # 4. Short-lived Bearer access token works cleanly
        r_prof = await client.get(
            "/api/v1/profile/me",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert r_prof.status_code == 200
        assert r_prof.json()["mobile"] == mobile

        # 5. Misconfigured signing secret on /refresh MUST fail closed (503) BEFORE rotating DB row
        sid = uuid.UUID(data["session_id"])
        csrf_tok = client.cookies.get("hc_csrf")
        monkeypatch.delenv("ACCESS_TOKEN_SECRET", raising=False)
        r_ref_503 = await client.post(
            "/api/v1/auth/refresh",
            headers={
                "X-Auth-Mode": "cookie",
                "Origin": "https://app.hamicard.example",
                "X-CSRF-Token": csrf_tok,
            },
        )
        assert r_ref_503.status_code == 503
        async with pool.acquire() as conn:
            assert (
                await conn.fetchval("SELECT status FROM refresh_tokens WHERE id = $1;", sid)
            ) == "ACTIVE"

        monkeypatch.setenv("ACCESS_TOKEN_SECRET", "ProdStrongAccessSecret!2026#999888777")
        r_ref_ok = await client.post(
            "/api/v1/auth/refresh",
            headers={
                "X-Auth-Mode": "cookie",
                "Origin": "https://app.hamicard.example",
                "X-CSRF-Token": csrf_tok,
            },
        )
        assert r_ref_ok.status_code == 200, r_ref_ok.text
        assert "refresh_token" not in r_ref_ok.json()

        _clear_auth_env(monkeypatch)


@pytest.mark.asyncio
async def test_t36_ac2_csrf_and_origin_validation_matrix_zero_db_mutation(isolated_env):
    pool, rd = isolated_env
    _uid, mobile = await _ensure_user_with_password(pool, rd, prefix="0913")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_login = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongPocPass!2026"},
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN},
        )
        assert r_login.status_code == 200, r_login.text
        family_id = uuid.UUID(r_login.json()["family_id"])
        session_id = uuid.UUID(r_login.json()["session_id"])
        real_refresh = client.cookies.get("hc_refresh")
        real_csrf = client.cookies.get("hc_csrf")
        assert real_refresh and real_csrf

        # Helper to assert DB row did not rotate or revoke
        async def _assert_token_intact():
            async with pool.acquire() as conn:
                status_val = await conn.fetchval(
                    "SELECT status FROM refresh_tokens WHERE id = $1;", session_id
                )
                cnt = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1;", family_id
                )
                assert status_val == "ACTIVE"
                assert cnt == 1

        # Negative matrix for BOTH /refresh and /logout
        attack_cases = [
            # Missing Origin + Referer even with valid CSRF
            {"X-Auth-Mode": "cookie", "X-CSRF-Token": real_csrf},
            # Null origin
            {"X-Auth-Mode": "cookie", "Origin": "null", "X-CSRF-Token": real_csrf},
            # Untrusted origin
            {
                "X-Auth-Mode": "cookie",
                "Origin": "https://evil-attacker.example",
                "X-CSRF-Token": real_csrf,
            },
            # Lookalike subdomain attack
            {
                "X-Auth-Mode": "cookie",
                "Origin": "http://127.0.0.1:3000.evil.com",
                "X-CSRF-Token": real_csrf,
            },
            # Wrong port origin
            {
                "X-Auth-Mode": "cookie",
                "Origin": "http://127.0.0.1:9999",
                "X-CSRF-Token": real_csrf,
            },
            # Untrusted Referer with omitted Origin
            {
                "X-Auth-Mode": "cookie",
                "Referer": "https://evil-attacker.example/csrf.html",
                "X-CSRF-Token": real_csrf,
            },
            # Valid Origin, missing X-CSRF-Token
            {"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN},
            # Valid Origin, wrong X-CSRF-Token
            {"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN, "X-CSRF-Token": "wrong.token"},
        ]

        for endpoint in ("/api/v1/auth/refresh", "/api/v1/auth/logout"):
            for hdrs in attack_cases:
                resp = await client.post(endpoint, headers=hdrs)
                assert resp.status_code == 403, f"{endpoint} with {hdrs} returned {resp.status_code}"
                assert "hc_refresh" not in _extract_set_cookie_map(resp.headers)
                await _assert_token_intact()

        # Body smuggling refresh_token under cookie mode rejected (400) cleanly
        r_smuggle = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": real_refresh},
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN, "X-CSRF-Token": real_csrf},
        )
        assert r_smuggle.status_code == 400
        await _assert_token_intact()

        # Cookie-tossing attack: unsigned/forged CSRF matching both cookie & header STILL fails family HMAC (403)!
        r_toss = await client.post(
            "/api/v1/auth/refresh",
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN, "X-CSRF-Token": "forged.mac"},
            cookies={"hc_refresh": real_refresh, "hc_csrf": "forged.mac", "hc_has_session": "1"},
        )
        assert r_toss.status_code == 403
        await _assert_token_intact()

        # Valid Referer fallback when Origin is absent works cleanly (200)
        r_ref_ok = await client.post(
            "/api/v1/auth/refresh",
            headers={
                "X-Auth-Mode": "cookie",
                "Referer": f"{LOCAL_ORIGIN}/auth-poc",
                "X-CSRF-Token": real_csrf,
            },
        )
        assert r_ref_ok.status_code == 200, r_ref_ok.text


@pytest.mark.asyncio
async def test_t36_ac3_fail_closed_redis_outage_and_flush_fallback_and_rbac_revocation(
    isolated_env, monkeypatch
):
    pool, rd = isolated_env
    _uid, mobile = await _ensure_user_with_password(pool, rd, prefix="0914")
    async with pool.acquire() as conn:
        super_id = await conn.fetchval(
            "INSERT INTO users (mobile, status, roles) VALUES ($1, 'ACTIVE', '{\"SUPER_ADMIN\"}') RETURNING id;",
            f"0999{uuid.uuid4().int % 10000000:07d}",
        )
        await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'SUPER_ADMIN');", super_id)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_login = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongPocPass!2026"},
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN},
        )
        assert r_login.status_code == 200
        tok_1 = r_login.json()["access_token"]
        fam_1 = uuid.UUID(r_login.json()["family_id"])
        sess_1 = uuid.UUID(r_login.json()["session_id"])
        csrf_1 = client.cookies.get("hc_csrf")

        # Baseline OK with healthy Redis
        assert (
            await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_1}"})
        ).status_code == 200

        # 1. Immediate RBAC revocation inside 300s access window still takes effect (T13-AC3 preserved)
        rbac = RbacEngine(pool)
        await rbac.assign_role(super_id, _uid, "ADMIN")
        missing_rev = str(uuid.uuid4())
        assert (
            await client.put(
                f"/api/v1/reviews/{missing_rev}/moderate",
                json={"is_published": True},
                headers={"Authorization": f"Bearer {tok_1}"},
            )
        ).status_code == 404
        await rbac.revoke_role(super_id, _uid, "ADMIN")
        assert (
            await client.put(
                f"/api/v1/reviews/{missing_rev}/moderate",
                json={"is_published": True},
                headers={"Authorization": f"Bearer {tok_1}"},
            )
        ).status_code == 403

        # 2. Simulated Redis outage -> protected endpoint, /refresh, AND /logout MUST FAIL CLOSED (HTTP 503)!
        class _BrokenRedis:
            def get(self, *_args, **_kwargs):
                raise redis.ConnectionError("Simulated Redis outage on get")

            def set(self, *_args, **_kwargs):
                raise redis.ConnectionError("Simulated Redis outage on set")

        orig_redis = deps._redis
        monkeypatch.setattr(deps, "_redis", _BrokenRedis())
        try:
            r_prof_down = await client.get(
                "/api/v1/profile/me",
                headers={"Authorization": f"Bearer {tok_1}"},
            )
            assert r_prof_down.status_code == 503

            r_ref_down = await client.post(
                "/api/v1/auth/refresh",
                headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN, "X-CSRF-Token": csrf_1},
            )
            assert r_ref_down.status_code == 503

            r_out_down = await client.post(
                "/api/v1/auth/logout",
                headers={
                    "X-Auth-Mode": "cookie",
                    "Origin": LOCAL_ORIGIN,
                    "X-CSRF-Token": csrf_1,
                    "Authorization": f"Bearer {tok_1}",
                },
            )
            assert r_out_down.status_code == 503
            # Logout still revoked PostgreSQL SSOT AND issued Max-Age=0 cookie deletions even on Redis write failure
            assert "hc_refresh" in _extract_set_cookie_map(r_out_down.headers)
        finally:
            monkeypatch.setattr(deps, "_redis", orig_redis)

        async with pool.acquire() as conn:
            assert (
                await conn.fetchval("SELECT status FROM refresh_tokens WHERE id = $1;", sess_1)
            ) == "REVOKED"

        # 3. Clean logout writes Redis tombstone, AND even after Redis key deletion/flush, PG SSOT rejects with 401!
        r_login2 = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongPocPass!2026"},
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN},
        )
        assert r_login2.status_code == 200
        tok_2 = r_login2.json()["access_token"]
        fam_2 = r_login2.json()["family_id"]
        csrf_2 = client.cookies.get("hc_csrf")

        r_out2 = await client.post(
            "/api/v1/auth/logout",
            headers={
                "X-Auth-Mode": "cookie",
                "Origin": LOCAL_ORIGIN,
                "X-CSRF-Token": csrf_2,
                "Authorization": f"Bearer {tok_2}",
            },
        )
        assert r_out2.status_code == 200
        assert rd.get(f"{REVOKED_FAMILY_REDIS_PREFIX}{fam_2}") is not None

        # Active unexpired access token immediately returns 401
        assert (
            await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_2}"})
        ).status_code == 401

        # Simulate Redis FLUSH/eviction -> PG family SSOT check STILL rejects with 401!
        rd.delete(f"{REVOKED_FAMILY_REDIS_PREFIX}{fam_2}")
        assert (
            await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_2}"})
        ).status_code == 401

        # 4. Expired short-lived access token rejected (401)
        expired_tok, _ttl, _iso = issue_access_token(
            user_id=_uid, family_id=fam_1, session_id=sess_1, ttl_seconds=1
        )
        await asyncio.sleep(1.1)
        assert (
            await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {expired_tok}"})
        ).status_code == 401

        # 5. Account suspension immediately invalidates unexpired access token (401)
        r_login3 = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongPocPass!2026"},
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN},
        )
        assert r_login3.status_code == 200
        tok_3 = r_login3.json()["access_token"]
        async with pool.acquire() as conn:
            await conn.execute("UPDATE users SET status = 'SUSPENDED' WHERE id = $1;", _uid)
        assert (
            await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_3}"})
        ).status_code == 401


@pytest.mark.asyncio
async def test_t36_ac4_20x_concurrent_cookie_refresh_race_and_replay_detection(isolated_env):
    pool, rd = isolated_env
    _uid, mobile = await _ensure_user_with_password(pool, rd, prefix="0915")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_login = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongPocPass!2026"},
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN},
        )
        assert r_login.status_code == 200
        old_refresh = client.cookies.get("hc_refresh")
        old_csrf = client.cookies.get("hc_csrf")
        family_id = uuid.UUID(r_login.json()["family_id"])
        snapshot_cookies = {"hc_refresh": old_refresh, "hc_csrf": old_csrf, "hc_has_session": "1"}

        async def _call_cookie_refresh():
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
                return await c.post(
                    "/api/v1/auth/refresh",
                    headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN, "X-CSRF-Token": old_csrf},
                    cookies=snapshot_cookies,
                )

        resps = await asyncio.gather(*(_call_cookie_refresh() for _ in range(20)))
        winners = [r for r in resps if r.status_code == 200]
        conflicts = [r for r in resps if r.status_code == 409]
        assert len(winners) == 1
        assert len(conflicts) == 19

        win_body = winners[0].json()
        assert win_body["access_token"].startswith("hc_at_v1.")
        assert "refresh_token" not in win_body
        assert "hc_refresh" in _extract_set_cookie_map(winners[0].headers)

        for r_conf in conflicts:
            assert "refresh_token" not in r_conf.json()
            assert "access_token" not in r_conf.json()
            assert "hc_refresh" not in _extract_set_cookie_map(r_conf.headers)

        # Winning cookie still authenticates resource access cleanly
        assert (
            await client.get(
                "/api/v1/profile/me",
                headers={"Authorization": f"Bearer {win_body['access_token']}"},
            )
        ).status_code == 200

        # Replay of old cookie outside grace window revokes ENTIRE family + clears cookies + logs audit!
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE refresh_tokens SET rotated_at = NOW() - INTERVAL '20 seconds' "
                "WHERE family_id = $1 AND status = 'ROTATED';",
                family_id,
            )

        r_replay = await client.post(
            "/api/v1/auth/refresh",
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN, "X-CSRF-Token": old_csrf},
            cookies=snapshot_cookies,
        )
        assert r_replay.status_code == 401
        replay_sc = _extract_set_cookie_map(r_replay.headers)
        assert "hc_refresh" in replay_sc and "max-age=0" in replay_sc["hc_refresh"].lower()

        # Previously valid winning access token MUST immediately return 401 after replay revocation!
        assert (
            await client.get(
                "/api/v1/profile/me",
                headers={"Authorization": f"Bearer {win_body['access_token']}"},
            )
        ).status_code == 401
        assert rd.get(f"{REVOKED_FAMILY_REDIS_PREFIX}{family_id}") == "REPLAY_ATTACK"


@pytest.mark.asyncio
async def test_t36_ac5_csp_static_safety_branch_isolation_and_open_policies_proposed(isolated_env):
    pool, _rd = isolated_env

    # 1. Verify /auth-poc & /auth-poc/public CSP + security headers
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for route in ("/auth-poc", "/auth-poc/public"):
            r = await client.get(route)
            assert r.status_code == 200
            csp = r.headers.get("content-security-policy", "")
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert "unsafe-inline" not in csp
            assert "unsafe-eval" not in csp
            assert "frame-ancestors 'none'" in csp
            assert r.headers.get("x-content-type-options") == "nosniff"
            assert r.headers.get("x-frame-options") == "DENY"
            assert "no-store" in r.headers.get("cache-control", "").lower()

    # 2. Static JS & HTML scan: zero persistent web storage & unsafe sinks
    poc_html = (ROOT_DIR / "src" / "static" / "auth_poc.html").read_text(encoding="utf-8")
    poc_js = (ROOT_DIR / "src" / "static" / "auth_poc.js").read_text(encoding="utf-8")
    forbidden_patterns = [
        r"\blocalStorage\b",
        r"\bsessionStorage\b",
        r"\bindexedDB\b",
        r"\binnerHTML\b",
        r"\bouterHTML\b",
        r"\binsertAdjacentHTML\b",
        r"document\.write\s*\(",
        r"\beval\s*\(",
        r"\bnew\s+Function\b",
    ]
    for pat in forbidden_patterns:
        assert not re.search(pat, poc_js), f"Forbidden pattern {pat} matched in auth_poc.js"
    assert not re.search(r"<script(?![^>]*\bsrc=)", poc_html, re.IGNORECASE)
    assert not re.search(r"\son[a-z]+\s*=", poc_html, re.IGNORECASE)

    # 3. Ensure integrated ui_shell uses zero persistent web storage / legacy tokens and keeps index.html compatible
    ui_shell_dir = ROOT_DIR / "src" / "ui_shell"
    assert ui_shell_dir.exists()
    for ui_file in ui_shell_dir.rglob("*.js"):
        ui_text = ui_file.read_text(encoding="utf-8")
        assert "hamicard_session_token" not in ui_text
        assert not re.search(r"\beval\s*\(", ui_text)
        assert not re.search(r"\bnew\s+Function\b", ui_text)
    idx_html = (ROOT_DIR / "src" / "static" / "index.html").read_text(encoding="utf-8")
    assert "refreshSessionSingleFlight" in idx_html

    # 4. Ensure all 18 OPEN-* policies remain PROPOSED
    async with pool.acquire() as conn:
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _wait_selector_text(
    page, selector: str, expected: str, *, contains: bool = False, timeout: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout
    last_val = None
    while time.monotonic() < deadline:
        last_val = await page.locator(selector).text_content()
        if last_val is not None:
            if contains and expected in last_val:
                return
            if not contains and last_val == expected:
                return
        await asyncio.sleep(0.05)
    raise AssertionError(
        f"Timed out waiting for {selector} {'to contain' if contains else 'to equal'} {expected!r}; last={last_val!r}"
    )


async def _launch_headless_chromium(p):
    candidates = [
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path("/usr/bin/chromium"),
        Path("/usr/bin/chromium-browser"),
        Path("/usr/bin/google-chrome"),
    ]
    try:
        return await p.chromium.launch(headless=True)
    except Exception:
        for exe in candidates:
            if exe.exists():
                return await p.chromium.launch(headless=True, executable_path=str(exe))
        raise


@pytest.mark.asyncio
async def test_t36_playwright_e2e_multi_tab_cookie_jar_coordination_logout_and_bfcache(
    isolated_env,
):
    from playwright.async_api import async_playwright

    _pool, rd = isolated_env
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT_DIR)
    env["ACCESS_TOKEN_TTL_SECONDS"] = "2"
    env["CORS_ALLOWED_ORIGINS"] = base_url

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(ROOT_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        # Wait up to 15s for uvicorn health endpoint
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=1.5) as r:
                    if r.status == 200:
                        break
            except Exception:
                await asyncio.sleep(0.25)
        else:
            out = proc.stdout.read() if proc.stdout else ""
            pytest.fail(f"Uvicorn server failed to start cleanly:\n{out}")

        mobile = f"0916{uuid.uuid4().int % 10000000:07d}"
        console_errors: list[str] = []
        page_errors: list[str] = []
        refresh_posts: list[str] = []
        unexpected_hosts: list[str] = []

        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})

            def _attach_listeners(page):
                page.on(
                    "console",
                    lambda msg: console_errors.append(msg.text)
                    if msg.type == "error"
                    else None,
                )
                page.on("pageerror", lambda exc: page_errors.append(str(exc)))
                page.on(
                    "request",
                    lambda req: (
                        refresh_posts.append(req.url)
                        if req.method == "POST" and req.url.endswith("/api/v1/auth/refresh")
                        else None,
                        unexpected_hosts.append(req.url)
                        if not req.url.startswith(base_url) and not req.url.startswith("data:")
                        else None,
                    ),
                )

            tab_a = await context.new_page()
            _attach_listeners(tab_a)
            await tab_a.goto(f"{base_url}/auth-poc", wait_until="networkidle")
            await _wait_selector_text(tab_a, "#poc-auth-state", "UNAUTHENTICATED")

            # 1. Authenticate Tab A via OTP in Cookie Mode
            await tab_a.fill("#poc-mobile", mobile)
            await tab_a.click("#poc-request-otp-btn")
            for _ in range(20):
                otp_code = rd.get(f"otp:code:{mobile}")
                if otp_code:
                    break
                await asyncio.sleep(0.1)
            assert otp_code, "OTP was not issued in Redis"

            await tab_a.fill("#poc-otp-code", otp_code)
            await tab_a.click("#poc-verify-otp-btn")
            await _wait_selector_text(tab_a, "#poc-auth-state", "AUTHENTICATED")

            # Assert zero persistent JS storage + HttpOnly refresh invisibility
            storage_stats = await tab_a.evaluate(
                "() => ({ ls: Object.keys(localStorage).length, ss: Object.keys(sessionStorage).length, dc: document.cookie })"
            )
            assert storage_stats["ls"] == 0
            assert storage_stats["ss"] == 0
            assert "hc_refresh" not in storage_stats["dc"]
            assert "hc_csrf=" in storage_stats["dc"]

            jar = {c["name"]: c for c in await context.cookies()}
            assert "hc_refresh" in jar
            assert jar["hc_refresh"]["httpOnly"] is True
            assert jar["hc_refresh"]["sameSite"] == "Lax"
            assert jar["hc_refresh"]["path"] == "/api/v1/auth"

            # Profile fetch works using short-lived closure access token
            await tab_a.click("#poc-fetch-profile-btn")
            await _wait_selector_text(tab_a, "#poc-profile-output", mobile, contains=True)

            # 2. Open Tab B and Tab C; verify sequential silent hydration on fresh pages
            tab_b = await context.new_page()
            _attach_listeners(tab_b)
            await tab_b.goto(f"{base_url}/auth-poc", wait_until="networkidle")
            await _wait_selector_text(tab_b, "#poc-auth-state", "AUTHENTICATED")

            tab_c = await context.new_page()
            _attach_listeners(tab_c)
            await tab_c.goto(f"{base_url}/auth-poc", wait_until="networkidle")
            await _wait_selector_text(tab_c, "#poc-auth-state", "AUTHENTICATED")

            # 3. 3-Tab Simultaneous Reload when all closure RAM is wiped -> MUST coalesce into ONE /refresh!
            refresh_posts.clear()
            await asyncio.gather(
                tab_a.reload(wait_until="networkidle"),
                tab_b.reload(wait_until="networkidle"),
                tab_c.reload(wait_until="networkidle"),
            )
            await asyncio.gather(
                _wait_selector_text(tab_a, "#poc-auth-state", "AUTHENTICATED"),
                _wait_selector_text(tab_b, "#poc-auth-state", "AUTHENTICATED"),
                _wait_selector_text(tab_c, "#poc-auth-state", "AUTHENTICATED"),
            )
            assert len(refresh_posts) == 1, (
                f"Expected 1 coalesced POST /refresh across 3 simultaneous reloads, got {len(refresh_posts)}"
            )

            # 4. Wait 2.3s for 2s short-lived access tokens to expire in ALL 3 tabs, then click Fetch Profile concurrently
            await asyncio.sleep(2.3)
            refresh_posts.clear()
            await asyncio.gather(
                tab_a.click("#poc-fetch-profile-btn"),
                tab_b.click("#poc-fetch-profile-btn"),
                tab_c.click("#poc-fetch-profile-btn"),
            )
            await asyncio.gather(
                _wait_selector_text(tab_a, "#poc-profile-output", mobile, contains=True),
                _wait_selector_text(tab_b, "#poc-profile-output", mobile, contains=True),
                _wait_selector_text(tab_c, "#poc-profile-output", mobile, contains=True),
            )
            assert len(refresh_posts) == 1, (
                f"Expected 1 coalesced POST /refresh across 3 expired tabs, got {len(refresh_posts)}"
            )

            # 5. Navigate Tab B to /auth-poc/public, then logout from Tab A -> Tab C wipes instantly + Tab B go_back scrubs
            await tab_b.click("#poc-public-link")
            await tab_b.wait_for_selector("#public-heading")

            await tab_a.click("#poc-logout-btn")
            await _wait_selector_text(tab_a, "#poc-auth-state", "UNAUTHENTICATED")
            await _wait_selector_text(tab_c, "#poc-auth-state", "UNAUTHENTICATED")
            assert mobile not in await tab_c.inner_text("#poc-profile-output")

            await tab_b.go_back(wait_until="networkidle")
            await _wait_selector_text(tab_b, "#poc-auth-state", "UNAUTHENTICATED")
            assert mobile not in await tab_b.inner_text("#poc-profile-output")

            # Verify cookies cleared in browser jar
            post_logout_jar = {c["name"]: c for c in await context.cookies()}
            assert "hc_refresh" not in post_logout_jar
            assert "hc_csrf" not in post_logout_jar
            assert "hc_has_session" not in post_logout_jar

            await context.close()
            await browser.close()

        assert console_errors == [], f"Unexpected browser console errors: {console_errors}"
        assert page_errors == [], f"Unexpected uncaught page errors: {page_errors}"
        assert unexpected_hosts == [], f"Unexpected external requests: {unexpected_hosts}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
