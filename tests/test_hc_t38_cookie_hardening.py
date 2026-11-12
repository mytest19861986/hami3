"""
HC-T38 (`HC-CMD-039`) Targeted Security Hardening Tests (T36-L1, T36-L2, T36-L3)
BASELINE: BL-HAMICARD-PRD-V1 | Contract: HC-T33 / HC-CMD-039
"""

import os
import sys
import uuid

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
from src.api.main import app  # noqa: E402
from src.auth.service import AuthService  # noqa: E402

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
    await auth_svc.set_password(uid, "StrongT38Pass!2026")
    return uid, mobile


@pytest_asyncio.fixture
async def isolated_t38_env(monkeypatch):
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


@pytest.mark.asyncio
async def test_t38_l1_unconditional_origin_enforcement_for_cookie_logins_preserving_legacy(
    isolated_t38_env,
):
    """
    T36-L1: Under X-Auth-Mode=cookie, /otp/verify and /password/login enforce Origin/Referer
    unconditionally (rejecting omitted, null, untrusted, lookalike, and wrong-port origins with 403
    BEFORE consuming OTP or creating sessions), while legacy Origin-less JSON clients keep 200 OK.
    """
    pool, rd = isolated_t38_env
    uid, mobile_pwd = await _ensure_user_with_password(pool, rd, prefix="0917")
    mobile_otp = f"0918{uuid.uuid4().int % 10000000:07d}"
    await AuthService(pool, rd).otp_service.request_otp(mobile_otp)
    otp_code = rd.get(f"otp:code:{mobile_otp}")
    assert otp_code is not None

    bad_origin_headers = [
        {"X-Auth-Mode": "cookie"},  # Missing BOTH Origin and Referer (previously bypassed!)
        {"X-Auth-Mode": "cookie", "Origin": "null"},
        {"X-Auth-Mode": "cookie", "Origin": "https://evil-login-csrf.example"},
        {"X-Auth-Mode": "cookie", "Origin": "http://127.0.0.1:3000.evil.com"},
        {"X-Auth-Mode": "cookie", "Origin": "http://127.0.0.1:9999"},
        {"X-Auth-Mode": "cookie", "Referer": "https://evil-login-csrf.example/form"},
    ]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        for hdrs in bad_origin_headers:
            r_otp_bad = await client.post(
                "/api/v1/auth/otp/verify",
                json={"mobile": mobile_otp, "code": otp_code},
                headers=hdrs,
            )
            assert r_otp_bad.status_code == 403, f"Expected 403 for {hdrs}, got {r_otp_bad.status_code}"
            assert "hc_refresh" not in _extract_set_cookie_map(r_otp_bad.headers)
            assert rd.get(f"otp:code:{mobile_otp}") == otp_code  # Unconsumed!

            r_pwd_bad = await client.post(
                "/api/v1/auth/password/login",
                json={"mobile": mobile_pwd, "password": "StrongT38Pass!2026"},
                headers=hdrs,
            )
            assert r_pwd_bad.status_code == 403, f"Expected 403 for {hdrs}, got {r_pwd_bad.status_code}"
            assert "hc_refresh" not in _extract_set_cookie_map(r_pwd_bad.headers)

        async with pool.acquire() as conn:
            pwd_sessions = await conn.fetchval(
                "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1;", uid
            )
            # Only the 1 initial OTP setup session exists
            assert pwd_sessions == 1

        # Valid Referer-only cookie login works cleanly (200)
        r_ref_login = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile_pwd, "password": "StrongT38Pass!2026"},
            headers={"X-Auth-Mode": "cookie", "Referer": f"{LOCAL_ORIGIN}/auth-poc"},
        )
        assert r_ref_login.status_code == 200, r_ref_login.text
        assert "hc_refresh" in _extract_set_cookie_map(r_ref_login.headers)

        # Documented legacy Origin-less JSON /otp/verify and /password/login still succeed (200)
        client.cookies.clear()
        r_legacy_otp = await client.post(
            "/api/v1/auth/otp/verify",
            json={"mobile": mobile_otp, "code": otp_code},
        )
        assert r_legacy_otp.status_code == 200, r_legacy_otp.text
        assert r_legacy_otp.json()["session"]["refresh_token"]

        r_legacy_pwd = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile_pwd, "password": "StrongT38Pass!2026"},
        )
        assert r_legacy_pwd.status_code == 200, r_legacy_pwd.text
        assert r_legacy_pwd.json()["session"]["refresh_token"]


@pytest.mark.asyncio
async def test_t38_l2_hc_has_session_non_authoritative_and_cookie_tossing_isolation(
    isolated_t38_env,
):
    """
    T36-L2: Ambient `hc_has_session` / `hc_csrf` cookies NEVER grant authentication or RBAC
    authority, NEVER switch legacy JSON/Bearer `/refresh` or `/logout` into cookie mode, and
    explicit `X-Auth-Mode: bearer` overrides ambient browser cookies.
    """
    pool, rd = isolated_t38_env
    _uid, mobile = await _ensure_user_with_password(pool, rd, prefix="0919")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Authenticate purely via legacy JSON mode (zero HttpOnly cookies stored)
        r_legacy = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongT38Pass!2026"},
        )
        assert r_legacy.status_code == 200
        tok_1 = r_legacy.json()["session"]["refresh_token"]

        # Simulate co-resident hostile/legacy subdomain/app tossing ambient hint + CSRF cookies!
        tossed = {"hc_has_session": "1", "hc_csrf": "tossed-nonce.forged-mac"}

        # Ambient hint/CSRF NEVER grant auth or admin/moderator authority
        r_me = await client.get("/api/v1/profile/me", cookies=tossed)
        assert r_me.status_code == 401
        r_admin = await client.put(
            f"/api/v1/reviews/{uuid.uuid4()}/moderate",
            json={"is_published": True},
            cookies=tossed,
        )
        assert r_admin.status_code == 401
        r_ref_no_auth = await client.post(
            "/api/v1/auth/refresh",
            headers={"X-Auth-Mode": "cookie", "Origin": LOCAL_ORIGIN, "X-CSRF-Token": "tossed-nonce.forged-mac"},
            cookies=tossed,
        )
        assert r_ref_no_auth.status_code == 401

        # 2. Legacy JSON /refresh MUST NOT be hijacked into cookie mode (400/403) by tossed cookies!
        r_ref_legacy = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tok_1},
            cookies=tossed,
        )
        assert r_ref_legacy.status_code == 200, r_ref_legacy.text
        tok_2 = r_ref_legacy.json()["refresh_token"]
        assert tok_2 != tok_1

        # 3. Legacy Bearer /logout MUST NOT be hijacked into cookie mode (403) by tossed cookies!
        r_out_legacy = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tok_2}"},
            cookies=tossed,
        )
        assert r_out_legacy.status_code == 200, r_out_legacy.text
        assert "auth_mode" not in r_out_legacy.json()

        # 4. Explicit `X-Auth-Mode: bearer` stays legacy even if stale/stray `hc_refresh` sits in jar
        r_legacy_2 = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongT38Pass!2026"},
        )
        assert r_legacy_2.status_code == 200
        tok_3 = r_legacy_2.json()["session"]["refresh_token"]

        stray_jar = {**tossed, "hc_refresh": "stale_cookie_from_other_tab"}
        r_explicit_bearer_ref = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tok_3},
            headers={"X-Auth-Mode": "bearer"},
            cookies=stray_jar,
        )
        assert r_explicit_bearer_ref.status_code == 200, r_explicit_bearer_ref.text
        tok_4 = r_explicit_bearer_ref.json()["refresh_token"]

        r_explicit_bearer_out = await client.post(
            "/api/v1/auth/logout",
            headers={"X-Auth-Mode": "bearer", "Authorization": f"Bearer {tok_4}"},
            cookies=stray_jar,
        )
        assert r_explicit_bearer_out.status_code == 200, r_explicit_bearer_out.text


@pytest.mark.asyncio
async def test_t38_l3_logout_signing_preflight_503_and_normalized_redis_outage_handling(
    isolated_t38_env, monkeypatch
):
    """
    T36-L3:
    1. Cookie-mode /logout with missing/invalid signing secret in restricted env fails closed
       with deterministic HTTP 503 (NOT 403), `Cache-Control: no-store`, `clear_cookies=False`,
       and zero session revocation in PostgreSQL.
    2. During Redis outage on /logout:
       - Cookie mode revokes BOTH cookie family and secondary Bearer family in PG SSOT before 503 + clears cookies.
       - Legacy Bearer mode returns uniform HTTP 503 + `Cache-Control: no-store` both at `get_current_user`
         AND during write-time family revocation (revoking both Bearer family and payload refresh_token family in PG).
    """
    pool, rd = isolated_t38_env
    _uid, mobile = await _ensure_user_with_password(pool, rd, prefix="0911")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.hamicard.example") as client:
        monkeypatch.setenv("ENVIRONMENT", "staging")
        monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.hamicard.example")
        monkeypatch.setenv("SMS_PROVIDER", "kavenegar")
        monkeypatch.setenv("KAVENEGAR_API_KEY", "test-staging-kavenegar-key-123456")
        monkeypatch.setenv("ACCESS_TOKEN_SECRET", "ProdStrongT38LogoutSecret!2026#888")

        # 1. Cookie login #1 + CSRF secret preflight check on /logout
        r_c1 = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongT38Pass!2026"},
            headers={"X-Auth-Mode": "cookie", "Origin": "https://app.hamicard.example"},
        )
        assert r_c1.status_code == 200
        fam_1 = uuid.UUID(r_c1.json()["family_id"])
        sess_1 = uuid.UUID(r_c1.json()["session_id"])
        csrf_1 = client.cookies.get("hc_csrf")

        monkeypatch.delenv("ACCESS_TOKEN_SECRET", raising=False)
        r_out_503 = await client.post(
            "/api/v1/auth/logout",
            headers={
                "X-Auth-Mode": "cookie",
                "Origin": "https://app.hamicard.example",
                "X-CSRF-Token": csrf_1,
            },
        )
        assert r_out_503.status_code == 503
        assert "no-store" in r_out_503.headers.get("cache-control", "").lower()
        assert "hc_refresh" not in _extract_set_cookie_map(r_out_503.headers)
        async with pool.acquire() as conn:
            assert (
                await conn.fetchval("SELECT status FROM refresh_tokens WHERE id = $1;", sess_1)
            ) == "ACTIVE"

        # Restore signing config; create a SECOND cookie family (`fam_2`) and verify dual-family revocation under Redis outage
        monkeypatch.setenv("ACCESS_TOKEN_SECRET", "ProdStrongT38LogoutSecret!2026#888")
        async with httpx.AsyncClient(
            transport=transport, base_url="https://app.hamicard.example"
        ) as second_client:
            r_c2 = await second_client.post(
                "/api/v1/auth/password/login",
                json={"mobile": mobile, "password": "StrongT38Pass!2026"},
                headers={"X-Auth-Mode": "cookie", "Origin": "https://app.hamicard.example"},
            )
            assert r_c2.status_code == 200
            fam_2 = uuid.UUID(r_c2.json()["family_id"])
            tok_2 = r_c2.json()["access_token"]

        class _BrokenSetRedis:
            def get(self, key):
                return None

            def set(self, *_args, **_kwargs):
                raise redis.ConnectionError("Simulated Redis write outage")

        class _BrokenAllRedis:
            def get(self, *_args, **_kwargs):
                raise redis.ConnectionError("Simulated total Redis outage")

            def set(self, *_args, **_kwargs):
                raise redis.ConnectionError("Simulated total Redis outage")

        orig_redis = deps._redis
        monkeypatch.setattr(deps, "_redis", _BrokenSetRedis())
        try:
            r_dual_out = await client.post(
                "/api/v1/auth/logout",
                headers={
                    "X-Auth-Mode": "cookie",
                    "Origin": "https://app.hamicard.example",
                    "X-CSRF-Token": csrf_1,
                    "Authorization": f"Bearer {tok_2}",
                },
            )
            assert r_dual_out.status_code == 503
            assert "no-store" in r_dual_out.headers.get("cache-control", "").lower()
            sc_dual = _extract_set_cookie_map(r_dual_out.headers)
            assert "hc_refresh" in sc_dual and "max-age=0" in sc_dual["hc_refresh"].lower()
        finally:
            monkeypatch.setattr(deps, "_redis", orig_redis)

        async with pool.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND status = 'ACTIVE';",
                    fam_1,
                )
            ) == 0
            assert (
                await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND status = 'ACTIVE';",
                    fam_2,
                )
            ) == 0

        # 3. Legacy Bearer /logout under write-time AND read-time Redis failure -> normalized 503 + no-store + PG revoked
        client.cookies.clear()
        r_leg_a = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongT38Pass!2026"},
        )
        r_leg_b = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongT38Pass!2026"},
        )
        assert r_leg_a.status_code == 200 and r_leg_b.status_code == 200
        leg_tok_a = r_leg_a.json()["session"]["refresh_token"]
        leg_fam_a = uuid.UUID(r_leg_a.json()["session"]["family_id"])
        leg_tok_b = r_leg_b.json()["session"]["refresh_token"]
        leg_fam_b = uuid.UUID(r_leg_b.json()["session"]["family_id"])

        monkeypatch.setattr(deps, "_redis", _BrokenSetRedis())
        try:
            r_leg_write_down = await client.post(
                "/api/v1/auth/logout",
                json={"refresh_token": leg_tok_b},
                headers={"Authorization": f"Bearer {leg_tok_a}"},
            )
            assert r_leg_write_down.status_code == 503
            assert "no-store" in r_leg_write_down.headers.get("cache-control", "").lower()
            assert "detail" in r_leg_write_down.json()
        finally:
            monkeypatch.setattr(deps, "_redis", orig_redis)

        async with pool.acquire() as conn:
            assert (
                await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE family_id IN ($1, $2) AND status = 'ACTIVE';",
                    leg_fam_a,
                    leg_fam_b,
                )
            ) == 0

        # Read-time Redis outage before revoke -> normalized 503 + no-store + {"detail": ...}
        r_leg_c = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": mobile, "password": "StrongT38Pass!2026"},
        )
        leg_tok_c = r_leg_c.json()["session"]["refresh_token"]
        monkeypatch.setattr(deps, "_redis", _BrokenAllRedis())
        try:
            r_leg_read_down = await client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {leg_tok_c}"},
            )
            assert r_leg_read_down.status_code == 503
            assert "no-store" in r_leg_read_down.headers.get("cache-control", "").lower()
            assert "detail" in r_leg_read_down.json()
        finally:
            monkeypatch.setattr(deps, "_redis", orig_redis)

