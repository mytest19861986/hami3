"""
Isolated Acceptance Test Suite for Simplified Architecture B2 (HC-T52-SIMPLIFIED-B2 / HC-T53)
BASELINE: BL-HAMICARD-PRD-V1 | BASE: develop @ 309a5853a3e9ee5503b4866b9370a8398c97264f
DESIGN SPEC: docs/AUTH_SIMPLIFIED_B2_ARCHITECTURE.md

Covers all 11 mandatory adversarial scenarios (HC-COMMANDER-015):
- CE-B2-01: Simultaneous first-tab bootstrap (two uncookied tabs + ASGI barrier)
- CE-B2-02: Concurrent login across two tabs (Web Lock + server Phase B lock)
- CE-B2-03: Login response racing with Logout (Password & OTP slow barriers + forged gen)
- CE-B2-04: Logout followed cleanly by a new login
- CE-B2-05: Concurrent refresh and single-use rotation (HTTP storm + Web Lock)
- CE-B2-06: Missing Web Locks support (fail-closed WEB_LOCKS_UNAVAILABLE, 0 HTTP calls)
- CE-B2-07: Stale access token after Logout (long TTL immediate revocation + Redis 503)
- CE-B2-08: Multi-device session isolation (same user B != A, unrelated User B)
- CE-B2-09: PostgreSQL mid-tx crash after DML + Redis outage & dual SKIP LOCKED reconcilers
- CE-B2-10: CSRF, Origin, refresh replay, Lua ZSET rate limit (0 PG DML on Redis 503)
- CE-B2-11: Adversarial garbage collection (preserves live/pending parent & child rows)
"""

from __future__ import annotations

import asyncio
import importlib
import os
import secrets
import socket
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
import httpx
import jwt
import pytest
import redis
import uvicorn
from playwright.async_api import async_playwright

from src.api import deps
from src.api.main import create_app
from src.core.security import hash_password

DEFAULT_PG_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_b2_isolated",
)
DEFAULT_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/15")
TEST_ACCESS_SECRET = "hamicard-b2-test-access-token-secret-at-least-64-chars-long-2026!"
TEST_QR_SECRET = "hamicard-b2-test-card-qr-secret-at-least-64-chars-long-2026!"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _extract_cookies_dict(resp: httpx.Response) -> dict[str, str]:
    jar: dict[str, str] = {}
    for k, v in resp.cookies.items():
        jar[k] = v
    return jar


def _set_cookie_headers(resp: httpx.Response) -> list[str]:
    return [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]


async def _create_test_user(
    pool: asyncpg.Pool,
    mobile: str,
    password: str = "HamiStrong!2026",
    status: str = "ACTIVE",
) -> uuid.UUID:
    pw_hash = hash_password(password)
    async with pool.acquire() as conn:
        async with conn.transaction():
            uid = await conn.fetchval(
                """
                INSERT INTO users (mobile, status, password_hash, is_mobile_verified)
                VALUES ($1, $2, $3, TRUE)
                RETURNING id;
                """,
                mobile,
                status,
                pw_hash,
            )
            await conn.execute(
                """
                INSERT INTO user_roles (user_id, role_id)
                VALUES ($1, 'USER')
                ON CONFLICT DO NOTHING;
                """,
                uid,
            )
            await conn.execute(
                """
                INSERT INTO wallets (user_id, withdrawable_balance_toman, locked_balance_toman, status)
                VALUES ($1, 0, 0, 'ACTIVE')
                ON CONFLICT (user_id) DO NOTHING;
                """,
                uid,
            )
            return uid


async def _require_b2_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        bs_exists = await conn.fetchval("SELECT to_regclass('public.browser_sessions');")
        ro_exists = await conn.fetchval("SELECT to_regclass('public.revocation_outbox');")
    assert bs_exists is not None, "B2 schema missing: table public.browser_sessions does not exist."
    assert ro_exists is not None, "B2 schema missing: table public.revocation_outbox does not exist."


@asynccontextmanager
async def _running_b2_server(asgi_wrapper=None, extra_env: dict[str, str] | None = None):
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    prev_env: dict[str, str | None] = {}
    updates = {
        "APP_ENV": "test",
        "ENVIRONMENT": "test",
        "NODE_ENV": "test",
        "DATABASE_URL": os.getenv("DATABASE_URL", DEFAULT_PG_URL),
        "REDIS_URL": os.getenv("REDIS_URL", DEFAULT_REDIS_URL),
        "CORS_ALLOWED_ORIGINS": f"http://127.0.0.1:{port},http://localhost:{port}",
        "ACCESS_TOKEN_SECRET": TEST_ACCESS_SECRET,
        "JWT_SECRET": TEST_ACCESS_SECRET,
        "ACCESS_TOKEN_TTL_SECONDS": "300",
        "CARD_QR_SECRET": TEST_QR_SECRET,
        "COOKIE_SECURE": "false",
    }
    if extra_env:
        updates.update(extra_env)

    for k, v in updates.items():
        prev_env[k] = os.environ.get(k)
        os.environ[k] = v

    # Reset deps singletons so the test server binds cleanly to isolated DB/Redis env
    await deps.close_pool()
    deps.close_redis()

    app = create_app()
    asgi_app = asgi_wrapper(app) if asgi_wrapper is not None else app
    config = uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=5.0) as probe:
            deadline = time.monotonic() + 10.0
            ready = False
            while time.monotonic() < deadline:
                try:
                    r = await probe.get("/api/v1/health")
                    if r.status_code == 200:
                        ready = True
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.05)
            assert ready, f"Uvicorn test server at {base_url} failed to become healthy."
        yield base_url, app
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(server_task, timeout=8.0)
        except Exception:
            server_task.cancel()
        await deps.close_pool()
        deps.close_redis()
        for k, old in prev_env.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


async def _bootstrap_cookie_session(
    client: httpx.AsyncClient,
    origin: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    resp = await client.post(
        "/api/v1/auth/browser/bootstrap",
        headers={"Origin": origin},
        json={},
    )
    assert resp.status_code == 200, (
        f"POST /api/v1/auth/browser/bootstrap expected 200, got {resp.status_code}: {resp.text}"
    )
    cookies = _extract_cookies_dict(resp)
    assert cookies.get("hc_browser"), "bootstrap response missing hc_browser cookie"
    assert cookies.get("hc_csrf"), "bootstrap response missing hc_csrf cookie"
    body = resp.json()
    assert isinstance(body.get("auth_generation"), int), f"Invalid bootstrap body: {body}"
    return cookies, body


@pytest.fixture(autouse=True)
async def _isolated_redis_cleanup():
    r_url = os.getenv("REDIS_URL", DEFAULT_REDIS_URL)
    assert r_url.endswith("/15"), f"Refusing test run against non-isolated Redis URL: {r_url}"
    os.environ.setdefault("DATABASE_URL", DEFAULT_PG_URL)
    os.environ.setdefault("REDIS_URL", DEFAULT_REDIS_URL)
    r = redis.Redis.from_url(r_url, decode_responses=True)
    r.flushdb()
    try:
        yield
    finally:
        r.flushdb()
        r.close()


# =============================================================================
# CE-B2-01: Simultaneous First-Tab Bootstrap (4.F, 4.C)
# =============================================================================
async def test_ce_b2_01_simultaneous_first_tab_bootstrap() -> None:
    unbootstrapped_count = 0
    first_entered = threading.Event()
    release_first = threading.Event()

    def _bootstrap_barrier_asgi(inner_app):
        async def wrapper(scope, receive, send):
            nonlocal unbootstrapped_count
            if (
                scope["type"] == "http"
                and scope.get("method") == "POST"
                and scope.get("path") == "/api/v1/auth/browser/bootstrap"
            ):
                headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
                cookie_hdr = headers.get("cookie", "")
                if "hc_browser=" not in cookie_hdr:
                    unbootstrapped_count += 1
                    if unbootstrapped_count == 1:
                        first_entered.set()
                        await asyncio.to_thread(release_first.wait, 5.0)
            await inner_app(scope, receive, send)

        return wrapper

    async with _running_b2_server(asgi_wrapper=_bootstrap_barrier_asgi) as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page_a = await context.new_page()
            page_b = await context.new_page()
            try:
                async def _open_tab_a():
                    resp_a = await page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="domcontentloaded")
                    assert resp_a is not None and resp_a.status == 200, (
                        f"Expected 200 on /phase3/#/auth/shell (Tab A), got {resp_a.status if resp_a else None}"
                    )

                async def _open_tab_b():
                    await asyncio.to_thread(first_entered.wait, 5.0)
                    resp_b = await page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="domcontentloaded")
                    assert resp_b is not None and resp_b.status == 200, (
                        f"Expected 200 on /phase3/#/auth/shell (Tab B), got {resp_b.status if resp_b else None}"
                    )

                task_a = asyncio.create_task(_open_tab_a())
                task_b = asyncio.create_task(_open_tab_b())
                await asyncio.sleep(0.25)
                release_first.set()
                await asyncio.gather(task_a, task_b)

                await page_a.wait_for_selector("#hc-browser-status[data-ready='true']", timeout=5000)
                await page_b.wait_for_selector("#hc-browser-status[data-ready='true']", timeout=5000)

                cookies = await context.cookies()
                hc_browsers = [c for c in cookies if c["name"] == "hc_browser"]
                assert len(hc_browsers) == 1, f"Expected exact 1 hc_browser cookie, got {len(hc_browsers)}"
                assert hc_browsers[0]["httpOnly"] is True
                assert unbootstrapped_count == 1, (
                    f"Web Lock 'hamicard_auth_op' failed to serialize uncookied bootstrap: "
                    f"saw {unbootstrapped_count} unbootstrapped calls."
                )

                raw_bid = hc_browsers[0]["value"].split(".", 1)[0]
                async with pool.acquire() as conn:
                    bs_rows = await conn.fetch(
                        "SELECT browser_id, auth_generation, active_status FROM browser_sessions WHERE browser_id = $1;",
                        raw_bid,
                    )
                assert len(bs_rows) == 1, f"Expected 1 browser_sessions row, got {len(bs_rows)}"
                assert bs_rows[0]["active_status"] == "LOGGED_OUT"
            finally:
                release_first.set()
                await context.close()
                await browser.close()


# =============================================================================
# CE-B2-02: Concurrent Login Across Two Tabs (4.A, 4.C)
# =============================================================================
async def test_ce_b2_02_concurrent_login_across_two_tabs() -> None:
    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        password = "HamiB2Concurrent!2026"
        uid = await _create_test_user(pool, mobile, password=password)

        # Part A: Two simultaneous Playwright tabs sharing cookie jar
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page_a = await context.new_page()
            page_b = await context.new_page()
            try:
                resp_a = await page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="domcontentloaded")
                assert resp_a is not None and resp_a.status == 200, (
                    f"Expected 200 on /phase3/#/auth/shell, got {resp_a.status if resp_a else None}"
                )
                resp_b = await page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="domcontentloaded")
                assert resp_b is not None and resp_b.status == 200

                await page_a.wait_for_selector("#hc-browser-status[data-ready='true']", timeout=5000)
                await page_b.wait_for_selector("#hc-browser-status[data-ready='true']", timeout=5000)

                await page_a.fill("#hc-login-mobile", mobile)
                await page_a.fill("#hc-login-password", password)
                await page_b.fill("#hc-login-mobile", mobile)
                await page_b.fill("#hc-login-password", password)

                await asyncio.gather(
                    page_a.evaluate("() => document.getElementById('hc-pwd-login-btn').click()"),
                    page_b.evaluate("() => document.getElementById('hc-pwd-login-btn').click()"),
                )
                await page_a.wait_for_selector("#hc-session-badge[data-authenticated='true']", timeout=8000)
                await page_b.wait_for_selector("#hc-session-badge[data-authenticated='true']", timeout=8000)

                cookies = await context.cookies()
                raw_bid = [c["value"].split(".", 1)[0] for c in cookies if c["name"] == "hc_browser"][0]
                async with pool.acquire() as conn:
                    active_cnt = await conn.fetchval(
                        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                        uid,
                    )
                    bs = await conn.fetchrow(
                        "SELECT active_family_id, active_status FROM browser_sessions WHERE browser_id = $1;",
                        raw_bid,
                    )
                assert active_cnt == 1, f"Expected strictly 1 ACTIVE token family after 2-tab login, got {active_cnt}"
                assert bs and bs["active_status"] == "ACTIVE" and bs["active_family_id"] is not None
            finally:
                await context.close()
                await browser.close()

        # Part B: Direct simultaneous HTTP login bypassing Web Locks -> server Phase B lock serializes cleanly
        async with httpx.AsyncClient(base_url=base_url) as client:
            cookies, boot = await _bootstrap_cookie_session(client, base_url)
            gen = boot["auth_generation"]
            headers = {
                "Origin": base_url,
                "X-Auth-Mode": "cookie",
                "X-CSRF-Token": cookies["hc_csrf"],
            }
            payload = {"mobile": mobile, "password": password, "expected_auth_generation": gen}
            r1, r2 = await asyncio.gather(
                client.post("/api/v1/auth/password/login", headers=headers, cookies=cookies, json=payload),
                client.post("/api/v1/auth/password/login", headers=headers, cookies=cookies, json=payload),
            )
            assert r1.status_code == 200 and r2.status_code == 200, (
                f"Both sequential/superseded logins expected 200, got {r1.status_code}, {r2.status_code}"
            )
            fams = {r1.json()["session"]["family_id"], r2.json()["session"]["family_id"]}
            assert len(fams) == 2

            raw_bid = cookies["hc_browser"].split(".", 1)[0]
            async with pool.acquire() as conn:
                active_rows = await conn.fetch(
                    "SELECT family_id FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                    uid,
                )
                bs_after = await conn.fetchrow(
                    "SELECT active_family_id FROM browser_sessions WHERE browser_id = $1;",
                    raw_bid,
                )
            distinct_active = {str(r["family_id"]) for r in active_rows}
            # Only winner of Phase B on this browser stays ACTIVE (note Playwright browser was separate browser_id -> total user active <= 2, THIS browser_id's superseded family is REVOKED)
            assert bs_after is not None and str(bs_after["active_family_id"]) in fams
            superseded_fams = fams - {str(bs_after["active_family_id"])}
            async with pool.acquire() as conn:
                sup_status = await conn.fetchval(
                    "SELECT status FROM refresh_tokens WHERE family_id = $1;",
                    uuid.UUID(next(iter(superseded_fams))),
                )
            assert sup_status == "REVOKED", f"Superseded same-browser family must be REVOKED, got {sup_status}"
            r_cli = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
            try:
                assert r_cli.exists(f"hc:revoked_family:{next(iter(superseded_fams))}") == 1
            finally:
                r_cli.close()
            assert distinct_active.intersection(superseded_fams) == set()


# =============================================================================
# CE-B2-03: Login Response Racing With Logout (4.B)
# =============================================================================
async def test_ce_b2_03_login_response_racing_with_logout() -> None:
    import src.auth.service as auth_service_mod
    from src.auth.otp_service import OtpService

    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        password = "HamiB2RacePassword!2026"
        uid = await _create_test_user(pool, mobile, password=password)

        orig_verify_pw = auth_service_mod.verify_password
        orig_verify_otp = OtpService.verify_otp

        pw_entered = threading.Event()
        pw_release = threading.Event()
        otp_entered = threading.Event()
        otp_release = threading.Event()

        def _slow_verify_pw(plain: str, hashed: str) -> bool:
            pw_entered.set()
            pw_release.wait(timeout=5.0)
            return orig_verify_pw(plain, hashed)

        def _slow_verify_otp(self, mob: str, code: str) -> bool:
            otp_entered.set()
            otp_release.wait(timeout=5.0)
            return orig_verify_otp(self, mob, code)

        async with httpx.AsyncClient(base_url=base_url) as client:
            cookies, boot = await _bootstrap_cookie_session(client, base_url)
            g0 = boot["auth_generation"]

            # 0. Forged / missing expected_auth_generation must fail 409 immediately
            forged_resp = await client.post(
                "/api/v1/auth/password/login",
                headers={
                    "Origin": base_url,
                    "X-Auth-Mode": "cookie",
                    "X-CSRF-Token": cookies["hc_csrf"],
                },
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": 999},
            )
            assert forged_resp.status_code == 409, (
                f"Forged expected_auth_generation=999 must fail 409, got {forged_resp.status_code}"
            )
            missing_gen_resp = await client.post(
                "/api/v1/auth/password/login",
                headers={
                    "Origin": base_url,
                    "X-Auth-Mode": "cookie",
                    "X-CSRF-Token": cookies["hc_csrf"],
                },
                cookies=cookies,
                json={"mobile": mobile, "password": password},
            )
            assert missing_gen_resp.status_code == 409, (
                f"Missing expected_auth_generation in cookie mode must fail 409, got {missing_gen_resp.status_code}"
            )

            # 1. Password Login interrupted mid-verification by Logout
            auth_service_mod.verify_password = _slow_verify_pw
            try:
                async def _call_slow_pw_login():
                    return await client.post(
                        "/api/v1/auth/password/login",
                        headers={
                            "Origin": base_url,
                            "X-Auth-Mode": "cookie",
                            "X-CSRF-Token": cookies["hc_csrf"],
                        },
                        cookies=cookies,
                        json={"mobile": mobile, "password": password, "expected_auth_generation": g0},
                    )

                pw_task = asyncio.create_task(_call_slow_pw_login())
                assert await asyncio.to_thread(pw_entered.wait, 5.0), "Password verification barrier never reached"

                logout_resp = await client.post(
                    "/api/v1/auth/logout",
                    headers={
                        "Origin": base_url,
                        "X-Auth-Mode": "cookie",
                        "X-CSRF-Token": cookies["hc_csrf"],
                    },
                    cookies=cookies,
                )
                assert logout_resp.status_code == 200, f"Concurrent logout failed: {logout_resp.text}"
                g1 = logout_resp.json().get("auth_generation")
                assert g1 == g0 + 1, f"Expected auth_generation bump {g0}->{g0+1}, got {g1}"
                cookies.update(_extract_cookies_dict(logout_resp))

                pw_release.set()
                delayed_pw = await pw_task
                assert delayed_pw.status_code == 409, (
                    f"CRITICAL SECURITY FAILURE: Delayed password login returned {delayed_pw.status_code} "
                    f"instead of 409 LOGIN_FENCED_BY_LOGOUT!"
                )
                assert not any("hc_refresh=" in h and "Max-Age=0" not in h for h in _set_cookie_headers(delayed_pw)), (
                    "Delayed password login must NEVER set hc_refresh cookie after logout!"
                )
            finally:
                pw_release.set()
                auth_service_mod.verify_password = orig_verify_pw

            async with pool.acquire() as conn:
                pw_active = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                    uid,
                )
            assert pw_active == 0, f"Expected 0 active tokens after fenced password login, found {pw_active}"

            # 2. OTP Verification interrupted mid-verification by Logout
            r_cli = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
            try:
                r_cli.setex(f"otp:code:{mobile}", 120, "654321")
            finally:
                r_cli.close()

            OtpService.verify_otp = _slow_verify_otp
            try:
                async def _call_slow_otp_verify():
                    return await client.post(
                        "/api/v1/auth/otp/verify",
                        headers={
                            "Origin": base_url,
                            "X-Auth-Mode": "cookie",
                            "X-CSRF-Token": cookies["hc_csrf"],
                        },
                        cookies=cookies,
                        json={"mobile": mobile, "code": "654321", "expected_auth_generation": g1},
                    )

                otp_task = asyncio.create_task(_call_slow_otp_verify())
                assert await asyncio.to_thread(otp_entered.wait, 5.0), "OTP verification barrier never reached"

                logout_resp2 = await client.post(
                    "/api/v1/auth/logout",
                    headers={
                        "Origin": base_url,
                        "X-Auth-Mode": "cookie",
                        "X-CSRF-Token": cookies["hc_csrf"],
                    },
                    cookies=cookies,
                )
                assert logout_resp2.status_code == 200
                g2 = logout_resp2.json().get("auth_generation")
                assert g2 == g1 + 1

                otp_release.set()
                delayed_otp = await otp_task
                assert delayed_otp.status_code == 409, (
                    f"CRITICAL SECURITY FAILURE: Delayed OTP login returned {delayed_otp.status_code} "
                    f"instead of 409 LOGIN_FENCED_BY_LOGOUT!"
                )
                assert not any("hc_refresh=" in h and "Max-Age=0" not in h for h in _set_cookie_headers(delayed_otp))
            finally:
                otp_release.set()
                OtpService.verify_otp = orig_verify_otp

            async with pool.acquire() as conn:
                otp_active = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                    uid,
                )
            assert otp_active == 0, f"Expected 0 active tokens after fenced OTP login, found {otp_active}"


# =============================================================================
# CE-B2-04: Logout Followed By A New Login (4.B)
# =============================================================================
async def test_ce_b2_04_logout_followed_by_new_login() -> None:
    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        password = "HamiB2Relogin!2026"
        uid = await _create_test_user(pool, mobile, password=password)

        async with httpx.AsyncClient(base_url=base_url) as client:
            cookies, boot = await _bootstrap_cookie_session(client, base_url)
            login1 = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": boot["auth_generation"]},
            )
            assert login1.status_code == 200
            cookies.update(_extract_cookies_dict(login1))
            f1 = login1.json()["session"]["family_id"]

            logout1 = await client.post(
                "/api/v1/auth/logout",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
            )
            assert logout1.status_code == 200
            cookies.update(_extract_cookies_dict(logout1))
            # Re-bootstrap cleanly after logout and verify updated auth_generation works
            cookies2, boot2 = await _bootstrap_cookie_session(client, base_url)
            cookies.update(cookies2)
            assert boot2["authenticated"] is False
            assert boot2["auth_generation"] == boot["auth_generation"] + 1

            login2 = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": boot2["auth_generation"]},
            )
            assert login2.status_code == 200, f"Fresh post-logout login failed: {login2.text}"
            cookies.update(_extract_cookies_dict(login2))
            body2 = login2.json()
            f2 = body2["session"]["family_id"]
            assert f2 != f1

            me = await client.get(
                "/api/v1/profile/me",
                headers={"Authorization": f"Bearer {body2['access_token']}"},
            )
            assert me.status_code == 200

            ref = await client.post(
                "/api/v1/auth/refresh",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={},
            )
            assert ref.status_code == 200
            async with pool.acquire() as conn:
                f1_st = await conn.fetchval(
                    "SELECT status FROM refresh_tokens WHERE family_id = $1 LIMIT 1;", uuid.UUID(f1)
                )
                active_cnt = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';", uid
                )
            assert f1_st == "REVOKED"
            assert active_cnt == 1


# =============================================================================
# CE-B2-05: Concurrent Refresh and Rotation (4.C, §4.5)
# =============================================================================
async def test_ce_b2_05_concurrent_refresh_and_rotation() -> None:
    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        password = "HamiB2Refresh!2026"
        await _create_test_user(pool, mobile, password=password)

        async with httpx.AsyncClient(base_url=base_url) as client:
            cookies, boot = await _bootstrap_cookie_session(client, base_url)
            login_resp = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": boot["auth_generation"]},
            )
            assert login_resp.status_code == 200
            cookies.update(_extract_cookies_dict(login_resp))
            r1 = cookies["hc_refresh"]

            hdrs = {"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]}
            storm = await asyncio.gather(
                *[client.post("/api/v1/auth/refresh", headers=hdrs, cookies=cookies, json={}) for _ in range(5)]
            )
            winners = [r for r in storm if r.status_code == 200]
            conflicts = [r for r in storm if r.status_code == 409]
            assert len(winners) == 1, f"Expected exact 1 winner (200), got statuses {[r.status_code for r in storm]}"
            assert len(conflicts) == 4, f"Expected 4 409 conflicts, got {[r.status_code for r in storm]}"

            for c_resp in conflicts:
                c_text = c_resp.text
                assert "refresh_token" not in c_text and "access_token" not in c_text
                assert not any("hc_refresh=" in h for h in _set_cookie_headers(c_resp))

            winner_cookies = _extract_cookies_dict(winners[0])
            r2 = winner_cookies["hc_refresh"]
            assert r2 != r1
            cookies.update(winner_cookies)

            followup = await client.post(
                "/api/v1/auth/refresh",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={},
            )
            assert followup.status_code == 200, f"Rotated token R2 should refresh cleanly, got {followup.status_code}"

        # Part B: Two Playwright tabs calling window.hamicardAuth.refreshSession() simultaneously share Web Lock
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page_a = await context.new_page()
            page_b = await context.new_page()
            refresh_statuses: list[int] = []

            def _on_response(resp):
                if "/api/v1/auth/refresh" in resp.url:
                    refresh_statuses.append(resp.status)

            page_a.on("response", _on_response)
            page_b.on("response", _on_response)
            try:
                r_a = await page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="domcontentloaded")
                assert r_a is not None and r_a.status == 200
                r_b = await page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="domcontentloaded")
                assert r_b is not None and r_b.status == 200
                await page_a.wait_for_selector("#hc-browser-status[data-ready='true']", timeout=5000)
                await page_a.fill("#hc-login-mobile", mobile)
                await page_a.fill("#hc-login-password", password)
                await page_a.click("#hc-pwd-login-btn")
                await page_a.wait_for_selector("#hc-session-badge[data-authenticated='true']", timeout=8000)

                await asyncio.gather(
                    page_a.evaluate("() => window.hamicardAuth.refreshSession()"),
                    page_b.evaluate("() => window.hamicardAuth.refreshSession()"),
                )
                assert refresh_statuses == [200, 200], (
                    f"Web Lock 'hamicard_auth_op' must serialize cross-tab refresh cleanly with [200, 200], got {refresh_statuses}"
                )
            finally:
                await context.close()
                await browser.close()


# =============================================================================
# CE-B2-06: Missing Web Locks Support (4.B, 4.C)
# =============================================================================
async def test_ce_b2_06_missing_web_locks_support() -> None:
    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            await context.add_init_script(
                "Object.defineProperty(Navigator.prototype, 'locks', { value: undefined, configurable: true });"
            )
            page = await context.new_page()
            mutating_auth_requests: list[str] = []

            def _on_request(req):
                if any(
                    ep in req.url
                    for ep in (
                        "/api/v1/auth/password/login",
                        "/api/v1/auth/otp/verify",
                        "/api/v1/auth/refresh",
                        "/api/v1/auth/logout",
                    )
                ):
                    mutating_auth_requests.append(req.url)

            page.on("request", _on_request)
            try:
                resp = await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="domcontentloaded")
                assert resp is not None and resp.status == 200, (
                    f"Expected 200 on /phase3/#/auth/shell, got {resp.status if resp else None}"
                )
                await page.wait_for_selector("#hc-weblocks-error", timeout=5000)
                await page.fill("#hc-login-mobile", "09120000001")
                await page.fill("#hc-login-password", "DummyPass!2026")
                await page.click("#hc-pwd-login-btn")
                await asyncio.sleep(0.3)

                assert len(mutating_auth_requests) == 0, (
                    f"Missing navigator.locks must fail closed locally with 0 auth network requests, saw {mutating_auth_requests}"
                )
            finally:
                await context.close()
                await browser.close()


# =============================================================================
# CE-B2-07: Stale Access Token After Logout (4.D)
# =============================================================================
async def test_ce_b2_07_stale_access_token_after_logout() -> None:
    async with _running_b2_server(extra_env={"ACCESS_TOKEN_TTL_SECONDS": "300"}) as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        importlib.import_module("src.auth.access_tokens")

        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        password = "HamiB2AccessRevoke!2026"
        await _create_test_user(pool, mobile, password=password)

        async with httpx.AsyncClient(base_url=base_url) as client:
            cookies, boot = await _bootstrap_cookie_session(client, base_url)
            login_resp = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": boot["auth_generation"]},
            )
            assert login_resp.status_code == 200
            cookies.update(_extract_cookies_dict(login_resp))
            access_token = login_resp.json()["access_token"]
            claims = jwt.decode(access_token, options={"verify_signature": False})
            assert claims["exp"] - time.time() > 240, "Access token TTL must be >=300s to prove immediate revocation."

            me_before = await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {access_token}"})
            assert me_before.status_code == 200

            logout_resp = await client.post(
                "/api/v1/auth/logout",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
            )
            assert logout_resp.status_code == 200

            me_after = await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {access_token}"})
            assert me_after.status_code == 401, (
                f"Stale access token must return 401 IMMEDIATELY after logout (not wait for exp), got {me_after.status_code}"
            )

            # Second session + simulated Redis outage must fail closed HTTP 503 on protected routes
            cookies2, boot2 = await _bootstrap_cookie_session(client, base_url)
            login2 = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies2["hc_csrf"]},
                cookies=cookies2,
                json={"mobile": mobile, "password": password, "expected_auth_generation": boot2["auth_generation"]},
            )
            assert login2.status_code == 200
            tok2 = login2.json()["access_token"]

            r_inst = deps.get_redis()
            orig_exists = r_inst.exists

            def _broken_exists(*args, **kwargs):
                raise redis.ConnectionError("Simulated Redis outage on access check")

            r_inst.exists = _broken_exists
            try:
                me_redis_down = await client.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok2}"})
                assert me_redis_down.status_code == 503, (
                    f"Protected endpoint must fail closed HTTP 503 when Redis is down, got {me_redis_down.status_code}"
                )
            finally:
                r_inst.exists = orig_exists


# =============================================================================
# CE-B2-08: Multi-Device Session Isolation (§2.3)
# =============================================================================
async def test_ce_b2_08_multi_device_session_isolation() -> None:
    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        mob_u1 = f"0912{secrets.randbelow(9000000) + 1000000}"
        mob_u2 = f"0912{secrets.randbelow(9000000) + 1000000}"
        pw = "HamiB2MultiDev!2026"
        await _create_test_user(pool, mob_u1, password=pw)
        await _create_test_user(pool, mob_u2, password=pw)

        async with (
            httpx.AsyncClient(base_url=base_url) as dev_a,
            httpx.AsyncClient(base_url=base_url) as dev_b,
            httpx.AsyncClient(base_url=base_url) as user_c,
        ):
            ca, ba = await _bootstrap_cookie_session(dev_a, base_url)
            cb, bb = await _bootstrap_cookie_session(dev_b, base_url)
            cc, bc = await _bootstrap_cookie_session(user_c, base_url)
            assert ca["hc_browser"].split(".", 1)[0] != cb["hc_browser"].split(".", 1)[0]

            la = await dev_a.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": ca["hc_csrf"]},
                cookies=ca,
                json={"mobile": mob_u1, "password": pw, "expected_auth_generation": ba["auth_generation"]},
            )
            lb = await dev_b.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cb["hc_csrf"]},
                cookies=cb,
                json={"mobile": mob_u1, "password": pw, "expected_auth_generation": bb["auth_generation"]},
            )
            lc = await user_c.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cc["hc_csrf"]},
                cookies=cc,
                json={"mobile": mob_u2, "password": pw, "expected_auth_generation": bc["auth_generation"]},
            )
            assert la.status_code == 200 and lb.status_code == 200 and lc.status_code == 200
            ca.update(_extract_cookies_dict(la))
            cb.update(_extract_cookies_dict(lb))
            cc.update(_extract_cookies_dict(lc))

            tok_b = lb.json()["access_token"]
            tok_c = lc.json()["access_token"]
            fam_b = uuid.UUID(lb.json()["session"]["family_id"])
            fam_c = uuid.UUID(lc.json()["session"]["family_id"])

            # Device A logs out -> Device B (same user) and User C MUST remain untouched
            lo_a = await dev_a.post(
                "/api/v1/auth/logout",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": ca["hc_csrf"]},
                cookies=ca,
            )
            assert lo_a.status_code == 200

            assert (await dev_b.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_b}"})).status_code == 200
            assert (await user_c.get("/api/v1/profile/me", headers={"Authorization": f"Bearer {tok_c}"})).status_code == 200

            ref_b = await dev_b.post(
                "/api/v1/auth/refresh",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cb["hc_csrf"]},
                cookies=cb,
                json={},
            )
            assert ref_b.status_code == 200

            async with pool.acquire() as conn:
                b_active = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND status = 'ACTIVE';", fam_b
                )
                c_active = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND status = 'ACTIVE';", fam_c
                )
            assert b_active == 1 and c_active == 1


# =============================================================================
# CE-B2-09: PostgreSQL & Redis Revocation Failure + Dual SKIP LOCKED (4.E)
# =============================================================================
async def test_ce_b2_09_postgres_and_redis_revocation_failure() -> None:
    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        outbox_mod = importlib.import_module("src.auth.revocation_outbox")
        reconcile_fn = outbox_mod.reconcile_pending_revocations

        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        password = "HamiB2Failures!2026"
        uid = await _create_test_user(pool, mobile, password=password)

        async with httpx.AsyncClient(base_url=base_url) as client:
            cookies, boot = await _bootstrap_cookie_session(client, base_url)
            login1 = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": boot["auth_generation"]},
            )
            assert login1.status_code == 200
            cookies.update(_extract_cookies_dict(login1))
            raw_bid = cookies["hc_browser"].split(".", 1)[0]
            f1 = uuid.UUID(login1.json()["session"]["family_id"])

            async with pool.acquire() as conn:
                g_before = await conn.fetchval(
                    "SELECT auth_generation FROM browser_sessions WHERE browser_id = $1;", raw_bid
                )

            # 1. Genuine mid-transaction PG crash AFTER at least 1 real DML statement executed inside tx
            orig_acquire = pool.acquire
            dml_executed_before_crash = 0
            crash_armed = True

            class _MidTxCrashConnProxy:
                def __init__(self, inner):
                    self._inner = inner

                def __getattr__(self, name):
                    return getattr(self._inner, name)

                async def execute(self, query: str, *args, **kwargs):
                    nonlocal dml_executed_before_crash, crash_armed
                    upper = query.strip().upper()
                    is_dml = upper.startswith(("INSERT", "UPDATE", "DELETE"))
                    res = await self._inner.execute(query, *args, **kwargs)
                    if crash_armed and is_dml:
                        dml_executed_before_crash += 1
                        if dml_executed_before_crash >= 1:
                            raise asyncpg.PostgresConnectionError("Simulated mid-tx PG crash after real SQL DML")
                    return res

            @asynccontextmanager
            async def _proxied_acquire(*args, **kwargs):
                async with orig_acquire(*args, **kwargs) as conn:
                    yield _MidTxCrashConnProxy(conn) if crash_armed else conn

            pool.acquire = _proxied_acquire
            try:
                lo_pg_fail = await client.post(
                    "/api/v1/auth/logout",
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                    cookies=cookies,
                )
            finally:
                crash_armed = False
                pool.acquire = orig_acquire

            assert dml_executed_before_crash >= 1, "PG fault proxy did not intercept a real SQL DML statement!"
            assert lo_pg_fail.status_code == 503, f"Mid-tx PG failure must return 503, got {lo_pg_fail.status_code}"

            async with pool.acquire() as conn:
                g_after_rollback = await conn.fetchval(
                    "SELECT auth_generation FROM browser_sessions WHERE browser_id = $1;", raw_bid
                )
                f1_status = await conn.fetchval(
                    "SELECT status FROM refresh_tokens WHERE family_id = $1;", f1
                )
            assert g_after_rollback == g_before, "Mid-tx rollback must preserve auth_generation."
            assert f1_status == "ACTIVE", "Mid-tx rollback must preserve refresh_tokens ACTIVE."

            # Retry logout once PG recovers -> 200
            lo_retry = await client.post(
                "/api/v1/auth/logout",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
            )
            assert lo_retry.status_code == 200
            cookies.update(_extract_cookies_dict(lo_retry))

            # 2. Redis outage AFTER PG commit -> durable PENDING_REVOKE + 503, then dual overlapping SKIP LOCKED workers
            cookies2, boot2 = await _bootstrap_cookie_session(client, base_url)
            cookies.update(cookies2)
            login2 = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": boot2["auth_generation"]},
            )
            assert login2.status_code == 200
            cookies.update(_extract_cookies_dict(login2))
            f2 = uuid.UUID(login2.json()["session"]["family_id"])

            r_inst = deps.get_redis()
            orig_setex = r_inst.setex

            def _broken_setex(*args, **kwargs):
                raise redis.ConnectionError("Simulated Redis outage post PG commit")

            r_inst.setex = _broken_setex
            try:
                lo_redis_fail = await client.post(
                    "/api/v1/auth/logout",
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                    cookies=cookies,
                )
            finally:
                r_inst.setex = orig_setex

            assert lo_redis_fail.status_code == 503
            async with pool.acquire() as conn:
                f2_rt = await conn.fetchval("SELECT status FROM refresh_tokens WHERE family_id = $1;", f2)
                f2_out = await conn.fetchval("SELECT status FROM revocation_outbox WHERE family_id = $1;", f2)
                assert f2_rt == "REVOKED"
                assert f2_out == "PENDING_REVOKE"

                synthetic_fams = [uuid.uuid4() for _ in range(30)]
                await conn.executemany(
                    """
                    INSERT INTO revocation_outbox (family_id, user_id, browser_id, reason, status)
                    VALUES ($1, $2, NULL, 'SYNTHETIC_OUTBOX_TEST', 'PENDING_REVOKE');
                    """,
                    [(sf, uid) for sf in synthetic_fams],
                )

            all_fams = [f2] + synthetic_fams
            w1_holding = threading.Event()
            w1_release = threading.Event()
            seen_families: list[str] = []
            wrap_lock = threading.Lock()

            def _overlap_setex(key: str, time_s: int, value: Any):
                with wrap_lock:
                    seen_families.append(key)
                    is_first = len(seen_families) == 1
                if is_first:
                    w1_holding.set()
                    w1_release.wait(timeout=5.0)
                return orig_setex(key, time_s, value)

            r_inst.setex = _overlap_setex
            try:
                worker1 = asyncio.create_task(reconcile_fn(pool, r_inst, batch_size=15, max_batches=20))
                assert await asyncio.to_thread(w1_holding.wait, 5.0), "Worker 1 failed to enter setex barrier"
                worker2 = asyncio.create_task(reconcile_fn(pool, r_inst, batch_size=15, max_batches=20))
                res2 = await asyncio.wait_for(worker2, timeout=5.0)
                w1_release.set()
                res1 = await asyncio.wait_for(worker1, timeout=5.0)
            finally:
                w1_release.set()
                r_inst.setex = orig_setex

            assert res1 >= 1 and res2 >= 1, (
                f"Expected both overlapping SKIP LOCKED workers to process disjoint batches: res1={res1}, res2={res2}"
            )
            async with pool.acquire() as conn:
                pending_left = await conn.fetchval(
                    "SELECT COUNT(*) FROM revocation_outbox WHERE family_id = ANY($1::uuid[]) AND status != 'REVOKED';",
                    all_fams,
                )
            assert pending_left == 0, f"Expected all outbox items REVOKED, left={pending_left}"
            for fid in all_fams:
                ttl = r_inst.ttl(f"hc:revoked_family:{fid}")
                assert ttl > 7 * 86400, f"Revocation key hc:revoked_family:{fid} TTL must be > 7 days, got {ttl}"


# =============================================================================
# CE-B2-10: CSRF, Origin, Replay & Lua ZSET Rate Limiting (§4.5)
# =============================================================================
async def test_ce_b2_10_csrf_origin_replay_and_rate_limit() -> None:
    async with _running_b2_server() as (base_url, _):
        pool = await deps.get_db_pool()
        await _require_b2_schema(pool)
        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        password = "HamiB2Security!2026"
        await _create_test_user(pool, mobile, password=password)

        async with httpx.AsyncClient(base_url=base_url) as client:
            cookies, boot = await _bootstrap_cookie_session(client, base_url)
            gen = boot["auth_generation"]

            # 1. Evil / missing Origin rejected 403
            evil_orig = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": "https://evil.example", "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": gen},
            )
            assert evil_orig.status_code == 403
            no_orig = await client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": gen},
            )
            assert no_orig.status_code == 403

            # Login cleanly then test CSRF checks on /refresh & /logout
            login_ok = await client.post(
                "/api/v1/auth/password/login",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={"mobile": mobile, "password": password, "expected_auth_generation": gen},
            )
            assert login_ok.status_code == 200
            cookies.update(_extract_cookies_dict(login_ok))
            r1 = cookies["hc_refresh"]
            fid = uuid.UUID(login_ok.json()["session"]["family_id"])

            bad_csrf_ref = await client.post(
                "/api/v1/auth/refresh",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": "forged_csrf_value"},
                cookies=cookies,
                json={},
            )
            assert bad_csrf_ref.status_code == 403
            bad_csrf_lo = await client.post(
                "/api/v1/auth/logout",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": "forged_csrf_value"},
                cookies=cookies,
            )
            assert bad_csrf_lo.status_code == 403

            # 2. Refresh Replay outside 5s grace revokes ENTIRE family + audit_logs
            rot = await client.post(
                "/api/v1/auth/refresh",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=cookies,
                json={},
            )
            assert rot.status_code == 200
            cookies.update(_extract_cookies_dict(rot))
            r2 = cookies["hc_refresh"]
            assert r2 != r1

            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE refresh_tokens SET rotated_at = NOW() - INTERVAL '15 seconds' WHERE family_id = $1 AND status = 'ROTATED';",
                    fid,
                )

            stale_cookies = dict(cookies)
            stale_cookies["hc_refresh"] = r1
            replay_resp = await client.post(
                "/api/v1/auth/refresh",
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                cookies=stale_cookies,
                json={},
            )
            assert replay_resp.status_code == 401
            async with pool.acquire() as conn:
                still_active = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND status != 'REVOKED';", fid
                )
                audit_cnt = await conn.fetchval(
                    "SELECT COUNT(*) FROM audit_logs WHERE action = 'TOKEN_REPLAY_ATTACK_DETECTED' AND entity_id = $1;",
                    str(fid),
                )
            assert still_active == 0
            assert audit_cnt >= 1

            # 3. Lua ZSET sliding-window rate limit + full Connection DML spy on 503
            r_inst = deps.get_redis()
            eval_scripts: list[str] = []
            orig_eval = r_inst.eval

            def _capture_eval(script, numkeys, *keys_and_args):
                eval_scripts.append(str(script))
                return orig_eval(script, numkeys, *keys_and_args)

            r_inst.eval = _capture_eval
            try:
                statuses = []
                for _ in range(25):
                    resp_rl = await client.post(
                        "/api/v1/auth/password/login",
                        headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                        cookies=cookies,
                        json={"mobile": mobile, "password": "WrongPassword!999", "expected_auth_generation": gen},
                    )
                    statuses.append(resp_rl.status_code)
                    if resp_rl.status_code == 429:
                        break
                assert 429 in statuses, f"Expected 429 from Lua ZSET rate limiter, saw {statuses}"
                assert any("TIME" in s and "ZADD" in s for s in eval_scripts), (
                    "Expected atomic Lua ZSET script using Redis TIME + ZADD."
                )
                # Ensure 429 did not pollute ZSET buckets beyond limit
                rl_keys = r_inst.keys("*rl*") or r_inst.keys("*rate*")
                for k in rl_keys:
                    if r_inst.type(k) == "zset":
                        assert r_inst.zcard(k) < len(statuses)
            finally:
                r_inst.eval = orig_eval

            # Break Redis -> must fail 503 with ZERO PG DML across ALL Connection methods
            orig_acquire = pool.acquire
            pg_dml_calls: list[str] = []

            def _check_dml(method: str, query: str):
                q_up = str(query).strip().upper()
                if any(tok in q_up for tok in ("INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "CREATE", "ALTER", "DROP")):
                    pg_dml_calls.append(f"{method}:{q_up[:80]}")

            class _AllMethodDmlSpyConn:
                def __init__(self, inner):
                    self._inner = inner

                def __getattr__(self, name):
                    return getattr(self._inner, name)

                async def execute(self, query, *args, **kwargs):
                    _check_dml("execute", query)
                    return await self._inner.execute(query, *args, **kwargs)

                async def executemany(self, command, *args, **kwargs):
                    _check_dml("executemany", command)
                    return await self._inner.executemany(command, *args, **kwargs)

                async def fetch(self, query, *args, **kwargs):
                    _check_dml("fetch", query)
                    return await self._inner.fetch(query, *args, **kwargs)

                async def fetchrow(self, query, *args, **kwargs):
                    _check_dml("fetchrow", query)
                    return await self._inner.fetchrow(query, *args, **kwargs)

                async def fetchval(self, query, *args, **kwargs):
                    _check_dml("fetchval", query)
                    return await self._inner.fetchval(query, *args, **kwargs)

                async def copy_from_query(self, query, *args, **kwargs):
                    _check_dml("copy_from_query", query)
                    return await self._inner.copy_from_query(query, *args, **kwargs)

                async def copy_records_to_table(self, table_name, *args, **kwargs):
                    pg_dml_calls.append(f"copy_records_to_table:{table_name}")
                    return await self._inner.copy_records_to_table(table_name, *args, **kwargs)

            @asynccontextmanager
            async def _spy_acquire(*args, **kwargs):
                async with orig_acquire(*args, **kwargs) as conn:
                    yield _AllMethodDmlSpyConn(conn)

            def _broken_eval(*args, **kwargs):
                raise redis.ConnectionError("Simulated Redis down during rate-limit check")

            pool.acquire = _spy_acquire
            r_inst.eval = _broken_eval
            try:
                rl_down = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": cookies["hc_csrf"]},
                    cookies=cookies,
                    json={"mobile": mobile, "password": password, "expected_auth_generation": gen},
                )
                assert rl_down.status_code == 503, f"Rate limiter Redis failure must return 503, got {rl_down.status_code}"
                assert len(pg_dml_calls) == 0, f"Expected ZERO PG writes during 503 rate-limit failure, got {pg_dml_calls}"
            finally:
                r_inst.eval = orig_eval
                pool.acquire = orig_acquire


# =============================================================================
# CE-B2-11: Adversarial Garbage Collection (§4.6)
# =============================================================================
async def test_ce_b2_11_adversarial_garbage_collection() -> None:
    pool = await asyncpg.create_pool(os.getenv("DATABASE_URL", DEFAULT_PG_URL), min_size=1, max_size=5)
    try:
        await _require_b2_schema(pool)
        outbox_mod = importlib.import_module("src.auth.revocation_outbox")
        purge_fn = outbox_mod.purge_expired_auth_records

        mobile = f"0912{secrets.randbelow(9000000) + 1000000}"
        uid = await _create_test_user(pool, mobile)
        now = datetime.now(UTC)

        bid_expired_lo = f"b_{secrets.token_hex(16)}"
        bid_unexpired_lo = f"b_{secrets.token_hex(16)}"
        bid_active = f"b_{secrets.token_hex(16)}"

        fam_active = uuid.uuid4()
        fam_rev_old = uuid.uuid4()
        fam_rev_recent = uuid.uuid4()
        fam_pending_old = uuid.uuid4()

        r_cli = redis.Redis.from_url(os.getenv("REDIS_URL", DEFAULT_REDIS_URL), decode_responses=True)
        r_cli.delete(f"hc:revoked_family:{fam_pending_old}")  # Ensure Redis key absent adversarially
        r_cli.close()

        async with pool.acquire() as conn:
            async with conn.transaction():
                # 1. Expired LOGGED_OUT browser_sessions -> PURGE
                await conn.execute(
                    """
                    INSERT INTO browser_sessions (browser_id, active_status, active_family_id, expires_at)
                    VALUES ($1, 'LOGGED_OUT', NULL, $2);
                    """,
                    bid_expired_lo,
                    now - timedelta(days=2),
                )
                # 2. Unexpired LOGGED_OUT browser_sessions -> SURVIVE
                await conn.execute(
                    """
                    INSERT INTO browser_sessions (browser_id, active_status, active_family_id, expires_at)
                    VALUES ($1, 'LOGGED_OUT', NULL, $2);
                    """,
                    bid_unexpired_lo,
                    now + timedelta(days=5),
                )
                # 3. ACTIVE browser_sessions + child ACTIVE refresh_tokens (even with old expires_at) -> BOTH SURVIVE
                await conn.execute(
                    """
                    INSERT INTO browser_sessions (browser_id, active_status, active_family_id, active_user_id, expires_at)
                    VALUES ($1, 'ACTIVE', $2, $3, $4);
                    """,
                    bid_active,
                    fam_active,
                    uid,
                    now - timedelta(days=1),
                )
                await conn.execute(
                    """
                    INSERT INTO refresh_tokens (user_id, family_id, token_hash, status, expires_at, created_at)
                    VALUES ($1, $2, $3, 'ACTIVE', $4, $5);
                    """,
                    uid,
                    fam_active,
                    secrets.token_hex(32),
                    now + timedelta(days=5),
                    now - timedelta(days=20),
                )
                # 4. Old confirmed REVOKED outbox + >10d revoked child token -> BOTH PURGE
                await conn.execute(
                    """
                    INSERT INTO revocation_outbox (family_id, user_id, reason, status, created_at, retain_until)
                    VALUES ($1, $2, 'OLD_CONFIRMED', 'REVOKED', $3, $4);
                    """,
                    fam_rev_old,
                    uid,
                    now - timedelta(days=20),
                    now - timedelta(days=1),
                )
                await conn.execute(
                    """
                    INSERT INTO refresh_tokens (user_id, family_id, token_hash, status, expires_at, created_at)
                    VALUES ($1, $2, $3, 'REVOKED', $4, $5);
                    """,
                    uid,
                    fam_rev_old,
                    secrets.token_hex(32),
                    now - timedelta(days=15),
                    now - timedelta(days=20),
                )
                # 5. Recent confirmed REVOKED outbox (<10d retain_until) -> SURVIVE
                await conn.execute(
                    """
                    INSERT INTO revocation_outbox (family_id, user_id, reason, status, created_at, retain_until)
                    VALUES ($1, $2, 'RECENT_CONFIRMED', 'REVOKED', $3, $4);
                    """,
                    fam_rev_recent,
                    uid,
                    now - timedelta(days=2),
                    now + timedelta(days=5),
                )
                # 6. Old PENDING_REVOKE outbox + >10d child refresh_tokens -> BOTH PARENT & CHILD SURVIVE!
                await conn.execute(
                    """
                    INSERT INTO revocation_outbox (family_id, user_id, reason, status, created_at, retain_until)
                    VALUES ($1, $2, 'STUCK_OUTBOX', 'PENDING_REVOKE', $3, $4);
                    """,
                    fam_pending_old,
                    uid,
                    now - timedelta(days=20),
                    now - timedelta(days=5),
                )
                await conn.execute(
                    """
                    INSERT INTO refresh_tokens (user_id, family_id, token_hash, status, expires_at, created_at)
                    VALUES ($1, $2, $3, 'REVOKED', $4, $5);
                    """,
                    uid,
                    fam_pending_old,
                    secrets.token_hex(32),
                    now - timedelta(days=15),
                    now - timedelta(days=20),
                )

        summary = await purge_fn(pool, batch_size=100)
        assert isinstance(summary, dict)

        async with pool.acquire() as conn:
            assert await conn.fetchval("SELECT COUNT(*) FROM browser_sessions WHERE browser_id = $1;", bid_expired_lo) == 0
            assert await conn.fetchval("SELECT COUNT(*) FROM browser_sessions WHERE browser_id = $1;", bid_unexpired_lo) == 1
            assert await conn.fetchval("SELECT COUNT(*) FROM browser_sessions WHERE browser_id = $1;", bid_active) == 1
            assert await conn.fetchval("SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1;", fam_active) == 1

            assert await conn.fetchval("SELECT COUNT(*) FROM revocation_outbox WHERE family_id = $1;", fam_rev_old) == 0
            assert await conn.fetchval("SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1;", fam_rev_old) == 0

            assert await conn.fetchval("SELECT COUNT(*) FROM revocation_outbox WHERE family_id = $1;", fam_rev_recent) == 1
            assert await conn.fetchval("SELECT COUNT(*) FROM revocation_outbox WHERE family_id = $1;", fam_pending_old) == 1
            assert (
                await conn.fetchval("SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1;", fam_pending_old) == 1
            ), "GC must preserve child refresh_tokens while parent revocation_outbox row is still PENDING_REVOKE!"
    finally:
        await pool.close()
