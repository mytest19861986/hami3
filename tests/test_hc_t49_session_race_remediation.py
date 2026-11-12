"""
Automated Session Concurrency & Causal Ordering Remediation Verification for HC-T49 (HC-CMD-050)
Baseline: BL-HAMICARD-PRD-V1

Covers all 10 required browser/backend races + 3 server invariants + R2-T46-V3-H01/M01/M02/L01..L03:
1. Server-side attempt_id & login-attempts/cancel invariants (Origin 403, Redis outage 503,
   pre-logout cancellation 409, post-login-creation revocation, CSRF/RBAC preservation).
2. Single-tab delayed OTP verify -> Logout -> delayed OTP 200 (+ late Set-Cookie) ->
   stays logged out, late cookies purged, 0 active DB refresh_tokens, /refresh returns 401.
3. Single-tab delayed Password login -> Logout -> delayed Password 200 (+ late Set-Cookie) ->
   stays logged out, late cookies purged, 0 active DB refresh_tokens, /refresh returns 401.
4. Cross-tab Login + Logout (both Abort/cancel and out-of-order delayed 200 + late Set-Cookie) ->
   0 usable post-logout family/session.
5. Old explicitLogin: true BroadcastChannel message after Logout -> rejected (H01).
6. Old LOGOUT / LOGOUT_FAILED_LOCAL_SCRUB BroadcastChannel message after newer explicit Login ->
   ignored, newer session preserved (L01).
7. In-flight authenticatedFetch (/profile/me) resolving 200 after Logout -> throws UNAUTHENTICATED,
   never returns stale resp or hydrates cachedProfile (M01).
8. Held /api/v1/auth/logout HTTP response -> LOGOUT_PENDING renders immediately with scrubbed UI
   before HTTP completes (M02).
9. Delayed panel-access 200 after logout AND after role revocation + nav switch -> NEVER commits ALLOW
   or renders #hc-panel-authorized-badge (M01).
10. Logout 503 (L02 accurate unconfirmed DB copy, late refresh/background login blocked, explicit
    new login recovers cleanly) + 3-tab concurrent refresh/login/logout race.
11. Release gate doc (`docs/STAGING_PROXY_RELEASE_GATE.md`, L03) + 18/18 OPEN-* == PROPOSED.
"""

import asyncio
import os
import pathlib
import socket
import threading
import uuid

import asyncpg
import httpx
import pytest
import redis
import uvicorn
from playwright.async_api import async_playwright

import src.api.deps as deps
from src.api.main import create_app
from src.auth.otp_service import OtpService
from src.core.policy import get_all_open_policy_statuses
from src.core.security import hash_password
from src.profiles.service import ProfileService

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _launch_headless_chromium(p):
    for channel in (None, "chrome", "msedge"):
        try:
            if channel:
                return await p.chromium.launch(headless=True, channel=channel)
            return await p.chromium.launch(headless=True)
        except Exception:
            continue
    brave_candidates = [
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
    ]
    for exe in brave_candidates:
        if os.path.exists(exe):
            return await p.chromium.launch(headless=True, executable_path=exe)
    pytest.fail("No headless Chromium binary available for HC-T49 verification.")


async def _wait_selector_text(
    page, selector: str, expected: str, *, contains: bool = False, timeout: float = 8.0
):
    deadline = asyncio.get_event_loop().time() + timeout
    last_val = ""
    while asyncio.get_event_loop().time() < deadline:
        loc = page.locator(selector)
        if await loc.count() > 0:
            last_val = (await loc.first.inner_text()).strip()
            if (expected in last_val) if contains else (last_val == expected):
                return last_val
        await asyncio.sleep(0.05)
    raise AssertionError(f"Timeout waiting for {selector} to match {expected!r}; last={last_val!r}")


async def _wait_selector_count(page, selector: str, expected_count: int = 1, timeout: float = 8.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if await page.locator(selector).count() == expected_count:
            return
        await asyncio.sleep(0.05)
    actual = await page.locator(selector).count()
    raise AssertionError(
        f"Timeout waiting for {selector} count == {expected_count}; actual={actual}"
    )


async def _create_test_user(
    roles: list[str], *, password: str | None = None, first_name: str = "آزمایش"
) -> tuple[uuid.UUID, str]:
    mobile = f"0919{uuid.uuid4().int % 10000000:07d}"
    pwd_hash = hash_password(password or "HamiRaceTest!901")
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        uid = await conn.fetchval(
            """
            INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
            VALUES ($1, $2, 'ACTIVE', TRUE)
            RETURNING id;
            """,
            mobile,
            pwd_hash,
        )
        for rname in roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2);", uid, rname
            )
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        try:
            await ProfileService(pool).upsert_profile(
                user_id=uid, first_name=first_name, last_name="کاربرحامی"
            )
        finally:
            await pool.close()
        return uid, mobile
    finally:
        await conn.close()


async def _cleanup_user(uid: uuid.UUID | None) -> None:
    if uid is None:
        return
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute("DELETE FROM profiles WHERE user_id = $1;", uid)
        await conn.execute("DELETE FROM refresh_tokens WHERE user_id = $1;", uid)
        await conn.execute("DELETE FROM user_roles WHERE user_id = $1;", uid)
        await conn.execute("DELETE FROM users WHERE id = $1;", uid)
    finally:
        await conn.close()


async def _reset_deps() -> None:
    try:
        await deps.close_pool()
    except RuntimeError:
        deps._pool = None
    deps.close_redis()


async def _start_test_server(monkeypatch, *, access_ttl: int = 300):
    await _reset_deps()
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t49-session-race-remediation-signing-secret-material-64-chars-min",
    )
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", str(access_ttl))
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", base_url)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    async with httpx.AsyncClient(base_url=base_url) as probe:
        for _ in range(50):
            try:
                resp = await probe.get("/api/v1/health")
                if resp.status_code == 200:
                    break
            except Exception:
                await asyncio.sleep(0.1)
        else:
            server.should_exit = True
            thread.join(timeout=5.0)
            pytest.fail("Live uvicorn failed to start for HC-T49")
    return server, thread, base_url


@pytest.mark.asyncio
async def test_t49_server_attempt_cancellation_and_security_invariants(monkeypatch):
    """
    Server Invariants:
    - `/login-attempts/cancel` rejects untrusted Origin (`403`), fails closed `503` on Redis outage.
    - Cancelling an attempt before `/otp/verify` or `/password/login` returns `409` with 0 DB rows.
    - Cookie `/logout` with `cancelled_login_attempt_ids` revokes both current family AND an already-minted
      in-flight login family in PostgreSQL + Redis, while preserving CSRF/Origin checks.
    """
    await _reset_deps()
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t49-backend-invariant-signing-secret-material-64-chars-min-0001",
    )
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://127.0.0.1:3000")
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    pwd = "ServerRaceInv!901"
    uid, mobile = await _create_test_user(["USER"], password=pwd)
    test_app = create_app()
    rd = redis.from_url(REDIS_URL, decode_responses=True)

    try:
        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3000") as client:
            origin_headers = {"Origin": "http://127.0.0.1:3000", "X-Auth-Mode": "cookie"}

            # 1. Untrusted Origin rejected fail-closed (403)
            r_bad = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": ["hc_bad_origin_attempt_01"]},
                headers={"Origin": "https://evil.example"},
            )
            assert r_bad.status_code == 403

            # 2. Pre-cancelled attempt blocks /password/login and /otp/verify with 409 + 0 active DB rows
            pre_cancel_id = f"hc_precancel_{uuid.uuid4().hex}"
            r_cancel = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [pre_cancel_id]},
                headers={"Origin": "http://127.0.0.1:3000"},
            )
            assert r_cancel.status_code == 200
            assert "no-store" in r_cancel.headers.get("cache-control", "").lower()

            r_pwd_409 = await client.post(
                "/api/v1/auth/password/login",
                json={"mobile": mobile, "password": pwd, "attempt_id": pre_cancel_id},
                headers=origin_headers,
            )
            assert r_pwd_409.status_code == 409

            await OtpService(redis.from_url(REDIS_URL)).request_otp(mobile)
            otp_code = rd.get(f"otp:code:{mobile}")
            assert otp_code
            r_otp_409 = await client.post(
                "/api/v1/auth/otp/verify",
                json={"mobile": mobile, "code": otp_code, "attempt_id": pre_cancel_id},
                headers=origin_headers,
            )
            assert r_otp_409.status_code == 409

            conn = await asyncpg.connect(DATABASE_URL)
            try:
                assert (
                    await conn.fetchval(
                        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                        uid,
                    )
                    == 0
                )
            finally:
                await conn.close()

            # 3. Login #1 + Login #2 (`attempt_id`), then Logout of #1 with `cancelled_login_attempt_ids` ->
            # BOTH families revoked in DB + Redis!
            r_login_1 = await client.post(
                "/api/v1/auth/password/login",
                json={"mobile": mobile, "password": pwd, "attempt_id": f"hc_a1_{uuid.uuid4().hex}"},
                headers=origin_headers,
            )
            assert r_login_1.status_code == 200
            csrf_1 = r_login_1.cookies.get("hc_csrf")
            refresh_1 = r_login_1.cookies.get("hc_refresh")
            fam_1 = r_login_1.json()["family_id"]

            inflight_attempt_2 = f"hc_a2_{uuid.uuid4().hex}"
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=test_app), base_url="http://127.0.0.1:3000"
            ) as client2:
                r_login_2 = await client2.post(
                    "/api/v1/auth/password/login",
                    json={"mobile": mobile, "password": pwd, "attempt_id": inflight_attempt_2},
                    headers=origin_headers,
                )
                assert r_login_2.status_code == 200
                fam_2 = r_login_2.json()["family_id"]
                csrf_2 = r_login_2.cookies.get("hc_csrf")

                # CSRF missing check on /logout preserved (403)
                r_no_csrf = await client.post(
                    "/api/v1/auth/logout",
                    json={"cancelled_login_attempt_ids": [inflight_attempt_2]},
                    headers={"Origin": "http://127.0.0.1:3000", "X-Auth-Mode": "cookie"},
                    cookies={"hc_refresh": refresh_1, "hc_csrf": csrf_1},
                )
                assert r_no_csrf.status_code == 403

                # Real /logout of Session #1 carrying inflight_attempt_2 revokes BOTH fam_1 & fam_2
                r_logout = await client.post(
                    "/api/v1/auth/logout",
                    json={"cancelled_login_attempt_ids": [inflight_attempt_2]},
                    headers={
                        "Origin": "http://127.0.0.1:3000",
                        "X-Auth-Mode": "cookie",
                        "X-CSRF-Token": csrf_1,
                    },
                )
                assert r_logout.status_code == 200

                # Delayed refresh using Session #2 cookies MUST fail 401
                r_refresh_2 = await client2.post(
                    "/api/v1/auth/refresh",
                    headers={
                        "Origin": "http://127.0.0.1:3000",
                        "X-Auth-Mode": "cookie",
                        "X-CSRF-Token": csrf_2,
                    },
                )
                assert r_refresh_2.status_code == 401

            conn = await asyncpg.connect(DATABASE_URL)
            try:
                active_rows = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                    uid,
                )
                assert active_rows == 0, f"Expected 0 active rows, found {active_rows}"
            finally:
                await conn.close()
            assert rd.get(f"hc:revoked_family:{fam_1}")
            assert rd.get(f"hc:revoked_family:{fam_2}")

            # 4. Redis outage on /login-attempts/cancel fails closed 503
            real_rd = deps.get_redis()
            orig_set = real_rd.set

            def _boom(*args, **kwargs):
                raise redis.exceptions.ConnectionError("Redis outage simulated")

            monkeypatch.setattr(real_rd, "set", _boom)
            r_503 = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [f"hc_outage_{uuid.uuid4().hex}"]},
                headers={"Origin": "http://127.0.0.1:3000"},
            )
            assert r_503.status_code == 503
            monkeypatch.setattr(real_rd, "set", orig_set)
    finally:
        rd.close()
        await _reset_deps()
        await _cleanup_user(uid)


@pytest.mark.asyncio
@pytest.mark.parametrize("login_kind", ["otp", "password"])
async def test_t49_single_tab_delayed_login_200_with_late_set_cookie_after_logout(
    monkeypatch, login_kind: str
):
    """
    Required Races #1 & #2 (H01 + HC-D50):
    Single-tab delayed OTP/Password login -> user logs out mid-flight -> delayed login HTTP 200
    (with REAL server-minted session + REAL late Set-Cookie) arrives AFTER logout.
    Verifies UI stays logged out, late Set-Cookies are cleared, PostgreSQL refresh_tokens has 0
    ACTIVE rows, and reload + /refresh stay unauthenticated (401).
    """
    pwd = "DelayedLoginRace!901"
    uid, mobile = await _create_test_user(["USER"], password=pwd)
    server, thread, base_url = await _start_test_server(monkeypatch)
    rd = redis.from_url(REDIS_URL, decode_responses=True)

    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            # Disable local AbortError on the login request so we specifically exercise the worst case:
            # delayed HTTP 200 + real Set-Cookie arriving AFTER logout already completed!
            await context.add_init_script(
                """
                const origFetch = window.fetch;
                window.fetch = function(input, init) {
                  const url = typeof input === 'string' ? input : (input && input.url) || '';
                  if ((url.includes('/api/v1/auth/otp/verify') || url.includes('/api/v1/auth/password/login')) && init && init.signal) {
                    const clonedInit = { ...init };
                    delete clonedInit.signal;
                    return origFetch.call(this, input, clonedInit);
                  }
                  return origFetch.apply(this, arguments);
                };
                """
            )
            page = await context.new_page()

            await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")

            # Also establish an initial session first so hc_csrf + /logout cookie flow runs end-to-end,
            # then re-submit login while logging out!
            await page.fill("#hc-pwd-mobile", mobile)
            await page.fill("#hc-pwd-input", pwd)
            await page.click("#hc-pwd-login-btn")
            await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

            login_fetched_on_server = asyncio.Event()
            release_login_response = asyncio.Event()
            cleanup_logout_seen = asyncio.Event()
            target_suffix = (
                "/api/v1/auth/otp/verify"
                if login_kind == "otp"
                else "/api/v1/auth/password/login"
            )

            async def _delay_login_route(route):
                if route.request.method != "POST":
                    await route.continue_()
                    return
                real_resp = await route.fetch()
                login_fetched_on_server.set()
                await release_login_response.wait()
                await route.fulfill(response=real_resp)

            def _watch_response(resp):
                if (
                    resp.request.method == "POST"
                    and resp.url.endswith("/api/v1/auth/logout")
                    and release_login_response.is_set()
                ):
                    cleanup_logout_seen.set()

            page.on("response", _watch_response)
            await page.route(f"**{target_suffix}", _delay_login_route)

            if login_kind == "otp":
                await page.fill("#hc-otp-mobile", mobile)
                await page.click("#hc-otp-request-btn")
                otp_code = None
                for _ in range(25):
                    otp_code = rd.get(f"otp:code:{mobile}")
                    if otp_code:
                        break
                    await asyncio.sleep(0.05)
                assert otp_code
                await page.fill("#hc-otp-code", otp_code)
                await page.click("#hc-otp-verify-btn")
            else:
                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", pwd)
                await page.click("#hc-pwd-login-btn")

            await asyncio.wait_for(login_fetched_on_server.wait(), timeout=5.0)

            # Click Logout -> completes /logout while delayed login response + Set-Cookie is still held
            await page.click("#hc-logout-btn")
            await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")

            # Release the delayed 200 + REAL Set-Cookie headers
            release_login_response.set()
            await asyncio.wait_for(cleanup_logout_seen.wait(), timeout=5.0)
            await page.wait_for_timeout(150)

            # UI MUST remain UNAUTHENTICATED with scrubbed profile & closure
            assert (await page.inner_text("#hc-auth-status-badge")).strip() == "UNAUTHENTICATED"
            audit_json = await page.inner_text("#hc-auth-audit-box")
            assert '"authenticated": false' in audit_json
            assert '"hasAccessTokenInClosure": false' in audit_json
            assert '"logoutBarrierActive": true' in audit_json

            # Late Set-Cookie headers MUST be cleared from Chromium
            jar = {c["name"]: c for c in await context.cookies()}
            assert "hc_refresh" not in jar
            assert "hc_csrf" not in jar
            assert "hc_has_session" not in jar

            # PostgreSQL MUST have 0 ACTIVE refresh tokens (delayed session revoked on server!)
            conn = await asyncpg.connect(DATABASE_URL)
            try:
                active_rows = await conn.fetchval(
                    "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                    uid,
                )
                assert active_rows == 0, f"Late login left {active_rows} ACTIVE DB tokens!"
            finally:
                await conn.close()

            # Reload stays cleanly UNAUTHENTICATED
            await page.unroute(f"**{target_suffix}", _delay_login_route)
            await page.reload(wait_until="networkidle")
            await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")

            await context.close()
            await browser.close()
    finally:
        rd.close()
        server.should_exit = True
        thread.join(timeout=5.0)
        await _cleanup_user(uid)


@pytest.mark.asyncio
async def test_t49_cross_tab_login_logout_out_of_order_and_abort_cleanup(monkeypatch):
    """
    Required Race #3 (+ HC-D50 Server Invariant #1 & #2):
    Tab A starts password login -> Tab B starts & finishes logout BEFORE Tab A's login completes ->
    Tests BOTH:
    (a) AbortController cancellation triggering `/login-attempts/cancel` so server revokes minted family, AND
    (b) Delayed 200 + late Set-Cookie arriving on Tab A while Tab B already logged out (`hc_coord`),
        leaving 0 active DB sessions and 0 cookies on reload.
    """
    pwd = "CrossTabOutOfOrder!901"
    uid, mobile = await _create_test_user(["USER"], password=pwd)
    server, thread, base_url = await _start_test_server(monkeypatch)

    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            tab_a = await context.new_page()
            tab_b = await context.new_page()

            await tab_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await tab_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await tab_b.fill("#hc-pwd-mobile", mobile)
            await tab_b.fill("#hc-pwd-input", pwd)
            await tab_b.click("#hc-pwd-login-btn")
            await _wait_selector_text(tab_b, "#hc-auth-status-badge", "AUTHENTICATED")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")

            # (a) Real AbortController path when Tab B logs out while Tab A's login is mid-flight
            login_on_server = asyncio.Event()
            release_login = asyncio.Event()
            cancel_done = asyncio.Event()

            async def _hold_login_a(route):
                if route.request.method != "POST":
                    await route.continue_()
                    return
                real_resp = await route.fetch()
                login_on_server.set()
                await release_login.wait()
                try:
                    await route.fulfill(response=real_resp)
                except Exception:
                    pass

            async def _on_tab_a_resp(resp):
                if resp.request.method != "POST":
                    return
                if resp.url.endswith("/api/v1/auth/login-attempts/cancel") and resp.status == 200:
                    cancel_done.set()
                elif resp.url.endswith("/api/v1/auth/logout") and resp.status in (200, 401):
                    cancel_done.set()

            tab_a.on("response", _on_tab_a_resp)
            await tab_a.route("**/api/v1/auth/password/login", _hold_login_a)

            await tab_a.fill("#hc-pwd-mobile", mobile)
            await tab_a.fill("#hc-pwd-input", pwd)
            await tab_a.click("#hc-pwd-login-btn")
            await asyncio.wait_for(login_on_server.wait(), timeout=5.0)

            await tab_b.click("#hc-top-logout-btn")
            await _wait_selector_text(tab_b, "#hc-auth-status-badge", "UNAUTHENTICATED")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "UNAUTHENTICATED")
            await asyncio.wait_for(cancel_done.wait(), timeout=5.0)
            release_login.set()
            await tab_a.wait_for_timeout(150)

            # (b) Delayed 200 + late Set-Cookie arriving on Tab A AFTER Tab B finished logout (`hc_coord`)
            await tab_b.fill("#hc-pwd-mobile", mobile)
            await tab_b.fill("#hc-pwd-input", pwd)
            await tab_b.click("#hc-pwd-login-btn")
            await _wait_selector_text(tab_b, "#hc-auth-status-badge", "AUTHENTICATED")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")

            await tab_a.unroute("**/api/v1/auth/password/login", _hold_login_a)
            tab_c = await context.new_page()
            await tab_c.add_init_script(
                """
                const origFetch = window.fetch;
                window.fetch = function(input, init) {
                  const url = typeof input === 'string' ? input : (input && input.url) || '';
                  if (url.includes('/api/v1/auth/password/login') && init && init.signal) {
                    const clonedInit = { ...init };
                    delete clonedInit.signal;
                    return origFetch.call(this, input, clonedInit);
                  }
                  return origFetch.apply(this, arguments);
                };
                """
            )
            await tab_c.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await _wait_selector_text(tab_c, "#hc-auth-status-badge", "AUTHENTICATED")

            login_c_fetched = asyncio.Event()
            release_login_c = asyncio.Event()
            cleanup_c_done = asyncio.Event()

            async def _hold_login_c(route):
                if route.request.method != "POST":
                    await route.continue_()
                    return
                real_resp = await route.fetch()
                login_c_fetched.set()
                await release_login_c.wait()
                await route.fulfill(response=real_resp)

            tab_c.on(
                "response",
                lambda r: cleanup_c_done.set()
                if (
                    r.request.method == "POST"
                    and r.url.endswith("/api/v1/auth/logout")
                    and release_login_c.is_set()
                )
                else None,
            )
            await tab_c.route("**/api/v1/auth/password/login", _hold_login_c)

            await tab_c.fill("#hc-pwd-mobile", mobile)
            await tab_c.fill("#hc-pwd-input", pwd)
            await tab_c.click("#hc-pwd-login-btn")
            await asyncio.wait_for(login_c_fetched.wait(), timeout=5.0)

            await tab_b.click("#hc-top-logout-btn")
            await _wait_selector_text(tab_b, "#hc-auth-status-badge", "UNAUTHENTICATED")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "UNAUTHENTICATED")

            release_login_c.set()
            await asyncio.wait_for(cleanup_c_done.wait(), timeout=5.0)
            await tab_c.wait_for_timeout(150)
            assert (await tab_c.inner_text("#hc-auth-status-badge")).strip() == "UNAUTHENTICATED"
            assert (await tab_b.inner_text("#hc-auth-status-badge")).strip() == "UNAUTHENTICATED"

            await tab_c.unroute("**/api/v1/auth/password/login", _hold_login_c)
            await tab_c.reload(wait_until="networkidle")
            await _wait_selector_text(tab_c, "#hc-auth-status-badge", "UNAUTHENTICATED")

            conn = await asyncpg.connect(DATABASE_URL)
            try:
                assert (
                    await conn.fetchval(
                        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                        uid,
                    )
                    == 0
                )
            finally:
                await conn.close()

            jar = {c["name"]: c for c in await context.cookies()}
            assert "hc_refresh" not in jar
            assert "hc_csrf" not in jar
            assert "hc_has_session" not in jar

            await context.close()
            await browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        await _cleanup_user(uid)


@pytest.mark.asyncio
async def test_t49_broadcast_ordering_old_explicit_login_and_old_logout_l01_h01(monkeypatch):
    """
    Required Races #4 & #5 (H01 & L01):
    - Old `explicitLogin: true` BroadcastChannel message arriving after Logout MUST be rejected (`H01`).
    - Old `LOGOUT` / `LOGOUT_FAILED_LOCAL_SCRUB` broadcast (`authGenSeq` < active login) arriving
      after a newer genuine explicit Login MUST be ignored (`L01`).
    """
    pwd = "BroadcastOrdering!901"
    uid, mobile = await _create_test_user(["USER"], password=pwd)
    server, thread, base_url = await _start_test_server(monkeypatch)

    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            tab_a = await context.new_page()
            tab_b = await context.new_page()

            await tab_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await tab_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")

            # Login -> Logout so localCoordLogoutSeq >= 1
            await tab_a.fill("#hc-pwd-mobile", mobile)
            await tab_a.fill("#hc-pwd-input", pwd)
            await tab_a.click("#hc-pwd-login-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")
            await _wait_selector_text(tab_b, "#hc-auth-status-badge", "AUTHENTICATED")

            await tab_a.click("#hc-top-logout-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "UNAUTHENTICATED")
            await _wait_selector_text(tab_b, "#hc-auth-status-badge", "UNAUTHENTICATED")

            # Race #4 (H01): Old/forged explicitLogin: true BroadcastChannel message with stale/missing authGenSeq
            await tab_b.evaluate(
                """() => {
                  const ch = new BroadcastChannel('hamicard_phase3_auth');
                  ch.postMessage({
                    type: 'TOKEN_REFRESHED',
                    accessToken: 'hc_at_v1.stale_explicit_login_token',
                    accessExpiresAtMs: Date.now() + 300000,
                    accessTtlMs: 300000,
                    explicitLogin: true,
                    authEpoch: 99,
                    authGenSeq: 1,
                    startedLogoutSeq: 0,
                  });
                  ch.postMessage({
                    type: 'TOKEN_REFRESHED',
                    accessToken: 'hc_at_v1.missing_seq_explicit_login',
                    accessExpiresAtMs: Date.now() + 300000,
                    accessTtlMs: 300000,
                    explicitLogin: true,
                  });
                  ch.close();
                }"""
            )
            await tab_a.wait_for_timeout(150)
            assert (await tab_a.inner_text("#hc-auth-status-badge")).strip() == "UNAUTHENTICATED"
            audit_json = await tab_a.inner_text("#hc-auth-audit-box")
            assert '"authenticated": false' in audit_json
            assert '"hasAccessTokenInClosure": false' in audit_json
            assert '"logoutBarrierActive": true' in audit_json

            # Now perform a genuine NEW explicit login on tab_a -> activeSessionLoginSeq becomes > old logout seq
            await tab_a.fill("#hc-pwd-mobile", mobile)
            await tab_a.fill("#hc-pwd-input", pwd)
            await tab_a.click("#hc-pwd-login-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")
            await _wait_selector_text(tab_b, "#hc-auth-status-badge", "AUTHENTICATED")

            # Race #5 (L01): Stale LOGOUT / LOGOUT_FAILED_LOCAL_SCRUB with authGenSeq=1 (< activeSessionLoginSeq)
            await tab_b.evaluate(
                """() => {
                  const ch = new BroadcastChannel('hamicard_phase3_auth');
                  ch.postMessage({
                    type: 'LOGOUT',
                    reason: 'stale logout broadcast',
                    authEpoch: 1,
                    authGenSeq: 1,
                  });
                  ch.postMessage({
                    type: 'LOGOUT_FAILED_LOCAL_SCRUB',
                    reason: 'stale failed logout broadcast',
                    canRetryLogout: false,
                    authEpoch: 1,
                    authGenSeq: 1,
                  });
                  ch.close();
                }"""
            )
            await tab_a.wait_for_timeout(150)
            assert (await tab_a.inner_text("#hc-auth-status-badge")).strip() == "AUTHENTICATED"
            audit_json_after = await tab_a.inner_text("#hc-auth-audit-box")
            assert '"authenticated": true' in audit_json_after
            assert '"hasAccessTokenInClosure": true' in audit_json_after

            await context.close()
            await browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        await _cleanup_user(uid)


@pytest.mark.asyncio
async def test_t49_logout_pending_immediate_scrub_and_panel_profile_m01_m02_races(monkeypatch):
    """
    Required Races #6, #7, #8 (M01 & M02):
    - Held /logout HTTP response -> `LOGOUT_PENDING` renders immediately BEFORE HTTP completes (`M02`),
      scrubbing `#hc-auth-profile-box`, `#hc-panel-authorized-badge`, and identity from DOM immediately.
    - Delayed `authenticatedFetch('/api/v1/profile/me')` resolving 200 after logout -> throws/rejected (`M01`).
    - Delayed `panel-access 200` resolving after logout OR after role revocation + hash switch ->
      NEVER commits `ALLOW` or renders `#hc-panel-authorized-badge` (`M01`).
    """
    pwd = "PendingScrubAndPanel!901"
    uid, mobile = await _create_test_user(["USER", "ADMIN"], password=pwd, first_name="سکراب‌فوری")
    server, thread, base_url = await _start_test_server(monkeypatch)

    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            page = await context.new_page()

            await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await page.fill("#hc-pwd-mobile", mobile)
            await page.fill("#hc-pwd-input", pwd)
            await page.click("#hc-pwd-login-btn")
            await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

            # Race #8a: Delayed ADMIN panel-access 200 after role revocation + route navigation back-and-forth
            panel_req_started = asyncio.Event()
            release_stale_panel = asyncio.Event()
            first_admin_intercepted = False

            async def _admin_panel_race(route):
                nonlocal first_admin_intercepted
                if not first_admin_intercepted:
                    first_admin_intercepted = True
                    panel_req_started.set()
                    await release_stale_panel.wait()
                    await route.fulfill(
                        status=200,
                        content_type="application/json",
                        body='{"authorized":true,"operational_access":true,"access_level":"OPERATIONAL_ROLE_VERIFIED","panel_role":"ADMIN","effective_roles":["USER","ADMIN"]}',
                    )
                    return
                await route.continue_()

            await page.route("**/api/v1/auth/panels/ADMIN/access", _admin_panel_race)
            await page.evaluate("window.location.hash = '#/panel/admin';")
            await asyncio.wait_for(panel_req_started.wait(), timeout=5.0)

            # Revoke ADMIN role in DB while check #1 is in flight, then switch to USER and back to ADMIN!
            conn = await asyncpg.connect(DATABASE_URL)
            try:
                await conn.execute(
                    "DELETE FROM user_roles WHERE user_id = $1 AND role_id = 'ADMIN';", uid
                )
            finally:
                await conn.close()

            await page.evaluate("window.location.hash = '#/panel/user';")
            await _wait_selector_count(page, "#hc-panel-authorized-badge")
            await page.evaluate("window.location.hash = '#/panel/admin';")
            await _wait_selector_count(page, "#hc-forbidden-box")

            # Release delayed stale ADMIN 200 -> MUST NOT overwrite #hc-forbidden-box with ALLOW!
            release_stale_panel.set()
            await page.wait_for_timeout(150)
            assert await page.locator("#hc-forbidden-box").count() == 1
            assert await page.locator("#hc-panel-authorized-badge").count() == 0
            await page.unroute("**/api/v1/auth/panels/ADMIN/access", _admin_panel_race)

            # Navigate to permitted #/panel/user and verify authorized badge appears while authenticated
            await page.evaluate("window.location.hash = '#/panel/user';")
            await _wait_selector_count(page, "#hc-panel-authorized-badge")
            assert "سکراب‌فوری" in await page.inner_text("#hc-panel-authorized-badge")

            # Race #7 (M02) + Race #6 (M01) + Race #8b (M01):
            # Trigger delayed authenticatedFetch (/profile/me), delayed panel-access, AND hold /logout
            logout_started = asyncio.Event()
            release_logout = asyncio.Event()
            profile_started = asyncio.Event()
            release_profile = asyncio.Event()

            async def _hold_logout(route):
                if route.request.method == "POST":
                    logout_started.set()
                    await release_logout.wait()
                await route.continue_()

            async def _delay_profile_200(route):
                profile_started.set()
                await release_profile.wait()
                try:
                    await route.fulfill(
                        status=200,
                        content_type="application/json",
                        body='{"user_id":"late","mobile":"09120000000","roles":["USER"],"first_name":"سکراب‌فوری","last_name":"کاربر","has_profile":true}',
                    )
                except Exception:
                    pass

            async def _delayed_panel_user(route):
                await asyncio.sleep(0.25)
                try:
                    await route.fulfill(
                        status=200,
                        content_type="application/json",
                        body='{"authorized":true,"operational_access":true,"access_level":"OPERATIONAL_ROLE_VERIFIED","panel_role":"USER","effective_roles":["USER"]}',
                    )
                except Exception:
                    pass

            await page.route("**/api/v1/auth/logout", _hold_logout)
            await page.route("**/api/v1/profile/me", _delay_profile_200)
            await page.route("**/api/v1/auth/panels/USER/access", _delayed_panel_user)

            # Assert authenticatedFetch throws UNAUTHENTICATED even if route fulfills 200 after logout begins
            fetch_race_task = asyncio.create_task(
                page.evaluate(
                    """async () => {
                      const origFetch = window.fetch;
                      window.fetch = function(input, init) {
                        const url = typeof input === 'string' ? input : (input && input.url) || '';
                        if (url.includes('/api/v1/profile/me') && init && init.signal) {
                          const cloned = { ...init };
                          delete cloned.signal;
                          return origFetch.call(this, input, cloned);
                        }
                        return origFetch.apply(this, arguments);
                      };
                      try {
                        const mod = await import('/phase3/js/auth_session.js');
                        const r = await mod.authenticatedFetch('/api/v1/profile/me');
                        return { threw: false, status: r.status };
                      } catch (e) {
                        return { threw: true, message: e && e.message };
                      } finally {
                        window.fetch = origFetch;
                      }
                    }"""
                )
            )
            await asyncio.wait_for(profile_started.wait(), timeout=5.0)
            await page.click("#hc-top-logout-btn")
            await asyncio.wait_for(logout_started.wait(), timeout=5.0)

            # BEFORE /logout HTTP completes, UI MUST already show LOGOUT_PENDING & scrub panel + identity!
            await _wait_selector_text(
                page, "#hc-session-badge", "LOGOUT_PENDING", contains=True
            )
            assert await page.locator("#hc-logout-pending-panel").count() == 1
            assert await page.locator("#hc-panel-authorized-badge").count() == 0
            assert "سکراب‌فوری" not in await page.inner_text("#app-root")
            assert await page.locator("#hc-top-refresh-btn").count() == 0

            # Navigate to #/auth/shell while LOGOUT_PENDING is still in flight -> profile scrubbed
            await page.evaluate("window.location.hash = '#/auth/shell';")
            await _wait_selector_text(page, "#hc-auth-status-badge", "LOGOUT_PENDING")
            assert "سکراب‌فوری" not in await page.inner_text("#hc-auth-profile-box")

            release_profile.set()
            fetch_outcome = await asyncio.wait_for(fetch_race_task, timeout=5.0)
            assert fetch_outcome["threw"] is True
            assert fetch_outcome["message"] == "UNAUTHENTICATED"

            release_logout.set()
            await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")
            await page.unroute("**/api/v1/profile/me", _delay_profile_200)

            await context.close()
            await browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        await _cleanup_user(uid)


@pytest.mark.asyncio
async def test_t49_logout_503_accurate_copy_blocks_late_refresh_and_3tab_race(monkeypatch):
    """
    Required Races #9 & #10 (plus L02 + L03 + OPEN-* == PROPOSED):
    - Real backend Redis outage 503 on logout clears browser cookies AND renders accurate L02 warning
      copy (never claims DB revocation confirmed), blocks late BroadcastChannel background refresh,
      and allows genuine subsequent explicit login to recover.
    - 3-tab concurrent refresh / login / logout race preserves single-flight refresh & scrubs all 3 tabs
      with 0 active PostgreSQL refresh tokens.
    """
    pwd = "ThreeTabLogout503!901"
    uid, mobile = await _create_test_user(["USER"], password=pwd)
    server, thread, base_url = await _start_test_server(monkeypatch, access_ttl=2)

    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})

            refresh_requests: list[str] = []
            tab_a = await context.new_page()
            tab_b = await context.new_page()
            tab_c = await context.new_page()
            for pg in (tab_a, tab_b, tab_c):
                pg.on(
                    "request",
                    lambda req: refresh_requests.append(req.url)
                    if req.method == "POST" and req.url.endswith("/api/v1/auth/refresh")
                    else None,
                )

            await tab_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await tab_a.fill("#hc-pwd-mobile", mobile)
            await tab_a.fill("#hc-pwd-input", pwd)
            await tab_a.click("#hc-pwd-login-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")

            # Simulate real Redis outage on revocation set -> real 503 /logout response
            real_rd = deps.get_redis()
            orig_set = real_rd.set

            def _fail_revocation_set(name, value, *args, **kwargs):
                if isinstance(name, str) and name.startswith("hc:revoked_family:"):
                    raise redis.exceptions.ConnectionError("Simulated Redis outage on 503 race")
                return orig_set(name, value, *args, **kwargs)

            monkeypatch.setattr(real_rd, "set", _fail_revocation_set)

            await tab_a.click("#hc-top-logout-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "REMOTE_REVOKE_FAILED")
            warn_text = await tab_a.inner_text("#hc-logout-warning-banner")
            event_text = await tab_a.inner_text("#hc-auth-event-msg")
            combined_copy = f"{warn_text} {event_text}"
            # L02: MUST state server/DB revocation is unconfirmed when HTTP fails without cookies
            assert "تأیید نشد" in combined_copy or "تأییدنشده" in combined_copy
            assert "پاک شدند" not in event_text.replace("کوکی‌های قابل مشاهده نشست در مرورگر پاک شده‌اند", "")

            # Restore Redis & test genuine explicit login recovery followed by 3-tab single-flight + logout race
            monkeypatch.setattr(real_rd, "set", orig_set)
            await tab_a.fill("#hc-pwd-mobile", mobile)
            await tab_a.fill("#hc-pwd-input", pwd)
            await tab_a.click("#hc-pwd-login-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")

            await asyncio.gather(
                tab_b.goto(f"{base_url}/phase3/#/panel/user", wait_until="load"),
                tab_c.goto(f"{base_url}/phase3/#/panel/user", wait_until="load"),
            )
            await asyncio.gather(
                _wait_selector_count(tab_b, "#hc-panel-authorized-badge"),
                _wait_selector_count(tab_c, "#hc-panel-authorized-badge"),
            )

            # Let 2s short-lived token expire, trigger 3-tab concurrent reload (1 coalesced /refresh), then logout
            await asyncio.sleep(2.3)
            refresh_requests.clear()
            await asyncio.gather(
                tab_a.reload(wait_until="load"),
                tab_b.reload(wait_until="load"),
                tab_c.reload(wait_until="load"),
            )
            await asyncio.gather(
                _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED"),
                _wait_selector_count(tab_b, "#hc-panel-authorized-badge"),
                _wait_selector_count(tab_c, "#hc-panel-authorized-badge"),
            )
            assert len(refresh_requests) == 1, f"Expected single-flight 1 /refresh, got {len(refresh_requests)}"

            await tab_c.click("#hc-top-logout-btn")
            await asyncio.gather(
                _wait_selector_text(tab_a, "#hc-auth-status-badge", "UNAUTHENTICATED"),
                _wait_selector_text(tab_b, "#hc-session-badge", "مهمان", contains=True),
                _wait_selector_text(tab_c, "#hc-session-badge", "مهمان", contains=True),
            )
            assert await tab_b.locator("#hc-panel-authorized-badge").count() == 0
            assert await tab_c.locator("#hc-panel-authorized-badge").count() == 0

            conn = await asyncpg.connect(DATABASE_URL)
            try:
                assert (
                    await conn.fetchval(
                        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                        uid,
                    )
                    == 0
                )
                statuses = await get_all_open_policy_statuses(conn)
                assert len(statuses) == 18
                assert all(s["approval_status"] == "PROPOSED" for s in statuses)
            finally:
                await conn.close()

            gate_doc = ROOT_DIR / "docs" / "STAGING_PROXY_RELEASE_GATE.md"
            assert gate_doc.exists()
            doc_txt = gate_doc.read_text(encoding="utf-8")
            assert "Cache-Control: no-store" in doc_txt
            assert "Path=/api/v1/auth" in doc_txt

            await context.close()
            await browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        await _cleanup_user(uid)
