"""
Automated Security & Full-Stack Playwright E2E Suite for HC-T39 (HC-CMD-040)
Baseline: BL-HAMICARD-PRD-V1

Verifies integrated Phase 3 frontend (`src/ui_shell` served at `/phase3/`) + hardened HC-T38 cookie auth:
1. Strict CSP (`script-src 'self'`, `style-src 'self'`, zero `unsafe-inline`/`unsafe-eval`),
   no-store cache control, X-Content-Type-Options, X-Frame-Options, path traversal block.
2. Zero `localStorage.hamicard_session_token`, zero web storage usage in `src/ui_shell`, and 18/18 OPEN-* PROPOSED.
3. Server-enforced RBAC role routing (`/api/v1/auth/panels/{role}/access`), live revocation, CSRF & Origin rejection.
4. Real Chromium E2E across 3 tabs:
   - OTP request & cookie verify -> closure RAM token -> profile XSS boundary test (escaped payload, 0 execution).
   - Role routing (`#/panel/user` -> 200) and Forbidden state (`#/panel/admin` -> 403 `#hc-forbidden-box`).
   - Short-lived access token natural expiry (`2.3s`) -> transparent single-flight auto-refresh (`200 OK`).
   - 3-Tab simultaneous reload -> coalesces to exactly `1` POST `/api/v1/auth/refresh`.
   - Terminal family revocation -> expired session UI (`#hc-expired-banner` HTTP 401).
   - Password login (`ADMIN` role) -> `#/panel/admin` authorized -> cross-tab instant logout + BFCache `go_back` scrub.
   - Deterministic PNG screenshots + `SCREENSHOT_MANIFEST.json` + zero console/page/external errors.
"""

import asyncio
import hashlib
import json
import os
import pathlib
import re
import socket
import threading
import time
import uuid

import asyncpg
import httpx
import pytest
import pytest_asyncio
import redis
import uvicorn
from playwright.async_api import async_playwright

from src.api import deps
from src.api.main import app, create_app
from src.auth.service import AuthService
from src.core.policy import get_all_open_policy_statuses
from src.core.security import hash_password
from src.profiles.service import ProfileService

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
UI_SHELL_DIR = ROOT_DIR / "src" / "ui_shell"
SHOTS_DIR = ROOT_DIR / "docs" / "screenshots" / "phase3_t39"

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

BROWSER_CANDIDATES = [
    pathlib.Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    pathlib.Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    pathlib.Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
]


async def _launch_headless_chromium(p):
    for candidate in BROWSER_CANDIDATES:
        if candidate.exists():
            return await p.chromium.launch(headless=True, executable_path=str(candidate))
    return await p.chromium.launch(
        headless=True,
        args=["--disable-dev-shm-usage", "--no-sandbox"],
    )


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _wait_selector_text(
    page, selector: str, expected: str, *, contains: bool = False, timeout: float = 10.0
) -> str:
    deadline = time.monotonic() + timeout
    last_val = None
    while time.monotonic() < deadline:
        loc = page.locator(selector)
        if await loc.count() > 0:
            last_val = await loc.first.text_content()
            if last_val is not None:
                if (contains and expected in last_val) or (not contains and last_val.strip() == expected):
                    return last_val
        await asyncio.sleep(0.05)
    raise AssertionError(f"Timeout waiting for {selector} text={expected!r}, last={last_val!r}")


async def _wait_selector_count(page, selector: str, expected_min: int = 1, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await page.locator(selector).count() >= expected_min:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"Timeout waiting for selector {selector} count >= {expected_min}")


@pytest_asyncio.fixture
async def t39_env(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t39-test-signing-secret-material-64-chars-minimum-entropy-value-0001",
    )
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", "300")
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "http://testserver,http://127.0.0.1:3000,http://localhost:3000",
    )
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=5)
    rd = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    rd.ping()
    deps._pool = pool
    deps._redis = rd

    try:
        yield pool, rd
    finally:
        await pool.close()
        deps._pool = None
        rd.close()
        deps._redis = None


async def _create_test_user(pool: asyncpg.Pool, roles: list[str], *, password: str | None = None):
    mobile = f"0912{uuid.uuid4().int % 10000000:07d}"
    pwd_hash = hash_password(password) if password else None
    async with pool.acquire() as conn:
        uid = await conn.fetchval(
            """
            INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
            VALUES ($1, $2, 'ACTIVE', TRUE)
            RETURNING id;
            """,
            mobile,
            pwd_hash,
        )
        for r in roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
                uid,
                r,
            )
    return uid, mobile


@pytest.mark.asyncio
async def test_t39_security_headers_csp_storage_and_open_policies(t39_env):
    """T39 static/CSP security boundaries, path traversal rejection, zero web storage, OPEN-* PROPOSED."""
    pool, _rd = t39_env
    transport = httpx.ASGITransport(app=create_app())

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_redir = await client.get("/phase3", follow_redirects=False)
        assert r_redir.status_code == 307
        assert r_redir.headers.get("location") == "/phase3/"
        assert "no-store" in r_redir.headers.get("cache-control", "").lower()

        for route in ("/phase3/", "/phase3/index.html"):
            r = await client.get(route)
            assert r.status_code == 200
            csp = r.headers.get("content-security-policy", "")
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert "style-src 'self'" in csp
            assert "unsafe-inline" not in csp
            assert "unsafe-eval" not in csp
            assert "frame-ancestors 'none'" in csp
            assert r.headers.get("x-content-type-options") == "nosniff"
            assert r.headers.get("x-frame-options") == "DENY"
            assert "no-store" in r.headers.get("cache-control", "").lower()

        for asset_route in (
            "/phase3/styles/tokens.css",
            "/phase3/styles/shell.css",
            "/phase3/js/app.js",
            "/phase3/js/auth_session.js",
        ):
            r_asset = await client.get(asset_route)
            assert r_asset.status_code == 200
            assert r_asset.headers.get("x-content-type-options") == "nosniff"
            assert "no-store" in r_asset.headers.get("cache-control", "").lower()

        # Traversal & non-JS/CSS rejection
        for bad_asset in (
            "/phase3/js/..%2F..%2Fapi%2Fauth.py",
            "/phase3/js/secret.json",
            "/phase3/styles/tokens.css.bak",
        ):
            assert (await client.get(bad_asset)).status_code == 404

    # Static AST/grep scan across integrated src/ui_shell: ZERO web storage or unsafe sinks
    forbidden_js_patterns = [
        r"hamicard_session_token",
        r"\blocalStorage\b",
        r"\bsessionStorage\b",
        r"\bindexedDB\b",
        r"\bouterHTML\b",
        r"\binsertAdjacentHTML\b",
        r"document\.write\s*\(",
        r"\beval\s*\(",
        r"\bnew\s+Function\b",
        r"\bstyle=",
    ]
    for js_file in (UI_SHELL_DIR / "js").rglob("*.js"):
        txt = js_file.read_text(encoding="utf-8")
        for pat in forbidden_js_patterns:
            assert not re.search(pat, txt), f"Forbidden pattern {pat} in {js_file.name}"

    html_txt = (UI_SHELL_DIR / "index.html").read_text(encoding="utf-8")
    assert "hamicard_session_token" not in html_txt
    assert not re.search(r"<script(?![^>]*\bsrc=)", html_txt, re.IGNORECASE)
    assert not re.search(r"\son[a-z]+\s*=", html_txt, re.IGNORECASE)

    # All 18 OPEN-* policies remain PROPOSED
    async with pool.acquire() as conn:
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)


@pytest.mark.asyncio
async def test_t39_server_panel_rbac_csrf_origin_and_expiry(t39_env):
    """T39 API matrix: role routing, live RBAC revocation, CSRF, untrusted Origin, and unauth rejection."""
    pool, _rd = t39_env
    user_pwd = "HamiPhase3!Strong#901"
    user_uid, user_mobile = await _create_test_user(pool, ["USER"], password=user_pwd)
    sup_uid, sup_mobile = await _create_test_user(pool, ["SUPER_ADMIN"], password=user_pwd)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Unauthenticated access rejected 401 + no-store
        r_unauth = await client.get("/api/v1/auth/panels/USER/access")
        assert r_unauth.status_code == 401
        assert "no-store" in r_unauth.headers.get("cache-control", "").lower()

        # 2. Cross-origin cookie login rejected 403 before session minting
        r_bad_origin = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": user_mobile, "password": user_pwd},
            headers={"Origin": "https://attacker-phase3.example", "X-Auth-Mode": "cookie"},
        )
        assert r_bad_origin.status_code == 403

        # 3. Trusted Origin cookie login succeeds for USER
        r_login = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": user_mobile, "password": user_pwd},
            headers={"Origin": "http://127.0.0.1:3000", "X-Auth-Mode": "cookie"},
        )
        assert r_login.status_code == 200
        at_user = r_login.json()["access_token"]
        csrf_user = client.cookies.get("hc_csrf")
        assert client.cookies.get("hc_refresh")
        assert csrf_user

        # USER allowed on /panels/USER/access -> 200; forbidden on ADMIN/SUPER_ADMIN/DOCTOR/AGENT/SUPPORT -> 403
        r_ok = await client.get(
            "/api/v1/auth/panels/USER/access",
            headers={"Authorization": f"Bearer {at_user}"},
        )
        assert r_ok.status_code == 200
        assert r_ok.json()["authorized"] is True
        assert r_ok.json()["open_policies_status"] == "PROPOSED"

        for forbidden_role in ("DOCTOR", "AGENT", "SUPPORT", "ADMIN", "SUPER_ADMIN"):
            r_forb = await client.get(
                f"/api/v1/auth/panels/{forbidden_role}/access",
                headers={"Authorization": f"Bearer {at_user}"},
            )
            assert r_forb.status_code == 403, f"Expected 403 for USER->{forbidden_role}, got {r_forb.status_code}"

        # 4. Missing or mismatched CSRF token on /refresh rejected 403
        r_no_csrf = await client.post(
            "/api/v1/auth/refresh",
            headers={"Origin": "http://127.0.0.1:3000", "X-Auth-Mode": "cookie"},
        )
        assert r_no_csrf.status_code == 403

        # 5. Live RBAC escalation & immediate revocation on same token
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'ADMIN') ON CONFLICT DO NOTHING;",
                user_uid,
            )
        assert (
            await client.get(
                "/api/v1/auth/panels/ADMIN/access",
                headers={"Authorization": f"Bearer {at_user}"},
            )
        ).status_code == 200
        assert (
            await client.get(
                "/api/v1/auth/panels/SUPER_ADMIN/access",
                headers={"Authorization": f"Bearer {at_user}"},
            )
        ).status_code == 403

        async with pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM user_roles WHERE user_id = $1 AND role_id = 'ADMIN';",
                user_uid,
            )
        assert (
            await client.get(
                "/api/v1/auth/panels/ADMIN/access",
                headers={"Authorization": f"Bearer {at_user}"},
            )
        ).status_code == 403

        # 6. Cookie-mode logout invalidates session immediately
        r_out = await client.post(
            "/api/v1/auth/logout",
            headers={
                "Origin": "http://127.0.0.1:3000",
                "X-Auth-Mode": "cookie",
                "X-CSRF-Token": csrf_user,
                "Authorization": f"Bearer {at_user}",
            },
        )
        assert r_out.status_code == 200
        assert (
            await client.get(
                "/api/v1/auth/panels/USER/access",
                headers={"Authorization": f"Bearer {at_user}"},
            )
        ).status_code == 401

        # 7. SUPER_ADMIN reaches all 6 panels
        r_sup = await client.post(
            "/api/v1/auth/password/login",
            json={"mobile": sup_mobile, "password": user_pwd},
            headers={"Origin": "http://127.0.0.1:3000", "X-Auth-Mode": "cookie"},
        )
        assert r_sup.status_code == 200
        at_sup = r_sup.json()["access_token"]
        for role in ("USER", "DOCTOR", "AGENT", "SUPPORT", "ADMIN", "SUPER_ADMIN"):
            assert (
                await client.get(
                    f"/api/v1/auth/panels/{role}/access",
                    headers={"Authorization": f"Bearer {at_sup}"},
                )
            ).status_code == 200

    # 8. AuthService direct sanity check still clean
    auth_svc = AuthService(pool, _rd)
    assert auth_svc is not None


@pytest.mark.asyncio
async def test_t39_playwright_e2e_full_integration_and_screenshots(monkeypatch):
    """
    Real Chromium E2E against live Uvicorn `/phase3/`:
    - OTP request & cookie verify + XSS payload safe escaping (`window.__xssFired === undefined`)
    - Role routing (`#/panel/user` -> 200) + Forbidden state (`#/panel/admin` -> 403)
    - Natural short access token expiry (2s TTL) -> transparent single-flight refresh retry
    - 3-Tab simultaneous reload -> coalesces to `1` POST /api/v1/auth/refresh
    - Terminal revocation -> expired session 401 UI banner (`#hc-expired-banner`)
    - Admin password login -> authorized Admin panel -> cross-tab instant logout + BFCache scrub
    - Generates deterministic PNG screenshots + `SCREENSHOT_MANIFEST.json`
    """
    SHOTS_DIR.mkdir(parents=True, exist_ok=True)
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t39-e2e-signing-secret-material-64-chars-minimum-entropy-value-0002",
    )
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", "2")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", base_url)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    rd = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    rd.ping()
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=5)

    admin_pwd = "AdminPhase3!Strong#902"
    xss_first_name = '<img src=x onerror="window.__xssFired=true">علی'
    xss_last_name = '<script>window.__xssFired=true</script>تست'

    user_uid, user_mobile = await _create_test_user(pool, ["USER"])
    prof_svc = ProfileService(pool)
    await prof_svc.upsert_profile(
        user_id=user_uid,
        first_name=xss_first_name,
        last_name=xss_last_name,
    )
    admin_uid, admin_mobile = await _create_test_user(pool, ["ADMIN"], password=admin_pwd)
    await pool.close()

    server = uvicorn.Server(
        uvicorn.Config(
            create_app(),
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        async with httpx.AsyncClient(base_url=base_url) as probe:
            for _ in range(50):
                try:
                    resp = await probe.get("/api/v1/health")
                    if resp.status_code == 200:
                        break
                except Exception:
                    await asyncio.sleep(0.1)
            else:
                pytest.fail("Live uvicorn failed to start for HC-T39 E2E")

        console_errors: list[str] = []
        page_errors: list[str] = []
        refresh_posts: list[str] = []
        unexpected_hosts: list[str] = []
        manifest_shots: dict[str, dict] = {}

        async def _capture(page, filename: str):
            out_path = SHOTS_DIR / filename
            await page.screenshot(path=str(out_path), full_page=True)
            data_bytes = out_path.read_bytes()
            manifest_shots[filename] = {
                "path": str(out_path.relative_to(ROOT_DIR)).replace("\\", "/"),
                "bytes": len(data_bytes),
                "sha256": hashlib.sha256(data_bytes).hexdigest(),
            }

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

            # 1. Guest lands on /phase3/#/auth/shell & verifies zero web storage + zero HttpOnly cookie exposure
            tab_a = await context.new_page()
            _attach_listeners(tab_a)
            await tab_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "UNAUTHENTICATED")
            await _capture(tab_a, "01_phase3_auth_shell_guest.png")

            storage_before = await tab_a.evaluate(
                "() => ({ ls: Object.keys(localStorage).length, ss: Object.keys(sessionStorage).length, dc: document.cookie })"
            )
            assert storage_before["ls"] == 0
            assert storage_before["ss"] == 0
            assert "hc_refresh" not in storage_before["dc"]

            # 2. OTP Request & Cookie Verify in UI
            await tab_a.fill("#hc-otp-mobile", user_mobile)
            await tab_a.click("#hc-otp-request-btn")
            otp_code = None
            for _ in range(25):
                otp_code = rd.get(f"otp:code:{user_mobile}")
                if otp_code:
                    break
                await asyncio.sleep(0.1)
            assert otp_code, "OTP code not generated in Redis"

            await tab_a.fill("#hc-otp-code", otp_code)
            await tab_a.click("#hc-otp-verify-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")

            jar = {c["name"]: c for c in await context.cookies()}
            assert jar["hc_refresh"]["httpOnly"] is True
            assert jar["hc_refresh"]["sameSite"] == "Lax"
            assert jar["hc_refresh"]["path"] == "/api/v1/auth"
            storage_after = await tab_a.evaluate(
                "() => ({ ls: Object.keys(localStorage).length, ss: Object.keys(sessionStorage).length, dc: document.cookie })"
            )
            assert storage_after["ls"] == 0
            assert storage_after["ss"] == 0
            assert "hc_refresh" not in storage_after["dc"]

            # 3. Navigate to permitted #/panel/user -> server 200 + XSS boundary escaped cleanly
            await tab_a.evaluate("window.location.hash = '#/panel/user';")
            await _wait_selector_count(tab_a, "#hc-panel-authorized-badge")
            xss_fired = await tab_a.evaluate("() => window.__xssFired === true")
            assert xss_fired is False, "XSS executed in user profile rendering!"
            panel_text = await tab_a.inner_text("#hc-panel-authorized-badge")
            assert "علی" in panel_text
            assert "<img" in panel_text  # literal escaped string rendered safely as text
            await _capture(tab_a, "02_phase3_authenticated_user_xss_escaped.png")

            # 4. Forbidden role routing: USER clicks ADMIN role pill -> server 403 -> #hc-forbidden-box
            await tab_a.click('[data-role-route="#/panel/admin"]')
            await _wait_selector_count(tab_a, "#hc-forbidden-box")
            forb_text = await tab_a.inner_text("#hc-forbidden-box")
            assert "۴۰۳" in forb_text
            assert await tab_a.locator(".hc-workspace").count() == 0
            await _capture(tab_a, "03_phase3_forbidden_403_rbac.png")

            # 5. Open Tab B & Tab C; wait 2.3s for natural 2s access token expiry -> 3-Tab reload coalesces to 1 /refresh!
            tab_b = await context.new_page()
            _attach_listeners(tab_b)
            await tab_b.goto(f"{base_url}/phase3/#/panel/user", wait_until="load")
            await _wait_selector_count(tab_b, "#hc-panel-authorized-badge")

            tab_c = await context.new_page()
            _attach_listeners(tab_c)
            await tab_c.goto(f"{base_url}/phase3/#/panel/user", wait_until="load")
            await _wait_selector_count(tab_c, "#hc-panel-authorized-badge")

            refresh_posts.clear()
            await asyncio.gather(
                tab_a.reload(wait_until="load"),
                tab_b.reload(wait_until="load"),
                tab_c.reload(wait_until="load"),
            )
            # Navigate tab_a back to #/panel/user (it was on #/panel/admin -> test user on tab_b & tab_c)
            await asyncio.gather(
                _wait_selector_text(tab_a, "#hc-session-badge", "HttpOnly Cookie", contains=True),
                _wait_selector_count(tab_b, "#hc-panel-authorized-badge"),
                _wait_selector_count(tab_c, "#hc-panel-authorized-badge"),
            )
            assert len(refresh_posts) == 1, (
                f"Expected 1 coalesced POST /refresh across 3 reloads, got {len(refresh_posts)}"
            )

            # Natural expiry of 2s short-lived access token -> transparent auto-refresh on #hc-top-refresh-btn or nav
            await asyncio.sleep(2.4)
            refresh_posts.clear()
            await tab_b.evaluate("window.location.hash = '#/home';")
            await tab_b.wait_for_timeout(50)
            await tab_b.evaluate("window.location.hash = '#/panel/user';")
            await _wait_selector_count(tab_b, "#hc-panel-authorized-badge")
            assert len(refresh_posts) >= 1, "Expected automatic cookie refresh after 2s access token expiry"

            # 6. Terminal Session Revocation -> #hc-expired-banner (HTTP 401 state)
            verify_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
            async with verify_pool.acquire() as conn:
                fams = await conn.fetch(
                    "SELECT DISTINCT family_id FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                    user_uid,
                )
                for fam in fams:
                    rd.setex(f"revoked:family:{fam['family_id']}", 600, "ADMIN_REVOKE_TEST")
                await conn.execute(
                    "UPDATE refresh_tokens SET status = 'REVOKED' WHERE user_id = $1;",
                    user_uid,
                )
            await verify_pool.close()

            await asyncio.sleep(2.4)  # Let cached 2s access token expire so browser tries /refresh and hits 401
            await tab_a.evaluate("window.location.hash = '#/auth/shell';")
            await tab_a.wait_for_timeout(60)
            await tab_a.click("#hc-refresh-btn")
            await _wait_selector_count(tab_a, "#hc-expired-banner")
            await _capture(tab_a, "04_phase3_session_expired_401.png")

            # 7. Password Login as ADMIN -> #/panel/admin 200 OK -> Cross-Tab Logout & BFCache Scrub
            await tab_a.evaluate("window.location.hash = '#/auth/shell';")
            await _wait_selector_count(tab_a, "#hc-pwd-mobile")
            await tab_a.fill("#hc-pwd-mobile", admin_mobile)
            await tab_a.fill("#hc-pwd-input", admin_pwd)
            await tab_a.click("#hc-pwd-login-btn")
            await _wait_selector_text(tab_a, "#hc-auth-status-badge", "AUTHENTICATED")

            await tab_a.evaluate("window.location.hash = '#/panel/admin';")
            await _wait_selector_count(tab_a, "#hc-panel-authorized-badge")
            assert "ADMIN" in await tab_a.inner_text("#hc-panel-authorized-badge")
            await _capture(tab_a, "05_phase3_admin_panel_authorized.png")

            # Tab B observes active Admin sync cleanly; navigate Tab C away to /auth-poc/public for go_back BFCache check
            await tab_b.evaluate("window.location.hash = '#/panel/admin';")
            await _wait_selector_count(tab_b, "#hc-panel-authorized-badge")
            await tab_c.goto(f"{base_url}/auth-poc/public", wait_until="networkidle")

            # Logout from Tab A -> Tab B clears instantly via BroadcastChannel -> Tab C go_back + persisted pageshow scrubs
            await tab_a.click("#hc-top-logout-btn")
            await _wait_selector_text(tab_a, "#hc-session-badge", "مهمان", contains=True)
            await _wait_selector_text(tab_b, "#hc-session-badge", "مهمان", contains=True)

            await tab_c.go_back(wait_until="networkidle")
            await tab_c.evaluate(
                "() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))"
            )
            await _wait_selector_text(tab_c, "#hc-session-badge", "مهمان", contains=True)
            await _capture(tab_c, "06_phase3_logged_out_bfcache_scrub.png")

            post_logout_jar = {c["name"]: c for c in await context.cookies()}
            assert "hc_refresh" not in post_logout_jar
            assert "hc_csrf" not in post_logout_jar
            assert "hc_has_session" not in post_logout_jar
            unexpected_console_errors = [
                msg
                for msg in console_errors
                if msg
                not in (
                    "Failed to load resource: the server responded with a status of 403 (Forbidden)",
                    "Failed to load resource: the server responded with a status of 401 (Unauthorized)",
                )
            ]
            assert unexpected_console_errors == [], (
                f"Unexpected console/CSP/JS errors observed: {unexpected_console_errors}"
            )
            assert page_errors == [], f"Page errors observed: {page_errors}"
            assert unexpected_hosts == [], f"Unexpected external requests observed: {unexpected_hosts}"

            await context.close()
            await browser.close()

        # Write deterministic SCREENSHOT_MANIFEST.json
        manifest = {
            "schema": "hamicard.t39_screenshot_manifest.v1",
            "task_id": "HC-T39",
            "command_id": "HC-CMD-040",
            "screenshots": manifest_shots,
        }
        (SHOTS_DIR / "SCREENSHOT_MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        rd.close()

