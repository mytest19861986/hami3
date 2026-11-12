"""
Automated Security & Regression Verification for HC-T45 (HC-CMD-046 / P3-05)
Baseline: BL-HAMICARD-PRD-V1

Verifies P3-05 closure in restricted (`production` / `staging`) environments:
1. `/auth-poc`, `/auth-poc/public`, `/static/auth_poc*`, `/static/index.html`, plus trailing
   slash, case, URL-encoded, double-encoded, dot-segment, duplicate-slash, backslash,
   matrix-param, and query-string variants all fail closed with HTTP `404` and strict
   `no-store` headers.
2. Approved Phase 3 frontend (`/`, `/phase3/`, `/phase3/js/*`, `/phase3/styles/*`, `/styles/*`,
   `/js/*`, `/manifest.json`) and `/api/v1/*` endpoints continue functioning normally in
   both `production` and `staging`.
3. `development` and `test` environments continue serving `/auth-poc`, `/auth-poc/public`,
   and `/static/auth_poc*` (`200 OK`) for developer/QA suites.
4. Conflicting/invalid environment config fails closed (`503`) without exposing `/auth-poc*`.
5. All 18 OPEN-* business policies remain `PROPOSED`.
"""

import asyncio
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
import uuid

import asyncpg
import httpx
import pytest
import uvicorn
from playwright.async_api import async_playwright

import src.api.deps as deps
from src.api.main import create_app
from src.api.release_entrypoint import validate_release_runtime_environment
from src.core.cors import CorsConfigurationError
from src.core.env import EnvironmentConfigurationError
from src.core.policy import get_all_open_policy_statuses
from src.core.security import hash_password

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


def _configure_restricted_env(monkeypatch, env_var: str, env_val: str) -> None:
    for var in ("APP_ENV", "ENVIRONMENT", "NODE_ENV"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv(env_var, env_val)
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.hamicard.ir")
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t45-restricted-route-gate-secret-material-64-chars-minimum-0001",
    )
    monkeypatch.setenv("SMS_PROVIDER", "kavenegar")
    monkeypatch.setenv("KAVENEGAR_API_KEY", "dummy-configured-test-only")
    monkeypatch.setenv("PAYMENT_GATEWAY", "zarinpal")
    monkeypatch.setenv("ZARINPAL_MERCHANT_ID", "00000000-0000-0000-0000-000000000000")


RESTRICTED_ENV_MATRIX = [
    ("ENVIRONMENT", "production"),
    ("APP_ENV", "prod"),
    ("ENVIRONMENT", "staging"),
    ("NODE_ENV", "stage"),
]

BLOCKED_POC_URLS = [
    "https://app.hamicard.ir/auth-poc",
    "https://app.hamicard.ir/auth-poc/",
    "https://app.hamicard.ir/auth-poc-preview",
    "https://app.hamicard.ir/auth-poc.html",
    "https://app.hamicard.ir/auth-poc-beta/step1",
    "https://app.hamicard.ir/%61uth-poc-preview",
    "https://app.hamicard.ir/AUTH-POC",
    "https://app.hamicard.ir/auth-poc?next=/panel",
    "https://app.hamicard.ir/%61uth-poc",
    "https://app.hamicard.ir/%2561uth-poc",
    "https://app.hamicard.ir/./auth-poc",
    "https://app.hamicard.ir//auth-poc",
    "https://app.hamicard.ir/auth-poc;v=1",
    "https://app.hamicard.ir/auth-poc/public",
    "https://app.hamicard.ir/auth-poc/public/",
    "https://app.hamicard.ir/AUTH-POC/PUBLIC",
    "https://app.hamicard.ir/auth-poc/%70ublic",
    "https://app.hamicard.ir/auth-poc//public",
    "https://app.hamicard.ir/auth_poc",
    "https://app.hamicard.ir/auth_poc_test",
    "https://app.hamicard.ir/auth_poc.html",
    "https://app.hamicard.ir/auth_poc/public",
    "https://app.hamicard.ir/static/auth_poc.html",
    "https://app.hamicard.ir/static/auth_poc_public.html",
    "https://app.hamicard.ir/static/auth_poc.js",
    "https://app.hamicard.ir/static/auth_poc.css",
    "https://app.hamicard.ir/phase3/auth_poc.html",
    "https://app.hamicard.ir/phase3/auth-poc.js",
    "https://app.hamicard.ir/static/AUTH_POC.JS",
    "https://app.hamicard.ir/static/%61uth_poc.js",
    "https://app.hamicard.ir/static/%2561uth_poc.html",
    "https://app.hamicard.ir/static/%5cauth_poc.js",
    "https://app.hamicard.ir/static/./auth_poc.js",
    "https://app.hamicard.ir/static//auth_poc.css",
    "https://app.hamicard.ir/static/sub/../auth_poc.js",
    "https://app.hamicard.ir/static/auth_poc.js?v=123",
    "https://app.hamicard.ir/static/auth_poc.js;cache=1",
    "https://app.hamicard.ir/static/index.html",
    "https://app.hamicard.ir/static/%69ndex.html",
    "https://app.hamicard.ir/static/./index.html",
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("env_var", "env_val"), RESTRICTED_ENV_MATRIX)
async def test_t45_restricted_envs_block_all_auth_poc_pages_assets_and_variants(
    monkeypatch, env_var: str, env_val: str
):
    _configure_restricted_env(monkeypatch, env_var, env_val)
    restricted_app = create_app()
    transport = httpx.ASGITransport(app=restricted_app)

    async with httpx.AsyncClient(
        transport=transport, base_url="https://app.hamicard.ir"
    ) as client:
        for url in BLOCKED_POC_URLS:
            resp = await client.get(url, follow_redirects=False)
            assert resp.status_code == 404, (
                f"Expected 404 for {url!r} in {env_var}={env_val}, got {resp.status_code}"
            )
            assert "no-store" in (resp.headers.get("cache-control") or "").lower(), (
                f"Expected no-store Cache-Control on blocked {url!r}"
            )
            assert resp.headers.get("pragma") == "no-cache"
            assert resp.headers.get("x-content-type-options") == "nosniff"
            assert "HamiCard" not in resp.text and "auth_poc" not in resp.text

        for head_path in ("/auth-poc", "/auth-poc/public", "/static/auth_poc.js"):
            head_resp = await client.head(head_path, follow_redirects=False)
            assert head_resp.status_code == 404
            assert "no-store" in (head_resp.headers.get("cache-control") or "").lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(("env_var", "env_val"), RESTRICTED_ENV_MATRIX[:3])
async def test_t45_restricted_envs_preserve_phase3_frontend_and_api_routes(
    monkeypatch, env_var: str, env_val: str
):
    _configure_restricted_env(monkeypatch, env_var, env_val)
    await deps.close_pool()
    deps.close_redis()

    restricted_app = create_app()
    transport = httpx.ASGITransport(app=restricted_app)

    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="https://app.hamicard.ir"
        ) as client:
            r_root = await client.get("/", follow_redirects=False)
            assert r_root.status_code == 200
            assert "script-src 'self'" in (
                r_root.headers.get("content-security-policy") or ""
            )
            assert "no-store" in (r_root.headers.get("cache-control") or "").lower()
            assert "hamicard_session_token" not in r_root.text

            r_p3_redir = await client.get("/phase3", follow_redirects=False)
            assert r_p3_redir.status_code == 307
            assert r_p3_redir.headers.get("location") == "/phase3/"
            assert "no-store" in (r_p3_redir.headers.get("cache-control") or "").lower()

            for asset_path in (
                "/phase3/",
                "/phase3/index.html",
                "/phase3/js/app.js",
                "/js/app.js",
                "/phase3/styles/tokens.css",
                "/styles/tokens.css",
                "/manifest.json",
                "/static/manifest.json",
            ):
                r_ok = await client.get(asset_path, follow_redirects=False)
                assert r_ok.status_code == 200, (
                    f"Expected 200 for {asset_path!r}, got {r_ok.status_code}"
                )

            # Public API health, plans, and auth routes remain active under restricted envs
            r_health = await client.get("/api/v1/health", follow_redirects=False)
            assert r_health.status_code == 200
            assert r_health.json()["status"] == "healthy"

            r_plans = await client.get("/api/v1/plans", follow_redirects=False)
            assert r_plans.status_code == 200

            r_panel = await client.get(
                "/api/v1/auth/panels/user/access", follow_redirects=False
            )
            assert r_panel.status_code == 401
    finally:
        await deps.close_pool()
        deps.close_redis()


@pytest.mark.asyncio
@pytest.mark.parametrize("env_val", ["test", "development"])
async def test_t45_non_restricted_envs_preserve_auth_poc_and_static_assets(
    monkeypatch, env_val: str
):
    for var in ("APP_ENV", "ENVIRONMENT", "NODE_ENV"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ENVIRONMENT", env_val)

    dev_app = create_app()
    transport = httpx.ASGITransport(app=dev_app)

    async with httpx.AsyncClient(
        transport=transport, base_url="http://127.0.0.1:8000"
    ) as client:
        for path in (
            "/auth-poc",
            "/auth-poc/public",
            "/static/auth_poc.html",
            "/static/auth_poc_public.html",
            "/static/auth_poc.js",
            "/static/auth_poc.css",
            "/static/index.html",
            "/",
        ):
            resp = await client.get(path, follow_redirects=False)
            assert resp.status_code == 200, (
                f"Expected 200 in {env_val} for {path!r}, got {resp.status_code}"
            )
            if path.startswith("/auth-poc"):
                assert "no-store" in (resp.headers.get("cache-control") or "").lower()
                assert "script-src 'self'" in (
                    resp.headers.get("content-security-policy") or ""
                )


@pytest.mark.asyncio
async def test_t45_conflicting_env_fails_closed_503_and_open_policies_remain_proposed(
    monkeypatch,
):
    _configure_restricted_env(monkeypatch, "ENVIRONMENT", "production")
    prod_app = create_app()

    # Introduce runtime env conflict -> must fail closed 503 even on /auth-poc
    monkeypatch.setenv("APP_ENV", "development")
    transport = httpx.ASGITransport(app=prod_app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://app.hamicard.ir"
    ) as client:
        r_conflict = await client.get("/auth-poc", follow_redirects=False)
        assert r_conflict.status_code == 503
        assert "no-store" in (r_conflict.headers.get("cache-control") or "").lower()

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)
    finally:
        await conn.close()


ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]

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
                if (contains and expected in last_val) or (
                    not contains and last_val.strip() == expected
                ):
                    return last_val
        await asyncio.sleep(0.05)
    raise AssertionError(f"Timeout waiting for {selector} text={expected!r}, last={last_val!r}")


@pytest.mark.parametrize(
    ("env_overrides", "expected_exc"),
    [
        ({}, EnvironmentConfigurationError),
        ({"APP_ENV": "   ", "ENVIRONMENT": ""}, EnvironmentConfigurationError),
        ({"ENVIRONMENT": "development"}, EnvironmentConfigurationError),
        ({"APP_ENV": "test"}, EnvironmentConfigurationError),
        (
            {"APP_ENV": "production", "ENVIRONMENT": "development"},
            EnvironmentConfigurationError,
        ),
        ({"ENVIRONMENT": "canary"}, EnvironmentConfigurationError),
        ({"ENVIRONMENT": "production", "CORS_ALLOWED_ORIGINS": ""}, CorsConfigurationError),
        ({"ENVIRONMENT": "production", "CORS_ALLOWED_ORIGINS": "*"}, CorsConfigurationError),
    ],
)
def test_t45_release_entrypoint_fails_closed_on_missing_or_invalid_env(
    monkeypatch, env_overrides: dict[str, str], expected_exc
):
    for var in ("APP_ENV", "ENVIRONMENT", "NODE_ENV", "CORS_ALLOWED_ORIGINS", "ALLOWED_CORS_ORIGINS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    for k, v in env_overrides.items():
        monkeypatch.setenv(k, v)

    with pytest.raises(expected_exc):
        validate_release_runtime_environment()

    clean_env = dict(os.environ)
    for var in ("APP_ENV", "ENVIRONMENT", "NODE_ENV", "CORS_ALLOWED_ORIGINS", "ALLOWED_CORS_ORIGINS"):
        clean_env.pop(var, None)
    for k, v in env_overrides.items():
        clean_env[k] = v

    proc = subprocess.run(
        [sys.executable, "-m", "src.api.release_entrypoint"],
        cwd=str(ROOT_DIR),
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert proc.returncode == 1
    assert "FAIL-CLOSED" in proc.stderr


def test_t45_release_entrypoint_and_packaging_enforce_restricted_prod_hygiene(monkeypatch):
    _configure_restricted_env(monkeypatch, "ENVIRONMENT", "production")
    assert validate_release_runtime_environment() == "production"

    dockerfile_text = (ROOT_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "rm -f src/static/auth_poc* src/static/index.html" in dockerfile_text
    assert '"src.api.release_entrypoint"' in dockerfile_text

    compose_prod_text = (ROOT_DIR / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "ENVIRONMENT: production" in compose_prod_text


@pytest.mark.asyncio
async def test_t45_asgi_lifespan_startup_and_shutdown_in_production(monkeypatch):
    _configure_restricted_env(monkeypatch, "ENVIRONMENT", "production")
    await deps.close_pool()
    deps.close_redis()

    prod_app = create_app()
    async with prod_app.router.lifespan_context(prod_app):
        assert hasattr(prod_app.state, "cors_settings")
        assert len(prod_app.state.settings) >= 18
        for k, v in prod_app.state.settings.items():
            if k.startswith("OPEN_"):
                assert v is not None

        transport = httpx.ASGITransport(app=prod_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://app.hamicard.ir"
        ) as client:
            r_health = await client.get("/api/v1/health")
            assert r_health.status_code == 200
            r_poc = await client.get("/auth-poc-preview")
            assert r_poc.status_code == 404
            assert "no-store" in (r_poc.headers.get("cache-control") or "").lower()

    await deps.close_pool()
    deps.close_redis()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_mode", ["http_403", "http_503", "network_abort"])
async def test_t45_browser_logout_failure_preserves_honest_warning_and_allows_retry(
    monkeypatch, failure_mode: str
):
    await deps.close_pool()
    deps.close_redis()

    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t45-logout-failure-e2e-signing-secret-material-64-chars-min-0001",
    )
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", base_url)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    mobile = f"0919{uuid.uuid4().int % 10000000:07d}"
    pwd = "LogoutHardening!901"
    pwd_hash = hash_password(pwd)

    conn = await asyncpg.connect(DATABASE_URL)
    uid = None
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
        await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'USER');", uid)
    finally:
        await conn.close()

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
                pytest.fail("Live uvicorn failed to start for logout failure test")

        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context(viewport={"width": 1280, "height": 800})
            page = await context.new_page()

            await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")

            await page.fill("#hc-pwd-mobile", mobile)
            await page.fill("#hc-pwd-input", pwd)
            await page.click("#hc-pwd-login-btn")
            await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

            # Simulate failed remote logout (403, 503, or network drop)
            async def _fail_logout(route):
                if failure_mode == "http_403":
                    await route.fulfill(
                        status=403,
                        content_type="application/json",
                        body='{"detail":"CSRF validation rejected"}',
                    )
                elif failure_mode == "http_503":
                    await route.fulfill(
                        status=503,
                        content_type="application/json",
                        body='{"detail":"Revocation store unavailable"}',
                    )
                else:
                    await route.abort()

            await page.route("**/api/v1/auth/logout", _fail_logout)
            await page.click("#hc-top-logout-btn")

            # Must scrub local RAM token BUT NEVER claim safe guest logout
            await _wait_selector_text(page, "#hc-auth-status-badge", "REMOTE_REVOKE_FAILED")
            session_badge_text = await page.inner_text("#hc-session-badge")
            assert "تأیید نشد" in session_badge_text
            assert "مهمان" not in session_badge_text
            assert await page.locator("#hc-retry-logout-btn").count() == 1
            assert await page.locator("#hc-auth-retry-logout-btn").count() == 1
            assert await page.locator("#hc-auth-error-msg").count() == 1

            audit_json = await page.inner_text("#hc-auth-audit-box")
            assert '"hasAccessTokenInClosure": false' in audit_json

            # Server session cookies were NOT revoked yet
            mid_jar = {c["name"]: c for c in await context.cookies()}
            assert "hc_refresh" in mid_jar
            assert "hc_has_session" in mid_jar

            # Reloading while unrevoked honestly reflects still-active server session
            await page.unroute("**/api/v1/auth/logout", _fail_logout)
            await page.reload(wait_until="networkidle")
            await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

            # Re-test single retry flow after transient failure -> real 200 clears everything cleanly
            await page.route("**/api/v1/auth/logout", _fail_logout)
            await page.click("#hc-top-logout-btn")
            await _wait_selector_text(page, "#hc-auth-status-badge", "REMOTE_REVOKE_FAILED")

            await page.unroute("**/api/v1/auth/logout", _fail_logout)
            await page.click("#hc-retry-logout-btn")
            await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")
            await _wait_selector_text(page, "#hc-session-badge", "مهمان", contains=True)

            post_jar = {c["name"]: c for c in await context.cookies()}
            assert "hc_refresh" not in post_jar
            assert "hc_csrf" not in post_jar
            assert "hc_has_session" not in post_jar

            await context.close()
            await browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        if uid is not None:
            cleanup_conn = await asyncpg.connect(DATABASE_URL)
            try:
                await cleanup_conn.execute("DELETE FROM refresh_tokens WHERE user_id = $1;", uid)
                await cleanup_conn.execute("DELETE FROM user_roles WHERE user_id = $1;", uid)
                await cleanup_conn.execute("DELETE FROM users WHERE id = $1;", uid)
            finally:
                await cleanup_conn.close()
