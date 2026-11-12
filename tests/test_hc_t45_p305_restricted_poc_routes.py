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

import os

import asyncpg
import httpx
import pytest

import src.api.deps as deps
from src.api.main import create_app
from src.core.policy import get_all_open_policy_statuses

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
    "https://app.hamicard.ir/auth_poc/public",
    "https://app.hamicard.ir/static/auth_poc.html",
    "https://app.hamicard.ir/static/auth_poc_public.html",
    "https://app.hamicard.ir/static/auth_poc.js",
    "https://app.hamicard.ir/static/auth_poc.css",
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
