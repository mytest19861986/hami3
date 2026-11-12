"""
Automated Professional Approval & RBAC Panel Gating Tests for HC-T41 (HC-CMD-042 / P3-02)
Verifies:
1. DOCTOR & AGENT with MISSING, PENDING, SUSPENDED, or REJECTED verification_status receive
   HTTP 403 PROFESSIONAL_APPROVAL_REQUIRED (operational_access=False, status_view_allowed=True).
2. DOCTOR & AGENT with APPROVED record receive HTTP 200 OPERATIONAL_APPROVED (operational_access=True).
3. Live status demotion (APPROVED -> SUSPENDED) and live role revocation take effect on the very next check.
4. SUPER_ADMIN administrative view returns ADMIN_REVIEW_ONLY with operational_access=False (never impersonates).
5. Headless Chromium UI reflects exact server state (#hc-application-status-box vs #hc-admin-review-badge vs #hc-panel-authorized-badge).
"""

import asyncio
import pathlib
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
from src.core.policy import get_all_open_policy_statuses
from src.core.security import hash_password

DATABASE_URL = "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
REDIS_URL = "redis://localhost:6379/0"

BROWSER_CANDIDATES = [
    pathlib.Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    pathlib.Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    pathlib.Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
]


async def _launch_browser(p):
    for cand in BROWSER_CANDIDATES:
        if cand.exists():
            return await p.chromium.launch(headless=True, executable_path=str(cand))
    return await p.chromium.launch(
        headless=True,
        args=["--disable-dev-shm-usage", "--no-sandbox"],
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest_asyncio.fixture
async def t41_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t41-test-signing-secret-material-64-chars-minimum-entropy-value-0001",
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


async def _create_user_with_roles(pool: asyncpg.Pool, roles: list[str], password: str):
    mobile = f"0913{uuid.uuid4().int % 10000000:07d}"
    pwd_hash = hash_password(password)
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
        for role in roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
                uid,
                role,
            )
    return uid, mobile


@pytest.mark.asyncio
async def test_t41_http_doctor_and_agent_approval_gating_and_admin_review_separation(t41_env):
    pool, _rd = t41_env
    pwd = "T41!StrongPass#2026"
    doc_uid, doc_mobile = await _create_user_with_roles(pool, ["DOCTOR"], pwd)
    agt_uid, agt_mobile = await _create_user_with_roles(pool, ["AGENT"], pwd)
    sup_uid, sup_mobile = await _create_user_with_roles(pool, ["SUPER_ADMIN"], pwd)
    adm_uid, adm_mobile = await _create_user_with_roles(pool, ["ADMIN"], pwd)
    _ = sup_uid, adm_uid

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Login all 4 actors
        async def login(mob: str) -> str:
            r = await client.post(
                "/api/v1/auth/password/login",
                json={"mobile": mob, "password": pwd},
                headers={"Origin": "http://127.0.0.1:3000", "X-Auth-Mode": "cookie"},
            )
            assert r.status_code == 200, r.text
            return r.json()["access_token"]

        at_doc = await login(doc_mobile)
        at_agt = await login(agt_mobile)
        at_sup = await login(sup_mobile)
        at_adm = await login(adm_mobile)

        # 1. MISSING doctor & agent records -> MUST reject 403 PROFESSIONAL_APPROVAL_REQUIRED
        r_doc_missing = await client.get("/api/v1/auth/panels/DOCTOR/access", headers={"Authorization": f"Bearer {at_doc}"})
        assert r_doc_missing.status_code == 403
        assert r_doc_missing.json()["code"] == "PROFESSIONAL_APPROVAL_REQUIRED"
        assert r_doc_missing.json()["verification_status"] == "MISSING"
        assert r_doc_missing.json()["operational_access"] is False

        r_agt_missing = await client.get("/api/v1/auth/panels/AGENT/access", headers={"Authorization": f"Bearer {at_agt}"})
        assert r_agt_missing.status_code == 403
        assert r_agt_missing.json()["code"] == "PROFESSIONAL_APPROVAL_REQUIRED"
        assert r_agt_missing.json()["verification_status"] == "MISSING"
        assert r_agt_missing.json()["operational_access"] is False

        # 2. Insert PENDING doctor and PENDING agent -> 403
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status)
                VALUES ($1, $2, 'داخلی', 'کلینیک تست', 1, 1, 'تهران', '02188000001', 'PENDING');
                """,
                doc_uid,
                f"MC-{uuid.uuid4().hex[:8]}",
            )
            await conn.execute(
                """
                INSERT INTO agents (user_id, business_name, business_type, province_id, city_id, verification_status)
                VALUES ($1, 'نمایندگی تست', 'INDIVIDUAL', 1, 1, 'PENDING');
                """,
                agt_uid,
            )

        for status_val in ("PENDING", "SUSPENDED", "REJECTED"):
            async with pool.acquire() as conn:
                await conn.execute("UPDATE doctors SET verification_status = $2 WHERE user_id = $1;", doc_uid, status_val)
                await conn.execute("UPDATE agents SET verification_status = $2 WHERE user_id = $1;", agt_uid, status_val)

            rd = await client.get("/api/v1/auth/panels/DOCTOR/access", headers={"Authorization": f"Bearer {at_doc}"})
            assert rd.status_code == 403
            assert rd.json()["verification_status"] == status_val
            assert rd.json()["operational_access"] is False

            ra = await client.get("/api/v1/auth/panels/AGENT/access", headers={"Authorization": f"Bearer {at_agt}"})
            assert ra.status_code == 403
            assert ra.json()["verification_status"] == status_val
            assert ra.json()["operational_access"] is False

        # 3. Approve both -> HTTP 200 OPERATIONAL_APPROVED
        async with pool.acquire() as conn:
            await conn.execute("UPDATE doctors SET verification_status = 'APPROVED' WHERE user_id = $1;", doc_uid)
            await conn.execute("UPDATE agents SET verification_status = 'APPROVED' WHERE user_id = $1;", agt_uid)

        rd_ok = await client.get("/api/v1/auth/panels/DOCTOR/access", headers={"Authorization": f"Bearer {at_doc}"})
        assert rd_ok.status_code == 200
        assert rd_ok.json()["authorized"] is True
        assert rd_ok.json()["operational_access"] is True
        assert rd_ok.json()["access_level"] == "OPERATIONAL_APPROVED"
        assert rd_ok.json()["verification_status"] == "APPROVED"

        ra_ok = await client.get("/api/v1/auth/panels/AGENT/access", headers={"Authorization": f"Bearer {at_agt}"})
        assert ra_ok.status_code == 200
        assert ra_ok.json()["operational_access"] is True
        assert ra_ok.json()["access_level"] == "OPERATIONAL_APPROVED"

        # 4. Live suspension + live role revocation take effect on next check
        async with pool.acquire() as conn:
            await conn.execute("UPDATE doctors SET verification_status = 'SUSPENDED' WHERE user_id = $1;", doc_uid)
        rd_susp = await client.get("/api/v1/auth/panels/DOCTOR/access", headers={"Authorization": f"Bearer {at_doc}"})
        assert rd_susp.status_code == 403
        assert rd_susp.json()["verification_status"] == "SUSPENDED"

        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM user_roles WHERE user_id = $1 AND role_id = 'AGENT';", agt_uid)
        ra_rev = await client.get("/api/v1/auth/panels/AGENT/access", headers={"Authorization": f"Bearer {at_agt}"})
        assert ra_rev.status_code == 403

        # 5. ADMIN cannot enter DOCTOR/AGENT panel directly (403), SUPER_ADMIN gets ADMIN_REVIEW_ONLY (operational_access=False)
        assert (await client.get("/api/v1/auth/panels/DOCTOR/access", headers={"Authorization": f"Bearer {at_adm}"})).status_code == 403
        assert (await client.get("/api/v1/auth/panels/AGENT/access", headers={"Authorization": f"Bearer {at_adm}"})).status_code == 403

        for sup_panel in ("DOCTOR", "AGENT"):
            rs = await client.get(f"/api/v1/auth/panels/{sup_panel}/access", headers={"Authorization": f"Bearer {at_sup}"})
            assert rs.status_code == 200
            assert rs.json()["access_level"] == "ADMIN_REVIEW_ONLY"
            assert rs.json()["operational_access"] is False
            assert rs.json()["verification_status"] == "ADMIN_REVIEW_ONLY"

        # Verify all 18 OPEN-* policies remain PROPOSED
        async with pool.acquire() as conn:
            statuses = await get_all_open_policy_statuses(conn)
            assert len(statuses) == 18
            assert all(s["approval_status"] == "PROPOSED" for s in statuses)


@pytest.mark.asyncio
async def test_t41_playwright_ui_reflects_pending_approved_and_admin_review_states(monkeypatch):
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("ACCESS_TOKEN_SECRET", "t41-ui-signing-secret-material-64-chars-minimum-entropy-value-0002")
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", "300")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", base_url)
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    conn = await asyncpg.connect(DATABASE_URL)
    pwd = "T41!UiPass#99"
    try:
        mobile_doc = f"0913{uuid.uuid4().int % 10000000:07d}"
        mobile_sup = f"0913{uuid.uuid4().int % 10000000:07d}"
        pwd_hash = hash_password(pwd)
        doc_uid = await conn.fetchval(
            """
            INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
            VALUES ($1, $2, 'ACTIVE', TRUE)
            RETURNING id;
            """,
            mobile_doc,
            pwd_hash,
        )
        await conn.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'DOCTOR') ON CONFLICT DO NOTHING;",
            doc_uid,
        )
        sup_uid = await conn.fetchval(
            """
            INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
            VALUES ($1, $2, 'ACTIVE', TRUE)
            RETURNING id;
            """,
            mobile_sup,
            pwd_hash,
        )
        await conn.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'SUPER_ADMIN') ON CONFLICT DO NOTHING;",
            sup_uid,
        )
        await conn.execute(
            """
            INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status)
            VALUES ($1, $2, 'عمومی', 'کلینیک تستی', 1, 1, 'تهران', '02188000002', 'PENDING');
            """,
            doc_uid,
            f"MC-{uuid.uuid4().hex[:8]}",
        )
    finally:
        await conn.close()
    doc_mobile = mobile_doc
    sup_mobile = mobile_sup
    deps._pool = None
    deps._redis = None

    config = uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15.0
        ready = False
        async with httpx.AsyncClient() as c:
            while time.monotonic() < deadline:
                if not thread.is_alive():
                    pytest.fail("Live uvicorn exited unexpectedly during startup")
                try:
                    if (await c.get(f"{base_url}/phase3/")).status_code == 200:
                        ready = True
                        break
                except Exception:
                    await asyncio.sleep(0.1)
        if not ready:
            pytest.fail("Live uvicorn did not become ready in time")

        async with async_playwright() as p:
            browser = await _launch_browser(p)
            ctx = await browser.new_context(viewport={"width": 1280, "height": 840})
            page = await ctx.new_page()

            await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await page.fill("#hc-pwd-mobile", doc_mobile)
            await page.fill("#hc-pwd-input", pwd)
            await page.click("#hc-pwd-login-btn")
            await page.wait_for_selector("#hc-top-logout-btn")

            # PENDING doctor -> MUST render limited #hc-application-status-box and 0 #hc-panel-authorized-badge
            await page.goto(f"{base_url}/phase3/#/panel/doctor", wait_until="networkidle")
            await page.wait_for_selector("#hc-application-status-box")
            assert await page.locator("#hc-panel-authorized-badge").count() == 0
            assert "PENDING" in (await page.locator("#hc-application-status-box").text_content() or "")

            # Approve doctor in DB -> reloading panel grants operational badge
            conn_upd = await asyncpg.connect(DATABASE_URL)
            try:
                await conn_upd.execute("UPDATE doctors SET verification_status = 'APPROVED' WHERE user_id = $1;", doc_uid)
            finally:
                await conn_upd.close()
            await page.reload(wait_until="networkidle")
            await page.wait_for_selector("#hc-panel-authorized-badge")
            assert await page.locator("#hc-application-status-box").count() == 0

            # Logout and sign in as SUPER_ADMIN -> #hc-admin-review-badge ONLY (never #hc-panel-authorized-badge)
            await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
            await page.click("#hc-logout-btn")
            await page.wait_for_function("() => !document.getElementById('hc-top-logout-btn')")
            await page.fill("#hc-pwd-mobile", sup_mobile)
            await page.fill("#hc-pwd-input", pwd)
            await page.click("#hc-pwd-login-btn")
            await page.wait_for_selector("#hc-top-logout-btn")

            await page.goto(f"{base_url}/phase3/#/panel/doctor", wait_until="networkidle")
            await page.wait_for_selector("#hc-admin-review-badge")
            assert await page.locator("#hc-panel-authorized-badge").count() == 0

            await browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        deps._pool = None
        deps._redis = None
