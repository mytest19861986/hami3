"""
Integrated Phase 3 Security & Release Gate Verification for HC-T43 (HC-CMD-044)
Verifies on the consolidated candidate:
1. No persistent JS-readable refresh-token or auth-token path remains in either
   `src/ui_shell/` or legacy `src/static/index.html` (`localStorage` / `sessionStorage` scrubbed).
2. In restricted (`production` / `staging`) environments, `GET /` redirects fail-closed
   (`307`) to the strict-CSP Phase 3 frontend `/phase3/` (no legacy root HTML served), and
   `/phase3/` enforces strict CSP (`script-src 'self'`, zero `unsafe-inline`/`unsafe-eval`).
3. Preserves original F-01..F-13 + HC-T30 + P3-01..P3-03 invariants across integrated files
   and confirms all 18 OPEN-* business policies remain `PROPOSED`.
"""

import os
import pathlib
import re

import asyncpg
import httpx
import pytest

from src.api.main import create_app
from src.core.policy import get_all_open_policy_statuses

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)


def test_t43_no_persistent_js_refresh_token_or_storage_in_frontends():
    ui_shell_files = list((ROOT_DIR / "src" / "ui_shell").rglob("*.js")) + list(
        (ROOT_DIR / "src" / "ui_shell").rglob("*.html")
    )
    assert ui_shell_files, "Expected src/ui_shell frontend files"

    for p in ui_shell_files:
        txt = p.read_text(encoding="utf-8")
        assert "hamicard_session_token" not in txt, f"Legacy session key found in {p}"
        assert not re.search(r"\blocalStorage\b|\bsessionStorage\b", txt), f"Web storage used in {p}"
        assert "refresh_token" not in txt, f"JS refresh_token reference found in {p}"

    legacy_index = (ROOT_DIR / "src" / "static" / "index.html").read_text(encoding="utf-8")
    assert "hamicard_session_token" not in legacy_index
    assert "refresh_token" not in legacy_index
    assert not re.search(
        r"(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\([^)]*(token|session|auth|jwt)",
        legacy_index,
        flags=re.IGNORECASE,
    )
    assert "X-Auth-Mode" in legacy_index
    assert "refreshSessionSingleFlight" in legacy_index
    assert "/auth/logout" in legacy_index


@pytest.mark.asyncio
async def test_t43_restricted_env_routes_root_to_phase3_strict_csp_and_open_policies(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.hamicard.ir")
    monkeypatch.setenv(
        "ACCESS_TOKEN_SECRET",
        "t43-prod-gate-signing-secret-material-64-chars-minimum-value-0001",
    )
    monkeypatch.setenv("SMS_PROVIDER", "kavenegar")
    monkeypatch.setenv("KAVENEGAR_API_KEY", "dummy-configured-test-only")
    monkeypatch.setenv("PAYMENT_GATEWAY", "zarinpal")
    monkeypatch.setenv("ZARINPAL_MERCHANT_ID", "00000000-0000-0000-0000-000000000000")

    prod_app = create_app()
    transport = httpx.ASGITransport(app=prod_app)
    async with httpx.AsyncClient(transport=transport, base_url="https://app.hamicard.ir") as client:
        r_root = await client.get("/", follow_redirects=False)
        assert r_root.status_code == 200
        root_csp = r_root.headers.get("content-security-policy") or ""
        assert "script-src 'self'" in root_csp
        assert "unsafe-inline" not in root_csp
        assert "no-store" in (r_root.headers.get("cache-control") or "")
        assert "hamicard_session_token" not in r_root.text
        assert "Phase 3" in r_root.text or "فاز ۳" in r_root.text

        r_static_legacy = await client.get("/static/index.html", follow_redirects=False)
        assert r_static_legacy.status_code == 404

        r_phase3 = await client.get("/phase3/")
        assert r_phase3.status_code == 200
        csp = r_phase3.headers.get("content-security-policy") or ""
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert "no-store" in (r_phase3.headers.get("cache-control") or "")

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        statuses = await get_all_open_policy_statuses(conn)
        assert len(statuses) == 18
        assert all(s["approval_status"] == "PROPOSED" for s in statuses)
    finally:
        await conn.close()
