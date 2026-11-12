"""
Automated Security Tests for Environment-Controlled Fail-Closed CORS Policy (HC-T26 / M-1)
BASELINE: BL-HAMICARD-PRD-V1 | HC-CMD-027

Covers:
- T26-AC1: Untrusted origins cannot receive credentialed CORS approval (no Origin reflection).
- T26-AC2: Explicitly approved origins work under environment configuration (GET & preflight OPTIONS).
- T26-AC3: Production configuration fails closed when missing/empty and never defaults to wildcard origins.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.main import create_app
from src.core.cors import (
    DEV_DEFAULT_CORS_ORIGINS,
    CorsConfigurationError,
    resolve_cors_settings,
)


def _clear_cors_env(monkeypatch):
    for key in (
        "APP_ENV",
        "ENVIRONMENT",
        "NODE_ENV",
        "CORS_ALLOWED_ORIGINS",
        "ALLOWED_CORS_ORIGINS",
        "CORS_ALLOW_CREDENTIALS",
    ):
        monkeypatch.delenv(key, raising=False)


def test_t26_ac3_production_missing_or_wildcard_cors_fails_closed(monkeypatch):
    _clear_cors_env(monkeypatch)
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "   ")
    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "*")
    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://*.hamicard.example")
    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "null")
    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.hamicard.example/path")
    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()


def test_t26_ac3_non_prod_never_uses_wildcard_and_rejects_star(monkeypatch):
    _clear_cors_env(monkeypatch)
    cfg = resolve_cors_settings()
    assert "*" not in cfg["allow_origins"]
    assert cfg["allow_origins"] == DEV_DEFAULT_CORS_ORIGINS
    assert cfg["allow_credentials"] is True

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "*")
    with pytest.raises(CorsConfigurationError):
        resolve_cors_settings()


@pytest.mark.asyncio
async def test_t26_ac1_ac2_explicit_origins_and_untrusted_origin_rejection(monkeypatch):
    _clear_cors_env(monkeypatch)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "https://panel.hamicard.example/, https://app.hamicard.example",
    )

    test_app = create_app()
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Allowed origin GET
        r_ok_get = await client.get(
            "/",
            headers={"Origin": "https://panel.hamicard.example"},
        )
        assert r_ok_get.status_code == 200
        assert r_ok_get.headers.get("access-control-allow-origin") == "https://panel.hamicard.example"
        assert r_ok_get.headers.get("access-control-allow-credentials") == "true"

        # Allowed origin Preflight OPTIONS with Idempotency-Key & Authorization
        r_ok_opt = await client.options(
            "/api/v1/profile/me",
            headers={
                "Origin": "https://app.hamicard.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type, Idempotency-Key",
            },
        )
        assert r_ok_opt.status_code == 200
        assert r_ok_opt.headers.get("access-control-allow-origin") == "https://app.hamicard.example"
        assert r_ok_opt.headers.get("access-control-allow-credentials") == "true"

        # Untrusted & lookalike origins GET: must NOT reflect Origin or grant credentialed CORS
        for bad_origin in (
            "https://evil-attacker.example",
            "https://app.hamicard.example.evil.com",
            "https://evil-app.hamicard.example",
            "null",
        ):
            r_bad_get = await client.get("/", headers={"Origin": bad_origin})
            assert r_bad_get.headers.get("access-control-allow-origin") is None
            assert r_bad_get.headers.get("access-control-allow-credentials") is None

        # Untrusted origin Preflight OPTIONS: must be rejected (400) with no ACAO/ACAC headers
        r_bad_opt = await client.options(
            "/api/v1/profile/me",
            headers={
                "Origin": "https://evil-attacker.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert r_bad_opt.status_code == 400
        assert r_bad_opt.headers.get("access-control-allow-origin") is None
        assert r_bad_opt.headers.get("access-control-allow-credentials") is None
