"""
HamiCard (حامی‌کارت) FastAPI Application Core
Baseline: BL-HAMICARD-PRD-V1
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from src.adapters.payment import PaymentGatewayError
from src.adapters.sms import SmsAdapterError
from src.api.auth import router as auth_router
from src.api.cards import router as cards_router
from src.api.content import router as content_router
from src.api.deps import close_pool, close_redis, init_pool, init_redis
from src.api.doctors import router as doctors_router
from src.api.health import router as health_router
from src.api.notifications import router as notifications_router
from src.api.payments import router as payments_router
from src.api.plans import router as plans_router
from src.api.profiles import router as profiles_router
from src.api.reference import router as reference_router
from src.api.reviews import router as reviews_router
from src.api.sales import router as sales_router
from src.api.visits import router as visits_router
from src.api.wallets import router as wallets_router
from src.auth.access_tokens import AccessTokenConfigurationError, RevocationStoreUnavailableError
from src.core.cors import StrictCORSMiddleware, resolve_cors_settings
from src.core.env import EnvironmentConfigurationError
from src.core.settings import load_and_validate_settings
from src.wallets.service import PayoutAdapterConfigurationError


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Enforce CORS policy validation cleanly at runtime startup too
    app.state.cors_settings = resolve_cors_settings()
    # Startup: Initialize DB connection pool and Redis
    pool = await init_pool()
    init_redis()
    # Enforce Fail-Closed Startup Invariant (OPEN-01..18)
    async with pool.acquire() as conn:
        app.state.settings = await load_and_validate_settings(conn)
    yield
    # Shutdown: Cleanly close pools
    await close_pool()
    close_redis()


STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
API_V1_PREFIX = "/api/v1"


def create_app() -> FastAPI:
    cors_cfg = resolve_cors_settings()
    application = FastAPI(
        title="HamiCard API",
        description="سامانه خدمات رفاهی و درمانی حامی‌کارت — هسته سرویس‌های بک‌اند",
        version="1.0.0",
        lifespan=lifespan,
    )

    @application.exception_handler(EnvironmentConfigurationError)
    @application.exception_handler(AccessTokenConfigurationError)
    @application.exception_handler(RevocationStoreUnavailableError)
    @application.exception_handler(PaymentGatewayError)
    @application.exception_handler(PayoutAdapterConfigurationError)
    @application.exception_handler(SmsAdapterError)
    async def fail_closed_runtime_config_handler(request: Request, exc: Exception):
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    # Environment-controlled fail-closed CORS configuration (M-1 / HC-T26)
    application.add_middleware(
        StrictCORSMiddleware,
        allow_origins=cors_cfg["allow_origins"],
        allow_credentials=cors_cfg["allow_credentials"],
        allow_methods=cors_cfg["allow_methods"],
        allow_headers=cors_cfg["allow_headers"],
    )

    # Register routers under /api/v1
    application.include_router(health_router, prefix=API_V1_PREFIX)
    application.include_router(auth_router, prefix=API_V1_PREFIX)
    application.include_router(reference_router, prefix=API_V1_PREFIX)
    application.include_router(doctors_router, prefix=API_V1_PREFIX)
    application.include_router(plans_router, prefix=API_V1_PREFIX)
    application.include_router(content_router, prefix=API_V1_PREFIX)
    application.include_router(profiles_router, prefix=API_V1_PREFIX)
    application.include_router(wallets_router, prefix=API_V1_PREFIX)
    application.include_router(visits_router, prefix=API_V1_PREFIX)
    application.include_router(sales_router, prefix=API_V1_PREFIX)
    application.include_router(payments_router, prefix=API_V1_PREFIX)
    application.include_router(cards_router, prefix=API_V1_PREFIX)
    application.include_router(reviews_router, prefix=API_V1_PREFIX)
    application.include_router(notifications_router, prefix=API_V1_PREFIX)

    # Mount static files and web portal
    if os.path.exists(STATIC_DIR):
        application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @application.get("/", include_in_schema=False)
    def root():
        index_file = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {
            "message": "به سامانه خدمات رفاهی و درمانی حامی‌کارت خوش آمدید.",
            "docs": "/docs",
            "health": "/api/v1/health",
        }

    @application.get("/manifest.json", include_in_schema=False)
    def manifest():
        manifest_file = os.path.join(STATIC_DIR, "manifest.json")
        if os.path.exists(manifest_file):
            return FileResponse(manifest_file, media_type="application/manifest+json")
        return {}

    _poc_security_headers = {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    @application.get("/auth-poc", include_in_schema=False)
    def auth_poc_page():
        poc_file = os.path.join(STATIC_DIR, "auth_poc.html")
        if os.path.exists(poc_file):
            return FileResponse(poc_file, media_type="text/html", headers=_poc_security_headers)
        return Response(status_code=404, content="Auth PoC page not found.")

    @application.get("/auth-poc/public", include_in_schema=False)
    def auth_poc_public_page():
        pub_file = os.path.join(STATIC_DIR, "auth_poc_public.html")
        if os.path.exists(pub_file):
            return FileResponse(pub_file, media_type="text/html", headers=_poc_security_headers)
        return Response(status_code=404, content="Auth PoC public page not found.")

    return application


app = create_app()
