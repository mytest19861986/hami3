"""
HamiCard (حامی‌کارت) FastAPI Application Core
Baseline: BL-HAMICARD-PRD-V1
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from src.api.deps import init_pool, close_pool, init_redis, close_redis
from src.api.health import router as health_router
from src.api.auth import router as auth_router
from src.api.reference import router as reference_router
from src.api.doctors import router as doctors_router
from src.api.plans import router as plans_router
from src.api.content import router as content_router
from src.api.profiles import router as profiles_router
from src.api.wallets import router as wallets_router
from src.api.visits import router as visits_router
from src.api.sales import router as sales_router
from src.api.payments import router as payments_router
from src.api.reviews import router as reviews_router
from src.api.notifications import router as notifications_router
from src.core.settings import load_and_validate_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
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


app = FastAPI(
    title="HamiCard API",
    description="سامانه خدمات رفاهی و درمانی حامی‌کارت — هسته سرویس‌های بک‌اند",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers under /api/v1
API_V1_PREFIX = "/api/v1"
app.include_router(health_router, prefix=API_V1_PREFIX)
app.include_router(auth_router, prefix=API_V1_PREFIX)
app.include_router(reference_router, prefix=API_V1_PREFIX)
app.include_router(doctors_router, prefix=API_V1_PREFIX)
app.include_router(plans_router, prefix=API_V1_PREFIX)
app.include_router(content_router, prefix=API_V1_PREFIX)
app.include_router(profiles_router, prefix=API_V1_PREFIX)
app.include_router(wallets_router, prefix=API_V1_PREFIX)
app.include_router(visits_router, prefix=API_V1_PREFIX)
app.include_router(sales_router, prefix=API_V1_PREFIX)
app.include_router(payments_router, prefix=API_V1_PREFIX)
app.include_router(reviews_router, prefix=API_V1_PREFIX)
app.include_router(notifications_router, prefix=API_V1_PREFIX)

# Mount static files and web portal
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def root():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "message": "به سامانه خدمات رفاهی و درمانی حامی‌کارت خوش آمدید.",
        "docs": "/docs",
        "health": "/api/v1/health"
    }


@app.get("/manifest.json", include_in_schema=False)
def manifest():
    manifest_file = os.path.join(STATIC_DIR, "manifest.json")
    if os.path.exists(manifest_file):
        return FileResponse(manifest_file, media_type="application/manifest+json")
    return {}
