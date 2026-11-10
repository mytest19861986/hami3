"""
HamiCard (حامی‌کارت) FastAPI Application Core
Baseline: BL-HAMICARD-PRD-V1
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB connection pool and Redis
    await init_pool()
    init_redis()
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


@app.get("/")
def root():
    return {
        "message": "به سامانه خدمات رفاهی و درمانی حامی‌کارت خوش آمدید.",
        "docs": "/docs",
        "health": "/api/v1/health"
    }
