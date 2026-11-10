"""
Authentication & Authorization API Endpoints (AUTH-001..017, RBAC-001..009)
"""

from typing import Dict, Any, Optional
import asyncpg
import redis
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field

from src.api.deps import get_db_pool, get_redis, get_current_user
from src.auth.service import AuthService
from src.auth.otp_service import OtpRateLimitError, OtpExpiredOrInvalidError, OtpMaxAttemptsExceededError, normalize_iranian_mobile
from src.auth.session_service import SessionService, SecurityReplayAttackError, AccountBlockedError
from src.common.validators import validate_iranian_mobile

router = APIRouter(prefix="/auth", tags=["Authentication"])


class OtpRequestSchema(BaseModel):
    mobile: str = Field(..., example="09121234567")


class OtpVerifySchema(BaseModel):
    mobile: str = Field(..., example="09121234567")
    code: str = Field(..., min_length=6, max_length=6, example="123456")


class PasswordLoginSchema(BaseModel):
    mobile: str = Field(..., example="09121234567")
    password: str = Field(..., example="SecurePassword123")


class RefreshTokenSchema(BaseModel):
    refresh_token: str


@router.post("/otp/request")
async def request_otp(
    payload: OtpRequestSchema,
    r: redis.Redis = Depends(get_redis)
):
    """Requests a 6-digit OTP code for mobile number with 120s cooldown."""
    if not validate_iranian_mobile(payload.mobile):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Iranian mobile number format."
        )

    clean_mobile = normalize_iranian_mobile(payload.mobile)
    from src.auth.otp_service import OtpService
    otp_svc = OtpService(r)

    try:
        success, ttl = otp_svc.request_otp(clean_mobile)
        return {
            "success": success,
            "message": "کد تأیید با موفقیت ارسال گردید.",
            "cooldown_seconds": ttl
        }
    except OtpRateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))


@router.post("/otp/verify")
async def verify_otp(
    payload: OtpVerifySchema,
    req: Request,
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis)
):
    """Verifies OTP and issues authenticated session with refresh token."""
    clean_mobile = normalize_iranian_mobile(payload.mobile)
    auth_svc = AuthService(pool, r)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        res = await auth_svc.authenticate_via_otp(
            raw_mobile=clean_mobile,
            otp_code=payload.code,
            device_info=req.headers.get("User-Agent", "Unknown Device"),
            ip_address=client_ip
        )
        return res
    except (OtpExpiredOrInvalidError, OtpMaxAttemptsExceededError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AccountBlockedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post("/password/login")
async def login_password(
    payload: PasswordLoginSchema,
    req: Request,
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis)
):
    """Authenticates via Argon2id hashed password."""
    clean_mobile = normalize_iranian_mobile(payload.mobile)
    auth_svc = AuthService(pool, r)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        res = await auth_svc.authenticate_via_password(
            mobile=clean_mobile,
            password=payload.password,
            device_info=req.headers.get("User-Agent", "Unknown Device"),
            ip_address=client_ip
        )
        return res
    except AccountBlockedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid mobile or password.")


@router.post("/refresh")
async def refresh_session(
    payload: RefreshTokenSchema,
    req: Request,
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Rotates refresh token under concurrent race protection (AC-15)."""
    session_svc = SessionService(pool)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        new_token = await session_svc.rotate_refresh_token(
            raw_token=payload.refresh_token,
            device_info=req.headers.get("User-Agent", "Unknown"),
            ip_address=client_ip
        )
        return {
            "success": True,
            "refresh_token": new_token,
            "token_type": "bearer"
        }
    except SecurityReplayAttackError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security violation: Replay attack detected. Session terminated."
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/logout")
async def logout(
    payload: RefreshTokenSchema,
    pool: asyncpg.Pool = Depends(get_db_pool),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Revokes active session."""
    session_svc = SessionService(pool)
    await session_svc.revoke_token(payload.refresh_token)
    return {"success": True, "message": "نشست با موفقیت پایان یافت."}
