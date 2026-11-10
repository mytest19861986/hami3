"""
Authentication & Authorization API Endpoints (AUTH-001..017, RBAC-001..009)
REMEDIATION: HC-T13 (F-01..F-05, T13-AC1..AC6)
"""

from typing import Any, Dict

import asyncpg
import redis
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from src.adapters.sms import SmsAdapterError
from src.api.deps import get_current_user, get_db_pool, get_redis
from src.auth.otp_service import (
    OtpExpiredOrInvalidError,
    OtpMaxAttemptsExceededError,
    OtpRateLimitError,
    OtpService,
    SmsDeliveryError,
    normalize_iranian_mobile,
)
from src.auth.service import AuthService, InvalidCredentialsError
from src.auth.session_service import (
    AccountBlockedError,
    ConcurrentRefreshConflictError,
    SecurityReplayAttackError,
    SessionExpiredError,
    SessionNotFoundError,
    SessionService,
)
from src.common.validators import validate_iranian_mobile
from src.core.security import hash_token

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


def _set_no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"


@router.post("/otp/request")
async def request_otp(
    payload: OtpRequestSchema,
    response: Response,
    r: redis.Redis = Depends(get_redis),
):
    """Requests a 6-digit OTP code for mobile number with fail-closed SMS dispatch."""
    _set_no_store(response)
    if not validate_iranian_mobile(payload.mobile):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Iranian mobile number format.",
        )

    clean_mobile = normalize_iranian_mobile(payload.mobile)

    try:
        otp_svc = OtpService(r)
        success, ttl = await otp_svc.request_otp(clean_mobile)
        return {
            "success": success,
            "message": "کد تأیید با موفقیت ارسال گردید.",
            "cooldown_seconds": ttl,
        }
    except OtpRateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except (SmsDeliveryError, SmsAdapterError) as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="سرویس ارسال پیامک در دسترس نیست. عملیات طبق سیاست ایمنی متوقف شد.",
        ) from e


@router.post("/otp/verify")
async def verify_otp(
    payload: OtpVerifySchema,
    req: Request,
    response: Response,
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis),
):
    """Atomically verifies & consumes OTP and issues authenticated session."""
    _set_no_store(response)
    if not validate_iranian_mobile(payload.mobile):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mobile or verification code.",
        )

    clean_mobile = normalize_iranian_mobile(payload.mobile)
    auth_svc = AuthService(pool, r)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        res = await auth_svc.authenticate_via_otp(
            raw_mobile=clean_mobile,
            otp_code=payload.code,
            device_info=req.headers.get("User-Agent", "Unknown Device"),
            ip_address=client_ip,
        )
        return res
    except OtpRateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except (OtpExpiredOrInvalidError, OtpMaxAttemptsExceededError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AccountBlockedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication unavailable for this account.",
        ) from e


@router.post("/password/login")
async def login_password(
    payload: PasswordLoginSchema,
    req: Request,
    response: Response,
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis),
):
    """
    Authenticates via Argon2id hashed password with lockout and strict non-enumerating errors (F-03, T13-AC2).
    """
    _set_no_store(response)
    if not validate_iranian_mobile(payload.mobile):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or authentication unavailable.",
        )

    clean_mobile = normalize_iranian_mobile(payload.mobile)
    auth_svc = AuthService(pool, r)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        res = await auth_svc.authenticate_via_password(
            raw_mobile=clean_mobile,
            plain_password=payload.password,
            device_info=req.headers.get("User-Agent", "Unknown Device"),
            ip_address=client_ip,
        )
        return res
    except (InvalidCredentialsError, AccountBlockedError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or authentication unavailable.",
        )


@router.post("/refresh")
async def refresh_session(
    payload: RefreshTokenSchema,
    req: Request,
    response: Response,
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Rotates refresh token under concurrent race protection (AC-15, F-01, T13-AC4).
    Competing concurrent callers receive HTTP 409 Conflict WITHOUT credential disclosure.
    """
    _set_no_store(response)
    session_svc = SessionService(pool)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        rotated = await session_svc.rotate_refresh_token(
            raw_refresh_token=payload.refresh_token,
            device_info=req.headers.get("User-Agent", "Unknown"),
            ip_address=client_ip,
        )
        return {
            "success": True,
            "refresh_token": rotated["refresh_token"],
            "session_id": rotated["session_id"],
            "family_id": rotated["family_id"],
            "expires_at": rotated["expires_at"],
            "token_type": "bearer",
        }
    except ConcurrentRefreshConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Concurrent refresh collision detected. No replacement credential disclosed.",
        ) from e
    except SecurityReplayAttackError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security violation: Replay attack detected. Session family revoked.",
        )
    except AccountBlockedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account access unavailable. Sessions revoked.",
        )
    except (SessionNotFoundError, SessionExpiredError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired.",
        ) from e


@router.post("/logout")
async def logout(
    response: Response,
    payload: RefreshTokenSchema | None = Body(default=None),
    pool: asyncpg.Pool = Depends(get_db_pool),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Revokes the ENTIRE active session family (F-05, T13-AC5) so neither the active token
    nor any prior/sibling token in the family can access protected endpoints or refresh.
    """
    _set_no_store(response)
    session_svc = SessionService(pool)

    # 1. Always revoke the bearer token's entire session family
    revoked_count = await session_svc.revoke_session_family(current_user["session_family_id"])

    # 2. If a refresh_token is explicitly provided, verify ownership before revoking its family too
    if payload and payload.refresh_token:
        digest = hash_token(payload.refresh_token)
        async with pool.acquire() as conn:
            tok_row = await conn.fetchrow(
                "SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = $1;",
                digest,
            )
            if tok_row and tok_row["user_id"] == current_user["id"]:
                revoked_count += await session_svc.revoke_session_family(tok_row["family_id"])

    return {
        "success": True,
        "revoked_tokens": revoked_count,
        "message": "نشست و تمامی توکن‌های خانواده نشست با موفقیت باطل شدند.",
    }
