"""
Authentication & Authorization API Endpoints (AUTH-001..017, RBAC-001..009)
REMEDIATION: HC-T13 (F-01..F-05, T13-AC1..AC6), HC-T36 (Cookie Refresh + Short-Lived Access + CSRF)
"""

import hmac
import os
from typing import Any, Dict

import asyncpg
import redis
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.adapters.sms import SmsAdapterError
from src.api.deps import get_current_user, get_db_pool, get_redis
from src.auth.access_tokens import (
    ACCESS_TOKEN_PREFIX,
    AccessTokenConfigurationError,
    InvalidAccessTokenError,
    RevocationStoreUnavailableError,
    generate_csrf_token,
    is_family_revoked_in_redis,
    issue_access_token,
    resolve_access_signing_secret,
    resolve_access_token_ttl,
    verify_access_token,
    verify_csrf_token,
)
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
from src.core.cors import (
    CorsConfigurationError,
    CorsOriginRejectedError,
    validate_cookie_request_origin,
)
from src.core.env import EnvironmentConfigurationError, is_restricted_environment
from src.core.security import hash_token

router = APIRouter(prefix="/auth", tags=["Authentication"])

REFRESH_COOKIE_NAME = "hc_refresh"
CSRF_COOKIE_NAME = "hc_csrf"
SESSION_HINT_COOKIE_NAME = "hc_has_session"
REFRESH_COOKIE_PATH = "/api/v1/auth"
REFRESH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60


class OtpRequestSchema(BaseModel):
    mobile: str = Field(..., example="09121234567")


class OtpVerifySchema(BaseModel):
    mobile: str = Field(..., example="09121234567")
    code: str = Field(..., min_length=6, max_length=6, example="123456")


class PasswordLoginSchema(BaseModel):
    mobile: str = Field(..., example="09121234567")
    password: str = Field(..., example="SecurePassword123")


class RefreshTokenSchema(BaseModel):
    refresh_token: str | None = None


def _set_no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"


def _resolve_cookie_secure(req: Request) -> bool:
    if is_restricted_environment():
        return True
    raw_flag = (os.getenv("COOKIE_SECURE") or "").strip().lower()
    if raw_flag in ("1", "true", "yes", "on"):
        return True
    return req.url.scheme.lower() == "https"


def _set_auth_cookies(
    response: Response,
    req: Request,
    *,
    raw_refresh_token: str,
    csrf_token: str,
) -> None:
    secure = _resolve_cookie_secure(req)
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=raw_refresh_token,
        max_age=REFRESH_COOKIE_MAX_AGE,
        path=REFRESH_COOKIE_PATH,
        secure=secure,
        httponly=True,
        samesite="lax",
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=REFRESH_COOKIE_MAX_AGE,
        path="/",
        secure=secure,
        httponly=False,
        samesite="lax",
    )
    response.set_cookie(
        key=SESSION_HINT_COOKIE_NAME,
        value="1",
        max_age=REFRESH_COOKIE_MAX_AGE,
        path="/",
        secure=secure,
        httponly=False,
        samesite="lax",
    )


def _clear_auth_cookies(response: Response, req: Request) -> None:
    try:
        secure = _resolve_cookie_secure(req)
    except EnvironmentConfigurationError:
        secure = True
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        secure=secure,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        secure=secure,
        httponly=False,
        samesite="lax",
    )
    response.delete_cookie(
        key=SESSION_HINT_COOKIE_NAME,
        path="/",
        secure=secure,
        httponly=False,
        samesite="lax",
    )


def _error_json(
    status_code: int,
    detail: str,
    req: Request,
    *,
    clear_cookies: bool = False,
) -> JSONResponse:
    resp = JSONResponse(status_code=status_code, content={"detail": detail})
    _set_no_store(resp)
    if clear_cookies:
        _clear_auth_cookies(resp, req)
    return resp


def _resolve_auth_mode_header(req: Request) -> str:
    raw_mode = (req.headers.get("x-auth-mode") or "").strip().lower()
    if raw_mode not in ("", "cookie", "bearer"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported X-Auth-Mode header value.",
        )
    return raw_mode


def _resolve_cookie_mode_header(req: Request) -> bool:
    return _resolve_auth_mode_header(req) == "cookie"


def _resolve_using_cookie(req: Request) -> tuple[bool, str | None, str | None]:
    """
    Determines whether `/refresh` or `/logout` runs in cookie mode without letting
    ambient client hint/CSRF cookies (`hc_has_session`, `hc_csrf`) hijack legacy callers (T36-L2).
    """
    auth_mode = _resolve_auth_mode_header(req)
    cookie_refresh = req.cookies.get(REFRESH_COOKIE_NAME)
    cookie_csrf = req.cookies.get(CSRF_COOKIE_NAME)
    if auth_mode == "cookie":
        using_cookie = True
    elif auth_mode == "bearer":
        using_cookie = False
    else:
        using_cookie = cookie_refresh is not None
    return using_cookie, cookie_refresh, cookie_csrf


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
    """Atomically verifies & consumes OTP and issues authenticated session (cookie or legacy mode)."""
    _set_no_store(response)
    cookie_mode = _resolve_cookie_mode_header(req)
    if cookie_mode:
        try:
            resolve_access_signing_secret()
            resolve_access_token_ttl()
        except AccessTokenConfigurationError as exc:
            return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False)
        try:
            validate_cookie_request_origin(req)
        except (CorsOriginRejectedError, CorsConfigurationError, EnvironmentConfigurationError) as exc:
            return _error_json(status.HTTP_403_FORBIDDEN, str(exc), req, clear_cookies=False)

    if not validate_iranian_mobile(payload.mobile):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mobile or verification code.",
        )

    clean_mobile = normalize_iranian_mobile(payload.mobile)
    try:
        auth_svc = AuthService(pool, r)
    except (SmsDeliveryError, SmsAdapterError) as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        res = await auth_svc.authenticate_via_otp(
            raw_mobile=clean_mobile,
            otp_code=payload.code,
            device_info=req.headers.get("User-Agent", "Unknown Device"),
            ip_address=client_ip,
        )
    except OtpRateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except (OtpExpiredOrInvalidError, OtpMaxAttemptsExceededError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AccountBlockedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication unavailable for this account.",
        ) from e

    if not cookie_mode:
        return res

    session = res["session"]
    try:
        access_token, expires_in, access_expires_at = issue_access_token(
            user_id=res["user_id"],
            family_id=session["family_id"],
            session_id=session["session_id"],
        )
        csrf_token = generate_csrf_token(session["family_id"])
        _set_auth_cookies(
            response,
            req,
            raw_refresh_token=session["refresh_token"],
            csrf_token=csrf_token,
        )
    except AccessTokenConfigurationError as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=True)
    except EnvironmentConfigurationError as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=True)

    return {
        "success": True,
        "auth_mode": "cookie",
        "user_id": res["user_id"],
        "mobile": res["mobile"],
        "is_new_user": res["is_new_user"],
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "access_expires_at": access_expires_at,
        "expires_at": session["expires_at"],
        "session_id": session["session_id"],
        "family_id": session["family_id"],
    }


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
    cookie_mode = _resolve_cookie_mode_header(req)
    if cookie_mode:
        try:
            resolve_access_signing_secret()
            resolve_access_token_ttl()
        except AccessTokenConfigurationError as exc:
            return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False)
        try:
            validate_cookie_request_origin(req)
        except (CorsOriginRejectedError, CorsConfigurationError, EnvironmentConfigurationError) as exc:
            return _error_json(status.HTTP_403_FORBIDDEN, str(exc), req, clear_cookies=False)

    if not validate_iranian_mobile(payload.mobile):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or authentication unavailable.",
        )

    clean_mobile = normalize_iranian_mobile(payload.mobile)
    try:
        auth_svc = AuthService(pool, r)
    except (SmsDeliveryError, SmsAdapterError) as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False)
    client_ip = req.client.host if req.client else "127.0.0.1"

    try:
        res = await auth_svc.authenticate_via_password(
            raw_mobile=clean_mobile,
            plain_password=payload.password,
            device_info=req.headers.get("User-Agent", "Unknown Device"),
            ip_address=client_ip,
        )
    except (InvalidCredentialsError, AccountBlockedError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or authentication unavailable.",
        )

    if not cookie_mode:
        return res

    session = res["session"]
    try:
        access_token, expires_in, access_expires_at = issue_access_token(
            user_id=res["user_id"],
            family_id=session["family_id"],
            session_id=session["session_id"],
        )
        csrf_token = generate_csrf_token(session["family_id"])
        _set_auth_cookies(
            response,
            req,
            raw_refresh_token=session["refresh_token"],
            csrf_token=csrf_token,
        )
    except (AccessTokenConfigurationError, EnvironmentConfigurationError) as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=True)

    return {
        "success": True,
        "auth_mode": "cookie",
        "user_id": res["user_id"],
        "mobile": res["mobile"],
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "access_expires_at": access_expires_at,
        "expires_at": session["expires_at"],
        "session_id": session["session_id"],
        "family_id": session["family_id"],
    }


@router.post("/refresh")
async def refresh_session(
    req: Request,
    response: Response,
    payload: RefreshTokenSchema | None = Body(default=None),
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis),
):
    """
    Rotates refresh token under concurrent race protection (AC-15, F-01, T13-AC4).
    Supports BOTH `HttpOnly` cookie transport + CSRF/Origin verification (HC-T36)
    and legacy JSON body transport (`RefreshTokenSchema`).
    Competing concurrent callers receive HTTP 409 Conflict WITHOUT credential disclosure.
    """
    _set_no_store(response)
    using_cookie, cookie_refresh, cookie_csrf = _resolve_using_cookie(req)

    session_svc = SessionService(pool, redis_client=r)
    client_ip = req.client.host if req.client else "127.0.0.1"

    if using_cookie:
        # 1. Fail-closed Origin/Referer barrier before any session state inspection
        try:
            validate_cookie_request_origin(req)
        except (CorsOriginRejectedError, CorsConfigurationError, EnvironmentConfigurationError) as exc:
            return _error_json(status.HTTP_403_FORBIDDEN, str(exc), req, clear_cookies=False)

        # 2. Fail-closed Double-Submit CSRF header vs cookie check
        header_csrf = req.headers.get("x-csrf-token")
        if (
            not cookie_csrf
            or not header_csrf
            or "." not in header_csrf
            or not hmac.compare_digest(cookie_csrf, header_csrf)
        ):
            return _error_json(
                status.HTTP_403_FORBIDDEN,
                "Missing or invalid X-CSRF-Token.",
                req,
                clear_cookies=False,
            )

        # 2b. Fail-closed signing configuration check BEFORE mutating token family in PostgreSQL
        try:
            resolve_access_signing_secret()
            resolve_access_token_ttl()
        except (AccessTokenConfigurationError, EnvironmentConfigurationError) as exc:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
            )

        if payload and payload.refresh_token:
            return _error_json(
                status.HTTP_400_BAD_REQUEST,
                "Refresh token body field is forbidden under cookie authentication mode.",
                req,
                clear_cookies=False,
            )

        if not cookie_refresh:
            return _error_json(
                status.HTTP_401_UNAUTHORIZED,
                "Session refresh cookie is missing or expired.",
                req,
                clear_cookies=True,
            )

        # 3. Read-only lookup to verify CSRF HMAC signature bound to target session family BEFORE rotation
        meta = await session_svc.get_refresh_token_meta(cookie_refresh)
        if meta is not None and not verify_csrf_token(header_csrf, meta["family_id"]):
            return _error_json(
                status.HTTP_403_FORBIDDEN,
                "CSRF token verification failed for session.",
                req,
                clear_cookies=False,
            )

        # 4. Fail-closed Redis revocation pre-check before issuing new short-lived access token
        if meta is not None:
            try:
                if is_family_revoked_in_redis(r, meta["family_id"]):
                    return _error_json(
                        status.HTTP_401_UNAUTHORIZED,
                        "Session family has been revoked.",
                        req,
                        clear_cookies=True,
                    )
            except RevocationStoreUnavailableError as exc:
                return _error_json(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    str(exc),
                    req,
                    clear_cookies=False,
                )

        try:
            rotated = await session_svc.rotate_refresh_token(
                raw_refresh_token=cookie_refresh,
                device_info=req.headers.get("User-Agent", "Unknown"),
                ip_address=client_ip,
            )
            access_token, expires_in, access_expires_at = issue_access_token(
                user_id=rotated.get("user_id") or meta["user_id"],
                family_id=rotated["family_id"],
                session_id=rotated["session_id"],
            )
            new_csrf = generate_csrf_token(rotated["family_id"])
            _set_auth_cookies(
                response,
                req,
                raw_refresh_token=rotated["refresh_token"],
                csrf_token=new_csrf,
            )
            return {
                "success": True,
                "auth_mode": "cookie",
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": expires_in,
                "access_expires_at": access_expires_at,
                "expires_at": rotated["expires_at"],
                "session_id": rotated["session_id"],
                "family_id": rotated["family_id"],
            }
        except ConcurrentRefreshConflictError:
            # CRITICAL (AC-15): never clear sibling valid cookies or disclose successor on 409 conflict
            return _error_json(
                status.HTTP_409_CONFLICT,
                "Concurrent refresh collision detected. No replacement credential disclosed.",
                req,
                clear_cookies=False,
            )
        except SecurityReplayAttackError:
            return _error_json(
                status.HTTP_401_UNAUTHORIZED,
                "Security violation: Replay attack detected. Session family revoked.",
                req,
                clear_cookies=True,
            )
        except AccountBlockedError:
            return _error_json(
                status.HTTP_403_FORBIDDEN,
                "Account access unavailable. Sessions revoked.",
                req,
                clear_cookies=True,
            )
        except (SessionNotFoundError, SessionExpiredError):
            return _error_json(
                status.HTTP_401_UNAUTHORIZED,
                "Session invalid or expired.",
                req,
                clear_cookies=True,
            )
        except (
            RevocationStoreUnavailableError,
            AccessTokenConfigurationError,
            EnvironmentConfigurationError,
        ) as exc:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(exc),
                req,
                clear_cookies=False,
            )

    # Legacy JSON body mode preserved for existing API callers & T13..T30 regression tests
    if not payload or not payload.refresh_token:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="refresh_token is required.",
        )

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
    except RevocationStoreUnavailableError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        ) from e


async def _revoke_families_fail_closed(
    session_svc: SessionService,
    family_ids: list[Any],
) -> tuple[int, RevocationStoreUnavailableError | None]:
    """
    Revokes every distinct target family in PostgreSQL SSOT even if Redis revocation store errors
    mid-batch, and returns any first RevocationStoreUnavailableError for fail-closed HTTP 503.
    """
    revoked_count = 0
    first_err: RevocationStoreUnavailableError | None = None
    seen: set[Any] = set()
    for fid in family_ids:
        if fid is None or fid in seen:
            continue
        seen.add(fid)
        try:
            revoked_count += await session_svc.revoke_session_family(fid, reason="LOGOUT")
        except RevocationStoreUnavailableError as exc:
            if first_err is None:
                first_err = exc
    return revoked_count, first_err


@router.post("/logout")
async def logout(
    req: Request,
    response: Response,
    payload: RefreshTokenSchema | None = Body(default=None),
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis),
):
    """
    Revokes the ENTIRE active session family (F-05, T13-AC5) in PostgreSQL and publishes a
    fail-closed revocation entry in Redis so even valid short-lived access tokens are immediately
    rejected (AC-14). Supports cookie + CSRF mode and legacy Bearer token mode.
    """
    _set_no_store(response)
    using_cookie, cookie_refresh, cookie_csrf = _resolve_using_cookie(req)

    session_svc = SessionService(pool, redis_client=r)
    auth_header = req.headers.get("authorization")

    if using_cookie:
        try:
            validate_cookie_request_origin(req)
        except (CorsOriginRejectedError, CorsConfigurationError, EnvironmentConfigurationError) as exc:
            return _error_json(status.HTTP_403_FORBIDDEN, str(exc), req, clear_cookies=False)

        header_csrf = req.headers.get("x-csrf-token")
        if (
            not cookie_csrf
            or not header_csrf
            or "." not in header_csrf
            or not hmac.compare_digest(cookie_csrf, header_csrf)
        ):
            return _error_json(
                status.HTTP_403_FORBIDDEN,
                "Missing or invalid X-CSRF-Token.",
                req,
                clear_cookies=False,
            )

        # Fail-closed signing configuration check BEFORE verifying HMAC CSRF or mutating state (T36-L3)
        try:
            resolve_access_signing_secret()
            resolve_access_token_ttl()
        except (AccessTokenConfigurationError, EnvironmentConfigurationError) as exc:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
            )

        target_family_id = None
        actor_user_id = None
        bearer_claims = None

        if auth_header and auth_header.lower().startswith("bearer "):
            raw_bearer = auth_header.split(" ", 1)[1].strip()
            if raw_bearer.startswith(f"{ACCESS_TOKEN_PREFIX}."):
                try:
                    bearer_claims = verify_access_token(raw_bearer, allow_expired=True)
                except AccessTokenConfigurationError as exc:
                    return _error_json(
                        status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
                    )
                except InvalidAccessTokenError:
                    pass

        meta = await session_svc.get_refresh_token_meta(cookie_refresh) if cookie_refresh else None
        if meta is not None:
            target_family_id = meta["family_id"]
            actor_user_id = meta["user_id"]
            if bearer_claims is not None and bearer_claims["user_id"] != meta["user_id"]:
                return _error_json(
                    status.HTTP_403_FORBIDDEN,
                    "Access credential and session cookie owner mismatch.",
                    req,
                    clear_cookies=False,
                )
        elif bearer_claims is not None:
            target_family_id = bearer_claims["family_id"]
            actor_user_id = bearer_claims["user_id"]

        if target_family_id is None:
            return _error_json(
                status.HTTP_401_UNAUTHORIZED,
                "Session invalid or expired.",
                req,
                clear_cookies=True,
            )

        if not verify_csrf_token(header_csrf, target_family_id):
            return _error_json(
                status.HTTP_403_FORBIDDEN,
                "CSRF token verification failed for session.",
                req,
                clear_cookies=False,
            )

        families_to_revoke = [target_family_id]
        if (
            bearer_claims is not None
            and bearer_claims["family_id"] != target_family_id
            and bearer_claims["user_id"] == actor_user_id
        ):
            families_to_revoke.append(bearer_claims["family_id"])

        revoked_count, revocation_err = await _revoke_families_fail_closed(
            session_svc, families_to_revoke
        )
        if revocation_err is not None:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(revocation_err),
                req,
                clear_cookies=True,
            )

        _clear_auth_cookies(response, req)
        return {
            "success": True,
            "auth_mode": "cookie",
            "revoked_tokens": revoked_count,
            "message": "نشست و تمامی توکن‌های خانواده نشست با موفقیت باطل شدند.",
        }

    # Legacy Bearer mode preserved for existing API callers
    try:
        current_user: Dict[str, Any] = await get_current_user(
            response=response,
            authorization=auth_header,
            pool=pool,
            r=r,
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(exc.detail),
                req,
                clear_cookies=False,
            )
        raise

    legacy_families = [current_user["session_family_id"]]
    if payload and payload.refresh_token:
        digest = hash_token(payload.refresh_token)
        async with pool.acquire() as conn:
            tok_row = await conn.fetchrow(
                "SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = $1;",
                digest,
            )
            if tok_row and tok_row["user_id"] == current_user["id"]:
                legacy_families.append(tok_row["family_id"])

    revoked_count, revocation_err = await _revoke_families_fail_closed(
        session_svc, legacy_families
    )
    if revocation_err is not None:
        return _error_json(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            str(revocation_err),
            req,
            clear_cookies=False,
        )

    return {
        "success": True,
        "revoked_tokens": revoked_count,
        "message": "نشست و تمامی توکن‌های خانواده نشست با موفقیت باطل شدند.",
    }
