"""
Authentication & Authorization API Endpoints (AUTH-001..017, RBAC-001..009)
REMEDIATION: HC-T13 (F-01..F-05, T13-AC1..AC6), HC-T36 (Cookie Refresh + Short-Lived Access + CSRF)
"""

import hashlib
import hmac
import os
import re
import uuid
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
from src.auth.rbac import RbacAccessDeniedError, RbacEngine
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
    attempt_id: str | None = Field(default=None, max_length=96)
    started_server_logout_seq: int | None = Field(default=None, ge=0)


class PasswordLoginSchema(BaseModel):
    mobile: str = Field(..., example="09121234567")
    password: str = Field(..., example="SecurePassword123")
    attempt_id: str | None = Field(default=None, max_length=96)
    started_server_logout_seq: int | None = Field(default=None, ge=0)


class RefreshTokenSchema(BaseModel):
    refresh_token: str | None = None
    cancelled_login_attempt_ids: list[str] | None = Field(default=None, max_length=16)


class CancelLoginAttemptsSchema(BaseModel):
    attempt_ids: list[str] = Field(..., min_length=1, max_length=16)


BROWSER_COORD_COOKIE_NAME = "hc_browser"
BROWSER_GLOBAL_SEQ_REDIS_PREFIX = "hc:browser_global_seq:"
BROWSER_LOGOUT_SEQ_REDIS_PREFIX = "hc:browser_logout_seq:"
BROWSER_LOGIN_SEQ_REDIS_PREFIX = "hc:browser_login_seq:"
BROWSER_RECENT_FAMILIES_REDIS_PREFIX = "hc:browser_recent_families:"
BROWSER_COORD_TTL_SECONDS = REFRESH_COOKIE_MAX_AGE
CANCELLED_LOGIN_ATTEMPT_REDIS_PREFIX = "hc:cancelled_login_attempt:"
LOGIN_ATTEMPT_FAMILY_REDIS_PREFIX = "hc:login_attempt_family:"
LOGIN_ATTEMPT_TTL_SECONDS = 600
UNAUTH_CANCELLED_ATTEMPT_TTL_SECONDS = 120
CANCEL_RL_WINDOW_SECONDS = 60
CANCEL_RL_IP_REQ_UNAUTH = 20
CANCEL_RL_IP_REQ_VERIFIED = 60
CANCEL_RL_IP_IDS_UNAUTH = 64
CANCEL_RL_IP_IDS_VERIFIED = 192
CANCEL_RL_GLOBAL_REQ = 600
CANCEL_RL_GLOBAL_IDS = 2400
COORD_RL_IP_REQ = 240
COORD_RL_GLOBAL_REQ = 3000
_ATTEMPT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,96}$")
_BROWSER_ID_RE = re.compile(r"^b_[0-9a-f]{32}$")


def _sanitize_attempt_id(raw: str | None) -> str | None:
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned or not _ATTEMPT_ID_RE.match(cleaned):
        return None
    return cleaned


def _sanitize_attempt_id_list(raw_list: list[str] | None) -> list[str]:
    if not raw_list:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw_list:
        aid = _sanitize_attempt_id(item)
        if aid and aid not in seen:
            seen.add(aid)
            out.append(aid)
    return out


def _is_login_attempt_cancelled(r: redis.Redis, attempt_id: str | None) -> bool:
    if not attempt_id:
        return False
    try:
        return bool(r.get(f"{CANCELLED_LOGIN_ATTEMPT_REDIS_PREFIX}{attempt_id}"))
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Authentication coordination store unavailable; fail-closed rejection."
        ) from exc


def _record_login_attempt_family(r: redis.Redis, attempt_id: str | None, family_id: Any) -> None:
    if not attempt_id or not family_id:
        return
    try:
        r.set(
            f"{LOGIN_ATTEMPT_FAMILY_REDIS_PREFIX}{attempt_id}",
            str(family_id),
            ex=LOGIN_ATTEMPT_TTL_SECONDS,
        )
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Authentication coordination store unavailable while binding login attempt."
        ) from exc


def _decode_redis_int(raw_val: Any) -> int:
    if raw_val is None:
        return 0
    try:
        s = raw_val.decode("utf-8") if isinstance(raw_val, bytes) else str(raw_val)
        return max(0, int(s))
    except (ValueError, TypeError):
        return 0


def _sign_browser_id(bid: str) -> str:
    secret = resolve_access_signing_secret()
    secret_bytes = secret if isinstance(secret, bytes) else secret.encode()
    sig = hmac.new(
        secret_bytes,
        f"hc_browser:{bid}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{bid}.{sig}"


def _verify_browser_id_cookie(raw_val: str | None) -> str | None:
    if not raw_val or "." not in raw_val:
        return None
    bid, provided_sig = raw_val.split(".", 1)
    if not _BROWSER_ID_RE.match(bid) or not provided_sig:
        return None
    try:
        expected = _sign_browser_id(bid)
    except (AccessTokenConfigurationError, EnvironmentConfigurationError):
        return None
    expected_sig = expected.split(".", 1)[1]
    if hmac.compare_digest(provided_sig, expected_sig):
        return bid
    return None


def _set_browser_coord_cookie(response: Response, req: Request, bid: str) -> None:
    try:
        secure = _resolve_cookie_secure(req)
    except EnvironmentConfigurationError:
        secure = True
    response.set_cookie(
        key=BROWSER_COORD_COOKIE_NAME,
        value=_sign_browser_id(bid),
        max_age=BROWSER_COORD_TTL_SECONDS,
        path=REFRESH_COOKIE_PATH,
        secure=secure,
        httponly=True,
        samesite="lax",
    )


def _ensure_browser_id(req: Request, response: Response) -> str:
    existing = _verify_browser_id_cookie(req.cookies.get(BROWSER_COORD_COOKIE_NAME))
    if existing:
        return existing
    bid = f"b_{uuid.uuid4().hex}"
    _set_browser_coord_cookie(response, req, bid)
    return bid


def _get_browser_coord_state(r: redis.Redis, bid: str | None) -> dict[str, int]:
    if not bid:
        return {"global_seq": 0, "logout_seq": 0, "login_seq": 0}
    try:
        g_raw = r.get(f"{BROWSER_GLOBAL_SEQ_REDIS_PREFIX}{bid}")
        lo_raw = r.get(f"{BROWSER_LOGOUT_SEQ_REDIS_PREFIX}{bid}")
        li_raw = r.get(f"{BROWSER_LOGIN_SEQ_REDIS_PREFIX}{bid}")
        return {
            "global_seq": _decode_redis_int(g_raw),
            "logout_seq": _decode_redis_int(lo_raw),
            "login_seq": _decode_redis_int(li_raw),
        }
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Authentication coordination store unavailable while reading browser generation."
        ) from exc


def _record_browser_recent_family(r: redis.Redis, bid: str | None, family_id: Any) -> None:
    if not bid or not family_id:
        return
    try:
        if not hasattr(r, "sadd"):
            r.set(f"{BROWSER_RECENT_FAMILIES_REDIS_PREFIX}{bid}", str(family_id), ex=LOGIN_ATTEMPT_TTL_SECONDS)
            return
        key = f"{BROWSER_RECENT_FAMILIES_REDIS_PREFIX}{bid}"
        r.sadd(key, str(family_id))
        if hasattr(r, "expire"):
            r.expire(key, LOGIN_ATTEMPT_TTL_SECONDS)
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Authentication coordination store unavailable while tracking browser login family."
        ) from exc


def _bump_browser_login_coord(r: redis.Redis, bid: str | None) -> dict[str, int]:
    if not bid:
        return {"global_seq": 0, "logout_seq": 0, "login_seq": 0}
    try:
        g_key = f"{BROWSER_GLOBAL_SEQ_REDIS_PREFIX}{bid}"
        li_key = f"{BROWSER_LOGIN_SEQ_REDIS_PREFIX}{bid}"
        lo_key = f"{BROWSER_LOGOUT_SEQ_REDIS_PREFIX}{bid}"
        if not hasattr(r, "incr"):
            r.set(li_key, "1", ex=BROWSER_COORD_TTL_SECONDS)
            return {"global_seq": 1, "logout_seq": 0, "login_seq": 1}
        new_seq = int(r.incr(g_key))
        if hasattr(r, "expire"):
            r.expire(g_key, BROWSER_COORD_TTL_SECONDS)
        r.set(li_key, str(new_seq), ex=BROWSER_COORD_TTL_SECONDS)
        lo_seq = _decode_redis_int(r.get(lo_key))
        return {
            "global_seq": new_seq,
            "logout_seq": lo_seq,
            "login_seq": new_seq,
        }
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Authentication coordination store unavailable while advancing browser login generation."
        ) from exc


def _bump_browser_logout_and_pop_families(
    r: redis.Redis, bid: str | None
) -> tuple[dict[str, int], list[uuid.UUID]]:
    if not bid:
        return {"global_seq": 0, "logout_seq": 0, "login_seq": 0}, []
    discovered: list[uuid.UUID] = []
    try:
        g_key = f"{BROWSER_GLOBAL_SEQ_REDIS_PREFIX}{bid}"
        lo_key = f"{BROWSER_LOGOUT_SEQ_REDIS_PREFIX}{bid}"
        li_key = f"{BROWSER_LOGIN_SEQ_REDIS_PREFIX}{bid}"
        fam_key = f"{BROWSER_RECENT_FAMILIES_REDIS_PREFIX}{bid}"
        if not hasattr(r, "incr"):
            r.set(lo_key, "1", ex=BROWSER_COORD_TTL_SECONDS)
            return {"global_seq": 1, "logout_seq": 1, "login_seq": 0}, []
        new_seq = int(r.incr(g_key))
        if hasattr(r, "expire"):
            r.expire(g_key, BROWSER_COORD_TTL_SECONDS)
        r.set(lo_key, str(new_seq), ex=BROWSER_COORD_TTL_SECONDS)
        li_seq = _decode_redis_int(r.get(li_key))
        if hasattr(r, "smembers"):
            raw_members = r.smembers(fam_key) or ()
            if raw_members and hasattr(r, "delete"):
                r.delete(fam_key)
            for m in raw_members:
                ms = m.decode("utf-8") if isinstance(m, bytes) else str(m)
                try:
                    discovered.append(uuid.UUID(ms))
                except ValueError:
                    pass
        return {"global_seq": new_seq, "logout_seq": new_seq, "login_seq": li_seq}, discovered
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Redis revocation store unavailable while advancing browser logout generation."
        ) from exc


def _enforce_sliding_quota(
    r: redis.Redis,
    *,
    key: str,
    amount: int,
    limit: int,
    window_seconds: int = CANCEL_RL_WINDOW_SECONDS,
) -> bool:
    try:
        if not hasattr(r, "incrby"):
            return True
        new_val = int(r.incrby(key, amount))
        if new_val <= amount and hasattr(r, "expire"):
            r.expire(key, window_seconds)
        return new_val <= limit
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Redis rate-limit store unavailable; fail-closed rejection."
        ) from exc


def _mark_login_attempts_cancelled(
    r: redis.Redis,
    attempt_ids: list[str],
    *,
    ttl_seconds: int = LOGIN_ATTEMPT_TTL_SECONDS,
) -> list[uuid.UUID]:
    discovered_families: list[uuid.UUID] = []
    if not attempt_ids:
        return discovered_families
    try:
        for aid in attempt_ids:
            r.set(
                f"{CANCELLED_LOGIN_ATTEMPT_REDIS_PREFIX}{aid}",
                "1",
                ex=ttl_seconds,
            )
            fid_raw = r.get(f"{LOGIN_ATTEMPT_FAMILY_REDIS_PREFIX}{aid}")
            if fid_raw:
                fid_str = fid_raw.decode("utf-8") if isinstance(fid_raw, bytes) else str(fid_raw)
                try:
                    discovered_families.append(uuid.UUID(fid_str))
                except ValueError:
                    pass
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            "Redis revocation store unavailable while cancelling pending login attempts."
        ) from exc
    return discovered_families


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


@router.post("/coord/session")
async def init_browser_coord_session(
    req: Request,
    response: Response,
    r: redis.Redis = Depends(get_redis),
):
    """
    Issues/reads an HttpOnly HMAC-signed browser coordination cookie (`hc_browser`) and
    returns the server-authoritative monotonic coordination sequences (`global_seq`,
    `logout_seq`, `login_seq`). Never grants authentication or reveals credentials.
    """
    _set_no_store(response)
    try:
        resolve_access_signing_secret()
    except (AccessTokenConfigurationError, EnvironmentConfigurationError) as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False)

    try:
        validate_cookie_request_origin(req)
    except (CorsOriginRejectedError, CorsConfigurationError, EnvironmentConfigurationError) as exc:
        return _error_json(status.HTTP_403_FORBIDDEN, str(exc), req, clear_cookies=False)

    client_ip = req.client.host if req.client else "127.0.0.1"
    try:
        ip_ok = _enforce_sliding_quota(
            r,
            key=f"hc:rl:coord:ip:{client_ip}",
            amount=1,
            limit=COORD_RL_IP_REQ,
        )
        global_ok = _enforce_sliding_quota(
            r,
            key="hc:rl:coord:global",
            amount=1,
            limit=COORD_RL_GLOBAL_REQ,
        )
    except RevocationStoreUnavailableError as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False)

    if not ip_ok or not global_ok:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many coordination requests. Please retry later.",
            headers={"Retry-After": str(CANCEL_RL_WINDOW_SECONDS)},
        )

    bid = _ensure_browser_id(req, response)
    try:
        coord = _get_browser_coord_state(r, bid)
    except RevocationStoreUnavailableError as exc:
        return _error_json(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False)

    return {
        "success": True,
        "coord": coord,
    }


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
    attempt_id = _sanitize_attempt_id(payload.attempt_id)
    browser_id: str | None = None
    pre_auth_logout_seq = 0
    if cookie_mode:
        browser_id = _ensure_browser_id(req, response)
        try:
            pre_coord = _get_browser_coord_state(r, browser_id)
            pre_auth_logout_seq = pre_coord["logout_seq"]
            if (
                payload.started_server_logout_seq is not None
                and pre_auth_logout_seq > payload.started_server_logout_seq
            ):
                return _error_json(
                    status.HTTP_409_CONFLICT,
                    "Login attempt was superseded by logout.",
                    req,
                    clear_cookies=False,
                )
        except RevocationStoreUnavailableError as exc:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
            )

    if attempt_id:
        try:
            if _is_login_attempt_cancelled(r, attempt_id):
                return _error_json(
                    status.HTTP_409_CONFLICT,
                    "Login attempt was superseded by logout.",
                    req,
                    clear_cookies=False,
                )
        except RevocationStoreUnavailableError as exc:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
            )

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

    session = res["session"]
    if attempt_id or (cookie_mode and browser_id):
        try:
            _record_login_attempt_family(r, attempt_id, session["family_id"])
            if cookie_mode and browser_id:
                _record_browser_recent_family(r, browser_id, session["family_id"])
            superseded = _is_login_attempt_cancelled(r, attempt_id)
            if not superseded and cookie_mode and browser_id:
                post_coord = _get_browser_coord_state(r, browser_id)
                if post_coord["logout_seq"] > pre_auth_logout_seq:
                    superseded = True
        except RevocationStoreUnavailableError as exc:
            try:
                await SessionService(pool, redis_client=r).revoke_session_family(
                    uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
                )
            except Exception:
                pass
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(exc),
                req,
                clear_cookies=False,
            )
        if superseded:
            try:
                await SessionService(pool, redis_client=r).revoke_session_family(
                    uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
                )
            except RevocationStoreUnavailableError as exc:
                return _error_json(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    str(exc),
                    req,
                    clear_cookies=False,
                )
            return _error_json(
                status.HTTP_409_CONFLICT,
                "Login attempt was superseded by logout.",
                req,
                clear_cookies=False,
            )

    if not cookie_mode:
        return res
    try:
        auth_coord = _bump_browser_login_coord(r, browser_id)
    except RevocationStoreUnavailableError as exc:
        try:
            await SessionService(pool, redis_client=r).revoke_session_family(
                uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
            )
        except Exception:
            pass
        return _error_json(
            status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
        )
    if auth_coord["logout_seq"] > pre_auth_logout_seq:
        try:
            await SessionService(pool, redis_client=r).revoke_session_family(
                uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
            )
        except RevocationStoreUnavailableError:
            pass
        return _error_json(
            status.HTTP_409_CONFLICT,
            "Login attempt was superseded by logout.",
            req,
            clear_cookies=False,
        )
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
        "auth_coord": auth_coord,
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
    attempt_id = _sanitize_attempt_id(payload.attempt_id)
    browser_id: str | None = None
    pre_auth_logout_seq = 0
    if cookie_mode:
        browser_id = _ensure_browser_id(req, response)
        try:
            pre_coord = _get_browser_coord_state(r, browser_id)
            pre_auth_logout_seq = pre_coord["logout_seq"]
            if (
                payload.started_server_logout_seq is not None
                and pre_auth_logout_seq > payload.started_server_logout_seq
            ):
                return _error_json(
                    status.HTTP_409_CONFLICT,
                    "Login attempt was superseded by logout.",
                    req,
                    clear_cookies=False,
                )
        except RevocationStoreUnavailableError as exc:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
            )

    if attempt_id:
        try:
            if _is_login_attempt_cancelled(r, attempt_id):
                return _error_json(
                    status.HTTP_409_CONFLICT,
                    "Login attempt was superseded by logout.",
                    req,
                    clear_cookies=False,
                )
        except RevocationStoreUnavailableError as exc:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
            )

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

    session = res["session"]
    if attempt_id or (cookie_mode and browser_id):
        try:
            _record_login_attempt_family(r, attempt_id, session["family_id"])
            if cookie_mode and browser_id:
                _record_browser_recent_family(r, browser_id, session["family_id"])
            superseded = _is_login_attempt_cancelled(r, attempt_id)
            if not superseded and cookie_mode and browser_id:
                post_coord = _get_browser_coord_state(r, browser_id)
                if post_coord["logout_seq"] > pre_auth_logout_seq:
                    superseded = True
        except RevocationStoreUnavailableError as exc:
            try:
                await SessionService(pool, redis_client=r).revoke_session_family(
                    uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
                )
            except Exception:
                pass
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(exc),
                req,
                clear_cookies=False,
            )
        if superseded:
            try:
                await SessionService(pool, redis_client=r).revoke_session_family(
                    uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
                )
            except RevocationStoreUnavailableError as exc:
                return _error_json(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    str(exc),
                    req,
                    clear_cookies=False,
                )
            return _error_json(
                status.HTTP_409_CONFLICT,
                "Login attempt was superseded by logout.",
                req,
                clear_cookies=False,
            )

    if not cookie_mode:
        return res
    try:
        auth_coord = _bump_browser_login_coord(r, browser_id)
    except RevocationStoreUnavailableError as exc:
        try:
            await SessionService(pool, redis_client=r).revoke_session_family(
                uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
            )
        except Exception:
            pass
        return _error_json(
            status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), req, clear_cookies=False
        )
    if auth_coord["logout_seq"] > pre_auth_logout_seq:
        try:
            await SessionService(pool, redis_client=r).revoke_session_family(
                uuid.UUID(str(session["family_id"])), reason="LOGOUT_SUPERSEDED"
            )
        except RevocationStoreUnavailableError:
            pass
        return _error_json(
            status.HTTP_409_CONFLICT,
            "Login attempt was superseded by logout.",
            req,
            clear_cookies=False,
        )
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
        "auth_coord": auth_coord,
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

        cancelled_attempt_ids = _sanitize_attempt_id_list(
            payload.cancelled_login_attempt_ids if payload else None
        )
        attempt_cancel_err: RevocationStoreUnavailableError | None = None
        if cancelled_attempt_ids:
            try:
                families_to_revoke.extend(_mark_login_attempts_cancelled(r, cancelled_attempt_ids))
            except RevocationStoreUnavailableError as exc:
                attempt_cancel_err = exc

        browser_id = _verify_browser_id_cookie(req.cookies.get(BROWSER_COORD_COOKIE_NAME))
        logout_coord: dict[str, int] = {"global_seq": 0, "logout_seq": 0, "login_seq": 0}
        browser_coord_err: RevocationStoreUnavailableError | None = None
        if browser_id:
            try:
                logout_coord, browser_recent_families = _bump_browser_logout_and_pop_families(
                    r, browser_id
                )
                families_to_revoke.extend(browser_recent_families)
            except RevocationStoreUnavailableError as exc:
                browser_coord_err = exc

        revoked_count, revocation_err = await _revoke_families_fail_closed(
            session_svc, families_to_revoke
        )
        effective_revocation_err = revocation_err or attempt_cancel_err or browser_coord_err
        if effective_revocation_err is not None:
            return _error_json(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(effective_revocation_err),
                req,
                clear_cookies=True,
            )

        _clear_auth_cookies(response, req)
        return {
            "success": True,
            "auth_mode": "cookie",
            "revoked_tokens": revoked_count,
            "cancelled_attempt_count": len(cancelled_attempt_ids),
            "auth_coord": logout_coord,
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

    cancelled_attempt_ids = _sanitize_attempt_id_list(
        payload.cancelled_login_attempt_ids if payload else None
    )
    attempt_cancel_err: RevocationStoreUnavailableError | None = None
    if cancelled_attempt_ids:
        try:
            legacy_families.extend(_mark_login_attempts_cancelled(r, cancelled_attempt_ids))
        except RevocationStoreUnavailableError as exc:
            attempt_cancel_err = exc

    revoked_count, revocation_err = await _revoke_families_fail_closed(
        session_svc, legacy_families
    )
    effective_revocation_err = revocation_err or attempt_cancel_err
    if effective_revocation_err is not None:
        return _error_json(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            str(effective_revocation_err),
            req,
            clear_cookies=False,
        )

    return {
        "success": True,
        "revoked_tokens": revoked_count,
        "cancelled_attempt_count": len(cancelled_attempt_ids),
        "message": "نشست و تمامی توکن‌های خانواده نشست با موفقیت باطل شدند.",
    }


@router.post("/login-attempts/cancel")
async def cancel_login_attempts(
    payload: CancelLoginAttemptsSchema,
    req: Request,
    response: Response,
    pool: asyncpg.Pool = Depends(get_db_pool),
    r: redis.Redis = Depends(get_redis),
):
    """
    Fail-closed cancellation barrier for in-flight OTP/password login attempts superseded by
    concurrent logout (HC-T49). Enforces per-IP + global rate limiting and Redis key-creation
    quotas, marks attempt_ids cancelled in Redis, bumps verified browser logout generation,
    and revokes any session family already recorded in PostgreSQL + Redis.
    """
    _set_no_store(response)
    try:
        validate_cookie_request_origin(req)
    except (CorsOriginRejectedError, CorsConfigurationError, EnvironmentConfigurationError) as exc:
        return _error_json(status.HTTP_403_FORBIDDEN, str(exc), req, clear_cookies=False)

    attempt_ids = _sanitize_attempt_id_list(payload.attempt_ids)
    if not attempt_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one valid attempt_id is required.",
        )

    browser_id = _verify_browser_id_cookie(req.cookies.get(BROWSER_COORD_COOKIE_NAME))
    auth_header = req.headers.get("authorization") or ""
    has_bearer_or_refresh = bool(req.cookies.get(REFRESH_COOKIE_NAME)) or auth_header.lower().startswith("bearer ")
    is_verified_context = bool(browser_id or has_bearer_or_refresh)

    client_ip = req.client.host if req.client else "127.0.0.1"
    ip_req_limit = CANCEL_RL_IP_REQ_VERIFIED if is_verified_context else CANCEL_RL_IP_REQ_UNAUTH
    ip_id_limit = CANCEL_RL_IP_IDS_VERIFIED if is_verified_context else CANCEL_RL_IP_IDS_UNAUTH
    cancel_ttl = LOGIN_ATTEMPT_TTL_SECONDS if is_verified_context else UNAUTH_CANCELLED_ATTEMPT_TTL_SECONDS

    try:
        ip_req_ok = _enforce_sliding_quota(
            r,
            key=f"hc:rl:cancel_req:ip:{client_ip}",
            amount=1,
            limit=ip_req_limit,
        )
        ip_ids_ok = _enforce_sliding_quota(
            r,
            key=f"hc:rl:cancel_ids:ip:{client_ip}",
            amount=len(attempt_ids),
            limit=ip_id_limit,
        )
        global_req_ok = _enforce_sliding_quota(
            r,
            key="hc:rl:cancel_req:global",
            amount=1,
            limit=CANCEL_RL_GLOBAL_REQ,
        )
        global_ids_ok = _enforce_sliding_quota(
            r,
            key="hc:rl:cancel_ids:global",
            amount=len(attempt_ids),
            limit=CANCEL_RL_GLOBAL_IDS,
        )
    except RevocationStoreUnavailableError as exc:
        return _error_json(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            str(exc),
            req,
            clear_cookies=False,
        )

    if not (ip_req_ok and ip_ids_ok and global_req_ok and global_ids_ok):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login cancellation requests. Please retry later.",
            headers={"Retry-After": str(CANCEL_RL_WINDOW_SECONDS)},
        )

    session_svc = SessionService(pool, redis_client=r)
    discovered_families: list[uuid.UUID] = []
    cancel_err: RevocationStoreUnavailableError | None = None
    try:
        discovered_families.extend(
            _mark_login_attempts_cancelled(r, attempt_ids, ttl_seconds=cancel_ttl)
        )
    except RevocationStoreUnavailableError as exc:
        cancel_err = exc

    logout_coord: dict[str, int] = {"global_seq": 0, "logout_seq": 0, "login_seq": 0}
    if browser_id and cancel_err is None:
        try:
            logout_coord, browser_recent = _bump_browser_logout_and_pop_families(r, browser_id)
            discovered_families.extend(browser_recent)
        except RevocationStoreUnavailableError as exc:
            cancel_err = exc

    revoked_count, revocation_err = await _revoke_families_fail_closed(
        session_svc, discovered_families
    )
    effective_err = revocation_err or cancel_err
    if effective_err is not None:
        return _error_json(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            str(effective_err),
            req,
            clear_cookies=False,
        )

    return {
        "success": True,
        "cancelled_attempt_count": len(attempt_ids),
        "revoked_tokens": revoked_count,
        "auth_coord": logout_coord,
    }


PANEL_ROLES_VALID = {"USER", "DOCTOR", "AGENT", "SUPPORT", "ADMIN", "SUPER_ADMIN"}


@router.get("/panels/{panel_role}/access")
async def check_panel_access(
    panel_role: str,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool),
):
    """
    Read-only server-authoritative panel role routing boundary check for Phase 3 UI integration.
    Re-reads live roles from PostgreSQL `user_roles` via `RbacEngine` without altering financial
    or OPEN-* policy gates.
    """
    _set_no_store(response)
    normalized = panel_role.strip().upper().replace("-", "_")
    if normalized not in PANEL_ROLES_VALID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported panel role.",
        )

    async with pool.acquire() as conn:
        rbac = RbacEngine(pool)
        try:
            roles = sorted(list(await rbac.get_user_roles(conn, current_user["id"])))
        except RbacAccessDeniedError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

        allowed = (
            "SUPER_ADMIN" in roles
            or normalized in roles
            or ("ADMIN" in roles and normalized == "USER")
        )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"عدم دسترسی مجاز به پنل {normalized}: نقش تاییدشده شما در سرور "
                    f"({', '.join(roles) or 'NONE'}) اجازه ورود به این بخش را ندارد."
                ),
            )

        verification_status = None
        operational_access = True
        access_level = "OPERATIONAL_ROLE_VERIFIED"

        if normalized in ("DOCTOR", "AGENT"):
            table_name = "doctors" if normalized == "DOCTOR" else "agents"
            if normalized in roles:
                verification_status = await conn.fetchval(
                    f"SELECT verification_status FROM {table_name} WHERE user_id = $1;",
                    current_user["id"],
                )
                if verification_status != "APPROVED":
                    effective_vstatus = verification_status or "MISSING"
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "detail": (
                                f"دسترسی عملیاتی به پنل {normalized} فقط پس از تایید نهایی (APPROVED) امکان‌پذیر است "
                                f"(وضعیت فعلی پرونده: {effective_vstatus})."
                            ),
                            "code": "PROFESSIONAL_APPROVAL_REQUIRED",
                            "panel_role": normalized,
                            "verification_status": effective_vstatus,
                            "operational_access": False,
                            "status_view_allowed": True,
                            "effective_roles": roles,
                            "open_policies_status": "PROPOSED",
                        },
                        headers={
                            "Cache-Control": "no-store, no-cache, must-revalidate, private",
                            "Pragma": "no-cache",
                        },
                    )
                access_level = "OPERATIONAL_APPROVED"
            else:
                # SUPER_ADMIN administrative inspection without impersonating an APPROVED professional record
                operational_access = False
                access_level = "ADMIN_REVIEW_ONLY"
                verification_status = "ADMIN_REVIEW_ONLY"

    return {
        "authorized": True,
        "operational_access": operational_access,
        "access_level": access_level,
        "panel_role": normalized,
        "effective_roles": roles,
        "verification_status": verification_status,
        "mode": "PHASE3_SYNTHETIC_INTEGRATED_READONLY",
        "open_policies_status": "PROPOSED",
    }
