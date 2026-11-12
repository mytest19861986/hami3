"""
Short-Lived In-Memory Access Tokens, Cryptographic Double-Submit CSRF,
and Fail-Closed Redis Family Revocation Store (HC-T36 / HC-CMD-037)
BASELINE: BL-HAMICARD-PRD-V1 | HC-T33 Contract | AC-14, AC-15

Security Guarantees:
- Short-lived signed `hc_at_v1.*` access tokens (max TTL <= 600s, default 300s) for JS closure RAM only;
  never carry authority roles (roles always resolved from PostgreSQL `user_roles`).
- Fail-closed signing secret resolution using unified `is_restricted_environment()` (`src/core/env.py`):
  missing, short (<32 bytes), or known dev placeholder secrets raise `AccessTokenConfigurationError` in
  production/staging or conflicting env configs.
- Cryptographic CSRF double-submit tokens bound via domain-separated HMAC-SHA256 to `family_id`.
- Fail-closed Redis revocation checks: any Redis error during revocation lookup or write raises
  `RevocationStoreUnavailableError` (HTTP 503) rather than silently bypassing revocation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Dict

import redis

from src.core.env import EnvironmentConfigurationError, is_restricted_environment

ACCESS_TOKEN_PREFIX = "hc_at_v1"
DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 300
MIN_ACCESS_TOKEN_TTL_SECONDS = 1
MAX_ACCESS_TOKEN_TTL_SECONDS = 600
REVOKED_FAMILY_REDIS_PREFIX = "hc:revoked_family:"
REVOKED_FAMILY_TTL_SECONDS = MAX_ACCESS_TOKEN_TTL_SECONDS + 120

_DEV_KNOWN_PLACEHOLDER_SECRETS = frozenset(
    {
        "hamicard_dev_access_token_secret_min_32_chars_long",
        "hamicard_dev_only_ephemeral_poc_signing_key_32b_minimum",
        "changeme",
        "secret",
    }
)
_DEV_FALLBACK_SIGNING_SECRET = "hamicard_dev_only_ephemeral_poc_signing_key_32b_minimum"


class AccessTokenConfigurationError(EnvironmentConfigurationError):
    """Raised when access token or CSRF signing configuration fails closed."""


class InvalidAccessTokenError(ValueError):
    """Raised when an access token is syntactically invalid or fails signature verification."""


class ExpiredAccessTokenError(InvalidAccessTokenError):
    """Raised when a syntactically valid access token has passed its `exp` timestamp."""


class RevocationStoreUnavailableError(RuntimeError):
    """Raised fail-closed when the Redis session revocation store is unreachable or errors."""


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(segment: str) -> bytes:
    if not segment or any(ch.isspace() for ch in segment):
        raise InvalidAccessTokenError("Invalid base64url segment.")
    pad = "=" * ((4 - len(segment) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(segment.encode("ascii") + pad.encode("ascii"))
    except Exception as exc:
        raise InvalidAccessTokenError("Malformed base64url encoding.") from exc


def resolve_access_signing_secret() -> bytes:
    """
    Resolves HMAC signing secret with strict fail-closed validation under restricted environments.
    """
    try:
        restricted = is_restricted_environment()
    except EnvironmentConfigurationError as exc:
        raise AccessTokenConfigurationError(str(exc)) from exc
    raw = os.getenv("ACCESS_TOKEN_SECRET")
    if raw is None or not raw.strip():
        raw = os.getenv("JWT_ACCESS_SECRET")

    if raw is None or not raw.strip():
        if restricted:
            raise AccessTokenConfigurationError(
                "FAIL-CLOSED AUTH: ACCESS_TOKEN_SECRET (or JWT_ACCESS_SECRET) must be explicitly "
                "configured in production/staging."
            )
        return _DEV_FALLBACK_SIGNING_SECRET.encode("utf-8")

    cleaned = raw.strip()
    if restricted:
        if len(cleaned) < 32:
            raise AccessTokenConfigurationError(
                "FAIL-CLOSED AUTH: Signing secret must be at least 32 characters in production/staging."
            )
        if cleaned in _DEV_KNOWN_PLACEHOLDER_SECRETS:
            raise AccessTokenConfigurationError(
                "FAIL-CLOSED AUTH: Default development signing secret is forbidden in production/staging."
            )
    elif len(cleaned) < 16:
        raise AccessTokenConfigurationError(
            "FAIL-CLOSED AUTH: Configured ACCESS_TOKEN_SECRET must be at least 16 characters."
        )

    return cleaned.encode("utf-8")


def _csrf_signing_key() -> bytes:
    return hashlib.sha256(b"hamicard:csrf:v1:" + resolve_access_signing_secret()).digest()


def resolve_access_token_ttl() -> int:
    """Resolves bounded short-lived access token TTL (1..600 seconds)."""
    raw = os.getenv("ACCESS_TOKEN_TTL_SECONDS")
    if raw is None or not raw.strip():
        return DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    try:
        ttl = int(raw.strip())
    except ValueError as exc:
        raise AccessTokenConfigurationError(
            f"FAIL-CLOSED AUTH: Invalid ACCESS_TOKEN_TTL_SECONDS={raw!r}."
        ) from exc

    if ttl < MIN_ACCESS_TOKEN_TTL_SECONDS or ttl > MAX_ACCESS_TOKEN_TTL_SECONDS:
        raise AccessTokenConfigurationError(
            f"FAIL-CLOSED AUTH: ACCESS_TOKEN_TTL_SECONDS must be between "
            f"{MIN_ACCESS_TOKEN_TTL_SECONDS} and {MAX_ACCESS_TOKEN_TTL_SECONDS}, got {ttl}."
        )
    return ttl


def issue_access_token(
    *,
    user_id: str | uuid.UUID,
    family_id: str | uuid.UUID,
    session_id: str | uuid.UUID,
    ttl_seconds: int | None = None,
) -> tuple[str, int, str]:
    """
    Issues a short-lived HMAC-SHA256 access token (`hc_at_v1.<payload>.<sig>`).
    Returns `(token, ttl_seconds, access_expires_at_iso)`.
    """
    secret = resolve_access_signing_secret()
    ttl = resolve_access_token_ttl() if ttl_seconds is None else int(ttl_seconds)
    if ttl < MIN_ACCESS_TOKEN_TTL_SECONDS or ttl > MAX_ACCESS_TOKEN_TTL_SECONDS:
        raise AccessTokenConfigurationError(
            f"Access token TTL must be in [{MIN_ACCESS_TOKEN_TTL_SECONDS}, {MAX_ACCESS_TOKEN_TTL_SECONDS}]."
        )

    now = int(time.time())
    exp = now + ttl
    payload = {
        "v": 1,
        "sub": str(uuid.UUID(str(user_id))),
        "fid": str(uuid.UUID(str(family_id))),
        "sid": str(uuid.UUID(str(session_id))),
        "jti": secrets.token_hex(16),
        "iat": now,
        "exp": exp,
    }
    encoded_payload = _b64u_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{ACCESS_TOKEN_PREFIX}.{encoded_payload}".encode("ascii")
    sig = _b64u_encode(hmac.new(secret, signing_input, hashlib.sha256).digest())
    exp_iso = datetime.fromtimestamp(exp, tz=UTC).isoformat()
    return f"{ACCESS_TOKEN_PREFIX}.{encoded_payload}.{sig}", ttl, exp_iso


def verify_access_token(raw_token: str, *, allow_expired: bool = False) -> Dict[str, Any]:
    """
    Verifies HMAC signature, structure, UUID claims, and expiration of an `hc_at_v1.*` access token.
    Never grants trust before verifying signature via constant-time `hmac.compare_digest`.
    """
    if not raw_token or not isinstance(raw_token, str):
        raise InvalidAccessTokenError("Missing access token.")

    parts = raw_token.split(".")
    if len(parts) != 3 or parts[0] != ACCESS_TOKEN_PREFIX:
        raise InvalidAccessTokenError("Unsupported access token format.")

    prefix, encoded_payload, provided_sig = parts
    secret = resolve_access_signing_secret()
    signing_input = f"{prefix}.{encoded_payload}".encode("ascii")
    expected_sig = _b64u_encode(hmac.new(secret, signing_input, hashlib.sha256).digest())

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise InvalidAccessTokenError("Access token signature verification failed.")

    try:
        payload_bytes = _b64u_decode(encoded_payload)
        claims = json.loads(payload_bytes.decode("utf-8"))
    except InvalidAccessTokenError:
        raise
    except Exception as exc:
        raise InvalidAccessTokenError("Malformed access token payload.") from exc

    if not isinstance(claims, dict) or claims.get("v") != 1:
        raise InvalidAccessTokenError("Unsupported access token claims version.")

    try:
        sub_uuid = uuid.UUID(str(claims["sub"]))
        fid_uuid = uuid.UUID(str(claims["fid"]))
        sid_uuid = uuid.UUID(str(claims["sid"]))
        iat = int(claims["iat"])
        exp = int(claims["exp"])
    except Exception as exc:
        raise InvalidAccessTokenError("Missing or malformed access token claims.") from exc

    if exp <= iat or (exp - iat) > MAX_ACCESS_TOKEN_TTL_SECONDS:
        raise InvalidAccessTokenError("Access token lifetime exceeds permitted bounds.")

    now = int(time.time())
    if not allow_expired and now >= exp:
        raise ExpiredAccessTokenError("Access token has expired.")

    return {
        "user_id": sub_uuid,
        "family_id": fid_uuid,
        "session_id": sid_uuid,
        "jti": str(claims.get("jti", "")),
        "iat": iat,
        "exp": exp,
    }


def generate_csrf_token(family_id: str | uuid.UUID) -> str:
    """
    Generates a double-submit CSRF token Cryptographically bound to `family_id`.
    """
    fid = str(uuid.UUID(str(family_id)))
    nonce = _b64u_encode(secrets.token_bytes(24))
    key = _csrf_signing_key()
    msg = f"hc_csrf_v1:{fid}:{nonce}".encode("ascii")
    mac = _b64u_encode(hmac.new(key, msg, hashlib.sha256).digest())
    return f"{nonce}.{mac}"


def verify_csrf_token(token: str | None, family_id: str | uuid.UUID) -> bool:
    """
    Verifies HMAC signature of a double-submit CSRF token against the target `family_id`.
    """
    if not token or not isinstance(token, str) or "." not in token:
        return False
    parts = token.split(".")
    if len(parts) != 2:
        return False
    nonce, provided_mac = parts
    if not nonce or not provided_mac:
        return False

    try:
        fid = str(uuid.UUID(str(family_id)))
        key = _csrf_signing_key()
    except (ValueError, AccessTokenConfigurationError):
        return False

    msg = f"hc_csrf_v1:{fid}:{nonce}".encode("ascii")
    expected_mac = _b64u_encode(hmac.new(key, msg, hashlib.sha256).digest())
    return hmac.compare_digest(provided_mac, expected_mac)


def is_family_revoked_in_redis(
    redis_client: redis.Redis | None,
    family_id: str | uuid.UUID,
) -> bool:
    """
    Fail-closed Redis check for revoked session families.
    Raises `RevocationStoreUnavailableError` on ANY Redis connectivity/client failure so outages
    never silently allow potentially revoked short-lived access tokens.
    """
    if redis_client is None:
        raise RevocationStoreUnavailableError(
            "FAIL-CLOSED REVOCATION: Redis revocation client is not initialized."
        )
    key = f"{REVOKED_FAMILY_REDIS_PREFIX}{uuid.UUID(str(family_id))}"
    try:
        val = redis_client.get(key)
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            f"FAIL-CLOSED REVOCATION: Redis revocation lookup failed: {exc}"
        ) from exc
    return bool(val)


def mark_family_revoked_in_redis(
    redis_client: redis.Redis | None,
    family_id: str | uuid.UUID,
    reason: str = "REVOKED",
    ttl_seconds: int = REVOKED_FAMILY_TTL_SECONDS,
) -> None:
    """
    Records revoked session family in Redis with TTL exceeding maximum access token lifetime.
    Raises `RevocationStoreUnavailableError` on ANY Redis write failure (fail-closed).
    """
    if redis_client is None:
        raise RevocationStoreUnavailableError(
            "FAIL-CLOSED REVOCATION: Redis revocation client is not initialized."
        )
    key = f"{REVOKED_FAMILY_REDIS_PREFIX}{uuid.UUID(str(family_id))}"
    try:
        redis_client.set(key, reason, ex=ttl_seconds)
    except redis.RedisError as exc:
        raise RevocationStoreUnavailableError(
            f"FAIL-CLOSED REVOCATION: Redis revocation write failed: {exc}"
        ) from exc
