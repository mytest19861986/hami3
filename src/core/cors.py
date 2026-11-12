"""
Environment-Controlled Fail-Closed CORS Policy Resolver (HC-T26 / M-1 Remediation)
BASELINE: BL-HAMICARD-PRD-V1
Guarantees:
- Never allows wildcard (`*`) origins with `allow_credentials=True` (nor `*` in allowlist).
- Never enables arbitrary `Origin` reflection (`allow_origin_regex` is unused).
- Fails closed in production/staging when explicit trusted origins are missing or invalid.
"""

import os
from typing import Any
from urllib.parse import urlparse

from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse, Response

from src.core.env import EnvironmentConfigurationError, is_restricted_environment

DEV_DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

ALLOWED_CORS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
ALLOWED_CORS_HEADERS = [
    "Authorization",
    "Content-Type",
    "Accept",
    "Origin",
    "X-Requested-With",
    "Idempotency-Key",
    "X-CSRF-Token",
    "X-Auth-Mode",
]


class CorsConfigurationError(ValueError):
    """Raised when CORS environment configuration violates security invariants."""


class CorsOriginRejectedError(ValueError):
    """Raised when a credentialed request originates from an untrusted or missing Origin/Referer."""


def is_production_environment() -> bool:
    try:
        return is_restricted_environment()
    except EnvironmentConfigurationError as exc:
        raise CorsConfigurationError(str(exc)) from exc


def _parse_bool_env(var_name: str, default: bool) -> bool:
    raw = os.getenv(var_name)
    if raw is None:
        return default
    clean = raw.strip().lower()
    if clean in ("1", "true", "yes", "on"):
        return True
    if clean in ("0", "false", "no", "off"):
        return False
    raise CorsConfigurationError(f"Invalid boolean value for {var_name}: {raw!r}")


def validate_cors_origin(raw_origin: str) -> str:
    origin = raw_origin.strip().rstrip("/")
    if not origin:
        raise CorsConfigurationError("Empty origin entry in CORS_ALLOWED_ORIGINS.")
    if "*" in origin:
        raise CorsConfigurationError(
            f"Wildcard origin '{raw_origin}' is strictly forbidden for credentialed CORS."
        )
    if origin.lower() == "null":
        raise CorsConfigurationError("Opaque 'null' origin is forbidden in CORS_ALLOWED_ORIGINS.")

    parsed = urlparse(origin)
    if parsed.scheme.lower() not in ("http", "https"):
        raise CorsConfigurationError(
            f"Invalid CORS origin scheme '{parsed.scheme}' in '{raw_origin}'; only http/https allowed."
        )
    if not parsed.netloc or not parsed.hostname:
        raise CorsConfigurationError(f"CORS origin '{raw_origin}' is missing a valid host.")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise CorsConfigurationError(
            f"CORS origin '{raw_origin}' must contain scheme and host[:port] only (no path/query/fragment)."
        )
    if parsed.username is not None or parsed.password is not None:
        raise CorsConfigurationError(f"CORS origin '{raw_origin}' must not contain userinfo.")

    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def resolve_cors_settings() -> dict[str, Any]:
    """
    Resolves validated CORS configuration from environment variables.
    Production / staging requires explicit valid `CORS_ALLOWED_ORIGINS` (or `ALLOWED_CORS_ORIGINS`).
    Non-production defaults to explicit localhost origins when unset.
    """
    is_prod = is_production_environment()
    allow_credentials = _parse_bool_env("CORS_ALLOW_CREDENTIALS", True)

    raw_env = os.getenv("CORS_ALLOWED_ORIGINS")
    if raw_env is None:
        raw_env = os.getenv("ALLOWED_CORS_ORIGINS")

    if raw_env is None:
        if is_prod:
            raise CorsConfigurationError(
                "FAIL-CLOSED CORS: CORS_ALLOWED_ORIGINS must be explicitly configured in production/staging."
            )
        origins = list(DEV_DEFAULT_CORS_ORIGINS)
    else:
        tokens = [part.strip() for part in raw_env.split(",") if part.strip()]
        if not tokens:
            if is_prod:
                raise CorsConfigurationError(
                    "FAIL-CLOSED CORS: CORS_ALLOWED_ORIGINS cannot be empty in production/staging."
                )
            origins = []
        else:
            seen: set[str] = set()
            origins = []
            for tok in tokens:
                normalized = validate_cors_origin(tok)
                if normalized not in seen:
                    seen.add(normalized)
                    origins.append(normalized)

    return {
        "allow_origins": origins,
        "allow_credentials": allow_credentials,
        "allow_methods": list(ALLOWED_CORS_METHODS),
        "allow_headers": list(ALLOWED_CORS_HEADERS),
    }


class StrictCORSMiddleware(CORSMiddleware):
    """
    CORS middleware that omits `Access-Control-Allow-Credentials` and
    `Access-Control-Allow-Origin` whenever the request `Origin` is not explicitly allowed.
    """

    def preflight_response(self, request_headers: Headers) -> Response:
        requested_origin = request_headers.get("origin", "")
        if self.allow_all_origins or not self.is_allowed_origin(origin=requested_origin):
            return PlainTextResponse(
                "Disallowed CORS origin",
                status_code=400,
                headers={"Vary": "Origin"},
            )
        return super().preflight_response(request_headers)

    async def send(self, message, send, request_headers) -> None:
        if message["type"] != "http.response.start":
            await send(message)
            return
        origin = request_headers.get("Origin", "")
        if self.allow_all_origins or not self.is_allowed_origin(origin=origin):
            message.setdefault("headers", [])
            headers = MutableHeaders(scope=message)
            headers.add_vary_header("Origin")
            await send(message)
            return
        await super().send(message, send, request_headers)


def validate_cookie_request_origin(request: Request) -> str:
    """
    Fail-closed Origin / Referer enforcement for cookie-authenticated endpoints (CSRF barrier #1).
    Accepts strictly verified origins matching `resolve_cors_settings()["allow_origins"]`
    (plus exact local `127.0.0.1`/`localhost` ephemeral port only in non-restricted env when
    explicit `CORS_ALLOWED_ORIGINS` is unset).
    Rejects missing `Origin`+`Referer`, `null`, wildcards, and lookalike/untrusted origins.
    """
    cfg = resolve_cors_settings()
    allowed_origins = set(cfg["allow_origins"])

    explicit_env = (os.getenv("CORS_ALLOWED_ORIGINS") is not None) or (
        os.getenv("ALLOWED_CORS_ORIGINS") is not None
    )
    if not explicit_env and not is_production_environment():
        host_hdr = (request.headers.get("host") or "").strip().lower()
        scheme = (request.url.scheme or "http").lower()
        if host_hdr and scheme in ("http", "https"):
            candidate_self = f"{scheme}://{host_hdr}"
            try:
                normalized_self = validate_cors_origin(candidate_self)
                parsed_self = urlparse(normalized_self)
                if parsed_self.hostname in ("127.0.0.1", "localhost"):
                    allowed_origins.add(normalized_self)
            except CorsConfigurationError:
                pass

    raw_origin = request.headers.get("origin")
    if raw_origin is not None:
        try:
            normalized = validate_cors_origin(raw_origin)
        except CorsConfigurationError as exc:
            raise CorsOriginRejectedError(f"Invalid request Origin header: {exc}") from exc
        if normalized not in allowed_origins:
            raise CorsOriginRejectedError(f"Untrusted request Origin: {normalized}")
        return normalized

    raw_referer = request.headers.get("referer")
    if raw_referer is not None:
        parsed = urlparse(raw_referer.strip())
        if not parsed.scheme or not parsed.netloc:
            raise CorsOriginRejectedError("Malformed request Referer header.")
        candidate = f"{parsed.scheme}://{parsed.netloc}"
        try:
            normalized_ref = validate_cors_origin(candidate)
        except CorsConfigurationError as exc:
            raise CorsOriginRejectedError(f"Invalid request Referer origin: {exc}") from exc
        if normalized_ref not in allowed_origins:
            raise CorsOriginRejectedError(f"Untrusted request Referer origin: {normalized_ref}")
        return normalized_ref

    raise CorsOriginRejectedError("Missing Origin or Referer header on cookie-authenticated request.")
