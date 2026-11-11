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

from fastapi.middleware.cors import CORSMiddleware
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse, Response

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
]


class CorsConfigurationError(ValueError):
    """Raised when CORS environment configuration violates security invariants."""


def is_production_environment() -> bool:
    for var in ("APP_ENV", "ENVIRONMENT", "NODE_ENV"):
        val = os.getenv(var, "").strip().lower()
        if val in ("production", "prod", "staging"):
            return True
    return False


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
