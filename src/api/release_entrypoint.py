"""
Fail-Closed Release Startup Guard & Entrypoint (R2-T46-H01 Remediation)
BASELINE: BL-HAMICARD-PRD-V1

Ensures release/container deployments NEVER silently fall back to `"development"`
when runtime environment declarations (`APP_ENV`, `ENVIRONMENT`, `NODE_ENV`) are
missing, empty, conflicting, invalid, or set to `development` / `test`.
"""

import os
import sys
from typing import Sequence

import uvicorn

from src.core.cors import CorsConfigurationError, resolve_cors_settings
from src.core.env import (
    RESTRICTED_ENVIRONMENTS,
    SUPPORTED_ENV_VARS,
    EnvironmentConfigurationError,
    resolve_runtime_environment,
)


def validate_release_runtime_environment() -> str:
    """
    Requires an explicit restricted runtime environment (`production` / `staging`)
    and valid fail-closed CORS configuration before starting the ASGI server.
    """
    explicitly_set = [var for var in SUPPORTED_ENV_VARS if (os.getenv(var) or "").strip()]
    if not explicitly_set:
        raise EnvironmentConfigurationError(
            "FAIL-CLOSED RELEASE STARTUP: Missing runtime environment declaration. "
            "Set APP_ENV, ENVIRONMENT, or NODE_ENV explicitly to 'production' or 'staging'."
        )

    canonical = resolve_runtime_environment()
    if canonical not in RESTRICTED_ENVIRONMENTS:
        raise EnvironmentConfigurationError(
            f"FAIL-CLOSED RELEASE STARTUP: Restricted environment required for release entrypoint; "
            f"got resolved environment '{canonical}'."
        )

    resolve_cors_settings()
    from src.api.main import create_app

    create_app()
    return canonical


def main(argv: Sequence[str] | None = None) -> int:
    try:
        validate_release_runtime_environment()
    except (EnvironmentConfigurationError, CorsConfigurationError) as exc:
        print(f"[HAMICARD-RELEASE-GUARD] FAIL-CLOSED: {exc}", file=sys.stderr)
        return 1

    host = os.getenv("HAMICARD_BIND_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", os.getenv("HAMICARD_PORT", "8000")))
    workers = int(os.getenv("WEB_CONCURRENCY", "4"))

    uvicorn.run(
        "src.api.main:app",
        host=host,
        port=port,
        workers=workers,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

