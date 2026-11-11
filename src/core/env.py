"""
Unified Fail-Closed Runtime Environment Classifier (HC-T30 / R-01)
BASELINE: BL-HAMICARD-PRD-V1

Guarantees:
- Reads every supported environment variable (`APP_ENV`, `ENVIRONMENT`, `NODE_ENV`).
- Classifies canonical `production` (`production`, `prod`) and `staging` (`staging`, `stage`)
  as restricted environments where mock/sandbox adapters and default dev CORS are strictly forbidden.
- Rejects conflicting environment declarations across variables AND unrecognized non-empty
  values fail closed via `EnvironmentConfigurationError`.
"""

import os
from typing import Dict

SUPPORTED_ENV_VARS: tuple[str, ...] = ("APP_ENV", "ENVIRONMENT", "NODE_ENV")

CANONICAL_ENVIRONMENT_ALIASES: Dict[str, str] = {
    "production": "production",
    "prod": "production",
    "staging": "staging",
    "stage": "staging",
    "development": "development",
    "dev": "development",
    "local": "development",
    "test": "test",
    "testing": "test",
}

RESTRICTED_ENVIRONMENTS: frozenset[str] = frozenset({"production", "staging"})


class EnvironmentConfigurationError(ValueError):
    """Raised when runtime environment variables are conflicting or unrecognized."""


def resolve_runtime_environment() -> str:
    """
    Resolves canonical runtime environment across `APP_ENV`, `ENVIRONMENT`, and `NODE_ENV`.
    Returns one of `'production'`, `'staging'`, `'development'`, `'test'`.
    Raises `EnvironmentConfigurationError` if any non-empty variable is unrecognized
    or if multiple variables resolve to conflicting canonical environments.
    """
    observed: list[tuple[str, str, str]] = []
    for var_name in SUPPORTED_ENV_VARS:
        raw = os.getenv(var_name)
        if raw is None:
            continue
        cleaned = raw.strip().lower()
        if not cleaned:
            continue
        canonical = CANONICAL_ENVIRONMENT_ALIASES.get(cleaned)
        if canonical is None:
            raise EnvironmentConfigurationError(
                f"FAIL-CLOSED ENV: Unrecognized runtime environment value {var_name}={raw!r}."
            )
        observed.append((var_name, cleaned, canonical))

    if not observed:
        return "development"

    distinct_canonicals = {item[2] for item in observed}
    if len(distinct_canonicals) > 1:
        details = ", ".join(
            f"{var}={raw_val!r} (-> {canon})" for var, raw_val, canon in observed
        )
        raise EnvironmentConfigurationError(
            f"FAIL-CLOSED ENV: Conflicting runtime environment variables: {details}."
        )

    return observed[0][2]


def is_restricted_environment() -> bool:
    """
    Returns True for `production` and `staging` across all supported env vars.
    Raises `EnvironmentConfigurationError` on ambiguous/conflicting/invalid env config.
    """
    return resolve_runtime_environment() in RESTRICTED_ENVIRONMENTS
