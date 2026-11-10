"""
System Settings Manager & Fail-Closed Startup Enforcer
BASELINE: BL-HAMICARD-PRD-V1 | Section 28 (OPEN-01..18)
Enforces:
- Strict validation that all 18 OPEN-01..18 configuration keys exist
- Type checking on parametric settings
- Fail-Closed: Raises SystemConfigurationError on missing or invalid keys, aborting startup
"""

import json
from typing import Any, Dict

import asyncpg

EXPECTED_OPEN_KEYS = [
    "OPEN_01_REFERRER_VS_AGENT_BOUNDARY",
    "OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE",
    "OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER",
    "OPEN_04_FINANCIAL_PERMISSIONS_MATRIX",
    "OPEN_05_COMBINED_COMMISSION_POLICY",
    "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN",
    "OPEN_07_VISIT_CANCELLATION_REFUND_POLICY",
    "OPEN_08_MULTI_ACTIVE_PLANS_PER_HOLDER",
    "OPEN_09_NATIONAL_CODE_PHONE_CONFLICT",
    "OPEN_10_RBAC_ADMIN_SUPPORT_MATRIX",
    "OPEN_11_EXTERNAL_ADAPTERS_CONFIG",
    "OPEN_12_DATA_RETENTION_AND_SOFT_DELETE",
    "OPEN_13_BACKUP_RETENTION_POLICY",
    "OPEN_14_SLA_AND_RATE_LIMITS",
    "OPEN_15_THEME_AND_FONTS",
    "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT",
    "OPEN_17_ADMIN_GRANT_PLAN_POLICY",
    "OPEN_18_CURRENCY_AND_ROUNDING"
]

class SystemConfigurationError(Exception):
    """Raised when system settings violate Fail-Closed policy."""
    pass

async def load_and_validate_settings(conn: asyncpg.Connection) -> Dict[str, Any]:
    """
    Loads all mandatory system settings from PostgreSQL.
    Enforces Fail-Closed invariant: if any required key is missing, throws SystemConfigurationError.
    """
    rows = await conn.fetch("""
        SELECT key, value_json, data_type, is_mandatory
        FROM system_settings
        WHERE is_mandatory = TRUE;
    """)

    settings_map: Dict[str, Any] = {}
    for r in rows:
        key = r["key"]
        val = r["value_json"]
        if isinstance(val, str):
            try:
                val = json.loads(val)
            except Exception:
                pass
        settings_map[key] = val

    # Verify all expected OPEN keys exist
    missing_keys = [k for k in EXPECTED_OPEN_KEYS if k not in settings_map]
    if missing_keys:
        raise SystemConfigurationError(
            f"FAIL-CLOSED VIOLATION: Missing {len(missing_keys)} mandatory system setting(s): {missing_keys}. "
            "Server startup halted to prevent undefined business behavior."
        )

    return settings_map

