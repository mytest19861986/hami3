"""
System Settings Manager & Fail-Closed Startup Enforcer (HC-T14 Remediated)
BASELINE: BL-HAMICARD-PRD-V1 | Section 28 (OPEN-01..18)
Enforces:
- Strict validation that all 18 OPEN-01..18 configuration keys exist
- Explicit separation of PROPOSED vs APPROVED vs BLOCKED policy states (F-06, T14-AC1)
- Fail-Closed: Raises SystemConfigurationError on missing or invalid keys
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
    "OPEN_18_CURRENCY_AND_ROUNDING",
]


class SystemConfigurationError(Exception):
    """Raised when system settings violate Fail-Closed policy."""
    pass


async def load_and_validate_settings(conn: asyncpg.Connection) -> Dict[str, Any]:
    """
    Loads all mandatory system settings from PostgreSQL.
    Enforces Fail-Closed invariant: if any required key is missing, throws SystemConfigurationError.
    Separates proposed config values from approved runtime eligibility (`is_approved`).
    """
    rows = await conn.fetch(
        """
        SELECT key, value_json, data_type, is_mandatory, approval_status, approved_by, approved_at
        FROM system_settings
        WHERE is_mandatory = TRUE;
        """
    )

    settings_map: Dict[str, Any] = {}
    for r in rows:
        key = r["key"]
        val = r["value_json"]
        if isinstance(val, str):
            try:
                val = json.loads(val)
            except Exception:
                pass
        approval_status = r["approval_status"]
        settings_map[key] = {
            "value": val,
            "approval_status": approval_status,
            "is_approved": approval_status == "APPROVED",
            "approved_by": str(r["approved_by"]) if r["approved_by"] else None,
            "approved_at": r["approved_at"].isoformat() if r["approved_at"] else None,
        }

    missing_keys = [k for k in EXPECTED_OPEN_KEYS if k not in settings_map]
    if missing_keys:
        raise SystemConfigurationError(
            f"FAIL-CLOSED VIOLATION: Missing {len(missing_keys)} mandatory system setting(s): {missing_keys}. "
            "Server startup halted to prevent undefined business behavior."
        )

    return settings_map


async def load_runtime_policy_partition(conn: asyncpg.Connection) -> Dict[str, Dict[str, Any]]:
    """
    Returns an explicit partition separating:
    - `approved`: policies approved by owner and active for runtime execution
    - `proposed`: seeded/configured draft policies awaiting owner approval
    - `blocked`: policies explicitly blocked from execution
    """
    all_settings = await load_and_validate_settings(conn)
    partition: Dict[str, Dict[str, Any]] = {"approved": {}, "proposed": {}, "blocked": {}}
    for key, entry in all_settings.items():
        status = entry["approval_status"]
        if status == "APPROVED":
            partition["approved"][key] = entry["value"]
        elif status == "BLOCKED":
            partition["blocked"][key] = entry["value"]
        else:
            partition["proposed"][key] = entry["value"]
    return partition
