"""
Runtime Business Policy Gate & Approval Tracker (HC-T14 | F-06, T14-AC1..AC2)
BASELINE: BL-HAMICARD-PRD-V1 | Section 28 (OPEN-01..OPEN-18)

Guarantees:
- Seeded OPEN-01..18 parameters remain explicitly flagged as 'PROPOSED' until
  explicit owner approval transitions them to 'APPROVED' (or 'BLOCKED').
- Financial & policy-sensitive operations fail closed with PolicyNotApprovedError
  unless every governing policy is in 'APPROVED' state.
- Rounding mode & settlement minimum are read dynamically from approved runtime
  settings rather than hardcoded SQL constraints or constants.
"""

import json
import math
import uuid
from typing import Any, Dict, List

import asyncpg

VALID_APPROVAL_STATUSES = ("PROPOSED", "APPROVED", "BLOCKED")


class PolicyError(Exception):
    """Base error for business policy configuration or lookup failures."""
    pass


class PolicyNotApprovedError(PolicyError):
    """Raised when an operation depends on an OPEN-* policy not yet APPROVED."""

    def __init__(self, key: str, approval_status: str, message: str | None = None):
        self.key = key
        self.approval_status = approval_status
        detail = message or (
            f"Operation disabled: required business policy '{key}' is in "
            f"'{approval_status}' status (owner approval required)."
        )
        super().__init__(detail)


def _decode_json_value(raw_val: Any) -> Any:
    if isinstance(raw_val, str):
        try:
            return json.loads(raw_val)
        except Exception:
            return raw_val
    return raw_val


async def get_policy_record(conn: asyncpg.Connection, key: str) -> Dict[str, Any]:
    """Fetches a single OPEN-* policy record including its approval_status."""
    row = await conn.fetchrow(
        """
        SELECT key, value_json, data_type, is_mandatory, approval_status,
               approved_by, approved_at, description, updated_at
        FROM system_settings
        WHERE key = $1;
        """,
        key,
    )
    if not row:
        raise PolicyError(f"Fail-Closed violation: Policy key '{key}' does not exist.")

    return {
        "key": row["key"],
        "value": _decode_json_value(row["value_json"]),
        "data_type": row["data_type"],
        "is_mandatory": row["is_mandatory"],
        "approval_status": row["approval_status"],
        "approved_by": str(row["approved_by"]) if row["approved_by"] else None,
        "approved_at": row["approved_at"].isoformat() if row["approved_at"] else None,
        "description": row["description"],
    }


async def require_approved_policy(conn: asyncpg.Connection, key: str) -> Dict[str, Any]:
    """
    Fail-Closed Policy Guard:
    Ensures the named policy exists AND is explicitly 'APPROVED'.
    Raises PolicyNotApprovedError if 'PROPOSED' or 'BLOCKED'.
    Returns the parsed JSON policy payload (`dict`).
    """
    rec = await get_policy_record(conn, key)
    if rec["approval_status"] != "APPROVED":
        raise PolicyNotApprovedError(key=key, approval_status=rec["approval_status"])
    val = rec["value"]
    return val if isinstance(val, dict) else {"value": val}


async def get_all_open_policy_statuses(conn: asyncpg.Connection) -> List[Dict[str, Any]]:
    """Lists OPEN-01..OPEN-18 traceability matrix with independent approval statuses."""
    rows = await conn.fetch(
        """
        SELECT key, value_json, approval_status, approved_by, approved_at, description
        FROM system_settings
        WHERE key LIKE 'OPEN\\_%' ESCAPE '\\'
        ORDER BY key ASC;
        """
    )
    return [
        {
            "key": r["key"],
            "value": _decode_json_value(r["value_json"]),
            "approval_status": r["approval_status"],
            "approved_by": str(r["approved_by"]) if r["approved_by"] else None,
            "approved_at": r["approved_at"].isoformat() if r["approved_at"] else None,
            "description": r["description"],
        }
        for r in rows
    ]


async def set_policy_approval(
    conn: asyncpg.Connection,
    key: str,
    approval_status: str,
    actor_user_id: uuid.UUID | None = None,
    updated_value_json: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Transitions a policy independently between PROPOSED / APPROVED / BLOCKED
    and logs an audit trail entry.
    """
    status_norm = approval_status.strip().upper()
    if status_norm not in VALID_APPROVAL_STATUSES:
        raise PolicyError(f"Invalid approval status: '{approval_status}'")

    current = await get_policy_record(conn, key)
    new_val_str = (
        json.dumps(updated_value_json, ensure_ascii=False)
        if updated_value_json is not None
        else json.dumps(current["value"], ensure_ascii=False)
    )

    if status_norm == "APPROVED":
        await conn.execute(
            """
            UPDATE system_settings
            SET approval_status = 'APPROVED',
                value_json = $2::jsonb,
                approved_by = $3,
                approved_at = NOW(),
                updated_by = $3,
                updated_at = NOW()
            WHERE key = $1;
            """,
            key,
            new_val_str,
            actor_user_id,
        )
    else:
        await conn.execute(
            """
            UPDATE system_settings
            SET approval_status = $2,
                value_json = $3::jsonb,
                approved_by = NULL,
                approved_at = NULL,
                updated_by = $4,
                updated_at = NOW()
            WHERE key = $1;
            """,
            key,
            status_norm,
            new_val_str,
            actor_user_id,
        )

    await conn.execute(
        """
        INSERT INTO audit_logs (
            actor_user_id, actor_role, action, entity_name, entity_id,
            old_values, new_values
        ) VALUES (
            $1, 'OWNER_POLICY_ADMIN', 'POLICY_APPROVAL_UPDATED', 'system_settings', $2,
            jsonb_build_object('approval_status', $3::text),
            jsonb_build_object('approval_status', $4::text)
        );
        """,
        actor_user_id,
        key,
        current["approval_status"],
        status_norm,
    )

    return await get_policy_record(conn, key)


def round_toman(raw_amount: float, rounding_policy: Dict[str, Any] | None = None) -> int:
    """Applies approved OPEN-18 rounding rule (default FLOOR per PRD)."""
    mode = (rounding_policy or {}).get("rounding_mode", "FLOOR").upper()
    if mode == "FLOOR":
        return math.floor(raw_amount)
    if mode == "CEIL":
        return math.ceil(raw_amount)
    return int(round(raw_amount))
