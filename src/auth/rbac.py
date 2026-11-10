"""
Role-Based Access Control (RBAC) & Operational Guard Engine
BASELINE: BL-HAMICARD-PRD-V1 | Section 4 (RBAC-001..009), Section 27 (BR-01..30)

Guarantees:
- Server-side authorization check for all 6 PRD roles:
  SUPER_ADMIN, ADMIN, SUPPORT, DOCTOR, AGENT, USER
- Granular permission check via (roles -> role_permissions) and user_roles
- Fail-Closed Doctor / Agent Verification Status:
  Unapproved (PENDING, REJECTED, SUSPENDED) doctors/agents CANNOT execute operational actions
- Negative guards: Prevent unauthorized privilege escalation, role delegation, or sensitive financial mutations
"""

import uuid
from typing import Set

import asyncpg


class RbacAccessDeniedError(Exception):
    """Raised when user lacks permission or fails role verification check."""
    pass

class ProfileNotApprovedError(RbacAccessDeniedError):
    """Raised when doctor or agent is not in APPROVED status."""
    pass

class RbacEngine:
    def __init__(self, db_pool: asyncpg.Pool):
        self.pool = db_pool

    async def get_user_roles(self, conn: asyncpg.Connection, user_id: uuid.UUID) -> Set[str]:
        """Fetches active roles for user from users table and user_roles mapping."""
        # 1. From users table roles array
        row = await conn.fetchrow("SELECT roles, status FROM users WHERE id = $1;", user_id)
        if not row:
            raise RbacAccessDeniedError("User does not exist.")
        if row["status"] != "ACTIVE":
            raise RbacAccessDeniedError(f"User account is {row['status']}. All access denied.")

        roles = set(row["roles"] or [])

        # 2. From user_roles relation
        ur_rows = await conn.fetch("SELECT role_id FROM user_roles WHERE user_id = $1;", user_id)
        for r in ur_rows:
            roles.add(r["role_id"])

        return roles

    async def get_user_permissions(self, conn: asyncpg.Connection, user_id: uuid.UUID) -> Set[str]:
        """Resolves all granular permissions for the user based on their active roles."""
        roles = await self.get_user_roles(conn, user_id)
        if not roles:
            return set()

        if "SUPER_ADMIN" in roles:
            # SUPER_ADMIN has every permission in the database
            all_perms = await conn.fetch("SELECT id FROM permissions;")
            return {p["id"] for p in all_perms}

        perm_rows = await conn.fetch("""
            SELECT DISTINCT permission_id 
            FROM role_permissions 
            WHERE role_id = ANY($1::varchar[]);
        """, list(roles))

        return {r["permission_id"] for r in perm_rows}

    async def check_permission(
        self,
        user_id: uuid.UUID,
        required_permission: str,
        is_operational_action: bool = False
    ) -> bool:
        """
        Validates whether user has the specified permission.
        Enforces Fail-Closed check on doctor/agent profile verification status.
        Raises RbacAccessDeniedError or ProfileNotApprovedError if unauthorized.
        """
        async with self.pool.acquire() as conn:
            roles = await self.get_user_roles(conn, user_id)

            # SUPER_ADMIN has unrestricted access
            if "SUPER_ADMIN" in roles:
                return True

            perms = await self.get_user_permissions(conn, user_id)
            if required_permission not in perms:
                raise RbacAccessDeniedError(
                    f"Access Denied: Missing required permission '{required_permission}'."
                )

            # Fail-Closed Verification Status Check (T10-AC2):
            # If action is DOCTOR operational (e.g., visits:record), check doctor approval
            if required_permission.startswith("visits:") or required_permission == "memberships:read":
                if "DOCTOR" in roles and "ADMIN" not in roles:
                    doc_status = await conn.fetchval(
                        "SELECT verification_status FROM doctors WHERE user_id = $1;",
                        user_id
                    )
                    if doc_status != "APPROVED":
                        raise ProfileNotApprovedError(
                            f"Doctor account is in '{doc_status or 'UNREGISTERED'}' status. "
                            "Action requires 'APPROVED' verification."
                        )

            # If action is AGENT operational (e.g. settlements:request), check agent approval
            if required_permission.startswith("sales_cases:") or (required_permission == "settlements:request" and "AGENT" in roles):
                if "AGENT" in roles and "ADMIN" not in roles:
                    agent_status = await conn.fetchval(
                        "SELECT verification_status FROM agents WHERE user_id = $1;",
                        user_id
                    )
                    if agent_status != "APPROVED":
                        raise ProfileNotApprovedError(
                            f"Agent account is in '{agent_status or 'UNREGISTERED'}' status. "
                            "Action requires 'APPROVED' verification."
                        )

            return True

    async def assign_role(
        self,
        actor_user_id: uuid.UUID,
        target_user_id: uuid.UUID,
        role_to_assign: str
    ) -> bool:
        """
        Assigns role to target user.
        Strict Negative Guard: ONLY SUPER_ADMIN can assign or modify administrative roles.
        """
        async with self.pool.acquire() as conn:
            actor_roles = await self.get_user_roles(conn, actor_user_id)
            if "SUPER_ADMIN" not in actor_roles:
                raise RbacAccessDeniedError("Only SUPER_ADMIN is authorized to assign or modify user roles.")

            # Validate role exists
            role_exists = await conn.fetchval("SELECT id FROM roles WHERE id = $1;", role_to_assign)
            if not role_exists:
                raise ValueError(f"Role '{role_to_assign}' does not exist.")

            # Insert into user_roles
            await conn.execute("""
                INSERT INTO user_roles (user_id, role_id, assigned_by)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id, role_id) DO NOTHING;
            """, target_user_id, role_to_assign, actor_user_id)

            # Sync array in users table
            await conn.execute("""
                UPDATE users 
                SET roles = array_append(roles, $1) 
                WHERE id = $2 AND NOT ($1 = ANY(roles));
            """, role_to_assign, target_user_id)

            # Record security audit log
            await conn.execute("""
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, action, entity_name, entity_id,
                    new_values
                ) VALUES (
                    $1, 'SUPER_ADMIN', 'ROLE_ASSIGNED', 'users', $2,
                    jsonb_build_object('assigned_role', $3::text)
                );
            """, actor_user_id, str(target_user_id), role_to_assign)

            return True

    async def has_permission(self, user_id: uuid.UUID, required_permission: str) -> bool:
        """Helper that returns boolean True/False instead of raising exceptions."""
        try:
            return await self.check_permission(user_id, required_permission)
        except RbacAccessDeniedError:
            return False

