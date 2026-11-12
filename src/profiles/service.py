"""Profile and Reference Data Service (Phase 3).
Enforces Iranian National Code, Card (Luhn), and Sheba (ISO 7064) validations,
province-city parent-child hierarchy, and role-based PII masking.
"""
import uuid
from typing import Any, Dict, List

import asyncpg

from src.common.pii import (
    mask_card_number,
    mask_national_code,
    mask_phone,
    mask_shaba,
)
from src.common.validators import (
    validate_iranian_card_number,
    validate_iranian_national_code,
    validate_iranian_shaba,
)


class ProfileValidationError(Exception):
    """Raised when profile input fails business rules or validation."""
    pass


class ReferenceService:
    """Manages Iranian provinces and cities hierarchy."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def get_all_provinces(self) -> List[Dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT id, name FROM provinces ORDER BY id ASC;")
            return [dict(r) for r in rows]

    async def get_cities_by_province(self, province_id: int) -> List[Dict[str, Any]]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, province_id, name FROM cities WHERE province_id = $1 ORDER BY id ASC;",
                province_id
            )
            return [dict(r) for r in rows]

    async def validate_province_and_city(self, province_id: int | None, city_id: int | None) -> bool:
        """Validates that city belongs to province."""
        if province_id is None and city_id is None:
            return True
        if province_id is None and city_id is not None:
            raise ProfileValidationError("City specified without a province.")
        if province_id is not None and city_id is None:
            # Province alone is permitted
            async with self.pool.acquire() as conn:
                exists = await conn.fetchval("SELECT EXISTS(SELECT 1 FROM provinces WHERE id = $1);", province_id)
                if not exists:
                    raise ProfileValidationError(f"Invalid province ID: {province_id}")
            return True

        async with self.pool.acquire() as conn:
            valid = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM cities WHERE id = $1 AND province_id = $2);",
                city_id, province_id
            )
            if not valid:
                raise ProfileValidationError(
                    f"City ID {city_id} does not belong to Province ID {province_id}."
                )
        return True


class ProfileService:
    """Manages user profiles with strict validation and PII masking."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.ref_service = ReferenceService(pool)

    async def get_profile(self, user_id: uuid.UUID, viewer_roles: List[str]) -> Dict[str, Any] | None:
        """
        Retrieves user profile. Masks sensitive financial and PII fields
        unless viewer has administrative privileges (SUPER_ADMIN or ADMIN).
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT p.id, p.user_id, p.first_name, p.last_name, p.national_code,
                       p.birth_date, p.gender, p.province_id, p.city_id,
                       p.address, p.postal_code, p.avatar_url,
                       p.bank_card_number, p.bank_sheba_number, p.bank_account_holder_name,
                       p.created_at, p.updated_at,
                       pr.name as province_name, ci.name as city_name,
                       u.mobile,
                       COALESCE(
                           ARRAY(SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = u.id ORDER BY ur.role_id),
                           ARRAY[]::varchar[]
                       ) AS roles
                FROM profiles p
                JOIN users u ON u.id = p.user_id
                LEFT JOIN provinces pr ON pr.id = p.province_id
                LEFT JOIN cities ci ON ci.id = p.city_id
                WHERE p.user_id = $1;
            """, user_id)

            if not row:
                return None

            data = dict(row)

            # Determine whether viewer has unmasked access
            is_admin = any(role in ("SUPER_ADMIN", "ADMIN") for role in viewer_roles)

            if not is_admin:
                # Mask PII and financial fields per PROFILE-006 and PROFILE-009
                data["national_code"] = mask_national_code(data["national_code"])
                data["mobile"] = mask_phone(data["mobile"])
                data["bank_card_number"] = mask_card_number(data["bank_card_number"])
                data["bank_sheba_number"] = mask_shaba(data["bank_sheba_number"])

            return data

    async def upsert_profile(
        self,
        user_id: uuid.UUID,
        first_name: str,
        last_name: str,
        national_code: str | None = None,
        birth_date: str | None = None,
        gender: str | None = None,
        province_id: int | None = None,
        city_id: int | None = None,
        address: str | None = None,
        postal_code: str | None = None,
        avatar_url: str | None = None,
        bank_card_number: str | None = None,
        bank_sheba_number: str | None = None,
        bank_account_holder_name: str | None = None,
    ) -> Dict[str, Any]:
        """
        Creates or updates a user profile enforcing all PRD domain invariants.
        """
        if not first_name or not first_name.strip():
            raise ProfileValidationError("First name is mandatory.")
        if not last_name or not last_name.strip():
            raise ProfileValidationError("Last name is mandatory.")

        # 1. National code validation
        clean_nc = None
        if national_code:
            clean_nc = national_code.strip()
            if not validate_iranian_national_code(clean_nc):
                raise ProfileValidationError(f"Invalid Iranian National Code: {national_code}")

        # 2. Bank card validation (optional, but must be valid Luhn if provided)
        clean_card = None
        if bank_card_number:
            clean_card = bank_card_number.replace("-", "").replace(" ", "").strip()
            if not validate_iranian_card_number(clean_card):
                raise ProfileValidationError(f"Invalid 16-digit bank card number (Luhn failure): {bank_card_number}")

        # 3. Bank Sheba validation (optional, but must be valid ISO 7064 if provided)
        clean_sheba = None
        if bank_sheba_number:
            clean_sheba = bank_sheba_number.replace(" ", "").strip().upper()
            if not validate_iranian_shaba(clean_sheba):
                raise ProfileValidationError(f"Invalid Iranian Sheba number (ISO 7064 failure): {bank_sheba_number}")

        # 4. Province and city relationship validation
        await self.ref_service.validate_province_and_city(province_id, city_id)

        # 5. Atomic Upsert in PostgreSQL
        async with self.pool.acquire() as conn:
            # Check national code uniqueness if changing
            if clean_nc:
                existing_user = await conn.fetchval(
                    "SELECT user_id FROM profiles WHERE national_code = $1 AND user_id != $2;",
                    clean_nc, user_id
                )
                if existing_user:
                    raise ProfileValidationError(f"National Code {clean_nc} is already registered to another user.")

            profile_id = await conn.fetchval("""
                INSERT INTO profiles (
                    user_id, first_name, last_name, national_code,
                    birth_date, gender, province_id, city_id,
                    address, postal_code, avatar_url,
                    bank_card_number, bank_sheba_number, bank_account_holder_name,
                    updated_at
                )
                VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7, $8,
                    $9, $10, $11,
                    $12, $13, $14,
                    NOW()
                )
                ON CONFLICT (user_id) DO UPDATE SET
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    national_code = COALESCE(EXCLUDED.national_code, profiles.national_code),
                    birth_date = COALESCE(EXCLUDED.birth_date, profiles.birth_date),
                    gender = COALESCE(EXCLUDED.gender, profiles.gender),
                    province_id = COALESCE(EXCLUDED.province_id, profiles.province_id),
                    city_id = COALESCE(EXCLUDED.city_id, profiles.city_id),
                    address = COALESCE(EXCLUDED.address, profiles.address),
                    postal_code = COALESCE(EXCLUDED.postal_code, profiles.postal_code),
                    avatar_url = COALESCE(EXCLUDED.avatar_url, profiles.avatar_url),
                    bank_card_number = COALESCE(EXCLUDED.bank_card_number, profiles.bank_card_number),
                    bank_sheba_number = COALESCE(EXCLUDED.bank_sheba_number, profiles.bank_sheba_number),
                    bank_account_holder_name = COALESCE(EXCLUDED.bank_account_holder_name, profiles.bank_account_holder_name),
                    updated_at = NOW()
                RETURNING id;
            """, user_id, first_name.strip(), last_name.strip(), clean_nc,
                 birth_date, gender, province_id, city_id,
                 address, postal_code, avatar_url,
                 clean_card, clean_sheba, bank_account_holder_name)

            return {
                "id": str(profile_id),
                "user_id": str(user_id),
                "first_name": first_name.strip(),
                "last_name": last_name.strip(),
                "national_code": clean_nc,
                "province_id": province_id,
                "city_id": city_id,
            }
