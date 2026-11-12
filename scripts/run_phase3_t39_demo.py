"""
Reproducible & Fail-Closed Local Demo Runner for HC-T39 / HC-T40 (P3-01 Hardened)
Baseline: BL-HAMICARD-PRD-V1

Security & Environment Isolation Guarantees:
1. Never forces ENVIRONMENT=test or inherits an ambient DATABASE_URL / REDIS_URL.
2. Rejects production/staging and conflicting or unrecognized APP_ENV/ENVIRONMENT/NODE_ENV.
3. Requires explicit isolated-demo DSN (`--demo-database-url` / `HAMICARD_DEMO_DATABASE_URL`)
   with local-only host and explicit `*_demo` / `*_test` DB name (prohibits `hamicard_dev`, prod, staging, shared DBs).
4. Verifies positive PostgreSQL database identity (`current_database()`) and `shobj_description`
   isolation marker (`HAMICARD_ISOLATED_DEMO_DB:<marker>`) BEFORE any SQL write.
5. Refuses to silently overwrite any existing user's password or roles; uses deterministic
   disposable synthetic demo accounts with safe marker-gated `--cleanup-demo`.
"""

import argparse
import asyncio
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.core.env import (  # noqa: E402
    EnvironmentConfigurationError,
    is_restricted_environment,
    resolve_runtime_environment,
)

ALLOWED_DEMO_DB_RE = re.compile(r"^hamicard(?:_[a-z0-9]+)*_(?:demo|test)$")
FORBIDDEN_DSN_TOKENS = ("prod", "production", "staging", "stage", "live", "master", "rds.amazonaws", "supabase", "neon.tech")
LOCAL_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
ISOLATION_MARKER_PREFIX = "HAMICARD_ISOLATED_DEMO_DB:"

DEMO_ACCOUNTS = [
    ("09999000001", ["USER"], "کاربر", "دموی ایزوله"),
    ("09999000002", ["DOCTOR"], "پزشک", "دموی ایزوله"),
    ("09999000003", ["ADMIN"], "مدیر", "دموی ایزوله"),
]
DEMO_MOBILES = [row[0] for row in DEMO_ACCOUNTS]


class DemoSafetyError(RuntimeError):
    """Raised whenever demo target validation fails closed before writing."""


def validate_demo_environment() -> str:
    try:
        canonical = resolve_runtime_environment()
        if is_restricted_environment() or canonical not in ("development", "test"):
            raise DemoSafetyError(
                f"FAIL-CLOSED DEMO: Restricted or invalid runtime environment '{canonical}' is forbidden for demo execution."
            )
    except EnvironmentConfigurationError as exc:
        raise DemoSafetyError(f"FAIL-CLOSED DEMO: {exc}") from exc
    return canonical


def validate_demo_dsn_inputs(
    demo_db_url: str | None,
    demo_redis_url: str | None,
    isolation_marker: str | None,
) -> tuple[str, str, str]:
    validate_demo_environment()

    explicit_db = (demo_db_url or os.getenv("HAMICARD_DEMO_DATABASE_URL") or "").strip()
    if not explicit_db:
        raise DemoSafetyError(
            "FAIL-CLOSED DEMO: Explicit isolated demo database URL is required via "
            "--demo-database-url or HAMICARD_DEMO_DATABASE_URL (inherited DATABASE_URL is refused)."
        )

    ambient_db = (os.getenv("DATABASE_URL") or "").strip()
    if ambient_db and ambient_db != explicit_db:
        raise DemoSafetyError(
            "FAIL-CLOSED DEMO: Ambient DATABASE_URL differs from explicit HAMICARD_DEMO_DATABASE_URL; refusing ambiguous target."
        )

    parsed_db = urlparse(explicit_db)
    if parsed_db.scheme not in ("postgresql", "postgres"):
        raise DemoSafetyError(f"FAIL-CLOSED DEMO: Unsupported database scheme '{parsed_db.scheme}'.")

    host = (parsed_db.hostname or "").strip().lower()
    if host not in LOCAL_ALLOWED_HOSTS:
        raise DemoSafetyError(
            f"FAIL-CLOSED DEMO: Non-local database host '{host}' is prohibited for synthetic demo execution."
        )

    db_name = parsed_db.path.lstrip("/").strip()
    lower_dsn = explicit_db.lower()
    if any(tok in lower_dsn for tok in FORBIDDEN_DSN_TOKENS) and not ALLOWED_DEMO_DB_RE.match(db_name):
        raise DemoSafetyError(
            f"FAIL-CLOSED DEMO: Database DSN rejected due to restricted token in target '{db_name}'."
        )

    if not ALLOWED_DEMO_DB_RE.match(db_name):
        raise DemoSafetyError(
            f"FAIL-CLOSED DEMO: Database name '{db_name}' must match explicit isolated pattern "
            "`hamicard*_demo` or `hamicard*_test` (shared `hamicard_dev` is forbidden)."
        )

    explicit_redis = (demo_redis_url or os.getenv("HAMICARD_DEMO_REDIS_URL") or "").strip()
    if not explicit_redis:
        raise DemoSafetyError(
            "FAIL-CLOSED DEMO: Explicit isolated Redis URL is required via --demo-redis-url or HAMICARD_DEMO_REDIS_URL."
        )

    ambient_redis = (os.getenv("REDIS_URL") or "").strip()
    if ambient_redis and ambient_redis != explicit_redis:
        raise DemoSafetyError(
            "FAIL-CLOSED DEMO: Ambient REDIS_URL differs from explicit HAMICARD_DEMO_REDIS_URL."
        )

    parsed_redis = urlparse(explicit_redis)
    redis_host = (parsed_redis.hostname or "").strip().lower()
    if redis_host not in LOCAL_ALLOWED_HOSTS:
        raise DemoSafetyError(f"FAIL-CLOSED DEMO: Non-local Redis host '{redis_host}' is prohibited.")

    marker = (isolation_marker or os.getenv("HAMICARD_DEMO_ISOLATION_MARKER") or "").strip()
    if len(marker) < 12 or any(bad in marker.lower() for bad in ("changeme", "default", "placeholder")):
        raise DemoSafetyError(
            "FAIL-CLOSED DEMO: Valid HAMICARD_DEMO_ISOLATION_MARKER / --isolation-marker (>=12 chars) is required."
        )

    return explicit_db, explicit_redis, marker


async def verify_positive_db_isolation(conn, expected_db_name: str, marker: str) -> None:
    actual_db = await conn.fetchval("SELECT current_database();")
    if actual_db != expected_db_name or not ALLOWED_DEMO_DB_RE.match(actual_db or ""):
        raise DemoSafetyError(
            f"FAIL-CLOSED DEMO: Positive DB identity check failed (expected='{expected_db_name}', actual='{actual_db}')."
        )

    db_comment = await conn.fetchval(
        """
        SELECT pg_catalog.shobj_description(oid, 'pg_database')
        FROM pg_catalog.pg_database
        WHERE datname = current_database();
        """
    )
    expected_comment = f"{ISOLATION_MARKER_PREFIX}{marker}"
    if db_comment != expected_comment:
        raise DemoSafetyError(
            "FAIL-CLOSED DEMO: Target database is missing the required positive isolation marker "
            f"(expected comment '{expected_comment}', got {db_comment!r}). No writes permitted."
        )


async def seed_isolated_demo_users(
    demo_db_url: str,
    demo_redis_url: str,
    marker: str,
) -> Dict[str, str]:
    import asyncpg
    import redis

    from src.core.policy import get_all_open_policy_statuses
    from src.core.security import hash_password
    from src.profiles.service import ProfileService

    expected_db_name = urlparse(demo_db_url).path.lstrip("/").strip()

    rd = redis.Redis.from_url(demo_redis_url, decode_responses=True)
    rd.ping()
    rd.close()

    demo_pass = f"Demo-{secrets.token_urlsafe(9)}!"
    pwd_hash = hash_password(demo_pass)

    pool = await asyncpg.create_pool(demo_db_url, min_size=1, max_size=3)
    try:
        profile_svc = ProfileService(pool)
        async with pool.acquire() as conn:
            await verify_positive_db_isolation(conn, expected_db_name, marker)

            statuses = await get_all_open_policy_statuses(conn)
            if len(statuses) != 18 or any(s["approval_status"] != "PROPOSED" for s in statuses):
                raise DemoSafetyError("Governance check failed: all 18 OPEN-* policies must remain PROPOSED.")

            # Refuse to silently modify or overwrite ANY pre-existing user account
            existing_rows = await conn.fetch(
                "SELECT id, mobile FROM users WHERE mobile = ANY($1::text[]);",
                DEMO_MOBILES,
            )
            if existing_rows:
                existing_mobiles = sorted(r["mobile"] for r in existing_rows)
                raise DemoSafetyError(
                    f"FAIL-CLOSED DEMO: Refusing to silently overwrite existing user account(s) {existing_mobiles}. "
                    "Run with --cleanup-demo on the isolated demo DB first."
                )

            async with conn.transaction():
                for mobile, roles, first_name, last_name in DEMO_ACCOUNTS:
                    uid = await conn.fetchval(
                        """
                        INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
                        VALUES ($1, $2, 'ACTIVE', TRUE)
                        RETURNING id;
                        """,
                        mobile,
                        pwd_hash,
                    )
                    for role in roles:
                        await conn.execute(
                            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2);",
                            uid,
                            role,
                        )
                    await conn.execute(
                        """
                        INSERT INTO profiles (user_id, first_name, last_name, province_id)
                        VALUES ($1, $2, $3, 1);
                        """,
                        uid,
                        first_name,
                        last_name,
                    )
                    if "DOCTOR" in roles:
                        await conn.execute(
                            """
                            INSERT INTO doctors (
                                user_id, medical_council_code, specialty, clinic_name,
                                province_id, city_id, clinic_address, clinic_phone,
                                verification_status
                            )
                            VALUES ($1, 'DEMO-MC-90002', 'پزشکی عمومی', 'کلینیک دموی ایزوله', 1, 1, 'تهران - دمو', '02199990002', 'APPROVED');
                            """,
                            uid,
                        )
        # Keep ProfileService referenced for governance consistency
        _ = profile_svc
    finally:
        await pool.close()

    return {
        "password": demo_pass,
        "USER": DEMO_ACCOUNTS[0][0],
        "DOCTOR": DEMO_ACCOUNTS[1][0],
        "ADMIN": DEMO_ACCOUNTS[2][0],
    }


async def cleanup_isolated_demo_users(demo_db_url: str, marker: str) -> int:
    import asyncpg

    expected_db_name = urlparse(demo_db_url).path.lstrip("/").strip()
    pool = await asyncpg.create_pool(demo_db_url, min_size=1, max_size=2)
    try:
        async with pool.acquire() as conn:
            await verify_positive_db_isolation(conn, expected_db_name, marker)
            uids = await conn.fetch(
                "SELECT id FROM users WHERE mobile = ANY($1::text[]);",
                DEMO_MOBILES,
            )
            if not uids:
                return 0
            uid_list = [r["id"] for r in uids]
            async with conn.transaction():
                await conn.execute("DELETE FROM refresh_tokens WHERE user_id = ANY($1::uuid[]);", uid_list)
                await conn.execute("DELETE FROM notifications WHERE user_id = ANY($1::uuid[]);", uid_list)
                await conn.execute("DELETE FROM doctors WHERE user_id = ANY($1::uuid[]);", uid_list)
                await conn.execute("DELETE FROM agents WHERE user_id = ANY($1::uuid[]);", uid_list)
                await conn.execute("DELETE FROM profiles WHERE user_id = ANY($1::uuid[]);", uid_list)
                await conn.execute("DELETE FROM user_roles WHERE user_id = ANY($1::uuid[]);", uid_list)
                res = await conn.execute("DELETE FROM users WHERE id = ANY($1::uuid[]);", uid_list)
                return int(res.split()[-1])
    finally:
        await pool.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run isolated & fail-closed HC-T39/HC-T40 Phase 3 local demo.")
    parser.add_argument("--demo-database-url", default=None)
    parser.add_argument("--demo-redis-url", default=None)
    parser.add_argument("--isolation-marker", default=None)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--access-ttl", type=int, default=120)
    parser.add_argument("--seed-only", action="store_true")
    parser.add_argument("--cleanup-demo", action="store_true")
    args = parser.parse_args()

    try:
        demo_db_url, demo_redis_url, marker = validate_demo_dsn_inputs(
            args.demo_database_url,
            args.demo_redis_url,
            args.isolation_marker,
        )
    except DemoSafetyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.cleanup_demo:
        deleted = asyncio.run(cleanup_isolated_demo_users(demo_db_url, marker))
        print(f"CLEANUP_OK: removed {deleted} disposable demo account(s) from isolated DB.")
        return 0

    try:
        seeded = asyncio.run(seed_isolated_demo_users(demo_db_url, demo_redis_url, marker))
    except DemoSafetyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Explicitly bind validated isolated DSNs only after passing fail-closed guards
    os.environ["DATABASE_URL"] = demo_db_url
    os.environ["REDIS_URL"] = demo_redis_url
    os.environ.setdefault("ACCESS_TOKEN_SECRET", secrets.token_hex(48))
    os.environ["ACCESS_TOKEN_TTL_SECONDS"] = str(args.access_ttl)
    os.environ["CORS_ALLOWED_ORIGINS"] = f"http://127.0.0.1:{args.port},http://localhost:{args.port}"
    os.environ.pop("COOKIE_SECURE", None)

    print("=" * 72)
    print("HamiCard Phase 3 Auth Integration Demo (HC-T40 Isolated | Non-Production)")
    print(f"UI URL        : http://{args.host}:{args.port}/phase3/")
    print(f"API Docs      : http://{args.host}:{args.port}/docs")
    print(f"Demo Password : {seeded['password']}")
    print(f"USER Mobile   : {seeded['USER']}")
    print(f"DOCTOR Mobile : {seeded['DOCTOR']} (APPROVED doctor fixture)")
    print(f"ADMIN Mobile  : {seeded['ADMIN']}")
    print("OPEN-01..18   : All 18 verified PROPOSED")
    print("=" * 72, flush=True)

    if args.seed_only:
        return 0

    import uvicorn

    from src.api.main import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
