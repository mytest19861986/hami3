"""
Reproducible Local Non-Production Demo Runner for HC-T39 (Phase 3 Auth + UI Shell)
Baseline: BL-HAMICARD-PRD-V1

Launches the integrated `/phase3/` UI Shell + hardened HC-T38 cookie/CSRF/RBAC backend
on http://127.0.0.1:8000 using synthetic non-production accounts only.
Does NOT activate live SMS, payments, real customer data, or approve any OPEN-* policies.
"""

import argparse
import asyncio
import os
import secrets
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def _configure_demo_env(port: int, access_ttl: int) -> None:
    os.environ["ENVIRONMENT"] = "test"
    os.environ.setdefault("DATABASE_URL", "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev")
    os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
    os.environ.setdefault("ACCESS_TOKEN_SECRET", secrets.token_hex(48))
    os.environ["ACCESS_TOKEN_TTL_SECONDS"] = str(access_ttl)
    os.environ["CORS_ALLOWED_ORIGINS"] = f"http://127.0.0.1:{port},http://localhost:{port}"
    os.environ.pop("COOKIE_SECURE", None)


async def seed_synthetic_demo_users() -> dict[str, str]:
    import asyncpg
    import redis

    from src.core.policy import get_all_open_policy_statuses
    from src.core.security import hash_password
    from src.profiles.service import ProfileService

    dsn = os.environ["DATABASE_URL"]
    redis_url = os.environ["REDIS_URL"]

    rd = redis.Redis.from_url(redis_url, decode_responses=True)
    rd.ping()
    rd.close()

    demo_pass = f"Demo-{secrets.token_urlsafe(9)}!"
    pwd_hash = hash_password(demo_pass)

    accounts = [
        ("09900000001", ["USER"], "کاربر", "نمونه تستی"),
        ("09900000002", ["DOCTOR"], "پزشک", "نمونه تستی"),
        ("09900000003", ["ADMIN"], "مدیر", "نمونه تستی"),
    ]

    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=3)
    try:
        profile_svc = ProfileService(pool)
        async with pool.acquire() as conn:
            statuses = await get_all_open_policy_statuses(conn)
            if len(statuses) != 18 or any(s["approval_status"] != "PROPOSED" for s in statuses):
                raise RuntimeError("Governance check failed: all 18 OPEN-* policies must remain PROPOSED.")

            for mobile, roles, first_name, last_name in accounts:
                uid = await conn.fetchval("SELECT id FROM users WHERE mobile = $1;", mobile)
                if uid is None:
                    uid = await conn.fetchval(
                        """
                        INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
                        VALUES ($1, $2, 'ACTIVE', TRUE)
                        RETURNING id;
                        """,
                        mobile,
                        pwd_hash,
                    )
                else:
                    await conn.execute(
                        "UPDATE users SET password_hash = $2, status = 'ACTIVE', is_mobile_verified = TRUE WHERE id = $1;",
                        uid,
                        pwd_hash,
                    )
                for role in roles:
                    await conn.execute(
                        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;",
                        uid,
                        role,
                    )
                await profile_svc.upsert_profile(
                    user_id=uid,
                    first_name=first_name,
                    last_name=last_name,
                    province_id=1,
                )
    finally:
        await pool.close()

    return {
        "password": demo_pass,
        "USER": "09900000001",
        "DOCTOR": "09900000002",
        "ADMIN": "09900000003",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reproducible HC-T39 Phase 3 Auth local demo.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--access-ttl", type=int, default=120)
    parser.add_argument("--seed-only", action="store_true", help="Seed synthetic accounts and exit without starting server.")
    args = parser.parse_args()

    _configure_demo_env(args.port, args.access_ttl)
    seeded = asyncio.run(seed_synthetic_demo_users())

    print("=" * 72)
    print("HamiCard Phase 3 Auth Integration Demo (HC-T39 | Non-Production)")
    print(f"UI URL        : http://{args.host}:{args.port}/phase3/")
    print(f"API Docs      : http://{args.host}:{args.port}/docs")
    print(f"Demo Password : {seeded['password']}")
    print(f"USER Mobile   : {seeded['USER']} (allowed: #/panel/user, forbidden 403: #/panel/admin)")
    print(f"DOCTOR Mobile : {seeded['DOCTOR']} (allowed: #/panel/doctor)")
    print(f"ADMIN Mobile  : {seeded['ADMIN']} (allowed: #/panel/admin, #/panel/user)")
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
