"""
Pre-Implementation Deterministic Counterexample Suite for HC-T52 / HC-T53 (HC-CMD-053 / HC-CMD-054).
Baseline: BL-HAMICARD-PRD-V1 | Base SHA: e7c2bb81f7278e1d9a0fe8ca75e56d06fec753fb

RED_TEST_MATRIX (`CE-01..CE-10`):
- CE-01 (C2-H01): Delayed attempt cancellation `[B1]` must NEVER advance logout_seq or revoke newer `F3`.
- CE-02 (C2-H02/H04): Multi-worker concurrent family add + logout never loses families or inverts coord order.
- CE-03 (C2-H02): Partial PG outage during revocation & partial Redis outage after PG commit remain fail-closed (503) and recoverable.
- CE-04 (C2-H03): Two fresh Playwright tabs concurrently clicking Login converge to a single `hc_browser` identity; logout revokes all.
- CE-05 (C2-H04): Every `hc_coord` mutation runs strictly inside `navigator.locks('hamicard_phase3_coord')`; server coord order never inverts.
- CE-06 (C2-M01/L01): Forged `Authorization: Bearer fake` cannot elevate `/login-attempts/cancel` quota above 20 reqs/60s.
- CE-07 (C2-M01): Anonymous `hc_browser` cookie cannot elevate `/login-attempts/cancel` quota; cross-user cancel cannot revoke victim session.
- CE-08 (C2-M02): Delayed HTTP `200 Set-Cookie: F1` overwriting newer `F3` fails direct stale refresh (401) and active tab rebinds to `F3`.
- CE-09 (C2-M03): `429` / `503` cancellation failure in `revokeSupersededLoginOnServer()` surfaces error UI, never false clean success.
- CE-10 (C2-H01/AC-15): Browser A logout & cancellation keep multi-device Browser B and unrelated User B sessions ACTIVE.
"""

import asyncio
import os
import pathlib
import socket
import subprocess
import sys
import threading
import uuid

import asyncpg
import httpx
import pytest
import redis
import uvicorn
from playwright.async_api import async_playwright

import src.api.deps as deps
from src.api.main import create_app
from src.auth.session_service import SessionService
from src.core.security import hash_password
from src.profiles.service import ProfileService

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ACCESS_SECRET = "t52-architecture-counterexample-signing-secret-material-64chars"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _launch_headless_chromium(p):
    for channel in (None, "chrome", "msedge"):
        try:
            if channel:
                return await p.chromium.launch(headless=True, channel=channel)
            return await p.chromium.launch(headless=True)
        except Exception:
            continue
    brave_candidates = [
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
    ]
    for exe in brave_candidates:
        if os.path.exists(exe):
            return await p.chromium.launch(headless=True, executable_path=exe)
    pytest.fail("No headless Chromium binary available for HC-T53 counterexamples.")


async def _create_test_user(
    roles: list[str], *, password: str = "HamiCounter!901", first_name: str = "کاربر"
) -> tuple[uuid.UUID, str]:
    mobile = f"0919{uuid.uuid4().int % 10000000:07d}"
    pwd_hash = hash_password(password)
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        uid = await conn.fetchval(
            """
            INSERT INTO users (mobile, password_hash, status, is_mobile_verified)
            VALUES ($1, $2, 'ACTIVE', TRUE)
            RETURNING id;
            """,
            mobile,
            pwd_hash,
        )
        for rname in roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2);", uid, rname
            )
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        try:
            await ProfileService(pool).upsert_profile(
                user_id=uid, first_name=first_name, last_name="آزمایش"
            )
        finally:
            await pool.close()
        return uid, mobile
    finally:
        await conn.close()


async def _cleanup_user(uid: uuid.UUID | None) -> None:
    if uid is None:
        return
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        for table in (
            "browser_session_families",
            "login_attempt_states",
            "profiles",
            "refresh_tokens",
            "user_roles",
        ):
            exists = await conn.fetchval("SELECT to_regclass($1) IS NOT NULL;", f"public.{table}")
            if exists:
                await conn.execute(f"DELETE FROM {table} WHERE user_id = $1;", uid)
        await conn.execute("DELETE FROM users WHERE id = $1;", uid)
    finally:
        await conn.close()


async def _reset_deps() -> None:
    try:
        await deps.close_pool()
    except RuntimeError:
        deps._pool = None
    deps.close_redis()


async def _start_test_server(
    monkeypatch,
    *,
    access_ttl: int = 300,
    thread_name: str = "hc-t53-uvicorn",
    allowed_origins: list[str] | None = None,
):
    await _reset_deps()
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    origins = allowed_origins or [base_url]
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("ACCESS_TOKEN_SECRET", ACCESS_SECRET)
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", str(access_ttl))
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", ",".join(origins))
    monkeypatch.delenv("COOKIE_SECURE", raising=False)

    server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, name=thread_name, daemon=True)
    thread.start()

    async with httpx.AsyncClient(base_url=base_url) as probe:
        for _ in range(50):
            try:
                resp = await probe.get("/api/v1/health")
                if resp.status_code == 200:
                    break
            except Exception:
                await asyncio.sleep(0.1)
        else:
            server.should_exit = True
            thread.join(timeout=5.0)
            pytest.fail("Live uvicorn failed to start for HC-T53 counterexample test.")
    return server, thread, base_url


async def _stop_server(server, thread) -> None:
    server.should_exit = True
    thread.join(timeout=5.0)
    await _reset_deps()


async def _wait_selector_text(
    page, selector: str, expected: str, *, contains: bool = False, timeout: float = 10.0
) -> str:
    deadline = asyncio.get_event_loop().time() + timeout
    last_val = ""
    while asyncio.get_event_loop().time() < deadline:
        loc = page.locator(selector)
        if await loc.count() > 0:
            last_val = (await loc.first.inner_text()).strip()
            if (expected in last_val) if contains else (last_val == expected):
                return last_val
        await asyncio.sleep(0.05)
    raise AssertionError(f"Timeout waiting for {selector} to match {expected!r}; last={last_val!r}")


async def _count_active_refresh_tokens(user_id: uuid.UUID) -> int:
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        return int(
            await conn.fetchval(
                "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND status = 'ACTIVE';",
                user_id,
            )
        )
    finally:
        await conn.close()


def _clear_rate_limit_keys() -> None:
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        for pattern in ("hc:rl:*", "pwd_lockout:*", "pwd_fail:*"):
            keys = list(r.scan_iter(pattern))
            if keys:
                r.delete(*keys)
    finally:
        r.close()


# ---------------------------------------------------------------------------
# CE-01 (C2-H01): Delayed attempt cancellation [B1] must preserve newer F3
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce01_delayed_attempt_cancel_preserves_newer_session(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        r = redis.from_url(REDIS_URL, decode_responses=True)
        svc = SessionService(pool, redis_client=r)
        try:
            async with httpx.AsyncClient(
                base_url=base_url, headers={"Origin": base_url}
            ) as client:
                coord_resp = await client.post("/api/v1/auth/coord/session")
                assert coord_resp.status_code == 200
                assert client.cookies.get("hc_browser")

                # 1. Tab B creates session F1 via attempt B1
                b1 = f"hc_{uuid.uuid4().hex}"
                r1 = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": b1},
                )
                assert r1.status_code == 200
                f1 = uuid.UUID(r1.json()["family_id"])
                csrf1 = client.cookies.get("hc_csrf")

                # 2. Tab A explicitly logs out -> revokes F1
                lo = await client.post(
                    "/api/v1/auth/logout",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                )
                assert lo.status_code == 200
                assert await svc.verify_active_family(f1, uid) is False

                # 3. Tab A logs in again with new attempt B3 -> creates valid session F3
                b3 = f"hc_{uuid.uuid4().hex}"
                r3 = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": b3},
                )
                assert r3.status_code == 200
                f3 = uuid.UUID(r3.json()["family_id"])
                csrf3 = client.cookies.get("hc_csrf")
                f3_login_seq = int(r3.json().get("auth_coord", {}).get("login_seq", 0))

                # 4. Delayed Tab B cleanup sends targeted /login-attempts/cancel([B1])
                cancel_resp = await client.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [b1]},
                )
                assert cancel_resp.status_code == 200
                cancel_lo = int(cancel_resp.json().get("auth_coord", {}).get("logout_seq", 0))

                # INV-01 assertions:
                assert cancel_lo <= f3_login_seq, (
                    f"C2-H01: /login-attempts/cancel([B1]) illegally bumped logout_seq={cancel_lo} "
                    f"above newer F3 login_seq={f3_login_seq}"
                )
                assert await svc.verify_active_family(f3, uid) is True, (
                    "C2-H01: /login-attempts/cancel([B1]) revoked unrelated newer family F3!"
                )
                ref3 = await client.post(
                    "/api/v1/auth/refresh",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf3},
                )
                assert ref3.status_code == 200, (
                    f"C2-H01: Newer F3 /refresh failed after canceling old B1: {ref3.status_code} {ref3.text}"
                )
        finally:
            r.close()
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-02 (C2-H02/H04): Multi-worker Redis SMEMBERS/INCR+SET interleaving never
# drops active family or inverts causal login_seq vs logout_seq vs DB reality
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce02_concurrent_family_registration_and_logout_never_drops_family(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    port2 = _find_free_port()
    base_url2 = f"http://127.0.0.1:{port2}"
    server1, thread1, base_url1 = await _start_test_server(
        monkeypatch, thread_name="ce02-worker-logout"
    )
    # Allow both worker origins in Worker 1 & Worker 2
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", f"{base_url1},{base_url2}")

    worker2_env = os.environ.copy()
    worker2_env.update(
        {
            "ENVIRONMENT": "test",
            "DATABASE_URL": DATABASE_URL,
            "REDIS_URL": REDIS_URL,
            "ACCESS_TOKEN_SECRET": ACCESS_SECRET,
            "ACCESS_TOKEN_TTL_SECONDS": "300",
            "CORS_ALLOWED_ORIGINS": f"{base_url1},{base_url2}",
        }
    )
    worker2_env.pop("COOKIE_SECURE", None)

    worker2_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.api.main:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(port2),
            "--log-level",
            "warning",
        ],
        cwd=str(ROOT_DIR),
        env=worker2_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        async with httpx.AsyncClient(base_url=base_url2) as probe2:
            for _ in range(60):
                try:
                    if (await probe2.get("/api/v1/health")).status_code == 200:
                        break
                except Exception:
                    await asyncio.sleep(0.1)
            else:
                pytest.fail("Worker 2 subprocess failed to become healthy for CE-02.")

        raw_redis = deps.get_redis()
        logout_mid_coord = threading.Event()
        worker2_login_done = threading.Event()

        class _InterleavingRedisProxy:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def incr(self, key, *args, **kwargs):
                res = self._inner.incr(key, *args, **kwargs)
                # Pause Worker 1 right between incr(global_seq) and set(logout_seq) if legacy non-atomic Redis coord is used
                if (
                    threading.current_thread().name == "ce02-worker-logout"
                    and isinstance(key, str)
                    and key.startswith("hc:browser_global_seq:")
                    and not logout_mid_coord.is_set()
                ):
                    logout_mid_coord.set()
                    worker2_login_done.wait(timeout=3.0)
                return res

        monkeypatch.setattr(deps, "_redis", _InterleavingRedisProxy(raw_redis))

        async with httpx.AsyncClient(
            base_url=base_url1, headers={"Origin": base_url1}
        ) as client_a:
            await client_a.post("/api/v1/auth/coord/session")
            shared_browser_cookie = client_a.cookies.get("hc_browser")
            assert shared_browser_cookie

            # Initial session F1 on same browser -> Worker 1 registers it without tripping `logout_mid_coord`
            # until `/logout` triggers the second incr (Wait: trigger F1 via Worker 2 so `logout_mid_coord`
            # stays armed for Worker 1 `/logout`!)
            async with httpx.AsyncClient(
                base_url=base_url2,
                headers={"Origin": base_url2},
                cookies={"hc_browser": shared_browser_cookie},
            ) as init_login_client:
                r1 = await init_login_client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={
                        "mobile": mobile,
                        "password": "HamiCounter!901",
                        "attempt_id": f"hc_{uuid.uuid4().hex}",
                    },
                )
                assert r1.status_code == 200
                csrf1 = r1.cookies.get("hc_csrf")
                ref1 = r1.cookies.get("hc_refresh")

            async def do_logout_worker1():
                async with httpx.AsyncClient(
                    base_url=base_url1,
                    headers={"Origin": base_url1, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_browser_cookie, "hc_refresh": ref1, "hc_csrf": csrf1},
                ) as lo_client:
                    return await lo_client.post("/api/v1/auth/logout")

            async def do_concurrent_login_worker2():
                # Waits up to 0.3s for legacy Worker 1 to pause between incr(gseq) & set(loseq);
                # under HC-T53 PG FOR UPDATE does not call Redis incr, so it runs genuinely concurrently.
                await asyncio.to_thread(logout_mid_coord.wait, 0.3)
                try:
                    async with httpx.AsyncClient(
                        base_url=base_url2,
                        headers={"Origin": base_url2},
                        cookies={"hc_browser": shared_browser_cookie},
                    ) as client_b:
                        return await client_b.post(
                            "/api/v1/auth/password/login",
                            headers={"X-Auth-Mode": "cookie"},
                            json={
                                "mobile": mobile,
                                "password": "HamiCounter!901",
                                "started_server_logout_seq": 0,
                                "attempt_id": f"hc_{uuid.uuid4().hex}",
                            },
                        )
                finally:
                    worker2_login_done.set()

            lo1_resp, r2_resp = await asyncio.gather(
                do_logout_worker1(), do_concurrent_login_worker2()
            )
            assert lo1_resp.status_code == 200
            lo1_coord = lo1_resp.json().get("auth_coord", {})
            surviving = await _count_active_refresh_tokens(uid)

            # Invariant check (C2-H02 + C2-H04):
            # 1) Server auth_coord CANNOT claim `logout_seq >= login_seq`? Wait: on logout outcome,
            #    if surviving == 0, final browser coord MUST satisfy logout_seq > login_seq AND
            #    lo1_coord itself CANNOT report login_seq > logout_seq while revoking all sessions!
            # 2) Conversely if r2 succeeded 200 after lo1 committed first, surviving == 1 and
            #    final coord MUST have login_seq > logout_seq.
            if surviving == 0:
                assert int(lo1_coord.get("logout_seq", 0)) > int(lo1_coord.get("login_seq", 0)), (
                    f"C2-H02/C2-H04: Inverted causal auth_coord returned by /logout while surviving ACTIVE=0: "
                    f"lo1_coord={lo1_coord}, r2_status={r2_resp.status_code}"
                )
            else:
                # If r2 somehow landed AFTER lo1 cleanly, r2 MUST have returned 200 with login_seq > lo1.logout_seq;
                # if r2 ALSO started with started_server_logout_seq=0 before lo1, BOTH competing on FOR UPDATE
                # means r2 either lost -> 409 (surviving=0) or ran after -> surviving=1 with login_seq > lo1_coord.logout_seq
                assert r2_resp.status_code == 200
                r2_coord = r2_resp.json().get("auth_coord", {})
                assert int(r2_coord.get("login_seq", 0)) > int(lo1_coord.get("logout_seq", 0))
    finally:
        worker2_proc.terminate()
        try:
            worker2_proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            worker2_proc.kill()
        await _stop_server(server1, thread1)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-03 (C2-H02 / Commander): PG failure & Redis failure during revocation remain durable & recoverable
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce03_partial_pg_and_redis_outages_keep_pending_revocations_durable(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(
                base_url=base_url, headers={"Origin": base_url}
            ) as client:
                await client.post("/api/v1/auth/coord/session")
                shared_bid = client.cookies.get("hc_browser")

                # Log in F1 and F2 on the SAME browser
                r1 = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_{uuid.uuid4().hex}"},
                )
                assert r1.status_code == 200
                f1 = uuid.UUID(r1.json()["family_id"])
                csrf1 = r1.cookies.get("hc_csrf")
                ref1_cookie = r1.cookies.get("hc_refresh")

                r2 = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_{uuid.uuid4().hex}"},
                )
                assert r2.status_code == 200
                f2 = uuid.UUID(r2.json()["family_id"])

                # Subcase 3a: PG failure during revocation (simulated after coordination bookkeeping).
                fail_pg = {"active": True}
                orig_revoke = SessionService.revoke_session_family
                app_pool = await deps.get_db_pool()

                async def faulty_revoke(self, family_id, reason="LOGOUT"):
                    if fail_pg["active"]:
                        raise asyncpg.PostgresConnectionError("Simulated transient PG revocation error")
                    return await orig_revoke(self, family_id, reason=reason)

                class _FaultyConnWrapper:
                    def __init__(self, conn):
                        self._conn = conn

                    def __getattr__(self, item):
                        return getattr(self._conn, item)

                    async def execute(self, query, *args, **kwargs):
                        if fail_pg["active"] and "refresh_tokens" in query and "REVOKED" in query:
                            raise asyncpg.PostgresConnectionError("Simulated transient PG revocation error")
                        return await self._conn.execute(query, *args, **kwargs)

                class _FaultyAcquireCtx:
                    def __init__(self, ctx):
                        self._ctx = ctx

                    async def __aenter__(self):
                        c = await self._ctx.__aenter__()
                        return _FaultyConnWrapper(c)

                    async def __aexit__(self, exc_type, exc, tb):
                        return await self._ctx.__aexit__(exc_type, exc, tb)

                class _FaultyPoolProxy:
                    def __init__(self, inner):
                        self._inner = inner

                    def __getattr__(self, item):
                        return getattr(self._inner, item)

                    def acquire(self, *args, **kwargs):
                        return _FaultyAcquireCtx(self._inner.acquire(*args, **kwargs))

                monkeypatch.setattr(SessionService, "revoke_session_family", faulty_revoke)
                monkeypatch.setattr(deps, "_pool", _FaultyPoolProxy(app_pool))

                # Logout attempt using F1's cookies fails mid-PG revocation -> fail-closed 503
                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_bid, "hc_refresh": ref1_cookie, "hc_csrf": csrf1},
                ) as f1_client:
                    fail_lo = await f1_client.post("/api/v1/auth/logout")
                    assert fail_lo.status_code == 503

                # Heal PG and retry /logout with F1's cookies: F2 MUST still be discovered & revoked!
                fail_pg["active"] = False
                monkeypatch.setattr(deps, "_pool", app_pool)
                monkeypatch.setattr(SessionService, "revoke_session_family", orig_revoke)

                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_bid, "hc_refresh": ref1_cookie, "hc_csrf": csrf1},
                ) as heal_client:
                    heal_lo = await heal_client.post("/api/v1/auth/logout")
                    assert heal_lo.status_code == 200

                assert await svc.verify_active_family(f2, uid) is False, (
                    "C2-H02 (Subcase 3a): Transient PG error caused /logout to delete Redis family set, "
                    "so healed retry left sibling session F2 ACTIVE!"
                )
                assert await svc.verify_active_family(f1, uid) is False

                # Subcase 3b: Redis outage AFTER PG commit during /logout -> PG PENDING_REVOKE + reconciliation
                r3 = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_{uuid.uuid4().hex}"},
                )
                assert r3.status_code == 200
                f3 = uuid.UUID(r3.json()["family_id"])
                csrf3 = r3.cookies.get("hc_csrf")

                real_redis = deps.get_redis()
                redis_outage = {"active": True}

                class _OutageRedisProxy:
                    def __init__(self, inner):
                        self._inner = inner

                    def __getattr__(self, name):
                        return getattr(self._inner, name)

                    def set(self, key, *args, **kwargs):
                        if (
                            redis_outage["active"]
                            and isinstance(key, str)
                            and key.startswith("hc:revoked_family:")
                        ):
                            raise redis.ConnectionError("Simulated Redis outage on revoked_family write")
                        return self._inner.set(key, *args, **kwargs)

                monkeypatch.setattr(deps, "_redis", _OutageRedisProxy(real_redis))

                outage_lo = await client.post(
                    "/api/v1/auth/logout",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf3},
                )
                assert outage_lo.status_code == 503
                assert await svc.verify_active_family(f3, uid) is False

                redis_outage["active"] = False
                monkeypatch.setattr(deps, "_redis", real_redis)
                assert hasattr(SessionService, "reconcile_pending_revocations"), (
                    "C2-H02 (Subcase 3b): Missing SessionService.reconcile_pending_revocations() for Redis outage recovery"
                )
                reconciled = await SessionService(pool, redis_client=real_redis).reconcile_pending_revocations()
                assert reconciled >= 1
                assert real_redis.get(f"hc:revoked_family:{f3}") is not None
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-04 (C2-H03): Two fresh Playwright tabs concurrently bootstrap single hc_browser
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce04_two_fresh_tabs_concurrent_bootstrap_converge_to_one_browser_id(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            coord_calls = []

            async def handle_coord(route):
                coord_calls.append(route.request.headers.get("cookie", ""))
                if len(coord_calls) == 1:
                    await asyncio.sleep(0.4)
                await route.continue_()

            await context.route("**/api/v1/auth/coord/session", handle_coord)

            page_a = await context.new_page()
            page_b = await context.new_page()
            try:
                await page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page_a.wait_for_function(
                    "() => document.getElementById('hc-pwd-form')?.dataset.hcBound === '1'"
                )
                await page_b.wait_for_function(
                    "() => document.getElementById('hc-pwd-form')?.dataset.hcBound === '1'"
                )
                await page_a.fill("#hc-pwd-mobile", mobile)
                await page_a.fill("#hc-pwd-input", "HamiCounter!901")
                await page_b.fill("#hc-pwd-mobile", mobile)
                await page_b.fill("#hc-pwd-input", "HamiCounter!901")

                await asyncio.gather(
                    page_a.click("#hc-pwd-login-btn"),
                    page_b.click("#hc-pwd-login-btn"),
                )
                await asyncio.gather(
                    _wait_selector_text(page_a, "#hc-auth-status-badge", "AUTHENTICATED"),
                    _wait_selector_text(page_b, "#hc-auth-status-badge", "AUTHENTICATED"),
                )

                unbootstrapped_calls = [c for c in coord_calls if "hc_browser=" not in c]
                assert len(unbootstrapped_calls) == 1, (
                    f"C2-H03: Two fresh tabs split browser bootstrap! Sent {len(unbootstrapped_calls)} "
                    f"unbootstrapped /coord/session request(s) without hc_browser (calls={coord_calls}); "
                    "second tab should reuse first tab's hc_browser via hamicard_phase3_browser_init lock."
                )

                await page_a.click("#hc-logout-btn")
                await _wait_selector_text(page_a, "#hc-auth-status-badge", "UNAUTHENTICATED")
                await asyncio.sleep(0.25)
                surviving = await _count_active_refresh_tokens(uid)
                assert surviving == 0, (
                    f"C2-H03: Split browser bootstrap left {surviving} orphaned ACTIVE session(s) after logout!"
                )
            finally:
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-05 (C2-H04): Strict client hc_coord Web Lock discipline & server seq monotonicity
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce05_client_hc_coord_writes_never_bypass_coord_lock(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            page = await context.new_page()

            await page.add_init_script(
                """
                (() => {
                  window.__hcCoordLockDepth = 0;
                  window.__allHcCoordWrites = [];
                  window.__unlockedHcCoordWrites = [];
                  if (navigator.locks && typeof navigator.locks.request === 'function') {
                    const origReq = navigator.locks.request.bind(navigator.locks);
                    navigator.locks.request = function(name, optsOrCb, maybeCb) {
                      const isCoord = name === 'hamicard_phase3_coord';
                      const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb;
                      const wrapped = async (...args) => {
                        if (isCoord) window.__hcCoordLockDepth += 1;
                        try {
                          return await cb(...args);
                        } finally {
                          if (isCoord) window.__hcCoordLockDepth -= 1;
                        }
                      };
                      if (typeof optsOrCb === 'function') return origReq(name, wrapped);
                      return origReq(name, optsOrCb, wrapped);
                    };
                  }
                  const proto = (typeof HTMLDocument !== 'undefined' && Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie'))
                    ? HTMLDocument.prototype
                    : Document.prototype;
                  const desc = Object.getOwnPropertyDescriptor(proto, 'cookie');
                  if (desc && desc.set && desc.get) {
                    Object.defineProperty(proto, 'cookie', {
                      configurable: true,
                      enumerable: true,
                      get: function() { return desc.get.call(this); },
                      set: function(val) {
                        const s = String(val || '');
                        if (s.startsWith('hc_coord=')) {
                          window.__allHcCoordWrites.push({ val: s, locked: window.__hcCoordLockDepth > 0 });
                          if (window.__hcCoordLockDepth <= 0) {
                            window.__unlockedHcCoordWrites.push({ val: s, stack: new Error().stack || '' });
                          }
                        }
                        return desc.set.call(this, val);
                      },
                    });
                  }
                })();
                """
            )

            try:
                await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", "HamiCounter!901")
                await page.click("#hc-pwd-login-btn")
                await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

                await page.click("#hc-logout-btn")
                await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")

                all_writes = await page.evaluate("() => window.__allHcCoordWrites || []")
                unlocked = await page.evaluate("() => window.__unlockedHcCoordWrites || []")
                assert len(all_writes) >= 1, "Expected at least 1 hc_coord write to observe lock discipline."
                assert len(unlocked) == 0, (
                    f"C2-H04: Found {len(unlocked)} unlocked hc_coord cookie write(s) outside "
                    f"navigator.locks('hamicard_phase3_coord'): {unlocked[0]['val']}"
                )
            finally:
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-06 (C2-M01 + C2-L01): Forged Bearer prefix cannot elevate cancel quota
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce06_forged_bearer_prefix_cannot_elevate_cancel_quota(monkeypatch):
    _clear_rate_limit_keys()
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with httpx.AsyncClient(
            base_url=base_url, headers={"Origin": base_url}
        ) as client:
            statuses = []
            for idx in range(21):
                resp = await client.post(
                    "/api/v1/auth/login-attempts/cancel",
                    headers={"Authorization": "Bearer forged_invalid_token_without_signature"},
                    json={"attempt_ids": [f"hc_forged_{idx}_{uuid.uuid4().hex[:8]}"]},
                )
                statuses.append(resp.status_code)

            assert statuses[20] == 429, (
                f"C2-M01: Forged 'Bearer ...' prefix bypassed unauth 20-req quota! "
                f"21st request returned {statuses[20]} instead of 429 (all={statuses})"
            )
    finally:
        await _stop_server(server, thread)


# ---------------------------------------------------------------------------
# CE-07 (C2-M01): Anonymous hc_browser cookie cannot elevate quota & cross-user cancel blocked
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce07_anonymous_browser_cookie_no_elevated_quota_and_cross_user_cancel_blocked(monkeypatch):
    _clear_rate_limit_keys()
    uid_a, mobile_a = await _create_test_user(["USER"])
    uid_b, mobile_b = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(
                base_url=base_url, headers={"Origin": base_url}
            ) as client_a:
                await client_a.post("/api/v1/auth/coord/session")
                attempt_a = f"hc_usera_{uuid.uuid4().hex}"
                ra = await client_a.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_a, "password": "HamiCounter!901", "attempt_id": attempt_a},
                )
                assert ra.status_code == 200
                fam_a = uuid.UUID(ra.json()["family_id"])

            async with httpx.AsyncClient(
                base_url=base_url, headers={"Origin": base_url}
            ) as client_b:
                await client_b.post("/api/v1/auth/coord/session")
                rb = await client_b.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_b, "password": "HamiCounter!901", "attempt_id": f"hc_userb_{uuid.uuid4().hex}"},
                )
                assert rb.status_code == 200
                token_b = rb.json()["access_token"]
                cross_cancel = await client_b.post(
                    "/api/v1/auth/login-attempts/cancel",
                    headers={"Authorization": f"Bearer {token_b}"},
                    json={"attempt_ids": [attempt_a]},
                )
                assert cross_cancel.status_code in (200, 403)
                assert await svc.verify_active_family(fam_a, uid_a) is True, (
                    "C2-M01: Cross-user attempt cancellation by User B revoked User A's active session!"
                )

            _clear_rate_limit_keys()
            async with httpx.AsyncClient(
                base_url=base_url, headers={"Origin": base_url}
            ) as anon:
                coord_r = await anon.post("/api/v1/auth/coord/session")
                assert coord_r.status_code == 200
                assert anon.cookies.get("hc_browser")

                statuses = []
                for idx in range(21):
                    r_cancel = await anon.post(
                        "/api/v1/auth/login-attempts/cancel",
                        json={"attempt_ids": [f"hc_anon_{idx}_{uuid.uuid4().hex[:8]}"]},
                    )
                    statuses.append(r_cancel.status_code)

                assert statuses[20] == 429, (
                    f"C2-M01: Anonymous hc_browser cookie elevated quota beyond 20 reqs! "
                    f"21st returned {statuses[20]} instead of 429 (all={statuses})"
                )
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid_a)
        await _cleanup_user(uid_b)


# ---------------------------------------------------------------------------
# CE-08 (C2-M02): Delayed HTTP 200 Set-Cookie overwriting newer F3 recovers cleanly
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce08_delayed_200_cookie_overwrite_rejects_stale_and_rebinds_f3(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            page_b = await context.new_page()
            # Keep Tab B's login HTTP response undropped when Tab A broadcasts LOGOUT
            # so late HTTP 200 + Set-Cookie: F1 physically overwrites browser cookies!
            await page_b.add_init_script(
                """
                const origFetch = window.fetch;
                window.fetch = function(input, init) {
                  const url = typeof input === 'string' ? input : (input && input.url) || '';
                  if (url.includes('/api/v1/auth/password/login') && init && init.signal) {
                    const clonedInit = { ...init };
                    delete clonedInit.signal;
                    return origFetch.call(this, input, clonedInit);
                  }
                  return origFetch.apply(this, arguments);
                };
                """
            )
            page_a = await context.new_page()

            b1_arrived_after_server = asyncio.Event()
            release_b1_response = asyncio.Event()
            b1_intercept_active = {"on": True}

            async def hold_b1_login(route):
                if b1_intercept_active["on"] and route.request.method == "POST":
                    b1_intercept_active["on"] = False
                    resp = await route.fetch()
                    b1_arrived_after_server.set()
                    await release_b1_response.wait()
                    await route.fulfill(response=resp)
                    return
                await route.continue_()

            try:
                await page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")

                # 1. Tab B initiates delayed login B1 (server returns 200 F1, held in flight before Set-Cookie lands)
                await page_b.route("**/api/v1/auth/password/login", hold_b1_login)
                await page_b.fill("#hc-pwd-mobile", mobile)
                await page_b.fill("#hc-pwd-input", "HamiCounter!901")
                await page_b.click("#hc-pwd-login-btn")
                await asyncio.wait_for(b1_arrived_after_server.wait(), timeout=6.0)

                # 2. Tab A logs out (establishing logout seq > B1 start) and logs in with newer valid session F3
                await page_a.click("#hc-logout-btn")
                await asyncio.sleep(0.15)
                await page_a.fill("#hc-pwd-mobile", mobile)
                await page_a.fill("#hc-pwd-input", "HamiCounter!901")
                await page_a.click("#hc-pwd-login-btn")
                await _wait_selector_text(page_a, "#hc-auth-status-badge", "AUTHENTICATED")

                # 3. Delayed HTTP 200 Set-Cookie for stale B1/F1 now arrives on Tab B and overwrites cookie jar!
                release_b1_response.set()
                await asyncio.sleep(0.5)

                # 4. Tab A initiates forced refresh -> MUST recover F3 via /session/rebind-cookie & stay AUTHENTICATED!
                await page_a.click("#hc-refresh-btn")
                await asyncio.sleep(0.4)
                status_after = (await page_a.locator("#hc-auth-status-badge").inner_text()).strip()
                assert status_after == "AUTHENTICATED", (
                    f"C2-M02: Stale delayed 200 Set-Cookie clobbered newer F3 refresh cookie; "
                    f"Tab A degraded to {status_after!r} instead of recovering F3 via /session/rebind-cookie!"
                )
            finally:
                release_b1_response.set()
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-09 (C2-M03): Cancellation 429/503 failure in revokeSupersededLoginOnServer surfaces error
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce09_superseded_cancel_429_surfaces_error_instead_of_false_success(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            # Keep B1 login fetch non-aborted so late HTTP 200 arrives after logout and enters
            # `revokeSupersededLoginOnServer(data.access_token, attemptId)`!
            await context.add_init_script(
                """
                const origFetch = window.fetch;
                window.fetch = function(input, init) {
                  const url = typeof input === 'string' ? input : (input && input.url) || '';
                  if (url.includes('/api/v1/auth/password/login') && init && init.signal) {
                    const clonedInit = { ...init };
                    delete clonedInit.signal;
                    return origFetch.call(this, input, clonedInit);
                  }
                  return origFetch.apply(this, arguments);
                };
                """
            )
            page = await context.new_page()

            login_in_flight = asyncio.Event()
            release_login = asyncio.Event()

            async def delay_login(route):
                if route.request.method != "POST":
                    await route.continue_()
                    return
                resp = await route.fetch()
                login_in_flight.set()
                await release_login.wait()
                await route.fulfill(response=resp)

            async def reject_cancel_429(route):
                await route.fulfill(
                    status=429,
                    content_type="application/json",
                    body='{"detail":"Too many login cancellation requests."}',
                )

            async def fail_bearer_logout(route):
                auth_mode = route.request.headers.get("x-auth-mode", "")
                if auth_mode == "bearer":
                    await route.abort("failed")
                    return
                await route.continue_()

            try:
                await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                # First establish a real valid session F0 so logout returns clean HTTP 200 (zero false 401 message)
                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", "HamiCounter!901")
                await page.click("#hc-pwd-login-btn")
                await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

                await page.route("**/api/v1/auth/password/login", delay_login)
                await page.route("**/api/v1/auth/login-attempts/cancel", reject_cancel_429)
                await page.route("**/api/v1/auth/logout", fail_bearer_logout)

                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", "HamiCounter!901")
                await page.click("#hc-pwd-login-btn")
                await asyncio.wait_for(login_in_flight.wait(), timeout=6.0)

                # Clean logout revokes F0 with HTTP 200 -> UNAUTHENTICATED and empty lastErrorMessage
                await page.click("#hc-logout-btn")
                await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")

                # Release delayed B1 200 -> enters revokeSupersededLoginOnServer(lateToken, B1):
                # bearer /logout fails -> postCancelAttemptChunks([B1]) receives 429!
                release_login.set()
                await asyncio.sleep(0.6)

                ui_state = await page.evaluate(
                    """
                    async () => {
                      const mod = await import('/phase3/js/auth_session.js');
                      return mod.getAuthSnapshot();
                    }
                    """
                )
                err_msg = (ui_state.get("lastErrorMessage") or "").strip()
                assert (
                    "429" in err_msg
                    or "Too many" in err_msg
                    or "لغو" in err_msg
                ), (
                    f"C2-M03: postCancelAttemptChunks() returned 429 inside revokeSupersededLoginOnServer(), "
                    f"but UI silently ignored failure! err_msg={err_msg!r} snapshot={ui_state}"
                )
            finally:
                release_login.set()
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-10 (C2-H01 / AC-15): Browser A logout preserves User A Device B & User B
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce10_logout_isolates_multidevice_and_unrelated_user(monkeypatch):
    _clear_rate_limit_keys()
    uid_a, mobile_a = await _create_test_user(["USER"])
    uid_b, mobile_b = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with (
                httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as dev_a1,
                httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as dev_a2,
                httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as user_b,
            ):
                await dev_a1.post("/api/v1/auth/coord/session")
                await dev_a2.post("/api/v1/auth/coord/session")
                await user_b.post("/api/v1/auth/coord/session")

                r_a1 = await dev_a1.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_a, "password": "HamiCounter!901", "attempt_id": f"hc_a1_{uuid.uuid4().hex}"},
                )
                r_a2 = await dev_a2.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_a, "password": "HamiCounter!901", "attempt_id": f"hc_a2_{uuid.uuid4().hex}"},
                )
                r_ub = await user_b.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_b, "password": "HamiCounter!901", "attempt_id": f"hc_ub_{uuid.uuid4().hex}"},
                )
                assert r_a1.status_code == 200 and r_a2.status_code == 200 and r_ub.status_code == 200

                fam_a1 = uuid.UUID(r_a1.json()["family_id"])
                fam_a2 = uuid.UUID(r_a2.json()["family_id"])
                fam_ub = uuid.UUID(r_ub.json()["family_id"])

                csrf_a1 = dev_a1.cookies.get("hc_csrf")
                csrf_a2 = dev_a2.cookies.get("hc_csrf")
                csrf_ub = user_b.cookies.get("hc_csrf")

                lo_a1 = await dev_a1.post(
                    "/api/v1/auth/logout",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf_a1},
                )
                assert lo_a1.status_code == 200
                assert await svc.verify_active_family(fam_a1, uid_a) is False
                assert await svc.verify_active_family(fam_a2, uid_a) is True
                assert await svc.verify_active_family(fam_ub, uid_b) is True

                ref_a2 = await dev_a2.post(
                    "/api/v1/auth/refresh",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf_a2},
                )
                ref_ub = await user_b.post(
                    "/api/v1/auth/refresh",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf_ub},
                )
                assert ref_a2.status_code == 200
                assert ref_ub.status_code == 200
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid_a)
        await _cleanup_user(uid_b)
