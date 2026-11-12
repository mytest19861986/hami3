"""
Pre-Implementation Deterministic Counterexample Suite for HC-T52 / HC-T53 (HC-CMD-053 / HC-CMD-054).
Baseline: BL-HAMICARD-PRD-V1 | Base SHA: e7c2bb81f7278e1d9a0fe8ca75e56d06fec753fb
Revision: HC-T52 Revision 1 (addresses R2-T52-V4-F01..F08 + Test Audit)

RED_TEST_MATRIX (`CE-01..CE-13`):
- CE-01  (C2-H01): Delayed attempt cancellation `[B1]` never advances logout_seq or revokes newer `F3`.
- CE-02  (C2-H02/H04/F01): Pre-logout server-started attempt racing `/logout` always leaves 0 active tokens & valid PG order.
- CE-03a (C2-H02/F06): Partial PG outage mid-revocation fails 503, preserves ACTIVE rows, and heals on retry.
- CE-03b (C2-H02/F06): Redis outage after PG commit leaves PENDING_REVOKE durable; concurrent dual reconcilers (SKIP LOCKED) promote 100%.
- CE-04  (C2-H03): Two fresh Playwright tabs concurrently clicking Login converge to 1 `hc_browser`; logout revokes all.
- CE-05  (C2-H04): Every `hc_coord` write runs strictly inside `navigator.locks('hamicard_phase3_coord')`.
- CE-06  (C2-M01/L01): Forged `Authorization: Bearer fake` cannot elevate `/login-attempts/cancel` quota above 20 reqs/60s.
- CE-07a (C2-M01/F02): Cross-user AND anonymous same-browser (no capability) cancel against bound session blocked (403); capability succeeds.
- CE-07b (C2-M01): Anonymous `hc_browser` cookie gets unauth 20 req quota & <= 120s tombstone TTL.
- CE-08  (C2-M02/F04/F05): Delayed 200 cookie overwrite rejects stale F1 (401) & rebinds F3 even when BroadcastChannel is blocked.
- CE-08b (C2-M02/F04/F05): Adversarial `/session/rebind-cookie` matrix (expired, bad origin, wrong browser, old family, logout race, concurrent refresh).
- CE-09  (C2-M03): Both 429 & 503 cancellation failures preserve `canRetryLogout`, `unresolvedAttemptCount >= 1`, and error copy.
- CE-10  (C2-H01/AC-15): Browser A logout/cancel keeps multi-device Browser B and unrelated User B sessions ACTIVE.
- CE-11  (F01/F03): Forged `started_server_logout_seq=999` bypass (pwd + OTP) rejected 409; concurrent duplicate `attempt_id` creates <= 1 family.
- CE-12  (F08): Continuous Lua ZSET sliding-window boundary + 429 non-pollution + weighted IDs (64 cap) + Redis 503 fail-closed.
- CE-13  (F07): Missing `navigator.locks` + forged `bi=1` hint fails closed rather than running unlocked cross-tab race.
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

import src.api.auth as auth_mod
import src.api.deps as deps
from src.api.main import create_app
from src.auth.otp_service import OtpService
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
            "login_attempt_states",
            "browser_session_families",
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
        for pattern in ("hc:rl:*", "pwd_lockout:*", "pwd_fail:*", "otp:rl:*", "otp:code:*"):
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
                tok3 = r3.json()["access_token"]
                f3_login_seq = int(r3.json().get("auth_coord", {}).get("login_seq", 0))

                # 4. Delayed Tab B cleanup sends targeted /login-attempts/cancel([B1]) as same user F3
                cancel_resp = await client.post(
                    "/api/v1/auth/login-attempts/cancel",
                    headers={"Authorization": f"Bearer {tok3}"},
                    json={"attempt_ids": [b1]},
                )
                assert cancel_resp.status_code == 200
                cancel_lo = int(cancel_resp.json().get("auth_coord", {}).get("logout_seq", 0))

                # INV-01 assertions:
                assert cancel_lo <= f3_login_seq, (
                    f"C2-H01: /login-attempts/cancel([B1]) illegally bumped logout_seq={cancel_lo} "
                    f"above newer F3 login_seq={f3_login_seq}"
                )
                assert await svc.verify_active_family(f1, uid) is False
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
# CE-02 (C2-H02/H04/F01): Pre-logout attempt racing /logout NEVER survives
# and always maintains strict PG causal ordering + REVOKED status
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce02_pre_logout_attempt_racing_logout_never_survives_or_inverts_coord(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    port2 = _find_free_port()
    base_url2 = f"http://127.0.0.1:{port2}"
    server1, thread1, base_url1 = await _start_test_server(
        monkeypatch, thread_name="ce02-worker-logout"
    )
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

            # Initial session F1 on same browser via Worker 2
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

            # Register Worker 2 attempt B2 BEFORE /logout begins!
            b2_attempt = f"hc_b2_{uuid.uuid4().hex}"
            async with httpx.AsyncClient(
                base_url=base_url2,
                headers={"Origin": base_url2},
                cookies={"hc_browser": shared_browser_cookie},
            ) as start_client:
                start_resp = await start_client.post(
                    "/api/v1/auth/login-attempts/start",
                    json={"attempt_id": b2_attempt, "flow": "PASSWORD"},
                )
                if start_resp.status_code == 200:
                    assert start_resp.json()["started_logout_seq"] == 0

            async def do_logout_worker1():
                async with httpx.AsyncClient(
                    base_url=base_url1,
                    headers={"Origin": base_url1, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_browser_cookie, "hc_refresh": ref1, "hc_csrf": csrf1},
                ) as lo_client:
                    return await lo_client.post("/api/v1/auth/logout")

            async def do_concurrent_login_worker2():
                await asyncio.to_thread(logout_mid_coord.wait, 0.2)
                try:
                    async with httpx.AsyncClient(
                        base_url=base_url2,
                        headers={"Origin": base_url2},
                        cookies={"hc_browser": shared_browser_cookie},
                    ) as client_b:
                        body = {
                            "mobile": mobile,
                            "password": "HamiCounter!901",
                            "attempt_id": b2_attempt,
                        }
                        if start_resp.status_code != 200:
                            body["started_server_logout_seq"] = 0
                        return await client_b.post(
                            "/api/v1/auth/password/login",
                            headers={"X-Auth-Mode": "cookie"},
                            json=body,
                        )
                finally:
                    worker2_login_done.set()

            lo1_resp, r2_resp = await asyncio.gather(
                do_logout_worker1(), do_concurrent_login_worker2()
            )
            assert lo1_resp.status_code == 200
            lo1_coord = lo1_resp.json().get("auth_coord", {})
            surviving = await _count_active_refresh_tokens(uid)

            # Because B2 genuinely started BEFORE /logout (started_logout_seq=0), NO schedule
            # is permitted to leave B2 surviving after /logout completed!
            assert surviving == 0, (
                f"C2-H02/F01: Pre-logout attempt B2 leaked {surviving} surviving ACTIVE session(s) after /logout! "
                f"(r2_status={r2_resp.status_code}, lo1_coord={lo1_coord})"
            )
            assert int(lo1_coord.get("logout_seq", 0)) > int(lo1_coord.get("login_seq", 0)), (
                f"C2-H04: Inverted causal auth_coord returned by /logout while surviving=0: {lo1_coord}"
            )
            if r2_resp.status_code == 200:
                r2_coord = r2_resp.json().get("auth_coord", {})
                assert int(lo1_coord.get("logout_seq", 0)) > int(r2_coord.get("login_seq", 0)), (
                    f"C2-H04: /password/login returned 200 after logout committed! lo1={lo1_coord}, r2={r2_coord}"
                )
            else:
                assert r2_resp.status_code == 409

            conn = await asyncpg.connect(DATABASE_URL)
            try:
                has_bsf = await conn.fetchval(
                    "SELECT to_regclass('public.browser_session_families') IS NOT NULL;"
                )
                assert has_bsf, "T52/T53 SSOT table browser_session_families must exist."
                non_revoked_fams = await conn.fetchval(
                    "SELECT COUNT(*) FROM browser_session_families WHERE user_id = $1 AND status != 'REVOKED';",
                    uid,
                )
                assert non_revoked_fams == 0
                if start_resp.status_code == 200:
                    start_seq_stored = await conn.fetchval(
                        "SELECT started_logout_seq FROM login_attempt_states WHERE attempt_id = $1;",
                        b2_attempt,
                    )
                    assert start_seq_stored == 0
            finally:
                await conn.close()
    finally:
        worker2_proc.terminate()
        try:
            worker2_proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            worker2_proc.kill()
        await _stop_server(server1, thread1)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-03a (C2-H02/F06): PG failure mid-revocation fails closed 503, keeps rows
# intact in PG discovery state, and heals cleanly on retry
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce03a_pg_revocation_outage_remains_durable_and_fails_closed(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client1, httpx.AsyncClient(
                base_url=base_url, headers={"Origin": base_url}
            ) as client2:
                await client1.post("/api/v1/auth/coord/session")
                shared_bid = client1.cookies.get("hc_browser")
                r1 = await client1.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_{uuid.uuid4().hex}"},
                )
                assert r1.status_code == 200
                f1 = uuid.UUID(r1.json()["family_id"])
                csrf1 = r1.cookies.get("hc_csrf")
                ref1_cookie = r1.cookies.get("hc_refresh")

                a2 = f"hc_a2_{uuid.uuid4().hex}"
                r2 = await client2.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a2},
                )
                assert r2.status_code == 200
                f2 = uuid.UUID(r2.json()["family_id"])

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
                        return _FaultyConnWrapper(await self._ctx.__aenter__())

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

                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_bid, "hc_refresh": ref1_cookie, "hc_csrf": csrf1},
                ) as f1_client:
                    fail_lo = await f1_client.post(
                        "/api/v1/auth/logout",
                        json={"cancelled_login_attempt_ids": [a2]},
                    )
                    assert fail_lo.status_code == 503

                # PG discovery state MUST still preserve BOTH F1 & F2 as ACTIVE until retry commits!
                assert await svc.verify_active_family(f1, uid) is True
                assert await svc.verify_active_family(f2, uid) is True

                fail_pg["active"] = False
                monkeypatch.setattr(deps, "_pool", app_pool)
                monkeypatch.setattr(SessionService, "revoke_session_family", orig_revoke)

                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_bid, "hc_refresh": ref1_cookie, "hc_csrf": csrf1},
                ) as heal_client:
                    heal_lo = await heal_client.post(
                        "/api/v1/auth/logout",
                        json={"cancelled_login_attempt_ids": [a2]},
                    )
                    assert heal_lo.status_code == 200

                assert await svc.verify_active_family(f1, uid) is False
                assert await svc.verify_active_family(f2, uid) is False
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-03b (C2-H02/F06): Redis outage after PG commit leaves PENDING_REVOKE
# durable and concurrent reconcilers promote 100% with SKIP LOCKED
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce03b_redis_outage_durable_pending_and_concurrent_reconcilers(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    seeded_fids: list[uuid.UUID] = []
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=6)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
                await client.post("/api/v1/auth/coord/session")
                shared_bid = client.cookies.get("hc_browser")
                r_login = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_{uuid.uuid4().hex}"},
                )
                assert r_login.status_code == 200
                f3 = uuid.UUID(r_login.json()["family_id"])
                csrf3 = r_login.cookies.get("hc_csrf")
                tok3 = r_login.json()["access_token"]

                real_redis = deps.get_redis()
                redis_outage = {"active": True}

                class _OutageRedisProxy:
                    def __init__(self, inner):
                        self._inner = inner

                    def __getattr__(self, name):
                        return getattr(self._inner, name)

                    def set(self, key, *args, **kwargs):
                        if redis_outage["active"] and isinstance(key, str) and key.startswith("hc:revoked_family:"):
                            raise redis.ConnectionError("Simulated Redis outage on revoked_family SET")
                        return self._inner.set(key, *args, **kwargs)

                    def setex(self, key, *args, **kwargs):
                        if redis_outage["active"] and isinstance(key, str) and key.startswith("hc:revoked_family:"):
                            raise redis.ConnectionError("Simulated Redis outage on revoked_family SETEX")
                        return self._inner.setex(key, *args, **kwargs)

                    def get(self, key, *args, **kwargs):
                        if redis_outage["active"] and isinstance(key, str) and key.startswith("hc:revoked_family:"):
                            raise redis.ConnectionError("Simulated Redis outage on revoked_family GET")
                        return self._inner.get(key, *args, **kwargs)

                    def exists(self, key, *args, **kwargs):
                        if redis_outage["active"] and isinstance(key, str) and key.startswith("hc:revoked_family:"):
                            raise redis.ConnectionError("Simulated Redis outage on revoked_family EXISTS")
                        return self._inner.exists(key, *args, **kwargs)

                monkeypatch.setattr(deps, "_redis", _OutageRedisProxy(real_redis))

                # 1. Logout during Redis outage -> fails closed 503
                outage_lo = await client.post(
                    "/api/v1/auth/logout",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf3},
                )
                assert outage_lo.status_code == 503

                # 2. Protected Bearer endpoint ALSO fails closed 503 while Redis down
                prof_503 = await client.get(
                    "/api/v1/profile/me",
                    headers={"Authorization": f"Bearer {tok3}"},
                )
                assert prof_503.status_code == 503

                # 3. Verify PG state BEFORE reconciliation: refresh_tokens REVOKED, BSF PENDING_REVOKE
                conn = await asyncpg.connect(DATABASE_URL)
                try:
                    assert (
                        await conn.fetchval(
                            "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND status = 'ACTIVE';",
                            f3,
                        )
                        == 0
                    )
                    has_bsf = await conn.fetchval(
                        "SELECT to_regclass('public.browser_session_families') IS NOT NULL;"
                    )
                    assert has_bsf, "C2-H02: browser_session_families table missing."
                    bsf_status = await conn.fetchval(
                        "SELECT status FROM browser_session_families WHERE family_id = $1;",
                        f3,
                    )
                    assert bsf_status == "PENDING_REVOKE", f"Expected PENDING_REVOKE before recovery, got {bsf_status!r}"

                    # Seed 5 additional PENDING_REVOKE rows to prove dual concurrent reconcilers cannot drop/collide
                    for idx in range(5):
                        extra_fid = uuid.uuid4()
                        seeded_fids.append(extra_fid)
                        await conn.execute(
                            """
                            INSERT INTO browser_session_families (family_id, browser_id, user_id, created_seq, status, revoke_reason)
                            VALUES ($1, $2, $3, $4, 'PENDING_REVOKE', 'LOGOUT');
                            """,
                            extra_fid,
                            shared_bid,
                            uid,
                            100 + idx,
                        )
                finally:
                    await conn.close()

                # 4. Heal Redis & run TWO concurrent reconcile_pending_revocations workers!
                redis_outage["active"] = False
                monkeypatch.setattr(deps, "_redis", real_redis)
                assert hasattr(SessionService, "reconcile_pending_revocations")

                svc_w1 = SessionService(pool, redis_client=real_redis)
                svc_w2 = SessionService(pool, redis_client=real_redis)
                c1, c2 = await asyncio.gather(
                    svc_w1.reconcile_pending_revocations(batch_size=2),
                    svc_w2.reconcile_pending_revocations(batch_size=2),
                )
                assert (c1 + c2) >= 6, f"Expected >= 6 reconciled PENDING_REVOKE rows, got c1={c1}, c2={c2}"

                all_fids = [f3, *seeded_fids]
                conn = await asyncpg.connect(DATABASE_URL)
                try:
                    statuses = await conn.fetch(
                        "SELECT family_id, status FROM browser_session_families WHERE family_id = ANY($1::uuid[]);",
                        all_fids,
                    )
                    assert len(statuses) == len(all_fids)
                    assert all(row["status"] == "REVOKED" for row in statuses), f"Unpromoted rows: {statuses}"
                finally:
                    await conn.close()

                for fid in all_fids:
                    rkey = f"hc:revoked_family:{fid}"
                    assert real_redis.get(rkey) is not None
                    assert real_redis.ttl(rkey) > 7 * 86400

                # 5. Now tok3 is fail-closed rejected 401
                prof_401 = await client.get(
                    "/api/v1/profile/me",
                    headers={"Authorization": f"Bearer {tok3}"},
                )
                assert prof_401.status_code == 401
                assert await svc.verify_active_family(f3, uid) is False
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
            second_unbootstrapped_seen = asyncio.Event()

            async def handle_coord(route):
                cookie_hdr = route.request.headers.get("cookie", "")
                coord_calls.append(cookie_hdr)
                if "hc_browser=" not in cookie_hdr and len(coord_calls) == 1:
                    try:
                        await asyncio.wait_for(second_unbootstrapped_seen.wait(), timeout=2.0)
                    except TimeoutError:
                        pass
                elif "hc_browser=" not in cookie_hdr:
                    second_unbootstrapped_seen.set()
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
                    f"unbootstrapped /coord/session calls without hc_browser (calls={coord_calls})"
                )

                await page_a.click("#hc-logout-btn")
                await _wait_selector_text(page_a, "#hc-auth-status-badge", "UNAUTHENTICATED")
                await asyncio.sleep(0.25)
                surviving = await _count_active_refresh_tokens(uid)
                assert surviving == 0, f"C2-H03: Left {surviving} orphaned ACTIVE session(s) after logout!"
            finally:
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-05 (C2-H04): Strict client hc_coord Web Lock discipline
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
                assert len(all_writes) >= 1
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
# CE-06 (C2-M01): Forged Bearer prefix cannot elevate cancel quota
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce06_forged_bearer_prefix_cannot_elevate_cancel_quota(monkeypatch):
    _clear_rate_limit_keys()
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
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
                f"21st returned {statuses[20]} instead of 429"
            )
    finally:
        await _stop_server(server, thread)


# ---------------------------------------------------------------------------
# CE-07a (C2-M01/F02): Cross-user & anonymous same-browser cancel blocked (403);
# valid attempt-scoped cancel_capability succeeds
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce07a_cross_user_and_anonymous_same_browser_cancel_blocked(monkeypatch):
    _clear_rate_limit_keys()
    uid_a, mobile_a = await _create_test_user(["USER"])
    uid_b, mobile_b = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client_a:
                await client_a.post("/api/v1/auth/coord/session")
                shared_bid_a = client_a.cookies.get("hc_browser")
                assert shared_bid_a

                attempt_a = f"hc_usera_{uuid.uuid4().hex}"
                start_a = await client_a.post(
                    "/api/v1/auth/login-attempts/start",
                    json={"attempt_id": attempt_a, "flow": "PASSWORD"},
                )
                cap_a = start_a.json().get("cancel_capability") if start_a.status_code == 200 else None

                ra = await client_a.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_a, "password": "HamiCounter!901", "attempt_id": attempt_a},
                )
                assert ra.status_code == 200
                fam_a = uuid.UUID(ra.json()["family_id"])

            # 1. Cross-user cancel by User B MUST return 403 and leave User A ACTIVE
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client_b:
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
                assert cross_cancel.status_code == 403
                assert await svc.verify_active_family(fam_a, uid_a) is True

            # 2. Anonymous caller carrying SAME hc_browser cookie (NO Authorization, NO cancel_capability)
            # MUST return 403 and MUST NOT revoke User A's bound session!
            async with httpx.AsyncClient(
                base_url=base_url,
                headers={"Origin": base_url},
                cookies={"hc_browser": shared_bid_a},
            ) as anon_same_browser:
                anon_cancel = await anon_same_browser.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [attempt_a]},
                )
                assert anon_cancel.status_code == 403, (
                    f"F02: Anonymous same-browser caller revoked/reached bound session without capability! status={anon_cancel.status_code}"
                )
                assert await svc.verify_active_family(fam_a, uid_a) is True

            # 3. Originating caller presenting valid cancel_capability succeeds (200) & revokes fam_a
            assert cap_a, "F02: /login-attempts/start must issue cancel_capability."
            async with httpx.AsyncClient(
                base_url=base_url,
                headers={"Origin": base_url},
                cookies={"hc_browser": shared_bid_a},
            ) as cap_caller:
                cap_cancel = await cap_caller.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [attempt_a], "cancel_capabilities": {attempt_a: cap_a}},
                )
                assert cap_cancel.status_code == 200
                assert await svc.verify_active_family(fam_a, uid_a) is False
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid_a)
        await _cleanup_user(uid_b)


# ---------------------------------------------------------------------------
# CE-07b (C2-M01): Anonymous hc_browser cookie cannot elevate quota or TTL
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce07b_anonymous_browser_cookie_no_elevated_quota_or_ttl(monkeypatch):
    _clear_rate_limit_keys()
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as anon:
            coord_r = await anon.post("/api/v1/auth/coord/session")
            assert coord_r.status_code == 200
            assert anon.cookies.get("hc_browser")

            first_aid = f"hc_anon_ttl_{uuid.uuid4().hex[:8]}"
            statuses = []
            for idx in range(21):
                aid = first_aid if idx == 0 else f"hc_anon_{idx}_{uuid.uuid4().hex[:8]}"
                r_cancel = await anon.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [aid]},
                )
                statuses.append(r_cancel.status_code)

            assert statuses[20] == 429, (
                f"C2-M01: Anonymous hc_browser cookie elevated quota beyond 20 reqs! 21st={statuses[20]}"
            )
            ttl_val = r.ttl(f"hc:cancelled_login_attempt:{first_aid}")
            assert 0 < ttl_val <= 120, (
                f"C2-M01: Anonymous cancellation TTL elevated above 120s! ttl={ttl_val}"
            )
    finally:
        r.close()
        await _stop_server(server, thread)


# ---------------------------------------------------------------------------
# CE-08 (C2-M02/F04/F05): Stale delayed F1 /refresh returns 401 and Tab A
# rebinds F3 even when COOKIE_MAY_BE_STALE BroadcastChannel delivery is dropped
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce08_delayed_200_cookie_overwrite_rejects_stale_and_rebinds_without_broadcast(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            page_b = await context.new_page()
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
                // Drop COOKIE_MAY_BE_STALE broadcast to prove client self-recovers via 401->rebind!
                if (typeof BroadcastChannel === 'function') {
                  const origPost = BroadcastChannel.prototype.postMessage;
                  BroadcastChannel.prototype.postMessage = function(msg) {
                    if (msg && msg.type === 'COOKIE_MAY_BE_STALE') return;
                    return origPost.apply(this, arguments);
                  };
                }
                """
            )
            page_a = await context.new_page()

            b1_arrived_after_server = asyncio.Event()
            release_b1_response = asyncio.Event()
            b1_intercept_active = {"on": True}
            rebind_responses: list[int] = []

            async def hold_b1_login(route):
                if b1_intercept_active["on"] and route.request.method == "POST":
                    b1_intercept_active["on"] = False
                    resp = await route.fetch()
                    b1_arrived_after_server.set()
                    await release_b1_response.wait()
                    await route.fulfill(response=resp)
                    return
                await route.continue_()

            page_a.on(
                "response",
                lambda r: rebind_responses.append(r.status)
                if r.request.method == "POST" and r.url.endswith("/api/v1/auth/session/rebind-cookie")
                else None,
            )

            try:
                await page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")

                # 1. Tab B initiates delayed login B1 (server mints F1, held in flight)
                await page_b.route("**/api/v1/auth/password/login", hold_b1_login)
                await page_b.fill("#hc-pwd-mobile", mobile)
                await page_b.fill("#hc-pwd-input", "HamiCounter!901")
                await page_b.click("#hc-pwd-login-btn")
                await asyncio.wait_for(b1_arrived_after_server.wait(), timeout=6.0)

                # 2. Tab A logs out (revoking F1) and logs in as F3
                await page_a.click("#hc-logout-btn")
                await asyncio.sleep(0.15)
                await page_a.fill("#hc-pwd-mobile", mobile)
                await page_a.fill("#hc-pwd-input", "HamiCounter!901")
                await page_a.click("#hc-pwd-login-btn")
                await _wait_selector_text(page_a, "#hc-auth-status-badge", "AUTHENTICATED")

                # 3. Delayed B1 HTTP 200 overwrites jar with revoked F1 (BroadcastChannel COOKIE_MAY_BE_STALE blocked!)
                release_b1_response.set()
                await asyncio.sleep(0.5)

                # Capture overwritten stale F1 cookies directly from Chromium jar and verify server rejects direct /refresh (401)
                jar_overwritten = {c["name"]: c["value"] for c in await context.cookies()}
                if jar_overwritten.get("hc_refresh") and jar_overwritten.get("hc_csrf"):
                    async with httpx.AsyncClient(
                        base_url=base_url,
                        headers={
                            "Origin": base_url,
                            "X-Auth-Mode": "cookie",
                            "X-CSRF-Token": jar_overwritten["hc_csrf"],
                        },
                        cookies=jar_overwritten,
                    ) as stale_client:
                        stale_ref = await stale_client.post("/api/v1/auth/refresh")
                        assert stale_ref.status_code == 401

                # 4. Tab A clicks forced refresh WITHOUT BroadcastChannel hint -> MUST hit /session/rebind-cookie -> 200 & stay AUTHENTICATED
                await page_a.click("#hc-refresh-btn")
                await asyncio.sleep(0.5)
                status_after = (await page_a.locator("#hc-auth-status-badge").inner_text()).strip()
                assert status_after == "AUTHENTICATED", (
                    f"C2-M02: Stale delayed 200 Set-Cookie broke Tab A ({status_after!r}) without COOKIE_MAY_BE_STALE!"
                )
                assert 200 in rebind_responses, f"Expected /session/rebind-cookie 200 recovery, got {rebind_responses}"
            finally:
                release_b1_response.set()
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-08b (F04/F05/Section 3): Adversarial /session/rebind-cookie security matrix
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce08b_rebind_cookie_adversarial_matrix(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch, access_ttl=1)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client_a:
                await client_a.post("/api/v1/auth/coord/session")
                bid_a = client_a.cookies.get("hc_browser")

                # Login F1 -> superseded by newer login F2 on SAME browser (LATEST_FAMILY_WINS)
                r1 = await client_a.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_f1_{uuid.uuid4().hex}"},
                )
                assert r1.status_code == 200
                tok1 = r1.json()["access_token"]
                f1 = uuid.UUID(r1.json()["family_id"])

                r2 = await client_a.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_f2_{uuid.uuid4().hex}"},
                )
                assert r2.status_code == 200
                tok2 = r2.json()["access_token"]
                f2 = uuid.UUID(r2.json()["family_id"])
                csrf2 = client_a.cookies.get("hc_csrf")

                # 1. Older superseded family F1 CANNOT rebind (no downgrade!)
                rebind_old = await client_a.post(
                    "/api/v1/auth/session/rebind-cookie",
                    headers={"Authorization": f"Bearer {tok1}"},
                )
                assert rebind_old.status_code in (401, 403)
                assert await svc.verify_active_family(f1, uid) is False

                # 2. Bad Origin rejected 403
                rebind_origin = await client_a.post(
                    "/api/v1/auth/session/rebind-cookie",
                    headers={"Origin": "https://evil.example", "Authorization": f"Bearer {tok2}"},
                )
                assert rebind_origin.status_code == 403

                # 3. Missing or wrong hc_browser rejected 401/403
                async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as no_bid:
                    rebind_nobid = await no_bid.post(
                        "/api/v1/auth/session/rebind-cookie",
                        headers={"Authorization": f"Bearer {tok2}"},
                    )
                    assert rebind_nobid.status_code in (401, 403)

                async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as wrong_bid:
                    await wrong_bid.post("/api/v1/auth/coord/session")
                    rebind_wbid = await wrong_bid.post(
                        "/api/v1/auth/session/rebind-cookie",
                        headers={"Authorization": f"Bearer {tok2}"},
                    )
                    assert rebind_wbid.status_code in (401, 403)

                # 4. Concurrent /rebind-cookie vs /refresh on active F2 must NOT falsely mark REPLAY_ATTACK
                ref_coro = client_a.post(
                    "/api/v1/auth/refresh",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf2},
                )
                reb_coro = client_a.post(
                    "/api/v1/auth/session/rebind-cookie",
                    headers={"Authorization": f"Bearer {tok2}"},
                )
                r_ref, r_reb = await asyncio.gather(ref_coro, reb_coro)
                assert {r_ref.status_code, r_reb.status_code} <= {200, 409}
                assert 200 in (r_ref.status_code, r_reb.status_code)
                assert await svc.verify_active_family(f2, uid) is True
                assert "refresh_token" not in r_reb.text

                # 5. Rebind vs /logout never resurrects F2 + expired bearer rejected 401
                lo_coro = client_a.post(
                    "/api/v1/auth/logout",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": client_a.cookies.get("hc_csrf")},
                )
                reb2_coro = client_a.post(
                    "/api/v1/auth/session/rebind-cookie",
                    headers={"Authorization": f"Bearer {tok2}"},
                    cookies={"hc_browser": bid_a},
                )
                r_lo, r_reb2 = await asyncio.gather(lo_coro, reb2_coro)
                assert r_lo.status_code == 200
                assert await svc.verify_active_family(f2, uid) is False

                await asyncio.sleep(1.3)
                rebind_exp = await client_a.post(
                    "/api/v1/auth/session/rebind-cookie",
                    headers={"Authorization": f"Bearer {tok2}"},
                    cookies={"hc_browser": bid_a},
                )
                assert rebind_exp.status_code == 401
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-09 (C2-M03): Both 429 & 503 cancellation failures preserve retry state
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("fail_status", [429, 503])
async def test_ce09_superseded_cancel_failure_surfaces_error_and_retry_state(monkeypatch, fail_status: int):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
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

            async def reject_cancel(route):
                await route.fulfill(
                    status=fail_status,
                    content_type="application/json",
                    body=f'{{"detail":"Simulated cancel failure HTTP {fail_status}"}}',
                )

            async def fail_bearer_logout(route):
                if route.request.headers.get("x-auth-mode", "") == "bearer":
                    await route.abort("failed")
                    return
                await route.continue_()

            try:
                await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", "HamiCounter!901")
                await page.click("#hc-pwd-login-btn")
                await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

                await page.route("**/api/v1/auth/password/login", delay_login)
                await page.route("**/api/v1/auth/login-attempts/cancel", reject_cancel)
                await page.route("**/api/v1/auth/logout", fail_bearer_logout)

                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", "HamiCounter!901")
                await page.click("#hc-pwd-login-btn")
                await asyncio.wait_for(login_in_flight.wait(), timeout=6.0)

                await page.click("#hc-logout-btn")
                await _wait_selector_text(page, "#hc-auth-status-badge", "UNAUTHENTICATED")

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
                assert str(fail_status) in err_msg or "لغو" in err_msg, f"C2-M03: Silent error={err_msg!r}"
                assert ui_state.get("canRetryLogout") is True, (
                    f"C2-M03: Expected preserved canRetryLogout=True on HTTP {fail_status}; snapshot={ui_state}"
                )
                assert int(ui_state.get("unresolvedAttemptCount", 0)) >= 1, (
                    f"C2-M03: Expected unresolvedAttemptCount >= 1 on HTTP {fail_status}; snapshot={ui_state}"
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


# ---------------------------------------------------------------------------
# CE-11 (F01 / F03): Forged started_server_logout_seq=999 bypass rejected &
# concurrent duplicate attempt_id produces at most 1 family
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce11_forged_logout_seq_bypass_and_duplicate_attempt_id_rejected(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
            await client.post("/api/v1/auth/coord/session")

            # Login & logout so browser logout_seq == 1
            r1 = await client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f"hc_init_{uuid.uuid4().hex}"},
            )
            assert r1.status_code == 200
            lo1 = await client.post(
                "/api/v1/auth/logout",
                headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": client.cookies.get("hc_csrf")},
            )
            assert lo1.status_code == 200

            # 1a. Password login forging started_server_logout_seq=999 MUST FAIL 409!
            forged_pwd = await client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={
                    "mobile": mobile,
                    "password": "HamiCounter!901",
                    "attempt_id": f"hc_forge_pwd_{uuid.uuid4().hex}",
                    "started_server_logout_seq": 999,
                },
            )
            assert forged_pwd.status_code == 409, (
                f"F01: Forged started_server_logout_seq=999 bypassed rejection! status={forged_pwd.status_code}"
            )

            # 1b. OTP verify forging started_server_logout_seq=999 MUST FAIL 409!
            await OtpService(r).request_otp(mobile)
            otp_code = r.get(f"otp:code:{mobile}")
            assert otp_code
            forged_otp = await client.post(
                "/api/v1/auth/otp/verify",
                headers={"X-Auth-Mode": "cookie"},
                json={
                    "mobile": mobile,
                    "code": otp_code,
                    "attempt_id": f"hc_forge_otp_{uuid.uuid4().hex}",
                    "started_server_logout_seq": 999,
                },
            )
            assert forged_otp.status_code == 409, (
                f"F01: OTP verify accepted forged started_server_logout_seq=999! status={forged_otp.status_code}"
            )
            assert await _count_active_refresh_tokens(uid) == 0

            # 2. Concurrent duplicate attempt_id MUST create at most ONE family and reject duplicate with 409!
            dup_aid = f"hc_dup_{uuid.uuid4().hex}"
            d1, d2 = await asyncio.gather(
                client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": dup_aid},
                ),
                client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": dup_aid},
                ),
            )
            codes = sorted([d1.status_code, d2.status_code])
            assert codes == [200, 409], f"F03: Duplicate attempt_id allowed multiple wins: {codes}"

            conn = await asyncpg.connect(DATABASE_URL)
            try:
                fam_count = await conn.fetchval(
                    "SELECT COUNT(*) FROM browser_session_families WHERE attempt_id = $1;",
                    dup_aid,
                )
                assert fam_count == 1
            finally:
                await conn.close()
    finally:
        r.close()
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-12 (F08): Continuous Lua ZSET sliding-window boundary, 429 non-pollution,
# weighted ID quota, & Redis 503 fail-closed
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce12_sliding_window_zset_boundary_weighted_ids_and_redis_503(monkeypatch):
    _clear_rate_limit_keys()
    monkeypatch.setattr(auth_mod, "CANCEL_RL_WINDOW_SECONDS", 2, raising=False)
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
            # 1. At t=0: send 10 requests; at t=1.1s: send 10 requests -> total 20 in window [0..2s]
            for i in range(10):
                resp = await client.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [f"hc_sw_t0_{i}_{uuid.uuid4().hex[:8]}"]},
                )
                assert resp.status_code == 200
            await asyncio.sleep(1.1)
            for i in range(10):
                resp = await client.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [f"hc_sw_t1_{i}_{uuid.uuid4().hex[:8]}"]},
                )
                assert resp.status_code == 200

            # 21st hits 429 AND must NOT pollute ZSET count!
            r429 = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [f"hc_sw_blocked_{uuid.uuid4().hex[:8]}"]},
            )
            assert r429.status_code == 429

            # Verify ZSET implementation (not fixed INCRBY string key) & 429 didn't inflate cardinality above 20
            ip_req_key = "hc:rl:cancel_req:ip:127.0.0.1"
            assert r.type(ip_req_key) == "zset", f"F08: Expected ZSET bucket, got type={r.type(ip_req_key)!r}"
            assert r.zcard(ip_req_key) == 20, f"F08: 429 request polluted ZSET count={r.zcard(ip_req_key)}"

            # Wait 1.05s -> total elapsed 2.15s: t=0 (10 entries) expired continuously, t=1.1s (10 entries) REMAIN!
            # Sending 11 more MUST allow first 10 and fail 429 on 11th (proving continuous sliding vs fixed reset)!
            await asyncio.sleep(1.05)
            post_statuses = []
            for i in range(11):
                resp = await client.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [f"hc_sw_t2_{i}_{uuid.uuid4().hex[:8]}"]},
                )
                post_statuses.append(resp.status_code)
            assert post_statuses[:10] == [200] * 10, f"Continuous window failed: {post_statuses}"
            assert post_statuses[10] == 429, f"F08: Fixed-window reset leaked extra capacity: {post_statuses}"

            # 2. Weighted ID cap check (64 unauth IDs): 4 batches * 16 = 64 pass; 5th batch of 1 hits 429!
            await asyncio.sleep(2.1)
            for b in range(4):
                batch_ids = [f"hc_wid_{b}_{j}_{uuid.uuid4().hex[:8]}" for j in range(16)]
                rw = await client.post("/api/v1/auth/login-attempts/cancel", json={"attempt_ids": batch_ids})
                assert rw.status_code == 200
            rw_over = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [f"hc_wid_over_{uuid.uuid4().hex[:8]}"]},
            )
            assert rw_over.status_code == 429

            # 3. Redis failure fails closed 503
            real_rd = deps.get_redis()

            class _EvalBoomRedis:
                def __init__(self, inner):
                    self._inner = inner

                def __getattr__(self, name):
                    return getattr(self._inner, name)

                def eval(self, *args, **kwargs):
                    raise redis.ConnectionError("Redis ZSET eval outage")

                def evalsha(self, *args, **kwargs):
                    raise redis.ConnectionError("Redis ZSET evalsha outage")

            monkeypatch.setattr(deps, "_redis", _EvalBoomRedis(real_rd))
            r503 = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [f"hc_rl503_{uuid.uuid4().hex[:8]}"]},
            )
            assert r503.status_code == 503
    finally:
        r.close()
        await _stop_server(server, thread)


# ---------------------------------------------------------------------------
# CE-13 (F07): Missing navigator.locks + forged hc_coord bi=1 fails closed
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce13_missing_web_locks_fails_closed_and_bi_hint_untrusted(monkeypatch):
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
                  try {
                    Object.defineProperty(Navigator.prototype, 'locks', {
                      configurable: true,
                      get: () => undefined,
                    });
                  } catch {
                    delete navigator.locks;
                  }
                  document.cookie = 'hc_coord=g.9.lo.0.li.9.sg.9.slo.0.sli.9.lp.0.bi.1; Path=/; SameSite=Lax';
                })();
                """
            )
            try:
                await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", "HamiCounter!901")
                await page.click("#hc-pwd-login-btn")
                await asyncio.sleep(0.4)

                snap = await page.evaluate(
                    """
                    async () => {
                      const mod = await import('/phase3/js/auth_session.js');
                      return mod.getAuthSnapshot();
                    }
                    """
                )
                assert snap.get("authenticated") is False, (
                    "F07: Client allowed unlocked cookie login without navigator.locks!"
                )
                assert "WEB_LOCKS" in (snap.get("lastErrorMessage") or "") or "Web Locks" in (snap.get("lastErrorMessage") or ""), (
                    f"F07: Expected explicit fail-closed WEB_LOCKS error when navigator.locks is missing, got {snap}"
                )
                assert await _count_active_refresh_tokens(uid) == 0
            finally:
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)
