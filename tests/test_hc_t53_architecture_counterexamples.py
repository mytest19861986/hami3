"""
Pre-Implementation Deterministic Counterexample Suite for HC-T52 / HC-T53 (HC-CMD-053 / HC-CMD-054).
Baseline: BL-HAMICARD-PRD-V1 | Base SHA: e7c2bb81f7278e1d9a0fe8ca75e56d06fec753fb
Revision: HC-T52 Revision 2.1 (closes Reviewer #2 HIGH-01..05, MEDIUM M-01..05, plus REV1 & V4)

RED_TEST_MATRIX (`CE-01..CE-16`):
- CE-01  (C2-H01): Delayed attempt cancellation `[B1]` never advances logout_seq or revokes newer `F3`.
- CE-02  (C2-H02/H04/REV1-H03): Deterministic Phase A->Phase B PG fence barrier racing `/logout` + reverse post-logout schedule.
- CE-03a (C2-H02/F06/HIGH-03): PG outage injected mid-tx AFTER real DB UPDATE mutation fails 503 & rolls back cleanly; retry revokes F1 while separate device F2 stays ACTIVE.
- CE-03b (C2-H02/F06/REV1-M01): Redis outage leaves PENDING_REVOKE durable; forced overlapping dual workers (`SKIP LOCKED`) partition disjoint batches.
- CE-04  (C2-H03/HIGH-02): Two fresh Playwright tabs initialized & logged in concurrently under deterministic server-side `/coord/session` boundary barrier converge to 1 `hc_browser`.
- CE-05  (C2-H04): Every `hc_coord` write runs strictly inside `navigator.locks('hamicard_phase3_coord')`.
- CE-06  (C2-M01/L01): Forged `Authorization: Bearer fake` cannot elevate `/login-attempts/cancel` quota above 20 reqs/120s.
- CE-07a (C2-M01/F02): Cross-user AND anonymous same-browser (no capability) cancel against bound session blocked (403); capability succeeds.
- CE-07b (C2-M01): Anonymous `hc_browser` cookie gets `:anon:` 20 req quota & <= 125s TTL.
- CE-08  (C2-M02/REV1-H04): Unconditionally verified delayed F1 overwrite + all-page BroadcastChannel suppression -> `401 /refresh` auto-rebinds F3.
- CE-08b (F04/F05/REV1-H04): Normal-TTL (120s) `/session/rebind-cookie` adversarial matrix (old family, bad origin, missing/wrong browser, refresh & logout race).
- CE-08c (F04/F05/REV1-H04): Isolated expired-bearer JWT rejected 401 on `/session/rebind-cookie`.
- CE-09  (C2-M03): Both 429 & 503 cancellation failures preserve `canRetryLogout`, `unresolvedAttemptCount >= 1`, and error copy.
- CE-10  (C2-H01/AC-15/M-01): Browser A logout/cancel keeps multi-device Browser B and unrelated User B sessions ACTIVE (strict 200 attempt registration).
- CE-11a (F01/HIGH-04): Pre-logout registered attempt -> logout -> delayed `/password/login` with forged `started_server_logout_seq=999` rejected 409.
- CE-11b (F01/HIGH-04): Pre-logout registered OTP attempt -> logout -> delayed `/otp/verify` with forged `started_server_logout_seq=999` rejected 409.
- CE-11c (F03/REV1-H05/M04): Concurrent duplicate `attempt_id` creates <= 1 family & rejects duplicate 409; PG FK rejects mismatched `(attempt_id, family_id)`.
- CE-12a (F08/M-02): Continuous Lua ZSET sliding-window boundary pruning & 429 non-pollution verified across all 4 `:anon:` buckets.
- CE-12b (REV1-H06): Mixed `:anon:` (120s) and `:auth:` (300s) namespace isolation prevents anonymous pruning/shortening of authenticated entries.
- CE-12c (F08/M-02): Weighted attempt-ID quota (`64` unauth IDs) & Redis outage 503 fail-closed with 0 PG write mutations.
- CE-13a (F07): Missing `navigator.locks` fails closed (`WEB_LOCKS_UNAVAILABLE`) with zero login traffic.
- CE-13b (F07/REV1-M02): Forged `hc_coord.bi=1` WITH normal `navigator.locks` still triggers `/coord/session` & cannot bypass validation.
- CE-14  (REV1-H07/H01): Pre-Phase-A delayed `/password/login` after `/login-attempts/start` rejected 409, unregistered `hc_browser` login rejected 409, & competing lock-order stress completes with 0 deadlocks.
- CE-15  (M-05): Unregistered & pre-Phase-A delayed `/otp/verify` rejected 409 strictly BEFORE `AuthService.authenticate_via_otp` / OTP consumption.
- CE-16  (REV1-M03/M-03): Adversarial GC preserves `STARTED`/`IN_FLIGHT`/`ACTIVE`/`PENDING_REVOKE` and unexpired tombstones while safely purging expired tombstones & >10d revoked families.
"""

import asyncio
import os
import pathlib
import socket
import threading
import time
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
from src.auth.service import AuthService
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
    asgi_wrapper=None,
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

    app = create_app()
    asgi_app = asgi_wrapper(app) if asgi_wrapper else app
    server = uvicorn.Server(
        uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="warning")
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


async def _register_attempt_required(
    client: httpx.AsyncClient, attempt_id: str, *, flow: str = "PASSWORD"
) -> dict:
    resp = await client.post(
        "/api/v1/auth/login-attempts/start",
        json={"attempt_id": attempt_id, "flow": flow},
    )
    assert resp.status_code == 200, (
        f"M-01: Mandatory /login-attempts/start failed (no 404 fallback permitted): "
        f"status={resp.status_code} body={resp.text}"
    )
    return resp.json()


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
                await _register_attempt_required(client, b1)
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
                await _register_attempt_required(client, b3)
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
# CE-02 (C2-H02/H04/F01/REV1-H03): Deterministic Phase A -> Phase B PG fence
# racing /logout + post-logout fresh start commits legitimately
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce02_pre_logout_attempt_racing_logout_never_survives_or_inverts_coord(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client_a:
            await client_a.post("/api/v1/auth/coord/session")
            shared_browser_cookie = client_a.cookies.get("hc_browser")
            assert shared_browser_cookie

            # Initial session F1 via registered login-attempts/start
            a1 = f"hc_a1_{uuid.uuid4().hex}"
            st1 = await client_a.post(
                "/api/v1/auth/login-attempts/start",
                json={"attempt_id": a1, "flow": "PASSWORD"},
            )
            assert st1.status_code == 200, f"F01/H03: /login-attempts/start missing or failed: {st1.status_code}"
            assert st1.json()["started_logout_seq"] == 0

            r1 = await client_a.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a1},
            )
            assert r1.status_code == 200
            csrf1 = client_a.cookies.get("hc_csrf")
            ref1 = client_a.cookies.get("hc_refresh")

            # Register pre-logout attempt B2 BEFORE /logout begins!
            b2_attempt = f"hc_b2_{uuid.uuid4().hex}"
            start_resp = await client_a.post(
                "/api/v1/auth/login-attempts/start",
                json={"attempt_id": b2_attempt, "flow": "PASSWORD"},
            )
            assert start_resp.status_code == 200
            assert start_resp.json()["started_logout_seq"] == 0
            assert start_resp.json().get("cancel_capability")

            # Schedule 1: Deterministic PG Phase A -> Phase B barrier via authenticate_via_password
            pause_b2 = {"active": True}
            b2_entered_slow_auth = threading.Event()
            release_b2_phase_b = threading.Event()
            orig_auth_pwd = AuthService.authenticate_via_password

            async def _paused_auth_pwd(self, *args, **kwargs):
                res = await orig_auth_pwd(self, *args, **kwargs)
                if pause_b2["active"]:
                    pause_b2["active"] = False
                    b2_entered_slow_auth.set()
                    await asyncio.to_thread(release_b2_phase_b.wait, 5.0)
                return res

            monkeypatch.setattr(AuthService, "authenticate_via_password", _paused_auth_pwd)

            async def do_b2_login():
                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url},
                    cookies={"hc_browser": shared_browser_cookie},
                ) as client_b:
                    return await client_b.post(
                        "/api/v1/auth/password/login",
                        headers={"X-Auth-Mode": "cookie"},
                        json={
                            "mobile": mobile,
                            "password": "HamiCounter!901",
                            "attempt_id": b2_attempt,
                        },
                    )

            b2_task = asyncio.create_task(do_b2_login())
            entered = await asyncio.to_thread(b2_entered_slow_auth.wait, 5.0)
            assert entered, "Pre-logout B2 never reached Phase A -> slow auth boundary!"

            # Tab A executes /logout while B2 is paused strictly between Phase A and Phase B!
            async with httpx.AsyncClient(
                base_url=base_url,
                headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                cookies={"hc_browser": shared_browser_cookie, "hc_refresh": ref1, "hc_csrf": csrf1},
            ) as lo_client:
                lo1_resp = await lo_client.post("/api/v1/auth/logout")
                assert lo1_resp.status_code == 200
                lo1_coord = lo1_resp.json().get("auth_coord", {})

            release_b2_phase_b.set()
            r2_resp = await b2_task
            assert r2_resp.status_code == 409, (
                f"F01/H03: Delayed pre-logout attempt B2 MUST fail 409 at Phase B after /logout, got {r2_resp.status_code}"
            )
            assert await _count_active_refresh_tokens(uid) == 0
            assert int(lo1_coord.get("logout_seq", 0)) > int(lo1_coord.get("login_seq", 0))

            conn = await asyncpg.connect(DATABASE_URL)
            try:
                assert await conn.fetchval("SELECT to_regclass('public.browser_session_families') IS NOT NULL;")
                non_revoked_fams = await conn.fetchval(
                    "SELECT COUNT(*) FROM browser_session_families WHERE user_id = $1 AND status != 'REVOKED';",
                    uid,
                )
                assert non_revoked_fams == 0
                start_seq_stored = await conn.fetchval(
                    "SELECT started_logout_seq FROM login_attempt_states WHERE attempt_id = $1;",
                    b2_attempt,
                )
                assert start_seq_stored == 0
            finally:
                await conn.close()

            # Schedule 2 (competing post-logout registration): B3 registered AFTER logout succeeds cleanly!
            b3_attempt = f"hc_b3_{uuid.uuid4().hex}"
            st3 = await client_a.post(
                "/api/v1/auth/login-attempts/start",
                json={"attempt_id": b3_attempt, "flow": "PASSWORD"},
            )
            assert st3.status_code == 200
            assert st3.json()["started_logout_seq"] >= 1
            r3 = await client_a.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": b3_attempt},
            )
            assert r3.status_code == 200
            r3_coord = r3.json()["auth_coord"]
            assert int(r3_coord["login_seq"]) > int(r3_coord["logout_seq"])
            assert await _count_active_refresh_tokens(uid) == 1
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-03a (C2-H02/F06/REV1-H02): PG failure mid-revocation fails closed 503, keeps
# F1 ACTIVE for retry, and Retry revokes F1 while separate device F2 stays ACTIVE
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
                a1_id = f"hc_{uuid.uuid4().hex}"
                await _register_attempt_required(client1, a1_id)
                r1 = await client1.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a1_id},
                )
                assert r1.status_code == 200
                f1 = uuid.UUID(r1.json()["family_id"])
                csrf1 = r1.cookies.get("hc_csrf")
                ref1_cookie = r1.cookies.get("hc_refresh")

                # Separate device client2 gets its OWN distinct browser_id -> F2 must stay isolated!
                await client2.post("/api/v1/auth/coord/session")
                bid2 = client2.cookies.get("hc_browser")
                assert bid2 and bid2 != shared_bid
                a2_id = f"hc_dev2_{uuid.uuid4().hex}"
                await _register_attempt_required(client2, a2_id)
                r2 = await client2.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a2_id},
                )
                assert r2.status_code == 200
                f2 = uuid.UUID(r2.json()["family_id"])

                fail_pg = {"active": True}
                tx_mutations: list[str] = []
                app_pool = await deps.get_db_pool()

                class _FaultyConnWrapper:
                    def __init__(self, conn):
                        self._conn = conn

                    def __getattr__(self, item):
                        return getattr(self._conn, item)

                    async def execute(self, query, *args, **kwargs):
                        q_upper = " ".join(str(query).upper().split())
                        is_write = any(
                            kw in q_upper for kw in ("UPDATE ", "INSERT ", "DELETE ")
                        )
                        if fail_pg["active"] and "UPDATE REFRESH_TOKENS" in q_upper and "REVOKED" in q_upper:
                            if not tx_mutations:
                                # Execute this real SQL UPDATE inside the open tx FIRST, then crash before commit
                                await self._conn.execute(query, *args, **kwargs)
                                tx_mutations.append(f"EXECUTED_BEFORE_CRASH:{q_upper[:80]}")
                                raise asyncpg.PostgresConnectionError(
                                    "Simulated mid-tx PG crash immediately after refresh_tokens UPDATE"
                                )
                            tx_mutations.append(f"CRASH_AFTER_PRIOR_MUTATION:{q_upper[:80]}")
                            raise asyncpg.PostgresConnectionError(
                                "Simulated mid-tx PG crash after prior DB mutation"
                            )
                        res = await self._conn.execute(query, *args, **kwargs)
                        if fail_pg["active"] and is_write:
                            tx_mutations.append(f"EXECUTED:{q_upper[:80]}")
                        return res

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

                monkeypatch.setattr(deps, "_pool", _FaultyPoolProxy(app_pool))

                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_bid, "hc_refresh": ref1_cookie, "hc_csrf": csrf1},
                ) as f1_client:
                    fail_lo = await f1_client.post("/api/v1/auth/logout")
                    assert fail_lo.status_code == 503

                assert any(m.startswith("EXECUTED") for m in tx_mutations), (
                    f"HIGH-03: Injected PG fault raised without executing an actual SQL mutation first: {tx_mutations}"
                )

                # Rolled-back transaction MUST preserve both F1 & F2 as ACTIVE and keep logout_seq=0!
                assert await svc.verify_active_family(f1, uid) is True
                assert await svc.verify_active_family(f2, uid) is True

                fail_pg["active"] = False
                monkeypatch.setattr(deps, "_pool", app_pool)

                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url, "X-Auth-Mode": "cookie", "X-CSRF-Token": csrf1},
                    cookies={"hc_browser": shared_bid, "hc_refresh": ref1_cookie, "hc_csrf": csrf1},
                ) as heal_client:
                    heal_lo = await heal_client.post("/api/v1/auth/logout")
                    assert heal_lo.status_code == 200

                # Same-browser F1 revoked cleanly while separate-device F2 REMAINS ACTIVE (INV-12 / REV1-H02)!
                assert await svc.verify_active_family(f1, uid) is False
                assert await svc.verify_active_family(f2, uid) is True
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-03b (C2-H02/F06/REV1-M01): Redis outage after PG commit leaves PENDING_REVOKE
# durable and overlapping concurrent reconcilers partition disjoint batches (SKIP LOCKED)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce03b_redis_outage_durable_pending_and_concurrent_reconcilers(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    seeded_fids: list[uuid.UUID] = []
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=8)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
                await client.post("/api/v1/auth/coord/session")
                shared_bid = client.cookies.get("hc_browser")
                a3_id = f"hc_{uuid.uuid4().hex}"
                await _register_attempt_required(client, a3_id)
                r_login = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a3_id},
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

                    # Seed 5 additional PENDING_REVOKE rows (6 total)
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

                # 4. Heal Redis & run TWO overlapping workers forced into simultaneous SKIP LOCKED row locks!
                redis_outage["active"] = False
                monkeypatch.setattr(deps, "_redis", real_redis)
                assert hasattr(SessionService, "reconcile_pending_revocations")

                overlap_barrier = threading.Barrier(2, timeout=4.0)
                worker_keys: dict[str, list[str]] = {"w1": [], "w2": []}

                class _OverlapRedisProxy:
                    def __init__(self, inner, worker_name: str):
                        self._inner = inner
                        self._worker_name = worker_name
                        self._tripped = False

                    def __getattr__(self, name):
                        return getattr(self._inner, name)

                    def setex(self, key, *args, **kwargs):
                        if isinstance(key, str) and key.startswith("hc:revoked_family:"):
                            worker_keys[self._worker_name].append(key)
                            if not self._tripped:
                                self._tripped = True
                                overlap_barrier.wait()
                        return self._inner.setex(key, *args, **kwargs)

                    def set(self, key, *args, **kwargs):
                        if isinstance(key, str) and key.startswith("hc:revoked_family:"):
                            worker_keys[self._worker_name].append(key)
                            if not self._tripped:
                                self._tripped = True
                                overlap_barrier.wait()
                        return self._inner.set(key, *args, **kwargs)

                def _run_reconciler_worker(worker_name: str) -> int:
                    async def _inner() -> int:
                        w_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
                        try:
                            w_svc = SessionService(w_pool, redis_client=_OverlapRedisProxy(real_redis, worker_name))
                            return await w_svc.reconcile_pending_revocations(batch_size=2, max_batches=1)
                        finally:
                            await w_pool.close()

                    return asyncio.run(_inner())

                c1, c2 = await asyncio.gather(
                    asyncio.to_thread(_run_reconciler_worker, "w1"),
                    asyncio.to_thread(_run_reconciler_worker, "w2"),
                )
                assert c1 >= 2 and c2 >= 2, (
                    f"REV1-M01: Expected both overlapping SKIP LOCKED workers to process disjoint batches >=2, "
                    f"got c1={c1}, c2={c2}"
                )
                assert set(worker_keys["w1"]).isdisjoint(set(worker_keys["w2"])), (
                    f"REV1-M01: Overlapping workers touched same families: {worker_keys}"
                )

                # Drain remaining batch (6 - 4 = 2)
                c_rem = await svc.reconcile_pending_revocations(batch_size=10, max_batches=5)
                assert (c1 + c2 + c_rem) >= 6

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
    server_coord_hits: list[dict] = []
    barrier_second_unbootstrapped = asyncio.Event()

    def _coord_barrier_wrapper(app):
        async def _wrapped(scope, receive, send):
            if (
                scope.get("type") == "http"
                and scope.get("method") == "POST"
                and scope.get("path") == "/api/v1/auth/coord/session"
            ):
                hdrs = {k.lower(): v for k, v in scope.get("headers", [])}
                cookie_val = hdrs.get(b"cookie", b"").decode("latin-1")
                has_browser = "hc_browser=" in cookie_val
                server_coord_hits.append(
                    {"has_browser": has_browser, "idx": len(server_coord_hits) + 1, "t": time.monotonic()}
                )
                if not has_browser:
                    if sum(1 for h in server_coord_hits if not h["has_browser"]) == 1:
                        # Hold the first unbootstrapped request deterministically at server /coord/session boundary
                        try:
                            await asyncio.wait_for(barrier_second_unbootstrapped.wait(), timeout=1.2)
                        except TimeoutError:
                            pass
                    else:
                        barrier_second_unbootstrapped.set()
            await app(scope, receive, send)

        return _wrapped

    server, thread, base_url = await _start_test_server(
        monkeypatch, asgi_wrapper=_coord_barrier_wrapper
    )
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            coord_calls = []

            async def handle_coord(route):
                cookie_hdr = route.request.headers.get("cookie", "")
                coord_calls.append(cookie_hdr)
                await route.continue_()

            await context.route("**/api/v1/auth/coord/session", handle_coord)

            page_a, page_b = await asyncio.gather(context.new_page(), context.new_page())
            try:
                await asyncio.gather(
                    page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle"),
                    page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle"),
                )
                await asyncio.gather(
                    page_a.wait_for_function(
                        "() => document.getElementById('hc-pwd-form')?.dataset.hcBound === '1'"
                    ),
                    page_b.wait_for_function(
                        "() => document.getElementById('hc-pwd-form')?.dataset.hcBound === '1'"
                    ),
                )
                await asyncio.gather(
                    page_a.fill("#hc-pwd-mobile", mobile),
                    page_b.fill("#hc-pwd-mobile", mobile),
                )
                await asyncio.gather(
                    page_a.fill("#hc-pwd-input", "HamiCounter!901"),
                    page_b.fill("#hc-pwd-input", "HamiCounter!901"),
                )

                await asyncio.gather(
                    page_a.evaluate("() => document.getElementById('hc-pwd-login-btn').click()"),
                    page_b.evaluate("() => document.getElementById('hc-pwd-login-btn').click()"),
                )
                await asyncio.gather(
                    _wait_selector_text(page_a, "#hc-auth-status-badge", "AUTHENTICATED"),
                    _wait_selector_text(page_b, "#hc-auth-status-badge", "AUTHENTICATED"),
                )

                server_unbootstrapped = [h for h in server_coord_hits if not h["has_browser"]]
                assert len(server_unbootstrapped) == 1, (
                    f"C2-H03/HIGH-02: Server /coord/session barrier caught {len(server_unbootstrapped)} "
                    f"concurrent unbootstrapped requests! server_trace={server_coord_hits}, client_calls={coord_calls}"
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
                reg_a = await _register_attempt_required(client_a, attempt_a)
                cap_a = reg_a["cancel_capability"]

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
                attempt_b = f"hc_userb_{uuid.uuid4().hex}"
                await _register_attempt_required(client_b, attempt_b)
                rb = await client_b.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_b, "password": "HamiCounter!901", "attempt_id": attempt_b},
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
# CE-08 (C2-M02/F04/F05/REV1-H04): Unconditionally verified F1 cookie
# overwrite + all-page BroadcastChannel suppression -> 401 /refresh rebinds F3
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
            # Suppress COOKIE_MAY_BE_STALE BroadcastChannel delivery across ALL pages in context
            await context.add_init_script(
                """
                (() => {
                  window.__hcStaleBroadcastReceived = 0;
                  if (typeof BroadcastChannel === 'function') {
                    const origPost = BroadcastChannel.prototype.postMessage;
                    BroadcastChannel.prototype.postMessage = function(msg) {
                      if (msg && msg.type === 'COOKIE_MAY_BE_STALE') return;
                      return origPost.apply(this, arguments);
                    };
                    const OrigBC = BroadcastChannel;
                    window.BroadcastChannel = class extends OrigBC {
                      addEventListener(type, listener, ...rest) {
                        if (type === 'message' && typeof listener === 'function') {
                          const wrapped = (ev) => {
                            if (ev && ev.data && ev.data.type === 'COOKIE_MAY_BE_STALE') {
                              window.__hcStaleBroadcastReceived += 1;
                              return;
                            }
                            return listener.call(this, ev);
                          };
                          return super.addEventListener(type, wrapped, ...rest);
                        }
                        return super.addEventListener(type, listener, ...rest);
                      }
                    };
                  }
                })();
                """
            )
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
                """
            )
            page_a = await context.new_page()

            b1_arrived_after_server = asyncio.Event()
            release_b1_response = asyncio.Event()
            b1_intercept_active = {"on": True}
            rebind_responses: list[int] = []
            refresh_responses: list[int] = []
            held_f1_refresh = {"value": ""}

            async def hold_b1_login(route):
                if b1_intercept_active["on"] and route.request.method == "POST":
                    b1_intercept_active["on"] = False
                    resp = await route.fetch()
                    for hdr_val in resp.headers_array:
                        if hdr_val["name"].lower() == "set-cookie" and hdr_val["value"].startswith("hc_refresh="):
                            held_f1_refresh["value"] = hdr_val["value"].split(";", 1)[0].split("=", 1)[1]
                    b1_arrived_after_server.set()
                    await release_b1_response.wait()
                    await route.fulfill(response=resp)
                    return
                await route.continue_()

            def _watch_page_a_resp(r):
                if r.request.method != "POST":
                    return
                if r.url.endswith("/api/v1/auth/session/rebind-cookie"):
                    rebind_responses.append(r.status)
                elif r.url.endswith("/api/v1/auth/refresh"):
                    refresh_responses.append(r.status)

            page_a.on("response", _watch_page_a_resp)

            try:
                await page_b.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page_a.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")

                # 1. Tab B initiates delayed login B1 (server mints F1, held in flight)
                await page_b.route("**/api/v1/auth/password/login", hold_b1_login)
                await page_b.fill("#hc-pwd-mobile", mobile)
                await page_b.fill("#hc-pwd-input", "HamiCounter!901")
                await page_b.click("#hc-pwd-login-btn")
                await asyncio.wait_for(b1_arrived_after_server.wait(), timeout=6.0)
                assert held_f1_refresh["value"], "Failed to capture F1 hc_refresh Set-Cookie from delayed 200!"

                # 2. Tab A logs out (revoking F1) and logs in as F3
                await page_a.click("#hc-logout-btn")
                await asyncio.sleep(0.15)
                await page_a.fill("#hc-pwd-mobile", mobile)
                await page_a.fill("#hc-pwd-input", "HamiCounter!901")
                await page_a.click("#hc-pwd-login-btn")
                await _wait_selector_text(page_a, "#hc-auth-status-badge", "AUTHENTICATED")
                jar_f3 = {c["name"]: c["value"] for c in await context.cookies()}
                assert jar_f3.get("hc_refresh") and jar_f3["hc_refresh"] != held_f1_refresh["value"]

                # 3. Release delayed B1 HTTP 200 and UNCONDITIONALLY assert jar was overwritten with stale F1
                release_b1_response.set()
                await asyncio.sleep(0.5)

                jar_overwritten = {c["name"]: c["value"] for c in await context.cookies()}
                assert jar_overwritten.get("hc_refresh") == held_f1_refresh["value"], (
                    f"REV1-H04: Delayed B1 did not overwrite jar with stale F1! "
                    f"held_f1={held_f1_refresh['value']!r}, jar={jar_overwritten.get('hc_refresh')!r}"
                )
                assert jar_overwritten.get("hc_csrf"), "Overwritten jar missing hc_csrf"
                assert await page_a.evaluate("() => window.__hcStaleBroadcastReceived") == 0

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

                # 4. Tab A clicks forced refresh WITHOUT BroadcastChannel hint -> MUST hit 401 then /rebind-cookie -> 200
                refresh_responses.clear()
                rebind_responses.clear()
                await page_a.click("#hc-refresh-btn")
                await asyncio.sleep(0.6)
                status_after = (await page_a.locator("#hc-auth-status-badge").inner_text()).strip()
                assert status_after == "AUTHENTICATED", (
                    f"C2-M02: Stale delayed 200 Set-Cookie broke Tab A ({status_after!r}) without COOKIE_MAY_BE_STALE!"
                )
                assert 401 in refresh_responses, f"Expected initial stale /refresh 401 before rebind, got {refresh_responses}"
                assert 200 in rebind_responses, f"Expected /session/rebind-cookie 200 recovery, got {rebind_responses}"
                jar_rebound = {c["name"]: c["value"] for c in await context.cookies()}
                assert jar_rebound.get("hc_refresh") and jar_rebound["hc_refresh"] != held_f1_refresh["value"]
            finally:
                release_b1_response.set()
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-08b (F04/F05/REV1-H04): Normal-TTL (120s) /session/rebind-cookie security matrix
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce08b_rebind_cookie_adversarial_matrix(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch, access_ttl=120)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=4)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client_a:
                await client_a.post("/api/v1/auth/coord/session")
                bid_a = client_a.cookies.get("hc_browser")
                assert bid_a

                # Login F1 -> superseded by newer login F2 on SAME browser (LATEST_FAMILY_WINS)
                f1_aid = f"hc_f1_{uuid.uuid4().hex}"
                await _register_attempt_required(client_a, f1_aid)
                r1 = await client_a.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f1_aid},
                )
                assert r1.status_code == 200
                tok1 = r1.json()["access_token"]
                f1 = uuid.UUID(r1.json()["family_id"])

                f2_aid = f"hc_f2_{uuid.uuid4().hex}"
                await _register_attempt_required(client_a, f2_aid)
                r2 = await client_a.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": f2_aid},
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

                # 5. Rebind vs /logout NEVER resurrects F2, and post-logout rebind fails 401
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
                assert r_reb2.status_code in (200, 401, 409)
                assert await svc.verify_active_family(f2, uid) is False

                rebind_after_lo = await client_a.post(
                    "/api/v1/auth/session/rebind-cookie",
                    headers={"Authorization": f"Bearer {tok2}"},
                    cookies={"hc_browser": bid_a},
                )
                assert rebind_after_lo.status_code == 401
                assert await svc.verify_active_family(f2, uid) is False
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-08c (F04/F05/REV1-H04): Isolated expired-bearer JWT rejected 401
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce08c_rebind_cookie_rejects_expired_bearer_jwt(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch, access_ttl=1)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client_a:
            await client_a.post("/api/v1/auth/coord/session")
            exp_aid = f"hc_exp_{uuid.uuid4().hex}"
            await _register_attempt_required(client_a, exp_aid)
            r_login = await client_a.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": exp_aid},
            )
            assert r_login.status_code == 200
            tok = r_login.json()["access_token"]

            await asyncio.sleep(1.5)
            rebind_exp = await client_a.post(
                "/api/v1/auth/session/rebind-cookie",
                headers={"Authorization": f"Bearer {tok}"},
            )
            assert rebind_exp.status_code == 401
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

                a1_id = f"hc_a1_{uuid.uuid4().hex}"
                a2_id = f"hc_a2_{uuid.uuid4().hex}"
                ub_id = f"hc_ub_{uuid.uuid4().hex}"
                await _register_attempt_required(dev_a1, a1_id)
                await _register_attempt_required(dev_a2, a2_id)
                await _register_attempt_required(user_b, ub_id)

                r_a1 = await dev_a1.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_a, "password": "HamiCounter!901", "attempt_id": a1_id},
                )
                r_a2 = await dev_a2.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_a, "password": "HamiCounter!901", "attempt_id": a2_id},
                )
                r_ub = await user_b.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile_b, "password": "HamiCounter!901", "attempt_id": ub_id},
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
# CE-11a (F01/REV1-M04): Forged started_server_logout_seq=999 on /password/login
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce11a_forged_logout_seq_password_login_rejected(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
            await client.post("/api/v1/auth/coord/session")

            init_aid = f"hc_init_pwd_{uuid.uuid4().hex}"
            await _register_attempt_required(client, init_aid)
            r1 = await client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": init_aid},
            )
            assert r1.status_code == 200
            # Register delayed attempt BEFORE logout (started_logout_seq == 0) -> then logout -> then delayed forged 999
            forged_aid = f"hc_forge_pwd_{uuid.uuid4().hex}"
            st_forged = await _register_attempt_required(client, forged_aid)
            assert st_forged["started_logout_seq"] == 0

            lo1 = await client.post(
                "/api/v1/auth/logout",
                headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": client.cookies.get("hc_csrf")},
            )
            assert lo1.status_code == 200

            forged_pwd = await client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={
                    "mobile": mobile,
                    "password": "HamiCounter!901",
                    "attempt_id": forged_aid,
                    "started_server_logout_seq": 999,
                },
            )
            assert forged_pwd.status_code == 409, (
                f"F01/HIGH-04: Pre-logout attempt with forged started_server_logout_seq=999 bypassed password rejection! "
                f"status={forged_pwd.status_code}"
            )
            assert await _count_active_refresh_tokens(uid) == 0
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-11b (F01/REV1-M04): Forged started_server_logout_seq=999 on /otp/verify
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce11b_forged_logout_seq_otp_verify_rejected(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
            await client.post("/api/v1/auth/coord/session")

            init_aid = f"hc_init_otp_{uuid.uuid4().hex}"
            await _register_attempt_required(client, init_aid)
            r1 = await client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": init_aid},
            )
            assert r1.status_code == 200
            # Register OTP attempt BEFORE logout (started_logout_seq == 0), execute logout, then submit delayed forged 999
            await OtpService(r).request_otp(mobile)
            otp_code = r.get(f"otp:code:{mobile}")
            assert otp_code
            forged_otp_aid = f"hc_forge_otp_{uuid.uuid4().hex}"
            st_forged_otp = await _register_attempt_required(client, forged_otp_aid, flow="OTP")
            assert st_forged_otp["started_logout_seq"] == 0

            lo1 = await client.post(
                "/api/v1/auth/logout",
                headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": client.cookies.get("hc_csrf")},
            )
            assert lo1.status_code == 200

            forged_otp = await client.post(
                "/api/v1/auth/otp/verify",
                headers={"X-Auth-Mode": "cookie"},
                json={
                    "mobile": mobile,
                    "code": otp_code,
                    "attempt_id": forged_otp_aid,
                    "started_server_logout_seq": 999,
                },
            )
            assert forged_otp.status_code == 409, (
                f"F01/HIGH-04: Pre-logout OTP attempt with forged started_server_logout_seq=999 bypassed rejection! "
                f"status={forged_otp.status_code}"
            )
            assert await _count_active_refresh_tokens(uid) == 0
    finally:
        r.close()
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-11c (F03/REV1-H05/M04): Concurrent duplicate attempt_id single family &
# PG 4-column composite FK rejects mismatched attempt/family binding
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce11c_concurrent_duplicate_attempt_id_and_binding_fk_enforced(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
            await client.post("/api/v1/auth/coord/session")

            dup_aid = f"hc_dup_{uuid.uuid4().hex}"
            await _register_attempt_required(client, dup_aid)
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
                fam_rows = await conn.fetch(
                    "SELECT family_id, browser_id, user_id FROM browser_session_families WHERE attempt_id = $1;",
                    dup_aid,
                )
                assert len(fam_rows) == 1
                fam_row = fam_rows[0]

                has_fk = await conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_las_exact_family_binding');"
                )
                assert has_fk, "REV1-H05: Composite 4-column FK fk_las_exact_family_binding missing from schema."

                mismatch_aid = f"hc_mismatch_{uuid.uuid4().hex}"
                with pytest.raises(asyncpg.ForeignKeyViolationError):
                    async with conn.transaction():
                        await conn.execute(
                            """
                            INSERT INTO login_attempt_states (
                                attempt_id, family_id, browser_id, user_id, status,
                                started_logout_seq, attempt_expires_at, expires_at
                            )
                            VALUES ($1, $2, $3, $4, 'ACTIVE', 0, NOW() + INTERVAL '30 seconds', NOW() + INTERVAL '3600 seconds');
                            """,
                            mismatch_aid,
                            fam_row["family_id"],
                            fam_row["browser_id"],
                            fam_row["user_id"],
                        )
            finally:
                await conn.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-12a (F08/REV1-M04): Continuous Lua ZSET sliding-window boundary & 429 non-pollution
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce12a_sliding_window_zset_boundary_and_429_non_pollution(monkeypatch):
    _clear_rate_limit_keys()
    monkeypatch.setattr(auth_mod, "CANCEL_RL_WINDOW_SECONDS", 2, raising=False)
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
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

            r429 = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [f"hc_sw_blocked_{uuid.uuid4().hex[:8]}"]},
            )
            assert r429.status_code == 429

            expected_anon_buckets = (
                "hc:rl:cancel:anon:ip:127.0.0.1:req",
                "hc:rl:cancel:anon:ip:127.0.0.1:ids",
                "hc:rl:cancel:anon:global:req",
                "hc:rl:cancel:anon:global:ids",
            )
            for bkey in expected_anon_buckets:
                assert r.type(bkey) == "zset", (
                    f"F08/M-02: Expected ZSET bucket {bkey}, got type={r.type(bkey)!r}"
                )
                assert r.zcard(bkey) == 20, (
                    f"F08/M-02: 429 request polluted ZSET bucket {bkey}: zcard={r.zcard(bkey)}"
                )

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
    finally:
        r.close()
        await _stop_server(server, thread)


# ---------------------------------------------------------------------------
# CE-12b (REV1-H06): Mixed :anon: (120s) and :auth: (300s) namespace isolation
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce12b_mixed_anon_and_auth_namespace_isolation(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with (
            httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as auth_client,
            httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as anon_client,
        ):
            await auth_client.post("/api/v1/auth/coord/session")
            a1 = f"hc_rl_auth_{uuid.uuid4().hex}"
            await _register_attempt_required(auth_client, a1)
            login_r = await auth_client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a1},
            )
            assert login_r.status_code == 200
            tok = login_r.json()["access_token"]

            c_auth = await auth_client.post(
                "/api/v1/auth/login-attempts/cancel",
                headers={"Authorization": f"Bearer {tok}"},
                json={"attempt_ids": [f"hc_auth_c_{uuid.uuid4().hex[:8]}"]},
            )
            assert c_auth.status_code == 200

            auth_ip_key = "hc:rl:cancel:auth:ip:127.0.0.1:req"
            assert r.type(auth_ip_key) == "zset", (
                f"REV1-H06: Expected isolated :auth: ZSET bucket, got type={r.type(auth_ip_key)!r}"
            )
            assert r.zcard(auth_ip_key) == 1
            auth_ttl_before = r.ttl(auth_ip_key)
            assert 250 <= auth_ttl_before <= 310

            # Seed an aged entry (180s ago: outside 120s anon window, INSIDE 300s auth window)
            aged_score = int(time.time() * 1000) - 180_000
            r.zadd(auth_ip_key, {f"{aged_score}:aged:1:1": aged_score})
            assert r.zcard(auth_ip_key) == 2

            # Now send 5 anonymous cancels from the same IP -> must hit :anon: ONLY!
            for idx in range(5):
                c_anon = await anon_client.post(
                    "/api/v1/auth/login-attempts/cancel",
                    json={"attempt_ids": [f"hc_anon_c_{idx}_{uuid.uuid4().hex[:8]}"]},
                )
                assert c_anon.status_code == 200

            anon_ip_key = "hc:rl:cancel:anon:ip:127.0.0.1:req"
            assert r.type(anon_ip_key) == "zset"
            assert r.zcard(anon_ip_key) == 5
            assert 0 < r.ttl(anon_ip_key) <= 130

            # Anonymous 120s pruning/PEXPIRE MUST NOT prune or shorten authenticated 300s entries!
            assert r.zcard(auth_ip_key) == 2, (
                f"REV1-H06: Anonymous 120s cleanup corrupted authenticated 300s bucket! zcard={r.zcard(auth_ip_key)}"
            )
            assert r.ttl(auth_ip_key) >= 250, (
                f"REV1-H06: Anonymous PEXPIRE truncated authenticated TTL to {r.ttl(auth_ip_key)}"
            )
    finally:
        r.close()
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-12c (F08/REV1-M04): Weighted attempt-ID quota & Redis outage 503 fail-closed
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce12c_weighted_ids_cap_and_redis_503_fail_closed(monkeypatch):
    _clear_rate_limit_keys()
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
            for b in range(4):
                batch_ids = [f"hc_wid_{b}_{j}_{uuid.uuid4().hex[:8]}" for j in range(16)]
                rw = await client.post("/api/v1/auth/login-attempts/cancel", json={"attempt_ids": batch_ids})
                assert rw.status_code == 200
            rw_over = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [f"hc_wid_over_{uuid.uuid4().hex[:8]}"]},
            )
            assert rw_over.status_code == 429, (
                f"F08: Weighted ID quota allowed >64 IDs! status={rw_over.status_code}"
            )
            ip_ids_key = "hc:rl:cancel:anon:ip:127.0.0.1:ids"
            assert r.type(ip_ids_key) == "zset"
            assert r.zcard(ip_ids_key) == 64

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
            app_pool = await deps.get_db_pool()
            pg_writes_during_503: list[str] = []

            class _WriteSpyConn:
                def __init__(self, conn):
                    self._conn = conn

                def __getattr__(self, item):
                    return getattr(self._conn, item)

                async def execute(self, query, *args, **kwargs):
                    q_up = " ".join(str(query).upper().split())
                    if any(kw in q_up for kw in ("INSERT ", "UPDATE ", "DELETE ")):
                        pg_writes_during_503.append(q_up[:100])
                    return await self._conn.execute(query, *args, **kwargs)

            class _WriteSpyAcquire:
                def __init__(self, ctx):
                    self._ctx = ctx

                async def __aenter__(self):
                    return _WriteSpyConn(await self._ctx.__aenter__())

                async def __aexit__(self, exc_type, exc, tb):
                    return await self._ctx.__aexit__(exc_type, exc, tb)

            class _WriteSpyPool:
                def __init__(self, inner):
                    self._inner = inner

                def __getattr__(self, item):
                    return getattr(self._inner, item)

                def acquire(self, *args, **kwargs):
                    return _WriteSpyAcquire(self._inner.acquire(*args, **kwargs))

            monkeypatch.setattr(deps, "_pool", _WriteSpyPool(app_pool))
            probe_503_aid = f"hc_rl503_{uuid.uuid4().hex[:8]}"
            r503 = await client.post(
                "/api/v1/auth/login-attempts/cancel",
                json={"attempt_ids": [probe_503_aid]},
            )
            monkeypatch.setattr(deps, "_pool", app_pool)
            assert r503.status_code == 503
            assert len(pg_writes_during_503) == 0, (
                f"M-02: Rate-limiter Redis 503 executed PG write mutations: {pg_writes_during_503}"
            )
            conn_chk = await asyncpg.connect(DATABASE_URL)
            try:
                if await conn_chk.fetchval("SELECT to_regclass('public.login_attempt_states') IS NOT NULL;"):
                    row_cnt = await conn_chk.fetchval(
                        "SELECT COUNT(*) FROM login_attempt_states WHERE attempt_id = $1;",
                        probe_503_aid,
                    )
                    assert row_cnt == 0, f"M-02: Redis 503 leaked PG attempt row {probe_503_aid}"
            finally:
                await conn_chk.close()
    finally:
        r.close()
        await _stop_server(server, thread)


# ---------------------------------------------------------------------------
# CE-13a (F07): Missing navigator.locks fails closed with zero login traffic
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce13a_missing_web_locks_fails_closed(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            page = await context.new_page()

            login_net_calls: list[str] = []
            page.on(
                "request",
                lambda req: login_net_calls.append(req.url) if "/api/v1/auth/password/login" in req.url else None,
            )

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
                assert len(login_net_calls) == 0, f"F07: Sent login request without navigator.locks: {login_net_calls}"
                assert await _count_active_refresh_tokens(uid) == 0
            finally:
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-13b (F07/REV1-M02): Forged hc_coord.bi=1 under normal Web Locks still
# invokes authoritative /coord/session and cannot trust forged seq values
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce13b_forged_bi_hint_ignored_under_normal_web_locks(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        async with async_playwright() as p:
            browser = await _launch_headless_chromium(p)
            context = await browser.new_context()
            page = await context.new_page()

            coord_requests: list[int] = []

            def _watch_coord(resp):
                if resp.request.method == "POST" and resp.url.endswith("/api/v1/auth/coord/session"):
                    coord_requests.append(resp.status)

            page.on("response", _watch_coord)

            await page.add_init_script(
                """
                (() => {
                  document.cookie = 'hc_coord=g.99.lo.0.li.99.sg.99.slo.0.sli.99.lp.0.bi.1; Path=/; SameSite=Lax';
                })();
                """
            )
            try:
                await page.goto(f"{base_url}/phase3/#/auth/shell", wait_until="networkidle")
                await page.fill("#hc-pwd-mobile", mobile)
                await page.fill("#hc-pwd-input", "HamiCounter!901")
                await page.click("#hc-pwd-login-btn")
                await _wait_selector_text(page, "#hc-auth-status-badge", "AUTHENTICATED")

                assert len(coord_requests) >= 1 and 200 in coord_requests, (
                    f"REV1-M02: Client skipped authoritative /coord/session due to forged hc_coord.bi=1! calls={coord_requests}"
                )
                jar = {c["name"]: c["value"] for c in await context.cookies()}
                assert jar.get("hc_browser"), "REV1-M02: Expected server-signed hc_browser cookie despite forged bi=1!"

                # Verify server PG state wasn't inflated to forged g.99 / lo.0 / li.99
                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers={"Origin": base_url},
                    cookies={"hc_browser": jar["hc_browser"]},
                ) as verify_client:
                    st = await verify_client.post(
                        "/api/v1/auth/login-attempts/start",
                        json={"attempt_id": f"hc_bi_check_{uuid.uuid4().hex}", "flow": "PASSWORD"},
                    )
                    assert st.status_code == 200, (
                        f"REV1-M02: /login-attempts/start missing or failed after login: {st.status_code}"
                    )
                    assert st.json()["started_logout_seq"] == 0
            finally:
                await context.close()
                await browser.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-14 (REV1-H07/REV1-H01): Pre-Phase-A delayed /password/login after
# /login-attempts/start rejected 409; unregistered coordinated login rejected
# 409; concurrent L1/L2/L4/L6/L3 operations complete with 0 PG deadlocks
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce14_pre_phase_a_delayed_login_unregistered_reject_and_lock_stress(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    try:
        pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=8)
        svc = SessionService(pool, redis_client=deps.get_redis())
        try:
            async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
                await client.post("/api/v1/auth/coord/session")

                # Setup login so browser logout_seq starts clean
                a_init = f"hc_ce14_init_{uuid.uuid4().hex}"
                st_init = await client.post(
                    "/api/v1/auth/login-attempts/start",
                    json={"attempt_id": a_init, "flow": "PASSWORD"},
                )
                assert st_init.status_code == 200, (
                    f"REV1-H07: /login-attempts/start missing or failed: {st_init.status_code}"
                )
                r_init = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a_init},
                )
                assert r_init.status_code == 200

                # 1. Pre-Phase-A delay scenario (REV1-H07):
                # Register delayed_aid at logout_seq=0, THEN Tab A logs out BEFORE delayed_aid reaches Phase A!
                delayed_aid = f"hc_ce14_prephasea_{uuid.uuid4().hex}"
                st_del = await client.post(
                    "/api/v1/auth/login-attempts/start",
                    json={"attempt_id": delayed_aid, "flow": "PASSWORD"},
                )
                assert st_del.status_code == 200
                assert st_del.json()["started_logout_seq"] == 0

                lo = await client.post(
                    "/api/v1/auth/logout",
                    headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": client.cookies.get("hc_csrf")},
                )
                assert lo.status_code == 200
                assert await _count_active_refresh_tokens(uid) == 0

                # Spy on AuthService.authenticate_via_password to prove Phase A rejects BEFORE Argon2 work!
                pwd_calls = {"count": 0}
                orig_auth_pwd = AuthService.authenticate_via_password

                async def _spy_auth_pwd(self, *args, **kwargs):
                    pwd_calls["count"] += 1
                    return await orig_auth_pwd(self, *args, **kwargs)

                monkeypatch.setattr(AuthService, "authenticate_via_password", _spy_auth_pwd)

                late_pre_phase_a = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": delayed_aid},
                )
                assert late_pre_phase_a.status_code == 409, (
                    f"REV1-H07: Pre-Phase-A delayed login bypassed post-registration logout! "
                    f"status={late_pre_phase_a.status_code}"
                )
                assert pwd_calls["count"] == 0, "REV1-H07: Rejected Phase A executed slow password verification!"

                # 2. Unregistered attempt on coordinated browser MUST fail 409 BEFORE Argon2!
                unreg_resp = await client.post(
                    "/api/v1/auth/password/login",
                    headers={"X-Auth-Mode": "cookie"},
                    json={
                        "mobile": mobile,
                        "password": "HamiCounter!901",
                        "attempt_id": f"hc_ce14_unreg_{uuid.uuid4().hex}",
                    },
                )
                assert unreg_resp.status_code == 409, (
                    f"REV1-H07: Coordinated browser accepted unregistered attempt_id! status={unreg_resp.status_code}"
                )
                assert pwd_calls["count"] == 0
                assert await _count_active_refresh_tokens(uid) == 0

                # 3. Competing PG lock-order stress across L1/L2/L4/L6/L3 (REV1-H01): 0 deadlocks, 0 5xx
                monkeypatch.setattr(AuthService, "authenticate_via_password", orig_auth_pwd)
                for _round in range(2):
                    a_main = f"hc_stress_main_{uuid.uuid4().hex}"
                    assert (await client.post(
                        "/api/v1/auth/login-attempts/start",
                        json={"attempt_id": a_main, "flow": "PASSWORD"},
                    )).status_code == 200
                    r_main = await client.post(
                        "/api/v1/auth/password/login",
                        headers={"X-Auth-Mode": "cookie"},
                        json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": a_main},
                    )
                    assert r_main.status_code == 200
                    tok_main = r_main.json()["access_token"]
                    csrf_main = client.cookies.get("hc_csrf")

                    a_race = f"hc_stress_race_{uuid.uuid4().hex}"
                    st_race = await client.post(
                        "/api/v1/auth/login-attempts/start",
                        json={"attempt_id": a_race, "flow": "PASSWORD"},
                    )
                    assert st_race.status_code == 200
                    cap_race = st_race.json()["cancel_capability"]

                    async def _do_l1(aid=a_race):
                        return await client.post(
                            "/api/v1/auth/password/login",
                            headers={"X-Auth-Mode": "cookie"},
                            json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": aid},
                        )

                    async def _do_l2(aid=a_race, cap=cap_race):
                        return await client.post(
                            "/api/v1/auth/login-attempts/cancel",
                            json={"attempt_ids": [aid], "cancel_capabilities": {aid: cap}},
                        )

                    async def _do_l4(csrf=csrf_main):
                        return await client.post(
                            "/api/v1/auth/logout",
                            headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": csrf},
                        )

                    async def _do_l6(tok=tok_main):
                        return await client.post(
                            "/api/v1/auth/session/rebind-cookie",
                            headers={"Authorization": f"Bearer {tok}"},
                        )

                    async def _do_l3():
                        return await svc.reconcile_pending_revocations(batch_size=5, max_batches=2)

                    results = await asyncio.gather(
                        _do_l1(),
                        _do_l2(),
                        _do_l4(),
                        _do_l6(),
                        _do_l3(),
                        return_exceptions=False,
                    )
                    for res in results[:4]:
                        assert res.status_code < 500, f"REV1-H01: Lock-order server failure status={res.status_code}: {res.text}"

                await svc.reconcile_pending_revocations(batch_size=20, max_batches=5)
                if client.cookies.get("hc_csrf"):
                    await client.post(
                        "/api/v1/auth/logout",
                        headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": client.cookies.get("hc_csrf")},
                    )
                assert await _count_active_refresh_tokens(uid) == 0
        finally:
            await pool.close()
    finally:
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-15 (M-05): Unregistered & pre-Phase-A delayed /otp/verify rejected 409
# strictly BEFORE AuthService.authenticate_via_otp / OTP consumption
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce15_unregistered_and_pre_phase_a_otp_verify_rejected(monkeypatch):
    _clear_rate_limit_keys()
    uid, mobile = await _create_test_user(["USER"])
    server, thread, base_url = await _start_test_server(monkeypatch)
    r = redis.from_url(REDIS_URL, decode_responses=True)
    try:
        async with httpx.AsyncClient(base_url=base_url, headers={"Origin": base_url}) as client:
            assert (await client.post("/api/v1/auth/coord/session")).status_code == 200

            # Request real OTP and keep it unused in Redis
            await OtpService(r).request_otp(mobile)
            otp_code = r.get(f"otp:code:{mobile}")
            assert otp_code

            # 1. Pre-Phase-A delayed OTP registration at logout_seq=0, then logout before /otp/verify reaches Phase A
            delayed_otp_aid = f"hc_ce15_pre_otp_{uuid.uuid4().hex}"
            st_otp = await _register_attempt_required(client, delayed_otp_aid, flow="OTP")
            assert st_otp["started_logout_seq"] == 0

            # Log in & out quickly via password to advance server logout_seq >= 1 cleanly
            pw_aid = f"hc_ce15_pw_{uuid.uuid4().hex}"
            await _register_attempt_required(client, pw_aid, flow="PASSWORD")
            # Actually re-registering/logging in pw_aid increments nothing until logout; logout invalidates delayed_otp_aid
            r_pw = await client.post(
                "/api/v1/auth/password/login",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "password": "HamiCounter!901", "attempt_id": pw_aid},
            )
            assert r_pw.status_code == 200
            lo = await client.post(
                "/api/v1/auth/logout",
                headers={"X-Auth-Mode": "cookie", "X-CSRF-Token": client.cookies.get("hc_csrf")},
            )
            assert lo.status_code == 200
            assert await _count_active_refresh_tokens(uid) == 0

            # Spy on AuthService.authenticate_via_otp to prove Phase A rejects BEFORE OTP verification/consume!
            otp_calls = {"count": 0}
            orig_auth_otp = AuthService.authenticate_via_otp

            async def _spy_auth_otp(self, *args, **kwargs):
                otp_calls["count"] += 1
                return await orig_auth_otp(self, *args, **kwargs)

            monkeypatch.setattr(AuthService, "authenticate_via_otp", _spy_auth_otp)

            late_otp = await client.post(
                "/api/v1/auth/otp/verify",
                headers={"X-Auth-Mode": "cookie"},
                json={"mobile": mobile, "code": otp_code, "attempt_id": delayed_otp_aid},
            )
            assert late_otp.status_code == 409, (
                f"M-05: Pre-Phase-A delayed /otp/verify bypassed post-registration logout! status={late_otp.status_code}"
            )
            assert otp_calls["count"] == 0, "M-05: Rejected OTP Phase A executed authenticate_via_otp!"
            assert r.get(f"otp:code:{mobile}") == otp_code, "M-05: Rejected /otp/verify consumed OTP!"

            # 2. Completely unregistered OTP attempt on coordinated browser MUST fail 409 BEFORE authenticate_via_otp!
            unreg_otp = await client.post(
                "/api/v1/auth/otp/verify",
                headers={"X-Auth-Mode": "cookie"},
                json={
                    "mobile": mobile,
                    "code": otp_code,
                    "attempt_id": f"hc_ce15_unreg_otp_{uuid.uuid4().hex}",
                },
            )
            assert unreg_otp.status_code == 409, (
                f"M-05: Coordinated browser accepted unregistered /otp/verify! status={unreg_otp.status_code}"
            )
            assert otp_calls["count"] == 0, "M-05: Unregistered /otp/verify executed authenticate_via_otp!"
            assert r.get(f"otp:code:{mobile}") == otp_code
            assert await _count_active_refresh_tokens(uid) == 0
    finally:
        r.close()
        await _stop_server(server, thread)
        await _cleanup_user(uid)


# ---------------------------------------------------------------------------
# CE-16 (REV1-M03/M-03): Adversarial Garbage Collection preserves STARTED,
# IN_FLIGHT, ACTIVE, PENDING_REVOKE, unexpired tombstones & <10d REVOKED families
# while safely collecting expired tombstones & >10d REVOKED families child-first
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ce16_gc_adversarial_preserves_live_records_and_tombstones(monkeypatch):
    _clear_rate_limit_keys()
    assert hasattr(SessionService, "purge_expired_auth_records"), (
        "M-03: SessionService.purge_expired_auth_records missing from baseline!"
    )
    uid, _mobile = await _create_test_user(["USER"])
    bid = f"b_gc_{uuid.uuid4().hex}"
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=2)
    svc = SessionService(pool, redis_client=deps.get_redis())

    fid_active = uuid.uuid4()
    fid_pending = uuid.uuid4()
    fid_recent_rev = uuid.uuid4()
    fid_old_rev = uuid.uuid4()

    aid_active = f"hc_gc_act_{uuid.uuid4().hex}"
    aid_pending = f"hc_gc_pnd_{uuid.uuid4().hex}"
    aid_recent_rev = f"hc_gc_rcr_{uuid.uuid4().hex}"
    aid_old_rev = f"hc_gc_oldr_{uuid.uuid4().hex}"
    aid_started = f"hc_gc_str_{uuid.uuid4().hex}"
    aid_inflight = f"hc_gc_inf_{uuid.uuid4().hex}"
    aid_tomb_keep = f"hc_gc_tk_{uuid.uuid4().hex}"
    aid_tomb_purge = f"hc_gc_tp_{uuid.uuid4().hex}"

    try:
        async with pool.acquire() as conn:
            has_tables = await conn.fetchval(
                "SELECT to_regclass('public.browser_session_families') IS NOT NULL "
                "AND to_regclass('public.login_attempt_states') IS NOT NULL;"
            )
            assert has_tables, "M-03: Coordination tables missing from schema!"

            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO browser_coord_state (browser_id, coordinated, global_seq, logout_seq, login_seq) "
                    "VALUES ($1, TRUE, 10, 1, 10);",
                    bid,
                )
                # 1. ACTIVE family + child attempt + ACTIVE token (even old timestamps -> NEVER purged!)
                await conn.execute(
                    "INSERT INTO browser_session_families (family_id, browser_id, user_id, attempt_id, created_seq, status, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, 10, 'ACTIVE', NOW() - INTERVAL '15 days', NOW() - INTERVAL '15 days');",
                    fid_active, bid, uid, aid_active,
                )
                await conn.execute(
                    "INSERT INTO login_attempt_states (attempt_id, family_id, browser_id, user_id, status, started_logout_seq, attempt_expires_at, expires_at) "
                    "VALUES ($1, $2, $3, $4, 'ACTIVE', 0, NOW() - INTERVAL '12 days', NOW() - INTERVAL '12 days');",
                    aid_active, fid_active, bid, uid,
                )
                await conn.execute(
                    "INSERT INTO refresh_tokens (family_id, user_id, token_hash, status, expires_at) "
                    "VALUES ($1, $2, $3, 'ACTIVE', NOW() + INTERVAL '7 days');",
                    fid_active, uid, uuid.uuid4().hex * 2,
                )

                # 2. PENDING_REVOKE family + child attempt + REVOKED token (unconfirmed by Redis -> NEVER purged!)
                await conn.execute(
                    "INSERT INTO browser_session_families (family_id, browser_id, user_id, attempt_id, created_seq, status, revoke_reason, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, 9, 'PENDING_REVOKE', 'LOGOUT', NOW() - INTERVAL '15 days', NOW() - INTERVAL '15 days');",
                    fid_pending, bid, uid, aid_pending,
                )
                await conn.execute(
                    "INSERT INTO login_attempt_states (attempt_id, family_id, browser_id, user_id, status, started_logout_seq, attempt_expires_at, expires_at) "
                    "VALUES ($1, $2, $3, $4, 'PENDING_REVOKE', 0, NOW() - INTERVAL '12 days', NOW() - INTERVAL '12 days');",
                    aid_pending, fid_pending, bid, uid,
                )
                await conn.execute(
                    "INSERT INTO refresh_tokens (family_id, user_id, token_hash, status, expires_at) "
                    "VALUES ($1, $2, $3, 'REVOKED', NOW() - INTERVAL '1 day');",
                    fid_pending, uid, uuid.uuid4().hex * 2,
                )

                # 3. Recent REVOKED family (2 days old < 10d retention -> PRESERVED!)
                await conn.execute(
                    "INSERT INTO browser_session_families (family_id, browser_id, user_id, attempt_id, created_seq, status, revoke_reason, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, 8, 'REVOKED', 'LOGOUT', NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days');",
                    fid_recent_rev, bid, uid, aid_recent_rev,
                )
                await conn.execute(
                    "INSERT INTO login_attempt_states (attempt_id, family_id, browser_id, user_id, status, started_logout_seq, attempt_expires_at, expires_at) "
                    "VALUES ($1, $2, $3, $4, 'REVOKED', 0, NOW() - INTERVAL '2 days', NOW() + INTERVAL '600 seconds');",
                    aid_recent_rev, fid_recent_rev, bid, uid,
                )

                # 4. Old REVOKED family (11 days old > 10d retention) + expired attempt + REVOKED token -> PURGED safely child-first!
                await conn.execute(
                    "INSERT INTO browser_session_families (family_id, browser_id, user_id, attempt_id, created_seq, status, revoke_reason, created_at, updated_at) "
                    "VALUES ($1, $2, $3, $4, 7, 'REVOKED', 'LOGOUT', NOW() - INTERVAL '15 days', NOW() - INTERVAL '11 days');",
                    fid_old_rev, bid, uid, aid_old_rev,
                )
                await conn.execute(
                    "INSERT INTO login_attempt_states (attempt_id, family_id, browser_id, user_id, status, started_logout_seq, attempt_expires_at, expires_at) "
                    "VALUES ($1, $2, $3, $4, 'REVOKED', 0, NOW() - INTERVAL '11 days', NOW() - INTERVAL '10 days');",
                    aid_old_rev, fid_old_rev, bid, uid,
                )
                await conn.execute(
                    "INSERT INTO refresh_tokens (family_id, user_id, token_hash, status, expires_at) "
                    "VALUES ($1, $2, $3, 'REVOKED', NOW() - INTERVAL '4 days');",
                    fid_old_rev, uid, uuid.uuid4().hex * 2,
                )

                # 5. Live STARTED & IN_FLIGHT attempts -> NEVER deleted!
                await conn.execute(
                    "INSERT INTO login_attempt_states (attempt_id, browser_id, status, started_logout_seq, attempt_expires_at, expires_at) "
                    "VALUES ($1, $2, 'STARTED', 1, NOW() + INTERVAL '25 seconds', NOW() + INTERVAL '3600 seconds'), "
                    "($3, $2, 'IN_FLIGHT', 1, NOW() + INTERVAL '25 seconds', NOW() + INTERVAL '3600 seconds');",
                    aid_started, bid, aid_inflight,
                )

                # 6. Unexpired CANCELLED tombstone (attempt_expires_at expired -60s ago, tombstone expires_at +1800s ahead -> KEPT!)
                #    vs fully expired CANCELLED tombstone (expires_at -60s -> PURGED!)
                await conn.execute(
                    "INSERT INTO login_attempt_states (attempt_id, browser_id, status, started_logout_seq, attempt_expires_at, expires_at) "
                    "VALUES ($1, $2, 'CANCELLED', 1, NOW() - INTERVAL '60 seconds', NOW() + INTERVAL '1800 seconds'), "
                    "($3, $2, 'CANCELLED', 1, NOW() - INTERVAL '4000 seconds', NOW() - INTERVAL '60 seconds');",
                    aid_tomb_keep, bid, aid_tomb_purge,
                )

        purged_count = await svc.purge_expired_auth_records(batch_size=200)
        assert purged_count >= 2

        async with pool.acquire() as conn:
            # Preserved entities
            assert await conn.fetchval("SELECT status FROM browser_session_families WHERE family_id = $1;", fid_active) == "ACTIVE"
            assert await conn.fetchval("SELECT status FROM login_attempt_states WHERE attempt_id = $1;", aid_active) == "ACTIVE"
            assert await conn.fetchval("SELECT status FROM browser_session_families WHERE family_id = $1;", fid_pending) == "PENDING_REVOKE"
            assert await conn.fetchval("SELECT status FROM login_attempt_states WHERE attempt_id = $1;", aid_pending) == "PENDING_REVOKE"
            assert await conn.fetchval("SELECT status FROM browser_session_families WHERE family_id = $1;", fid_recent_rev) == "REVOKED"
            assert await conn.fetchval("SELECT status FROM login_attempt_states WHERE attempt_id = $1;", aid_started) == "STARTED"
            assert await conn.fetchval("SELECT status FROM login_attempt_states WHERE attempt_id = $1;", aid_inflight) == "IN_FLIGHT"
            assert await conn.fetchval("SELECT status FROM login_attempt_states WHERE attempt_id = $1;", aid_tomb_keep) == "CANCELLED"

            # Collected expired entities
            assert await conn.fetchval("SELECT COUNT(*) FROM login_attempt_states WHERE attempt_id = $1;", aid_tomb_purge) == 0
            assert await conn.fetchval("SELECT COUNT(*) FROM login_attempt_states WHERE attempt_id = $1;", aid_old_rev) == 0
            assert await conn.fetchval("SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1;", fid_old_rev) == 0
            assert await conn.fetchval("SELECT COUNT(*) FROM browser_session_families WHERE family_id = $1;", fid_old_rev) == 0
    finally:
        async with pool.acquire() as conn:
            for tbl, col, vals in (
                ("login_attempt_states", "browser_id", bid),
                ("refresh_tokens", "user_id", uid),
                ("browser_session_families", "browser_id", bid),
                ("browser_coord_state", "browser_id", bid),
            ):
                if await conn.fetchval("SELECT to_regclass($1) IS NOT NULL;", f"public.{tbl}"):
                    await conn.execute(f"DELETE FROM {tbl} WHERE {col} = $1;", vals)
        await pool.close()
        await _cleanup_user(uid)
