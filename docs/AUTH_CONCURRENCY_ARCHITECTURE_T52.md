# HamiCard Phase 3 Authentication Concurrency Architecture & Failure-Recovery Specification (`HC-T52`)

- **Command**: `HC-CMD-053` / `HC-T52` (Design-and-Test-First Gate prior to `HC-T53` implementation)
- **Base Commit (`OLD_CANDIDATE`)**: `e7c2bb81f7278e1d9a0fe8ca75e56d06fec753fb`
- **Target Scope**: Remediate all `4` HIGH (`R2-T50-C2-H01..H04`), `3` MEDIUM (`R2-T50-C2-M01..M03`), and `1` LOW (`R2-T50-C2-L01`) defects by simplifying coordination around PostgreSQL ACID linearization + durable pending-revocation bookkeeping + strictly scoped attempt cancellation.
- **Invariant Constraint**: Zero application behavior edits (`src/`, `db/`, `scripts/`, `Dockerfile`) in `HC-T52`. Implementation runs in `HC-T53` only after independent Design Gate `PASS`.

---

## 1. Architectural Simplification, Coordination Tradeoff & Source References

In `e7c2bb81`, two design choices caused cascading races:
1. Overloading `POST /api/v1/auth/login-attempts/cancel` with browser-wide logout bumps (`_bump_browser_logout_and_pop_families` at `src/api/auth.py:1505-1515`) triggered automatically on non-logged-out cleanup (`src/ui_shell/js/auth_session.js:560-564`).
2. Keeping mutable sequence state and family discovery in non-atomic Redis commands (`INCR` + `SET` + `SMEMBERS` + `DEL` at `src/api/auth.py:265-324`) deleted **before** PostgreSQL revocation completed (`src/api/auth.py:1330-1339`), plus unlocked provisional `writeCoordCookie()` calls (`src/ui_shell/js/auth_session.js:425-430, 1241-1246, 1468-1580`), unvalidated `hc_browser` / `Bearer ` quota escalation (`src/api/auth.py:1445-1454`), fixed-window `_enforce_sliding_quota` (`src/api/auth.py:327-345`), and duplicate bootstrap minting (`src/api/auth.py:221-228`).

**Coordination Simplification Evaluation (`HC-CMD-053`)**:
We evaluated removing browser-wide coordination (`hc_browser`, `hc_coord`) completely. Keeping only `attempt_id` handles pre-commit cancellations, **except** when a user initiates `/logout` in Tab A *after* Tab B started an in-flight `/otp/verify` or `/password/login` whose `attempt_id` hasn't yet reached Tab A's closure (or when a delayed HTTP `200 Set-Cookie` overwrites a newer family's jar cookie and needs generation check for `/session/rebind-cookie`). Therefore, `T52` **minimizes** browser-wide state to ONLY what per-attempt binding cannot express:
- **`/login-attempts/cancel` is strictly attempt-scoped**: NEVER touches `browser_coord_state.logout_seq` and NEVER pops unrelated browser families (`browser_session_families`). It cancels ONLY supplied `attempt_id`s and revokes ONLY 1:1 bound families (`login_attempt_states.family_id`) after verifying ownership (same verified user or unauthenticated same-browser binding).
- **PostgreSQL (`SELECT ... FOR UPDATE`) is the Single Source of Truth (SSOT)** for browser sequence linearization (`browser_coord_state`), active/pending browser session families (`browser_session_families`), and login-attempt ownership/cancellation state (`login_attempt_states`).
- **Redis** holds:
  1. Fail-closed fast revocation cache (`hc:revoked_family:{fid}`) populated **from** PostgreSQL and never treated as sole storage of unrevoked work (`PENDING_REVOKE` stays in PG until Redis confirms).
  2. Atomic Lua `MAX`-monotonic coordination cache (`hc:browser_coord:{bid}`) synced from PG (preventing sequence inversion even under out-of-order async tasks).
  3. Atomic Lua ZSET sliding-window rate-limit buckets (`hc:rl:*`).
- **Client `hc_coord` is a non-secret UI sync hint only**: every write runs exclusively inside `withCoordLock(...)` (including an in-tab async queue + `navigator.locks`); initial `hc_browser` bootstrap runs under a dedicated `hamicard_phase3_browser_init` lock so two fresh tabs cannot split `hc_browser` identities and logout cannot deadlock behind a slow bootstrap call.

**Exact Defect -> Source Reference Matrix (`e7c2bb81` -> `HC-T53` Targets)**:

| ID | Vulnerable `e7c2bb81` Source | `HC-T53` Target Locations |
|----|------------------------------|---------------------------|
| `C2-H01` | `src/api/auth.py:1505-1515`, `src/ui_shell/js/auth_session.js:560-564` | `src/auth/session_service.py`, `src/api/auth.py` (`/login-attempts/cancel`), `src/ui_shell/js/auth_session.js` (`revokeSupersededLoginOnServer`) |
| `C2-H02` | `src/api/auth.py:248-324, 1330-1347`, `src/auth/session_service.py:331-348` | `db/schema.sql`, `src/auth/session_service.py` (`PENDING_REVOKE` + `reconcile_pending_revocations`), `src/api/auth.py` |
| `C2-H03` | `src/api/auth.py:221-228`, `src/ui_shell/js/auth_session.js:249-276` | `src/ui_shell/js/auth_session.js` (`hamicard_phase3_browser_init`), `src/api/auth.py` (`_ensure_browser_id` + `/coord/session`) |
| `C2-H04` | `src/api/auth.py:265-324`, `src/ui_shell/js/auth_session.js:425-430, 1241-1246, 1468-1580` | `src/auth/session_service.py` (`FOR UPDATE` + Lua `MAX`), `src/ui_shell/js/auth_session.js` (strict `withCoordLock` discipline) |
| `C2-M01` | `src/api/auth.py:1445-1454, 348-375` | `src/api/auth.py` (real crypto `verify_access_token` + `verify_active_session` + Redis revocation check; ownership binding) |
| `C2-M02` | `src/api/auth.py` (cookie jar overwrite by late HTTP 200), `src/ui_shell/js/auth_session.js:569-630` | `src/api/auth.py` (`POST /api/v1/auth/session/rebind-cookie`), `src/ui_shell/js/auth_session.js` (`COOKIE_MAY_BE_STALE` + `executeCookieRefreshRequest`) |
| `C2-M03` | `src/ui_shell/js/auth_session.js:534-565` | `src/ui_shell/js/auth_session.js` (`unresolvedCancelledAttemptIds` + error UI state + retryable status), `src/ui_shell/js/app.js` |
| `C2-L01` | `src/api/auth.py:327-345` | `src/api/auth.py` (Lua ZSET continuous sliding window) |

---

## 2. Additive PostgreSQL SSOT Schema (for `HC-T53`)

1. **`browser_coord_state`**
   - `browser_id VARCHAR(64) PRIMARY KEY`
   - `global_seq BIGINT NOT NULL DEFAULT 0`
   - `logout_seq BIGINT NOT NULL DEFAULT 0`
   - `login_seq BIGINT NOT NULL DEFAULT 0`
   - `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
2. **`browser_session_families`**
   - `family_id UUID PRIMARY KEY`
   - `browser_id VARCHAR(64) NOT NULL REFERENCES browser_coord_state(browser_id) ON DELETE CASCADE`
   - `user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE`
   - `attempt_id VARCHAR(96) NULL`
   - `created_seq BIGINT NOT NULL`
   - `status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'PENDING_REVOKE', 'REVOKED'))`
   - `revoke_reason VARCHAR(40) NULL`
   - `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
   - Partial index on `(browser_id, status) WHERE status IN ('ACTIVE', 'PENDING_REVOKE')` and index `(status) WHERE status = 'PENDING_REVOKE'`.
3. **`login_attempt_states`**
   - `attempt_id VARCHAR(96) PRIMARY KEY`
   - `family_id UUID NULL`
   - `browser_id VARCHAR(64) NULL`
   - `user_id UUID NULL`
   - `status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'CANCELLED', 'PENDING_REVOKE', 'REVOKED'))`
   - `expires_at TIMESTAMPTZ NOT NULL`
   - `created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
   - `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`
   - Partial index on `(status) WHERE status = 'PENDING_REVOKE'`.

All `CREATE TABLE IF NOT EXISTS` statements live in `db/schema.sql` and are additionally ensured idempotently via `SessionService.ensure_coord_schema()`. Zero changes to financial/core tables (`wallets`, `settlements`, `system_settings`, etc.); existing 26 tables and `18/18 OPEN-* == PROPOSED` remain unchanged.

---

## 3. Complete State Machines

### 3.1 Session Family Lifecycle (PG + Redis)
- `NONE` --(Login Commit w/o superseding logout/cancel)--> `ACTIVE` (`created_seq = new_seq`, `refresh_tokens.status = 'ACTIVE'`)
- `ACTIVE` --(Logout / Replay / Account Suspend / Targeted Attempt Cancel of owning attempt)--> **`PENDING_REVOKE`** (`refresh_tokens.status = 'REVOKED'` committed FIRST in same PG txn)
- `PENDING_REVOKE` --(Redis `SET hc:revoked_family:{fid}` succeeds)--> **`REVOKED`**
- `PENDING_REVOKE` --(Redis `RedisError`)--> **remains `PENDING_REVOKE`** (HTTP `503` returned; PG `refresh_tokens` already `'REVOKED'`; next `reconcile_pending_revocations()` sweeps PG `PENDING_REVOKE` rows to Redis & promotes to `REVOKED`).

### 3.2 Login Attempt Lifecycle (`login_attempt_states`)
- `NONE` --(`/login-attempts/cancel` or `/logout` before login commits)--> `CANCELLED` (`family_id=NULL`, TTL `120s` unauth / `300s` verified)
- `NONE` --(Login Commit succeeds)--> `ACTIVE` (`family_id`, `browser_id`, `user_id` bound 1:1)
- `ACTIVE` --(Targeted `/login-attempts/cancel` of exact `attempt_id`, ownership verified)--> `PENDING_REVOKE` -> PG revokes ONLY bound `family_id` -> Redis `hc:revoked_family:{fid}` -> `REVOKED`
- `CANCELLED` --(Slow `/otp/verify` or `/password/login` finishes late)--> Inside Login Commit `FOR UPDATE` txn, sees `status != 'ACTIVE'` -> revokes newly created `session.family_id` in PG & marks `PENDING_REVOKE` -> Redis write -> `REVOKED` -> returns `HTTP 409 clear_cookies=False`.

### 3.3 Browser Bootstrap (`hc_browser` & `POST /api/v1/auth/coord/session`)
- Client `auth_session.js` state: `UNINITIALIZED (bi=0)` -> acquires `navigator.locks` lock `hamicard_phase3_browser_init` (with in-process promise FIFO fallback) -> re-checks `hc_coord.bi` -> calls `/coord/session` ONLY if `bi == 0` -> marks `bi=1` inside `withCoordLock` -> releases init lock.
- Two tabs clicking login concurrently serialize cleanly on `hamicard_phase3_browser_init`; Tab B always sends Tab A's committed `HttpOnly` `hc_browser` cookie.
- Server `_ensure_browser_id(req, response)`: verifies existing `hc_browser`; if absent AND an active `hc_refresh_token` is present whose PG `browser_session_families.browser_id` exists, adopts that existing `browser_id` rather than minting a conflicting second ID. Never overwrites a valid `hc_browser`.

### 3.4 Refresh & Delayed HTTP 200 Cookie Rebind (`POST /api/v1/auth/session/rebind-cookie`)
- If a slow pre-logout login's HTTP `200 Set-Cookie` packet arrives late over the wire **after** a newer explicit login (`F3`) has already succeeded:
  1. Browser's `hc_refresh_token` & `hc_csrf` are transiently overwritten with stale `F1`.
  2. Tab B detects supersession -> discards `F1`, calls **targeted** cleanup (`Bearer F1 /logout` or `/login-attempts/cancel([B1])`) which revokes **only `F1`**, never `F3`, and broadcasts `COOKIE_MAY_BE_STALE` to open tabs.
  3. Any direct `/refresh` with overwritten `F1` cookie **fails `401`** on the server (stale session can never be accepted).
  4. Active tab holding closure-RAM `access_token(F3)` detects `COOKIE_MAY_BE_STALE` (or `hc_csrf` mismatch vs `activeSessionFamilyId` before refresh) and calls `POST /api/v1/auth/session/rebind-cookie` (`Origin` + `Authorization: Bearer <access_token(F3)>` + `hc_browser`).
  5. Server validates `hc_at_v1(F3)` signature/expiry + Redis not revoked + PG `F3` is `ACTIVE` AND `F3.created_seq == browser_coord_state.login_seq` AND `F3.created_seq > browser_coord_state.logout_seq` -> atomically rotates `F3`'s active `refresh_tokens` row under `FOR UPDATE` and issues fresh `HttpOnly` `Set-Cookie: hc_refresh_token` + `hc_csrf(F3)` (**never** exposing refresh tokens in JSON or JS storage). Note: expired/older-generation tokens (`created_seq < login_seq`) are rejected `401/409` so cookie downgrade is impossible.

### 3.5 Client Auth State Machine & Failure Surfacing
- `UNAUTHENTICATED` / `AUTHENTICATED` / `LOGOUT_PENDING` / `EXPIRED` / `REMOTE_REVOKE_FAILED`.
- **`hc_coord` Locking Invariant**: Zero calls to `writeCoordCookie()` outside `withCoordLock(...)` (which runs inside both an in-process FIFO mutex chain AND `navigator.locks.request('hamicard_phase3_coord', ...)`). Wait-free UI scrub (`logoutBarrierActive = true; authEpoch += 1; accessToken = null; cachedProfile = null; authStatusLabel = 'LOGOUT_PENDING'; notifyChange();`) runs synchronously in RAM/DOM, while `hc_coord` write runs exclusively via `bumpCoordLogoutSeqAtomic(..., pending=true)`.
- **`M03` Failure Propagation**: `revokeSupersededLoginOnServer()` inspects BOTH `bearerRevoked` and `postCancelAttemptChunks().allOk`. If cleanup fails (`429`, `503`, or status `0`), unresolved `attempt_id`s are retained in `unresolvedCancelledAttemptIds` (closure Set), `unresolvedCancellationError = true`, `canRetryLogout = true` / explicit error status is surfaced to UI via `notifyChange()`, and failed status is never coerced to success.

---

## 4. Exact Linearization Points (`L1..L7`)

| ID | Operation | Exact Atomic Linearization Point | Guarantee |
|----|-----------|----------------------------------|-----------|
| **L1** | Login Commit vs Logout | PG transaction locking `browser_coord_state FOR UPDATE` (`src/auth/session_service.py`) | Total order on `(global_seq, login_seq, logout_seq)` per `browser_id`; either login commits BEFORE logout (row becomes `'ACTIVE'`, so later logout revokes it), OR logout commits first (`logout_seq > pre_auth_logout_seq`, so login immediately revokes new family & returns `409`). |
| **L2** | Attempt Cancellation Isolation | PG transaction locking `login_attempt_states WHERE attempt_id = ANY($1) FOR UPDATE` | Never touches `browser_coord_state.logout_seq` and never queries `browser_session_families` by `browser_id`. Cancels strictly `attempt_id -> family_id`. |
| **L3** | Pending Revocation Durability | PG `COMMIT` of `refresh_tokens='REVOKED'` + `browser_session_families='PENDING_REVOKE'` BEFORE Redis write | Partial Redis failure never deletes pending revocation work; PG remains authoritative fail-closed. |
| **L4** | Redis Coordination Cache Sync | Atomic Redis Lua script (`EVAL`) computing `max(existing, incoming)` on `g`, `lo`, `li` | Out-of-order async tasks writing to Redis after PG commit can never invert `login_seq` vs `logout_seq`. |
| **L5** | Two-Tab `hc_browser` Bootstrap | Web Lock `hamicard_phase3_browser_init` (`bi=0 -> bi=1`) + in-tab FIFO lock + PG cookie adoption | Serializes initial `/coord/session` across tabs so Tab B inherits Tab A's committed `hc_browser`. |
| **L6** | Delayed-200 Cookie Rebind | PG transaction locking `refresh_tokens WHERE family_id=$1 FOR UPDATE` + verifying `created_seq == login_seq > logout_seq` | Prevents stale-session downgrade; restores `HttpOnly` cookie only for the strictly latest valid browser family. |
| **L7** | Cancel Rate-Limit Quota | Atomic Redis Lua ZSET sliding window (`ZREMRANGEBYSCORE` + weighted count + `ZADD` + `PEXPIRE`) | True continuous sliding window; fails `429` before any PG/Redis cancellation key allocation; elevated quotas require real crypto verification of token/active cookie. |

---

## 5. Authoritative Security Invariants (`INV-01..INV-10`)

- **INV-01 (`C2-H01`)**: Calling `/login-attempts/cancel([B1])` must NEVER advance `logout_seq` and must NEVER revoke any family `F3` whose bound `attempt_id != B1`.
- **INV-02 (`C2-H02`)**: No active family tracking entry is ever removed from PG prior to PG `refresh_tokens.status = 'REVOKED'` AND Redis `hc:revoked_family:{fid}` write confirmation (`ACTIVE -> PENDING_REVOKE -> REVOKED`).
- **INV-03 (`C2-H02`)**: Under concurrent login & logout (simulated Redis/PG yield), no family committed under `browser_id` can escape revocation after `/logout` completes `200`.
- **INV-04 (`C2-H03`)**: Two fresh tabs initializing concurrently with delayed `/coord/session` `Set-Cookie` converge to the same `browser_id`, and subsequent `/logout` leaves 0 active sessions.
- **INV-05 (`C2-H04`)**: Client `hc_coord` mutations are 100% inside `withCoordLock`; server `g, lo, li` transitions serialize via PG `FOR UPDATE` + Redis Lua `max` sync so observed sequence order never inverts.
- **INV-06 (`C2-M01`)**: `Authorization: Bearer invalid` and anonymous `hc_browser` cookies receive unauthenticated IP/global sliding-window quotas (`20 req / 64 ids / 60s`, `120s` TTL) — elevated quotas require verified signature + non-revoked active session. Cross-user attempt cancellation is rejected/blocked.
- **INV-07 (`C2-M02`)**: When a delayed HTTP `200 Set-Cookie` overwrites the browser jar with revoked `F1` after newer `F3` succeeded, `F1` fails server validation (`401`) and active UI rebinds `HttpOnly` cookie to `F3` via `/session/rebind-cookie` so subsequent `/refresh` succeeds.
- **INV-08 (`C2-M03`)**: When `/login-attempts/cancel` returns `429`, `503`, or network failure, client does NOT report success; unresolved revocation state + error message remain surfaced and retryable.
- **INV-09 (`AC-14/AC-15/Multi-device`)**: Revoking browser A's sessions never revokes user sessions belonging to a separate device/browser (`test_t13_ac5`), CSRF `hc_csrf` HMAC binding stays enforced, guest UI load stays 0-API-call (`test_t16`), CSP stays zero-`outerHTML`/zero-WebStorage (`test_t39`), rapid re-login (`test_t41`) & `REMOTE_REVOKE_FAILED` reload (`test_t45`) stay green.
- **INV-10 (`Outage Recovery`)**: A Redis outage during `/logout` or `/login-attempts/cancel` returns fail-closed HTTP `503` while leaving `PENDING_REVOKE` durable in PG; calling `reconcile_pending_revocations(pool, redis)` drains all `PENDING_REVOKE` rows to Redis once Redis recovers.

---

## 6. Failure & Partial-Outage Recovery Design

1. **PG Failure Before/During Revocation Commit (`CE-03a`)**:
   - In `e7c2bb81`, `_bump_browser_logout_and_pop_families()` deleted `hc:browser_recent_families:{bid}` BEFORE PostgreSQL revocation ran, losing undispatched families forever if PG raised an error.
   - In `T52/T53`, family discovery lives in PostgreSQL (`browser_session_families`), NOT in a pop-on-read Redis set. If PG rolls back / fails mid-transaction: `browser_session_families` rows remain `'ACTIVE'` in PG, nothing is lost/popped prematurely, and endpoint returns fail-closed `HTTP 503`. The next `/logout` or retry discovers and revokes all remaining `'ACTIVE'` / `'PENDING_REVOKE'` families.
2. **PG Commit Succeeded, Redis Fails Mid-Revocation (`CE-03b`)**:
   - `refresh_tokens.status` in PG IS ALREADY `'REVOKED'`.
   - `browser_session_families.status` / `login_attempt_states.status` remains `'PENDING_REVOKE'`.
   - Endpoint returns fail-closed `HTTP 503`.
   - `get_current_user` checks Redis (which also fails `503` while Redis is down, and checks PG `verify_active_family` which returns `False`!).
   - Upon Redis recovery: `SessionService.reconcile_pending_revocations()` (invoked opportunistically by auth coordination endpoints when pending count > 0 and directly testable) queries `status = 'PENDING_REVOKE'`, pushes `hc:revoked_family:{fid}` + cancelled keys to Redis, and promotes rows to `'REVOKED'`.
3. **PG Outage on Protected Auth / Refresh**: Fail-closed `HTTP 503` (`asyncpg.PostgresError` / pool error).

---

## 7. `RED_TEST_MATRIX` (Mandatory Pre-Implementation Counterexamples in `tests/test_hc_t53_architecture_counterexamples.py`)

| Test ID | Mapping | Counterexample Scenario | Expected on `e7c2bb81` (RED) | Expected after `HC-T53` (GREEN) |
|---------|---------|-----------------------|-------------------------------|---------------------------------|
| `CE-01` | `C2-H01` | Tab B starts `B1`; Tab A logs out, then logs in `F3`; delayed `B1` bearer `/logout` fails -> `/login-attempts/cancel(['B1'])` fires | **FAILS**: server revokes `F3` & `/refresh` fails `401` | `F3` stays `ACTIVE`; only `B1`/`F1` revoked; `F3` `/refresh` returns `200` |
| `CE-02` | `C2-H02` | Concurrent login + logout with artificial yield/interleaving around family tracking | **FAILS**: non-atomic Redis `SMEMBERS+DEL` race can drop family | 100% serialized via PG `FOR UPDATE`; `0` surviving active families |
| `CE-03` | `C2-H02` | Partial failure injection: (a) PG error during revocation after coordination bookkeeping & (b) Redis `ConnectionError` after PG revocation | **FAILS**: `e7c2bb81` already deleted `hc:browser_recent_families:{bid}` from Redis before PG completed | Returns `503`; pending work remains durable in PG (`ACTIVE`/`PENDING_REVOKE`); retry / `reconcile_pending_revocations()` revokes 100% & promotes `'REVOKED'` |
| `CE-04` | `C2-H03` | Two fresh Playwright tabs on blank context concurrently click Login with delayed `/coord/session` `Set-Cookie` on Tab A | **FAILS**: Tab A & Tab B can mint two distinct `hc_browser` IDs | `BROWSER_INIT_LOCK_NAME` converges both tabs to 1 `hc_browser`; subsequent logout leaves `0` active families |
| `CE-05` | `C2-H04` | Concurrent client/server seq updates + inspect `logoutCookie()` / `clearPrivateState()` Web Lock discipline | **FAILS**: unlocked provisional `hc_coord` write & non-atomic Redis seqs | Every `hc_coord` write locked; Redis Lua `max` prevents seq inversion |
| `CE-06` | `C2-M01` | 22 rapid `/login-attempts/cancel` calls with forged `Authorization: Bearer invalid_prefix_only` | **FAILS**: receives `60 req` verified quota instead of `20 req` unauth `429` | Enforces unauthenticated `20 req` quota -> `429` by call 21; real sliding window resets properly |
| `CE-07` | `C2-M01` | 22 rapid `/login-attempts/cancel` calls with anonymous `hc_browser` cookie (from `/coord/session`) | **FAILS**: anonymous `hc_browser` elevates quota to `60 req` & `300s` TTL | Enforces strict unauthenticated `20 req` quota & `120s` TTL; cross-user cancel rejected |
| `CE-08` | `C2-M02` | Older `B1` HTTP `200 Set-Cookie: F1` delayed until AFTER newer `F3` login completed; then `/refresh` called | **FAILS**: `F1` overwrites jar, `stillLoggedOut=false`, `/refresh` fails `401` | Direct `F1` fails `401`; Tab rebinds cookie to `F3` via `/session/rebind-cookie` -> subsequent `/refresh` succeeds `200` as `F3` |
| `CE-09` | `C2-M03` | `revokeSupersededLoginOnServer()` when `/login-attempts/cancel` returns `429` or `503` | **FAILS**: silently discards `allOk: false`, UI shows clean success | UI surfaces unresolved cancellation warning / error & preserves retryable state |
| `CE-10` | `C2-H01 / AC-15` | Logout of User A / Device A + multi-device User A Device B & User B isolation | Verify isolation invariant | Multi-device Session B & unrelated User B remain `ACTIVE` |

---

## 8. Interleaving Diagrams (T52 Causality Flows)

### 8.1 Delayed `B1` Cancel After Newer `F3` Login (`CE-01` / `C2-H01`)
```text
Tab B (Attempt B1 -> F1)        PG SSOT (L1/L2)                  Tab A (Logout -> Login F3)
-----------------------        ----------------                  --------------------------
POST login (attempt=B1) -----> INSERT login_attempt_states(B1,F1)
                               (logout_seq advances) <---------- POST /logout (revokes F1)
                               INSERT browser_session_families(F3) <-- POST login (F3, new_seq=3)
(late 200 arrives; F1 stale)
POST /login-attempts/cancel([B1]) --> LOCK login_attempt_states(B1)
                                      Revokes ONLY F1 (already REVOKED)
                                      Does NOT touch logout_seq or F3!
                                                                 POST /refresh (F3) -> HTTP 200 OK
```

### 8.2 Delayed HTTP `200 Set-Cookie: F1` Overwrite Recovery (`CE-08` / `C2-M02`)
```text
Tab B (Slow F1 Response)        Browser Jar / Server              Tab A (Active Session F3)
------------------------        --------------------              -------------------------
                                Jar: F3 (login_seq=3)             RAM: accessToken(F3), fid=F3
Late HTTP 200 Set-Cookie: F1 -> Jar OVERWRITTEN: F1!
Tab B sees superseded --------> POST /login-attempts/cancel([B1]) (revokes F1 only)
                           \--> BroadcastChannel: COOKIE_MAY_BE_STALE(staleFamily=F1)
(if attacker/tab sends /refresh w/ F1) -> Server: F1 REVOKED -> 401
                                                                  Tab A calls POST /session/rebind-cookie
                                                                  (Bearer accessToken(F3) + Origin + hc_browser)
                                PG FOR UPDATE checks F3.created_seq == login_seq > logout_seq
                                <-------------------------------- Set-Cookie: HttpOnly F3_rot + CSRF(F3)
                                                                  Tab A POST /refresh -> HTTP 200 OK
```

### 8.3 Two-Tab Concurrent Fresh Bootstrap (`CE-04` / `C2-H03`)
```text
Tab A (bi=0, no hc_browser)     navigator.locks(browser_init)     Tab B (bi=0, no hc_browser)
---------------------------     -----------------------------     --------------------------
click Login ------------------> ACQUIRE hamicard_phase3_browser_init   click Login (awaits lock)
POST /coord/session ----------> Sets HttpOnly hc_browser=bid_1
Set hc_coord.bi=1 ------------> RELEASE lock -------------------> ACQUIRE lock, reads hc_coord.bi==1
POST login (cookie bid_1)                                         skip /coord/session, sends bid_1
POST /logout (cookie bid_1) --> PG queries browser_session_families WHERE browser_id=bid_1 -> 0 ACTIVE
```
