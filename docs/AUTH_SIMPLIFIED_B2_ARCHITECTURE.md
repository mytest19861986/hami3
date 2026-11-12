# HamiCard Simplified Authentication & Concurrency Architecture (`HC-T52-SIMPLIFIED-B2-REV1`)

- **Command**: `HC-COMMANDER-016` / `HC-T52-SIMPLIFIED-B2-REV1` (Final Bounded Documentation & Test Revision Gate prior to `HC-T53`)
- **Branch**: `feat/hc-t52-simplified-b2-design`
- **Base Commit (`develop`)**: `309a5853a3e9ee5503b4866b9370a8398c97264f` (`main`: `6bae506b0e6097f7d698eb312e3e06d4325af78c`)
- **Preserved Prior Commit**: `d533f334a6f1e9fc9935d341e4dd6ba675b396a5` (Initial B2 design & test commit) is preserved untouched; this revision builds strictly as a single new commit on top of it.
- **Superseded Track**: `feat/hc-t52-auth-architecture-design` (`53a3540017356660434ad996dbd4653e157ebd26`, Revision 2.1) is preserved untouched and superseded by this simpler `B2` design.
- **Change Boundary (`HC-T52-SIMPLIFIED-B2-REV1`)**: ZERO edits to `src/`, `db/`, `scripts/`, `Dockerfile`, protected core files (`settings.py`, `env.py`, `adapters/`, `wallets/`), `develop`, `main`, or `hamicard_dev` (`30` baseline tables and `18/18 OPEN_* = PROPOSED` with `approved_by IS NULL` preserved). Only `docs/AUTH_SIMPLIFIED_B2_ARCHITECTURE.md` and `tests/test_hc_t53_b2_acceptance.py` may be edited.

---

## 1. Architectural Simplification Rationale & Eliminated Complexity

The prior `T49/T52` coordination architecture tried to simulate independent multi-attempt state across same-origin browser tabs sharing an `HttpOnly` cookie jar, requiring `3` complex interconnected tables, a 4-level PostgreSQL lock matrix with dynamic rollback retries (`L2`), client sequence cookies (`hc_coord`), and `4` extra coordination endpoints.

`B2` eliminates **~80% of that machinery** while preserving every security invariant—especially guaranteeing that **no delayed `/password/login` or `/otp/verify` can resurrect an authenticated session after `/logout`**:

### Eliminated Components (Forbidden in `B2`)
- **No** 4-level distributed PostgreSQL lock hierarchy (`1 -> 2 -> 3 -> 4`) and **no** dynamic `L2` pre-scan/rollback/retry loop.
- **No** `browser_coord_state` table.
- **No** `login_attempt_states` table, `attempt_id` tracking, or 4-column composite FK choreography.
- **No** `hc_coord` client sequence cookie.
- **No** `POST /api/v1/auth/coord/session`.
- **No** `POST /api/v1/auth/login-attempts/start` or `/login-attempts/cancel`.
- **No** `POST /api/v1/auth/session/rebind-cookie`.

### Retained & Minimal Replacement Core
- **`browser_sessions`** (1 minimal slot + `auth_generation` per browser identity).
- **`revocation_outbox`** (1 decoupled leaf table for fail-closed Redis durability & `SKIP LOCKED` recovery).
- Existing **`refresh_tokens`** table (`BL-HAMICARD-PRD-V1` base schema).
- **`POST /api/v1/auth/browser/bootstrap`** (single idempotent browser identity + current `auth_generation` endpoint).
- Client-side single serialized lock **`navigator.locks('hamicard_auth_op')`** guarding all 5 mutating cookie-mode operations (`bootstrap`, `password/login`, `otp/verify`, `refresh`, `logout`), failing closed (`WEB_LOCKS_UNAVAILABLE`) if Web Locks is unavailable.

---

## 2. Browser Cookie Semantics & Multi-Device Isolation (`4.A`)

1. **Honest Same-Origin Shared Cookie Semantics (RFC 6265)**:
   - Browser cookies (`hc_browser`, `hc_refresh`, `hc_csrf`) are scoped by `(scheme, host, path)`, **NOT per browser tab**. All tabs opened inside one browser profile share a single cookie jar.
   - `B2` **NEVER** promises independent authenticated sessions across two tabs of the same browser profile. Every browser context has **at most ONE active browser cookie identity (`browser_id`)** and **at most ONE active cookie session (`active_family_id`)** at any moment.
   - Signing in on Tab B cleanly supersedes any prior session in the same browser jar (atomically revoking the superseded `family_id` on the server and overwriting `hc_refresh` / `hc_csrf`). Signing out on Tab A cleanly invalidates the entire browser session across every tab of that browser profile.
2. **Cookies Defined by `B2` & Mandatory Security Attributes (`H-02`, `M-01`)**:
   - **`hc_browser`**: `HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000` (30 days). `Secure` attribute is MANDATORY whenever `COOKIE_SECURE=true`. Format: `b_<32-hex>.<hmac_sha256_hex>` signed with server secret (`ACCESS_TOKEN_SECRET`). Carries **only** opaque server identity (`browser_id`); carries zero sequence numbers or client state.
   - **`hc_refresh`**: `HttpOnly; SameSite=Lax; Path=/api/v1/auth; Max-Age=604800` (7 days). `Secure` attribute is MANDATORY whenever `COOKIE_SECURE=true`. Rotated single-use per `/refresh`.
   - **`hc_csrf`**: Non-HttpOnly (`SameSite=Lax; Path=/; Max-Age=2592000`). `Secure` attribute is MANDATORY whenever `COOKIE_SECURE=true`. Non-HttpOnly so client JavaScript can read it from `document.cookie` and attach it to mutating request headers as `X-CSRF-Token`.
   - **Authoritative CSRF Token Binding (`M-01`)**:
     - `hc_csrf` is **strictly HMAC-bound to `browser_id`** (`hmac_sha256(browser_id, ACCESS_TOKEN_SECRET)[:32]`). (Any prior reference to `family_id` binding is superseded: binding to `browser_id` provides CSRF protection even before an authenticated session family exists, e.g. during initial bootstrap and login).
     - Lifecycle:
       1. *Bootstrap (`POST /api/v1/auth/browser/bootstrap`)*: Generates/reads `browser_id`, computes `hc_csrf`, sets both cookies. Bootstrap is exempt from incoming `X-CSRF-Token` header on first uncookied visit.
       2. *Login (`/password/login`, `/otp/verify`)*: Client sends header `X-CSRF-Token: <val>` matching `hc_csrf`. Server asserts `hmac.compare_digest(header_csrf, cookie_csrf)` AND confirms `cookie_csrf` is valid for the `browser_id` in `hc_browser`.
       3. *Refresh (`/refresh`)*: Client sends `X-CSRF-Token` matching `hc_csrf`.
       4. *Logout (`/logout`)*: Client sends `X-CSRF-Token` matching `hc_csrf`. On logout, `hc_refresh` is expired (`Max-Age=0`), while `hc_browser` and `hc_csrf` remain valid for the next session.
   - **Production Security Invariant (`H-02`)**:
     - In staging and production (`APP_ENV` / `ENVIRONMENT` in `restricted_environments`), `COOKIE_SECURE=true` is **strictly mandatory**. Server startup halts (`CorsConfigurationError`) if `COOKIE_SECURE` is false or unset in restricted environments.
     - Acceptance tests must inspect actual raw `Set-Cookie` response headers across `/bootstrap`, `/login`, `/refresh`, and `/logout` to verify `; Secure` presence when `COOKIE_SECURE=true`.
3. **Separate Multi-Device & API Client Isolation**:
   - Separate devices or separate browser profiles receive distinct `hc_browser` cookies (`browser_id_A != browser_id_B`) and independent `refresh_tokens.family_id` rows.
   - Non-cookie JSON/Bearer API callers (`T13..T30` service/mobile flows omitting `X-Auth-Mode: cookie`) operate with `browser_id = NULL` (`family_id` tracked solely in `refresh_tokens` + `revocation_outbox`).
   - Logging out or superseding on `Browser A` **strictly never** revokes `Browser B` (same user on another device) or unrelated `User B`.

---

## 3. Minimal Additive PostgreSQL Schema (`30 -> 32` Public Tables for `HC-T53`)

Existing `30` baseline public tables (including `refresh_tokens` and all financial/policy/RBAC tables) remain structurally compatible and unchanged. `HC-T53` adds **only 2 tables**:

### 3.1 `browser_sessions`
```sql
CREATE TABLE IF NOT EXISTS browser_sessions (
    browser_id        VARCHAR(64) PRIMARY KEY,
    auth_generation   BIGINT NOT NULL DEFAULT 1,
    active_family_id  UUID NULL,
    active_user_id    UUID NULL REFERENCES users(id) ON DELETE CASCADE,
    active_status     VARCHAR(20) NOT NULL DEFAULT 'LOGGED_OUT'
                      CHECK (active_status IN ('LOGGED_OUT', 'ACTIVE')),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days')
);

CREATE INDEX IF NOT EXISTS idx_browser_sessions_gc
    ON browser_sessions(active_status, expires_at)
    WHERE active_status = 'LOGGED_OUT';
```

### 3.2 `revocation_outbox`
```sql
CREATE TABLE IF NOT EXISTS revocation_outbox (
    family_id    UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    browser_id   VARCHAR(64) NULL,
    reason       VARCHAR(40) NOT NULL,
    status       VARCHAR(20) NOT NULL DEFAULT 'PENDING_REVOKE'
                 CHECK (status IN ('PENDING_REVOKE', 'REVOKED')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retain_until TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '10 days')
);

CREATE INDEX IF NOT EXISTS idx_revocation_outbox_pending
    ON revocation_outbox(created_at ASC, family_id ASC)
    WHERE status = 'PENDING_REVOKE';
```

### 3.3 Simple Fixed Lock Order (No Dynamic Escalations or Retries)
Every multi-table PostgreSQL transaction in `B2` acquires locks strictly in one flat sequence:
`1. browser_sessions (single row by PK browser_id, if cookie/browser-bound) -> 2. refresh_tokens (ORDER BY id ASC) -> 3. revocation_outbox (single-row PK upsert / insert)`.

Background workers (`reconcile_pending_revocations`) lock **only `revocation_outbox`** (`FOR UPDATE SKIP LOCKED`) and never lock `browser_sessions` or `refresh_tokens`. Wait-for cycles (`AB-BA`) are structurally impossible.

---

## 4. Login/Logout Concurrency, Operation Serialization & Token Revocation

### 4.1 Server-Side `auth_generation` Fencing (`4.B`)
How `B2` defeats the **delayed Login racing with Logout (`CE-B2-03`)** scenario without `login_attempt_states`:
1. **Bootstrap (`POST /api/v1/auth/browser/bootstrap`)**:
   - Validates existing signed `hc_browser` cookie, or generates a fresh `browser_id`, `INSERT INTO browser_sessions (browser_id) VALUES ($1) ON CONFLICT DO NOTHING`, and sets `Set-Cookie: hc_browser=<signed>` + `Set-Cookie: hc_csrf=<hmac_csrf>` (Non-HttpOnly, HMAC-bound to `browser_id`).
   - Returns `{ "browser_initialized": true, "auth_generation": <int>, "authenticated": <bool>, "active_family_id": <str|null> }` inside a short PK-locked read/insert. (Replaces both `/coord/session` and `/login-attempts/start`).
2. **Mandatory `expected_auth_generation` in Cookie-Mode Login (`/password/login`, `/otp/verify`)**:
   - Whenever `X-Auth-Mode: cookie` (or browser cookie login) is invoked, valid signed `hc_browser` cookie **and** exact integer `expected_auth_generation` in JSON body are strictly required (`409 Conflict` `BROWSER_SESSION_REQUIRED` / `AUTH_GENERATION_MISMATCH` if absent, malformed, or forged e.g. `999`).
   - **Pre-Check Redis Availability**: Execute `redis.ping()` before Phase B commit (`503` if Redis is down, failing closed before creating an un-evictable session).
   - **Phase A (Pre-Verification Guard, Zero Locks Held)**: Reads `browser_sessions.auth_generation` for `browser_id`. If `auth_generation != expected_auth_generation`, rejects immediately with **`409 Conflict` (`LOGIN_FENCED_BY_LOGOUT`)** before running Argon2id or consuming OTP (`0` CPU/OTP burn on stale pre-logout tabs).
   - Slow cryptographic verification (`Argon2id` password verify or Redis atomic OTP verify) executes completely outside any PostgreSQL transaction lock.
   - **Phase B (Atomic Commit, Flat Lock Order)**:
     ```python
     # Pseudocode for Phase B atomic commit (fail-closed)
     try:
         async with pool.acquire() as conn:
             async with conn.transaction():
                 brow = await conn.fetchrow(
                     "SELECT auth_generation, active_family_id FROM browser_sessions WHERE browser_id = $1 FOR UPDATE;",
                     browser_id,
                 )
                 if not brow or brow["auth_generation"] != expected_auth_generation:
                     raise LoginFencedByLogoutError(
                         current_generation=(brow["auth_generation"] if brow else None)
                     )
                 old_fid = brow["active_family_id"]
                 if old_fid is not None:
                     await conn.fetch(
                         "SELECT id FROM refresh_tokens WHERE family_id = $1 ORDER BY id ASC FOR UPDATE;",
                         old_fid,
                     )
                     await conn.execute(
                         "UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = $1 AND status != 'REVOKED';",
                         old_fid,
                     )
                     await conn.execute(
                         """
                         INSERT INTO revocation_outbox (family_id, user_id, browser_id, reason, status, retain_until)
                         VALUES ($1, $2, $3, 'SUPERSEDED_LOGIN', 'PENDING_REVOKE', NOW() + INTERVAL '10 days')
                         ON CONFLICT (family_id) DO UPDATE
                         SET status = 'PENDING_REVOKE',
                             retain_until = GREATEST(revocation_outbox.retain_until, NOW() + INTERVAL '10 days'),
                             updated_at = NOW();
                         """,
                         old_fid,
                         user_id,
                         browser_id,
                     )
                 # Insert new refresh_tokens row (F_new, status='ACTIVE') and update browser_sessions
                 await conn.execute(
                     """
                     UPDATE browser_sessions
                     SET active_family_id = $2, active_user_id = $3, active_status = 'ACTIVE',
                         updated_at = NOW(), expires_at = NOW() + INTERVAL '30 days'
                     WHERE browser_id = $1;
                     """,
                     browser_id,
                     new_family_id,
                     user_id,
                 )
     except LoginFencedByLogoutError:
         raise  # HTTP 409 Conflict (LOGIN_FENCED_BY_LOGOUT)
     except asyncpg.PostgresError as exc:
         raise ServiceUnavailableError("PostgreSQL transaction failed; login aborted.") from exc  # HTTP 503
     ```
   - After commit, if `old_fid` was superseded, execute `SETEX hc:revoked_family:{old_fid} <ttl> 1` and promote `revocation_outbox.status = 'REVOKED'` cleanly. If Redis fails post-commit, `revocation_outbox` retains `old_fid` as `PENDING_REVOKE` (`get_current_user` returns `503` while Redis is down and checks `revocation_outbox` in PG after Redis recovery until reconciled).
3. **Two Independent Logout Paths: Cookie Mode vs. Bearer Mode (`POST /api/v1/auth/logout`, `H-01`)**:
   - **Path A: Cookie-Mode Logout (`X-Auth-Mode: cookie` or cookie session present)**:
     - Validates strict `Origin`/`Referer` allowlist + double-submit CSRF (`hc_csrf` cookie vs `X-CSRF-Token` header, HMAC-bound to `browser_id`).
     - Inside PostgreSQL transaction (`try ... except asyncpg.PostgresError -> 503`, strictly `browser_sessions FOR UPDATE -> refresh_tokens ORDER BY id ASC FOR UPDATE -> revocation_outbox`):
       1. Locks and reads `browser_sessions` by PK `browser_id`.
       2. Always increments `browser_sessions.auth_generation = auth_generation + 1` (atomically fencing ALL in-flight or delayed Phase A/Phase B logins bound to `<= g`!).
       3. Clears `active_family_id = NULL`, `active_user_id = NULL`, sets `active_status = 'LOGGED_OUT'`.
       4. Locks and marks `refresh_tokens.status = 'REVOKED'` across BOTH `browser_sessions.active_family_id` AND the incoming `hc_refresh` family if valid and owned by this user/browser (`403` if cross-user/cross-browser forged token).
       5. Inserts/upserts `revocation_outbox(family_id, user_id, browser_id, reason='COOKIE_LOGOUT', status='PENDING_REVOKE', retain_until = GREATEST(revocation_outbox.retain_until, NOW() + INTERVAL '10 days'))`.
     - Post-commit: sets `hc:revoked_family:{fid}` in Redis (TTL > 7 days) and promotes outbox to `REVOKED`. If Redis fails post-commit, returns `503` (client clears local token, outbox reconciler heals later).
     - Returns updated `auth_generation` in response and expires `hc_refresh` (`Max-Age=0; Path=/api/v1/auth; SameSite=Lax; HttpOnly; Secure` when `COOKIE_SECURE=true`), keeping signed `hc_browser` + fresh `browser_id`-bound `hc_csrf` intact so the next login knows the fenced `auth_generation`.
   - **Path B: Bearer-Mode Logout (Bearer API token in `Authorization: Bearer <token>`, no `X-Auth-Mode: cookie`)**:
     - **Must NOT require or touch `browser_sessions`**: `browser_id` is `NULL`.
     - Authenticates the caller via `get_current_user` (verifies access JWT signature, expiration, Redis blacklist, and PostgreSQL `users.status == 'ACTIVE'`).
     - Obtains authoritative `caller_user_id` and `caller_family_id` strictly from the verified access token claims (`sub`, `fid`).
     - Inside PostgreSQL transaction (`try ... except asyncpg.PostgresError -> 503`, strictly `refresh_tokens ORDER BY id ASC FOR UPDATE -> revocation_outbox`):
       1. Locks and validates that `refresh_tokens.family_id = caller_family_id` belongs strictly to `caller_user_id` (`403 Forbidden` on any ownership mismatch).
       2. If caller passes optional `payload.refresh_token`, verifies that token digest matches and belongs strictly to `caller_user_id` before revoking its family too. Rejects arbitrary unauthenticated client-supplied family IDs (`403 Forbidden` if `tok_row.user_id != caller_user_id`).
       3. Atomically updates `refresh_tokens SET status = 'REVOKED' WHERE family_id = caller_family_id AND status != 'REVOKED';`
       4. Inserts/upserts `revocation_outbox(family_id, user_id, browser_id=NULL, reason='BEARER_LOGOUT', status='PENDING_REVOKE', retain_until = GREATEST(revocation_outbox.retain_until, NOW() + INTERVAL '10 days'))`.
     - Post-commit: sets `hc:revoked_family:{caller_family_id}` in Redis (TTL > 7 days) and promotes outbox to `REVOKED` (`503` if Redis fails).
     - Returns `{ "success": True, "revoked_tokens": n, "auth_generation": null, "mode": "bearer" }`. Zero cookie headers emitted. Bearer logout strictly never touches unrelated browser slots or cross-user families.

### 4.2 Client Authentication Operation Serialization (`4.C` & `4.F`)
Why a **refresh-only lock is insufficient**: Locking only `/refresh` permits two fresh tabs (`CE-B2-01`) to simultaneously enter `/browser/bootstrap` without `hc_browser` and overwrite each other's identities, permits `/login` and `/logout` to interleave `Set-Cookie` headers in arbitrary HTTP completion order, and allows stale tokens to overwrite newer session state in UI memory.

Therefore, `src/ui_shell/js/auth_session.js` funnels **ALL 5 mutating cookie-mode authentication operations** through **one single Web Lock** helper `withSerializedAuthOp(opName, fn)`:
```javascript
async function withSerializedAuthOp(opName, fn) {
  if (typeof navigator === 'undefined' || !navigator.locks || typeof navigator.locks.request !== 'function') {
    throw Object.assign(new Error('مرورگر از قفل هم‌زمانی نشست (Web Locks) پشتیبانی نمی‌کند.'), {
      code: 'WEB_LOCKS_UNAVAILABLE',
    });
  }
  return navigator.locks.request('hamicard_auth_op', async () => fn());
}
```
Serialized operations under `navigator.locks('hamicard_auth_op')`:
1. **Initial browser bootstrap** (`POST /api/v1/auth/browser/bootstrap`) — cached only after cookie issuance is verified; when two fresh tabs boot simultaneously (`CE-B2-01`), Tab A holds `hamicard_auth_op` across the initial unbootstrapped HTTP call, writes `hc_browser` via `Set-Cookie`, and Tab B (if it calls bootstrap afterward) automatically carries `hc_browser`, yielding strictly `1` unbootstrapped request at the server boundary.
2. **Password login** (`POST /api/v1/auth/password/login`) — fetches fresh `expected_auth_generation` from bootstrap inside the lock right before submitting, submits login, and updates in-memory `accessToken`.
3. **OTP verification** (`POST /api/v1/auth/otp/verify`) — identically fetches fresh `expected_auth_generation` inside `hamicard_auth_op` right before verification.
4. **Refresh** (`POST /api/v1/auth/refresh`) — attaches `X-CSRF-Token`, rotates single-use `hc_refresh` inside the lock so sibling tabs never race rotation into false replay detection.
5. **Logout** (`POST /api/v1/auth/logout`) — attaches `X-CSRF-Token`, revokes server session + increments `auth_generation`, clears in-memory `accessToken` + UI state immediately, and publishes advisory `BroadcastChannel('hamicard_auth_sync')` notification so sibling tabs clear in-memory `accessToken` cleanly.

**Explicit Non-Security Role of `BroadcastChannel`**: `BroadcastChannel` is strictly an **advisory UI freshness signal** to help background tabs update their displayed badge quickly; it is NEVER a security control, and all invariants hold even if `BroadcastChannel` messages are dropped or blocked.
**Fail-Closed Missing `navigator.locks`**: Missing `navigator.locks` throws `WEB_LOCKS_UNAVAILABLE`, displays an explicit error banner, and sends **zero** mutating auth network requests.

### 4.3 Immediate Access Token Revocation (`4.D`)
- **Bounded Expiry (`exp`, e.g. `300s`–`900s`) Alone Is Insufficient**: Short JWT lifetimes cap exposure window only asynchronously; after `/logout`, a stolen or sibling-tab Bearer token would still succeed until `exp` elapsed.
- **Immediate Server-Side Revocation Enforced by `B2`**:
  1. Every access JWT (HS256 via `ACCESS_TOKEN_SECRET`, min 32 chars, fail-closed if unset) embeds `sub` (`user_id`), `fid` (`family_id`), `jti`, and `exp`.
  2. Every protected endpoint (`get_current_user` in `src/api/deps.py`) executes **all** of:
     - Cryptographic JWT signature + `exp > now` check (`allow_expired=False`, `401` on invalid/expired).
     - Redis immediate revocation check: `EXISTS hc:revoked_family:{fid}` -> **`401 Unauthorized` immediately after `/logout` or replay** (regardless of remaining JWT `exp` lifetime!). If Redis throws `RedisError`, **fail closed with `HTTP 503`** (`SESSION_VERIFICATION_UNAVAILABLE`).
     - Authoritative PostgreSQL single-connection check (`users.status == 'ACTIVE'`, live RBAC `user_roles`, AND defense-in-depth `NOT EXISTS (SELECT 1 FROM revocation_outbox WHERE family_id = $2)` so even if Redis restarted empty before background `reconcile_pending_revocations` ran, a revoked family is still deterministically rejected `401` with zero extra connection acquisition; `users.status != 'ACTIVE'` returns `403` and revokes the family).

### 4.4 Durable Revocation, Outbox Reconciliation & Fail-Closed Guarantees (`4.E`)
1. **PostgreSQL Outage During `/logout`**: Transaction rolls back (`auth_generation` unchanged, `refresh_tokens` unchanged, `revocation_outbox` unchanged), endpoint returns **`HTTP 503`**, never returns `200` on failed revocation, and retrying `/logout` once PG recovers succeeds `200`.
2. **Redis Outage After PostgreSQL Revocation Commit**:
   - PostgreSQL transaction commits `refresh_tokens.status = 'REVOKED'`, `browser_sessions.auth_generation += 1` (`active_family_id = NULL, active_status = 'LOGGED_OUT'`), and `revocation_outbox.status = 'PENDING_REVOKE'`.
   - Post-commit `SETEX hc:revoked_family:{fid} <ttl> 1` (`ttl = refresh_ttl_seconds + access_ttl_seconds + 86400`, e.g. `8 days`) raises `RedisError` -> row remains **`PENDING_REVOKE`** in `revocation_outbox` and `/logout` returns **`HTTP 503`** (client clears local token & preserves retry affordance; protected endpoints ALSO fail closed **`HTTP 503`** while Redis is unavailable).
3. **Concurrent Worker Reconciliation (`reconcile_pending_revocations(batch_size=50, max_batches=20)`)**:
   - Single-table leaf transaction on `revocation_outbox`:
     ```python
     # Leaf worker: locks ONLY revocation_outbox (no browser_sessions or refresh_tokens locks)
     reconciled = 0
     for _ in range(max_batches):
         try:
             async with pool.acquire() as conn:
                 async with conn.transaction():
                     rows = await conn.fetch(
                         """
                         SELECT family_id FROM revocation_outbox
                         WHERE status = 'PENDING_REVOKE'
                         ORDER BY created_at ASC, family_id ASC
                         FOR UPDATE SKIP LOCKED LIMIT $1;
                         """,
                         batch_size,
                     )
                     if not rows:
                         break
                     for row in rows:
                         await asyncio.to_thread(
                             redis_client.setex,
                             f"hc:revoked_family:{row['family_id']}",
                             revocation_ttl_seconds,
                             "1",
                         )
                     await conn.execute(
                         """
                         UPDATE revocation_outbox
                         SET status = 'REVOKED', updated_at = NOW()
                         WHERE family_id = ANY($1::uuid[]);
                         """,
                         [r["family_id"] for r in rows],
                     )
                     reconciled += len(rows)
         except (RedisError, asyncpg.PostgresError):
             break  # Rolled back atomically; PENDING_REVOKE preserved cleanly
     ```
   - Two concurrent workers cleanly process disjoint `SKIP LOCKED` batches. Executed at FastAPI `lifespan` startup, on background schedule, and opportunistically.

#### 4.4.1 Outbox Operations, Scheduling, Metrics & Alerting (`M-07`)
- **Operational Cadence**:
  - `lifespan` startup task runs initial catchup reconciliation before serving user traffic.
  - Periodic background task runs every `30 seconds` (`OUTBOX_RECONCILE_INTERVAL_SECONDS = 30`).
  - Opportunistic trigger runs after any successful `/logout` or superseded login whenever previous Redis writes experienced transient failure.
- **Bounded Retry Policy & Exponential Backoff**:
  - When Redis is unreachable, worker captures `RedisError`, backs off with `delay = min(60, 2 ** attempt)` seconds (up to 10 attempts).
  - Transactions on `revocation_outbox` rollback cleanly on Redis failure; rows remain in durable `PENDING_REVOKE` state without data loss.
- **Metrics & Observability**:
  - Gauge `hamicard_auth_outbox_pending_count`: total count of rows where `status = 'PENDING_REVOKE'`.
  - Counter `hamicard_auth_outbox_reconciled_total`: count of successfully reconciled and promoted revocations.
  - Gauge `hamicard_auth_outbox_oldest_pending_age_seconds`: elapsed seconds since `created_at` of oldest pending revocation.
- **Production Alerts**:
  - **`AuthOutboxDelayedReconciliation` (WARNING)**: Fires if `oldest_pending_age_seconds > 60` for 2 consecutive scrape cycles (indicates reconciliation worker lag or Redis blip).
  - **`AuthOutboxCriticalAccumulation` (CRITICAL / P1)**: Fires if `pending_count > 100` OR `oldest_pending_age_seconds > 300` (indicates sustained Redis partition). Defense-in-depth DB check protects tokens, but operator intervention is required.
- **Safe Operator Recovery Procedure**:
  - If Redis cluster underwent complete cold restart with cache loss, run `python -m src.auth.reconcile_outbox --all-pending` or trigger authenticated admin endpoint `POST /api/v1/admin/auth/reconcile-outbox` (`SUPER_ADMIN` RBAC permission required).
  - Script locks batches of 100 `FOR UPDATE SKIP LOCKED`, verifies existing Redis entries, re-populates missing keys with full TTL (`> 7 days`), and promotes `status = 'REVOKED'` without downtime.

### 4.5 Refresh Rotation, CSRF/Origin Protection & Sliding-Window Rate Limiting
- **Single-Use Refresh Rotation (`rotate_refresh_token`)**: Locked in flat order `browser_sessions FOR UPDATE` (if browser-bound, asserting `active_status == 'ACTIVE'` and `active_family_id == token_row.family_id`) followed by `refresh_tokens ORDER BY id ASC FOR UPDATE`. At most 1 successor issued; competing call inside 5s grace window raises `409` without credential leak; reuse outside grace revokes entire `family_id` via `revocation_outbox` + Redis (`fail-closed 503` if Redis unavailable) and logs `TOKEN_REPLAY_ATTACK_DETECTED` (`401`).
- **CSRF & Origin Validation**:
  - `POST /api/v1/auth/browser/bootstrap`: enforces strict allowlisted `Origin`/`Referer` (`403` otherwise; exempt from `X-CSRF-Token` solely on first-load bootstrap so an uncookied tab can obtain initial signed `hc_browser` + HMAC-bound `hc_csrf`).
  - `POST /api/v1/auth/password/login`, `/otp/verify`, `/refresh`, `/logout` (when invoked in cookie mode): enforce **BOTH** strict allowlisted `Origin`/`Referer` AND valid HMAC-bound `X-CSRF-Token == hc_csrf` (`403` on missing/mismatched header or cookie). Missing `Origin` + missing `Referer` fails closed (`403`).
- **Lua ZSET Sliding-Window Rate Limiting**: Single atomic Lua `EVAL` using authoritative Redis server `redis.call('TIME')` (`redis.replicate_commands()`) + per-call 96-bit `secrets.token_hex(12)` nonce (`ARGV`), checking all ceilings BEFORE `ZADD` so `429` never pollutes ZSET buckets, and failing closed `HTTP 503` with **0 PostgreSQL writes** on `RedisError`. Standalone Redis topology assumed (Redis Cluster would require `{hash_tag}` common slots for multi-key Lua).

### 4.6 Adversarial Garbage Collection Policy (`purge_expired_auth_records`)
- Executed in strictly bounded batches cleanly preserving every live/pending entity:
  - **Protected (NEVER deleted by GC)**:
    1. Any `browser_sessions` row where `active_status = 'ACTIVE'` or `expires_at > NOW()`.
    2. Any `revocation_outbox` row where `status = 'PENDING_REVOKE'` OR (`status = 'REVOKED'` AND `retain_until > NOW()` — full 10-day retention).
    3. Any `refresh_tokens` row where `status = 'ACTIVE'` OR `family_id IN (SELECT family_id FROM revocation_outbox WHERE status = 'PENDING_REVOKE')` OR `created_at > NOW() - INTERVAL '10 days'`.
  - **Safely Purged**:
    1. Expired `LOGGED_OUT` `browser_sessions` (`active_status = 'LOGGED_OUT' AND active_family_id IS NULL AND expires_at <= NOW()`).
    2. Old confirmed `REVOKED` `revocation_outbox` rows (`status = 'REVOKED' AND retain_until <= NOW()`).
    3. Old `REVOKED`/`EXPIRED` `refresh_tokens` (`status IN ('REVOKED', 'EXPIRED') AND created_at <= NOW() - INTERVAL '10 days'` and no `PENDING_REVOKE` outbox entry).

---

## 5. Authoritative Acceptance Test Matrix (`tests/test_hc_t53_b2_acceptance.py`)

### Baseline RED Verification Nature (`LOW-01`)
On `develop @ 309a5853a3e9ee5503b4866b9370a8398c97264f`, all 11 acceptance scenarios cleanly fail RED (`11 failed, 0 passed, 0 skipped`). As accurately noted under `LOW-01`, this baseline failure occurs at the initial schema assertion (`public.browser_sessions` / `public.revocation_outbox` do not exist on `develop`), proving that `develop` lacks the B2 architecture tables. Once `HC-T53` provisions the schema and endpoints, the suite independently evaluates each adversarial behavioral scenario to prove zero race conditions.

| Scenario ID | Requirement | Adversarial Verification Summary | Expected on `develop @ 309a5853` (RED) | Expected after `HC-T53` (GREEN) |
|---|---|---|---|---|
| `CE-B2-01` | `4.F, M-02` | Two simultaneous uncookied tabs boot `/phase3/#/auth/shell` concurrently across ASGI boundary barrier with deterministic client-side lock contention barrier (`window.__tab_b_lock_waiting`) | **FAILS**: `browser_sessions` absent | Both tabs converge to `1` `hc_browser`; Tab B actually waits for Tab A; server sees `1` unbootstrapped request; `0` surviving tokens after logout |
| `CE-B2-02` | `4.A, 4.C` | Concurrent `/password/login` across two tabs sharing `hc_browser` (`'hamicard_auth_op'` Web Lock + raw concurrent HTTP replacement test) | **FAILS**: `browser_sessions` absent | Strictly `<= 1` `ACTIVE` family for `browser_id`, superseded family atomically `REVOKED` + in Redis, `0` orphaned families |
| `CE-B2-03` | `4.B, M-06` | Login response racing with `/logout` (pre-logout slow verification barrier + forged generation `999` + late HTTP response arrival with old `Set-Cookie` unable to restore session) | **FAILS**: `browser_sessions` absent | `auth_generation` increments on `/logout`; delayed login fails `409`; late response arriving after logout rejected on refresh; `0` active tokens remain |
| `CE-B2-04` | `4.B` | Valid `/logout` incrementing `auth_generation` followed cleanly by a fresh login using updated generation | **FAILS**: `browser_sessions` absent | New login commits `200`, `1` `ACTIVE` family, fresh Bearer token & `/refresh` work cleanly |
| `CE-B2-05` | `4.C, §4.5` | Concurrent multi-request `/refresh` rotation (`1` winner `200` + rotated cookie, competing callers `409` w/o token disclosure) + client `'hamicard_auth_op'` serialized tab refresh | **FAILS**: `browser_sessions` absent | At most `1` usable successor issued; `0` credential leaks; valid rotated cookie continues smoothly |
| `CE-B2-06` | `4.B, 4.C, M-03` | Browser without `navigator.locks` opens shell and attempts login (network spy monitors all 5 endpoints including `/bootstrap`) | **FAILS**: `browser_sessions` absent | Fails closed locally (`WEB_LOCKS_UNAVAILABLE`), `authenticated=False`, `0` mutating auth HTTP requests sent across all 5 endpoints |
| `CE-B2-07` | `4.D` | Stale access token used immediately after `/logout` (with long `access_ttl=300` proving immediate revocation rather than JWT expiry) + Redis outage `503` fail-closed | **FAILS**: `browser_sessions` absent | `/profile/me` immediately returns `401` post-logout (`exp` still `+290s` ahead); returns `503` fail-closed on Redis outage |
| `CE-B2-08` | `§2.3` | Multi-device session isolation: Browser A logs out / overwrites session while separate device Browser B (`bid_B`) for same user AND unrelated User B remain `ACTIVE` | **FAILS**: `browser_sessions` absent | Browser B & User B stay `200` / `ACTIVE` throughout Browser A logout and re-login |
| `CE-B2-09` | `4.E, M-04` | Mid-transaction PG fault injected across `execute`/`fetch`/`fetchrow`/`executemany` with socket disconnect (`503`, rollback, `auth_generation` preserved, retry succeeds) + Redis outage after PG commit (`503`, `PENDING_REVOKE` durable, dual forced-overlapping `SKIP LOCKED` reconcilers promote to `REVOKED` + Redis `TTL > 7d`) | **FAILS**: `browser_sessions` absent | PG rollback intact (`auth_generation` unchanged); dual overlapping workers process disjoint `SKIP LOCKED` batches -> `REVOKED` + Redis `TTL > 7d` |
| `CE-B2-10` | `§4.5, M-05` | Missing/evil `Origin`, missing/mismatched `X-CSRF-Token`, refresh replay outside grace (`REVOKED` whole family + audit log), Lua ZSET sliding window with exact pre-429 and post-429 cardinality and member equality (`503` with `0` PG DML across all connection methods) | **FAILS**: `browser_sessions` absent | Malicious Origin/CSRF rejected `403`; replay revokes family `401`; ZSET cardinality and membership unchanged on 429; `0` PG writes on 503 |
| `CE-B2-11` | `§4.6, L-02` | Adversarial garbage collection (`purge_expired_auth_records`) preserving `ACTIVE`/unexpired `browser_sessions`, `PENDING_REVOKE`/`<10d` `revocation_outbox` (with `GREATEST` retention renewal), AND child `ACTIVE`/`PENDING_REVOKE` `refresh_tokens`, while safely purging expired `LOGGED_OUT` slots and `>10d` confirmed revoked rows | **FAILS**: `browser_sessions` absent | Live/pending families + child `refresh_tokens` 100% preserved; expired slots & `>10d` confirmed revoked rows cleanly purged |
| `CE-B2-12` | `H-01, H-02` | Dual-mode logout & cookie security: positive Bearer logout revoking caller family without `browser_sessions` + negative test rejecting cross-user family manipulation + raw Set-Cookie header inspection asserting `; Secure` on all 3 cookies when `COOKIE_SECURE=true` | **FAILS**: `browser_sessions` absent | Bearer caller revokes own family cleanly; cross-user manipulation fails `403`; `hc_browser`, `hc_refresh`, `hc_csrf` all contain `; Secure` in production |
