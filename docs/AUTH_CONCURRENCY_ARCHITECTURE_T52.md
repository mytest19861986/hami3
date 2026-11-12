# HamiCard Phase 3 Authentication Concurrency Architecture & Failure-Recovery Specification (`HC-T52` Revision 1)

- **Command**: `HC-CMD-053` / `HC-T52` (Design-and-Test-First Gate prior to `HC-T53` implementation)
- **Base Commit (`OLD_CANDIDATE`)**: `e7c2bb81f7278e1d9a0fe8ca75e56d06fec753fb`
- **Review Alignment**: Addresses all Independent Reviewer #2 findings `R2-T52-V4-F01` through `R2-T52-V4-F08` (`CRITICAL` / `HIGH` / `MEDIUM`), `/session/rebind-cookie` security conditions, counterexample test matrix repairs, cookie name alignment (`hc_refresh`), and live DB/repo verification evidence.
- **Target Scope**: Remediate all `4` HIGH (`R2-T50-C2-H01..H04`), `3` MEDIUM (`R2-T50-C2-M01..M03`), and `1` LOW (`R2-T50-C2-L01`) defects by centering concurrency control on PostgreSQL ACID linearization + durable `PENDING_REVOKE` bookkeeping + server-owned epoch fencing + capability-scoped attempt cancellation.
- **Invariant Constraint**: Zero application behavior edits (`src/`, `db/`, `scripts/`, `Dockerfile`) in `HC-T52`. Implementation runs in `HC-T53` only after explicit independent Design Gate `PASS`.

---

## 1. Architectural Simplification, Coordination Tradeoff & Source References

In `e7c2bb81`, two design choices caused cascading races:
1. Overloading `POST /api/v1/auth/login-attempts/cancel` with browser-wide logout bumps (`_bump_browser_logout_and_pop_families` at `src/api/auth.py:1505-1515`) triggered automatically on delayed cleanup (`src/ui_shell/js/auth_session.js:560-564`).
2. Keeping mutable sequence state and family discovery in non-atomic Redis commands (`INCR` + `SET` + `SMEMBERS` + `DEL` at `src/api/auth.py:265-324`) deleted **before** PostgreSQL revocation completed (`src/api/auth.py:1330-1339`), plus client-trusted `started_server_logout_seq` fencing (`src/api/auth.py:630-639, 826-835`), unlocked provisional `writeCoordCookie()` calls (`src/ui_shell/js/auth_session.js:1241-1246`), unvalidated `hc_browser` / `Bearer ` quota escalation (`src/api/auth.py:1445-1454`), fixed-window `INCRBY` quota checks (`src/api/auth.py:327-345`), and duplicate bootstrap minting (`src/api/auth.py:221-228`).

**Coordination Simplification Evaluation (`HC-CMD-053`)**:
We evaluated removing browser-wide coordination (`hc_browser`, `hc_coord`) completely. Keeping only `attempt_id` handles pre-commit cancellations, **except** when a user initiates `/logout` in Tab A *after* Tab B started an in-flight `/otp/verify` or `/password/login` (whose `attempt_id` is unknown to Tab A) or when a delayed HTTP `200 Set-Cookie` overwrites a newer family's jar cookie and needs latest-family verification for `/session/rebind-cookie`. Therefore, `T52` **minimizes** browser-wide state strictly to what per-attempt binding cannot express:
- **`/login-attempts/cancel` is strictly attempt-scoped**: NEVER modifies `browser_coord_state.logout_seq` and NEVER pops or queries unrelated browser families. It cancels ONLY supplied `attempt_id`s and revokes ONLY 1:1 bound families (`login_attempt_states.family_id`) after verifying attempt ownership (authenticated matching `user_id` OR unguessable SHA-256 `cancel_capability`; never anonymous `hc_browser` alone).
- **PostgreSQL (`SELECT ... FOR UPDATE`) is the Single Source of Truth (SSOT)** for:
  - Server-captured immutable login-attempt start generations (`login_attempt_states.started_logout_seq`), ownership (`user_id`, `browser_id`, `cancel_token_hash`), 1:1 `family_id`, and atomic pre-commit cancellation tombstones.
  - Browser sequence linearization (`browser_coord_state`).
  - Active/pending/revoked session families (`browser_session_families`) under **`LATEST_FAMILY_WINS` (`SINGLE_CURRENT_FAMILY_PER_BROWSER`)** policy.
- **Redis** holds only derived/ephemeral fast-path structures:
  1. Fail-closed fast revocation cache (`hc:revoked_family:{fid}`, `hc:cancelled_login_attempt:{aid}`) populated **from** PostgreSQL (`PENDING_REVOKE` stays durable in PG until Redis confirms write with TTL strictly greater than max token TTL).
  2. Atomic Lua `MAX`-monotonic coordination cache (`hc:browser_coord:{bid}`) synced from PG (preventing sequence inversion under out-of-order async tasks).
  3. Atomic multi-key Lua ZSET sliding-window rate-limit buckets (`hc:rl:*`).
- **Client `hc_coord` is strictly a non-authoritative UI sync hint** (never trusted as security proof, `bi` never trusted without server/Web-Lock guarantees): every write runs exclusively inside `withCoordLock(...)` under strict hierarchical Web-Lock ordering (`hamicard_phase3_browser_init` -> `hamicard_phase3_refresh` -> `hamicard_phase3_coord`). Browsers without `navigator.locks` fail closed for multi-tab cookie coordination.

**Exact Defect -> Source Reference Matrix (`e7c2bb81` -> `HC-T53` Targets)**:

| ID | Vulnerable `e7c2bb81` Source | `HC-T53` Target Locations |
|----|------------------------------|---------------------------|
| `C2-H01` | `src/api/auth.py:1505-1515`, `src/ui_shell/js/auth_session.js:560-564` | `src/auth/session_service.py`, `src/api/auth.py` (`/login-attempts/start`, `/login-attempts/cancel`), `src/ui_shell/js/auth_session.js` |
| `C2-H02` | `src/api/auth.py:248-324, 1330-1347`, `src/auth/session_service.py:331-348` | `db/schema.sql`, `src/auth/session_service.py` (`PENDING_REVOKE`, `reconcile_pending_revocations`, `FOR UPDATE SKIP LOCKED`), `src/api/auth.py`, `src/api/deps.py` |
| `C2-H03` | `src/api/auth.py:221-228`, `src/ui_shell/js/auth_session.js:249-276` | `src/ui_shell/js/auth_session.js` (`hamicard_phase3_browser_init`, Web-Locks fail-closed guard), `src/api/auth.py` (`_ensure_browser_id` + `/coord/session`) |
| `C2-H04` | `src/api/auth.py:265-324, 630-639, 826-835`, `src/ui_shell/js/auth_session.js:425-430, 1241-1246` | `src/auth/session_service.py` (universal PG lock order + server-owned `started_logout_seq` + Lua `MAX`), `src/ui_shell/js/auth_session.js` (`withCoordLock` discipline) |
| `C2-M01` | `src/api/auth.py:1445-1454, 348-375` | `src/api/auth.py` (real crypto `verify_access_token` + PG `verify_active_family`, ownership + `cancel_capability`) |
| `C2-M02` | `src/api/auth.py` (cookie jar overwrite by late 200), `src/ui_shell/js/auth_session.js:609-688` | `src/api/auth.py` (`POST /api/v1/auth/session/rebind-cookie`), `src/ui_shell/js/auth_session.js` (`COOKIE_MAY_BE_STALE` + `401` safe-rebind fallback) |
| `C2-M03` | `src/ui_shell/js/auth_session.js:534-565` | `src/ui_shell/js/auth_session.js` (`unresolvedCancelledAttemptIds` + `canRetryLogout` + error UI state), `src/ui_shell/js/app.js` |
| `C2-L01` | `src/api/auth.py:327-345` | `src/api/auth.py` (multi-key atomic Lua ZSET sliding window) |

---

## 2. Additive PostgreSQL SSOT Schema (for `HC-T53`)

Currently live PG schema contains `30` tables (`agents`, `audit_logs`, `cities`, `commissions`, `content_pages`, `discount_plans`, `doctor_reviews`, `doctors`, `documents`, `login_attempts`, `memberships`, `notifications`, `orders_payments`, `permissions`, `plan_holders`, `profiles`, `provinces`, `referrals`, `refresh_tokens`, `role_permissions`, `roles`, `sales_cases`, `service_contracts`, `settlements`, `system_settings`, `user_roles`, `users`, `visits`, `wallet_ledger_entries`, `wallets`). `T53` adds strictly `3` new tables (total `33`) without altering any financial/core table or any of the `18` `OPEN-*` settings (`PROPOSED`):

```sql
CREATE TABLE IF NOT EXISTS browser_coord_state (
    browser_id VARCHAR(64) PRIMARY KEY,
    global_seq BIGINT NOT NULL DEFAULT 0,
    logout_seq BIGINT NOT NULL DEFAULT 0,
    login_seq  BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS browser_session_families (
    family_id     UUID PRIMARY KEY,
    browser_id    VARCHAR(64) NOT NULL REFERENCES browser_coord_state(browser_id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempt_id    VARCHAR(96) NULL,
    created_seq   BIGINT NOT NULL,
    status        VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'PENDING_REVOKE', 'REVOKED')),
    revoke_reason VARCHAR(40) NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_browser_session_families_attempt_id
    ON browser_session_families (attempt_id)
    WHERE attempt_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_bsf_browser_active
    ON browser_session_families (browser_id, status)
    WHERE status IN ('ACTIVE', 'PENDING_REVOKE');

CREATE INDEX IF NOT EXISTS idx_bsf_pending_revoke
    ON browser_session_families (updated_at, family_id)
    WHERE status = 'PENDING_REVOKE';

CREATE TABLE IF NOT EXISTS login_attempt_states (
    attempt_id         VARCHAR(96) PRIMARY KEY,
    family_id          UUID NULL REFERENCES browser_session_families(family_id) ON DELETE SET NULL,
    browser_id         VARCHAR(64) NULL REFERENCES browser_coord_state(browser_id) ON DELETE CASCADE,
    user_id            UUID NULL REFERENCES users(id) ON DELETE CASCADE,
    cancel_token_hash  VARCHAR(64) NULL,
    started_logout_seq BIGINT NOT NULL DEFAULT 0,
    status             VARCHAR(20) NOT NULL CHECK (status IN ('STARTED', 'IN_FLIGHT', 'ACTIVE', 'CANCELLED', 'PENDING_REVOKE', 'REVOKED')),
    attempt_expires_at TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_las_pending_revoke
    ON login_attempt_states (updated_at, attempt_id)
    WHERE status = 'PENDING_REVOKE';
```

### Schema Invariants (`R2-T52-V4-F01..F03`)
1. **1:1 Binding**: `uq_browser_session_families_attempt_id` guarantees at most ONE `family_id` can ever reference any `attempt_id`. `login_attempt_states.family_id` enforces FK integrity to `browser_session_families(family_id)`.
2. **Immutable Ownership & Start Epoch**: Once non-null, `started_logout_seq`, `browser_id`, `user_id`, `cancel_token_hash`, and `family_id` are NEVER overwritten.
3. **Tombstone vs Attempt Lifetime**: Max in-flight authentication window is `MAX_AUTH_ATTEMPT_LIFETIME_SECONDS = 30s` (`attempt_expires_at`). Cancellation tombstone retention (`expires_at`) is `120s` (unauthenticated) / `300s` (authenticated or capability-verified) — strictly `4x..10x` longer than `attempt_expires_at`, so a tombstone NEVER expires before an in-flight login finishes.

---

## 3. Single-Current-Family Policy & Universal PG Lock Order (`R2-T52-V4-F04..F05`)

### 3.1 Policy Decision: `SINGLE_CURRENT_FAMILY_PER_BROWSER` (`LATEST_FAMILY_WINS`)
Within a single `browser_id` (`hc_browser`), at most ONE session family (`created_seq == browser_coord_state.login_seq > browser_coord_state.logout_seq`, `status == 'ACTIVE'`) is authorized at any point in time:
- When a newer login (`F_new`) commits on `browser_id`, inside the same serialized `L1` PG transaction, all prior `'ACTIVE'` families belonging to that same `browser_id` are transitioned to `'PENDING_REVOKE'` (with `revoke_reason = 'SUPERSEDED_BY_NEWER_LOGIN'` and `refresh_tokens.status = 'REVOKED'`), then published to Redis (`hc:revoked_family:{fid}`) and promoted to `'REVOKED'`.
- **Multi-device isolation**: Families belonging to any other `browser_id` (or legacy API sessions with `browser_id IS NULL`) remain **100% untouched** (`CE-10`).
- **Endpoint alignment**:
  - `POST /api/v1/auth/refresh`: Verifies `refresh_tokens.status == 'ACTIVE'` AND (if linked to `browser_session_families`) `family.status == 'ACTIVE'` AND `family.created_seq == coord.login_seq > coord.logout_seq` AND (when `hc_browser` cookie is present) `family.browser_id == caller_browser_id`. Stale superseded families always fail `401` (`clear_cookies=True`), never causing downgrade or resurrection.
  - `get_current_user` (`src/api/deps.py`): Verifies Redis not revoked + PG `verify_active_family(conn, family_id, user_id)` confirming `refresh_tokens` active AND `browser_session_families.status == 'ACTIVE'` AND `created_seq == login_seq > logout_seq`.
  - `POST /api/v1/auth/session/rebind-cookie`: Only rebinds the strictly latest `'ACTIVE'` family (`created_seq == login_seq > logout_seq`).
  - `POST /api/v1/auth/logout`: Accepts an older `hc_refresh` cookie from the SAME `hc_browser` (valid `CSRF(meta.family_id)`) **solely to prove logout intent for that `browser_id`**, advancing `logout_seq`, revoking any current `'ACTIVE'`/`'PENDING_REVOKE'` family on that `browser_id`, clearing cookies, and returning `200 OK` (preserving cross-tab race semantics when Tab B logs out with `F0` while Tab C's `F1` `Set-Cookie` was delayed in transit).

### 3.2 Strict Universal PostgreSQL Lock Order (Deadlock-Free Guarantee)
Every mutating auth transaction in `SessionService` and `auth.py` MUST acquire `FOR UPDATE` row locks in this strict, total global order (after any read-only `family_id -> browser_id` resolution, BEFORE acquiring any `FOR UPDATE` lock):
1. **`browser_coord_state`** (`WHERE browser_id = $1 FOR UPDATE`) — skipped only when `browser_id IS NULL`.
2. **`login_attempt_states`** (`ORDER BY attempt_id ASC FOR UPDATE`) — preceded by `INSERT ... ON CONFLICT (attempt_id) DO NOTHING` when inserting a new tombstone/attempt row.
3. **`browser_session_families`** (`ORDER BY family_id ASC FOR UPDATE`).
4. **`refresh_tokens`** (`ORDER BY id ASC FOR UPDATE`).

**Never** acquire `refresh_tokens FOR UPDATE` before `browser_coord_state` or `browser_session_families`. Zero `AB-BA` deadlocks across concurrent `/login`, `/logout`, `/login-attempts/cancel`, `/refresh`, `/session/rebind-cookie`, and `reconcile_pending_revocations()`.

---

## 4. Complete State Machines & Server-Owned Linearization (`L1..L7`)

### 4.1 Server-Captured Epoch Fencing (`R2-T52-V4-F01`, `L1`)
1. **Attempt Registration (`POST /api/v1/auth/login-attempts/start` & Optional in `POST /api/v1/auth/otp/request`)**:
   - Validates `Origin` (cookie mode), applies sliding rate limit, resolves/issues `hc_browser`.
   - Generates random 256-bit `cancel_capability`, stores `cancel_token_hash = sha256(cancel_capability)`.
   - Inside PG lock Level 1 (`browser_coord_state FOR UPDATE`) -> Level 2: inserts `login_attempt_states(attempt_id, browser_id, cancel_token_hash, started_logout_seq = browser_coord_state.logout_seq, status='STARTED', attempt_expires_at = NOW() + 30s, expires_at = NOW() + 300s)` using `ON CONFLICT DO NOTHING RETURNING ...`.
   - If conflict occurs (pre-cancelled `CANCELLED` or duplicate `attempt_id`), locks existing row via Level 2 and returns deterministic `HTTP 409 Conflict` ("Duplicate or already cancelled attempt_id").
   - Returns `{ attempt_id, started_logout_seq, cancel_capability, attempt_expires_at }` with `Cache-Control: no-store`.
   - Client keeps `(attempt_id, cancel_capability)` strictly in private ES module closure RAM (`attemptCapabilities` Map; zero WebStorage).
2. **Pre-Auth Guard (Phase A — Before slow Argon2id / OTP verification in `/password/login` & `/otp/verify`)**:
   - Cookie mode validates `Origin`, config, `_ensure_browser_id`.
   - Resolves actor (`verified_actor_user_id` if optional Bearer? No, anonymous until credentials verify, binds `browser_id`).
   - Locks Level 1 (`browser_coord_state`) -> Level 2 (`login_attempt_states`, inserting `'IN_FLIGHT'` with `started_logout_seq = coord.logout_seq` `ON CONFLICT DO NOTHING` if direct API caller omitted `/login-attempts/start`).
   - Enforces **strict anti-forgery & duplicate rejection**:
     - If row existed with `status IN ('CANCELLED', 'IN_FLIGHT', 'ACTIVE', 'PENDING_REVOKE', 'REVOKED')` -> return **`409 Conflict`**.
     - If `NOW() > attempt_expires_at` -> transition `'CANCELLED'`, commit, return **`409 Conflict`**.
     - If `row.browser_id IS NOT NULL AND row.browser_id != browser_id` -> return **`409 Conflict`**.
     - **Client `started_server_logout_seq` hardening**: Never used to relax fencing! If `payload.started_server_logout_seq is not None` and `payload.started_server_logout_seq != row.started_logout_seq` (either `<` stale OR `>` forged!), OR `coord.logout_seq > row.started_logout_seq` -> mark `'CANCELLED'`, commit, return **`409 Conflict`** immediately (zero Argon2/OTP work executed!).
     - Transition row `STARTED -> IN_FLIGHT` and commit Phase A BEFORE slow password/OTP verification (holds zero DB locks during Argon2!).
3. **Auth Verification & Atomic Login Commit (Phase B — `L1`)**:
   - Execute credential verification (`AuthService`: Argon2id / OTP consume) **without** prematurely committing an active `hc_refresh` session outside the fence (or passing `commit_session_fn` executed inside `L1`).
   - Lock Level 1 (`browser_coord_state FOR UPDATE`) -> Level 2 (`login_attempt_states(attempt_id) FOR UPDATE`) -> Level 3 (`browser_session_families WHERE browser_id = $1 AND status IN ('ACTIVE', 'PENDING_REVOKE') ORDER BY family_id FOR UPDATE`) -> Level 4 (`refresh_tokens` of superseded families `ORDER BY id FOR UPDATE`):
     - Re-verify `user.status == 'ACTIVE'` (`403`/`401`).
     - Re-verify `attempt_row.status == 'IN_FLIGHT'` AND `NOW() <= attempt_row.attempt_expires_at` AND `browser_coord_state.logout_seq == attempt_row.started_logout_seq`!
     - **If superseded** (`status != 'IN_FLIGHT'` or `logout_seq > attempt_row.started_logout_seq` or expired):
       - DO NOT insert any active session or advance `login_seq`!
       - If not already `'CANCELLED'`/`'PENDING_REVOKE'`/`'REVOKED'`, mark `login_attempt_states.status = 'CANCELLED'`. Commit & return **`409 Conflict`** (`clear_cookies=False`).
     - **If still valid (`logout_seq == attempt_row.started_logout_seq` and `status == 'IN_FLIGHT'`)**:
       - Supersede all prior `'ACTIVE'` families for same `browser_id` (`LATEST_FAMILY_WINS`): mark `browser_session_families.status = 'PENDING_REVOKE', revoke_reason = 'SUPERSEDED_BY_NEWER_LOGIN'` and `refresh_tokens.status = 'REVOKED'`.
       - Advance `global_seq = global_seq + 1`, `login_seq = new_seq`.
       - Insert new `browser_session_families(family_id, browser_id, user_id, attempt_id, created_seq=new_seq, status='ACTIVE')` (protected by `uq_browser_session_families_attempt_id` -> `UniqueViolationError` maps to `409`) and `refresh_tokens(..., status='ACTIVE')`.
       - Update `login_attempt_states SET family_id = $fid, user_id = $uid, status = 'ACTIVE', updated_at = NOW()`.
       - `COMMIT` PG!
       - Publish Redis revocations for superseded same-browser families & promote those superseded rows to `'REVOKED'` (best-effort fail-closed: if Redis fails on superseding prior family, `PENDING_REVOKE` remains durable in PG; optional fail-closed 503 if prior active family existed, returning 0 cookies so partial outage cannot split active sessions!).
       - Sync PG `auth_coord` to Redis Lua `MAX`.

### 4.2 Atomic Cancellation Tombstone & Ownership Authorization (`R2-T52-V4-F02`, `L2`)
On `POST /api/v1/auth/login-attempts/cancel` (accepting `{ attempt_ids: list[str], cancel_capabilities: dict[str, str] | None }`):
1. Validate `Origin` (`403` on reject), sanitize non-empty `attempt_ids` (sorted distinct, max `16`).
2. Identify caller credentials cleanly:
   - Check verified caller identity (`verified_actor_user_id`):
     - Valid non-expired `Authorization: Bearer hc_at_v1.*` passing Redis non-revoked AND PG `verify_active_family` -> yields `verified_actor_user_id` AND enables verified quota (`60 req / 192 ids / 300s` TTL). (Allow recently-minted valid token even if called immediately).
     - OR valid `'ACTIVE'` `hc_refresh` cookie verified against Redis + PG -> yields `verified_actor_user_id` + verified quota.
     - Otherwise `verified_actor_user_id = None` (receives **unauthenticated quota `20 req / 64 ids / 120s` TTL**, even if `hc_browser` cookie is present!).
3. Enforce **Multi-Key Atomic Lua ZSET Sliding-Window Quota** (`L7`) BEFORE any PG or Redis cancellation write (`RedisError` -> `503`; exceeded -> `429 Retry-After: 60`).
4. Inside ONE ACID PG transaction locking strictly in canonical order:
   - Level 2 Pre-Lock Upsert (eliminates `NONE -> CANCELLED` phantom race!):
     For each `aid` in sorted `attempt_ids`:
     ```sql
     INSERT INTO login_attempt_states (
         attempt_id, browser_id, user_id, status, started_logout_seq,
         attempt_expires_at, expires_at
     )
     VALUES ($1, $2, NULL, 'CANCELLED', 0, NOW(), $3)
     ON CONFLICT (attempt_id) DO NOTHING;
     ```
     Immediately followed by:
     ```sql
     SELECT attempt_id, family_id, browser_id, user_id, status, cancel_token_hash
     FROM login_attempt_states
     WHERE attempt_id = ANY($1::varchar[])
     ORDER BY attempt_id ASC
     FOR UPDATE;
     ```
   - Collect all non-null `family_id` values (`sorted_fids`), lock Level 3 (`browser_session_families WHERE family_id = ANY($1) ORDER BY family_id FOR UPDATE`), then evaluate authorization on **EVERY** requested row BEFORE mutating ANY existing row (all-or-nothing fail-closed `403`):

   **Exact Ownership & Capability Authorization Matrix (`check_attempt_cancel_authorized`)**:
   | Row State at Lock Time | Has `user_id`? | Has `cancel_token_hash`? | Caller Authorization Rule | Unauthorized Action |
   |------------------------|----------------|--------------------------|---------------------------|---------------------|
   | Newly inserted by this tx (`ON CONFLICT` inserted `'CANCELLED'`) | `NULL` | `NULL` | Permitted (pre-cancel tombstone creation; binds `browser_id = caller_browser_id` if present). | N/A |
   | Existing row (`STARTED` / `IN_FLIGHT`) | `NULL` | Non-null (`sha256(cap)`) | Caller MUST provide `hmac.compare_digest(sha256(cap_for_aid), row.cancel_token_hash)` (or `verified_actor_user_id` if matched). Anonymous `hc_browser` alone is **DENIED**! | `ROLLBACK` & return `HTTP 403` |
   | Existing row (`ACTIVE` / `PENDING_REVOKE` / `REVOKED`) | **Non-null (`uid_owner`)** | Null or non-null | `(verified_actor_user_id == uid_owner)` **OR** valid matching `cancel_capability`. **Anonymous same-browser request (`verified_actor_user_id IS NULL`) without valid `cancel_capability` is STRICTLY DENIED even if `hc_browser` matches!** Wrong authenticated `user_id` (`uid_b != uid_owner`) is **STRICTLY DENIED**! | `ROLLBACK` & return `HTTP 403` |
   | Existing `'CANCELLED'` pre-tombstone | `NULL` | `NULL` | Permitted ONLY if `(row.browser_id IS NULL OR row.browser_id == caller_browser_id OR verified_actor_user_id IS NOT NULL)` (idempotent `'CANCELLED'`). | `ROLLBACK` & return `HTTP 403` |

   - If ALL rows pass authorization:
     - Lock Level 4 (`refresh_tokens WHERE family_id = ANY($1) ORDER BY id FOR UPDATE`) -> set `status = 'REVOKED'` where `status != 'REVOKED'`.
     - For bound rows (`family_id IS NOT NULL` or `'ACTIVE'`/`'IN_FLIGHT'`/`'STARTED'` -> mark `browser_session_families.status = 'PENDING_REVOKE'`, `login_attempt_states.status = 'PENDING_REVOKE'`; tombstones with `family_id IS NULL` & no prior active session remain `'CANCELLED'`).
     - NEVER reads or writes `browser_coord_state.logout_seq`!
     - `COMMIT` PG!
   - Publish `hc:revoked_family:{fid}` and `hc:cancelled_login_attempt:{aid}` to Redis with TTL `>= REFRESH_COOKIE_MAX_AGE + 86400` (`8 days`) for revoked families and `120s`/`300s` for un-minted cancelled tombstones -> ONLY AFTER Redis confirms writes, promote `'PENDING_REVOKE' -> 'REVOKED'` in PG! If Redis fails, return `HTTP 503` (leaving `'PENDING_REVOKE'` durable in PG for `reconcile_pending_revocations()`).

### 4.3 Multi-Worker Failure Recovery (`R2-T52-V4-F06`, `L3`)
- **`SessionService.reconcile_pending_revocations(batch_size: int = 50, max_batches: int = 20) -> int`**:
  1. Runs inside bounded short transactions locking batches with deterministic ordering:
     - `SELECT family_id FROM browser_session_families WHERE status = 'PENDING_REVOKE' ORDER BY updated_at ASC, family_id ASC FOR UPDATE SKIP LOCKED LIMIT $1`
     - Defensive invariant enforcement inside same lock: `UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = ANY($1) AND status != 'REVOKED'`.
     - **While holding those `FOR UPDATE SKIP LOCKED` row locks** (typically `< 2ms` local Redis pipeline), write `SET hc:revoked_family:{fid} reason EX 691200` (`8 days`, strictly `> 7-day refresh TTL` + `300s access TTL`) to Redis for EVERY locked row.
     - **Crash & error safety**:
       - If Redis raises `RedisError`, `ROLLBACK` without promoting (`status` stays `'PENDING_REVOKE'`; raises `RevocationStoreUnavailableError` if critical/propagated).
       - If this worker crashes BEFORE `COMMIT`, PostgreSQL automatically releases row locks, rows remain `'PENDING_REVOKE'`, Redis writes are idempotent, and another worker picks them up cleanly with zero lost work.
       - Concurrent Worker 2 executing `FOR UPDATE SKIP LOCKED` skips rows locked by Worker 1 and handles distinct batches concurrently — zero race or double promotion!
     - ONLY AFTER Redis confirms writes: `UPDATE browser_session_families SET status = 'REVOKED', updated_at = NOW() WHERE family_id = ANY($1)` and `COMMIT`.
     - Repeat similarly for `login_attempt_states WHERE status = 'PENDING_REVOKE' ORDER BY updated_at ASC, attempt_id ASC FOR UPDATE SKIP LOCKED LIMIT $1` (writing `hc:cancelled_login_attempt:{aid}` + promoting `'REVOKED'`).
  2. **Invocation**:
     - FastAPI startup lifespan hook (best-effort bounded sweep if PG & Redis healthy).
     - Opportunistically invoked (`LIMIT 20`) inside coordination endpoints (`/coord/session`, `/logout`, `/login-attempts/cancel`, `/refresh`) when pending rows exist.
- **Fail-Closed Outage Matrix**:
  - Any `asyncpg.PostgresError` or pool error in `get_current_user`, `/refresh`, `/logout`, `/session/rebind-cookie`, `/login-attempts/start`, `/login-attempts/cancel`, `/coord/session` returns normalized `HTTP 503 Service Unavailable` with `Cache-Control: no-store`.
  - Any `redis.RedisError` returns `HTTP 503` without deleting or skipping PG `'PENDING_REVOKE'` state.

### 4.4 `/session/rebind-cookie` Security Contract (`R2-T52-V4-F04`, `F05`, `L6`)
Restores `HttpOnly hc_refresh` + `hc_csrf` after a delayed HTTP `200 Set-Cookie` from a stale pre-logout login (`F1`) overwrote a newer active session (`F3`)'s browser cookie jar:
1. Validate `Origin` (`validate_cookie_request_origin(req)` -> `403`).
2. Extract & cryptographically verify `Authorization: Bearer hc_at_v1.<payload>.<sig>` with **`allow_expired=False`** (`401` if missing, invalid, or expired!).
3. Extract & HMAC-verify mandatory signed `hc_browser` cookie (`401`/`403` if missing or invalid; NEVER mints a new browser ID here).
4. Preflight signing secret + TTL (`503` if misconfigured) & check Redis `is_family_revoked_in_redis(r, claims['family_id'])` (`401` if revoked; `503` on `RedisError`).
5. Execute universal locked PG transaction (`1: browser_coord_state -> 3: browser_session_families(F) -> 4: refresh_tokens(F, ORDER BY id FOR UPDATE)`):
   - Verify user `users.status == 'ACTIVE'` (otherwise revoke family `'PENDING_REVOKE'` -> Redis -> `'REVOKED'` & return `401`).
   - Verify `family.family_id == claims['family_id']` AND `family.user_id == claims['user_id']`.
   - Verify `family.browser_id == caller_browser_id` (`403` on wrong browser!).
   - Verify `family.status == 'ACTIVE'` (`401` otherwise).
   - Verify `family.created_seq == browser_coord_state.login_seq` AND `family.created_seq > browser_coord_state.logout_seq` (`401` on older/superseded family or logged-out browser!).
   - Verify at least one `'ACTIVE'` non-expired token row exists in `refresh_tokens` for `family_id`.
   - Atomically rotate the latest `'ACTIVE'` token row (`old.status = 'ROTATED', rotated_at = NOW(), successor_id = new.id`; insert fresh `'ACTIVE'` token), commit, and set `HttpOnly; SameSite=Lax; Path=/api/v1/auth` `hc_refresh`, `hc_csrf(family_id)`, `hc_has_session=1`, `Cache-Control: no-store`. Never expose any refresh token in JSON response body.
6. **Concurrent Rebind / Refresh / Logout Safety**:
   - Because `/refresh` and `/session/rebind-cookie` and `/logout` all acquire PG locks in identical `1 -> 3 -> 4` order:
     - `/logout` vs `/rebind-cookie`: either `/logout` locks `browser_coord_state` first (advancing `logout_seq`, marking `F3` `REVOKED` -> `/rebind-cookie` fails `401`), or `/rebind-cookie` commits first and `/logout` immediately revokes `F3` including its newly rotated token! Zero resurrection possible!
     - Concurrent `/refresh` vs `/rebind-cookie`: if `/rebind-cookie` rotates `T_old -> T_new` first, an already-in-flight `/refresh(T_old)` arrives 2nd inside the `5s` grace window (`rotated_at`), raising `ConcurrentRefreshConflictError` (`HTTP 409`, `clear_cookies=False`) WITHOUT triggering `REPLAY_ATTACK` revocation!
7. **Client Mandatory Rebind-Before-Discard (`R2-T52-V4-F04`)**:
   - `executeCookieRefreshRequest()` MUST NOT depend solely on receiving `COOKIE_MAY_BE_STALE` over `BroadcastChannel`.
   - If `POST /api/v1/auth/refresh` returns `401` while `!logoutBarrierActive && hasFreshAccessToken() && activeSessionFamilyId && !isNonLoginInvalidated(...)`, client MUST automatically invoke `POST /api/v1/auth/session/rebind-cookie` once (`rebindAttempted = false -> true`), and only retry `/refresh` if rebind succeeds `200`. If rebind returns `401/403/409`, fail closed (`EXPIRED`).

### 4.5 Browser Bootstrap, `bi` Hint Policy & Client Lock Hierarchy (`R2-T52-V4-F07`, `L5`)
- **Supported Browser Policy**: Web Locks API (`navigator.locks.request`) is **mandatory** for multi-tab Phase 3 session coordination (supported across Chromium 69+, Edge 79+, Firefox 96+, Safari 15.4+).
- **Fail-Closed Fallback When `navigator.locks` Is Unavailable**:
  - Do NOT silently run an unlocked cross-tab cookie race or merge `hc_coord` across tabs.
  - All in-tab operations serialize via FIFO promise queue (`inTabLockQueue`), explicit local cleanup/logout ALWAYS works, AND multi-tab credential bootstrap/login/background refresh FAIL CLOSED with explicit `WEB_LOCKS_UNAVAILABLE` error state (`lastErrorMessage`, zero silent success) without ever trusting `hc_coord.bi`.
- **`hc_coord.bi` Strictly a Hint**: `bi=1` NEVER bypasses server checks and NEVER grants coordination trust. Inside `hamicard_phase3_browser_init` Web Lock (`L5`), Tab B calls `POST /api/v1/auth/coord/session` ONLY after Tab A finishes bootstrap and sets `HttpOnly hc_browser` (or if `bi=1` was cached inside a valid Web-Lock context AND `serverGlobalSeq > 0`, still verified authoritatively on server `/login-attempts/start` & `/coord/session`; if Tab B calls `/coord/session`, it sends Tab A's committed `HttpOnly hc_browser` cookie so server confirms the SAME `browser_id` and issues `0` duplicate unbootstrapped cookies!).
- **Server `hc_browser` Cookie Adoption Validation (`_ensure_browser_id`)**:
  - When signed `hc_browser` cookie is absent/invalid: adopt existing `browser_id` ONLY if client presents a valid `hc_refresh` cookie whose PG `refresh_tokens` row is `'ACTIVE'` (non-expired) AND linked `browser_session_families` row is `'ACTIVE'` with `created_seq == browser_coord_state.login_seq > browser_coord_state.logout_seq`. Never adopt from revoked cookies or unverified client headers. Otherwise mint new random `b_<uuid>` and insert `browser_coord_state` row cleanly.
- **Strictly Acyclic Client Lock Hierarchy**:
  1. Level 1 (Outer): `hamicard_phase3_browser_init` — serializes initial `/coord/session` across tabs.
  2. Level 2 (Middle): `hamicard_phase3_refresh` — serializes `/refresh` & `/session/rebind-cookie`; never acquires Level 1.
  3. Level 3 (Innermost Leaf): `hamicard_phase3_coord` (`withCoordLock`) — synchronous-only cookie parse/update (`writeCoordCookie` forbidden anywhere outside!); NEVER performs `fetch()` or acquires Level 1 / Level 2. Zero `writeCoordCookie()` calls are permitted outside `withCoordLock()`.

### 4.6 Multi-Key Atomic Lua ZSET Sliding-Window Rate Limiter (`R2-T52-V4-F08`, `L7`)
All quota checks in `/login-attempts/cancel` execute as ONE multi-key Redis `EVAL` Lua script atomically before allocating PG rows or cancellation keys:
```lua
-- KEYS = [ip_req_key, ip_ids_key, global_req_key, global_ids_key]
-- ARGV = [now_ms, window_ms, req_weight, ids_weight, ip_req_lim, ip_ids_lim, gl_req_lim, gl_ids_lim, nonce]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local cutoff = now_ms - window_ms
local weights = { tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[3]), tonumber(ARGV[4]) }
local limits  = { tonumber(ARGV[5]), tonumber(ARGV[6]), tonumber(ARGV[7]), tonumber(ARGV[8]) }
local nonce   = ARGV[9]

for idx = 1, 4 do
  redis.call('ZREMRANGEBYSCORE', KEYS[idx], '-inf', cutoff)
  local cur = tonumber(redis.call('ZCARD', KEYS[idx])) or 0
  if (cur + weights[idx]) > limits[idx] then
    return {0, idx, cur}
  end
end

for idx = 1, 4 do
  local w = weights[idx]
  for j = 1, w do
    redis.call('ZADD', KEYS[idx], now_ms, tostring(now_ms) .. ':' .. nonce .. ':' .. tostring(idx) .. ':' .. tostring(j))
  end
  redis.call('PEXPIRE', KEYS[idx], window_ms + 5000)
end
return {1, 0, 0}
```
- Rejected `429` requests NEVER insert ZSET members and NEVER burn sibling global buckets.
- Concurrent sub-millisecond requests get distinct `now_ms:nonce:idx:j` members.
- Any `redis.RedisError` fails closed `HTTP 503` (zero PG mutations).

---

## 5. Authoritative Security Invariants (`INV-01..INV-12`)

- **INV-01 (`C2-H01`)**: Calling `/login-attempts/cancel([B1])` NEVER advances `logout_seq` and NEVER revokes any family `F3` whose `attempt_id != B1`.
- **INV-02 (`C2-H02`)**: No active family tracking entry is ever removed from PG prior to PG `refresh_tokens.status = 'REVOKED'` AND Redis confirmation (`ACTIVE -> PENDING_REVOKE -> REVOKED`).
- **INV-03 (`C2-H02` / `F01`)**: Under concurrent login & logout where attempt started BEFORE logout (`started_logout_seq` captured server-side at start), `0` active sessions survive after both settle; pre-logout attempt CANNOT bypass logout even with forged `started_server_logout_seq`.
- **INV-04 (`C2-H03` / `F07`)**: Two fresh tabs initializing concurrently with delayed `/coord/session` converge to 1 `hc_browser`; missing `navigator.locks` fails closed instead of running unlocked cross-tab race; `bi=1` never bypasses validation.
- **INV-05 (`C2-H04`)**: Client `hc_coord` mutations are 100% inside `withCoordLock`; PG lock acquisition obeys universal order `browser_coord_state -> login_attempt_states -> browser_session_families -> refresh_tokens`.
- **INV-06 (`C2-M01` / `F02`)**: Forged `Bearer` & anonymous `hc_browser` cookies receive unauthenticated quotas (`20 req / 64 ids / 120s` TTL). Anonymous same-browser `/login-attempts/cancel` WITHOUT valid `cancel_capability` returns `403` and cannot revoke any bound user's session; cross-user cancel returns `403`.
- **INV-07 (`C2-M02` / `F04` / `F05`)**: Overwritten stale `F1` fails `/refresh` (`401`) and cannot downgrade; client auto-rebinds `HttpOnly hc_refresh` to `F3` via `/session/rebind-cookie` EVEN when `COOKIE_MAY_BE_STALE` broadcast is dropped!
- **INV-08 (`C2-M03`)**: When `/login-attempts/cancel` returns `429`, `503`, or `0`, UI does NOT report clean success and preserves `unresolvedCancelledAttemptIds` + `canRetryLogout` + error copy.
- **INV-09 (`F03`)**: Duplicate concurrent `attempt_id` produces at most 1 family in `browser_session_families` and deterministically rejects duplicate with `409`; tombstone TTL (`120s`/`300s`) outlives `attempt_expires_at` (`30s`).
- **INV-10 (`F06`)**: Separate PG and Redis failures both fail closed (`503`); two concurrent `reconcile_pending_revocations()` workers (`FOR UPDATE SKIP LOCKED`) reconcile 100% of `PENDING_REVOKE` rows to Redis & `'REVOKED'` with zero loss.
- **INV-11 (`F08`)**: Lua ZSET enforces continuous sliding window, weighted attempt-ID limits (`64` unauth / `192` auth), non-pollution on `429`, and fail-closed `503` on Redis outage.
- **INV-12 (`AC-14/AC-15/Multi-device`)**: Multi-device `Browser B` and unrelated `User B` remain `ACTIVE` when `Browser A` logs out; existing `T13..T49` invariants remain `100%` intact.

---

## 6. `RED_TEST_MATRIX` (Pre-Implementation Counterexamples in `tests/test_hc_t53_architecture_counterexamples.py`)

| Test ID | Mapping | Counterexample Scenario | Expected on `e7c2bb81` (RED) | Expected after `HC-T53` (GREEN) |
|---------|---------|-----------------------|-------------------------------|---------------------------------|
| `CE-01` | `C2-H01` | Delayed `[B1]` cancellation after logout & newer `F3` login | **FAILS**: revokes `F3`, `/refresh` `401` | `F3` stays `ACTIVE`, `/refresh` `200`, `B1` revoked |
| `CE-02` | `C2-H02/H04/F01` | Pre-logout started attempt (`login-attempts/start` -> `started_logout_seq=0`) racing concurrent `/logout` | **FAILS**: inverted `auth_coord` / lost or un-fenced session | Server captures `started_logout_seq=0`, linearizes PG `FOR UPDATE`, `0` surviving active tokens in all schedules, PG statuses `'REVOKED'`, pre-logout commit losing race rejected `409` |
| `CE-03a` | `C2-H02/F06` | PG failure injected mid-`refresh_tokens` revocation during `/logout` | **FAILS**: `e7c2bb81` popped `hc:browser_recent_families` before PG ran, losing `F1` | Fails `503`, `F1` remains `'ACTIVE'` in PG, healed `/logout` revokes `F1` (`REVOKED` + Redis) |
| `CE-03b` | `C2-H02/F06` | Redis outage AFTER PG commit + dual concurrent `reconcile_pending_revocations()` workers | **FAILS**: missing `PENDING_REVOKE` & `reconcile_pending_revocations` | Returns `503`, PG `refresh_tokens='REVOKED'` & `browser_session_families='PENDING_REVOKE'`, dual workers (`SKIP LOCKED`) reconcile all rows to `'REVOKED'` + Redis (`TTL > 7d`) with `0` loss |
| `CE-04` | `C2-H03` | Two fresh tabs concurrently click Login with delayed `/coord/session` | **FAILS**: splits `hc_browser` | `hamicard_phase3_browser_init` converges to 1 `hc_browser`; logout leaves `0` active tokens |
| `CE-05` | `C2-H04` | Web Lock `withCoordLock` discipline audit on `hc_coord` mutations | **FAILS**: unlocked `hc_coord` write | 100% `hc_coord` writes strictly inside `navigator.locks('hamicard_phase3_coord')` |
| `CE-06` | `C2-M01` | 21 rapid `/login-attempts/cancel` requests with forged `Bearer` | **FAILS**: elevates to `60` req quota | Enforces `20` req unauth quota -> `429` by call 21 |
| `CE-07a` | `C2-M01/F02` | Cross-user AND anonymous same-browser (no capability) `/login-attempts/cancel` against bound `user_a` attempt | **FAILS**: anonymous same-browser or weak ownership leaks revocation | Both blocked `403`; `fam_a` stays `ACTIVE`; valid `cancel_capability` / owning `user_a` succeeds `200` |
| `CE-07b` | `C2-M01` | 21 rapid `/login-attempts/cancel` requests with anonymous `hc_browser` cookie | **FAILS**: elevates to `60` req / `300s` TTL | Enforces `20` req quota (`429` by call 21) & `<= 120s` TTL |
| `CE-08` | `C2-M02/F04/F05` | Delayed `200 Set-Cookie: F1` overwrite + dropped `BroadcastChannel` + adversarial rebind matrix (`expired bearer`, `wrong browser`, `old family`, `bad origin`, `rebind vs refresh/logout`) | **FAILS**: `/refresh` with stale `F1` fails without rebind recovery; no `/session/rebind-cookie` | Direct stale `F1` `/refresh` returns `401`; Tab A recovers `F3` via `/rebind-cookie` even without `COOKIE_MAY_BE_STALE` & `/refresh` returns `200`; all adversarial checks pass |
| `CE-09` | `C2-M03` | `429` & `503` cancellation failures in `revokeSupersededLoginOnServer()` | **FAILS**: drops failure silently | UI surfaces error + `REMOTE_REVOKE_FAILED` + preserves `canRetryLogout` & unresolved attempt IDs |
| `CE-10` | `C2-H01/AC-15` | Multi-device Browser B & unrelated User B isolation | Baseline PASS | Both remain `ACTIVE` after Browser A logout/cancel |
| `CE-11` | `F01/F03` | Forged `started_server_logout_seq=999` bypass attempt (password & OTP) + duplicate concurrent `attempt_id` | **FAILS**: `e7c2bb81` accepts `999` after logout (`200`) & mints 2 families for 1 `attempt_id` | Forged `started_server_logout_seq` rejected `409` (`0` active tokens); duplicate `attempt_id` creates at most `1` family & rejects loser `409` |
| `CE-12` | `F08` | Continuous Lua ZSET sliding-window boundary + `429` non-pollution + weighted `ids` (`64`) + Redis `503` | **FAILS**: fixed-window `INCRBY` pollutes & resets abruptly at boundary | Sliding window expires chronologically, `429` does not pollute ZSET, weighted IDs capped cleanly, Redis error returns `503` |
| `CE-13` | `F07` | Missing `navigator.locks` + forged `hc_coord` `bi=1` fallback | **FAILS**: runs unlocked without fail-closed guard | Fails closed with explicit `WEB_LOCKS` error state without trusting `bi=1` |
