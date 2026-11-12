# HamiCard Phase 3 Authentication Concurrency Architecture & Failure-Recovery Specification (`HC-T52` Revision 2.1)

- **Command**: `HC-CMD-053` / `HC-T52` (Bounded Final Revision 2.1 authorized by `HC-COMMANDER-014` prior to `HC-T53`)
- **Base Commit (`OLD_CANDIDATE`)**: `e7c2bb81f7278e1d9a0fe8ca75e56d06fec753fb`
- **Review Alignment**: Closes Reviewer #2 Revision 2 findings `HIGH-01`..`HIGH-05` & `MEDIUM M-01`..`M-05`, alongside `R2-T52-REV1-H01`..`H07`, `REV1-M01`..`M04`, and `R2-T52-V4-F01`..`F08`.
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
    browser_id  VARCHAR(64) PRIMARY KEY,
    coordinated BOOLEAN NOT NULL DEFAULT FALSE,
    global_seq  BIGINT NOT NULL DEFAULT 0,
    logout_seq  BIGINT NOT NULL DEFAULT 0,
    login_seq   BIGINT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_bsf_family_attempt_browser_user
        UNIQUE (family_id, attempt_id, browser_id, user_id)
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
    family_id          UUID NULL,
    browser_id         VARCHAR(64) NULL REFERENCES browser_coord_state(browser_id) ON DELETE CASCADE,
    user_id            UUID NULL REFERENCES users(id) ON DELETE CASCADE,
    cancel_token_hash  VARCHAR(64) NULL,
    started_logout_seq BIGINT NOT NULL DEFAULT 0,
    status             VARCHAR(20) NOT NULL CHECK (status IN ('STARTED', 'IN_FLIGHT', 'ACTIVE', 'CANCELLED', 'PENDING_REVOKE', 'REVOKED')),
    attempt_expires_at TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_las_family_requires_owner
        CHECK (family_id IS NULL OR (browser_id IS NOT NULL AND user_id IS NOT NULL)),
    CONSTRAINT fk_las_exact_family_binding
        FOREIGN KEY (family_id, attempt_id, browser_id, user_id)
        REFERENCES browser_session_families (family_id, attempt_id, browser_id, user_id)
        ON DELETE NO ACTION
);

CREATE INDEX IF NOT EXISTS idx_las_pending_revoke
    ON login_attempt_states (updated_at, attempt_id)
    WHERE status = 'PENDING_REVOKE';

CREATE INDEX IF NOT EXISTS idx_las_tombstone_expires
    ON login_attempt_states (expires_at, attempt_id)
    WHERE status IN ('CANCELLED', 'REVOKED');
```

### Schema Invariants (`R2-T52-V4-F01..F03`, `R2-T52-REV1-H05`, `REV1-M03`)
1. **Mutual 1:1 Database-Enforced Binding (`REV1-H05`)**:
   - `uq_browser_session_families_attempt_id` ensures two family rows can never share one `attempt_id`.
   - `uq_bsf_family_attempt_browser_user` + `fk_las_exact_family_binding (MATCH SIMPLE)` + `chk_las_family_requires_owner` guarantee at the PostgreSQL catalog level that whenever `login_attempt_states.family_id IS NOT NULL`, the referenced `browser_session_families` row MUST have the exact same `(family_id, attempt_id, browser_id, user_id)` tuple — making asymmetric binding (`attempt A -> F_B -> attempt B`) or cross-user/cross-browser binding structurally impossible in PostgreSQL!
   - In addition, `L1` (Phase B) and `L2` (cancellation under row locks) explicitly verify `row.browser_id == fam.browser_id AND row.user_id == fam.user_id AND (fam.attempt_id IS NULL OR fam.attempt_id == row.attempt_id)`.
2. **Immutable Ownership & Start Epoch**: Once non-null, `started_logout_seq`, `browser_id`, `user_id`, `cancel_token_hash`, and `family_id` are NEVER overwritten.
3. **Tombstone vs Attempt Lifetime**: Max in-flight authentication window is `MAX_AUTH_ATTEMPT_LIFETIME_SECONDS = 30s` (`attempt_expires_at`). Cancellation tombstone retention (`expires_at`) is `3600s` (1 hour — strictly `120x` longer than `attempt_expires_at` and well above the `300s` max sliding-window TTL), so a tombstone NEVER expires before an in-flight login or rate-limit window finishes.
4. **Refresh Tokens Linkage**: Note existing `refresh_tokens(family_id)` rows hold `id, family_id, user_id, token_hash, status, expires_at, rotated_at, successor_id`. All session creation/rotation/revocation operations keep `refresh_tokens` consistent with `browser_session_families` inside the same serialized PG transaction.

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

### 3.2 Strict Universal PostgreSQL Lock Order & Cycle-Free Proof (`R2-T52-REV1-H01`)
Every mutating auth transaction in `SessionService` and `auth.py` obeys a strict 4-level total global hierarchy:
1. **Level 1 — `browser_coord_state`** (`ORDER BY browser_id ASC FOR UPDATE`)
2. **Level 2 — `login_attempt_states`** (`ORDER BY attempt_id ASC FOR UPDATE`)
3. **Level 3 — `browser_session_families`** (`ORDER BY family_id ASC FOR UPDATE`)
4. **Level 4 — `refresh_tokens`** (`ORDER BY id ASC FOR UPDATE`)

**Prefix-Omission & Pre-Scan Theorem (Deadlock-Free Proof)**:
- **Strictly increasing acquisition**: No transaction may EVER acquire a lower-numbered Level after holding a higher-numbered Level (`i < j => Lock(j)` never precedes `Lock(i)`), nor acquire multiple rows in non-ascending primary-key order within the same level.
- **No dynamic upward escalation**: Because `browser_id` (`Level 1`) is an ancestor of both `login_attempt_states` and `browser_session_families`:
  - **`L1` (`/login-attempts/start`, Phase A, Phase B)**: Knows `browser_id` up-front from signed `hc_browser` (or newly ensured row). Locks strictly `Level 1 -> Level 2 [-> Level 3 -> Level 4]`.
  - **`L2` (`/login-attempts/cancel`)**:
    1. Executes an **unlocked read pre-scan** (`SELECT DISTINCT browser_id FROM login_attempt_states WHERE attempt_id = ANY($1) AND browser_id IS NOT NULL`) union `{caller_cookie_browser_id}` -> sorted `known_bids`.
    2. Locks **Level 1** (`browser_coord_state WHERE browser_id = ANY($known_bids) ORDER BY browser_id ASC FOR UPDATE` if `known_bids` is non-empty — ensures parent row exists safely and respects Level 1 first!).
    3. Executes `INSERT INTO login_attempt_states (...) ON CONFLICT (attempt_id) DO NOTHING`, followed by **Level 2** (`SELECT ... FROM login_attempt_states WHERE attempt_id = ANY($1) ORDER BY attempt_id ASC FOR UPDATE`).
    4. **Dynamic race guard**: Checks whether any locked `login_attempt_states` row now has a non-null `browser_id` absent from `known_bids` (possible if a concurrent Phase A committed without `hc_browser` between step 1 and step 3). If so, `L2` **rolls back immediately and retries** with the expanded `known_bids` (bounded `max_retries=2`). It **NEVER** locks `browser_coord_state` after `login_attempt_states`!
    5. Evaluates `check_attempt_cancel_authorized(...)` across all rows + locked **Level 3** (`browser_session_families ORDER BY family_id ASC FOR UPDATE`) + **Level 4** (`refresh_tokens ORDER BY id ASC FOR UPDATE`). (Note: `L2` never bumps `logout_seq`, yet acquiring Level 1 upfront eliminates any cycle against `L1`/`logout` that touch Levels `1 -> 2 -> 3 -> 4`).
  - **`L3` (`reconcile_pending_revocations`)**:
    - Batch Phase 1 (Families): Runs as a **Level 3 -> optional Level 4** leaf transaction (`SELECT family_id FROM browser_session_families WHERE status = 'PENDING_REVOKE' ORDER BY updated_at ASC, family_id ASC FOR UPDATE SKIP LOCKED LIMIT $1`, then defensive `Level 4` update on `refresh_tokens WHERE family_id = ANY($1) ORDER BY id`). Strictly **NEVER** acquires Level 1 or Level 2!
    - Batch Phase 2 (Attempts): Separate transaction locking strictly **Level 2** (`login_attempt_states ORDER BY attempt_id ASC FOR UPDATE SKIP LOCKED`) with ZERO Level 1, Level 3, or Level 4 acquisitions after Level 2.
    - Because neither transaction ever acquires a lower Level (`Level 1`), nor waits on locked rows (`SKIP LOCKED`), `L3` cannot participate in any wait-for cycle with `L1`, `L2`, `L4`, `L5`, or `L6`.
  - **`L4/L5/L6` (`/logout`, `/refresh`, `/session/rebind-cookie`, `/coord/session`)**: Pre-resolves `browser_id` via unlocked read from `refresh_tokens JOIN browser_session_families` BEFORE acquiring locks, then acquires strictly `Level 1 -> [Level 2 if /logout carries cancelled_login_attempt_ids] -> Level 3 -> Level 4`.

All wait-for edges point strictly forward (`1 -> 2 -> 3 -> 4`) and ascending by PK within every level; therefore deadlock cycles (`AB-BA`) are mathematically impossible across all concurrent endpoints and background reconcilers.

#### 3.2.1 Endpoint & Background Task SQL Lock-Acquisition Matrix (`HIGH-01`)

| Operation / Endpoint | Ordered Lock Sequence | Permitted Skipped Levels | Prohibited Acquisitions | Retry / Rollback Contract |
|---|---|---|---|---|
| `POST /api/v1/auth/coord/session` | `L1 (browser_coord_state)` | Skips `L2`, `L3`, `L4` | Any lock on `L2..L4` before `L1` | `INSERT ... ON CONFLICT DO UPDATE`, single short commit |
| `POST /api/v1/auth/login-attempts/start` | `L1 -> L2 (login_attempt_states)` | Skips `L3`, `L4` | Locking `L1` after `L2` | Rejects `409` on seq mismatch or duplicate `attempt_id` |
| `/password/login` & `/otp/verify` Phase A | `L1 -> L2` | Skips `L3`, `L4` | Holding ANY DB lock across Argon2id / OTP check | Commits `STARTED -> IN_FLIGHT` before slow verification |
| `/password/login` & `/otp/verify` Phase B (`L1`) | `L1 -> L2 -> L3 -> L4` | None (or skips `L4` if no active superseded token rows) | Acquiring `L1/L2` after `L3/L4`, descending PK order | Rejects `409` cleanly (marks `CANCELLED`) if fenced |
| `POST /api/v1/auth/login-attempts/cancel` (`L2`) | `L1 (sorted known_bids) -> L2 (sorted attempt_ids) -> L3 (sorted family_ids) -> L4 (sorted token ids)` | Skips `L1` only if `known_bids` empty; skips `L3`/`L4` if no bound `family_id` | Acquiring `L1` after `L2` (even for newly discovered `browser_id`); locking `L2` before `L1` | **Pre-scan/rollback/retry** (`max_retries=2`): rolls back entire tx if any locked `L2` row carries `browser_id` outside `known_bids` |
| `POST /api/v1/auth/logout` (`L4`) | `L1 -> [L2 optional] -> L3 -> L4` | Skips `L2` if `cancelled_login_attempt_ids` is empty | Acquiring `L1` after `L2/L3/L4` | Pre-resolves `browser_id` read-only from token/family before locking |
| `POST /api/v1/auth/refresh` (`L5`) | `L1 -> L3 -> L4` | Skips `L2` | Acquiring `L1/L2` after `L3/L4` | Pre-resolves `browser_id` read-only from `refresh_tokens JOIN browser_session_families` |
| `POST /api/v1/auth/session/rebind-cookie` (`L6`) | `L1 -> L3 -> L4` | Skips `L2` | Acquiring `L1/L2` after `L3/L4` | Pre-resolves `browser_id` read-only; verifies `family.created_seq == login_seq > logout_seq` |
| `reconcile_pending_revocations` Phase 1 (`L3`) | `L3 (SKIP LOCKED) -> L4` | Skips `L1`, `L2` | Strictly NEVER locks `L1` or `L2` | Non-blocking `FOR UPDATE SKIP LOCKED`; rolls back to preserve `PENDING_REVOKE` on `RedisError` |
| `reconcile_pending_revocations` Phase 2 (`L3`) | `L2 (SKIP LOCKED)` | Skips `L1`, `L3`, `L4` | Strictly NEVER locks `L1`, `L3`, or `L4` after `L2` | Non-blocking leaf tx; keeps `PENDING_REVOKE` on `RedisError` |
| `purge_expired_auth_records` (GC) | `Tx A: L2 (SKIP LOCKED)`; `Tx B: L2 -> L3 (REVOKED >10d FOR UPDATE SKIP LOCKED) -> L4` | Skips `L1` | Strictly NEVER locks `L1`; NEVER locks `L2` after `L3/L4` | Sweeps expired leaf attempts (`Tx A`), then locks frozen `>10d` revoked families strictly in `L2 -> L3 -> L4` order (`Tx B`) before deleting in child->parent order (`L2 -> L4 -> L3`) |

#### 3.2.2 Executable Algorithm for `L2` (`/login-attempts/cancel` Pre-Scan / Rollback / Retry)

```python
async def cancel_attempts_l2(conn, caller_browser_id: str | None, attempt_ids: list[str], verified_uid: UUID | None, caps: dict[str, str]):
    sorted_aids = sorted(set(attempt_ids))
    extra_bids: set[str] = {caller_browser_id} if caller_browser_id else set()
    for retry in range(3):  # initial try + max_retries=2
        # 1. Unlocked pre-scan BEFORE acquiring any row lock in this attempt
        prescan = await conn.fetch(
            "SELECT DISTINCT browser_id FROM login_attempt_states "
            "WHERE attempt_id = ANY($1::varchar[]) AND browser_id IS NOT NULL;",
            sorted_aids,
        )
        known_bids = sorted(extra_bids | {r["browser_id"] for r in prescan})

        async with conn.transaction():
            # 2. LEVEL 1: browser_coord_state (ASC PK order) — ONLY here, NEVER after L2!
            if known_bids:
                await conn.execute(
                    "INSERT INTO browser_coord_state (browser_id) SELECT unnest($1::varchar[]) ON CONFLICT DO NOTHING;",
                    known_bids,
                )
                await conn.fetch(
                    "SELECT browser_id FROM browser_coord_state "
                    "WHERE browser_id = ANY($1::varchar[]) ORDER BY browser_id ASC FOR UPDATE;",
                    known_bids,
                )

            # 3. LEVEL 2: insert tombstones idempotently, then lock in ASC PK order
            await conn.execute(
                "INSERT INTO login_attempt_states (attempt_id, browser_id, user_id, status, started_logout_seq, attempt_expires_at, expires_at) "
                "SELECT aid, $2, NULL, 'CANCELLED', 0, NOW(), NOW() + INTERVAL '3600 seconds' "
                "FROM unnest($1::varchar[]) AS aid ON CONFLICT (attempt_id) DO NOTHING;",
                sorted_aids, caller_browser_id,
            )
            rows = await conn.fetch(
                "SELECT attempt_id, family_id, browser_id, user_id, status, cancel_token_hash "
                "FROM login_attempt_states WHERE attempt_id = ANY($1::varchar[]) ORDER BY attempt_id ASC FOR UPDATE;",
                sorted_aids,
            )

            # 4. Dynamic race guard: did concurrent Phase A bind an unseen browser_id?
            unseen_bids = {r["browser_id"] for r in rows if r["browser_id"] and r["browser_id"] not in known_bids}
            if unseen_bids:
                extra_bids.update(known_bids)
                extra_bids.update(unseen_bids)
                # Exit async with conn.transaction() cleanly via controlled exception -> immediate ROLLBACK!
                raise _RetryCancelWithExpandedBids()

            # 5. LEVEL 3: browser_session_families (ASC PK order)
            fids = sorted({r["family_id"] for r in rows if r["family_id"] is not None})
            fam_map = {}
            if fids:
                fams = await conn.fetch(
                    "SELECT family_id, browser_id, user_id, attempt_id, status FROM browser_session_families "
                    "WHERE family_id = ANY($1::uuid[]) ORDER BY family_id ASC FOR UPDATE;",
                    fids,
                )
                fam_map = {f["family_id"]: f for f in fams}

            # 6. Verify 1:1 binding invariant & evaluate all-or-nothing ownership (ROLLBACK -> 403 if any denied)
            enforce_exact_binding_and_authorization(rows, fam_map, caller_browser_id, verified_uid, caps)

            # 7. LEVEL 4: refresh_tokens (ASC PK order) -> revoke & transition L2/L3 to PENDING_REVOKE/CANCELLED
            if fids:
                await conn.fetch(
                    "SELECT id FROM refresh_tokens WHERE family_id = ANY($1::uuid[]) ORDER BY id ASC FOR UPDATE;",
                    fids,
                )
                await conn.execute("UPDATE refresh_tokens SET status = 'REVOKED' WHERE family_id = ANY($1::uuid[]) AND status != 'REVOKED';", fids)
                await conn.execute("UPDATE browser_session_families SET status = 'PENDING_REVOKE', updated_at = NOW() WHERE family_id = ANY($1::uuid[]) AND status != 'REVOKED';", fids)
            return apply_attempt_state_updates_and_commit(conn, rows, fids)
    raise ConcurrentRetryExhausted409()
```

---

## 4. Complete State Machines & Server-Owned Linearization (`L1..L7`)

### 4.1 Server-Captured Epoch Fencing & Coordinated Attempt Registration (`R2-T52-V4-F01`, `R2-T52-REV1-H07`, `L1`)
1. **Mandatory Coordinated Attempt Registration (`POST /api/v1/auth/login-attempts/start`, anchored by `browser_coord_state.coordinated`)**:
   - **Rule (`REV1-H07`)**: `POST /api/v1/auth/coord/session` sets `browser_coord_state.coordinated = TRUE` monotonically for that browser. Whenever a caller executes cookie-mode `/password/login` or `/otp/verify` against a coordinated browser (`browser_coord_state.coordinated = TRUE`, which covers **all** browser UI tabs bootstrapped via `/coord/session` and all multi-tab coordinated clients), Phase A **STRICTLY REQUIRES** prior server-issued attempt registration via `POST /api/v1/auth/login-attempts/start` (`attempt_id` present in `login_attempt_states` with matching `browser_id`, `status = 'STARTED'`, `NOW() <= attempt_expires_at`). Phase A **NEVER** auto-creates `login_attempt_states` when `coordinated = TRUE`! Unregistered, missing, expired, or pre-cancelled `attempt_id` requests on a coordinated browser fail deterministically with **`HTTP 409 Conflict`** (`ATTEMPT_REGISTRATION_REQUIRED` / `LOGIN_ATTEMPT_EXPIRED` / `ATTEMPT_CANCELLED`) before any Argon2/OTP work runs.
   - `/coord/session` ensures `browser_coord_state` exists and executes `SET coordinated = TRUE` atomically inside Level 1 lock.
   - `/login-attempts/start` validates `Origin` (cookie mode), applies sliding rate limit, resolves/issues `hc_browser` (marking `coordinated = TRUE`), generates 256-bit `cancel_capability` (`cancel_token_hash = sha256(cancel_capability)`), and accepts optional `client_observed_logout_seq` (if supplied and `!= browser_coord_state.logout_seq` — whether stale `<` or forged `>` — immediately rejects `HTTP 409 Conflict`).
   - Inside `Level 1 -> Level 2`: inserts `login_attempt_states(attempt_id, browser_id, cancel_token_hash, started_logout_seq = browser_coord_state.logout_seq, status='STARTED', attempt_expires_at = NOW() + 30s, expires_at = NOW() + 3600s)` using `ON CONFLICT DO NOTHING RETURNING ...`. Duplicate/cancelled conflict returns `HTTP 409`.
   - Returns `{ attempt_id, started_logout_seq, cancel_capability, attempt_expires_at }` with `Cache-Control: no-store`.
   - Client (`auth_session.js`) keeps `(attempt_id, cancel_capability)` strictly in private ES module closure RAM (`attemptCapabilities` Map; zero WebStorage) and ALWAYS registers via `POST /api/v1/auth/login-attempts/start` BEFORE issuing `/password/login` or `/otp/verify`. Consequently, even if `/password/login` is delayed in transit **before hitting Phase A** while another tab calls `/logout`, Phase A reads the registered `started_logout_seq` and deterministically rejects `409`.
2. **Pre-Auth Guard (Phase A — Before slow Argon2id / OTP verification in `/password/login` & `/otp/verify`)**:
   - Validates `Origin` and config in cookie mode.
   - **Coordinated (`coordinated = TRUE`) vs Uncoordinated (`coordinated = FALSE`) Scope**:
     - When `hc_browser` cookie resolves to `browser_coord_state.coordinated = TRUE` (or `hc_browser` belongs to any coordinated browser session): Phase A **strictly requires** a valid pre-registered `attempt_id` row in `login_attempt_states` matching `browser_id` (`status == 'STARTED'`, `NOW() <= attempt_expires_at`), rejecting missing/unregistered/expired/cancelled rows with `HTTP 409` cleanly BEFORE Argon2/OTP work.
     - Only for uncoordinated direct API callers (`browser_id` absent or `browser_coord_state.coordinated = FALSE`, i.e., legacy non-UI single-client `httpx` callers that never called `/coord/session` or `/login-attempts/start`): `_ensure_browser_id` mints/reuses the uncoordinated `browser_id` (`coordinated = FALSE`), inserts `IN_FLIGHT` (`ON CONFLICT DO NOTHING`, respecting pre-existing `'CANCELLED'` tombstones -> `409`), and captures `started_logout_seq = browser_coord_state.logout_seq` in PG. (Note: any legacy `T36`/`T38`/`T49` single-client `httpx` test remains `100%` backward compatible without modifying prior tests.)
   - Inside `Level 1 (browser_coord_state FOR UPDATE) -> Level 2 (login_attempt_states FOR UPDATE)`:
     - Reject **`409 Conflict`** if row is `'CANCELLED'`, `'IN_FLIGHT'`, `'ACTIVE'`, `'PENDING_REVOKE'`, `'REVOKED'`, expired (`NOW() > attempt_expires_at` -> transition `'CANCELLED'`), or `row.browser_id != browser_id`.
     - **Client `started_server_logout_seq` hardening**: Never used to relax fencing! If `payload.started_server_logout_seq is not None` and `payload.started_server_logout_seq != row.started_logout_seq` (either `<` stale OR `>` forged!), OR `coord.logout_seq != row.started_logout_seq` -> mark `'CANCELLED'`, commit, return **`409 Conflict`** immediately (zero Argon2/OTP work executed!).
     - Transition row `STARTED -> IN_FLIGHT` and commit Phase A BEFORE slow password/OTP verification (holds zero DB locks during Argon2!).
3. **Auth Verification & Atomic Login Commit (Phase B — `L1`)**:
   - Execute credential verification (`AuthService`: Argon2id / OTP consume) without prematurely committing an active `hc_refresh` session outside the fence.
   - Lock strictly `Level 1 (browser_coord_state FOR UPDATE) -> Level 2 (login_attempt_states FOR UPDATE) -> Level 3 (browser_session_families WHERE browser_id = $1 AND status IN ('ACTIVE', 'PENDING_REVOKE') ORDER BY family_id FOR UPDATE) -> Level 4 (refresh_tokens of superseded families ORDER BY id FOR UPDATE)`:
     - Re-verify `user.status == 'ACTIVE'` (`403`/`401`).
     - Re-verify `attempt_row.status == 'IN_FLIGHT'` AND `NOW() <= attempt_row.attempt_expires_at` AND `browser_coord_state.logout_seq == attempt_row.started_logout_seq` AND `attempt_row.browser_id == browser_id`!
     - **If superseded** (`status != 'IN_FLIGHT'` or `logout_seq != attempt_row.started_logout_seq` or expired):
       - DO NOT insert any active session or advance `login_seq`!
       - If not already `'CANCELLED'`/`'PENDING_REVOKE'`/`'REVOKED'`, mark `login_attempt_states.status = 'CANCELLED'`. Commit & return **`409 Conflict`** (`clear_cookies=False`).
     - **If still valid (`logout_seq == attempt_row.started_logout_seq` and `status == 'IN_FLIGHT'`)**:
       - Supersede all prior `'ACTIVE'` families for same `browser_id` (`LATEST_FAMILY_WINS`): mark `browser_session_families.status = 'PENDING_REVOKE', revoke_reason = 'SUPERSEDED_BY_NEWER_LOGIN'` and `refresh_tokens.status = 'REVOKED'`.
       - Advance `global_seq = global_seq + 1`, `login_seq = new_seq`.
       - Insert new `browser_session_families(family_id, browser_id, user_id, attempt_id, created_seq=new_seq, status='ACTIVE')` (protected by `uq_browser_session_families_attempt_id` & `uq_bsf_family_attempt_browser_user` -> `UniqueViolationError` maps to `409`) and `refresh_tokens(..., status='ACTIVE')`.
       - Update `login_attempt_states SET family_id = $fid, user_id = $uid, status = 'ACTIVE', updated_at = NOW()` (database-checked by `fk_las_exact_family_binding`).
       - `COMMIT` PG!
       - Publish Redis revocations for superseded same-browser families & promote those superseded rows to `'REVOKED'`.
       - Sync PG `auth_coord` to Redis Lua `MAX`.

### 4.2 Atomic Cancellation Tombstone & Ownership Authorization (`R2-T52-V4-F02`, `L2`)
On `POST /api/v1/auth/login-attempts/cancel` (accepting `{ attempt_ids: list[str], cancel_capabilities: dict[str, str] | None }`):
1. Validate `Origin` (`403` on reject), sanitize non-empty `attempt_ids` (sorted distinct, max `16`).
2. Identify caller credentials cleanly:
   - Valid non-expired `Authorization: Bearer hc_at_v1.*` passing Redis non-revoked AND PG `verify_active_family` -> yields `verified_actor_user_id` AND enables verified quota (`auth` namespace: `60 req / 192 ids / 300s`).
   - OR valid `'ACTIVE'` `hc_refresh` cookie verified against Redis + PG -> yields `verified_actor_user_id` + verified quota.
   - Otherwise `verified_actor_user_id = None` (receives **unauthenticated quota (`anon` namespace: `20 req / 64 ids / 120s`)**, even if `hc_browser` cookie is present!).
3. Enforce **Namespace-Isolated Multi-Key Atomic Lua ZSET Sliding-Window Quota** (`L7`) BEFORE any PG or Redis cancellation write (`RedisError` -> `503`; exceeded -> `429 Retry-After: 60`).
4. Execute canonical lock-ordered PG transaction (using Section 3.2 `L2` pre-scan + rollback/retry on new dynamic `browser_id`, NEVER acquiring Level 1 after Level 2):
   - Step A (Pre-scan): Read `SELECT DISTINCT browser_id FROM login_attempt_states WHERE attempt_id = ANY($1) AND browser_id IS NOT NULL` union `{caller_browser_id}` -> sorted `known_bids`.
   - Step B (**Level 1**): Lock `browser_coord_state WHERE browser_id = ANY($known_bids) ORDER BY browser_id ASC FOR UPDATE` (if non-empty).
   - Step C (**Level 2**): For each `aid` in sorted `attempt_ids`, insert tombstone `ON CONFLICT (attempt_id) DO NOTHING`:
     ```sql
     INSERT INTO login_attempt_states (
         attempt_id, browser_id, user_id, status, started_logout_seq,
         attempt_expires_at, expires_at
     )
     VALUES ($1, $2, NULL, 'CANCELLED', 0, NOW(), NOW() + INTERVAL '3600 seconds')
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
   - Step D (**Dynamic Escalation Guard**): If any returned row has `browser_id IS NOT NULL AND browser_id NOT IN known_bids`, rollback immediately and retry from Step A with expanded `known_bids` (max `2` retries).
   - Step E (**Level 3** + Consistency Check): Collect all non-null `family_id` values (`sorted_fids`), lock `browser_session_families WHERE family_id = ANY($sorted_fids) ORDER BY family_id ASC FOR UPDATE`. Under lock, verify mandatory binding invariant: for every attempt with non-null `family_id`, confirm `fam.family_id == row.family_id AND fam.browser_id == row.browser_id AND fam.user_id == row.user_id AND (fam.attempt_id IS NULL OR fam.attempt_id == row.attempt_id)` (`500`/`409` fail-closed on corruption).
   - Step F: Evaluate authorization on **EVERY** requested row BEFORE mutating ANY existing row (all-or-nothing fail-closed `403`):

   **Exact Ownership & Capability Authorization Matrix (`check_attempt_cancel_authorized`)**:
   | Row State at Lock Time | Has `user_id`? | Has `cancel_token_hash`? | Caller Authorization Rule | Unauthorized Action |
   |------------------------|----------------|--------------------------|---------------------------|---------------------|
   | Newly inserted by this tx (`ON CONFLICT` inserted `'CANCELLED'`) | `NULL` | `NULL` | Permitted (pre-cancel tombstone creation; binds `browser_id = caller_browser_id` if present). | N/A |
   | Existing row (`STARTED` / `IN_FLIGHT`) | `NULL` | Non-null (`sha256(cap)`) | Caller MUST provide `hmac.compare_digest(sha256(cap_for_aid), row.cancel_token_hash)`. Anonymous `hc_browser` alone is **DENIED**! | `ROLLBACK` & return `HTTP 403` |
   | Existing row (`ACTIVE` / `PENDING_REVOKE` / `REVOKED`) | **Non-null (`uid_owner`)** | Null or non-null | `(verified_actor_user_id == uid_owner)` **OR** valid matching `cancel_capability`. **Anonymous same-browser request (`verified_actor_user_id IS NULL`) without valid `cancel_capability` is STRICTLY DENIED even if `hc_browser` matches!** Wrong authenticated `user_id` (`uid_b != uid_owner`) is **STRICTLY DENIED**! | `ROLLBACK` & return `HTTP 403` |
   | Existing `'CANCELLED'` pre-tombstone | `NULL` | `NULL` | Permitted ONLY if `(row.browser_id IS NULL OR row.browser_id == caller_browser_id OR verified_actor_user_id IS NOT NULL)` (idempotent `'CANCELLED'`). | `ROLLBACK` & return `HTTP 403` |

   - Step G: If ALL rows pass authorization:
     - Lock **Level 4** (`refresh_tokens WHERE family_id = ANY($sorted_fids) ORDER BY id ASC FOR UPDATE`) -> set `status = 'REVOKED'` where `status != 'REVOKED'`.
     - For bound rows (`family_id IS NOT NULL` or `'ACTIVE'`/`'IN_FLIGHT'`/`'STARTED'`), mark `browser_session_families.status = 'PENDING_REVOKE'`, `login_attempt_states.status = 'PENDING_REVOKE'`; tombstones with `family_id IS NULL` & no prior active session remain `'CANCELLED'`.
     - NEVER reads or writes `browser_coord_state.logout_seq`!
     - `COMMIT` PG!
   - Publish `hc:revoked_family:{fid}` and `hc:cancelled_login_attempt:{aid}` to Redis with TTL `>= REFRESH_COOKIE_MAX_AGE + 86400` (`8 days`) for revoked families, `120s` (anonymous `anon` caller) / `300s` (authenticated `auth` caller) for un-minted cancelled tombstones on Redis (matching each class's quota window and `CE-07b`), and `3600s` in PostgreSQL `login_attempt_states.expires_at` (authoritative PG durability) -> ONLY AFTER Redis confirms writes, promote `'PENDING_REVOKE' -> 'REVOKED'` in PG! If Redis fails, return `HTTP 503` (leaving `'PENDING_REVOKE'` durable in PG for `reconcile_pending_revocations()`).

### 4.3 Multi-Worker Failure Recovery (`R2-T52-V4-F06`, `R2-T52-REV1-H01`, `L3`)
- **`SessionService.reconcile_pending_revocations(batch_size: int = 50, max_batches: int = 20) -> int`**:
  1. Executes in two strictly leaf-scoped transaction phases (zero Level-1 acquisition, zero lock-order cycles):
     - **Phase A (`browser_session_families`, Level 3 -> optional Level 4)**:
       - `SELECT family_id FROM browser_session_families WHERE status = 'PENDING_REVOKE' ORDER BY updated_at ASC, family_id ASC FOR UPDATE SKIP LOCKED LIMIT $1`
       - Defensive invariant enforcement inside same lock (strictly increasing Level 3 -> Level 4): `SELECT id FROM refresh_tokens WHERE family_id = ANY($1) AND status != 'REVOKED' ORDER BY id ASC FOR UPDATE`, then `UPDATE refresh_tokens SET status = 'REVOKED' WHERE ...`.
       - **While holding those `FOR UPDATE SKIP LOCKED` row locks** (typically `< 2ms` local Redis pipeline), write `SET hc:revoked_family:{fid} reason EX 691200` (`8 days`, strictly `> 7-day refresh TTL` + `300s access TTL`) to Redis for EVERY locked row.
       - ONLY AFTER Redis confirms writes: `UPDATE browser_session_families SET status = 'REVOKED', updated_at = NOW() WHERE family_id = ANY($1)` and `COMMIT`.
     - **Phase B (`login_attempt_states`, Level 2 Leaf-Only — zero Level 1/3/4 locks)**:
       - `SELECT attempt_id FROM login_attempt_states WHERE status = 'PENDING_REVOKE' ORDER BY updated_at ASC, attempt_id ASC FOR UPDATE SKIP LOCKED LIMIT $1`
       - Write `SET hc:cancelled_login_attempt:{aid} 1 EX 3600` to Redis while holding `SKIP LOCKED` locks.
       - ONLY AFTER Redis confirms writes: `UPDATE login_attempt_states SET status = 'REVOKED', updated_at = NOW() WHERE attempt_id = ANY($1)` and `COMMIT`.
     - **Crash & error safety**:
       - If Redis raises `RedisError`, `ROLLBACK` without promoting (`status` stays `'PENDING_REVOKE'`; raises `RevocationStoreUnavailableError` if critical/propagated).
       - If a worker crashes BEFORE `COMMIT`, PostgreSQL automatically releases row locks, rows remain `'PENDING_REVOKE'`, Redis writes are idempotent, and another worker picks them up cleanly with zero lost work.
       - Concurrent Worker 2 executing `FOR UPDATE SKIP LOCKED` skips rows locked by Worker 1 and handles distinct batches concurrently — zero race or double promotion!
  2. **Invocation**:
     - FastAPI startup lifespan hook (best-effort bounded sweep if PG & Redis healthy).
     - Opportunistically invoked (`LIMIT 20`) inside coordination endpoints (`/coord/session`, `/logout`, `/login-attempts/cancel`, `/refresh`) when pending rows exist.
- **Fail-Closed Outage Matrix**:
  - Any `asyncpg.PostgresError` or pool error in `get_current_user`, `/refresh`, `/logout`, `/session/rebind-cookie`, `/login-attempts/start`, `/login-attempts/cancel`, `/coord/session` returns normalized `HTTP 503 Service Unavailable` with `Cache-Control: no-store`.
  - Any `redis.RedisError` returns `HTTP 503` without deleting or skipping PG `'PENDING_REVOKE'` state.

#### 4.3.1 Tombstone & Revocation Garbage Collection Contract (`REV1-M03`)
- **Explicit Distinction**:
  - `attempt_expires_at` (`NOW() + 30s`): Authentication validity cutoff. Enforced at runtime (`STARTED -> CANCELLED` / `409`); **never** triggers row deletion.
  - `expires_at` (`NOW() + 3600s`): Cancellation tombstone retention horizon (strictly exceeding max `300s` sliding-window & delayed cross-tab retries).
  - Revoked family retention: `browser_session_families` rows with `status = 'REVOKED'` are retained for at least `10 days` (`> 8-day Redis revocation TTL` + grace) before archival/purge.
- **`SessionService.purge_expired_auth_records(batch_size: int = 200) -> int`**:
  - Strictly NEVER deletes rows with `status IN ('STARTED', 'IN_FLIGHT', 'ACTIVE', 'PENDING_REVOKE')` or rows whose linked family is `'ACTIVE'` or `'PENDING_REVOKE'`.
  - Executes inside bounded `FOR UPDATE SKIP LOCKED` transactions in strict child-before-parent FK order:
    1. Expired `login_attempt_states`: delete rows where `status IN ('CANCELLED', 'REVOKED') AND expires_at < NOW()` AND `(family_id IS NULL OR NOT EXISTS (SELECT 1 FROM browser_session_families f WHERE f.family_id = login_attempt_states.family_id AND f.status IN ('ACTIVE', 'PENDING_REVOKE')))` — also cleaning expired `IN_PROGRESS` attempts only by first marking expired attempts `CANCELLED` after `attempt_expires_at` and deleting only after `expires_at < NOW()`.
    2. Archived/purged `browser_session_families`: delete only where `status = 'REVOKED' AND updated_at < NOW() - INTERVAL '10 days'` AFTER deleting any child `login_attempt_states` and `refresh_tokens` belonging solely to those frozen revoked families (`fk_las_exact_family_binding` satisfied safely without `ON DELETE CASCADE` risks on active/pending records).

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

### 4.6 Namespace-Isolated Multi-Key Atomic Lua ZSET Sliding-Window Rate Limiter (`R2-T52-V4-F08`, `R2-T52-REV1-H06`, `L7`)
All quota checks in `/login-attempts/cancel` execute as ONE multi-key Redis `EVAL` Lua script atomically before allocating PG rows or cancellation keys, with **strictly separated policy key namespaces** and **authoritative Redis server time (`redis.call('TIME')`)**:
- **Quota Classes & Isolated Key Namespaces**:
  - **Anonymous (`anon`) Class** (`window_ms = 120000`, limits: `20 req / 64 IDs` per IP, `120 req / 384 IDs` global):
    - `hc:rl:cancel:anon:ip:{client_ip}:req`
    - `hc:rl:cancel:anon:ip:{client_ip}:ids`
    - `hc:rl:cancel:anon:global:req`
    - `hc:rl:cancel:anon:global:ids`
  - **Authenticated (`auth`) Class** (`window_ms = 300000`, limits: `60 req / 192 IDs` per IP/actor, `360 req / 1152 IDs` global):
    - `hc:rl:cancel:auth:ip:{client_ip}:req`
    - `hc:rl:cancel:auth:ip:{client_ip}:ids`
    - `hc:rl:cancel:auth:global:req`
    - `hc:rl:cancel:auth:global:ids`
  Because `anon` and `auth` buckets use disjoint `:anon:` vs `:auth:` prefixes, an unauthenticated `120s` prune/PEXPIRE **can never** truncate or expire authenticated `300s` entries or corrupt authenticated capacity accounting (`REV1-H06`).
```lua
-- KEYS = [ip_req_key, ip_ids_key, global_req_key, global_ids_key]
-- ARGV = [window_ms, req_weight, ids_weight, ip_req_lim, ip_ids_lim, gl_req_lim, gl_ids_lim, nonce]
if redis.replicate_commands then redis.replicate_commands() end
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local window_ms = tonumber(ARGV[1])
local cutoff = now_ms - window_ms
local weights = { tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[2]), tonumber(ARGV[3]) }
local limits  = { tonumber(ARGV[4]), tonumber(ARGV[5]), tonumber(ARGV[6]), tonumber(ARGV[7]) }
local nonce   = ARGV[8]

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
- **Zero Worker Clock Skew**: Timestamps derive solely from Redis `TIME`, eliminating inter-worker wall-clock skew across Uvicorn/Gunicorn workers.
- **Zero `429` Bucket Pollution**: Rejected `429` requests NEVER insert ZSET members and NEVER burn sibling global or ID buckets.
- **Unique Members & Fail-Closed**: Concurrent sub-millisecond requests receive distinct server-generated 96-bit CSPRNG nonces (`secrets.token_hex(12)` -> `now_ms:nonce:idx:j` members); any `redis.RedisError` fails closed `HTTP 503` (zero PG mutations).

#### 4.6.1 Operational Scope & Deployment Assumptions (`MEDIUM-04`)
1. **Quota Key Scopes**:
   - **Anonymous (`anon`) Class**: Enforced strictly **per client IP (`hc:rl:cancel:anon:ip:{client_ip}:{req|ids}`) + global (`hc:rl:cancel:anon:global:{req|ids}`)** (`120s` window).
   - **Authenticated (`auth`) Class**: Granted **ONLY** after full cryptographic token verification + Redis non-revocation check + PostgreSQL `verify_active_family` check, and isolated inside **`hc:rl:cancel:auth:ip:{client_ip}:{req|ids}` + `hc:rl:cancel:auth:global:{req|ids}`** (`300s` window). Because unauthenticated callers cannot enter `:auth:` keys and cross-user cancellations remain blocked by PG ownership checks (`403`), `:auth:` buckets enforce bounded per-IP and global throughput isolation without sharing expiry/pruning state with `:anon:`.
2. **Unique Lua Request Nonces**: Every Python rate-limit invocation passes `nonce = secrets.token_hex(12)` into `ARGV[8]` so simultaneous requests within the same Redis millisecond NEVER collide on ZSET member strings.
3. **Standalone Redis Topology Assumption**: The multi-key atomic `EVAL` script (`KEYS[1..4]`) assumes HamiCard deploys a **standalone Redis** (or primary-replica Sentinel) topology where all keys reside in one keyspace. Should HamiCard later migrate to Redis Cluster, keys MUST be hash-tagged to a single common slot (or split cleanly per shard) to prevent `CROSSSLOT` errors.

---

## 5. Authoritative Security Invariants (`INV-01..INV-12`)

- **INV-01 (`C2-H01`)**: Calling `/login-attempts/cancel([B1])` NEVER advances `logout_seq` and NEVER revokes any family `F3` whose `attempt_id != B1`.
- **INV-02 (`C2-H02`)**: No active family tracking entry is ever removed from PG prior to PG `refresh_tokens.status = 'REVOKED'` AND Redis confirmation (`ACTIVE -> PENDING_REVOKE -> REVOKED`).
- **INV-03 (`C2-H02` / `F01`)**: Under concurrent login & logout where attempt started BEFORE logout (`started_logout_seq` captured server-side at start), `0` active sessions survive after both settle; pre-logout attempt CANNOT bypass logout even with forged `started_server_logout_seq`.
- **INV-04 (`C2-H03` / `F07`)**: Two fresh tabs initializing concurrently with delayed `/coord/session` converge to 1 `hc_browser`; missing `navigator.locks` fails closed instead of running unlocked cross-tab race; `bi=1` never bypasses validation.
- **INV-05 (`C2-H04`, `REV1-H01`)**: Client `hc_coord` mutations are 100% inside `withCoordLock`; PG lock acquisition obeys the cycle-free 4-level hierarchy (`browser_coord_state -> login_attempt_states -> browser_session_families -> refresh_tokens`) with `L2` pre-scan/retry and leaf-only `L3` reconciliation.
- **INV-06 (`C2-M01` / `F02`)**: Forged `Bearer` & anonymous `hc_browser` cookies receive unauthenticated `:anon:` quotas (`20 req / 64 ids / 120s` TTL). Anonymous same-browser `/login-attempts/cancel` WITHOUT valid `cancel_capability` returns `403` and cannot revoke any bound user's session; cross-user cancel returns `403`.
- **INV-07 (`C2-M02` / `F04` / `F05` / `REV1-H04`)**: Overwritten stale `F1` fails `/refresh` (`401`) and cannot downgrade; client auto-rebinds `HttpOnly hc_refresh` to `F3` via `/session/rebind-cookie` EVEN when `COOKIE_MAY_BE_STALE` broadcast is dropped!
- **INV-08 (`C2-M03`)**: When `/login-attempts/cancel` returns `429`, `503`, or `0`, UI does NOT report clean success and preserves `unresolvedCancelledAttemptIds` + `canRetryLogout` + error copy.
- **INV-09 (`F03`, `REV1-H05`, `REV1-M03`)**: Duplicate concurrent `attempt_id` produces at most 1 family and deterministically rejects duplicate with `409`; mutual 4-column FK + lock validation prevents mismatched `(attempt_id, family_id, browser_id, user_id)` binding; tombstone retention (`3600s`) strictly outlives `attempt_expires_at` (`30s`), and GC never purges `ACTIVE` or `PENDING_REVOKE` records.
- **INV-10 (`F06`, `REV1-M01`)**: Separate PG and Redis failures both fail closed (`503`); two overlapping `reconcile_pending_revocations()` workers (`FOR UPDATE SKIP LOCKED`) partition disjoint `PENDING_REVOKE` batches concurrently (`c1 >= 2 and c2 >= 2`) and reconcile 100% to Redis & `'REVOKED'`.
- **INV-11 (`F08`, `REV1-H06`)**: Namespace-isolated Lua ZSET (`:anon:` vs `:auth:`) uses Redis server `TIME`, enforces weighted ID limits (`64`/`192`), zero `429` bucket pollution, zero cross-class pruning/PEXPIRE interference, and fail-closed `503` on Redis outage.
- **INV-12 (`AC-14/AC-15/Multi-device`)**: Multi-device `Browser B` and unrelated `User B` remain `ACTIVE` when `Browser A` logs out; existing `T13..T49` invariants remain `100%` intact.

---

## 6. `RED_TEST_MATRIX` (Pre-Implementation Counterexamples in `tests/test_hc_t53_architecture_counterexamples.py`)

| Test ID | Mapping | Counterexample Scenario | Expected on `e7c2bb81` (RED) | Expected after `HC-T53` (GREEN) |
|---------|---------|-----------------------|-------------------------------|---------------------------------|
| `CE-01` | `C2-H01` | Delayed `[B1]` cancellation after logout & newer `F3` login | **FAILS**: revokes `F3`, `/refresh` `401` | `F3` stays `ACTIVE`, `/refresh` `200`, `B1` revoked |
| `CE-02` | `C2-H02/H04/REV1-H03` | Deterministic Phase A->Phase B PG fence barrier (`verify_password` hook) racing `/logout` + reverse post-logout registration (`started_logout_seq == 1`) | **FAILS**: `/login-attempts/start` missing (`404`) / inverted seq | Unconditional `200` start (`seq=0`); pre-logout delayed Phase B rejected `409` (`0` active); post-logout registered login commits `200` (`login_seq > logout_seq`) |
| `CE-03a` | `C2-H02/F06/HIGH-03` | Mid-transaction PG failure injected *after* actual DB `UPDATE` mutation executes inside `client1` logout tx while separate-device `client2` (`bid_2`) holds `F2` | **FAILS**: `500 != 503` / loses tracking | Verifies actual SQL mutation executed before crash; rollback restores `logout_seq=0`, `F1` & `F2` `'ACTIVE'`; healed retry revokes `F1` (`False`) while **`F2` stays `'ACTIVE'` (`True`)** |
| `CE-03b` | `C2-H02/F06/REV1-M01` | Redis outage AFTER PG commit + forced overlapping barrier across dual `reconcile_pending_revocations(batch_size=2)` workers (`SKIP LOCKED`) | **FAILS**: missing `PENDING_REVOKE` & reconciler | Returns `503`, PG `PENDING_REVOKE` durable; overlapping barrier forces `c1 >= 2 and c2 >= 2` disjoint batches; all 6 rows become `'REVOKED'` + Redis (`TTL > 7d`) |
| `CE-04` | `C2-H03/HIGH-02` | Concurrent initial tab navigation (`asyncio.gather`) + concurrent Login + deterministic **server-side `/coord/session` ASGI boundary barrier** holding unbootstrapped entry | **FAILS**: both unbootstrapped tabs enter `/coord/session` barrier (`len == 2`) | `hamicard_phase3_browser_init` holds Tab B client-side across server barrier (`1` unbootstrapped `/coord/session` server entry); logout leaves `0` active tokens |
| `CE-05` | `C2-H04` | Web Lock `withCoordLock` discipline audit on `hc_coord` mutations | **FAILS**: unlocked `hc_coord` write | 100% `hc_coord` writes strictly inside `navigator.locks('hamicard_phase3_coord')` |
| `CE-06` | `C2-M01` | 21 rapid `/login-attempts/cancel` requests with forged `Bearer` | **FAILS**: elevates to `60` req quota | Enforces `20` req unauth quota -> `429` by call 21 |
| `CE-07a` | `C2-M01/F02` | Cross-user AND anonymous same-browser (no capability) `/login-attempts/cancel` against bound `user_a` attempt | **FAILS**: anonymous same-browser or weak ownership leaks revocation | Both blocked `403`; `fam_a` stays `ACTIVE`; valid `cancel_capability` / owning `user_a` succeeds `200` |
| `CE-07b` | `C2-M01` | 21 rapid `/login-attempts/cancel` requests with anonymous `hc_browser` cookie | **FAILS**: elevates to `60` req / `300s` TTL | Enforces `20` req quota (`429` by call 21) & `:anon:` bucket TTL (`<= 125s`) |
| `CE-08` | `C2-M02/REV1-H04` | Delayed `200 Set-Cookie: F1` unconditionally verified overwriting jar + all-page `BroadcastChannel` suppression -> `401 /refresh` auto-rebinds `F3` | **FAILS**: `/refresh` fails `EXPIRED` without rebind recovery | Cookie jar verified holding `F1`; `/refresh` `401` triggers `/rebind-cookie` `200` -> `F3` restored & Tab A stays `AUTHENTICATED` |
| `CE-08b` | `F04/F05/REV1-H04` | Rebind adversarial matrix with normal TTL (`120s`): missing/wrong `hc_browser`, older `F1`, bad `Origin`, revoked family, & `/rebind-cookie` vs `/logout` race | **FAILS**: `404` (endpoint absent) | All invalid/stale/wrong-browser/post-logout rebind attempts rejected (`401`/`403`); `/logout` + `/rebind` never resurrects `REVOKED` family |
| `CE-08c` | `F04/F05/REV1-H04` | Isolated expired-bearer JWT (`exp = now - 60`) on `/session/rebind-cookie` | **FAILS**: `404` (endpoint absent) | Deterministically rejected `401` (`allow_expired=False`) |
| `CE-09` | `C2-M03` | `[429, 503]` cancellation failures in `revokeSupersededLoginOnServer()` | **FAILS**: drops failure silently | UI surfaces error + `REMOTE_REVOKE_FAILED` + preserves `canRetryLogout` & `unresolvedAttemptCount` |
| `CE-10` | `C2-H01/AC-15/M-01` | Multi-device Browser B & unrelated User B isolation (unconditional HTTP 200 registration, zero `404` masking) | **FAILS**: `/login-attempts/start` absent (`404 != 200`) | Both remain `ACTIVE` after Browser A logout/cancel |
| `CE-11a` | `F01/HIGH-04` | **Pre-logout** `/login-attempts/start` (`started_logout_seq=0`) -> `/logout` (`seq >= 1`) -> delayed `/password/login` with forged `started_server_logout_seq=999` | **FAILS**: `/login-attempts/start` `404` & `e7c2bb81` trusts forged `999` | Rejected `409` (`0` active tokens) |
| `CE-11b` | `F01/HIGH-04` | **Pre-logout** `/login-attempts/start` (`flow="OTP"`, `seq=0`) -> `/logout` (`seq >= 1`) -> delayed `/otp/verify` with forged `started_server_logout_seq=999` | **FAILS**: `/login-attempts/start` `404` & `e7c2bb81` trusts forged `999` | Rejected `409` (`0` active tokens) |
| `CE-11c` | `F03/REV1-H05/M04` | Concurrent duplicate `attempt_id` creates <= 1 family + PG negative test rejecting mismatched `(attempt_id, family_id)` binding | **FAILS**: mints 2 families / missing composite FK | At most `1` family created + loser `409`; PG rejects mismatched binding (`ForeignKeyViolationError`) |
| `CE-12a` | `F08/M-02` | Continuous Lua ZSET sliding-window recovery + `429` non-pollution verified across **all 4 `:anon:` buckets** (`ip:req`, `ip:ids`, `global:req`, `global:ids`) | **FAILS**: fixed-window `string` bucket instead of `zset` | ZSET sliding boundary prunes oldest entry & `429` leaves all `4` `:anon:` buckets at exact `20` |
| `CE-12b` | `REV1-H06` | Mixed `:anon:` (`120s`) & `:auth:` (`300s`) namespace isolation (`anon` never prunes/shortens `auth`) | **FAILS**: shared keys / non-ZSET bucket | Disjoint `:anon:` & `:auth:` keys preserve authenticated entries & `300s` TTL across anonymous bursts |
| `CE-12c` | `F08/M-02` | Weighted attempt-ID cap (`64` unauth IDs) + Redis `503` fail-closed verifying **zero PostgreSQL write mutations** during outage | **FAILS**: unweighted / shared fixed keys | Weighted IDs capped cleanly (`429` > `64`); Redis `503` performs `0` PG mutations |
| `CE-13a` | `F07` | Missing `navigator.locks` fails closed (`WEB_LOCKS_UNAVAILABLE`) | **FAILS**: runs unlocked & logs in (`200`) | Blocked locally (`authenticated=False`), zero network login sent |
| `CE-13b` | `F07/REV1-M02` | Forged `hc_coord.bi=1` cookie WITH normal `navigator.locks` still triggers `/coord/session` & cannot bypass validation | **FAILS**: trusts client `bi=1` / no server fence | Client calls `/coord/session`, gets signed `hc_browser`, forged `hc_coord` ignored |
| `CE-14` | `REV1-H07/H01` | Pre-Phase-A delayed `/password/login` after `/login-attempts/start`, unregistered `hc_browser` login rejected `409` (`0` Argon2 calls), & concurrent `L1/L2/L4/L6/L3` lock-order stress (`0` deadlocks) | **FAILS**: missing `/login-attempts/start` (`404`) / permits unregistered cookie login | Pre-Phase-A delayed & unregistered password attempts rejected `409` (`pwd_calls==0`); stress completes with `0` deadlocks |
| `CE-15` | `M-05` | Unregistered & pre-Phase-A delayed `/otp/verify` on coordinated browser rejected `409` strictly BEFORE `AuthService.authenticate_via_otp` / OTP consumption | **FAILS**: missing `/login-attempts/start` (`404`) / permits unregistered cookie OTP | Both rejected `409` with `otp_calls == 0`, OTP code preserved unconsumed in Redis, `0` active tokens |
| `CE-16` | `REV1-M03/M-03` | Adversarial GC (`purge_expired_auth_records`) preserving `STARTED`, `IN_FLIGHT`, `ACTIVE`, `PENDING_REVOKE`, unexpired tombstones, and `<10d` revoked families while safely child-before-parent purging truly expired records | **FAILS**: `purge_expired_auth_records` & coord tables absent | Live/pending/unexpired rows 100% preserved; truly expired tombstones & `>10d` revoked families purged cleanly without FK error |
