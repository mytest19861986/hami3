# Migration Plan — `002_policy_approval_and_settlement_min` (`HC-T14`)

- **Baseline Target**: `BL-HAMICARD-PRD-V1` (PostgreSQL 16 schema on `develop@9fdaa66`)
- **Migration Files**:
  - Forward: [`db/migrations/002_policy_approval_and_settlement_min.sql`](../db/migrations/002_policy_approval_and_settlement_min.sql)
  - Rollback: [`db/migrations/002_rollback.sql`](../db/migrations/002_rollback.sql)
- **Safety Scope**: Tested ONLY on isolated local PostgreSQL test databases (`hamicard_t14`, `hamicard_t14_mig`). **Never executed on production.**

---

## 1. Pre-Migration Checks

Run against target non-production DB before applying forward migration:

```sql
-- Verify PostgreSQL version and active tables
SELECT version();
SELECT count(*) AS open_keys_count
FROM system_settings
WHERE key LIKE 'OPEN\_%' ESCAPE '\';

-- Verify zero negative/zero settlement rows exist
SELECT count(*) AS invalid_amounts
FROM settlements
WHERE amount_toman <= 0;
```

## 2. Forward Migration Steps

Inside a single atomic `BEGIN ... COMMIT` transaction:
1. Add columns to `system_settings`:
   - `approval_status VARCHAR(20) NOT NULL DEFAULT 'PROPOSED'`
   - `approved_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT`
   - `approved_at TIMESTAMPTZ NULL`
   - Constraint `chk_system_settings_approval_status CHECK (approval_status IN ('PROPOSED', 'APPROVED', 'BLOCKED'))`
2. Set all seeded unapproved `OPEN_%` settings explicitly to `approval_status = 'PROPOSED'` unless already approved (`approved_at IS NOT NULL`).
3. Dynamically find and drop any existing inline `CHECK` constraint referencing `amount_toman` on `settlements` (removes hardcoded `amount_toman >= 100000`).
4. Add `CONSTRAINT chk_settlements_amount_positive CHECK (amount_toman > 0)`.

**Preserved Financial Invariants**:
- `wallets.withdrawable_balance_toman >= 0` (unchanged)
- `wallets.locked_balance_toman >= 0` (unchanged)
- `wallet_ledger_entries.amount_toman > 0` (unchanged)
- `idx_one_open_settlement_per_user` partial unique index (`WHERE status IN ('PENDING', 'PROCESSING', 'APPROVED') AND deleted_at IS NULL`) (unchanged)
- `orders_payments.amount_toman >= 0` and `commissions.amount_toman >= 0` (unchanged)

## 3. Post-Migration Verification Queries

```sql
-- 1. All 18 OPEN-* settings start as PROPOSED
SELECT approval_status, count(*)
FROM system_settings
WHERE key LIKE 'OPEN\_%' ESCAPE '\'
GROUP BY approval_status;

-- 2. Settlements constraint is chk_settlements_amount_positive CHECK (amount_toman > 0)
SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'settlements'::regclass
  AND contype = 'c';
```

## 4. Rollback Plan & Preconditions

Before running [`db/migrations/002_rollback.sql`](../db/migrations/002_rollback.sql):
- **Precondition**: Confirm no settlement rows have `amount_toman < 100000` (check `SELECT count(*) FROM settlements WHERE amount_toman < 100000;`), otherwise `ADD CONSTRAINT settlements_amount_toman_check CHECK (amount_toman >= 100000)` fails safely inside its transaction without partial schema mutation.
- Rollback drops `chk_settlements_amount_positive`, restores `CHECK (amount_toman >= 100000)`, drops `chk_system_settings_approval_status`, `approved_at`, `approved_by`, and `approval_status` inside a single `BEGIN ... COMMIT` transaction.

## 5. Dry-Run Verification Evidence

Verified on isolated database `hamicard_t14_mig` initialized from legacy `git show 9fdaa66:db/init.sql`:
- `002_policy_approval_and_settlement_min.sql` exited `0`, marked `18/18` rows `PROPOSED`, and replaced `settlements_amount_toman_check` with `chk_settlements_amount_positive CHECK (amount_toman > 0)`.
- `002_rollback.sql` exited `0` and restored `settlements_amount_toman_check CHECK (amount_toman >= 100000)` cleanly.
