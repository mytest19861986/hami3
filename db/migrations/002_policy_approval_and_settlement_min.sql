-- ============================================================================
-- Migration 002: Policy Approval Lifecycle & Dynamic Settlement Minimum
-- Remediates F-06 / F-07 / T14-AC1..AC2
-- ============================================================================

BEGIN;

-- 1. Separate proposed policy parameters from approved runtime policy (T14-AC1)
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) NOT NULL DEFAULT 'PROPOSED',
    ADD COLUMN IF NOT EXISTS approved_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_system_settings_approval_status'
          AND conrelid = 'system_settings'::regclass
    ) THEN
        ALTER TABLE system_settings
            ADD CONSTRAINT chk_system_settings_approval_status
            CHECK (approval_status IN ('PROPOSED', 'APPROVED', 'BLOCKED'));
    END IF;
END $$;

-- Explicitly mark existing unapproved seeded OPEN-* policies as PROPOSED unless already approved
UPDATE system_settings
SET approval_status = 'PROPOSED',
    approved_by = NULL,
    approved_at = NULL
WHERE key LIKE 'OPEN\_%' ESCAPE '\'
  AND approved_at IS NULL;

-- 2. Replace hardcoded SQL 100000 settlement minimum with strict positive amount check (T14-AC2)
DO $$
DECLARE
    c_name TEXT;
BEGIN
    FOR c_name IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'settlements'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%amount_toman%'
    LOOP
        EXECUTE format('ALTER TABLE settlements DROP CONSTRAINT IF EXISTS %I;', c_name);
    END LOOP;
END $$;

ALTER TABLE settlements
    ADD CONSTRAINT chk_settlements_amount_positive CHECK (amount_toman > 0);

COMMIT;
