-- ============================================================================
-- Rollback 002: Revert Policy Approval Metadata & Settlement Check Constraint
-- NOTE: Requires no open/historical settlements with amount_toman < 100000
-- ============================================================================

BEGIN;

ALTER TABLE settlements
    DROP CONSTRAINT IF EXISTS chk_settlements_amount_positive;

ALTER TABLE settlements
    ADD CONSTRAINT settlements_amount_toman_check CHECK (amount_toman >= 100000);

ALTER TABLE system_settings
    DROP CONSTRAINT IF EXISTS chk_system_settings_approval_status,
    DROP COLUMN IF EXISTS approved_at,
    DROP COLUMN IF EXISTS approved_by,
    DROP COLUMN IF EXISTS approval_status;

COMMIT;
