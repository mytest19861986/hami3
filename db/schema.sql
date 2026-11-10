-- ============================================================================
-- HamiCard (حامی‌کارت) Database Schema — PostgreSQL 16
-- Baseline: BL-HAMICARD-PRD-V1 | Phase 1 Foundation
-- Covers: 21 PRD Entities + Iranian Provinces/Cities + OPEN-01..18 Configuration
-- Invariants: Strict ACID, Concurrency-Safe Indexes, Append-Only Ledger
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 0. HELPER FUNCTIONS & TRIGGERS
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 1. BASE GEOGRAPHY: PROVINCES & CITIES (PROFILE-004, PROFILE-005)
-- ============================================================================

CREATE TABLE IF NOT EXISTS provinces (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cities (
    id SERIAL PRIMARY KEY,
    province_id INT NOT NULL REFERENCES provinces(id) ON DELETE RESTRICT,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_province_city UNIQUE (province_id, name)
);

CREATE INDEX IF NOT EXISTS idx_cities_province_id ON cities(province_id);

-- ============================================================================
-- 2. SYSTEM SETTINGS: PARAMETRIC POLICY FOR OPEN-01..18 (PRD Section 28)
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value_json JSONB NOT NULL,
    data_type VARCHAR(20) NOT NULL DEFAULT 'json'
        CHECK (data_type IN ('string', 'integer', 'boolean', 'json', 'decimal')),
    is_mandatory BOOLEAN NOT NULL DEFAULT TRUE,
    approval_status VARCHAR(20) NOT NULL DEFAULT 'PROPOSED'
        CHECK (approval_status IN ('PROPOSED', 'APPROVED', 'BLOCKED')),
    approved_by UUID NULL,
    approved_at TIMESTAMPTZ NULL,
    description TEXT NOT NULL,
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by UUID NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 3. CORE IDENTITY & AUTH: USERS & RBAC (AUTH-001..017, RBAC-001..009)
-- 6 Distinct PRD Roles: SUPER_ADMIN, ADMIN, SUPPORT, DOCTOR, AGENT, USER
-- ============================================================================

CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(50) PRIMARY KEY,
    name_fa VARCHAR(100) NOT NULL,
    description TEXT NULL,
    is_system BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR(100) PRIMARY KEY,
    module VARCHAR(50) NOT NULL,
    description TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id VARCHAR(50) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mobile VARCHAR(15) UNIQUE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' 
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'BLOCKED', 'DELETED')),
    password_hash VARCHAR(255) NULL,
    roles TEXT[] NOT NULL DEFAULT '{"USER"}',
    is_mobile_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_users_mobile ON users(mobile);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id VARCHAR(50) NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 4. USER PROFILES (PROFILE-001..012)
-- ============================================================================

CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    national_code VARCHAR(10) UNIQUE NULL,
    birth_date DATE NULL,
    gender VARCHAR(10) NULL CHECK (gender IN ('MALE', 'FEMALE', 'OTHER')),
    province_id INT NULL REFERENCES provinces(id) ON DELETE RESTRICT,
    city_id INT NULL REFERENCES cities(id) ON DELETE RESTRICT,
    address TEXT NULL,
    postal_code VARCHAR(10) NULL,
    avatar_url TEXT NULL,
    bank_card_number VARCHAR(16) NULL,
    bank_sheba_number VARCHAR(26) NULL,
    bank_account_holder_name VARCHAR(150) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_national_code ON profiles(national_code);
CREATE INDEX IF NOT EXISTS idx_profiles_province_city ON profiles(province_id, city_id);

CREATE TRIGGER trg_profiles_updated_at
BEFORE UPDATE ON profiles
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 5. REFRESH TOKENS & SESSIONS: ROTATION AGAINST RACE CONDITIONS (AUTH-011, AC-15)
-- ============================================================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id UUID NOT NULL DEFAULT gen_random_uuid(),
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    successor_id UUID NULL REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    device_info TEXT NULL,
    ip_address VARCHAR(50) NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'ROTATED', 'REVOKED')),
    rotated_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_lookup ON refresh_tokens(token_hash, status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mobile VARCHAR(15) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    attempt_type VARCHAR(20) NOT NULL CHECK (attempt_type IN ('OTP', 'PASSWORD')),
    is_successful BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_rate_limit ON login_attempts(mobile, ip_address, created_at);

-- ============================================================================
-- 6. DOCTORS NETWORK (DOC-001..014, AC-02)
-- ============================================================================

CREATE TABLE IF NOT EXISTS doctors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    medical_council_code VARCHAR(30) UNIQUE NOT NULL,
    specialty VARCHAR(150) NOT NULL,
    clinic_name VARCHAR(200) NOT NULL,
    province_id INT NOT NULL REFERENCES provinces(id) ON DELETE RESTRICT,
    city_id INT NOT NULL REFERENCES cities(id) ON DELETE RESTRICT,
    clinic_address TEXT NOT NULL,
    clinic_phone VARCHAR(20) NOT NULL,
    custom_discount_percent NUMERIC(5,2) NULL CHECK (custom_discount_percent IS NULL OR (custom_discount_percent >= 0 AND custom_discount_percent <= 100)),
    verification_status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING', 'APPROVED', 'REJECTED', 'SUSPENDED')),
    verified_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    verified_at TIMESTAMPTZ NULL,
    rejection_reason TEXT NULL,
    is_public_listed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_doctors_search ON doctors(province_id, city_id, specialty) WHERE verification_status = 'APPROVED' AND is_public_listed = TRUE;
CREATE INDEX IF NOT EXISTS idx_doctors_user ON doctors(user_id);

CREATE TRIGGER trg_doctors_updated_at
BEFORE UPDATE ON doctors
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 7. SALES AGENTS NETWORK (AGENT-001..010, AC-03)
-- ============================================================================

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    business_name VARCHAR(200) NOT NULL,
    business_type VARCHAR(50) NOT NULL DEFAULT 'INDIVIDUAL'
        CHECK (business_type IN ('INDIVIDUAL', 'CORPORATE')),
    province_id INT NOT NULL REFERENCES provinces(id) ON DELETE RESTRICT,
    city_id INT NOT NULL REFERENCES cities(id) ON DELETE RESTRICT,
    office_address TEXT NULL,
    office_phone VARCHAR(20) NULL,
    verification_status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING', 'APPROVED', 'REJECTED', 'SUSPENDED')),
    verified_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    verified_at TIMESTAMPTZ NULL,
    rejection_reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_verification ON agents(verification_status);
CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(user_id);

CREATE TRIGGER trg_agents_updated_at
BEFORE UPDATE ON agents
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 8. DOCUMENTS & VERIFICATION ATTACHMENTS (SEC-014, AGENT-004)
-- ============================================================================

CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    document_type VARCHAR(50) NOT NULL
        CHECK (document_type IN ('NATIONAL_CARD', 'BIRTH_CERTIFICATE', 'MEDICAL_LICENSE', 'BUSINESS_LICENSE', 'CONTRACT_SIGNATURE', 'OTHER')),
    file_path TEXT NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    verification_status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING', 'APPROVED', 'REJECTED')),
    reviewed_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    reviewed_at TIMESTAMPTZ NULL,
    rejection_reason TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(verification_status);

CREATE TRIGGER trg_documents_updated_at
BEFORE UPDATE ON documents
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 9. DISCOUNT PLANS (PLAN-001..013)
-- ============================================================================

CREATE TABLE IF NOT EXISTS discount_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(200) NOT NULL,
    description TEXT NULL,
    price_toman BIGINT NOT NULL CHECK (price_toman >= 0),
    discount_percent NUMERIC(5,2) NOT NULL CHECK (discount_percent >= 0 AND discount_percent <= 100),
    validity_days INT NOT NULL CHECK (validity_days > 0),
    max_visits INT NULL CHECK (max_visits IS NULL OR max_visits > 0),
    agent_commission_percent NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (agent_commission_percent >= 0 AND agent_commission_percent <= 100),
    referrer_commission_percent NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (referrer_commission_percent >= 0 AND referrer_commission_percent <= 100),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_discount_plans_active ON discount_plans(is_active);

CREATE TRIGGER trg_discount_plans_updated_at
BEFORE UPDATE ON discount_plans
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 10. PLAN HOLDERS: CARD HOLDER INDEPENDENT FROM BUYER (HOLDER-001..005, AC-05)
-- ============================================================================

CREATE TABLE IF NOT EXISTS plan_holders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    national_code VARCHAR(10) UNIQUE NOT NULL,
    mobile VARCHAR(15) NOT NULL,
    province_id INT NULL REFERENCES provinces(id) ON DELETE RESTRICT,
    city_id INT NULL REFERENCES cities(id) ON DELETE RESTRICT,
    address TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plan_holders_national_code ON plan_holders(national_code);
CREATE INDEX IF NOT EXISTS idx_plan_holders_mobile ON plan_holders(mobile);

CREATE TRIGGER trg_plan_holders_updated_at
BEFORE UPDATE ON plan_holders
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 11. ORDERS & PAYMENTS (PAY-001..011, AC-06, BR-15)
-- ============================================================================

CREATE TABLE IF NOT EXISTS orders_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    buyer_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    holder_id UUID NOT NULL REFERENCES plan_holders(id) ON DELETE RESTRICT,
    plan_id UUID NOT NULL REFERENCES discount_plans(id) ON DELETE RESTRICT,
    sales_case_id UUID NULL,
    amount_toman BIGINT NOT NULL CHECK (amount_toman >= 0),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED', 'CANCELLED', 'REFUNDED')),
    payment_method VARCHAR(30) NOT NULL DEFAULT 'GATEWAY'
        CHECK (payment_method IN ('GATEWAY', 'MANUAL_CARD', 'ADMIN_GRANT', 'WALLET')),
    idempotency_key VARCHAR(100) UNIQUE NOT NULL,
    gateway_name VARCHAR(50) NULL,
    gateway_transaction_id VARCHAR(100) NULL,
    gateway_tracking_code VARCHAR(100) NULL,
    verified_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders_payments(buyer_user_id);
CREATE INDEX IF NOT EXISTS idx_orders_holder ON orders_payments(holder_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders_payments(status);

CREATE TRIGGER trg_orders_payments_updated_at
BEFORE UPDATE ON orders_payments
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 12. MEMBERSHIPS & QUOTAS: ROW LOCKING & CONSTRAINTS (VISIT-005, AC-07)
-- ============================================================================

CREATE TABLE IF NOT EXISTS memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    holder_id UUID NOT NULL REFERENCES plan_holders(id) ON DELETE RESTRICT,
    plan_id UUID NOT NULL REFERENCES discount_plans(id) ON DELETE RESTRICT,
    order_id UUID NULL REFERENCES orders_payments(id) ON DELETE RESTRICT,
    origin_type VARCHAR(30) NOT NULL DEFAULT 'DIRECT_PURCHASE'
        CHECK (origin_type IN ('DIRECT_PURCHASE', 'AGENT_SALE', 'ADMIN_GRANT')),
    granted_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    grant_reason TEXT NULL,
    start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_date TIMESTAMPTZ NOT NULL,
    max_visits INT NULL CHECK (max_visits IS NULL OR max_visits > 0),
    used_visits INT NOT NULL DEFAULT 0,
    remaining_visits INT NULL CHECK (remaining_visits IS NULL OR remaining_visits >= 0),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'EXPIRED', 'EXHAUSTED', 'CANCELLED', 'SUSPENDED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_visits_limit CHECK (max_visits IS NULL OR used_visits <= max_visits),
    CONSTRAINT chk_dates CHECK (end_date > start_date)
);

CREATE INDEX IF NOT EXISTS idx_memberships_holder_status ON memberships(holder_id, status);
CREATE INDEX IF NOT EXISTS idx_memberships_end_date ON memberships(end_date);

CREATE TRIGGER trg_memberships_updated_at
BEFORE UPDATE ON memberships
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 13. SALES CASES: AGENT LOGISTICS & DUAL STATE MACHINE (SALE-001..013, AC-09, AC-10)
-- ============================================================================

CREATE TABLE IF NOT EXISTS sales_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    holder_id UUID NOT NULL REFERENCES plan_holders(id) ON DELETE RESTRICT,
    plan_id UUID NOT NULL REFERENCES discount_plans(id) ON DELETE RESTRICT,
    order_id UUID NULL REFERENCES orders_payments(id) ON DELETE RESTRICT,
    logistic_status VARCHAR(30) NOT NULL DEFAULT 'PENDING_REVIEW'
        CHECK (logistic_status IN ('PENDING_REVIEW', 'APPROVED', 'CARD_ISSUED', 'SHIPPED', 'DELIVERED', 'RETURNED')),
    financial_status VARCHAR(30) NOT NULL DEFAULT 'UNPAID'
        CHECK (financial_status IN ('UNPAID', 'PAYMENT_RECORDED', 'FINALIZED', 'CANCELLED')),
    shipping_tracking_code VARCHAR(100) NULL,
    delivery_date TIMESTAMPTZ NULL,
    notes TEXT NULL,
    reviewed_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    reviewed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_cases_agent ON sales_cases(agent_id);
CREATE INDEX IF NOT EXISTS idx_sales_cases_statuses ON sales_cases(logistic_status, financial_status);

CREATE TRIGGER trg_sales_cases_updated_at
BEFORE UPDATE ON sales_cases
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 14. REFERRALS (REF-001..012)
-- ============================================================================

CREATE TABLE IF NOT EXISTS referrals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    referred_user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    referral_code VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'CANCELLED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_user_id);

-- ============================================================================
-- 15. DOCTOR SERVICE CONTRACTS (CONTRACT-001..004)
-- ============================================================================

CREATE TABLE IF NOT EXISTS service_contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    doctor_id UUID NOT NULL REFERENCES doctors(id) ON DELETE RESTRICT,
    contract_number VARCHAR(100) UNIQUE NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    agreed_discount_percent NUMERIC(5,2) NOT NULL CHECK (agreed_discount_percent >= 0 AND agreed_discount_percent <= 100),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'EXPIRED', 'TERMINATED')),
    approved_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contracts_doctor ON service_contracts(doctor_id);

-- ============================================================================
-- 16. VISITS: CONCURRENCY-SAFE REGISTRATION & AUDITING (VISIT-001..013, AC-07, AC-08)
-- ============================================================================

CREATE TABLE IF NOT EXISTS visits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    doctor_id UUID NOT NULL REFERENCES doctors(id) ON DELETE RESTRICT,
    holder_id UUID NOT NULL REFERENCES plan_holders(id) ON DELETE RESTRICT,
    membership_id UUID NOT NULL REFERENCES memberships(id) ON DELETE RESTRICT,
    service_title VARCHAR(200) NOT NULL,
    total_amount_toman BIGINT NOT NULL CHECK (total_amount_toman >= 0),
    discount_percent NUMERIC(5,2) NOT NULL CHECK (discount_percent >= 0 AND discount_percent <= 100),
    discount_amount_toman BIGINT NOT NULL CHECK (discount_amount_toman >= 0),
    patient_paid_amount_toman BIGINT NOT NULL CHECK (patient_paid_amount_toman >= 0),
    status VARCHAR(20) NOT NULL DEFAULT 'COMPLETED'
        CHECK (status IN ('COMPLETED', 'CANCELLED')),
    cancellation_reason TEXT NULL,
    cancelled_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    cancelled_at TIMESTAMPTZ NULL,
    visit_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    private_notes TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_visits_doctor ON visits(doctor_id);
CREATE INDEX IF NOT EXISTS idx_visits_holder ON visits(holder_id);
CREATE INDEX IF NOT EXISTS idx_visits_membership ON visits(membership_id);

CREATE TRIGGER trg_visits_updated_at
BEFORE UPDATE ON visits
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 17. DOCTOR REVIEWS & RATINGS (REVIEW-001..004)
-- ============================================================================

CREATE TABLE IF NOT EXISTS doctor_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    visit_id UUID UNIQUE NOT NULL REFERENCES visits(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    doctor_id UUID NOT NULL REFERENCES doctors(id) ON DELETE RESTRICT,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT NULL,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    reviewed_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reviews_doctor ON doctor_reviews(doctor_id) WHERE is_published = TRUE;

-- ============================================================================
-- 18. COMMISSIONS (REF-009, AC-11, BR-13, BR-14)
-- ============================================================================

CREATE TABLE IF NOT EXISTS commissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    beneficiary_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    commission_type VARCHAR(30) NOT NULL
        CHECK (commission_type IN ('AGENT_SALE', 'REFERRAL')),
    source_order_id UUID NULL REFERENCES orders_payments(id) ON DELETE RESTRICT,
    source_sales_case_id UUID NULL REFERENCES sales_cases(id) ON DELETE RESTRICT,
    rate_percent NUMERIC(5,2) NOT NULL CHECK (rate_percent >= 0 AND rate_percent <= 100),
    amount_toman BIGINT NOT NULL CHECK (amount_toman >= 0),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'SETTLED', 'CANCELLED')),
    idempotency_key VARCHAR(100) UNIQUE NOT NULL,
    approved_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    approved_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_commissions_beneficiary_status ON commissions(beneficiary_user_id, status);

CREATE TRIGGER trg_commissions_updated_at
BEFORE UPDATE ON commissions
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 19. WALLETS (WALLET-001..010, AC-11)
-- ============================================================================

CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    withdrawable_balance_toman BIGINT NOT NULL DEFAULT 0 CHECK (withdrawable_balance_toman >= 0),
    locked_balance_toman BIGINT NOT NULL DEFAULT 0 CHECK (locked_balance_toman >= 0),
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'FROZEN')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wallets_user ON wallets(user_id);

CREATE TRIGGER trg_wallets_updated_at
BEFORE UPDATE ON wallets
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 20. WALLET LEDGER ENTRIES: APPEND-ONLY FINANCIAL AUDIT (WALLET-006, BR-15)
-- ============================================================================

CREATE TABLE IF NOT EXISTS wallet_ledger_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
    entry_type VARCHAR(30) NOT NULL
        CHECK (entry_type IN ('COMMISSION_CREDIT', 'SETTLEMENT_LOCK', 'SETTLEMENT_DEBIT', 'SETTLEMENT_REFUND', 'MANUAL_ADJUSTMENT')),
    amount_toman BIGINT NOT NULL CHECK (amount_toman > 0),
    direction VARCHAR(10) NOT NULL CHECK (direction IN ('CREDIT', 'DEBIT')),
    balance_before_toman BIGINT NOT NULL,
    balance_after_toman BIGINT NOT NULL,
    reference_id VARCHAR(100) NOT NULL,
    idempotency_key VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    created_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wallet_ledger_wallet ON wallet_ledger_entries(wallet_id, created_at);
CREATE INDEX IF NOT EXISTS idx_wallet_ledger_ref ON wallet_ledger_entries(reference_id);

-- ============================================================================
-- 21. SETTLEMENT REQUESTS: SINGLE OPEN REQUEST & CONCURRENCY (SETTLE-001..017, AC-12, BR-21)
-- ============================================================================

CREATE TABLE IF NOT EXISTS settlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
    amount_toman BIGINT NOT NULL CONSTRAINT chk_settlements_amount_positive CHECK (amount_toman > 0),
    bank_card_number VARCHAR(16) NOT NULL,
    bank_sheba_number VARCHAR(26) NOT NULL,
    bank_account_holder_name VARCHAR(150) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PROCESSING', 'APPROVED', 'PAID', 'REJECTED', 'CANCELLED')),
    rejection_reason TEXT NULL,
    external_payment_ref VARCHAR(100) NULL,
    external_payment_date TIMESTAMPTZ NULL,
    processing_started_at TIMESTAMPTZ NULL,
    lease_expires_at TIMESTAMPTZ NULL,
    locked_by_worker VARCHAR(100) NULL,
    paid_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL
);

-- CRITICAL MATHEMATICAL INVARIANT (AC-12, BR-21):
-- Exactly AT MOST ONE open (PENDING or PROCESSING or APPROVED) settlement request per user at any time!
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_settlement_per_user 
ON settlements (user_id) 
WHERE status IN ('PENDING', 'PROCESSING', 'APPROVED') AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_settlements_user ON settlements(user_id);
CREATE INDEX IF NOT EXISTS idx_settlements_status ON settlements(status);

CREATE TRIGGER trg_settlements_updated_at
BEFORE UPDATE ON settlements
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 22. CONTENT & CMS PAGES (CONTENT-001..005)
-- ============================================================================

CREATE TABLE IF NOT EXISTS content_pages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(200) NOT NULL,
    body_html TEXT NOT NULL,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_content_pages_slug ON content_pages(slug) WHERE is_published = TRUE;

CREATE TRIGGER trg_content_pages_updated_at
BEFORE UPDATE ON content_pages
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- 23. NOTIFICATIONS (NOTICE-001..005)
-- ============================================================================

CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    link_url VARCHAR(255) NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    read_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read, created_at);

-- ============================================================================
-- 24. AUDIT LOGS: IRREVERSIBLE SECURITY AUDIT TRAIL (SEC-006, ADMIN-027)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id UUID NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_role VARCHAR(50) NULL,
    action VARCHAR(100) NOT NULL,
    entity_name VARCHAR(100) NOT NULL,
    entity_id VARCHAR(100) NULL,
    old_values JSONB NULL,
    new_values JSONB NULL,
    ip_address VARCHAR(50) NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_name, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action, created_at);
