# Policy Approval Matrix (`OPEN-01` .. `OPEN-18`)

- **Task**: `HC-T14` (`HC-CMD-015`) — Database Policy and Financial Integrity Remediation
- **Baseline**: `BL-HAMICARD-PRD-V1` (Section 28)
- **Remediation Targets**: `F-06` (`UNAPPROVED_POLICY_HARDCODED`), `T14-AC1`, `T14-AC2`
- **Owner Approval Status**: All 18 keys start as **`PROPOSED`** (`approval_status = 'PROPOSED'`, `approved_by = NULL`, `approved_at = NULL`). **No owner approval is claimed.**

---

## 1. Independent Policy State Model (`system_settings`)

Migration [`002_policy_approval_and_settlement_min.sql`](../db/migrations/002_policy_approval_and_settlement_min.sql) and [`src/core/policy.py`](../src/core/policy.py) enforce three explicit states per key:

| State | Runtime Behavior | `approved_by` / `approved_at` | Partition (`load_runtime_policy_partition`) |
|---|---|---|---|
| `PROPOSED` | Seeded/proposed value stored for inspection ONLY. Dependent financial/policy operations **fail closed (`PolicyNotApprovedError` / HTTP 403)**. | `NULL` / `NULL` | `partition["proposed"]` |
| `APPROVED` | Explicitly approved by owner/admin (`SUPER_ADMIN`). Active at runtime for governed domain/API execution. | Non-null audit timestamp (`NOW()`) | `partition["approved"]` |
| `BLOCKED` | Explicitly disabled by owner/admin. Dependent operations **fail closed (`PolicyNotApprovedError` / HTTP 403)**. | `NULL` / `NULL` | `partition["blocked"]` |

Every approval status change writes an immutable audit trail entry into `audit_logs` (`action = 'POLICY_APPROVAL_UPDATED'`).

---

## 2. Traceability Matrix (`OPEN-01` .. `OPEN-18`)

| # | DB Key (`system_settings.key`) | Seeded Proposed Value (`BL-HAMICARD-PRD-V1`) | Default Status | Independent Traceable? | Runtime Enforcement & Code Touchpoints |
|---|---|---|---|---|---|
| `OPEN-01` | `OPEN_01_REFERRER_VS_AGENT_BOUNDARY` | `{"allow_referrer_sales_cases": false, "referrer_requires_agent_approval": true}` | `PROPOSED` | Yes | Separated referrer (`referral:*`) vs approved agent (`agents.verification_status='APPROVED'`) in `src/sales/service.py` & `src/core/policy.py`. |
| `OPEN-02` | `OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE` | `{"precedence": "CUSTOM_FIRST", ...}` | `PROPOSED` | Yes | Loaded via `load_runtime_policy_partition`; isolated from approved financial policies. |
| `OPEN-03` | `OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER` | `{"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": true}` | `PROPOSED` | Yes | **Gated**: `SalesCaseService.finalize_financial_status` & `POST /api/v1/sales/cases/{case_id}/finalize` return `403` until `APPROVED`. |
| `OPEN-04` | `OPEN_04_FINANCIAL_PERMISSIONS_MATRIX` | `{"record_sale_payment": ["ADMIN", "SUPER_ADMIN"], "mark_settlement_paid": ["SUPER_ADMIN"], "edit_financial_settings": ["SUPER_ADMIN"]}` | `PROPOSED` | Yes | **Gated**: `WalletService.finalize_settlement_payout` fails closed (`PolicyNotApprovedError`) until `APPROVED`. |
| `OPEN-05` | `OPEN_05_COMBINED_COMMISSION_POLICY` | `{"allow_combined": false, "max_total_percent": 30.0}` | `PROPOSED` | Yes | **Gated**: `PaymentService.verify_and_fulfill_payment` & `POST /api/v1/payments/orders/{order_id}/verify` require `APPROVED` when applying referral commission (`403` if `PROPOSED`/`BLOCKED`). |
| `OPEN-06` | `OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN` | `{"min_amount_toman": 100000, "lock_on_request": true}` | `PROPOSED` | Yes | **Gated & Dynamic**: Hardcoded SQL `>= 100000` CHECK and Pydantic `ge=100000` **removed**. `WalletService.lock_funds_for_settlement` & `POST /api/v1/wallet/settle` fail with `403` unless `APPROVED`, then read `min_amount_toman` dynamically from DB. |
| `OPEN-07` | `OPEN_07_VISIT_CANCELLATION_REFUND_POLICY` | `{"restore_quota": true, "refund_requires_reason": true}` | `PROPOSED` | Yes | **Gated & Dynamic**: `VisitService.cancel_visit` & `POST /api/v1/visits/{visit_id}/cancel` require `APPROVED` (`403`) and apply `restore_quota` dynamically. |
| `OPEN-08` | `OPEN_08_MULTI_ACTIVE_PLANS_PER_HOLDER` | `{"allow_multiple_active_plans": false, "extension_adds_to_end_date": true}` | `PROPOSED` | Yes | Independently configurable/blockable via `set_policy_approval` & `load_runtime_policy_partition`. |
| `OPEN-09` | `OPEN_09_NATIONAL_CODE_PHONE_CONFLICT` | `{"national_code_unique": true, "phone_change_requires_admin": true}` | `PROPOSED` | Yes | Independently tracked in `system_settings` (`PROPOSED` by default). |
| `OPEN-10` | `OPEN_10_RBAC_ADMIN_SUPPORT_MATRIX` | `{"support_can_view_sheba": false, "support_can_approve_financials": false}` | `PROPOSED` | Yes | Independently tracked in `system_settings`; SUPPORT lacks `settlements:pay` & `settings:write`. |
| `OPEN-11` | `OPEN_11_EXTERNAL_ADAPTERS_CONFIG` | `{"sms_provider": "mock", "payment_gateway": "mock", "is_production_ready": false}` | `PROPOSED` | Yes | Explicitly flags `is_production_ready: false`; adapter fail-closed guards enforced cleanly. |
| `OPEN-12` | `OPEN_12_DATA_RETENTION_AND_SOFT_DELETE` | `{"soft_delete_only": true, "retain_financial_records_days": -1}` | `PROPOSED` | Yes | Independently tracked; ledger & settlement financial tables preserve `ON DELETE RESTRICT` & `deleted_at`. |
| `OPEN-13` | `OPEN_13_BACKUP_RETENTION_POLICY` | `{"daily_backups_kept": 7, "weekly_backups_kept": 4, "monthly_backups_kept": 6, "encrypt_with_age": true}` | `PROPOSED` | Yes | Independently tracked in `system_settings` (`PROPOSED` until ops sign-off). |
| `OPEN-14` | `OPEN_14_SLA_AND_RATE_LIMITS` | `{"max_concurrent_users": 500, "api_p95_ms": 200, "otp_rate_limit_per_hour": 5}` | `PROPOSED` | Yes | Independently tracked in `system_settings` (`PROPOSED`). |
| `OPEN-15` | `OPEN_15_THEME_AND_FONTS` | `{"font_family": "Vazirmatn", "primary_color_hex": "#0d9488", "secondary_color_hex": "#059669"}` | `PROPOSED` | Yes | Explicitly flagged `PROPOSED` (used only as proposed tokens in isolated Phase 3 UI shell pending owner approval). |
| `OPEN-16` | `OPEN_16_VISIT_MEDICAL_RECORD_LIMIT` | `{"store_diagnosis": false, "store_full_emr": false, "allow_private_notes": true}` | `PROPOSED` | Yes | **Gated & Dynamic**: `VisitService.record_visit` & `POST /api/v1/visits/record` require `APPROVED` and enforce `allow_private_notes` dynamically. |
| `OPEN-17` | `OPEN_17_ADMIN_GRANT_PLAN_POLICY` | `{"roles_allowed": ["ADMIN", "SUPER_ADMIN"], "mandatory_reason": true}` | `PROPOSED` | Yes | Independently tracked (`plans:admin_grant` RBAC permission separated). |
| `OPEN-18` | `OPEN_18_CURRENCY_AND_ROUNDING` | `{"currency_stored": "TOMAN", "currency_display": "TOMAN", "rounding_mode": "FLOOR"}` | `PROPOSED` | Yes | **Gated & Dynamic**: Governs `WalletService`, `PaymentService`, `SalesCaseService`, `VisitService`, `/wallet/settle`, `/payments/orders/*/verify`, `/sales/cases/*/finalize`, and `/visits/record`; rounding uses `round_toman(..., policy)` (default `FLOOR`). |
