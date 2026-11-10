# گزارش شواهد فنی و راستی‌آزمایی فاز ۱ (اصلاحات) و فاز ۲ (هسته احراز هویت و RBAC)
**Mission ID:** `M-HAMICARD-ZERO-TO-PROD`  
**Baseline ID:** `BL-HAMICARD-PRD-V1` (PRD v1.0, 29 Sections, BR-01..30, AC-01..18)  
**تاریخ گزارش:** ۲۰۲۶-۱۱-۱۰  
**وضعیت:** تکمیل‌شده و راستی‌آزمایی‌شده با ۲۲ تست سبز (۱۰۰٪ قبولی)  
**شاخه و کامیت‌ها:**
- `develop`: `bdd7ba1` (Merged Remediation `3ce30c2`)
- `feature/auth-rbac-core`: `a338679`

---

## ۱. ماتریس اجرای فرامین ابلاغی فرماندهی ارشد

| شناسه تسک | فرمان ابلاغی | هدف عملیاتی | وضعیت | شواهد و فایل‌های مرجع |
| :--- | :--- | :--- | :---: | :--- |
| **HC-T08** | `HC-CMD-009` | انتشار و همگام‌سازی شاخه `develop` در گیت‌هاب | **COMPLETED** | شاخه `origin/develop` در مخزن ریموت بروزرسانی و تأیید شد. |
| **HC-T09** | `HC-CMD-010` | رفع یافته‌های بازبین‌های مستقل (Qwen و GLM) | **COMPLETED** | اصلاح AC-07 (سهمیه ویزیت اتمیک)، AC-12 (ایندکس جزئی و وضعیت PROCESSING)، نقش‌های ۶‌گانه، لاگ‌های ممیزی و Fail-Closed (`tests/test_phase1_remediation.py`: ۶/۶ پاس). |
| **HC-T10** | `HC-CMD-011` | پیاده‌سازی هسته احراز هویت و مجوزها (RBAC) | **COMPLETED** | ۶ نقش PRD، اعتبارسنجی تلفن همراه، چرخه OTP، رمزنگاری Argon2id و گیت تأیید پزشک/نماینده (`tests/test_auth_rbac.py`: ۶/۶ پاس). |
| **HC-T11** | `HC-CMD-012` | چرخه حیات نشست و چرخش رقابتی توکن (AC-15) | **COMPLETED** | جدول `refresh_tokens` در PostgreSQL با خانواده توکن، ابطال Replay و مهلت ۵ ثانیه‌ای (`tests/test_session_concurrency.py`: ۴/۴ پاس). |

---

## ۲. مستندات معماری و رفع یافته‌ها (Remediation Details)

### ۲.۱. ناوردای سهمیه استانی ویزیت (AC-07)
- **مشکل شناسایی‌شده توسط Qwen:** مدل اعتبارسنجی دو مرحله‌ای (Read then Write) در درخواست‌های هم‌زمان منجر به Over-consumption و مانده منفی می‌گردید.
- **راهکار پیاده‌سازی‌شده:** اجرای دستور کاملاً اتمیک در سطح PostgreSQL:
```sql
UPDATE memberships
SET used_visits = used_visits + 1,
    remaining_visits = remaining_visits - 1,
    updated_at = NOW()
WHERE id = $1 AND status = 'ACTIVE' AND remaining_visits >= 1
RETURNING id, remaining_visits, used_visits;
```
- **نتیجه تست استرس:** ۵۰ درخواست ناهمگام هم‌زمان روی سهمیه ۵ عددی اجرا گردید. دقیقاً ۵ درخواست موفق، ۴۵ درخواست رد و موجودی نهایی دقیقاً ۰ شد (Zero Negative Visits).

### ۲.۲. ناوردای تسویه حساب و وضعیت PROCESSING (AC-12)
- **مشکل شناسایی‌شده توسط GLM و Qwen:** در نظر نگرفتن وضعیت `PROCESSING` در ایندکس یکتایی، که امکان ایجاد درخواست دوم در حین پردازش تسویه را فراهم می‌کرد.
- **راهکار پیاده‌سازی‌شده:**
  1. اضافه شدن فیلدهای `processing_started_at`, `lease_expires_at`, `locked_by_worker`, `deleted_at` به جدول `settlements`.
  2. ایجاد Partial Unique Index:
  ```sql
  CREATE UNIQUE INDEX idx_settlements_single_active 
  ON settlements (doctor_id) 
  WHERE status IN ('PENDING', 'PROCESSING', 'APPROVED') AND deleted_at IS NULL;
  ```
  3. در لایه نرم‌افزار، بروز خطای `23505` صید شده و به خطای ساختاریافته دامنه (`409 Conflict`) نگاشت می‌شود.

### ۲.۳. ساختار کامل نقش‌ها و تفکیک بازاریاب (BR-01..30)
- تعریف و درج ۶ نقش رسمی در دیتابیس: `SUPER_ADMIN`, `ADMIN`, `SUPPORT`, `DOCTOR`, `AGENT`, `USER`.
- تعریف ۲۶ مجوز دانه‌بندی‌شده در جدول `permissions`.
- اعطای دسترسی‌های بازاریاب (`referral:generate_code`, `referral:view_stats`, `referral:view_commission`) به نقش‌های `USER` و `AGENT` بدون اعطای دسترسی به بخش‌های مالی یا ادمین.
- پیاده‌سازی گیت بررسی وضعیت پزشک/نماینده (`verification_status == 'APPROVED'`) که در وضعیت `PENDING` یا `REJECTED` دسترسی عملیاتی را مسدود می‌کند.

### ۲.۴. نشست پایدار و چرخش امن توکن (AC-14 و AC-15)
- دیتابیس PostgreSQL به عنوان مرجع واحد حقیقت (SSOT) نشست‌ها تعیین شد (`refresh_tokens`).
- استفاده از `family_id` برای رهگیری تبار هر توکن رفرش.
- تشخیص حملات بازپخش (Replay Attack): در صورت استفاده از توکنی که قبلاً چرخیده است، فوراً تمام توکن‌های آن خانواده باطل شده (`REVOKED`) و هشدار امنیتی ثبت می‌شود.
- در نظر گرفتن بازه مهلت (Grace Period) ۵ ثانیه‌ای جهت بازگرداندن توکن جانشین به درخواست‌های موازی شبکه ناشی از قطعی موقت کلاینت.
- تست هم‌زمانی با ۲۰ درخواست هم‌زمان روی ۱ توکن تأیید کرد که دقیقاً ۱ درخواست چرخش موفق انجام داده و ۱۹ درخواست دیگر توکن جانشین معتبر دریافت کردند.

---

## ۳. جدول نتایج آزمون‌های خودکار (Automated Test Matrix)

| مجموعه تست | مسیر فایل | تعداد تست | وضعیت | درصد موفقیت |
| :--- | :--- | :---: | :---: | :---: |
| پایگاه داده و اسکیمای فاز ۱ | `tests/test_phase1_database.py` | ۶ | **PASSED** | ۱۰۰٪ |
| اصلاحات فاز ۱ (AC-07, AC-12, Settings) | `tests/test_phase1_remediation.py` | ۶ | **PASSED** | ۱۰۰٪ |
| هسته احراز هویت و RBAC | `tests/test_auth_rbac.py` | ۶ | **PASSED** | ۱۰۰٪ |
| هم‌زمانی نشست و چرخش توکن (AC-15) | `tests/test_session_concurrency.py` | ۴ | **PASSED** | ۱۰۰٪ |
| **مجموع کل آزمون‌ها** | — | **۲۲** | **PASSED** | **۱۰۰٪** |

---

## ۴. بلوک گزارش رسمی به فرماندهی (commander.v2)

```json
{
  "schema": "commander.v2",
  "turn_id": "HC-STATUS-004",
  "agent": "Antigravity-IDE (Primary Executor & Coordinator)",
  "state_update": {
    "phase": "PHASE_1_REMEDIATED_AND_PHASE_2_CORE_IMPLEMENTED",
    "status": "AWAITING_COMMANDER_DECISION",
    "completed": [
      "HC-T08 (GitHub develop branch push verified)",
      "HC-T09 (Phase 1 database, AC-07, AC-12, audit logs, and settings remediation)",
      "HC-T10 (Phase 2 Auth, 6-role RBAC, Argon2id, and Fail-Closed verification)",
      "HC-T11 (AC-14 and AC-15 token rotation, replay detection, and concurrency tests)"
    ],
    "in_progress": [
      "HC-T12 (Second-Pass Review Coordination)"
    ],
    "blocked": [
      "Merge feature/auth-rbac-core into develop pending Commander approval",
      "Production deployment pending owner gate"
    ],
    "evidence_references": [
      "commit develop: bdd7ba1",
      "commit feature/auth-rbac-core: a338679",
      "tests/test_phase1_remediation.py: 6/6 passed",
      "tests/test_auth_rbac.py: 6/6 passed",
      "tests/test_session_concurrency.py: 4/4 passed"
    ],
    "next_best_action": "Evaluate remediation and Phase 2 implementation, authorize merge of feature/auth-rbac-core into develop, and dispatch Phase 3 (Surfaces & UI Integration) tasks."
  }
}
```

