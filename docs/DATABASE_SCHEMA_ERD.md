# مدل داده، نمودار روابط (ERD) و راهبرد هم‌زمانی مالی حامی‌کارت

**شناسه سند:** `DOC-DATA-ERD-V1`  
**شناسه مرجع محصول:** `BL-HAMICARD-PRD-V1`  
**شناسه تسک:** `T-01-ARCH-AND-OPEN-DECISIONS` (`HC-T03`)  
**پایگاه داده:** PostgreSQL 16 (مبتنی بر تراکنش‌های اسیدی، قفل سطری و ایندکس‌های یکتای جزئی)

---

## ۱. جدول مشخصات ۲۱ موجودیت اصلی PRD و جداول کمکی

| # | نام جدول | موجودیت در PRD (بخش ۲۴) | کلیدهای اصلی / یکتا | قیود کلیدی و ایندکس‌های هم‌زمانی |
|---|---|---|---|---|
| ۱ | `users` | حساب کاربری | `id` (PK), `mobile` (UQ) | `status IN ('ACTIVE','SUSPENDED','BLOCKED','DELETED')` |
| ۲ | `profiles` | پروفایل | `id` (PK), `user_id` (UQ), `national_code` (UQ) | کارت و شبا اختیاری؛ ایندکس `province_id, city_id` |
| ۳ | `doctors` | پزشک | `id` (PK), `user_id` (UQ), `medical_council_code` (UQ) | `is_public_listed` فقط برای `APPROVED`؛ ایندکس جست‌وجو |
| ۴ | `agents` | نماینده فروش | `id` (PK), `user_id` (UQ) | وضعیت تایید `PENDING/APPROVED/REJECTED/SUSPENDED` |
| ۵ | `documents` | مدارک و پیوست‌ها | `id` (PK) | دسترسی خصوصی؛ وضعیت بررسی هر مدرک |
| ۶ | `discount_plans` | طرح تخفیف | `id` (PK) | مبالغ `BIGINT` به تومان؛ درصدهای تخفیف و پورسانت |
| ۷ | `plan_holders` | دارنده کارت | `id` (PK), `national_code` (UQ) | تفکیک کامل دارنده از خریدار (`AC-05`) |
| ۸ | `memberships` | عضویت و اعتبار | `id` (PK) | `CONSTRAINT chk_visits_limit CHECK (used_visits <= max_visits)` |
| ۹ | `orders_payments` | خرید و پرداخت | `id` (PK), `idempotency_key` (UQ) | وضعیت‌های `PENDING/SUCCESS/FAILED/CANCELLED/REFUNDED` |
| ۱۰ | `sales_cases` | مشتری و فروش نمایندگی | `id` (PK) | ماشین وضعیت دوگانه لجستیکی و مالی (`SALE-004/005`) |
| ۱۱ | `referrals` | معرفی و ارجاع | `id` (PK), `referred_user_id` (UQ) | کد معرف و تاریخچه تعلق پورسانت |
| ۱۲ | `service_contracts` | قرارداد خدمت پزشک | `id` (PK), `contract_number` (UQ) | درصد تخفیف توافق‌شده و بازه اعتبار |
| ۱۳ | `visits` | ویزیت و مصرف خدمت | `id` (PK) | قفل سهمیه، ثبت مبالغ، تخفیف، و یادداشت کوتاه خصوصی |
| ۱۴ | `doctor_reviews` | نظر و امتیاز پزشک | `id` (PK), `visit_id` (UQ) | ثبت امتیاز ۱ تا ۵ فقط پس از ویزیت تکمیل‌شده |
| ۱۵ | `commissions` | پورسانت فروش و معرفی | `id` (PK), `idempotency_key` (UQ) | محاسبه بدون تکرار؛ ورود به مانده فقط در وضعیت `APPROVED` |
| ۱۶ | `wallets` | کیف پول | `id` (PK), `user_id` (UQ) | تفکیک `withdrawable_balance` از `locked_balance` |
| ۱۷ | `wallet_ledger_entries` | دفترکل مالی | `id` (PK), `idempotency_key` (UQ) | رکورد غیرقابل تغییر (Append-Only) با مانده قبل و بعد |
| ۱۸ | `settlements` | درخواست تسویه | `id` (PK) | **`idx_one_open_settlement_per_user` (حداکثر ۱ درخواست باز)** |
| ۱۹ | `content_pages` | صفحات عمومی و CMS | `id` (PK), `slug` (UQ) | مدیریت صفحات محتوایی و قوانین |
| ۲۰ | `notifications` | اعلان‌ها | `id` (PK) | اعلان‌های درون‌برنامه‌ای با وضعیت خوانده‌شدن |
| ۲۱ | `audit_logs` | تاریخچه ممیزی امنیتی | `id` (PK) | ثبت ناوردا از عامل، اقدام، مقادیر قدیم/جدید و IP |
| ۲۲ | `provinces` | استان‌های ایران | `id` (PK), `name` (UQ) | ۳۱ استان رسمی کشور |
| ۲۳ | `cities` | شهرهای ایران | `id` (PK), `(province_id, name)` (UQ) | شهرهای تابعه با وابستگی به استان |
| ۲۴ | `refresh_tokens` | توکن‌های نشست چرخشی | `id` (PK), `token_hash` (UQ) | چرخش یک‌بارمصرف با وضعیت‌های `ACTIVE/ROTATED/REVOKED` |
| ۲۵ | `system_settings` | تنظیمات سیستم (OPEN-01..18)| `key` (PK) | تنظیمات پارامتریک تجاری و امنیتی |

---

## ۲. قیدهای ریاضی و ناورداهای هم‌زمانی (Concurrency Invariants)

### ۱. جلوگیری از درخواست تسویه مضاعف (AC-12, SETTLE-005, BR-21)
- **قاعده:** هر کاربر در هر لحظه حداکثر می‌تواند **یک** درخواست تسویه در وضعیت باز (`PENDING` یا `APPROVED`) داشته باشد.
- **تضمین در سطح دیتابیس:**
```sql
CREATE UNIQUE INDEX idx_one_open_settlement_per_user 
ON settlements (user_id) 
WHERE status IN ('PENDING', 'APPROVED');
```
- **رفتار در رقابت (Race Condition):** اگر کاربر دو درخواست تسویه هم‌زمان ارسال کند، تراکنش دوم با خطای `unique_violation (23505)` بلافاصله توسط موتور پایگاه داده رد می‌شود و موجودی کیف پول هرگز دوبار بلوکه نمی‌گردد.

---

### ۲. جلوگیری از مصرف بیش از سهمیه در ویزیت هم‌زمان (AC-07, VISIT-005, BR-08)
- **قاعده:** اگر یک عضویت تنها ۱ سهمیه استفاده باقی‌مانده دارد و دو ویزیت هم‌زمان ارسال شود، دقیقاً یکی ثبت و دیگری با خطای اتمام سهمیه رد می‌شود.
- **تضمین در سطح دیتابیس:**
```sql
-- قید سخت‌گیرانه در جدول memberships:
CONSTRAINT chk_visits_limit CHECK (max_visits IS NULL OR used_visits <= max_visits);

-- ترتیب قفل تراکنش در Visit Engine:
BEGIN;
SELECT id, used_visits, max_visits, status 
FROM memberships 
WHERE id = $membership_id 
FOR UPDATE;

-- بررسی در حافظه: if (used_visits >= max_visits) ROLLBACK with QuotaExhaustedException;
UPDATE memberships 
SET used_visits = used_visits + 1,
    status = CASE WHEN max_visits IS NOT NULL AND used_visits + 1 >= max_visits THEN 'EXHAUSTED' ELSE status END
WHERE id = $membership_id;

INSERT INTO visits (...) VALUES (...);
COMMIT;
```

---

### ۳. چرخش اتمیک توکن تمدید نشست (AC-15, AUTH-011)
- **قاعده:** هر Refresh Token فقط یک‌بار قابل استفاده است. ارسال ۱۰ درخواست هم‌زمان تمدید نشست باید دقیقاً ۱ توکن جدید ایجاد کند و ۹ درخواست دیگر رد شوند.
- **تضمین اتمیک با SQL:**
```sql
UPDATE refresh_tokens 
SET status = 'ROTATED', rotated_at = NOW() 
WHERE token_hash = $token_hash AND status = 'ACTIVE' 
RETURNING id, user_id;
-- اگر تعداد رکوردهای بروزرسانی‌شده صفر باشد -> درخواست هم‌زمان تکراری یا دزدی توکن بوده و کل نشست‌ها باطل می‌شوند.
```

---

### ۴. اصل تطابق مانده کیف پول و دفترکل (AC-11, WALLET-006)
- **قاعده:** هر تغییری در مانده کیف پول (`withdrawable_balance` یا `locked_balance`) **باید** دقیقاً دارای یک ردیف متناظر در جدول `wallet_ledger_entries` با `idempotency_key` یکتا باشد:
$$\text{Withdrawable Balance} = \sum \text{Credits (Approved Commissions)} - \sum \text{Locked/Debited Settlements}$$

---

## ۳. سلسله‌مراتب قفل‌گذاری جهت پیشگیری از Deadlock (Lock Ordering Hierarchy)

برای جلوگیری از بن‌بست در پایگاه داده هنگام تراکنش‌های پیچیده، تمامی سرویس‌ها موظف به رعایت ترتیب قفل زیر بر اساس شناسه صعودی (ASC) هستند:

```text
۱. جدول wallets (قفل بر اساس user_id صعودی)
۲. جدول memberships (قفل بر اساس id صعودی)
۳. جدول orders_payments
۴. جدول commissions
۵. جدول settlements
```
هیچ تراکنشی مجاز نیست پس از قفل کردن `settlements` اقدام به قفل کردن `wallets` نماید.

---

## ۴. سناریوهای آزمون هم‌زمانی (Concurrency Test Plan)

1. **تست C-01 (مسابقه سهمیه آخر ویزیت — AC-07):**
   - ایجاد یک عضویت با `max_visits = 1` و `used_visits = 0`.
   - ارسال ۵ درخواست هم‌زمان ثبت ویزیت با `Promise.all` یا `ThreadPoolExecutor`.
   - **معیار پذیرش:** دقیقاً یک ویزیت ثبت شود (`HTTP 200/201`)، ۴ درخواست دیگر خطای `409/422` دریافت کنند و در دیتابیس `used_visits = 1` باشد.
2. **تست C-02 (مسابقه ثبت تسویه مضاعف — AC-12):**
   - ایجاد یک کیف پول با مانده ۵۰۰,۰۰۰ تومان.
   - ارسال هم‌زمان ۳ درخواست تسویه ۲۰۰,۰۰۰ تومانی برای همان کاربر.
   - **معیار پذیرش:** دقیقاً یک درخواست در وضعیت `PENDING` ثبت شود، مانده بلوکه‌شده دقیقا ۲۰۰,۰۰۰ تومان شود، و دو درخواست دیگر با خطای «درخواست باز موجود است» رد شوند.
3. **تست C-03 (مسابقه تمدید توکن نشست — AC-15):**
   - ایجاد یک Refresh Token فعال.
   - ارسال هم‌زمان ۱۰ درخواست تمدید با همان توکن.
   - **معیار پذیرش:** دقیقاً یک نشست جدید صادر شود و سایر درخواست‌ها رد شوند.
