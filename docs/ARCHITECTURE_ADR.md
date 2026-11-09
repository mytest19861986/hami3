# معماری کلان و تصمیم‌های کلیدی معماری حامی‌کارت (Architecture ADR & System Design)

**شناسه سند:** `DOC-ARCH-ADR-V1`  
**شناسه مرجع محصول:** `BL-HAMICARD-PRD-V1` (منطبق بر سند ۲۹ بخشی PRD نسخه ۱.۰)  
**شناسه تسک:** `T-01-ARCH-AND-OPEN-DECISIONS` (`HC-T02`)  
**محیط هدف:** Ubuntu 24.04 LTS | 4 vCPU | 8 GB RAM | Docker Compose  

---

## ۱. تصمیم‌های معماری (Architecture Decision Records — ADR)

### ADR-001: انتخاب الگوی Modular Monolith به‌جای Microservices
- **وضعیت:** تصویب‌شده (Approved)
- **زمینه و مسئله:** سخت‌افزار سرور پروداکشن کارفرما دارای ۸ گیگابایت رم و ۴ هسته پردازنده است. الزامات PRD شامل تراکنش‌های اتمیک بانکی، قفل‌های هم‌زمانی، ثبت ویزیت بدون رقابت، و کیف پول بدون دوبار برداشت است (`BR-15`, `BR-16`, `AC-07`, `AC-12`). اجرای معماری میکروسرویس روی سرور ۸ گیگ به دلیل سربار اجرای چندین JVM/Node runtime و شبکه داخلی، ریسک شدید OOM Kill و پیچیدگی‌های تراکنش‌های توزیع‌شده (2PC / Sagas) را به همراه دارد.
- **تصمیم:** بازنویسی حامی‌کارت به‌صورت یک **Modular Monolith** یکپارچه در قالب یک ریپازیتوری، با جداسازی سخت لایه‌های Domain، Service و Persistence.
- **پیامدها:**
  - تضمین ۱۰۰٪ اتمیک بودن تراکنش‌ها در سطح هسته PostgreSQL با صفر سربار شبکه بین‌سرویسی.
  - مصرف حافظه رم کل برنامه زیر ۲.۵ گیگابایت (باقی‌ماندن فضای کافی برای دیتابیس و کش).
  - سهولت در دیپلوی، بکاپ‌گیری سازگار و تست‌های هم‌زمانی محلی.

---

### ADR-002: انتخاب PostgreSQL 16 به‌عنوان تنها مرجع حقیقت داده و مالی
- **وضعیت:** تصویب‌شده (Approved)
- **زمینه و مسئله:** نیازمندی‌های `AC-07` (عدم مصرف دوبار سهمیه در درخواست هم‌زمان)، `AC-12` (حداکثر یک درخواست باز تسویه)، `AC-15` (عدم تکثیر توکن تمدید نشست) و `WALLET-006` (دفترکل غیرقابل تغییر).
- **تصمیم:** پایگاه داده **PostgreSQL 16** تنها منبع حقیقت داده‌های مالی، عضویت، هویت و تراکنش‌ها است:
  - استفاده از **Partial Unique Index** برای تضمین ریاضی `SETTLE-005` و `AC-12`:
    `CREATE UNIQUE INDEX idx_one_open_settlement_per_user ON settlements (user_id) WHERE status IN ('PENDING', 'APPROVED');`
  - استفاده از **Row-Level Locking (`SELECT ... FOR UPDATE`)** در سطح ردیف عضویت برای ثبت ویزیت (`VISIT-005`, `AC-07`) و بررسی سهمیه `chk_visits_limit`.
  - استفاده از جدول **Append-Only Financial Ledger (`wallet_ledger_entries`)** برای هرگونه تغییر مانده کیف پول با کلید یکتای `idempotency_key`.
  - عدم استفاده از `ON DELETE CASCADE` روی رکوردهای مالی، حساب‌ها، ویزیت‌ها و مدارک جهت حفظ تاریخچه قانونی و قابلیت ممیزی (`BR-29`).

---

### ADR-003: استفاده از Redis 7 برای کش، Rate-Limiting و چرخش توکن نشست
- **وضعیت:** تصویب‌شده (Approved)
- **زمینه و مسئله:** نیاز به محدودسازی درخواست کد تایید (`AUTH-003`, `OPEN-14`)، ابطال فوری نشست هنگام خروج (`AUTH-010`), و جلوگیری از Race Condition در تمدید توکن (`AC-15`).
- **تصمیم:** **Redis 7** با استراتژی `volatile-lru` و محدودیت حافظه ۳۸۴ مگابایت:
  - ذخیره کلیدهای توکن OTP با انقضای خودکار ۱۲۰ ثانیه.
  - پیاده‌سازی Token Bucket Rate Limiter با اسکریپت اتمیک Lua.
  - قفل توزیع‌شده (Redlock) برای عملیات فوق‌سریع در صورت نیاز، همراه با پایگاه داده اصلی.

---

### ADR-004: طراحی پارامتریک و Fail-Closed برای تصمیم‌های باز تجاری (OPEN-01 تا OPEN-18)
- **وضعیت:** تصویب‌شده (Approved)
- **زمینه و مسئله:** ۱۸ تصمیم تجاری در بخش ۲۸ PRD هنوز قطعی نشده‌اند اما نباید مانع پیشرفت ساختار نرم‌افزار شوند.
- **تصمیم:** تمامی ۱۸ تصمیم در جدول `system_settings` با ساختار کلید/JSON ذخیره شده و در لایه قوانین کسب‌وکار به‌صورت Fail-Closed (امن‌ترین حالت ممکن) عمل می‌کنند تا پس از تایید مدیر بدون نیاز به تغییر کد یا مایگریشن دیتابیس در لحظه قابل تغییر باشند.

---

## ۲. ماتریس ردیابی نیازمندی‌های حیاتی (P0 Traceability Matrix)

| کد سناریو PRD | عنوان سناریو | ماژول و لایه مسئول | مکانیزم تضمین و عدم خطا |
|---|---|---|---|
| **AC-01** | ثبت‌نام و ورود کاربر تازه | `AuthModule` / `UserModule` | تایید OTP در ردیس، ایجاد کاربر با نقش پیش‌فرض `USER`، ایجاد پروفایل و کیف پول اولیه در یک تراکنش |
| **AC-02** | ثبت‌نام پزشک و تایید | `DoctorModule` / `AdminModule` | وضعیت اولیه `PENDING`، محدود بودن دسترسی‌ها تا تایید مدیر، فیلتر دایرکتوری عمومی فقط روی `APPROVED` |
| **AC-03** | ثبت‌نام نماینده و مدارک | `AgentModule` / `DocumentModule` | آپلود امن مدارک در مسیر محافظت‌شده، صف بررسی توسط مدیر، عدم امکان ثبت فروش تا تایید |
| **AC-04** | ثبت هویت و اطلاعات بانکی | `ProfileModule` / `SettlementModule` | کارت و شبا در پروفایل اختیاری است؛ در زمان ثبت تسویه اعتبارسنجی Mod 97-10 شبا و Luhn کارت اجباری است |
| **AC-05** | خرید طرح برای دارنده متفاوت | `PlanModule` / `OrderModule` | تفکیک کامل `buyer_user_id` از `holder_id` در جدول `orders_payments` و `memberships` |
| **AC-06** | جلوگیری از تکرار یا جعل پرداخت | `PaymentModule` | استفاده از `idempotency_key` یکتا، تغییر وضعیت به `SUCCESS` فقط توسط وب‌هوک/کالبک امضاشده درگاه یا تایید ادمین |
| **AC-07** | ثبت ویزیت با سهمیه هم‌زمان | `VisitModule` / `MembershipModule` | تراکنش اتمیک با `SELECT ... FOR UPDATE` روی ردیف `memberships` و قفل پایگاه‌داده `used_visits <= max_visits` |
| **AC-08** | ثبت ویزیت با طرح نامعتبر | `VisitModule` | بررسی وضعیت طرح (`ACTIVE`)، تاریخ اعتبار (`end_date > NOW()`) و وضعیت پزشک (`APPROVED`) قبل از ثبت |
| **AC-09** | چرخه فروش و تحویل کارت | `SalesCaseModule` | ماشین وضعیت دوگانه لجستیکی (`PENDING_REVIEW` -> `APPROVED` -> `CARD_ISSUED` -> `SHIPPED` -> `DELIVERED`) و مالی |
| **AC-10** | مرجوعی فروش و لغو اثر مالی | `SalesCaseModule` / `CommissionModule` | لغو عضویت، ابطال پورسانت پرداخت‌نشده، کسر از مانده یا ثبت بدهی با علت |
| **AC-11** | پورسانت و کیف پول | `CommissionModule` / `WalletModule` | فقط پورسانت‌های `APPROVED` وارد `withdrawable_balance` می‌شوند؛ ثبت در دفترکل مالی `wallet_ledger_entries` |
| **AC-12** | رقابت در درخواست تسویه | `SettlementModule` / `WalletModule` | Partial Unique Index `idx_one_open_settlement_per_user` مانع ایجاد بیش از ۱ درخواست باز می‌شود؛ بلوکه کردن وجه |
| **AC-13** | کنترل تفکیک نقش ادمین/پشتیبان | `RbacGuard` / `AdminModule` | عدم دسترسی نقش `SUPPORT` به شبا و تنظیمات مالی؛ عملیات حساس مالی منحصراً برای `SUPER_ADMIN` |
| **AC-14** | ابطال نشست و خروج ایمن | `AuthModule` / `SessionModule` | ابطال توکن رفرش در دیتابیس/ردیس، ارسال هدرهای `Cache-Control: no-store, no-cache` |
| **AC-15** | رقابت در تمدید نشست (Rotation) | `AuthModule` / `RefreshTokenModule` | بروزرسانی اتمیک `UPDATE refresh_tokens SET status='ROTATED' WHERE token_hash=$1 AND status='ACTIVE'` |
| **AC-16** | بازیابی اطلاعات از بکاپ | `OpsModule` / `BackupScripts` | بکاپ رمزنگاری‌شده شبانه با `age`، ذخیره در Google Drive، آزمون بازیابی و اسکریپت ممیزی تطابق |
| **AC-17** | رابط کاربری فارسی و موبایل RTL | `FrontendUI` (Tailwind + Radix) | `dir="rtl"` بومی، تقویم جلالی، ارقام فارسی، طراحی واکنش‌گرا بدون اسکرول افقی |
| **AC-18** | گزارش‌های مالی قابل تطبیق | `ReportModule` / `AuditModule` | کوئری‌های قطعی روی `wallet_ledger_entries` و `orders_payments` بدون داده‌های ساختگی |

---

## ۳. نقشه ماژول‌ها و مسیرهای ارتباطی (Module & Boundary Architecture)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION & API LAYER                        │
│   Next.js App Router (RTL Pages + REST / Server Actions)                │
│   - Public Portal: /, /doctors, /plans, /about, /terms, /privacy       │
│   - Auth: /login, /verify-otp, /set-password                           │
│   - Dashboards: /panel/user, /panel/doctor, /panel/agent, /panel/admin │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ RBAC Guard / Auth Middleware
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        APPLICATION & DOMAIN SERVICES                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │   AuthService   │  │  ProfileService │  │  DoctorService  │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│  ┌────────┴────────┐  ┌────────┴────────┐  ┌────────┴────────┐         │
│  │   AgentService  │  │   PlanService   │  │   VisitEngine   │         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│  ┌────────┴────────┐  ┌────────┴────────┐  ┌────────┴────────┐         │
│  │ CommissionEngine│  │  WalletLedger   │  │SettlementService│         │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Repositories & ACID Transactions
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       PERSISTENCE & INFRASTRUCTURE                     │
│  - PostgreSQL 16: 21 Entities + Strict ACID + Partial Indexes          │
│  - Redis 7: Rate-Limiting + Ephemeral OTP + Blacklist Tokens           │
│  - External Adapters (Mock / Real): SMS Gateway + Payment Gateway      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ۴. طراحی امنیت و حریم خصوصی (Security & Privacy Design)

1. **مدیریت نشست و توکن چرخشی (Single-Use Refresh Tokens):**
   - عمر Access Token: ۱۵ دقیقه.
   - عمر Refresh Token: ۷ روز با چرخش یک‌بارمصرف.
   - هر درخواست تمدید، توکن قبلی را به `ROTATED` تبدیل کرده و توکن جدید صادر می‌کند. در صورت استفاده مجدد از توکن قبلی (نشان‌دهنده دزدی توکن)، تمام نشست‌های آن کاربر فوراً باطل می‌شوند (`REVOKED`).
2. **محافظت از اطلاعات بانکی و PII:**
   - شماره کارت و شبا در دیتابیس با کلید متقارن AES-256-GCM رمزنگاری می‌شوند.
   - در نمایش‌های عمومی و گزارش‌های عادی، شماره کارت به‌صورت `۶۰۳۷-****-****-۱۲۳۴` ماسک می‌شود (`PROFILE-009`, `ADMIN-022`).
3. **کنترل دسترسی افقی و عمودی (Strict RBAC & IDOR Prevention):**
   - هر کوئری در سرویس‌های داده‌ای با شرط صریح `WHERE user_id = :currentUser` (یا بررسی رابطه مالکیت دارنده/نماینده) فیلتر می‌شود تا امکان دسترسی به پرونده دیگران با تغییر ID در URL ناممکن باشد (`RBAC-006`, `SEC-009`).
4. **دفترکل ممیزی تغییرناپذیر (Immutable Audit Log):**
   - هرگونه عملیات حساس (تغییر نقش، تایید مدارک، ثبت پرداخت، تغییر وضعیت تسویه، لغو ویزیت) با ذخیره `actor_user_id`, `actor_role`, `action`, `old_values`, `new_values`, `ip_address` در جدول `audit_logs` ثبت می‌شود (`SEC-006`, `ADMIN-027`).
