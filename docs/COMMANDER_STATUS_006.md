# گزارش جامع عملیاتی و پیشرفت فاز ۳ به فرمانده ارشد (HC-STATUS-006)

**To:** Master Commander (ChatGPT)  
**From:** Antigravity IDE Primary Executor & Coordinator  
**Mission ID:** `M-HAMICARD-ZERO-TO-PROD`  
**Baseline:** `BL-HAMICARD-PRD-V1` (PRD v1.0, 29 Sections, BR-01..30, AC-01..18, OPEN-01..18)  
**Git Repository:** `https://github.com/mytest19861986/hami3`  
**Current HEAD Commits:**
- `develop`: `bdd7ba1` (Merged Remediation Phase 1)
- `feature/auth-rbac-core`: `49279d9` (Phase 2 Auth & 6-Role RBAC Core)
- `feature/phase3-profiles-and-validators`: `4f10e32` (Phase 3 Services, Validators, FastAPI HTTP REST Layer)

---

## ۱. خلاصه دستاوردهای کلیدی و وضعیت کلی سامانه

سامانه حامی‌کارت با موفقیت کامل تمامی الزامات فاز ۱، فاز ۲ و کلیه دامنه‌ها و سرویس‌های کسب‌وکاری و لایه API فاز ۳ را طبق PRD v1.0 پیاده‌سازی نموده است:

### نتایج آزمون‌های خودکار مستر (Master Test Runner):
- **۱۴ سوئیت آزمون جامع خودکار (۱۴ از ۱۴ پاس - ۱۰۰٪ سبز)**
- **۷۳ تست یکپارچه و اتمیک با زمان اجرای ۱۵ ثانیه و صفر خطا (Zero Failures)**

| شماره سوئیت | حوزه تست و ارزیابی | فایل تست | نتیجه |
| :---: | :--- | :--- | :---: |
| ۱ | بنیاد دیتابیس PostgreSQL و جداول ۲۱ گانه | `tests/test_phase1_database.py` | **۶/۶ پاس (۱۰۰٪)** |
| ۲ | راستی‌آزمایی ناورداهای AC-07 و AC-12 | `tests/test_phase1_remediation.py` | **۶/۶ پاس (۱۰۰٪)** |
| ۳ | احراز هویت، ۶ نقش PRD، رمزنگاری Argon2id | `tests/test_auth_rbac.py` | **۶/۶ پاس (۱۰۰٪)** |
| ۴ | چرخش رقابتی توکن، تشخیص Replay و مهلت ۵ ثانیه (AC-15) | `tests/test_session_concurrency.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۵ | اعتبارسنج‌های ریاضی ایرانی (کد ملی، کارت شتاب، شبا، موبایل) | `tests/test_validators.py` | **۸/۸ پاس (۱۰۰٪)** |
| ۶ | سرویس پروفایل، جغرافیای ۳۱ استان و ماسک PII | `tests/test_profiles.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۷ | شبکه پزشکان و کاتالوگ طرح‌های تخفیف | `tests/test_doctors_and_plans.py` | **۵/۵ پاس (۱۰۰٪)** |
| ۸ | صفحات محتوایی CMS و قوانین عمومی | `tests/test_content.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۹ | ثبت ویزیت، کسر اتمیک سهمیه و لغو ویزیت (AC-07, AC-08) | `tests/test_visits.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۱۰ | کیف پول، دفترکل تغییرناپذیر و تسویه حساب (AC-11, AC-12) | `tests/test_wallets.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۱۱ | ماشین وضعیت دوگانه لجستیک و مالی پرونده‌های فروش (AC-09, AC-10) | `tests/test_sales_cases.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۱۲ | درگاه پرداخت، فعال‌سازی کارت و پورسانت معرف (AC-06) | `tests/test_payments_and_referrals.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۱۳ | نظرات و امتیازات بیماران و اعلان‌های درون‌برنامه‌ای | `tests/test_reviews_and_notifications.py` | **۴/۴ پاس (۱۰۰٪)** |
| ۱۴ | لایه کامل اندپوینت‌های REST HTTP فریم‌ورک FastAPI | `tests/test_api_endpoints.py` | **۱۰/۱۰ پاس (۱۰۰٪)** |

---

## ۲. جزئیات معماری و سرویس‌های پیاده‌سازی‌شده فاز ۳

۱. **اعتبارسنجی‌های بومی و امنیت داده‌های هویتی (`src/common/validators.py` و `src/common/pii.py`):**
   - الگوریتم دقیق کد ملی بر مبنای تقسیم بر ۱۱ با کنترل کدهای نامعتبر تکراری (مانند `1111111111`).
   - الگوریتم Luhn Mod 10 برای کارت‌های بانکی شتاب.
   - الگوریتم ISO 7064 Mod 97-10 برای شماره شبای بانکی با پیشوند IR.
   - ماسک‌گذاری داینامیک داده‌های حساس (PII) بر اساس سطح اختیارات RBAC کاربر.

۲. **پروفایل و مرجع جغرافیایی کشور (`src/profiles/service.py`):**
   - مدل‌سازی کامل ۳۱ استان و شهرهای منتخب کشور با کنترل رابطه والد-فرزند.
   - نگهداری اطلاعات هویتی و بانکی با قفل یکتایی کد ملی و عدم امکان ثبت تکراری.

۳. **شبکه پزشکان و مراکز درمانی طرف قرارداد (`src/doctors/service.py`):**
   - چرخه حیات تایید پزشک (`PENDING` -> `APPROVED`/`REJECTED`/`SUSPENDED`).
   - جستجوی عمومی پزشکان با اصل Fail-Closed (صرفاً پزشکان تاییدشده در جستجو نمایش داده می‌شوند).
   - ثبت و بایگانی قراردادهای رسمی درمانی و درصد تخفیف اختصاصی.

۴. **طرح‌های تخفیف و فروشگاه (`src/plans/service.py`):**
   - اعتبارسنجی حدود قیمت، درصد تخفیف، روزهای اعتبار و پورسانت نماینده و معرف.
   - فعال/غیرفعال‌سازی با ثبت لاگ ممیزی و ارائه کاتالوگ عمومی به خریداران.

۵. **ثبت ویزیت درمانی و ناوردای سهمیه (`src/visits/service.py` - AC-07):**
   - کسر اتمیک سهمیه در سطح PostgreSQL بدون امکان پدیده منفی شدن سهمیه (Zero Negative Visits).
   - انتقال خودکار وضعیت عضویت به `EXHAUSTED` در صورت پایان سهمیه.
   - قابلیت لغو ویزیت و بازگرداندن اتمیک سهمیه به کارت بیمار.

۶. **کیف پول و دفترکل مالی تغییرناپذیر (`src/wallets/service.py` - AC-11, AC-12):**
   - مانع اتمیک از منفی شدن موجودی کیف پول.
   - ثبت تمامی تراکنش‌ها در `wallet_ledger_entries`.
   - مسدودسازی وجوه هنگام ثبت درخواست تسویه.
   - تضمین قطعی ناوردای AC-12: حداکثر ۱ درخواست تسویه باز در کل سیستم به ازای هر کاربر.

۷. **پرونده‌های فروش نمایندگی با ماشین وضعیت دوگانه (`src/sales/service.py` - AC-09, AC-10):**
   - استقلال بعد لجستیک (`PENDING_REVIEW` -> `APPROVED` -> `CARD_ISSUED` -> `SHIPPED` -> `DELIVERED`).
   - الزام به درج کد رهگیری پستی ۲۴ رقمی برای تغییر وضعیت به `SHIPPED` (AC-09).
   - قطعی‌سازی وضعیت مالی (`FINALIZED`) و واریز خودکار پورسانت به کیف پول نماینده (AC-10).

۸. **پرداخت‌ها، عضویت و کمیسیون معرف (`src/payments/service.py` و `src/referrals/service.py`):**
   - ثبت سفارش با کلید یکتایی (Idempotency Key) جهت جلوگیری از پرداخت تکراری.
   - تایید پرداخت و فعال‌سازی فوری کارت عضویت حامی‌کارت با بازه تاریخی معتبر.
   - محاسبه و واریز پورسانت معرف بر مبنای کد معرف (`HAMI-XXXXXX`).

۹. **مدیریت محتوا و CMS عمومی (`src/content/service.py`):**
   - صفحات قوانین، حریم خصوصی، درباره ما، پرسش‌های متداول و صفحه اصلی.

۱۰. **نظرات درمانی و اعلان‌های سامانه (`src/reviews/service.py` و `src/notifications/service.py`):**
    - امکان ثبت نظر صرفاً برای ویزیت‌های تکمیل‌شده (`COMPLETED`) با امتیاز ۱ تا ۵.
    - تایید و انتشار نظرات توسط ادمین و محاسبه میانگین امتیاز پزشک.
    - اعلان‌های زنده درون‌برنامه‌ای با بج تعداد خوانده‌نشده.

۱۱. **لایه کامل API رست با ۱۱ روتر تحت FastAPI (`src/api/`):**
    - اتصال کامل دیتابیس پول asyncpg و ردیس با مدیریت چرخه حیات lifespan.
    - لایه احراز هویت با Bearer Token و کنترل دسترسی ریزدانه با دکوراتور `require_permission`.

۱۲. **نوار شناور نصب PWA در موبایل (Manager Directive):**
    - فایل پروتوتایپ کامل HTML/CSS/JS در `src/frontend/pwa_install_bar.html`.
    - پشتیبانی از نصب یک کلیکی WebAPK در اندروید (با رویداد `beforeinstallprompt`).
    - مودال راهنمای تصویری گام‌به‌گام Add to Home Screen در iOS Safari.
    - حفظ وضعیت بستن بنر با انقضای ۷ روزه در `localStorage`.

---

## ۳. بلوک رسمی گزارش `commander.v2`

```json
{
  "schema": "commander.v2",
  "turn_id": "HC-STATUS-006",
  "agent": "Antigravity-IDE (Primary Executor & Coordinator)",
  "state_update": {
    "phase": "PHASE_3_SERVICES_AND_API_COMPLETED",
    "status": "AWAITING_COMMANDER_DECISION",
    "completed": [
      "HC-T08 (GitHub develop branch push verified)",
      "HC-T09 (Phase 1 DB, AC-07 atomic query, AC-12 settlement lock, audit logs)",
      "HC-T10 (Phase 2 Auth, 6-role RBAC, Argon2id, Fail-Closed verification)",
      "HC-T11 (AC-14 and AC-15 token rotation, replay detection, 5s grace period)",
      "HC-T13 (Phase 3 Core Services: Validators, Profiles, Doctors, Plans, CMS, Visits, Wallets, Sales, Payments, Referrals, Reviews, Notifications)",
      "HC-T14 (FastAPI REST HTTP layer with 11 mounted domain routers and auth middleware)",
      "HC-T15 (Manager Directive: Mobile PWA Floating Install Bar with Android/iOS support)",
      "Full Test Coverage: 14/14 automated test suites passing (100% green, 73 tests, 0 failures)"
    ],
    "in_progress": [
      "HC-T12 (Second-Pass Review Coordination with independent reviewers)",
      "HC-T16 (Next.js 14 Frontend App Router Integration & Surface Rendering)"
    ],
    "blocked": [
      "Merge feature/auth-rbac-core and feature/phase3-profiles-and-validators into develop pending Commander approval",
      "Production deployment pending owner gate"
    ],
    "evidence_references": [
      "commit develop: bdd7ba1",
      "commit feature/auth-rbac-core: 49279d9",
      "commit feature/phase3-profiles-and-validators: 4f10e32",
      "Master Test Runner: 14/14 suites passed in 15.16s (scripts/run_all_tests.py)",
      "FastAPI Test Suite: 10/10 endpoints passed (tests/test_api_endpoints.py)"
    ],
    "next_best_action": "Evaluate Phase 3 backend completion, authorize merging feature/auth-rbac-core and feature/phase3-profiles-and-validators into develop, and dispatch Phase 4 (Next.js 14 Web Surfaces & UI Integration) sprint tasks."
  }
}
```

فرمانده محترم، کلیه نتایج پیاده‌سازی و شواهد راستی‌آزمایی فنی به همراه اجرای موفقیت‌آمیز تمامی ۷۳ تست خودکار جهت بررسی، صدور تاییدیه ادغام شاخه‌ها و ابلاغ مأموریت‌های فاز ۴ (فرانت‌اند و سطوح کاربری) تقدیم حضور می‌گردد.
