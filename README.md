# سامانه جامع خدمات رفاهی و درمانی حامی‌کارت (HamiCard)

> **Mission ID:** `M-HAMICARD-ZERO-TO-PROD`  
> **Baseline:** `BL-HAMICARD-PRD-V1` (PRD v1.0, 29 Sections, BR-01..30, AC-01..18, OPEN-01..18)

---

## ۱. معرفی و اهداف پروژه

**حامی‌کارت** سامانه‌ای جامع برای ارتقای سلامت و کاهش هزینه‌های درمانی خانواده‌های ایرانی است. این پلتفرم دسترسی متقاضیان را به شبکه پزشکان طرف قرارداد، کلینیک‌ها و مراکز درمانی در ۳۱ استان کشور تسهیل کرده و مدیریت طرح‌های تخفیف، صدور کارت، ثبت پرونده‌های فروش و تسویه حساب مالی را به صورت اتمیک و خودکار انجام می‌دهد.

---

## ۲. پشته فناوری (Tech Stack)

- **بک‌اند:** Python 3.13 | FastAPI 0.141+ | Pydantic v2
- **پایگاه داده (SSOT):** PostgreSQL 16 Alpine با asyncpg و اتصال پولینگ بهینه
- **کش و صف نشست:** Redis 7 Alpine با سیاست ماندگاری AOF و الگوریتم `volatile-lru`
- **رمزنگاری و امنیت:** Argon2id برای گذرواژه‌ها طبق استاندارد OWASP | SHA-256 برای سشن‌ها | الگوریتم‌های اعتبارسنجی بومی (کد ملی، Luhn شتاب، ISO 7064 شبا)
- **فرانت‌اند و سطوح کاربری:** پورتال وب واکنش‌گرا (RTL)، وب‌مانیفست PWA، سرویس‌ورکر و نوار شناور اختصاصی نصب موبایل (WebAPK و iOS Safari)
- **کانتینرسازی و CI/CD:** Docker multi-stage | Docker Compose | GitHub Actions با اجرای خودکار ۱۴ سوئیت آزمون مستر

---

## ۳. معماری سیستم و دامنه‌های کسب‌وکاری

```
                        +---------------------------------------+
                        |        کاربران و کلاینت‌ها (PWA)        |
                        +---------------------------------------+
                                           |
                                  [ REST API /api/v1 ]
                                           v
+-----------------------------------------------------------------------------------+
|                            FASTAPI APPLICATION CORE                               |
+-----------------------------------------------------------------------------------+
|  - Auth & RBAC (6 Roles: SUPER_ADMIN, ADMIN, SUPPORT, DOCTOR, AGENT, USER)        |
|  - Profiles & Geography (31 Provinces, Iranian Validators, PII Masking)           |
|  - Doctors Network & Service Contracts (Fail-Closed Public Directory)            |
|  - Discount Plans Storefront (Silver, Gold, Diamond)                              |
|  - Medical Visits & Atomic Quota Decrement (AC-07 Invariant)                      |
|  - Wallets & Append-Only Financial Ledger (AC-11, AC-12 Single Settlement Lock)   |
|  - Sales Cases & Dual State Machine (Logistic vs Financial, AC-09, AC-10)         |
|  - Payments & Subscription Fulfillment (Idempotency Key & Referral Commissions)  |
|  - Doctor Reviews & Administrative Moderation                                     |
|  - In-App Notifications & Unread Badges                                           |
+-----------------------------------------------------------------------------------+
             |                                                  |
             v                                                  v
+-------------------------+                        +-------------------------+
|      PostgreSQL 16      |                        |         Redis 7         |
|  (21 Relational Tables) |                        | (OTP Cooldown & Ephem)  |
+-------------------------+                        +-------------------------+
```

---

## ۴. راه‌اندازی سریع در محیط توسعه (Quickstart)

### ۱. پیش‌نیازها
- Python 3.13+
- Docker & Docker Compose

### ۲. اجرای کانتینرهای پایگاه داده و ردیس
```bash
docker compose -f docker-compose.dev.yml up -d
```

### ۳. نصب وابستگی‌های پایتون
```bash
pip install -r requirements-dev.txt
```

### ۴. اجرای آزمون‌های خودکار مستر (۱۴ سوئیت)
```bash
python scripts/run_all_tests.py
```

### ۵. راه‌اندازی سرور توسعه FastAPI
```bash
uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```
- **پورتال وب و PWA:** `http://localhost:8000/`
- **مستندات تعاملی Swagger:** `http://localhost:8000/docs`
- **مستندات ReDoc:** `http://localhost:8000/redoc`
- **بررسی سلامت سیستم:** `http://localhost:8000/api/v1/health`

---

## ۵. ماتریس آزمون‌های خودکار مستر (Master Test Matrix)

| شماره | حوزه آزمون | فایل تست | هدف و ناوردای آزموده شده |
| :---: | :--- | :--- | :--- |
| ۱ | بنیاد دیتابیس | `tests/test_phase1_database.py` | ساختار ۲۱ جدول و رفرنس‌های کلید خارجی |
| ۲ | اصلاحات فاز ۱ | `tests/test_phase1_remediation.py` | ناوردای AC-07 (سهمیه) و AC-12 (تسویه حساب) |
| ۳ | احراز هویت و RBAC | `tests/test_auth_rbac.py` | ۶ نقش PRD، رمزنگاری Argon2id و Fail-Closed |
| ۴ | چرخش رقابتی توکن | `tests/test_session_concurrency.py` | پایداری سشن، کشف Replay و مهلت ۵ ثانیه‌ای |
| ۵ | اعتبارسنج‌های ریاضی | `tests/test_validators.py` | کد ملی (mod 11)، کارت شتاب (Luhn)، شبا (ISO 7064) |
| ۶ | پروفایل و جغرافیا | `tests/test_profiles.py` | ۳۱ استان، شهرهای منتخب و ماسک‌گذاری PII |
| ۷ | پزشکان و طرح‌ها | `tests/test_doctors_and_plans.py` | تایید پزشک، قرارداد درمانی و کاتالوگ فروشگاه |
| ۸ | مدیریت محتوا CMS | `tests/test_content.py` | صفحات عمومی، قوانین و حریم خصوصی |
| ۹ | ویزیت و سهمیه | `tests/test_visits.py` | کسر اتمیک سهمیه و لغو ویزیت با بازگشت سهمیه |
| ۱۰ | کیف پول و دفترکل | `tests/test_wallets.py` | عدم امکان مانده منفی، قفل تسویه و واریز پورسانت |
| ۱۱ | فروش نمایندگی | `tests/test_sales_cases.py` | ماشین وضعیت دوگانه لجستیک/مالی، کد پستی (AC-09/10) |
| ۱۲ | پرداخت‌ها و معرف | `tests/test_payments_and_referrals.py` | ثبت سفارش با آیدمپوتنسی، فعال‌سازی کارت و کمیسیون |
| ۱۳ | نظرات و اعلان‌ها | `tests/test_reviews_and_notifications.py` | ثبت نظر برای ویزیت تکمیل‌شده و اعلان زنده |
| ۱۴ | لایه کامل REST API | `tests/test_api_endpoints.py` | تست جامع ۱۱ اندپوینت HTTP، روت وب‌پورتال و مانیفست |

---

## ۶. استقرار در محیط عملیاتی (Production Deployment)

جهت اجرای سامانه در محیط پروداکشن با کانتینرهای ایمن، ایزوله و پرفورمنس بالا:

```bash
# تنظیم متغیرهای محیطی در فایل .env
cp .env.example .env

# اجرای استک پروداکشن
docker compose -f docker-compose.prod.yml up -d --build
```

### بکاپ‌گیری دوره‌ای دیتابیس (OPEN-13)
جهت اجرای بکاپ خودکار مطابق با سیاست نگهداشت ۷ روزه، ۴ هفتگی و ۶ ماهه:
```bash
python ops/backup.py
```

---

## ۷. مجوز و کپی‌رایت
تمامی حقوق مادی و معنوی متعلق به سامانه خدمات رفاهی و درمانی حامی‌کارت می‌باشد.

