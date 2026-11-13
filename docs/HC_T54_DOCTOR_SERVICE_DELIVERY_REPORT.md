# گزارش تحویل فنی برش عمودی خدمات پزشکی و پرتابل پزشک (HC-T54)
## HC-T54: Doctor Service Vertical Slice Delivery Report
**شماره ابلاغیه فرماندهی کل:** `HC-COMMANDER-017`  
**وضعیت تسک:** آماده بازبینی و ممیزی (READY FOR REVIEW)  
**شاخه گیت اختصاصی:** `feat/hc-t54-doctor-service-slice`  
**محیط کار ایزوله (Worktree):** `D:\project\hami3-worktrees\hami3-wt-t54`  
**بر مبنای تعهد مبنا:** `develop @ 309a5853a3e9ee5503b4866b9370a8398c97264f`  
**تاریخ گزارش:** ۱۴۰۵/۰۸/۲۲ (2026-11-13)  

---

### ۱. چکیده مدیریتی و اهداف ابلاغیه HC-COMMANDER-017
پیرو ابلاغیه قطعی فرمانده ارشد سیستم (`HC-COMMANDER-017`) ذیل دستور `OPTION_A_APPROVED_WITH_SECURITY_GATES`، معماری احراز هویت همزمانی B2 در وضعیت منجمد (`FROZEN`) قرار گرفت و هرگونه بازطراحی B2-Rev2 ممنوع اعلام شد (`FORBIDDEN`). پروژه فوراً بر خلق ارزش واقعی تجاری سامانه در قالب تسک **HC-T54** متمرکز گردید.

هدف از این تسک پیاده‌سازی و راستی‌آزمایی یک **برش عمودی کامل (Vertical Slice)** شامل پرتابل پزشک، استعلام اعتبار و سهمیه بیمار، ثبت رسمی خدمات درمانی با کسر اتمیک سهمیه، جلوگیری از ثبت تکراری (Idempotency / Rapid Replay)، دفاع کامل در برابر نفوذ و جعل هویت (IDOR)، و حفاظت از حریم خصوصی بیمار (Masked PII) با دیتای آزمایشی ۱۰۰٪ سینتتیک (Synthetic) بوده است.

---

### ۲. قلمرو پیاده‌سازی و مشخصات فنی (Scopes 1 to 9)

#### حوزه ۱: نمایش قراردادها و خدمات مجاز پزشک (`service_contracts`)
- **اندپوینت‌ها:**
  - `GET /api/v1/doctors/me/portal`: بازگرداندن خلاصه عملکرد مطب، مشخصات نظام پزشکی، قراردادهای فعال و شاخص‌های مالی و آماری ویزیت‌ها.
  - `GET /api/v1/doctors/me/contracts`: بازگرداندن لیست قراردادهای رسمی فعال پزشک لاگین‌شده.
  - `GET /api/v1/doctors/{doctor_id}/contracts`: بازگرداندن قراردادهای پزشک مشروط بر تطابق هویت پزشک لاگین‌شده یا دسترسی `ADMIN`.
- **قواعد تجاری:**
  - قراردادها مستقیماً از جدول `service_contracts` فیلتر می‌شوند (`status = 'ACTIVE'` و بازه زمانی معتبر).

#### حوزه ۲: استعلام برخط اعتبار و سهمیه بیمار توسط پزشک
- **اندپوینت:** `POST /api/v1/visits/inquire`
- **ورودی‌ها:** پشتیبانی از کد ملی بیمار (`national_code`) یا شناسه عضویت (`membership_id`) یا شماره کارت (`card_number`).
- **خروجی امنیتی:**
  - وضعیت اعتبار (`is_eligible: true/false`).
  - علت عدم اعتبار (`ineligibility_reason`: نظیر `QUOTA_EXHAUSTED` یا `MEMBERSHIP_EXPIRED` یا `MEMBERSHIP_STATUS_SUSPENDED`).
  - سهمیه باقیمانده (`remaining_visits`) و کل سهمیه طرح (`max_visits`).
  - درصد تخفیف موثر سامانه (`effective_discount_percent`) محاسبه‌شده بر اساس اولویت خط‌مشی تاییدشده `OPEN_02`.
  - **حفاظت از PII:** کد ملی بیمار همواره به صورت ماسک‌شده (`001****789`) به پزشک بازگردانده می‌شود تا از نشت هویت بیماران جلوگیری شود.

#### حوزه ۳: ثبت قطعی خدمت درمانی تخفیف‌دار (`POST /visits/record`)
- محاسبه قطعی و ریاضی مبالغ تخفیف و پرداختی بیمار در سمت سرور با موتور `Decimal` و قاعده رندینگ مصوب `OPEN_18` (هرگونه تخفیف ارسالی توسط کلاینت به عنوان ورودی غیرمعتبر نادیده گرفته می‌شود).
- کسر اتمیک سهمیه با قفل سطری `FOR UPDATE` و اعتبارسنجی `remaining_visits >= 1` (`AC-07`).
- ثبت کامل ممیزی در `audit_logs` با وضعیت محاسباتی قیمت و شناسه یکتا.

#### حوزه ۴: نمایش وضعیت ثبت در پرتابل و کاردکس ویزیت‌های پزشک
- **اندپوینت‌ها:**
  - `GET /api/v1/visits/my-visits`: اندپوینت اختصاصی و امن برای پزشک لاگین‌شده بدون نیاز به ارسال `doctor_id` در URL (جلوگیری ساختاری از IDOR).
  - نمایش آنی ویزیت‌های اخیر در داشبورد پرتابل پزشک (`GET /doctors/me/portal`).

#### حوزه ۵: اعتبارسنجی سمت سرور هویت و پروانه پزشک
- بررسی قطعی دو لایه: نقش `DOCTOR` در `user_roles` به همراه `verification_status == 'APPROVED'` در جدول `doctors`.
- رفتار پیش‌فرض شکست در حالت بسته (`Fail-Closed`): چنانچه وضعیت پزشک `PENDING`، `REJECTED` یا `SUSPENDED` باشد، دسترسی با خطای `403 Forbidden` مسدود می‌گردد.

#### حوزه ۶: کنترل مالکیت و جلوگیری قاطع از نفوذ و دسترسی غیرمجاز (IDOR)
- پزشک الف تحت هیچ شرایطی نمی‌تواند قراردادها (`GET /doctors/{docB}/contracts`) یا لیست ویزیت‌های پزشک ب (`GET /visits/doctor/{docB}`) را مشاهده کند (رد با خطای ۴۰۳).
- پزشک الف در صورت ارسال فیلد `doctor_id = docB` در بدنه ثبت ویزیت، با خطای ۴۰۳ رد شده و مجاز به جعل هویت پزشک دیگر نیست.

#### حوزه ۷: تست‌های دسترسی منفی (Negative Tests)
- کاربر عادی فاقد نقش پزشک -> خطای ۴۰۳.
- پزشک تاییدنشده / در انتظار بررسی -> خطای ۴۰۳.
- درخواست فاقد توکن احراز هویت -> خطای ۴۰۱.

#### حوزه ۸: پیشگیری از ثبت تکراری (Idempotency & Rapid Replay Defense)
- **دفاع اول (Rapid Replay Window):** سرور ثبت مجدد همان خدمت (همان پزشک، همان دارنده کارت، همان عضویت و همان عنوان خدمت) را در بازه زمانی کمتر از ۳۰ ثانیه شناسایی کرده و با خطای `409 Conflict` رد می‌کند.
- **دفاع دوم (Idempotency-Key):** پشتیبانی از هدر رسمی `Idempotency-Key` و فیلد بدنه؛ در صورت ارسال کلید تکراری، با خطای `409 Conflict` ثبت مجدد مسدود می‌گردد.

#### حوزه ۹: داده‌های آزمایشی ۱۰۰٪ سینتتیک (Synthetic Mock Data)
- هیچ‌گونه داده واقعی، کد ملی حقیقی یا اطلاعات اشخاص در آزمون‌ها یا پایگاه داده استفاده نشده است. تمامی داده‌ها توسط ژنراتورهای تصادفی سینتتیک تولید شده‌اند.

#### حوزه ۱۰: تطابق سخت‌گیرانه با سیستم خط‌مشی‌های باز (OPEN Policies)
- در صورت عدم تایید خط‌مشی `OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE`، سیستم در حالت Fail-Closed قرار گرفته و با خطای ۴۰۳ از انجام تراکنش جلوگیری می‌کند.

---

### ۳. رابط کاربری (Frontend UI Shell Integration)
در فایل `src/static/index.html` امکانات ذیل اضافه شد:
1. **دکمه دسترسی اختصاصی پزشک:** دکمه «پرتابل مطب و ثبت خدمت» در هدر سامانه که فقط برای کاربران دارای نقش `DOCTOR` (یا ادمین) فعال و قابل مشاهده است.
2. **مودال جامع پرتابل پزشک (`doctor-portal-modal`):**
   - بنر اطلاعات هویتی، نام کلینیک، شماره نظام پزشکی و برچسب وضعیت تاییدیه (`APPROVED`).
   - کارت قراردادهای رسمی فعال حامی‌کارت با نمایش درصد تخفیف توافقی.
   - کارت‌های آماری زنده: کل خدمات ثبت‌شده، خدمات امروز، مجموع تخفیف‌های حامی، و دریافتی از بیماران.
   - بخش استعلام سهمیه و کارت بیمار با کد ملی یا شناسه عضویت، نمایش کد ملی ماسک‌شده، و وضعیت صلاحیت.
   - فرم ۲ مرحله‌ای ثبت خدمت درمانی با پیش‌نمایش زنده محاسبه تخفیف و پرداختی بیمار و تولید خودکار کلید ضدتکرار (Idempotency Key).
   - جدول تاریخچه سوابق ویزیت‌های ثبت‌شده با امکان بروزرسانی زنده.

---

### ۴. نتایج آزمون‌های خودکار در محیط ایزوله (Automated Test Suite)
آزمون‌های این تسک در فایل مستقل `tests/test_hc_t54_doctor_service_slice.py` تدوین و بر روی دیتابیس کاملاً مجزای `hamicard_t54_isolated` و ردیس شماره ۱۵ اجرا شدند:

```
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\project\hami3-worktrees\hami3-wt-t54
collected 9 items

tests/test_hc_t54_doctor_service_slice.py::test_doctor_portal_view_active_contracts PASSED [ 11%]
tests/test_hc_t54_doctor_service_slice.py::test_patient_eligibility_inquiry_active_and_eligible PASSED [ 22%]
tests/test_hc_t54_doctor_service_slice.py::test_patient_eligibility_inquiry_exhausted_or_expired PASSED [ 33%]
tests/test_hc_t54_doctor_service_slice.py::test_record_visit_success_decrements_quota PASSED [ 44%]
tests/test_hc_t54_doctor_service_slice.py::test_duplicate_visit_rapid_replay_defense PASSED [ 55%]
tests/test_hc_t54_doctor_service_slice.py::test_idempotency_key_duplicate_defense PASSED [ 66%]
tests/test_hc_t54_doctor_service_slice.py::test_doctor_idor_prevented PASSED [ 77%]
tests/test_hc_t54_doctor_service_slice.py::test_negative_access_pending_or_unapproved_doctor_rejected PASSED [ 88%]
tests/test_hc_t54_doctor_service_slice.py::test_unapproved_open_policy_fails_closed PASSED [100%]

======================= 9 passed, 66 warnings in 7.32s ========================
```

---

### ۵. راستی‌آزمایی عدم دست‌خوردگی دیتابیس اصلی (Pre == Post Fingerprint)
قبل و بعد از اجرای آزمون‌ها، هش و شمارش سطرهای تمامی ۳۰ جدول دیتابیس توسعه (`hamicard_dev`) بررسی گردید:
```
Pre == Post: True
hamicard_dev is 100% UNTOUCHED and INTACT.
```
هیچ‌گونه سطر، ساختار یا خط‌مشی در پایگاه داده اصلی دستخوش تغییر نشد.

---

### ۶. فایل‌های تغییریافته در شاخه `feat/hc-t54-doctor-service-slice`
1. `src/doctors/service.py`: متدهای `list_doctor_contracts` و `get_doctor_portal_summary` با ماسک PII.
2. `src/api/doctors.py`: اندپوینت‌های `/me/portal` و `/me/contracts` و `/{id}/contracts`.
3. `src/visits/service.py`: متد `inquire_patient_eligibility`، استثنای `DuplicateVisitError`، و مکانیزم ضدتکرار (Rapid Replay & Idempotency Key) در `record_visit`.
4. `src/api/visits.py`: اندپوینت‌های `/inquire` و `/my-visits` و اتصال هدر `Idempotency-Key` و مدیریت خطای ۴۰۹.
5. `src/static/index.html`: مودال و توابع جاوااسکریپت پرتابل مطب و ثبت خدمت درمانی.
6. `tests/test_hc_t54_doctor_service_slice.py`: مجموعه ۹ آزمون یکپارچه خودکار.
7. `docs/HC_T54_DOCTOR_SERVICE_DELIVERY_REPORT.md`: سند تحویل حاضر.
