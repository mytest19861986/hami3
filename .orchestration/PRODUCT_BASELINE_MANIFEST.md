# Product Baseline Manifest — حامی‌کارت (HamiCard)

```text
BASELINE_ID: BL-HAMICARD-PRD-V1
PROJECT_ID: HAMICARD-V1             REVISION: 1.0.0-draft
BASELINE_KIND: PRODUCT_SPEC_BASELINE
GOAL / OWNER_EXPECTATION: بازنویسی صفر تا صد سامانه عضویت، تخفیف خدمات درمانی، شبکه پزشکان، نمایندگان فروش، پورسانت، کیف پول و تسویه (ثبت خارج از سامانه) با رعایت کامل قواعد مالی، امنیتی، هم‌زمانی (Idempotency/Concurrency) و تجربه کاربری فارسی RTL، در محیط لوکال با مدیریت نسخه GitHub و استقرار نهایی روی سرور Ubuntu 24.04 (4 vCPU, 8GB RAM).
APPROVAL: approved_by=Human Manager; evidence_ref=docs/PRD_HamiCard_v1.0_FA.md; status=PARTIAL (P0/P1 نیازمندی‌ها مشخص؛ ۱۸ تصمیم تجاری OPEN-01 تا OPEN-18 نیازمند تعیین تکلیف)
REQUIRED_SURFACES / USER_JOURNEYS:
  - ID: SURF-PUBLIC    EXPECTED: صفحه اصلی، معرفی طرح‌ها، دایرکتوری و جست‌وجوی پزشکان (استان/شهر/تخصص)، صفحات محتوایی  CRITICAL: yes  REFERENCE: PRD §8.1, §20, §27
  - ID: SURF-AUTH      EXPECTED: ورود/ثبت‌نام با موبایل و OTP، ورود با رمز، مدیریت نشست و توکن چرخشی ضد مصرف هم‌زمان (AC-14, AC-15)  CRITICAL: yes  REFERENCE: PRD §4
  - ID: SURF-USER      EXPECTED: داشبورد کاربر عادی، پروفایل (کارت/شبا اختیاری تا زمان تسویه)، دارندگان طرح، عضویت‌ها، خریدها، سوابق ویزیت  CRITICAL: yes  REFERENCE: PRD §5, §6, §7, §15
  - ID: SURF-DOCTOR    EXPECTED: ثبت‌نام پزشک، صفحه انتظار تأیید، داشبورد پزشک تأییدشده، استعلام دارنده و ثبت ویزیت با قفل سهمیه (AC-07, AC-08)  CRITICAL: yes  REFERENCE: PRD §8.2, §9, §16
  - ID: SURF-AGENT     EXPECTED: ثبت‌نام نماینده و مدارک، داشبورد فروش، ثبت مشتری، پیگیری کارت/ارسال/تحویل، کیف پول، پورسانت و درخواست تسویه (AC-09..12)  CRITICAL: yes  REFERENCE: PRD §10..14, §17
  - ID: SURF-ADMIN     EXPECTED: پنل ADMIN، SUPER_ADMIN و SUPPORT با تفکیک دقیق RBAC، تأیید پزشک/نماینده، مدیریت طرح/فروش/پورسانت/تسویه، گزارش‌های قابل تطبیق و Audit Log  CRITICAL: yes  REFERENCE: PRD §3, §18, §19, §22
SOURCE_CANDIDATES:
  - candidate_id=CAND-LOCAL-GREENFIELD repo=d:/project/hami3 branch=UNSET commit=UNSET worktree=d:/project/hami3 dirty=yes (initial orchestration scaffolding)
  - candidate_id=CAND-HISTORICAL-REF repo=https://github.com/mytest19861986/mypush2-1 branch=sprint-2-user-profile-dashboard-fixes commit=UNKNOWN worktree=REMOTE_ONLY dirty=UNKNOWN (فقط مرجع شناخت دامنه طبق PRD؛ نه کد مبنا برای کپی باگ‌ها)
COMPONENT_COVERAGE:
  - component=PRD_Specification     expected_ref=docs/PRD_HamiCard_v1.0_FA.md  actual_source=docs/PRD_HamiCard_v1.0_FA.md  status=APPROVED
  - component=Architecture_Spec     expected_ref=docs/ARCHITECTURE.md          actual_source=NONE                          status=MISSING
  - component=Database_Schema       expected_ref=prisma/migrations             actual_source=NONE                          status=MISSING
  - component=Backend_API           expected_ref=src/api                       actual_source=NONE                          status=MISSING
  - component=Frontend_UI           expected_ref=src/web                       actual_source=NONE                          status=MISSING
  - component=Deployment_Ops        expected_ref=ops/                          actual_source=ops/SERVER_SPEC.md            status=PENDING
DATA/DB: environment_id=LOCAL_DEV_PENDING schema/migration=NONE seed/role_ref=NONE
ASSETS / FLAGS / CONFIG_REF: SMS_GATEWAY=UNSET (PENDING OPEN-11), PAYMENT_GATEWAY=UNSET (PENDING OPEN-11)
OWNER_PREVIEW: URL_or_access_path=UNSET; status=UNSET
NON_CANONICAL_CANDIDATES/RUNTIMES: https://github.com/mytest19861986/mypush2-1 (صرفاً مرجع مطالعه دامنه؛ کد آن نباید بدون ممیزی و بازنویسی تمیز وارد ریپوی جدید شود)
KNOWN_GAPS / CONFLICTS / IMPACTED_TASKS:
  - ۱۸ تصمیم تجاری باز (OPEN-01 تا OPEN-18 در بخش ۲۸ PRD) باید پیش از قفل شدن منطق مالی/تسویه/تخفیف با مدیر یا فرمانده تعیین تکلیف شوند.
INTEGRATION_DECISION: KEEP (شروع تمیز Greenfield در d:/project/hami3 بر اساس PRD v1.0)
LAST_EVIDENCE_REF / LAST_VERIFIED_AT: docs/PRD_HamiCard_v1.0_FA.md / 2026-11-09T19:46:00+03:30
```

