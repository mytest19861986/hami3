# گزارش راستی‌آزمایی رابط کاربری فاز ۳ (`HC-T16`)

- **شناسه دستور / تسک**: `HC-CMD-016` / `HC-T16`
- **بیس‌لاین مرجع**: `BL-HAMICARD-PRD-V1` (بخش‌های ۱۵..۲۱ و ۲۷، `AC-17`)
- **وضعیت انزوا**: کار روی شاخه مستقل `feat/hc-t16-phase3-ui-shell` بدون هرگونه فایل مشترک با `HC-T13` و `HC-T14`.
- **وضعیت تایید بصری و سیاست‌ها**: رنگ‌بندی و تایپوگرافی (`OPEN-15`) به‌صورت صریح **`PROPOSED`** اعلام شده و در انتظار تایید مالک محصول است. داده‌ها کاملاً مصنوعی (`Synthetic Demo Data`) هستند و هیچ اتصال به اندپوینت‌های احراز هویت تاییدنشده یا مالی وجود ندارد.

---

## ۱. خروجی‌های تولیدشده

- [`docs/PHASE_3_ROUTE_MATRIX.md`](./PHASE_3_ROUTE_MATRIX.md) — نقشه کامل مسیرهای عمومی، دایرکتوری پزشکان، کاتالوگ طرح‌ها، اسکلت ورود غیرمتصل و پنل‌های ۶گانه (`USER`, `DOCTOR`, `AGENT`, `SUPPORT`, `ADMIN`, `SUPER_ADMIN`) به همراه ماتریس ۵ وضعیت رابط کاربری.
- [`docs/PHASE_3_DESIGN_SYSTEM.md`](./PHASE_3_DESIGN_SYSTEM.md) — مستندسازی توکن‌های پیشنهادی `OPEN-15`، کنتراست دسترس‌پذیری `WCAG AA/AAA`، تقویم جلالی و قواعد موبایل/تبلت/دسکتاپ.
- شِل مستقل تحت `src/ui_shell/`:
  - `src/ui_shell/index.html`
  - `src/ui_shell/styles/tokens.css`
  - `src/ui_shell/styles/shell.css`
  - `src/ui_shell/js/jalali.js`
  - `src/ui_shell/js/demo_data.js`
  - `src/ui_shell/js/app.js`
- آزمون خودکار مرورگر واقعی (`tests/test_hc_t16_ui_shell.py`) و تصاویر شاهد در `docs/screenshots/phase3/`:
  - `desktop_home.png` (`1280x800`)
  - `desktop_plans.png` (`1280x800`)
  - `desktop_panel_agent.png` (`1280x800`)
  - `desktop_state_disabled.png` (`1280x800`)
  - `tablet_doctors.png` (`768x1024`)
  - `mobile_home.png` (`390x844`)
  - `mobile_panel_support.png` (`390x844`)

---

## ۲. خلاصه نتایج آزمون مرورگر (`Playwright Headless Chromium`)

- **فرمان اجرا**: `python -m pytest -v tests/test_hc_t16_ui_shell.py`
- **پوشش آزمون**:
  - `dir="rtl"` و `lang="fa"` در تمام نماها و ویوپورت‌ها تایید شد.
  - تبدیل قطعی تاریخ جلالی (`2026-11-10` ← `۱۴۰۵/۰۸/۱۹`) و نمایش واحد پول (`تومان`) بررسی شد.
  - **۱۵ مسیر کامل بخش ۲۷** × **۳ ویوپورت (`1280x800`, `768x1024`, `390x844`)** × **۵ وضعیت (`NORMAL`, `LOADING`, `EMPTY`, `ERROR`, `DISABLED_GATE`)** همگی دارای `scrollWidth <= innerWidth` (اسکرول افقی غیرمنتظره **صفر**) بودند.
  - آزمون تعاملی جست‌وجو/فیلتر پزشکان، وضعیت خالی فیلتر، بستن منوی موبایل با کلید `Escape`, نبود خطای کنسول (`0 console errors`), نبود خطای ران‌تایم (`0 page errors`), نبود فراخوانی به API بک‌اند یا سرویس خارجی (`0 unexpected requests`), و نبود هرگونه رمز/توکن نمایشی در سورس پاس شد.
