import ctypes
import time
import pyperclip
import os

if os.name == "nt":
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        ctypes.windll.user32.SetProcessDPIAware()
    try:
        hwinsta = ctypes.windll.user32.OpenWindowStationW("winsta0", False, 0x0000037F)
        if hwinsta:
            ctypes.windll.user32.SetProcessWindowStation(hwinsta)
        hdesk = ctypes.windll.user32.OpenDesktopW("default", 0, False, 0x01FF)
        if hdesk:
            ctypes.windll.user32.SetThreadDesktop(hdesk)
    except Exception:
        pass

import pyautogui as gui
gui.FAILSAFE = False

MESSAGE = """<AGENT_REPORT sender="Codex">
[RESULT][message_id=MSG-HC-BOOT-001][run_id=RUN-HAMICARD-001][task_id=T-01-ARCH-AND-OPEN-DECISIONS]
Worker/model: Antigravity-Gemini (Primary Executor / Coordinator)
Status: IMPLEMENTATION_VERIFIED_LOCALLY | AWAITING_INDEPENDENT_REVIEW_OR_NEXT_TASK

خلاصه گزارش اجرای تسک‌های فاز ۱ (HC-T01 تا HC-T04):
۱. ممیزی مخزن و زیرساخت (HC-T01): مخزن git محلی بررسی شد. شاخه develop فعال است. ریپازیتوری گیت‌هاب مقصد به آدرس https://github.com/mytest19861986/hami3 تنظیم شد.
۲. طراحی معماری و ADR (HC-T02): سند docs/ARCHITECTURE_ADR.md با ADR-001 (معماری Modular Monolith با مصرف حافظه زیر ۲.۵ گیگ جهت سازگاری با سرور 8GB RAM)، ADR-002 (پایگاه داده PostgreSQL 16 به‌عنوان مرجع واحد حقیقت مالی)، ADR-003 (استفاده از Redis 7 برای نرخ و چرخش توکن) و ADR-004 (طراحی پارامتریک و Fail-Closed برای OPEN-01..18) تدوین شد. تمامی نیازمندی‌های P0 و سناریوهای AC-01..18 به ماژول‌ها نگاشت شدند.
۳. مدل داده و ناورداهای هم‌زمانی (HC-T03): سند docs/DATABASE_SCHEMA_ERD.md و اسکریپت SQL در db/schema.sql تدوین شد. تمامی ۲۱ موجودیت PRD به‌علاوه ۳۱ استان، شهرهای کشور، نشست‌ها و جدول system_settings پیاده‌سازی شدند. ناورداهای حیاتی شامل ایندکس جزئی یکتای idx_one_open_settlement_per_user (تضمین AC-12 و BR-21)، قفل سطری و قید chk_visits_limit (تضمین AC-07)، و دفترکل تغییرناپذیر wallet_ledger_entries (تضمین AC-11 و WALLET-006) اعمال شدند.
۴. استقرار زیرساخت و تست محلی (HC-T04): فایل‌های docker-compose.dev.yml و .env.example ایجاد شد. کانتینرهای PostgreSQL 16 و Redis 7 با محدودیت منابع بالا آمدند و در وضعیت Healthy هستند. اسکریپت tests/test_phase1_database.py اجرا شد و ۱۰۰٪ تست‌ها (۶ از ۶) با موفقیت کامل پاس شدند. تغییرات با شناسه کامیت 198c4eb در گیت ثبت گردید.

Evidence/Artifacts:
- db/schema.sql (26 tables, strict foreign keys RESTRICT, unique partial indexes)
- db/seed.sql (31 provinces, 48 cities, 18 OPEN parametric settings, 3 plans, 5 content pages)
- docs/ARCHITECTURE_ADR.md & docs/DATABASE_SCHEMA_ERD.md
- tests/test_phase1_database.py (Live DB verification passed 100%)
- docker-compose.dev.yml (PostgreSQL 16.15 + Redis 7.2)
- Commit: 198c4eb

درخواست تصمیم از فرمانده (Decision Request):
۱. آیا خروجی و معماری فاز ۱ را تایید می‌کنید؟
۲. با توجه به آماده بودن زیرساخت و دیتابیس، آیا اجرای فاز ۲ (هسته احراز هویت OTP، رمز عبور، چرخش توکن رقابتی AC-15 و RBAC) را در دستور کار قرار دهیم؟
</AGENT_REPORT>"""

# 1. Copy message
pyperclip.copy(MESSAGE)

# 2. Click in input box at (500, 905)
gui.click(500, 905)
time.sleep(0.3)

# 3. Paste
gui.hotkey('ctrl', 'v')
time.sleep(0.5)

# 4. Click Send button at (915, 905)
gui.click(915, 905)
time.sleep(0.2)
gui.press('enter')

print("Message submitted. Waiting 3 seconds per user rule...")
time.sleep(3.0)

# 5. Capture verification screenshot
pic = gui.screenshot()
os.makedirs("scripts", exist_ok=True)
pic.save("scripts/commander_3s_verify.png")
print("Captured 3s verification screenshot to scripts/commander_3s_verify.png")

