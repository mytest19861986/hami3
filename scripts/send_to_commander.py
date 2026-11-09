import ctypes
from ctypes import wintypes
import time
import pyperclip

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

def init_desktop():
    hwinsta = user32.OpenWindowStationW('winsta0', False, 0x0000037F)
    user32.SetProcessWindowStation(hwinsta)
    hdesk = user32.OpenDesktopW('default', 0, False, 0x01FF)
    user32.SetThreadDesktop(hdesk)

def get_brave_hwnd():
    init_desktop()
    brave_hwnd = None
    def cb(hwnd, l):
        nonlocal brave_hwnd
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buff, length + 1)
                if 'Brave' in buff.value:
                    brave_hwnd = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    return brave_hwnd

def activate_brave():
    hwnd = get_brave_hwnd()
    if not hwnd:
        print("Brave window not found!")
        return False
    fore_hwnd = user32.GetForegroundWindow()
    fore_thread = user32.GetWindowThreadProcessId(fore_hwnd, None)
    app_thread = kernel32.GetCurrentThreadId()
    user32.AttachThreadInput(fore_thread, app_thread, True)
    user32.ShowWindow(hwnd, 3) # SW_SHOWMAXIMIZED
    user32.SwitchToThisWindow(hwnd, True)
    user32.BringWindowToTop(hwnd)
    user32.AttachThreadInput(fore_thread, app_thread, False)
    time.sleep(0.5)
    return True

def switch_to_tab(tab_number):
    activate_brave()
    user32.keybd_event(0x11, 0, 0, 0) # CTRL down
    time.sleep(0.05)
    vk = ord(str(tab_number))
    user32.keybd_event(vk, 0, 0, 0) # key down
    time.sleep(0.05)
    user32.keybd_event(vk, 0, 2, 0) # key up
    user32.keybd_event(0x11, 0, 2, 0) # CTRL up
    time.sleep(1.0)
    print(f"Switched to tab {tab_number}")

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

# 1. Switch to tab 4 (ChatGPT hami3)
switch_to_tab(4)
time.sleep(1.0)

# 2. Copy message to clipboard
pyperclip.copy(MESSAGE)
print("Message copied to clipboard.")

# 3. Click input box in ChatGPT (x=500, y=900)
user32.SetCursorPos(500, 900)
time.sleep(0.15)
user32.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
user32.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.3)

# 4. Paste with Ctrl+V
user32.keybd_event(0x11, 0, 0, 0) # CTRL down
user32.keybd_event(0x56, 0, 0, 0) # V down
time.sleep(0.05)
user32.keybd_event(0x56, 0, 2, 0) # V up
user32.keybd_event(0x11, 0, 2, 0) # CTRL up
time.sleep(0.6)

# 5. Click Send button at x=915, y=900 (or press Enter)
user32.SetCursorPos(915, 900)
time.sleep(0.1)
user32.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
user32.mouse_event(0x0004, 0, 0, 0, 0)
print("Send button clicked.")

# 6. User Rule: Wait 3 seconds
print("Waiting 3 seconds to verify chatbox...")
time.sleep(3.0)
print("3 seconds elapsed. Verification ready.")

