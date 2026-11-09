import ctypes
from ctypes import wintypes
import time
import pyperclip
import os
import sys

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

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

MESSAGE = """[RESULT][message_id=MSG-HC-BOOT-001][run_id=RUN-HAMICARD-001][task_id=T-01-ARCH-AND-OPEN-DECISIONS]
Worker/model: Antigravity-Gemini (Primary Executor / Coordinator)
Status: IMPLEMENTATION_VERIFIED_LOCALLY | AWAITING_INDEPENDENT_REVIEW_OR_NEXT_TASK

گزارش وضعیت اجرای تسک‌های فاز ۱ (HC-T01 تا HC-T04):
۱. ممیزی مخزن و زیرساخت (HC-T01): شاخه develop فعال، ریپازیتوری https://github.com/mytest19861986/hami3 متصل شد.
۲. معماری و ADR (HC-T02): سند docs/ARCHITECTURE_ADR.md تدوین شد (معماری Modular Monolith، دیتابیس Postgres 16، ردیس 7، تنظیمات Fail-Closed).
۳. مدل داده و هم‌زمانی (HC-T03): سند docs/DATABASE_SCHEMA_ERD.md و db/schema.sql با ۲۱ موجودیت PRD، قید سهمیه ویزیت AC-07 و ایندکس جزئی یکتای تسویه AC-12 پیاده‌سازی شدند.
۴. زیرساخت و تست (HC-T04): کانتینرهای PostgreSQL 16 و Redis 7 با docker-compose بالا آمدند. تمام ۶ تست tests/test_phase1_database.py با موفقیت ۱۰۰٪ پاس شدند. کامیت 198c4eb ثبت شد.

Evidence/Artifacts:
- db/schema.sql (26 tables, strict foreign keys RESTRICT, unique partial indexes)
- db/seed.sql (31 provinces, 48 cities, 18 OPEN parametric settings, 3 plans, 5 content pages)
- docs/ARCHITECTURE_ADR.md & docs/DATABASE_SCHEMA_ERD.md
- tests/test_phase1_database.py (Live DB verification passed 100%)
- docker-compose.dev.yml (PostgreSQL 16.15 + Redis 7.2)
- Commit: 198c4eb

درخواست تصمیم از فرمانده (Decision Request):
۱. آیا خروجی و معماری فاز ۱ مورد تایید است؟
۲. با توجه به آماده بودن زیرساخت و دیتابیس، آیا اجرای فاز ۲ (هسته احراز هویت OTP، رمز عبور، چرخش توکن رقابتی AC-15 و RBAC) را آغاز کنیم؟"""

def find_brave():
    brave_hwnd = None
    def cb(hwnd, l):
        nonlocal brave_hwnd
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buff, length + 1)
                if "Brave" in buff.value:
                    brave_hwnd = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    return brave_hwnd

def activate_brave_tab(tab_num=4):
    hwnd = find_brave()
    if not hwnd:
        print("ERROR: Brave window not found")
        sys.exit(1)
    
    # Minimize Firefox if present to prevent focus fight
    def enum_cb(h, l):
        if user32.IsWindowVisible(h):
            length = user32.GetWindowTextLengthW(h)
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(h, buff, length + 1)
                if "Firefox" in buff.value:
                    user32.ShowWindow(h, 6) # SW_MINIMIZE
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(enum_cb), 0)
    time.sleep(0.2)

    # Bring Brave to front
    user32.ShowWindow(hwnd, 3) # SW_SHOWMAXIMIZED
    user32.SwitchToThisWindow(hwnd, True)
    user32.SetForegroundWindow(hwnd)
    user32.BringWindowToTop(hwnd)
    time.sleep(0.5)

    # Press Ctrl + tab_num
    gui.hotkey('ctrl', str(tab_num))
    time.sleep(0.8)

def send_message():
    activate_brave_tab(4)

    # Copy message to clipboard
    pyperclip.copy(MESSAGE)
    print("Copied message to clipboard.")

    # Click on the input box
    # From screenshot brave_tab4_current.png: input box is at x=500, y=905
    gui.click(500, 905)
    time.sleep(0.4)

    # Paste
    gui.hotkey('ctrl', 'v')
    time.sleep(0.8)

    # Click Send button at (913, 905) and also press Enter
    gui.click(913, 905)
    time.sleep(0.2)
    gui.press('enter')
    print("Message send triggered. Starting 3-second check...")

    # USER RULE: Check after exactly 3 seconds if chatbox is empty
    time.sleep(3.0)

    # Capture 3s verification screenshot
    pic = gui.screenshot()
    pic.save("d:/project/hami3/scripts/verify_3s_commander.png")
    print("Verification screenshot saved to scripts/verify_3s_commander.png")

if __name__ == "__main__":
    send_message()
