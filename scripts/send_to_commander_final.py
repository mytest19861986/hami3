import ctypes
from ctypes import wintypes
import time
import pyperclip
import os
import sys

user32 = ctypes.windll.user32
try:
    user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except Exception:
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass

hwinsta = user32.OpenWindowStationW("winsta0", False, 0x0000037F)
if hwinsta:
    user32.SetProcessWindowStation(hwinsta)
hdesk = user32.OpenDesktopW("default", 0, False, 0x01FF)
if hdesk:
    user32.SetThreadDesktop(hdesk)

import pyautogui as gui
gui.FAILSAFE = False

MESSAGE = """[RESULT][message_id=MSG-HC-EVID-002][run_id=RUN-HAMICARD-001][task_id=HC-T06,HC-T05,HC-T07][turn_id=HC-COMMANDER-002]
Worker/model: Antigravity-Gemini (Primary Executor / Coordinator)
Status: EVIDENCE_VERIFIED | INDEPENDENT_REVIEWS_COMPLETED | PHASE_2_DESIGN_READY

پاسخ به فرامین سه‌گانه فرمانده ارشد (HC-CMD-006 تا HC-CMD-008):

۱. گزارش رفع مغایرت گیت و ممیزی شواهد محلی (HC-T06):
- وضعیت Git: کامیت 198c4eb روی شاخه develop محلی معتبر و فعال است (HEAD: 198c4eb96e48629bbf10926066f7cacc8ec89aca).
- چرایی خالی بودن GitHub: طبق پروتکل امنیتی (tools_forbidden: [git-push]) و اصل عدم تغییر پیش از تأیید فرمانده، دستور git push origin develop متوقف مانده بود تا ابتدا شواهد مستقل ارائه شود. با صدور مجوز شما، فوراً به مخزن https://github.com/mytest19861986/hami3 ارسال می‌گردد.
- شواهد زنده آزمون: ۱۰۰٪ تست‌های tests/test_phase1_database.py با خروجی Exit Code: 0 پاس شدند. کانتینرهای PostgreSQL 16 و Redis 7 در وضعیت سالم (Healthy) هستند. مانیفست هش‌های SHA256 در docs/PHASE_1_EVIDENCE_REPORT.md ثبت شد.

۲. بازبینی مستقل داوران در مرورگر (HC-T05 - Builder ≠ Final Judge):
- داور ۱ (Qwen 3.8-Max در تب ۵): رأی [NEEDS_FIXES]. تأیید ناوردای AC-12 در سطح دیتابیس با توصیه افزودن lease/heartbeat به وضعیت PROCESSING، هندلینگ خطای 23505 و ارتقای کسر سهمیه ویزیت AC-07 به UPDATE شرطی اتمیک (متن کامل در docs/reviews/qwen_review.md).
- داور ۲ (GLM-5.3-Flash در تب ۶): رأی [NEEDS_FIXES]. ارائه ۶ الزام اصلاحی شامل تثبیت SSOT توکن‌ها در دیتابیس، سیاست ماسکینگ PII، لاگ ممیزی و رفتار Fail-Closed (متن کامل در docs/reviews/glm_review.md).
- سند تلفیق در docs/INDEPENDENT_REVIEW_SYNTHESIS.md ثبت شد.

۳. قرارداد طراحی و آزمون فاز ۲ (HC-T07):
- سند جامع docs/PHASE_2_AUTH_RBAC_DESIGN.md شامل مدل هویت، ماتریس مجوزهای ۵ نقش، جریان احراز هویت OTP و Argon2id، چرخه رفرش توکن رقابتی AC-15 با تشخیص Replay و ابطال خانواده نشست، و گراف وظایف پیاده‌سازی تدوین شد.

Evidence/Artifacts:
- docs/PHASE_1_EVIDENCE_REPORT.md (Git Reconciliation & SHA256 Hashes)
- docs/reviews/qwen_review.md (Qwen Concurrency Review - 30.5KB)
- docs/reviews/glm_review.md (GLM PRD & Security Review - 7KB)
- docs/INDEPENDENT_REVIEW_SYNTHESIS.md (Review Consensus & Fix List)
- docs/PHASE_2_AUTH_RBAC_DESIGN.md (Complete Phase 2 Architecture Contract)

درخواست تصمیم از فرمانده (Decision Request):
۱. صدور مجوز git-push جهت انتقال شاخه develop محلی (کامیت 198c4eb) به مخزن گیت‌هاب https://github.com/mytest19861986/hami3 جهت رفع مغایرت ریموت.
۲. صدور فرمان اجرایی پیاده‌سازی فاز ۲ (هسته احراز هویت، RBAC، رفرش رقابتی AC-15) با اعمال اصلاحات داوران مستقل."""

def find_brave():
    brave_hwnd = None
    def cb(hwnd, l):
        nonlocal brave_hwnd
        if user32.IsWindowVisible(hwnd):
            buff = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, buff, 512)
            if "Brave" in buff.value:
                brave_hwnd = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    return brave_hwnd

def activate_tab(tab_num=4):
    user32.keybd_event(0x12, 0, 0, 0)
    time.sleep(0.02)
    user32.keybd_event(0x12, 0, 2, 0)
    time.sleep(0.05)

    brave = find_brave()
    if not brave:
        print("ERROR: Brave not found")
        sys.exit(1)
    user32.ShowWindow(brave, 3)
    user32.SwitchToThisWindow(brave, True)
    user32.SetForegroundWindow(brave)
    user32.BringWindowToTop(brave)
    time.sleep(0.3)

    gui.hotkey('ctrl', str(tab_num))
    time.sleep(0.8)

def send_to_commander():
    activate_tab(4)
    pyperclip.copy(MESSAGE)
    print("Copied final report to clipboard.")

    # Click input box at (500, 905)
    print("Clicking chat input at (500, 905)...")
    gui.click(500, 905)
    time.sleep(0.3)

    # Paste
    print("Pasting message via Shift+Insert...")
    user32.keybd_event(0x10, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 2, 0)
    user32.keybd_event(0x10, 0, 2, 0)
    time.sleep(0.8)

    # Click send button at (913, 905) and press Enter
    print("Clicking send button at (913, 905)...")
    gui.click(913, 905)
    time.sleep(0.2)
    gui.press('enter')

    # Rule 4: Wait 3 seconds
    print("Waiting 3 seconds per rule 4...")
    time.sleep(3.0)

    # Capture 3s verification
    pic = gui.screenshot()
    os.makedirs("d:/project/hami3/scripts", exist_ok=True)
    pic.save("d:/project/hami3/scripts/commander_final_3s.png")
    print("Verification screenshot saved to scripts/commander_final_3s.png")

if __name__ == "__main__":
    send_to_commander()

