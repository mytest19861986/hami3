import ctypes
from ctypes import wintypes
import time
import pyperclip
import os
import sys

# 1. Desktop & DPI
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

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
from PIL import Image
gui.FAILSAFE = False

QWEN_PROMPT = """مأموریت بازبینی مستقل معماری و مدل داده (Independent Review: SQL & Concurrency)
Task ID: HC-T05 / QWEN-REVIEW
پروژه: حامی‌کارت (HamiCard) - فاز ۱ (پایگاه داده و ناورداهای هم‌زمانی)
مدل و سیستم دیتابیس: PostgreSQL 16 + Redis 7

لطفاً اسکریپت DDL و تمهیدات هم‌زمانی زیر را از نظر ناورداهای تراکنشی، ریسک Race Condition، ددلاک، کارایی و انطباق با نیازمندی‌های PRD v1.0 به صورت دقیق و نقادانه ارزیابی کن:

۱. ناوردای AC-12 (تضمین حداکثر یک درخواست تسویه باز در لحظه برای هر کاربر):
در جدول settlement_requests:
CREATE UNIQUE INDEX idx_one_open_settlement_per_user ON settlement_requests (user_id) WHERE status IN ('PENDING', 'PROCESSING');
آیا این Partial Unique Index در سطح دیتابیس مانع از Race Condition در درخواست‌های هم‌زمان تسویه توسط کاربر یا بات می‌شود؟

۲. ناوردای AC-07 (سهمیه ویزیت استانی و جلوگیری از مصرف مازاد):
در جدول memberships:
ALTER TABLE memberships ADD CONSTRAINT chk_visits_limit CHECK (remaining_visits >= 0 AND used_visits <= total_visits);
و در کد ثبت ویزیت: استفاده از قفل سطری SELECT ... FOR UPDATE روی سطر membership کاربر قبل از کاهش سهمیه. آیا این ترکیب از مصرف منفی سهمیه در درخواست‌های موازی به طور قطعی جلوگیری می‌کند؟

۳. ناوردای AC-11 و WALLET-006 (دفترکل تغییرناپذیر کیف پول):
جدول wallet_ledger_entries به صورت Append-Only با فیلدهای idempotency_key یکتا، type (CREDIT/DEBIT/LOCK/UNLOCK)، amount و running_balance.
کنترل تراز کیف پول با قید CHECK (balance >= locked_balance AND locked_balance >= 0) روی جدول wallets.

۴. سلسله‌مراتب قفل‌گذاری و پیشگیری از Deadlock:
ترتیب اخذ قفل در تراکنش‌های چند جدولی:
users -> memberships -> wallets -> settlement_requests
آیا در سناریوهای تلاقی (مثلاً تسویه هم‌زمان با خرید ویزیت یا لغو عضویت) پتانسیل ددلاک وجود دارد؟

۵. جدول تنظیمات پارامتریک (OPEN-01 تا OPEN-18):
جدول system_settings با الگوی Fail-Closed و مقادیر پیش‌فرض امن.

خروجی مورد انتظار:
- ارزیابی صریح و بی‌طرفانه هر یک از ۵ بخش فوق
- شناسایی هرگونه باگ احتمالی، سناریوی شکست مرزی (Edge Case)، یا ریسک ددلاک
- نتیجه نهایی: [APPROVED / NEEDS_FIXES] به همراه لیست اصلاحات الزامی در صورت وجود"""

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

def activate_tab(tab_num=5):
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

def send_to_qwen():
    activate_tab(5)
    pyperclip.copy(QWEN_PROMPT)
    print("Copied Qwen prompt to clipboard.")

    # Click in input box at (500, 885)
    print("Clicking input box at (500, 885)...")
    gui.click(500, 885)
    time.sleep(0.3)

    # Paste via Shift+Insert
    print("Pasting prompt via Shift+Insert...")
    user32.keybd_event(0x10, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(0x2D, 0, 2, 0)
    user32.keybd_event(0x10, 0, 2, 0)
    time.sleep(0.8)

    # Click send at (865, 885) and Enter
    print("Clicking send button at (865, 885)...")
    gui.click(865, 885)
    time.sleep(0.2)
    gui.press('enter')

    # Rule 4: Wait 3 seconds
    print("Waiting 3 seconds per rule 4...")
    time.sleep(3.0)

    # Capture 3s verification
    pic = gui.screenshot()
    os.makedirs("d:/project/hami3/scripts", exist_ok=True)
    pic.save("d:/project/hami3/scripts/qwen_3s_verify.png")
    print("Verification screenshot saved to scripts/qwen_3s_verify.png")

if __name__ == "__main__":
    send_to_qwen()

