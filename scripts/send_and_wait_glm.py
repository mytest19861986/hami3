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
from PIL import Image
gui.FAILSAFE = False

GLM_PROMPT = """مأموریت بازبینی مستقل نیازمندی‌های PRD، امنیت RBAC و تجربه کاربری RTL (Independent Review: PRD, RBAC & RTL UX)
Task ID: HC-T05 / GLM-REVIEW
پروژه: سامانه حامی‌کارت (HamiCard) - فاز ۱ (طراحی معماری، پایگاه داده و تنظیمات پایه)
مرجع سند: PRD نسخه 1.0 (شامل ۲۹ بخش، ۳۰ قاعده کسب‌وکار BR-01..30 و ۱۸ معیار پذیرش AC-01..18)

لطفاً معماری فاز ۱ و مدل داده مستقر در db/schema.sql و مستندات docs/ARCHITECTURE_ADR.md را از دیدگاه‌های زیر به صورت مستقل و موشکافانه ارزیابی کن:

۱. تطابق با ۲۱ موجودیت PRD و پوشش نیازمندی‌های پایه:
- جدول‌های users, roles, permissions, user_roles, doctor_profiles, agent_profiles, marketer_profiles, memberships, provinces, cities, wallet, settlement_requests, transactions, system_settings, content_pages و ...
- آیا نقصی در روابط کلید خارجی (Foreign Keys با سیاست RESTRICT) یا پوشش موجودیت‌های PRD مشاهده می‌شود؟

۲. ماتریس دسترسی RBAC و جداسازی نقش‌ها (Security & Privilege Separation):
- ۵ نقش اصلی: SUPER_ADMIN, ADMIN, DOCTOR, AGENT, MARKETER, USER
- وضعیت‌های تأیید هویت پزشکان و نمایندگان (PENDING, APPROVED, REJECTED)
- اصل حداقل دسترسی و جلوگیری از نشت اطلاعات PII (کد ملی، شماره شبا، شماره موبایل) در لاگ‌ها و پاسخ‌های عمومی.

۳. سازگاری بومی و تجربه کاربری زبان فارسی (RTL & Iranian Localization):
- ذخیره‌سازی نام و توضیحات با یونیکد UTF-8
- نگهداری مبالغ به واحد ریال (BIGINT) و پشتیبانی از تقویم جلالی/شمسی در لایه نمایش
- جدول‌های ۳۱ استان و شهرهای رسمی کشور.

۴. انطباق تصمیمات باز (OPEN-01 تا OPEN-18) با الگوی Fail-Closed:
- تنظیمات پارامتریک در جدول system_settings و رفتار سامانه در صورت عدم وجود کلید یا خطای سیستمی.

خروجی مورد انتظار:
- ارزیابی دقیق هر یک از محورهای ۴ گانه
- بیان شفاف نقاط قوت، نقاط ضعف و ریسک‌های امنیتی
- نتیجه بازبینی نهایی: [APPROVED / NEEDS_FIXES] به همراه الزامات اصلاحی در صورت وجود"""

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

def activate_tab(tab_num=6):
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

def send_to_glm():
    activate_tab(6)
    pyperclip.copy(GLM_PROMPT)
    print("Copied GLM prompt to clipboard.")

    # Click in input box at (450, 835)
    print("Clicking input box at (450, 835)...")
    gui.click(450, 835)
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

    # Click send button at (1115, 913) and press Enter
    print("Clicking send button at (1115, 913)...")
    gui.click(1115, 913)
    time.sleep(0.2)
    gui.press('enter')

    # Rule 4: Wait 3 seconds
    print("Waiting 3 seconds per rule 4...")
    time.sleep(3.0)

    # Capture 3s verification
    pic = gui.screenshot()
    os.makedirs("d:/project/hami3/scripts", exist_ok=True)
    pic.save("d:/project/hami3/scripts/glm_3s_verify.png")
    print("Verification screenshot saved to scripts/glm_3s_verify.png")

if __name__ == "__main__":
    send_to_glm()

