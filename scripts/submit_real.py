import ctypes
from ctypes import wintypes
import time
import pyperclip
from PIL import ImageGrab

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

def init_desktop():
    hwinsta = user32.OpenWindowStationW('winsta0', False, 0x0000037F)
    user32.SetProcessWindowStation(hwinsta)
    hdesk = user32.OpenDesktopW('default', 0, False, 0x01FF)
    user32.SetThreadDesktop(hdesk)

def force_firefox_foreground():
    init_desktop()
    firefox_hwnd = None
    def cb(hwnd, l):
        nonlocal firefox_hwnd
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buff, length + 1)
                if 'Firefox' in buff.value:
                    firefox_hwnd = hwnd
        return True
    user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    
    if not firefox_hwnd:
        print("Firefox not found!")
        return False
        
    user32.keybd_event(0x12, 0, 0, 0) # ALT down
    user32.keybd_event(0x12, 0, 2, 0) # ALT up
    user32.ShowWindow(firefox_hwnd, 9)
    user32.ShowWindow(firefox_hwnd, 3)
    user32.SetForegroundWindow(firefox_hwnd)
    time.sleep(0.5)
    return True

DIRECTIVE = """[COMMANDER_DIRECTIVE][run_id=RUN-HAMICARD-001][task_id=TASK-GLM-002-CORE-LOGIC-AND-GIT-SYNC][worker=GLM]
سطح فرمان: L2 — Structured
مرجع محصول: BL-HAMICARD-PRD-V1 (پروژه حامی‌کارت - PRD v1.0)
هدف مأموریت: تثبیت کدهای پیاده‌سازی‌شده در مخزن گیت، انطباق کامل با ناورداهای تجاری/مالی PRD، و تکمیل تمامی سطوح کاربری سامانه

خسته نباشید؛ بازطراحی هویت بصری، تایپوگرافی محلی (Vazirmatn + Estedad)، امنیت CSP/CSRF و سناریوی ورود دوستونه و ادمین به عنوان پایه‌ای ارزشمند مورد بررسی و ارزیابی قرار گرفت.
اکنون جهت ارتقای پروژه در تمام ابعاد و هدایت محصول به سمت استقرار نهایی، دستورات اجرایی زیر را بدون توقف پیاده‌سازی کن:

۱. تثبیت و همگام‌سازی فوری در مخزن گیت (Git Commit & Push):
   - تمام تغییرات اعمال‌شده در /home/z/my-project را با پیام ساختاریافته کامیت کن:
     feat(ui-auth): Persian RTL visual polish, Vazirmatn typography, CSP/CSRF security headers, and admin OTP flow
   - تغییرات را به مخزن GitHub مرتبط (در صورت اتصال ریپازیتوری mytest19861986/hami3) push کن تا از ماندگاری کدها اطمینان حاصل شود. وضعیت git status را گزارش کن.

۲. پیاده‌سازی و تضمین ناورداهای حیاتی مالی و هم‌زمانی (Financial & Concurrency Invariants):
   - [AC-12 / SETTLE-005]: تضمین حداکثر ۱ درخواست باز تسویه به ازای هر کاربر. این قید باید با Partial Unique Index یا قید دیتابیس قفل شود:
     status IN ('PENDING', 'APPROVED') -> فقط یک رکورد برای هر user_id
   - [AC-11 / WALLET-006]: مدل داده دفترکل مالی (wallet_ledger_entries) به صورت Append-Only با فیلد idempotency_key برای جلوگیری از تراکنش تکراری.
   - [AC-07 / BR-08]: قفل اتمیک سهمیه ویزیت در زمان ثبت (جلوگیری از ثبت دو ویزیت هم‌زمان با سهمیه یکسان).
   - [AC-15 / AUTH-011]: چرخش اتمیک Refresh Token و باطل‌سازی نشست در صورت سوءاستفاده.

۳. تکمیل و توسعه سطوح کاربری باقی‌مانده (Surfaces Implementation):
   - سطح پزشک (SURF-DOCTOR):
     * فرم استعلام دارنده حامی‌کارت با کد ملی و شماره همراه.
     * نمایش سهمیه باقیمانده و فرم ثبت ویزیت/خدمت با محاسبه تخفیف بر اساس طرح یا قرارداد اختصاصی پزشک (OPEN-02).
   - سطح نماینده فروش (SURF-AGENT):
     * فرم ثبت مشتری و دارنده جدید حامی‌کارت.
     * داشبورد فروش و ره‌گیری فیزیکی کارت‌ها و بسته‌ها.
     * کیف پول نماینده، تاریخچه پورسانت‌ها و ثبت درخواست تسویه (حداقل ۱۰۰,۰۰۰ تومان - OPEN-06).
   - سطح کاربر عادی (SURF-USER):
     * نمایش کارت مجازی با مشخصات، انقضا و بارکد/سریال.
     * تاریخچه خدمات دریافت شده و مراکز درمانی طرف قرارداد.
   - سطح عمومی (SURF-PUBLIC):
     * دایرکتوری و جست‌وجوی پیشرفته پزشکان بر اساس استان، شهر و تخصص.

۴. پارامتریک‌سازی تصمیم‌های باز تجاری (OPEN-01 تا OPEN-18):
   - مقادیر پیش‌فرض مصوب (مطابق سند نقشه راه و جدول system_settings) در پنل مدیریت قابل ویرایش باشند.

۵. تست‌های خودکار و تحویل Evidence:
   - تست‌های E2E جدید با agent-browser برای سناریوهای پزشک و نماینده.
   - اسکرین‌شات‌های جدید در پوشه download/ .
   - گزارش نهایی شامل: STATUS (PASS/FIX_REQUIRED), SEVERITY, FILES_CHANGED, GIT_COMMIT_HASH, REMAINING_WORK."""

def run():
    if not force_firefox_foreground():
        return
    time.sleep(0.5)
    
    # 1. Click input box text area at (300, 830)
    print("Clicking input area...")
    user32.SetCursorPos(300, 830)
    time.sleep(0.1)
    user32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.05)
    user32.mouse_event(0x0004, 0, 0, 0, 0)
    time.sleep(0.3)
    
    # 2. Copy directive and paste with Ctrl+V
    print("Copying to clipboard...")
    pyperclip.copy(DIRECTIVE)
    time.sleep(0.1)
    
    print("Sending Ctrl+V...")
    user32.keybd_event(0x11, 0, 0, 0) # CTRL down
    user32.keybd_event(0x56, 0, 0, 0) # V down
    time.sleep(0.1)
    user32.keybd_event(0x56, 0, 2, 0) # V up
    user32.keybd_event(0x11, 0, 2, 0) # CTRL up
    time.sleep(0.8)
    
    # 3. Click send button at (797, 902)
    print("Clicking send button at (797, 902)...")
    user32.SetCursorPos(797, 902)
    time.sleep(0.1)
    user32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.05)
    user32.mouse_event(0x0004, 0, 0, 0, 0)
    time.sleep(0.5)
    
    # Also press Enter just in case
    user32.keybd_event(0x0D, 0, 0, 0) # ENTER down
    time.sleep(0.05)
    user32.keybd_event(0x0D, 0, 2, 0) # ENTER up
    time.sleep(1.0)
    
    im = ImageGrab.grab()
    im.save(r'C:\Users\IT\.gemini\antigravity\brain\7cae2d48-3747-4722-9e99-34a9e33eaa04\scratch\submitted_proof.png')
    print("Finished submit.")

if __name__ == '__main__':
    run()
