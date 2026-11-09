import ctypes
import time
import pyperclip

user32 = ctypes.windll.user32
hwinsta = user32.OpenWindowStationW('winsta0', False, 0x0000037F)
user32.SetProcessWindowStation(hwinsta)
hdesk = user32.OpenDesktopW('default', 0, False, 0x01FF)
user32.SetThreadDesktop(hdesk)

PROMPT = """[TASK_AUDIT_REQUEST][run_id=RUN-HAMICARD-001][task_id=T-01-ARCH-AND-OPEN-DECISIONS][worker=Qwen]
نقش شما: بازبین مستقل معماری دیتابیس، تراکنش‌ها و هم‌زمانی مالی (Backend & Concurrency Reviewer)
مرجع مأموریت: BL-HAMICARD-PRD-V1 (پروژه حامی‌کارت - فاز ۱: معماری و مدل داده)
قانون کلیدی: Builder ≠ Final Judge. ممیزی شما باید مستقل، نقادانه و بر اساس شواهد فنی باشد.

خلاصه اقدامات انجام‌شده در فاز ۱:
۱. زیرساخت لوکال داکر (PostgreSQL 16 + Redis 7) راه‌اندازی و در سلامت کامل تست شد.
۲. مدل داده کامل برای ۲۱ موجودیت PRD + جداول استان‌ها، شهرها، نشست‌ها و سیستم تنظیمات پیاده‌سازی شد.
۳. تمامی ۱۸ تصمیم تجاری (OPEN-01 تا OPEN-18) به‌صورت پارامتریک در جدول system_settings پیاده‌سازی شدند.
۴. ناورداهای هم‌زمانی زیر با تست‌های خودکار اثبات و پاس شدند:
   - AC-12 / BR-21 / SETTLE-005: تضمین حداکثر ۱ درخواست باز تسویه با Partial Unique Index:
     CREATE UNIQUE INDEX idx_one_open_settlement_per_user ON settlements (user_id) WHERE status IN ('PENDING', 'APPROVED');
   - AC-07 / VISIT-005 / BR-08: تضمین عدم مصرف مضاعف سهمیه در ویزیت‌های هم‌زمان با قفل سطری SELECT ... FOR UPDATE و قفل دیتابیس chk_visits_limit.
   - AC-15 / AUTH-011: چرخش اتمیک Refresh Token با یک‌بارمصرف‌سازی اتمیک در SQL.
   - AC-11 / WALLET-006: دفترکل مالی غیرقابل تغییر (Append-Only) در wallet_ledger_entries با کلید یکتای idempotency_key.

فایل‌های اساسی زیر پیاده‌سازی شده‌اند (خلاصه SQL و ERD):
- db/schema.sql (شامل تمام ۲۱ موجودیت، کلیدهای خارجی با RESTRICT، ایندکس‌ها و تریگرها)
- docs/DATABASE_SCHEMA_ERD.md (قیدهای ریاضی، سلسله‌مراتب قفل‌گذاری و پلن تست هم‌زمانی)
- tests/test_phase1_database.py (اجرا شده روی کانتینر واقعی داکر با موفقیت ۱۰۰٪ هر ۶ تست)

لطفاً ممیزی تخصصی خود را در قالب زیر به زبان فارسی تحویل بده:
۱. وضعیت نهایی ممیزی (STATUS): PASS یا FIX_REQUIRED
۲. شدت یافته‌ها (SEVERITY): BLOCKER / HIGH / MEDIUM / LOW
۳. ارزیابی ناورداهای هم‌زمانی مالی (AC-07, AC-11, AC-12, AC-15)
۴. ارزیابی پوشش ۲۱ موجودیت PRD و جدول system_settings
۵. نقاط ضعف احتمالی یا ریسک‌های Deadlock و پیشنهادات اصلاحی
۶. رفرنس بازبین (REVIEWER_REF): Qwen3.8-Max
"""

pyperclip.copy(PROMPT)
print("Prompt copied to clipboard.")

# Click on Qwen chat input box
user32.SetCursorPos(500, 880)
time.sleep(0.2)
user32.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
user32.mouse_event(0x0004, 0, 0, 0, 0)
time.sleep(0.3)

# Paste with Ctrl+V
user32.keybd_event(0x11, 0, 0, 0) # CTRL down
user32.keybd_event(0x56, 0, 0, 0) # V down
time.sleep(0.05)
user32.keybd_event(0x56, 0, 2, 0) # V up
user32.keybd_event(0x11, 0, 2, 0) # CTRL up
time.sleep(0.5)

# Press Enter
user32.keybd_event(0x0D, 0, 0, 0) # ENTER down
time.sleep(0.05)
user32.keybd_event(0x0D, 0, 2, 0) # ENTER up
print("Enter pressed.")

# Or click send button at x=865, y=880
time.sleep(0.5)
user32.SetCursorPos(865, 880)
time.sleep(0.1)
user32.mouse_event(0x0002, 0, 0, 0, 0)
time.sleep(0.05)
user32.mouse_event(0x0004, 0, 0, 0, 0)
print("Send button clicked.")

# User Rule: Wait 3 seconds
print("Waiting 3 seconds to check chatbox...")
time.sleep(3.0)
print("3 seconds elapsed.")
