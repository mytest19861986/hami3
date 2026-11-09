# پرامپت انتقال به چت جدید Antigravity (Handoff & Resume Prompt)

هر زمان خواستید در یک پنجره/چت جدید در **Antigravity IDE** کار را ادامه دهید، کافی است متن داخل کادر زیر را کپی کرده و در اولین پیام به چت جدید بدهید:

---

## متن آماده کپی برای چت جدید Antigravity:

```text
ما در حال اجرای پروژه «حامی‌کارت (HamiCard)» در فضای کاری d:\project\hami3 هستیم.
پروتکل اجرایی، وضعیت پروژه، نقشه راه ۱۰ فازی و دفترکل تسک‌ها از قبل در پوشه پروژه آماده و قفل شده‌اند.

قبل از هر کاری، بدون مقدمه و تعارف، این ۵ فایل را بخوان تا کاملاً در جریان وضعیت فعلی قرار بگیری:
1. @[d:\project\hami3\prompts\MASTER_COMMANDER_v4.3_FULL.md] (پروتکل فرماندهی و قوانین غیرقابل‌مذاکره)
2. @[d:\project\hami3\.orchestration\STATE.json] (آخرین وضعیت پروژه و تصمیم‌ها)
3. @[d:\project\hami3\.orchestration\PRODUCT_BASELINE_MANIFEST.md] (شناسنامه مرجع محصول BL-HAMICARD-PRD-V1)
4. @[d:\project\hami3\docs\MASTER_ROADMAP_FA.md] (نقشه راه ۱۰ فازی، معماری و پیشنهادهای OPEN-01..18)
5. @[d:\project\hami3\docs\PRD_HamiCard_v1.0_FA.md] (سند جامع نیازمندی‌های محصول)

همچنین مهارت‌های زیر را برای هماهنگی چندعاملی در نظر داشته باش:
- C:\Users\IT\.gemini\config\skills\loop-orchestrator\SKILL.md
- C:\Users\IT\.gemini\config\skills\commander-bridge\SKILL.md
- C:\Users\IT\.gemini\config\skills\ai-site-runner\SKILL.md
- C:\Users\IT\.gemini\config\skills\result-synthesizer\SKILL.md

نقش تو در این پروژه:
- تو هم‌زمان Coordinator (مدیریت STATE.json و ledger.jsonl و ارتباط با ایجنت‌های مرورگر Qwen و GLM) و Primary Executor / Codex (کدنویسی صفر تا صد در d:\project\hami3، تست، گیت و داکر) هستی.
- فرمانده کل پروژه (Master Commander) در ChatGPT است (که یا دستوراتش را من به تو می‌دهم یا از طریق مرورگر با commander-bridge از او می‌گیری).
- بازبین‌های مستقل (Reviewers) طبق قانون Builder ≠ Final Judge، دو ایجنت Qwen و GLM در مرورگر هستند.

وظیفه فوری تو در این نوبت:
1. فایل‌های بالا و وضعیت `d:\project\hami3\.orchestration\ledger.jsonl` را بررسی کن.
2. کامیت اولیه زیرساخت‌های ارکستریشن را در گیت ثبت کن.
3. بلافاصله اجرای تسک `T-01-ARCH-AND-OPEN-DECISIONS` (فاز ۱ نقشه راه: ایجاد ساختار پروژه، `docker-compose.dev.yml` برای PostgreSQL 16 و Redis 7، و طراحی کامل Database Schema برای ۲۱ موجودیت PRD + جدول تنظیمات OPEN-01..18) را آغاز کن و گزارش استاندارد را همراه با بلاک JSON اسکیمای `commander.v2` تحویل بده.
```
