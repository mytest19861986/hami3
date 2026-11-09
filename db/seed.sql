-- ============================================================================
-- HamiCard (حامی‌کارت) Database Seed Data
-- 1. Provinces and Cities of Iran (PROFILE-004)
-- 2. Parametric System Settings for OPEN-01..18 (PRD Section 28)
-- 3. Default Discount Plans (PLAN-001)
-- 4. Default Content Pages (CONTENT-001..005)
-- ============================================================================

-- ============================================================================
-- 1. PROVINCES (استان‌های کشور)
-- ============================================================================

INSERT INTO provinces (id, name) VALUES
(1, 'تهران'),
(2, 'اصفهان'),
(3, 'فارس'),
(4, 'خراسان رضوی'),
(5, 'آذربایجان شرقی'),
(6, 'مازندران'),
(7, 'خوزستان'),
(8, 'البرز'),
(9, 'گیلان'),
(10, 'کرمان'),
(11, 'قم'),
(12, 'یزد'),
(13, 'هرمزگان'),
(14, 'مرکزی'),
(15, 'همدان'),
(16, 'کرمانشاه'),
(17, 'لرستان'),
(18, 'بوشهر'),
(19, 'قزوین'),
(20, 'زنجان'),
(21, 'سمنان'),
(22, 'گلستان'),
(23, 'اردبیل'),
(24, 'چهارمحال و بختیاری'),
(25, 'کردستان'),
(26, 'سیستان و بلوچستان'),
(27, 'خراسان جنوبی'),
(28, 'خراسان شمالی'),
(29, 'ایلام'),
(30, 'کهگیلویه و بویراحمد'),
(31, 'آذربایجان غربی')
ON CONFLICT (id) DO NOTHING;

-- Reset sequence for provinces
SELECT setval('provinces_id_seq', (SELECT MAX(id) FROM provinces));

-- ============================================================================
-- 2. MAJOR CITIES (شهرهای منتخب)
-- ============================================================================

INSERT INTO cities (province_id, name) VALUES
-- تهران
(1, 'تهران'), (1, 'شهریار'), (1, 'اسلامشهر'), (1, 'ری'), (1, 'دماوند'), (1, 'ورامین'),
-- اصفهان
(2, 'اصفهان'), (2, 'کاشان'), (2, 'نجف‌آباد'), (2, 'شاهین‌شهر'), (2, 'خمینی‌شهر'),
-- فارس
(3, 'شیراز'), (3, 'مرودشت'), (3, 'جهرم'), (3, 'فسا'), (3, 'کازرون'),
-- خراسان رضوی
(4, 'مشهد'), (4, 'نیشابور'), (4, 'سبزوار'), (4, 'تربت حیدریه'),
-- آذربایجان شرقی
(5, 'تبریز'), (5, 'مراغه'), (5, 'مرند'), (5, 'میانه'),
-- مازندران
(6, 'ساری'), (6, 'بابل'), (6, 'آمل'), (6, 'قائم‌شهر'),
-- خوزستان
(7, 'اهواز'), (7, 'دزفول'), (7, 'آبادان'), (7, 'خرمشهر'),
-- البرز
(8, 'کرج'), (8, 'فردیس'), (8, 'نظرآباد'), (8, 'هشتگرد'),
-- گیلان
(9, 'رشت'), (9, 'لاهیجان'), (9, 'بندر انزلی'), (9, 'لنگرود'),
-- کرمان
(10, 'کرمان'), (10, 'سیرجان'), (10, 'رفسنجان'), (10, 'جیرفت'),
-- قم
(11, 'قم'),
-- یزد
(12, 'یزد'), (12, 'میبد'), (12, 'اردکان')
ON CONFLICT (province_id, name) DO NOTHING;

-- ============================================================================
-- 3. SYSTEM SETTINGS: PARAMETRIC POLICY FOR OPEN-01 TO OPEN-18
-- ============================================================================

INSERT INTO system_settings (key, value_json, description, is_secret) VALUES
('OPEN_01_REFERRER_VS_AGENT_BOUNDARY', '{"allow_referrer_sales_cases": false, "referrer_requires_agent_approval": true}', 'مرز همکار معرفی و نماینده فروش: معرف فقط لینک/کد معرفی دارد و حق ثبت پرونده فروش حضوری ندارد مگر نقش نماینده او تأیید شود.', false),
('OPEN_02_DOCTOR_DISCOUNT_PRECEDENCE', '{"precedence": "CUSTOM_FIRST", "description": "در صورت وجود تخفیف اختصاصی پزشک، آن اعمال میشود؛ در غیر این صورت درصد طرح"}', 'تقدم درصد تخفیف پزشک بر طرح: CUSTOM_FIRST یا PLAN_FIRST', false),
('OPEN_03_AGENT_SALE_FINALIZATION_TRIGGER', '{"trigger": "PAYMENT_RECORDED_AND_CASE_APPROVED", "auto_activate_membership": true}', 'زمان قطعی شدن فروش نمایندگی و فعالسازی عضویت و پورسانت', false),
('OPEN_04_FINANCIAL_PERMISSIONS_MATRIX', '{"record_sale_payment": ["ADMIN", "SUPER_ADMIN"], "mark_settlement_paid": ["SUPER_ADMIN"], "edit_financial_settings": ["SUPER_ADMIN"]}', 'مجوز ثبت پرداخت فروش دستی و پرداخت تسویه خارج سامانه', false),
('OPEN_05_COMBINED_COMMISSION_POLICY', '{"allow_combined": false, "max_total_percent": 30.0}', 'جمع پورسانت فروش و معرفی و سقف مجاز', false),
('OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN', '{"min_amount_toman": 100000, "lock_on_request": true}', 'حداقل مبلغ تسویه و قاعده مسدودی موجودی در کیف پول', false),
('OPEN_07_VISIT_CANCELLATION_REFUND_POLICY', '{"restore_quota": true, "refund_requires_reason": true}', 'بازگشت اعتبار سهمیه و اصلاح پورسانت در لغو یا مرجوعی', false),
('OPEN_08_MULTI_ACTIVE_PLANS_PER_HOLDER', '{"allow_multiple_active_plans": false, "extension_adds_to_end_date": true}', 'سیاست چند طرح فعال همزمان برای یک دارنده (کد ملی)', false),
('OPEN_09_NATIONAL_CODE_PHONE_CONFLICT', '{"national_code_unique": true, "phone_change_requires_admin": true}', 'سیاست تناقض یا تغییر کد ملی و شماره موبایل', false),
('OPEN_10_RBAC_ADMIN_SUPPORT_MATRIX', '{"support_can_view_sheba": false, "support_can_approve_financials": false}', 'ماتریس دقیق اختیارات SUPPORT و ADMIN و SUPER_ADMIN', false),
('OPEN_11_EXTERNAL_ADAPTERS_CONFIG', '{"sms_provider": "mock", "payment_gateway": "mock", "is_production_ready": false}', 'پیکربندی سرویس پیامک و درگاه پرداخت (Sandbox / Manual)', false),
('OPEN_12_DATA_RETENTION_AND_SOFT_DELETE', '{"soft_delete_only": true, "retain_financial_records_days": -1}', 'سیاست نگهداری اسناد و حذف کاربر (حذف منطقی بدون پاکسازی فیزیکی مالی)', false),
('OPEN_13_BACKUP_RETENTION_POLICY', '{"daily_backups_kept": 7, "weekly_backups_kept": 4, "monthly_backups_kept": 6, "encrypt_with_age": true}', 'دوره نگهداری بکاپهای رمزنگاریشده روی سرور و Google Drive', false),
('OPEN_14_SLA_AND_RATE_LIMITS', '{"max_concurrent_users": 500, "api_p95_ms": 200, "otp_rate_limit_per_hour": 5}', 'معیارهای عددی بار، سرعت و محدودیت ارسال کد تایید', false),
('OPEN_15_THEME_AND_FONTS', '{"font_family": "Vazirmatn", "primary_color_hex": "#0d9488", "secondary_color_hex": "#059669"}', 'تنظیمات رنگ سازمانی (سبز زمردی/فیروزهای) و فونت فارسی وزیرمتن', false),
('OPEN_16_VISIT_MEDICAL_RECORD_LIMIT', '{"store_diagnosis": false, "store_full_emr": false, "allow_private_notes": true}', 'حد ثبت اطلاعات پزشکی در ویزیت جهت حفظ حریم خصوصی بیمار', false),
('OPEN_17_ADMIN_GRANT_PLAN_POLICY', '{"roles_allowed": ["ADMIN", "SUPER_ADMIN"], "mandatory_reason": true}', 'قاعده اعطای طرح بدون پرداخت توسط مدیر', false),
('OPEN_18_CURRENCY_AND_ROUNDING', '{"currency_stored": "TOMAN", "currency_display": "TOMAN", "rounding_mode": "FLOOR"}', 'واحد مبالغ (تومان صحیح BIGINT) و گرد کردن پورسانت به سمت پایین (Floor)', false)
ON CONFLICT (key) DO UPDATE SET 
    value_json = EXCLUDED.value_json,
    description = EXCLUDED.description,
    updated_at = NOW();

-- ============================================================================
-- 4. DEFAULT DISCOUNT PLANS (طرح‌های تخفیف پایه)
-- ============================================================================

INSERT INTO discount_plans (title, description, price_toman, discount_percent, validity_days, max_visits, agent_commission_percent, referrer_commission_percent, is_active) VALUES
('طرح سلامت نقره‌ای حامی‌کارت', 'شامل ۱۰ نوبت خدمات تخفیف درمانی در شبکه پزشکان طرف قرارداد با تخفیف ۳۰٪ به مدت ۱ سال', 350000, 30.00, 365, 10, 15.00, 5.00, true),
('طرح سلامت طلایی حامی‌کارت', 'شامل ۲۰ نوبت خدمات تخفیف درمانی در شبکه پزشکان طرف قرارداد با تخفیف ۴۰٪ به مدت ۱ سال', 650000, 40.00, 365, 20, 18.00, 7.00, true),
('طرح جامع درمانی الماس حامی‌کارت', 'خدمات تخفیف درمانی بدون محدودیت سقف تعداد نوبت (نامحدود) با تخفیف ۵۰٪ به مدت ۱ سال', 1200000, 50.00, 365, NULL, 20.00, 10.00, true)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 5. DEFAULT CONTENT PAGES (صفحات عمومی و قوانین)
-- ============================================================================

INSERT INTO content_pages (slug, title, body_html, is_published) VALUES
('home', 'صفحه اصلی حامی‌کارت', '<h1>سامانه حامی‌کارت</h1><p>بستری امن برای دسترسی به خدمات تخفیف درمانی، شبکه پزشکان و نمایندگان فروش.</p>', true),
('about-us', 'درباره حامی‌کارت', '<h2>درباره حامی‌کارت</h2><p>حامی‌کارت با هدف کاهش هزینه‌های درمان و ارتقای سلامت خانواده‌های ایرانی طراحی شده است.</p>', true),
('terms', 'قوانین و شرایط استفاده', '<h2>قوانین حامی‌کارت</h2><p>استفاده از خدمات حامی‌کارت منوط به رعایت ضوابط قانونی و استانداردهای درمانی است.</p>', true),
('privacy', 'سیاست حریم خصوصی', '<h2>حریم خصوصی</h2><p>اطلاعات پزشکی، هویتی و بانکی کاربران با استانداردهای امنیتی سخت‌گیرانه محافظت می‌شود.</p>', true),
('faq', 'پرسش‌های متداول', '<h2>پرسش‌های متداول</h2><p>پاسخ به سوالات رایج پیرامون نحوه خرید طرح، دریافت کارت، مراجعه به پزشک و دریافت پورسانت.</p>', true)
ON CONFLICT (slug) DO UPDATE SET
    title = EXCLUDED.title,
    body_html = EXCLUDED.body_html,
    is_published = EXCLUDED.is_published,
    updated_at = NOW();
