"""
CMS and Content Pages Domain Service (CONTENT-001..005)
Manages static and informational pages (Terms, Privacy, About Us, FAQ, Contact)
with markdown/HTML content, publishing controls, and administrative auditing.
"""

import uuid
import re
from typing import Dict, Any, List, Optional
import asyncpg


class ContentError(Exception):
    """Base exception for CMS errors."""
    pass


class PageNotFoundError(ContentError):
    """Raised when requested content page does not exist."""
    pass


class InvalidSlugError(ContentError):
    """Raised when slug format is invalid."""
    pass


DEFAULT_PAGES = [
    {
        "slug": "terms",
        "title": "قوانین و مقررات استفاده از حامی‌کارت",
        "body_html": """<h2>قوانین و مقررات سامانه خدمات رفاهی و درمانی حامی‌کارت</h2>
<p>به سامانه حامی‌کارت خوش آمدید. استفاده از خدمات این سامانه به منزله پذیرش کلیه شرایط و مقررات مندرج در این سند است.</p>
<h3>۱. تعاریف و کلیات</h3>
<p>حامی‌کارت بستری جهت معرفی و اتصال دارندگان کارت به مراکز درمانی، تشخیصی و بهداشتی طرف قرارداد با اعمال تخفیفات معین می‌باشد.</p>
<h3>۲. شرایط عضویت و صدور کارت</h3>
<p>کلیه اطلاعات وارد شده در زمان ثبت‌نام باید مطابق با مدارک هویتی رسمی (کد ملی و شناسنامه) باشد.</p>
<h3>۳. نحوه استفاده در مراکز درمانی</h3>
<p>دارندگان کارت موظفند قبل از دریافت خدمات، وضعیت فعال بودن اشتراک خود را به پذیرش مرکز درمانی اعلام نمایند.</p>""",
        "is_published": True
    },
    {
        "slug": "privacy",
        "title": "سیاست حفظ حریم خصوصی",
        "body_html": """<h2>سیاست حفظ حریم خصوصی کاربران حامی‌کارت</h2>
<p>سامانه حامی‌کارت متعهد به حفاظت از اطلاعات شخصی، سوابق هویتی و داده‌های مالی کاربران مطابق با استانداردهای امنیتی روز می‌باشد.</p>
<p>اطلاعات حساس مالی از جمله شماره کارت و شماره شبا صرفاً جهت تسویه‌حساب‌های قانونی پردازش شده و به صورت ماسک‌شده ذخیره و نمایش داده می‌شوند.</p>""",
        "is_published": True
    },
    {
        "slug": "about-us",
        "title": "درباره ما",
        "body_html": """<h2>درباره حامی‌کارت</h2>
<p>حامی‌کارت با هدف کاهش هزینه‌های درمانی خانواده‌ها و ارتقای سطح سلامت عمومی، شبکه‌ای گسترده از پزشکان متخصص، دندانپزشکان، مراکز تصویربرداری و آزمایشگاه‌های معتبر را در سراسر کشور گردهم آورده است.</p>""",
        "is_published": True
    },
    {
        "slug": "faq",
        "title": "پرسش‌های متداول",
        "body_html": """<h2>پرسش‌های متداول کاربران</h2>
<details>
  <summary><strong>چگونه می‌توانم از تخفیف پزشکان طرف قرارداد استفاده کنم؟</strong></summary>
  <p>پس از تهیه طرح و فعال‌سازی عضویت، با مراجعه به مرکز درمانی و ارائه کد ملی یا کارت عضویت، تخفیف مصوب اعمال می‌گردد.</p>
</details>
<details>
  <summary><strong>آیا کارت حامی‌کارت بیمه درمانی است؟</strong></summary>
  <p>خیر، حامی‌کارت کارت تخفیف مستقیم و خدمات رفاهی درمانی است و محدودیت‌های معمول بیمه‌های پایه را ندارد.</p>
</details>""",
        "is_published": True
    },
    {
        "slug": "contact",
        "title": "تماس با ما",
        "body_html": """<h2>راه‌های ارتباطی با پشتیبانی حامی‌کارت</h2>
<p>تلفن پشتیبانی: ۰۲۱-۹۱۰۰۰۰۰۰</p>
<p>ایمیل: support@hamikart.ir</p>
<p>ساعات پاسخگویی: شنبه تا چهارشنبه ۹ الی ۱۸، پنج‌شنبه ۹ الی ۱۴</p>""",
        "is_published": True
    }
]


class ContentService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @staticmethod
    def validate_slug(slug: str) -> str:
        """Validates slug: lowercase alphanumeric, hyphens, and underscores."""
        clean = slug.strip().lower()
        if not clean or not re.match(r"^[a-z0-9_-]{2,100}$", clean):
            raise InvalidSlugError(
                f"Invalid slug '{slug}'. Must be 2-100 characters of lowercase letters, digits, dashes or underscores."
            )
        return clean

    async def upsert_page(
        self,
        slug: str,
        title: str,
        body_html: str,
        is_published: bool = True,
        updated_by: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
        """Creates or updates a content page by slug, with administrative audit logging."""
        valid_slug = self.validate_slug(slug)
        title_clean = title.strip()
        if not title_clean:
            raise ContentError("Page title cannot be empty.")
        if not body_html.strip():
            raise ContentError("Page body cannot be empty.")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO content_pages (slug, title, body_html, is_published, updated_by)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (slug) DO UPDATE
                    SET title = EXCLUDED.title,
                        body_html = EXCLUDED.body_html,
                        is_published = EXCLUDED.is_published,
                        updated_by = EXCLUDED.updated_by,
                        updated_at = NOW()
                    RETURNING id, slug, title, body_html, is_published, updated_by, created_at, updated_at
                    """,
                    valid_slug, title_clean, body_html.strip(), is_published, updated_by
                )

                # Record audit log
                await conn.execute(
                    """
                    INSERT INTO audit_logs (
                        actor_user_id, actor_role, action, entity_name, entity_id,
                        new_values
                    ) VALUES (
                        $1, 'ADMIN', 'CMS_PAGE_UPSERTED', 'content_pages', $2::varchar,
                        jsonb_build_object('slug', $2::varchar, 'title', $3::varchar, 'is_published', $4::boolean)
                    )
                    """, updated_by, valid_slug, title_clean, is_published
                )

                return dict(row)

    async def get_published_page(self, slug: str) -> Dict[str, Any]:
        """Returns a published page by slug for public visitors."""
        valid_slug = self.validate_slug(slug)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, slug, title, body_html, updated_at
                FROM content_pages
                WHERE slug = $1 AND is_published = TRUE
                """, valid_slug
            )
            if not row:
                raise PageNotFoundError(f"Published page with slug '{slug}' not found.")
            return dict(row)

    async def get_page_by_slug(self, slug: str, admin_mode: bool = False) -> Dict[str, Any]:
        """Retrieves page by slug, optionally allowing unpublished in admin mode."""
        valid_slug = self.validate_slug(slug)
        async with self.pool.acquire() as conn:
            if admin_mode:
                row = await conn.fetchrow(
                    "SELECT * FROM content_pages WHERE slug = $1", valid_slug
                )
            else:
                row = await conn.fetchrow(
                    "SELECT * FROM content_pages WHERE slug = $1 AND is_published = TRUE", valid_slug
                )

            if not row:
                raise PageNotFoundError(f"Page '{slug}' not found.")
            return dict(row)

    async def list_pages(self, published_only: bool = True) -> List[Dict[str, Any]]:
        """Lists content pages with metadata."""
        async with self.pool.acquire() as conn:
            if published_only:
                rows = await conn.fetch(
                    """
                    SELECT id, slug, title, updated_at
                    FROM content_pages
                    WHERE is_published = TRUE
                    ORDER BY slug ASC
                    """
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT id, slug, title, is_published, updated_by, created_at, updated_at
                    FROM content_pages
                    ORDER BY slug ASC
                    """
                )
            return [dict(r) for r in rows]

    async def delete_page(self, slug: str, admin_id: uuid.UUID) -> bool:
        """Deletes a CMS page and records audit."""
        valid_slug = self.validate_slug(slug)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                res = await conn.execute(
                    "DELETE FROM content_pages WHERE slug = $1", valid_slug
                )
                if "DELETE 1" in res:
                    await conn.execute(
                        """
                        INSERT INTO audit_logs (
                            actor_user_id, actor_role, action, entity_name, entity_id
                        ) VALUES ($1, 'ADMIN', 'CMS_PAGE_DELETED', 'content_pages', $2)
                        """, admin_id, valid_slug
                    )
                    return True
                return False

    async def seed_default_pages(self, admin_id: Optional[uuid.UUID] = None) -> int:
        """Seeds default terms, privacy, about-us, faq, and contact pages."""
        seeded = 0
        for p in DEFAULT_PAGES:
            await self.upsert_page(
                slug=p["slug"],
                title=p["title"],
                body_html=p["body_html"],
                is_published=p["is_published"],
                updated_by=admin_id
            )
            seeded += 1
        return seeded
