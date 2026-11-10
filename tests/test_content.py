"""
Automated Verification Suite for CMS & Content Pages (CONTENT-001..005)
Baseline: BL-HAMICARD-PRD-V1
Tests:
1. Seeding of standard institutional pages (Terms, Privacy, About Us, FAQ, Contact).
2. Public retrieval of published pages by slug.
3. Slug formatting and validation guards.
4. Visibility guards for unpublished drafts.
5. Administrative update, publish toggle, and audit trail.
6. Page deletion and cleanup.
"""

import asyncio
import os
import uuid
import asyncpg

from src.content.service import (
    ContentService, ContentError, PageNotFoundError, InvalidSlugError
)

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


async def test_seed_and_retrieve_default_pages(pool: asyncpg.Pool):
    print("\n[CMS TEST 1/4] Testing Standard Content Pages Seeding & Public Retrieval...")
    content_svc = ContentService(pool)

    # 1. Seed pages
    count = await content_svc.seed_default_pages()
    assert count >= 5, f"Expected at least 5 default pages, got {count}."
    print(f"  ✓ Successfully seeded {count} standard pages (terms, privacy, about-us, faq, contact).")

    # 2. Retrieve Terms page
    terms = await content_svc.get_published_page("terms")
    assert terms["slug"] == "terms"
    assert "قوانین و مقررات" in terms["title"]
    assert "حامی‌کارت" in terms["body_html"]
    print("  ✓ Public retrieval of 'terms' page verified.")

    # 3. Retrieve FAQ page
    faq = await content_svc.get_published_page("faq")
    assert faq["slug"] == "faq"
    assert "پرسش‌های متداول" in faq["title"]
    print("  ✓ Public retrieval of 'faq' page verified.")


async def test_slug_validation(pool: asyncpg.Pool):
    print("\n[CMS TEST 2/4] Testing Slug Validation Guards...")
    content_svc = ContentService(pool)

    invalid_slugs = [
        "page with spaces",
        "invalid@char",
        "UPPERCASE_NOT_ALLOWED!",
        "",
        "a" # too short
    ]

    for bad_slug in invalid_slugs:
        blocked = False
        try:
            content_svc.validate_slug(bad_slug)
        except InvalidSlugError:
            blocked = True
        assert blocked, f"Invalid slug '{bad_slug}' was not blocked!"

    print("  ✓ Invalid slug formats strictly rejected.")

    # Valid slugs
    assert content_svc.validate_slug("valid-slug-123") == "valid-slug-123"
    assert content_svc.validate_slug("about_us") == "about_us"
    print("  ✓ Valid kebab-case and snake_case slugs accepted.")


async def test_unpublished_page_guards(pool: asyncpg.Pool):
    print("\n[CMS TEST 3/4] Testing Draft / Unpublished Page Security Guards...")
    content_svc = ContentService(pool)

    test_slug = f"draft-{uuid.uuid4().hex[:6]}"

    # Create unpublished draft
    page = await content_svc.upsert_page(
        slug=test_slug,
        title="Draft Announcment",
        body_html="<p>Confidential Internal Draft</p>",
        is_published=False
    )
    assert page["is_published"] is False

    # 1. Public retrieval must fail
    public_blocked = False
    try:
        await content_svc.get_published_page(test_slug)
    except PageNotFoundError:
        public_blocked = True
    assert public_blocked, "Unpublished draft was accessible to public!"
    print("  ✓ Unpublished page hidden from public (Fail-Closed PASS).")

    # 2. Admin mode must allow retrieval
    admin_page = await content_svc.get_page_by_slug(test_slug, admin_mode=True)
    assert admin_page["slug"] == test_slug
    print("  ✓ Admin mode successfully retrieves unpublished draft.")

    # 3. Publish page
    await content_svc.upsert_page(
        slug=test_slug,
        title="Published Announcement",
        body_html="<p>Now public!</p>",
        is_published=True
    )
    public_after = await content_svc.get_published_page(test_slug)
    assert public_after["title"] == "Published Announcement"
    print("  ✓ Page becomes publicly accessible upon publication.")


async def test_page_audit_and_deletion(pool: asyncpg.Pool):
    print("\n[CMS TEST 4/4] Testing Audit Logging and Page Deletion...")
    content_svc = ContentService(pool)

    async with pool.acquire() as conn:
        admin_row = await conn.fetchrow(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id",
            f"0920{uuid.uuid4().int % 10000000:07d}"
        )

    del_slug = f"temp-{uuid.uuid4().hex[:6]}"
    await content_svc.upsert_page(
        slug=del_slug,
        title="Temporary Page",
        body_html="<p>Will be deleted</p>",
        is_published=True,
        updated_by=admin_row["id"]
    )

    # Delete page
    deleted = await content_svc.delete_page(del_slug, admin_id=admin_row["id"])
    assert deleted is True
    print("  ✓ Temporary page deleted successfully.")

    # Verify audit log was recorded
    async with pool.acquire() as conn:
        audit = await conn.fetchrow(
            """
            SELECT * FROM audit_logs
            WHERE entity_name = 'content_pages' AND entity_id = $1
            ORDER BY created_at DESC LIMIT 1
            """, del_slug
        )
        assert audit is not None
        assert audit["action"] == "CMS_PAGE_DELETED"
        assert audit["actor_user_id"] == admin_row["id"]
        print("  ✓ Deletion audit log confirmed in audit_logs table.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_seed_and_retrieve_default_pages(pool)
        await test_slug_validation(pool)
        await test_unpublished_page_guards(pool)
        await test_page_audit_and_deletion(pool)
        print("\n" + "=" * 70)
        print("ALL 4 CMS & CONTENT PAGES TEST SUITES PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
