"""
Automated Verification Suite for Doctor Reviews & In-App Notifications (REVIEW-001..004, NOTICE-001..005)
Baseline: BL-HAMICARD-PRD-V1
Tests:
1. Review submission for completed visits.
2. Single-review per visit invariant.
3. Rating boundary validation (1..5).
4. Review moderation lifecycle and aggregate rating computation.
5. In-app notification creation, unread count badge, and read acknowledgments.
"""

import asyncio
import os
import uuid
import asyncpg

from src.reviews.service import (
    DoctorReviewService, ReviewError, DuplicateReviewError, InvalidRatingError
)
from src.notifications.service import (
    NotificationService, NotificationError
)

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


async def test_review_submission_and_invariants(pool: asyncpg.Pool):
    print("\n[REVIEW TEST 1/4] Testing Review Submission & Single-Review Invariant...")
    review_svc = DoctorReviewService(pool)

    async with pool.acquire() as conn:
        doc_user = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0954{uuid.uuid4().int % 10000000:07d}")
        patient_user = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0955{uuid.uuid4().int % 10000000:07d}")
        doc = await conn.fetchrow(
            "INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Cardio', 'Cardio Clinic', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id",
            doc_user["id"], f"MED-{uuid.uuid4().hex[:6]}"
        )
        holder = await conn.fetchrow("INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('رضا', 'نیکزاد', $1, $2) RETURNING id", f"{uuid.uuid4().int % 1000000000:010d}", f"0956{uuid.uuid4().int % 10000000:07d}")
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days) VALUES ('طرح پایه', 100000, 20.0, 30) RETURNING id")
        mem = await conn.fetchrow("INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 5, 5, 0, 'ACTIVE') RETURNING id", holder["id"], plan["id"])
        # Completed visit
        visit = await conn.fetchrow(
            """
            INSERT INTO visits (
                doctor_id, holder_id, membership_id, service_title,
                total_amount_toman, discount_percent, discount_amount_toman,
                patient_paid_amount_toman, status
            ) VALUES ($1, $2, $3, 'معاینه قلب', 300000, 20.0, 60000, 240000, 'COMPLETED')
            RETURNING id
            """, doc["id"], holder["id"], mem["id"]
        )

    # 1. Invalid rating guards
    invalid_rating_blocked = False
    try:
        await review_svc.submit_review(visit_id=visit["id"], user_id=patient_user["id"], rating=6)
    except InvalidRatingError:
        invalid_rating_blocked = True
    assert invalid_rating_blocked, "Rating > 5 was allowed!"
    print("  ✓ Invalid rating guard PASS: Rating > 5 rejected.")

    # 2. Valid review submission
    review = await review_svc.submit_review(
        visit_id=visit["id"],
        user_id=patient_user["id"],
        rating=5,
        comment="بسیار پزشک باحوصله و بااخلاقی بودند."
    )
    assert review["id"] is not None
    assert review["rating"] == 5
    assert review["is_published"] is False
    print("  ✓ Review submitted in moderation state (is_published=FALSE).")

    # 3. Duplicate review on same visit must be blocked
    duplicate_blocked = False
    try:
        await review_svc.submit_review(
            visit_id=visit["id"],
            user_id=patient_user["id"],
            rating=4,
            comment="تلاش مجدد برای ثبت نظر"
        )
    except DuplicateReviewError:
        duplicate_blocked = True
    assert duplicate_blocked, "Duplicate review on same visit was allowed!"
    print("  ✓ Invariant PASS: Single review per visit enforced.")


async def test_review_moderation_and_aggregates(pool: asyncpg.Pool):
    print("\n[REVIEW TEST 2/4] Testing Review Moderation & Average Rating Aggregate...")
    review_svc = DoctorReviewService(pool)

    async with pool.acquire() as conn:
        admin = await conn.fetchrow("INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id", f"0957{uuid.uuid4().int % 10000000:07d}")
        doc_user = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0958{uuid.uuid4().int % 10000000:07d}")
        patient = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0959{uuid.uuid4().int % 10000000:07d}")
        doc = await conn.fetchrow("INSERT INTO doctors (user_id, medical_council_code, specialty, clinic_name, province_id, city_id, clinic_address, clinic_phone, verification_status) VALUES ($1, $2, 'Eye', 'Eye Clinic', 1, 1, 'Addr', '111', 'APPROVED') RETURNING id", doc_user["id"], f"MED-{uuid.uuid4().hex[:6]}")
        holder = await conn.fetchrow("INSERT INTO plan_holders (first_name, last_name, national_code, mobile) VALUES ('ندا', 'رستمی', $1, $2) RETURNING id", f"{uuid.uuid4().int % 1000000000:010d}", f"0960{uuid.uuid4().int % 10000000:07d}")
        plan = await conn.fetchrow("INSERT INTO discount_plans (title, price_toman, discount_percent, validity_days) VALUES ('طرح چشم', 100000, 20.0, 30) RETURNING id")
        mem = await conn.fetchrow("INSERT INTO memberships (holder_id, plan_id, start_date, end_date, max_visits, remaining_visits, used_visits, status) VALUES ($1, $2, NOW(), NOW() + interval '30 days', 5, 5, 0, 'ACTIVE') RETURNING id", holder["id"], plan["id"])

        # Create 2 visits
        v1 = await conn.fetchrow("INSERT INTO visits (doctor_id, holder_id, membership_id, service_title, total_amount_toman, discount_percent, discount_amount_toman, patient_paid_amount_toman, status) VALUES ($1, $2, $3, 'معاینه ۱', 100000, 20.0, 20000, 80000, 'COMPLETED') RETURNING id", doc["id"], holder["id"], mem["id"])
        v2 = await conn.fetchrow("INSERT INTO visits (doctor_id, holder_id, membership_id, service_title, total_amount_toman, discount_percent, discount_amount_toman, patient_paid_amount_toman, status) VALUES ($1, $2, $3, 'معاینه ۲', 100000, 20.0, 20000, 80000, 'COMPLETED') RETURNING id", doc["id"], holder["id"], mem["id"])

    # Submit 2 reviews: rating 4 and rating 5
    r1 = await review_svc.submit_review(v1["id"], patient["id"], 4, "خوب بود")
    r2 = await review_svc.submit_review(v2["id"], patient["id"], 5, "عالی بود")

    # Before approval: 0 published reviews
    stats_before = await review_svc.get_doctor_reviews(doc["id"], published_only=True)
    assert stats_before["total_reviews"] == 0

    # Admin moderates and publishes both
    await review_svc.moderate_review(r1["id"], is_published=True, admin_id=admin["id"])
    await review_svc.moderate_review(r2["id"], is_published=True, admin_id=admin["id"])

    # After approval: 2 reviews, average = 4.5
    stats_after = await review_svc.get_doctor_reviews(doc["id"], published_only=True)
    assert stats_after["total_reviews"] == 2
    assert stats_after["average_rating"] == 4.5
    print("  ✓ Review moderation and aggregate rating verified: 2 reviews, avg rating = 4.50.")


async def test_notifications_lifecycle(pool: asyncpg.Pool):
    print("\n[NOTIFICATION TEST 3/4] Testing In-App Notifications Lifecycle...")
    notif_svc = NotificationService(pool)

    async with pool.acquire() as conn:
        user = await conn.fetchrow("INSERT INTO users (mobile) VALUES ($1) RETURNING id", f"0961{uuid.uuid4().int % 10000000:07d}")
        user_id = user["id"]

    # 1. Create 3 notifications
    n1 = await notif_svc.create_notification(user_id, "خوش‌آمدگویی", "به سامانه حامی‌کارت خوش آمدید.")
    n2 = await notif_svc.create_notification(user_id, "فعال‌سازی عضویت", "کارت عضویت شما با موفقیت صادر گردید.", "/dashboard/card")
    n3 = await notif_svc.create_notification(user_id, "واریز پورسانت", "مبلغ ۵۰،۰۰۰ تومان به کیف پول شما واریز شد.", "/dashboard/wallet")

    # 2. Check unread count -> 3
    unread_count = await notif_svc.get_unread_count(user_id)
    assert unread_count == 3
    print("  ✓ Unread notifications count verified: 3.")

    # 3. Mark single notification as read
    marked = await notif_svc.mark_as_read(n1["id"], user_id)
    assert marked is True
    assert await notif_svc.get_unread_count(user_id) == 2
    print("  ✓ Single notification marked as read (unread count: 2).")

    # 4. Mark all as read
    count_marked = await notif_svc.mark_all_as_read(user_id)
    assert count_marked == 2
    assert await notif_svc.get_unread_count(user_id) == 0
    print("  ✓ All notifications marked as read (unread count: 0).")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_review_submission_and_invariants(pool)
        await test_review_moderation_and_aggregates(pool)
        await test_notifications_lifecycle(pool)
        print("\n" + "=" * 70)
        print("ALL DOCTOR REVIEWS & NOTIFICATIONS TEST SUITES PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
