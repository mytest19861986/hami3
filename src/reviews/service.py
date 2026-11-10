"""
Doctor Reviews & Ratings Domain Service (REVIEW-001..004)
Allows verified patients to submit clinical ratings and comments for completed visits.
Enforces the single-review per visit invariant and administrative moderation.
"""

import uuid
from typing import Any, Dict

import asyncpg


class ReviewError(Exception):
    """Base exception for review operations."""
    pass


class DuplicateReviewError(ReviewError):
    """Raised when a visit has already been reviewed."""
    pass


class InvalidRatingError(ReviewError):
    """Raised when rating is not an integer between 1 and 5."""
    pass


class DoctorReviewService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def submit_review(
        self,
        visit_id: uuid.UUID,
        user_id: uuid.UUID,
        rating: int,
        comment: str | None = None
    ) -> Dict[str, Any]:
        """Submits a patient review for a completed medical visit."""
        if not (1 <= rating <= 5):
            raise InvalidRatingError("Rating must be an integer between 1 and 5.")

        async with self.pool.acquire() as conn:
            # 1. Verify visit exists, is COMPLETED
            visit = await conn.fetchrow(
                "SELECT id, doctor_id, status FROM visits WHERE id = $1", visit_id
            )
            if not visit:
                raise ReviewError(f"Visit {visit_id} not found.")
            if visit["status"] != "COMPLETED":
                raise ReviewError("Reviews can only be submitted for COMPLETED visits.")

            doctor_id = visit["doctor_id"]

            # 2. Check if already reviewed
            existing = await conn.fetchrow(
                "SELECT id FROM doctor_reviews WHERE visit_id = $1", visit_id
            )
            if existing:
                raise DuplicateReviewError("A review has already been submitted for this visit.")

            # 3. Insert review in pending moderation state (is_published = FALSE)
            row = await conn.fetchrow(
                """
                INSERT INTO doctor_reviews (
                    visit_id, user_id, doctor_id, rating, comment, is_published
                ) VALUES ($1, $2, $3, $4, $5, FALSE)
                RETURNING id, visit_id, user_id, doctor_id, rating, comment, is_published, created_at
                """,
                visit_id, user_id, doctor_id, rating, comment.strip() if comment else None
            )
            return dict(row)

    async def moderate_review(
        self,
        review_id: uuid.UUID,
        is_published: bool,
        admin_id: uuid.UUID
    ) -> Dict[str, Any]:
        """Admin approves or hides review from public directory."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE doctor_reviews
                SET is_published = $1,
                    reviewed_by = $2
                WHERE id = $3
                RETURNING *
                """, is_published, admin_id, review_id
            )
            if not row:
                raise ReviewError(f"Review {review_id} not found.")

            # Audit log
            await conn.execute(
                """
                INSERT INTO audit_logs (
                    actor_user_id, action, entity_name, entity_id, new_values
                ) VALUES (
                    $1, 'REVIEW_MODERATED', 'doctor_reviews', $2::varchar,
                    jsonb_build_object('is_published', $3::boolean)
                )
                """, admin_id, str(review_id), is_published
            )
            return dict(row)

    async def get_doctor_reviews(
        self,
        doctor_id: uuid.UUID,
        published_only: bool = True
    ) -> Dict[str, Any]:
        """Returns reviews and aggregate average rating for a doctor."""
        async with self.pool.acquire() as conn:
            where_clause = "WHERE doctor_id = $1" + (" AND is_published = TRUE" if published_only else "")

            # Aggregate stats
            stats = await conn.fetchrow(
                f"""
                SELECT COUNT(*) as total_reviews,
                       COALESCE(ROUND(AVG(rating), 2), 0.0) as average_rating
                FROM doctor_reviews
                {where_clause}
                """, doctor_id
            )

            # Item list
            items = await conn.fetch(
                f"""
                SELECT id, rating, comment, is_published, created_at
                FROM doctor_reviews
                {where_clause}
                ORDER BY created_at DESC
                LIMIT 50
                """, doctor_id
            )

            return {
                "doctor_id": str(doctor_id),
                "total_reviews": int(stats["total_reviews"]),
                "average_rating": float(stats["average_rating"]),
                "reviews": [dict(r) for r in items]
            }
