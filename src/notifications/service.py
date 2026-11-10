"""
Notifications Domain Service (NOTICE-001..005)
Manages user alerts, status updates (visit confirmed, settlement paid, review approved),
and in-app messaging with unread badges and timestamps.
"""

import uuid
from typing import Any, Dict, List

import asyncpg


class NotificationError(Exception):
    """Base exception for notification operations."""
    pass


class NotificationService:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def create_notification(
        self,
        user_id: uuid.UUID,
        title: str,
        message: str,
        link_url: str | None = None
    ) -> Dict[str, Any]:
        """Creates a new in-app notification for a user."""
        title_clean = title.strip()
        msg_clean = message.strip()
        if not title_clean or not msg_clean:
            raise NotificationError("Title and message cannot be empty.")

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO notifications (user_id, title, message, link_url, is_read)
                VALUES ($1, $2, $3, $4, FALSE)
                RETURNING id, user_id, title, message, link_url, is_read, created_at
                """, user_id, title_clean, msg_clean, link_url
            )
            return dict(row)

    async def get_user_notifications(
        self,
        user_id: uuid.UUID,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieves user notification history with pagination."""
        async with self.pool.acquire() as conn:
            clause = "WHERE user_id = $1" + (" AND is_read = FALSE" if unread_only else "")
            rows = await conn.fetch(
                f"""
                SELECT id, title, message, link_url, is_read, read_at, created_at
                FROM notifications
                {clause}
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                """, user_id, limit, offset
            )
            return [dict(r) for r in rows]

    async def get_unread_count(self, user_id: uuid.UUID) -> int:
        """Returns the number of unread notifications for bell badge."""
        async with self.pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE",
                user_id
            )
            return count or 0

    async def mark_as_read(self, notification_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        """Marks a single notification as read."""
        async with self.pool.acquire() as conn:
            res = await conn.execute(
                """
                UPDATE notifications
                SET is_read = TRUE, read_at = NOW()
                WHERE id = $1 AND user_id = $2 AND is_read = FALSE
                """, notification_id, user_id
            )
            return "UPDATE 1" in res

    async def mark_all_as_read(self, user_id: uuid.UUID) -> int:
        """Marks all unread notifications of a user as read."""
        async with self.pool.acquire() as conn:
            res = await conn.execute(
                """
                UPDATE notifications
                SET is_read = TRUE, read_at = NOW()
                WHERE user_id = $1 AND is_read = FALSE
                """, user_id
            )
            # Parse number of updated rows
            try:
                return int(res.split(" ")[1])
            except (IndexError, ValueError):
                return 0
