"""
Notifications API Endpoints (NOTICE-001..005)
Manages user alerts, status updates, unread badges, and read confirmations.
"""

import uuid
from typing import Dict, Any, Optional
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status

from src.api.deps import get_db_pool, get_current_user
from src.notifications.service import NotificationService, NotificationError

router = APIRouter(prefix="/notifications", tags=["In-App Notifications"])


@router.get("")
async def get_my_notifications(
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Retrieves authenticated user notification history."""
    notif_svc = NotificationService(pool)
    return await notif_svc.get_user_notifications(
        user_id=current_user["id"],
        unread_only=unread_only,
        limit=limit,
        offset=offset
    )


@router.get("/unread-count")
async def get_unread_count(
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Returns number of unread notifications for bell badge."""
    notif_svc = NotificationService(pool)
    count = await notif_svc.get_unread_count(current_user["id"])
    return {"unread_count": count}


@router.put("/{notification_id}/read")
async def mark_as_read(
    notification_id: uuid.UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Marks a single notification as read."""
    notif_svc = NotificationService(pool)
    success = await notif_svc.mark_as_read(notification_id, current_user["id"])
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found or already marked as read."
        )
    return {"success": True}


@router.post("/read-all")
async def mark_all_as_read(
    current_user: Dict[str, Any] = Depends(get_current_user),
    pool: asyncpg.Pool = Depends(get_db_pool)
):
    """Marks all unread notifications of the user as read."""
    notif_svc = NotificationService(pool)
    updated_count = await notif_svc.mark_all_as_read(current_user["id"])
    return {"success": True, "updated_count": updated_count}
