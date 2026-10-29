from typing import Optional
from fastapi import APIRouter, HTTPException
from ...schemas.notification import NotificationItem, NotificationCountResponse
from ...storage.db import db

router = APIRouter(prefix="/notifications", tags=["Notifications"])

@router.get("", response_model=list[NotificationItem])
def get_notifications(
    severity: Optional[str] = None,
    detection_source: Optional[str] = None,
    unread_only: bool = False,
    limit: int = 50
):
    return db.get_notifications(
        severity=severity,
        detection_source=detection_source,
        unread_only=unread_only,
        limit=limit
    )

@router.get("/unread-count", response_model=NotificationCountResponse)
def get_unread_count():
    unread = db.get_unread_notifications_count()
    all_notifs = db.get_notifications(limit=1000)
    return NotificationCountResponse(
        unreadCount=unread,
        totalCount=len(all_notifs)
    )

@router.patch("/{notification_id}/read")
def mark_notification_read(notification_id: str):
    success = db.mark_notification_read(notification_id)
    if not success:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"success": True, "id": notification_id}

@router.post("/mark-all-read")
def mark_all_read():
    count = db.mark_all_notifications_read()
    return {"success": True, "markedCount": count}

@router.delete("/{notification_id}")
def dismiss_notification(notification_id: str):
    success = db.dismiss_notification(notification_id)
    if not success:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"success": True, "id": notification_id, "dismissed": True}

@router.delete("/clear/read")
def clear_read_notifications():
    count = db.clear_read_notifications()
    return {"success": True, "clearedCount": count}
