import random
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from ...schemas.alert import SecurityAlert, AlertStatusUpdate, BlockIpRequest, BlockIpResponse
from ...storage.db import db

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=list[SecurityAlert])
def list_alerts(
    severity: Optional[str] = Query(None),
    attackType: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    detectionSource: Optional[str] = Query(None),
    captureId: Optional[str] = Query(None),
    sourceType: Optional[str] = Query(None),
    timeRange: Optional[str] = Query(None),
    sortBy: Optional[str] = Query("created_at"),
    sortOrder: Optional[str] = Query("desc"),
    offset: Optional[int] = Query(0),
    limit: Optional[int] = Query(None)
):
    alerts = db.get_alerts(
        severity=severity,
        attack_type=attackType,
        status=status,
        search=search,
        detection_source=detectionSource,
        capture_id=captureId,
        source_type=sourceType,
        time_range=timeRange,
        sort_by=sortBy,
        sort_order=sortOrder,
        offset=offset,
        limit=limit
    )
    return alerts

@router.delete("/clear")
def clear_alerts(captureId: Optional[str] = Query(None)):
    count = db.clear_alerts(capture_id=captureId)
    return {"success": True, "deletedCount": count}

@router.get("/summary")
def get_alerts_summary(
    captureId: Optional[str] = Query(None),
    sourceType: Optional[str] = Query(None),
    timeRange: Optional[str] = Query(None)
):
    return db.get_alerts_summary(
        capture_id=captureId,
        source_type=sourceType,
        time_range=timeRange
    )

@router.get("/{alert_id}", response_model=SecurityAlert)
def get_alert_detail(alert_id: str):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")
    return alert

@router.patch("/{alert_id}/status")
def update_alert_status(alert_id: str, update: AlertStatusUpdate):
    success = db.update_alert_status(alert_id, update.status)
    if not success:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found")
    return {"success": True, "id": alert_id, "status": update.status}

@router.post("/block-ip", response_model=BlockIpResponse)
def block_ip(req: BlockIpRequest):
    # Safe, non-destructive simulated host quarantine rule ID
    rule_id = f"FW-BLOCK-{random.randint(10000, 99999)}"
    return BlockIpResponse(
        success=True,
        ruleId=rule_id,
        message=f"Simulated firewall rule generated for {req.ipAddress}. No external systems were modified."
    )
