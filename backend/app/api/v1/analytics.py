from fastapi import APIRouter, Query
from ...schemas.analytics import DashboardStats, TrafficTimelinePoint, ProtocolDistribution
from ...core.state import global_state
from ...storage.db import db

router = APIRouter(prefix="", tags=["Analytics & Dashboard"])

@router.get("/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(timeRange: str = Query("1H")):
    alerts = db.get_alerts()
    recent = alerts[:4]

    # Compute threat score
    threat_score = 40
    if any(a.severity == "CRITICAL" for a in alerts):
        threat_score = 92
    elif any(a.severity == "HIGH" for a in alerts):
        threat_score = 78
    elif any(a.severity == "MEDIUM" for a in alerts):
        threat_score = 65

    # Timeline points
    timeline = get_traffic_timeline(timeRange)
    protos = get_protocol_distribution()

    total_pkts = global_state.total_packets_count

    return DashboardStats(
        totalPackets=total_pkts,
        activeHosts=global_state.get_active_hosts_count(),
        threatsCount=len(alerts),
        threatScore=threat_score,
        networkStatus="Monitoring Active" if global_state.is_monitoring else "Paused",
        trafficTimeline=timeline,
        protocolDistribution=protos,
        recentAlerts=recent
    )

@router.get("/analytics/timeline", response_model=list[TrafficTimelinePoint])
def get_traffic_timeline(timeRange: str = Query("1H")):
    pps, _ = global_state.get_rates()
    current_pps = pps if global_state.is_monitoring else 0

    if timeRange == "24H":
        return [
            TrafficTimelinePoint(time="12:00", packets=6500),
            TrafficTimelinePoint(time="16:00", packets=8200),
            TrafficTimelinePoint(time="20:00", packets=4100),
            TrafficTimelinePoint(time="00:00", packets=1200),
            TrafficTimelinePoint(time="04:00", packets=950),
            TrafficTimelinePoint(time="08:00", packets=9400),
            TrafficTimelinePoint(time="12:00", packets=current_pps)
        ]
    elif timeRange == "6H":
        return [
            TrafficTimelinePoint(time="05:00", packets=840),
            TrafficTimelinePoint(time="06:00", packets=1100),
            TrafficTimelinePoint(time="07:00", packets=2400),
            TrafficTimelinePoint(time="08:00", packets=5200),
            TrafficTimelinePoint(time="09:00", packets=9100),
            TrafficTimelinePoint(time="10:00", packets=current_pps)
        ]
    else:  # 1H default
        return [
            TrafficTimelinePoint(time="10:00", packets=1420),
            TrafficTimelinePoint(time="10:15", packets=1680),
            TrafficTimelinePoint(time="10:30", packets=4890),
            TrafficTimelinePoint(time="10:45", packets=12842),
            TrafficTimelinePoint(time="11:00", packets=current_pps)
        ]

@router.get("/analytics/protocols", response_model=list[ProtocolDistribution])
def get_protocol_distribution():
    return [
        ProtocolDistribution(name="TCP", value=61.0, color="#06b6d4"),
        ProtocolDistribution(name="UDP", value=24.0, color="#3b82f6"),
        ProtocolDistribution(name="ICMP", value=9.0, color="#f59e0b"),
        ProtocolDistribution(name="ARP", value=6.0, color="#10b981")
    ]
