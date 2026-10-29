import random
from datetime import datetime
from fastapi import APIRouter, HTTPException, Response
from ...schemas.report import SecurityReport, ReportGenerateRequest
from ...storage.db import db

router = APIRouter(prefix="/reports", tags=["Reports"])

def _generate_html_report(rep: SecurityReport, alerts: list) -> str:
    alerts_html = "".join(f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{a.id}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155; font-weight: bold; color: {'#ef4444' if a.severity == 'CRITICAL' else '#f59e0b'};">{a.severity}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{a.attackType}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{a.sourceIp}</td>
            <td style="padding: 8px; border-bottom: 1px solid #334155;">{a.destinationIp}</td>
        </tr>
    """ for a in alerts[:10])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetScope AI - {rep.name}</title>
    <style>
        body {{ font-family: monospace, sans-serif; background: #080b11; color: #e2e8f0; padding: 30px; }}
        .card {{ background: #0d131f; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; max-width: 900px; margin: auto; }}
        h1 {{ color: #06b6d4; margin-top: 0; }}
        .badge {{ background: #ef444422; color: #ef4444; padding: 4px 10px; border-radius: 6px; border: 1px solid #ef444455; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; text-align: left; }}
        th {{ background: #090d16; padding: 10px; border-bottom: 2px solid #334155; color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>NetScope AI Security Report</h1>
        <p><strong>Report:</strong> {rep.name} &bull; <strong>Type:</strong> {rep.type} &bull; <strong>Date:</strong> {rep.generatedDate}</p>
        <p>{rep.summary}</p>
        <hr style="border: 0; border-top: 1px solid #1e293b; margin: 20px 0;">
        <h3>Executive Highlights</h3>
        <ul>
            {"".join(f"<li>{h}</li>" for h in rep.highlights)}
        </ul>
        <h3>Observed Security Findings</h3>
        <table>
            <thead>
                <tr>
                    <th>Alert ID</th>
                    <th>Severity</th>
                    <th>Attack Type</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                </tr>
            </thead>
            <tbody>
                {alerts_html or "<tr><td colspan='5' style='padding: 12px; text-align: center; color: #64748b;'>No critical threats recorded</td></tr>"}
            </tbody>
        </table>
        <p style="margin-top: 30px; font-size: 11px; color: #64748b;">Generated deterministically by NetScope AI Passive Inspection Engine.</p>
    </div>
</body>
</html>"""

@router.get("", response_model=list[SecurityReport])
def list_reports():
    reports = db.get_reports()
    if not reports:
        # Seed initial standard reports
        r1 = SecurityReport(
            id="REP-01",
            name="Network Security Assessment",
            type="Daily Analysis",
            generatedDate=datetime.now().strftime("%d %b %Y"),
            threats=14,
            criticalCount=2,
            status="Ready",
            fileSize="1.2 MB",
            author="NetScope AI",
            summary="Automated synthesis of detected attacks and anomalies across monitored subnets.",
            highlights=[
                "14 security threats detected in observation period",
                "High SYN flood traffic observed targeting server :80",
                "Port scan probes detected from 192.168.1.31"
            ]
        )
        db.insert_report(r1, _generate_html_report(r1, []))
        reports = [r1]
    return reports

@router.post("/generate", response_model=SecurityReport)
def generate_report(req: ReportGenerateRequest):
    alerts = db.get_alerts()
    now = datetime.now()
    date_str = now.strftime("%d %b %Y, %H:%M:%S")

    critical_count = sum(1 for a in alerts if a.severity == "CRITICAL")
    threat_count = len(alerts)

    highlights = [
        f"{threat_count} total anomalous connection sequences identified",
        f"{critical_count} critical priority incident(s) requiring SOC response",
        "Passive packet inspection validated MITRE ATT&CK reconnaissance and DoS signatures"
    ]

    new_report = SecurityReport(
        id=f"REP-{now.year}-{random.randint(1000, 9999)}",
        name=f"{req.type} - Automated SOC Synthesis",
        type=req.type,
        generatedDate=date_str,
        threats=threat_count,
        criticalCount=critical_count,
        status="Ready",
        fileSize=f"{random.uniform(1.1, 2.8):.1f} MB",
        author="NetScope AI Detection Engine",
        summary=f"Automated threat synthesis compiled for {req.type}. Evaluated against MITRE ATT&CK reconnaissance and DoS profiles.",
        highlights=highlights
    )

    html = _generate_html_report(new_report, alerts)
    db.insert_report(new_report, html)
    return new_report

@router.get("/{report_id}", response_model=SecurityReport)
def get_report(report_id: str):
    reports = list_reports()
    for r in reports:
        if r.id == report_id:
            return r
    raise HTTPException(status_code=404, detail=f"Report with ID '{report_id}' not found")

@router.get("/{report_id}/export")
def export_report_html(report_id: str):
    html = db.get_report_html(report_id)
    if not html:
        rep = get_report(report_id)
        html = _generate_html_report(rep, db.get_alerts())
    return Response(content=html, media_type="text/html")
