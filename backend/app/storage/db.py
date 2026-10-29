import sqlite3
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from pathlib import Path
from ..config import settings
from ..schemas.alert import SecurityAlert, AlertEvidence
from ..schemas.notification import NotificationItem
from ..schemas.report import SecurityReport
from ..schemas.pcap import PcapAnalysisResult, TopProtocol, DetectedSignature, CaptureSession

class Database:
    def __init__(self, db_path: Path = settings.DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Alerts table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                timestamp TEXT NOT NULL,
                duration TEXT NOT NULL,
                status TEXT NOT NULL,
                threat_score INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                ai_explanation TEXT NOT NULL,
                recommendations_json TEXT NOT NULL,
                interface TEXT,
                detection_source TEXT DEFAULT 'RULE_ENGINE',
                model_name TEXT,
                model_version TEXT,
                anomaly_score REAL,
                decision_threshold REAL,
                observed_features_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            # Migration check for existing databases
            cursor.execute("PRAGMA table_info(alerts)")
            existing_cols = [row[1] for row in cursor.fetchall()]
            if "detection_source" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN detection_source TEXT DEFAULT 'RULE_ENGINE'")
            if "model_name" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN model_name TEXT")
            if "model_version" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN model_version TEXT")
            if "anomaly_score" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN anomaly_score REAL")
            if "decision_threshold" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN decision_threshold REAL")
            if "observed_features_json" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN observed_features_json TEXT")
            if "capture_id" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN capture_id TEXT")
            if "capture_name" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN capture_name TEXT")
            if "source_type" not in existing_cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN source_type TEXT DEFAULT 'PCAP'")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_capture_id ON alerts(capture_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_type ON alerts(source_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC)")

            # Captures table for session isolation
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS captures (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                filesize TEXT NOT NULL,
                packets_count INTEGER NOT NULL,
                unique_hosts_count INTEGER NOT NULL,
                tcp_connections_count INTEGER NOT NULL,
                threats_count INTEGER NOT NULL,
                rule_threats_count INTEGER NOT NULL DEFAULT 0,
                ml_threats_count INTEGER NOT NULL DEFAULT 0,
                duration_seconds REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'COMPLETED',
                analyzed_at TEXT NOT NULL,
                observed_hosts_json TEXT NOT NULL DEFAULT '[]',
                top_protocols_json TEXT NOT NULL DEFAULT '[]',
                detected_signatures_json TEXT NOT NULL DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_captures_analyzed_at ON captures(analyzed_at DESC)")

            # Reports table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                generated_date TEXT NOT NULL,
                threats INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                file_size TEXT NOT NULL,
                author TEXT NOT NULL,
                summary TEXT NOT NULL,
                highlights_json TEXT NOT NULL,
                html_content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # PCAP analysis history
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS pcap_history (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                filesize TEXT NOT NULL,
                packets_analyzed INTEGER NOT NULL,
                unique_hosts INTEGER NOT NULL,
                tcp_connections INTEGER NOT NULL,
                potential_threats INTEGER NOT NULL,
                duration_seconds REAL NOT NULL,
                top_protocols_json TEXT NOT NULL,
                detected_signatures_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            # Settings key-value
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings_kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """)

            # Notifications table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                alert_id TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                detection_source TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                is_dismissed INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_notif_read ON notifications(is_read)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_notif_dismissed ON notifications(is_dismissed)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at)")
            conn.commit()

    # Alert Methods
    def _row_to_alert(self, r: sqlite3.Row) -> SecurityAlert:
        ev_data = json.loads(r["evidence_json"])
        recs = json.loads(r["recommendations_json"])
        obs_feats = json.loads(r["observed_features_json"]) if r["observed_features_json"] else None
        keys = r.keys()
        return SecurityAlert(
            id=r["id"],
            title=r["title"],
            severity=r["severity"],
            attackType=r["attack_type"],
            sourceIp=r["source_ip"],
            destinationIp=r["destination_ip"],
            sourcePort=r["source_port"],
            destinationPort=r["destination_port"],
            timestamp=r["timestamp"],
            duration=r["duration"],
            status=r["status"],
            threatScore=r["threat_score"],
            evidence=AlertEvidence(**ev_data),
            aiExplanation=r["ai_explanation"],
            recommendations=recs,
            interface=r["interface"],
            detectionSource=r["detection_source"] or "RULE_ENGINE",
            modelName=r["model_name"],
            modelVersion=r["model_version"],
            anomalyScore=r["anomaly_score"],
            decisionThreshold=r["decision_threshold"],
            observedFeatures=obs_feats,
            captureId=r["capture_id"] if "capture_id" in keys else None,
            captureName=r["capture_name"] if "capture_name" in keys else None,
            sourceType=r["source_type"] if "source_type" in keys else "PCAP"
        )

    # Alert Methods
    def insert_alert(self, alert: SecurityAlert) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO alerts (
                id, title, severity, attack_type, source_ip, destination_ip,
                source_port, destination_port, timestamp, duration, status,
                threat_score, evidence_json, ai_explanation, recommendations_json, interface,
                detection_source, model_name, model_version, anomaly_score, decision_threshold, observed_features_json,
                capture_id, capture_name, source_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id,
                alert.title,
                alert.severity,
                alert.attackType,
                alert.sourceIp,
                alert.destinationIp,
                alert.sourcePort,
                alert.destinationPort,
                alert.timestamp,
                alert.duration,
                alert.status,
                alert.threatScore,
                alert.evidence.model_dump_json(),
                alert.aiExplanation,
                json.dumps(alert.recommendations),
                alert.interface or "All",
                alert.detectionSource or "RULE_ENGINE",
                alert.modelName,
                alert.modelVersion,
                alert.anomalyScore,
                alert.decisionThreshold,
                json.dumps(alert.observedFeatures) if alert.observedFeatures else None,
                alert.captureId,
                alert.captureName,
                alert.sourceType or "PCAP"
            ))

            # Automatically create notification with deduplication per alert ID
            notif_id = f"NTF-{alert.id}"
            cursor.execute("""
            INSERT OR IGNORE INTO notifications (
                id, alert_id, title, severity, attack_type, source_ip, destination_ip,
                timestamp, detection_source, is_read, is_dismissed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
            """, (
                notif_id,
                alert.id,
                alert.title,
                alert.severity,
                alert.attackType,
                alert.sourceIp,
                alert.destinationIp,
                alert.timestamp,
                alert.detectionSource or "RULE_ENGINE"
            ))
            conn.commit()

    def get_alerts(
        self,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        detection_source: Optional[str] = None,
        capture_id: Optional[str] = None,
        source_type: Optional[str] = None,
        time_range: Optional[str] = None,
        sort_by: Optional[str] = "created_at",
        sort_order: Optional[str] = "desc",
        offset: Optional[int] = 0,
        limit: Optional[int] = None
    ) -> list[SecurityAlert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity and severity != "ALL":
            query += " AND severity = ?"
            params.append(severity)
        if attack_type and attack_type != "ALL":
            query += " AND attack_type = ?"
            params.append(attack_type)
        if status and status != "ALL":
            query += " AND status = ?"
            params.append(status)
        if detection_source and detection_source != "ALL":
            query += " AND detection_source = ?"
            params.append(detection_source)
        if capture_id and capture_id != "ALL":
            query += " AND capture_id = ?"
            params.append(capture_id)
        if source_type and source_type != "ALL":
            query += " AND source_type = ?"
            params.append(source_type)
        if time_range and time_range != "ALL":
            now_dt = datetime.now(timezone.utc)
            if time_range == "1h":
                cutoff = (now_dt - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at >= ?"
                params.append(cutoff)
            elif time_range == "24h":
                cutoff = (now_dt - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at >= ?"
                params.append(cutoff)
            elif time_range == "7d":
                cutoff = (now_dt - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at >= ?"
                params.append(cutoff)

        if search:
            query += " AND (title LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR attack_type LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s, s])

        allowed_sort = {
            "created_at": "created_at",
            "timestamp": "timestamp",
            "severity": "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END",
            "threat_score": "threat_score",
            "attack_type": "attack_type"
        }
        order_col = allowed_sort.get(sort_by or "created_at", "created_at")
        order_dir = "ASC" if sort_order and sort_order.lower() == "asc" else "DESC"
        query += f" ORDER BY {order_col} {order_dir}"

        if limit and limit > 0:
            query += f" LIMIT {int(limit)}"
            if offset and offset > 0:
                query += f" OFFSET {int(offset)}"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_alert(r) for r in rows]

    def get_alerts_summary(
        self,
        capture_id: Optional[str] = None,
        source_type: Optional[str] = None,
        time_range: Optional[str] = None
    ) -> dict[str, int]:
        query = "SELECT severity, COUNT(*) as cnt FROM alerts WHERE 1=1"
        params = []
        if capture_id and capture_id != "ALL":
            query += " AND capture_id = ?"
            params.append(capture_id)
        if source_type and source_type != "ALL":
            query += " AND source_type = ?"
            params.append(source_type)
        if time_range and time_range != "ALL":
            now_dt = datetime.now(timezone.utc)
            if time_range == "1h":
                cutoff = (now_dt - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at >= ?"
                params.append(cutoff)
            elif time_range == "24h":
                cutoff = (now_dt - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at >= ?"
                params.append(cutoff)
            elif time_range == "7d":
                cutoff = (now_dt - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at >= ?"
                params.append(cutoff)

        query += " GROUP BY severity"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            counts = {row["severity"]: row["cnt"] for row in cursor.fetchall()}
            crit = counts.get("CRITICAL", 0)
            high = counts.get("HIGH", 0)
            med = counts.get("MEDIUM", 0)
            low = counts.get("LOW", 0)
            return {
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "total": crit + high + med + low
            }

    def clear_alerts(self, capture_id: Optional[str] = None) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if capture_id:
                cursor.execute("DELETE FROM alerts WHERE capture_id = ?", (capture_id,))
            else:
                cursor.execute("DELETE FROM alerts")
            conn.commit()
            return cursor.rowcount

    def get_alert_by_id(self, alert_id: str) -> Optional[SecurityAlert]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return self._row_to_alert(r)

    # Capture History Methods
    def insert_capture(self, cap: CaptureSession) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO captures (
                id, filename, filesize, packets_count, unique_hosts_count,
                tcp_connections_count, threats_count, rule_threats_count, ml_threats_count,
                duration_seconds, status, analyzed_at, observed_hosts_json,
                top_protocols_json, detected_signatures_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cap.id,
                cap.filename,
                cap.filesize,
                cap.packetsAnalyzed,
                cap.uniqueHosts,
                cap.tcpConnections,
                cap.potentialThreats,
                cap.ruleThreats,
                cap.mlThreats,
                cap.durationSeconds,
                cap.status,
                cap.analyzedAt,
                json.dumps(cap.observedHosts),
                json.dumps([p.model_dump() for p in cap.topProtocols]),
                json.dumps([s.model_dump() for s in cap.detectedSignatures])
            ))
            conn.commit()

    def get_captures(self, limit: int = 50) -> list[CaptureSession]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM captures ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append(CaptureSession(
                    id=r["id"],
                    filename=r["filename"],
                    filesize=r["filesize"],
                    packetsAnalyzed=r["packets_count"],
                    uniqueHosts=r["unique_hosts_count"],
                    tcpConnections=r["tcp_connections_count"],
                    potentialThreats=r["threats_count"],
                    ruleThreats=r["rule_threats_count"],
                    mlThreats=r["ml_threats_count"],
                    durationSeconds=r["duration_seconds"],
                    status=r["status"],
                    analyzedAt=r["analyzed_at"],
                    observedHosts=json.loads(r["observed_hosts_json"]),
                    topProtocols=[TopProtocol(**p) for p in json.loads(r["top_protocols_json"])],
                    detectedSignatures=[DetectedSignature(**s) for s in json.loads(r["detected_signatures_json"])]
                ))
            return results

    def get_capture_by_id(self, capture_id: str) -> Optional[CaptureSession]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM captures WHERE id = ?", (capture_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return CaptureSession(
                id=r["id"],
                filename=r["filename"],
                filesize=r["filesize"],
                packetsAnalyzed=r["packets_count"],
                uniqueHosts=r["unique_hosts_count"],
                tcpConnections=r["tcp_connections_count"],
                potentialThreats=r["threats_count"],
                ruleThreats=r["rule_threats_count"],
                mlThreats=r["ml_threats_count"],
                durationSeconds=r["duration_seconds"],
                status=r["status"],
                analyzedAt=r["analyzed_at"],
                observedHosts=json.loads(r["observed_hosts_json"]),
                topProtocols=[TopProtocol(**p) for p in json.loads(r["top_protocols_json"])],
                detectedSignatures=[DetectedSignature(**s) for s in json.loads(r["detected_signatures_json"])]
            )

    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
            conn.commit()
            return cursor.rowcount > 0

    # Report Methods
    def insert_report(self, report: SecurityReport, html_content: Optional[str] = None) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO reports (
                id, name, type, generated_date, threats, critical_count,
                status, file_size, author, summary, highlights_json, html_content
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.id,
                report.name,
                report.type,
                report.generatedDate,
                report.threats,
                report.criticalCount,
                report.status,
                report.fileSize,
                report.author,
                report.summary,
                json.dumps(report.highlights),
                html_content or ""
            ))
            conn.commit()

    def get_reports(self) -> list[SecurityReport]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reports ORDER BY created_at DESC")
            rows = cursor.fetchall()
            reports = []
            for r in rows:
                reports.append(SecurityReport(
                    id=r["id"],
                    name=r["name"],
                    type=r["type"],
                    generatedDate=r["generated_date"],
                    threats=r["threats"],
                    criticalCount=r["critical_count"],
                    status=r["status"],
                    fileSize=r["file_size"],
                    author=r["author"],
                    summary=r["summary"],
                    highlights=json.loads(r["highlights_json"])
                ))
            return reports

    def get_report_html(self, report_id: str) -> Optional[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT html_content FROM reports WHERE id = ?", (report_id,))
            r = cursor.fetchone()
            return r["html_content"] if r else None

    # Settings KV
    def set_setting(self, key: str, value: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO settings_kv (key, value) VALUES (?, ?)", (key, value))
            conn.commit()

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings_kv WHERE key = ?", (key,))
            r = cursor.fetchone()
            return r["value"] if r else default

    # Notification Methods
    def get_notifications(
        self,
        severity: Optional[str] = None,
        detection_source: Optional[str] = None,
        unread_only: bool = False,
        limit: int = 50
    ) -> list[NotificationItem]:
        query = "SELECT * FROM notifications WHERE is_dismissed = 0"
        params: list[Any] = []
        if severity and severity != "ALL":
            query += " AND severity = ?"
            params.append(severity)
        if detection_source and detection_source != "ALL":
            query += " AND detection_source = ?"
            params.append(detection_source)
        if unread_only:
            query += " AND is_read = 0"

        query += " ORDER BY created_at DESC"
        if limit > 0:
            query += f" LIMIT {int(limit)}"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [
                NotificationItem(
                    id=r["id"],
                    alertId=r["alert_id"],
                    title=r["title"],
                    severity=r["severity"],
                    attackType=r["attack_type"],
                    sourceIp=r["source_ip"],
                    destinationIp=r["destination_ip"],
                    timestamp=r["timestamp"],
                    detectionSource=r["detection_source"],
                    isRead=bool(r["is_read"]),
                    isDismissed=bool(r["is_dismissed"]),
                    createdAt=str(r["created_at"])
                )
                for r in rows
            ]

    def get_unread_notifications_count(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM notifications WHERE is_read = 0 AND is_dismissed = 0")
            return int(cursor.fetchone()[0])

    def mark_notification_read(self, notif_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notif_id,))
            conn.commit()
            return cursor.rowcount > 0

    def mark_all_notifications_read(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE notifications SET is_read = 1 WHERE is_read = 0")
            conn.commit()
            return cursor.rowcount

    def dismiss_notification(self, notif_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE notifications SET is_dismissed = 1 WHERE id = ?", (notif_id,))
            conn.commit()
            return cursor.rowcount > 0

    def clear_read_notifications(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM notifications WHERE is_read = 1")
            conn.commit()
            return cursor.rowcount

db = Database()
