import time
from collections import deque
from typing import Optional, Literal
from datetime import datetime, timezone
from ..schemas.packet import LivePacket, CaptureStats
from ..schemas.alert import SecurityAlert
from ..storage.db import db
from ..ingestion.interface_manager import is_npcap_available, is_admin
from .security import settings

class GlobalState:
    def __init__(self):
        self.is_monitoring: bool = False
        self.active_interface: str = "Synthetic Mode"
        self.is_synthetic: bool = True
        self.capture_mode: Literal["REAL", "SYNTHETIC", "STOPPED"] = "STOPPED"
        self.capture_start_time: Optional[float] = None
        self.capture_error: Optional[str] = None
        
        # Bounded packet buffer for live streaming
        self.packet_buffer: deque[LivePacket] = deque(maxlen=settings.PACKET_BUFFER_LIMIT)
        
        # Traffic metrics (isolated & explicit)
        self.packets_captured_count: int = 0
        self.packets_processed_count: int = 0
        self.total_packets_count: int = 0  # mirrors packets_processed_count
        self.total_bytes_count: int = 0
        self.total_flows_count: int = 0
        self.ml_inferences_count: int = 0
        self.dropped_packets_count: int = 0
        
        self.recent_packet_times: deque[tuple[float, int]] = deque(maxlen=2000)  # (timestamp, bytes)
        self.observed_hosts: dict[str, float] = {}  # ip -> last_seen_timestamp
        
        # Active connections counter (active 4-tuples)
        self.active_flows: dict[tuple, float] = {}  # (src, dst, sport, dport) -> last_seen

        # Capture sessions cache: capture_id -> { "id": str, "name": str, "packets": list, "alerts": list, "features": any, "timestamp": str }
        self.captures: dict[str, dict] = {}
        self.active_capture_id: Optional[str] = None
        self.last_pcap_name: Optional[str] = None
        self.last_pcap_packets: list = []

    def set_capture(self, capture_id: str, name: str, packets: list, alerts: list = None, features: any = None, hosts: list = None):
        self.captures[capture_id] = {
            "id": capture_id,
            "name": name,
            "packets": packets,
            "alerts": alerts or [],
            "features": features,
            "hosts": hosts or [],
            "timestamp": time.time()
        }
        self.active_capture_id = capture_id
        self.last_pcap_name = name
        self.last_pcap_packets = packets

    def set_last_pcap(self, name: str, packets: list):
        self.last_pcap_name = name
        self.last_pcap_packets = packets

    def get_pcap_packets(self) -> list:
        return self.last_pcap_packets

    def get_capture_packets(self, capture_id: Optional[str] = None) -> list:
        if capture_id:
            if capture_id in self.captures:
                return self.captures[capture_id]["packets"]
            return []
        if self.active_capture_id and self.active_capture_id in self.captures:
            return self.captures[self.active_capture_id]["packets"]
        return self.last_pcap_packets

    def get_capture_session(self, capture_id: Optional[str] = None) -> Optional[dict]:
        cid = capture_id or self.active_capture_id
        if cid and cid in self.captures:
            return self.captures[cid]
        return None

    def add_packet(self, pkt: LivePacket, byte_size: int):
        now = time.time()
        self.packet_buffer.append(pkt)
        self.packets_processed_count += 1
        self.total_packets_count = self.packets_processed_count
        self.total_bytes_count += byte_size
        self.recent_packet_times.append((now, byte_size))
        
        self.observed_hosts[pkt.sourceIp] = now
        self.observed_hosts[pkt.destinationIp] = now
        
        if pkt.sourcePort and pkt.destinationPort:
            key = (pkt.sourceIp, pkt.destinationIp, pkt.sourcePort, pkt.destinationPort)
            if key not in self.active_flows:
                self.total_flows_count += 1
            self.active_flows[key] = now

    def get_rates(self) -> tuple[int, str]:
        """Calculates actual packets/sec and bytes/sec over the last 1.0-second sliding window."""
        if not self.is_monitoring or self.capture_mode == "STOPPED":
            return 0, "0 B/s"

        now = time.time()
        # Filter entries older than 1.0 second
        while self.recent_packet_times and (now - self.recent_packet_times[0][0]) > 1.0:
            self.recent_packet_times.popleft()

        pps = len(self.recent_packet_times)
        bps = sum(b for _, b in self.recent_packet_times)

        if bps > 1024 * 1024:
            b_str = f"{bps / (1024 * 1024):.1f} MB/s"
        elif bps > 1024:
            b_str = f"{bps / 1024:.1f} KB/s"
        else:
            b_str = f"{bps} B/s"

        return pps, b_str

    def get_elapsed_seconds(self) -> float:
        if self.capture_start_time and self.is_monitoring:
            return round(time.time() - self.capture_start_time, 1)
        return 0.0

    def get_active_hosts_count(self) -> int:
        if not self.is_monitoring:
            return len(self.observed_hosts)
        now = time.time()
        # Hosts seen in the last 5 minutes
        active = [ip for ip, ts in self.observed_hosts.items() if (now - ts) < 300]
        return len(active)

    def get_active_connections_count(self) -> int:
        if not self.is_monitoring:
            return 0
        now = time.time()
        # Flows active in the last 60 seconds
        active = [f for f, ts in self.active_flows.items() if (now - ts) < 60]
        return len(active)

    def get_capture_stats(self) -> CaptureStats:
        pps, bps = self.get_rates()
        start_str = (
            datetime.fromtimestamp(self.capture_start_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if self.capture_start_time
            else None
        )
        return CaptureStats(
            captureMode=self.capture_mode,
            interfaceName=self.active_interface,
            ipAddress="127.0.0.1",
            packetsPerSec=pps if self.is_monitoring else 0,
            bytesPerSec=bps if self.is_monitoring else "0 B/s",
            packetsCaptured=self.packets_captured_count,
            packetsProcessed=self.packets_processed_count,
            totalPackets=self.total_packets_count,
            flowsCount=self.total_flows_count,
            mlInferencesCount=self.ml_inferences_count,
            droppedPackets=self.dropped_packets_count,
            startTime=start_str,
            elapsedSeconds=self.get_elapsed_seconds(),
            promiscuousMode=False,
            activeConnections=self.get_active_connections_count() if self.is_monitoring else 0,
            captureError=self.capture_error,
            npcapAvailable=is_npcap_available(),
            hasAdminPrivileges=is_admin()
        )

global_state = GlobalState()
