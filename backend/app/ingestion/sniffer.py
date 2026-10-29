import time
import random
import threading
from typing import Optional, Callable
from datetime import datetime
from ..core.state import global_state
from ..schemas.packet import LivePacket
from ..ingestion.interface_manager import is_npcap_available, is_admin
from ..detection.engine import detection_engine
from ..ingestion.pcap_parser import ParsedPacket
from ..ingestion.feature_extractor import extract_features

class SnifferManager:
    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._broadcast_callback: Optional[Callable[[dict], None]] = None
        self._packet_window: list[ParsedPacket] = []

    def set_broadcast_callback(self, cb: Callable[[dict], None]):
        self._broadcast_callback = cb

    def start(self, interface: str = "Synthetic Mode", force_synthetic: bool = False) -> dict:
        with self._lock:
            if global_state.is_monitoring:
                if interface == global_state.active_interface:
                    return {
                        "status": "already_running",
                        "interface": global_state.active_interface,
                        "capture_mode": global_state.capture_mode
                    }
                # Switching interface: clean stop previous first
                self._stop_event.set()
                global_state.is_monitoring = False
                if self._thread and self._thread.is_alive():
                    self._thread.join(timeout=1.5)
                self._thread = None

            npcap = is_npcap_available()
            admin = is_admin()

            capture_error = None
            requested_real = not force_synthetic and interface != "Synthetic Mode"
            
            if requested_real:
                if not npcap:
                    capture_error = (
                        "Npcap driver not detected on Windows (wpcap.dll missing). "
                        "Real physical packet capture requires Npcap (https://npcap.com). "
                        "Operating in explicit synthetic fallback mode."
                    )
                    use_synthetic = True
                else:
                    use_synthetic = False
            else:
                use_synthetic = True

            global_state.is_monitoring = True
            global_state.active_interface = interface if not use_synthetic else "Synthetic Mode"
            global_state.is_synthetic = use_synthetic
            global_state.capture_mode = "SYNTHETIC" if use_synthetic else "REAL"
            global_state.capture_start_time = time.time()
            global_state.capture_error = capture_error
            global_state.recent_packet_times.clear()

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                args=(use_synthetic, interface),
                daemon=True
            )
            self._thread.start()

            return {
                "status": "started",
                "interface": global_state.active_interface,
                "capture_mode": global_state.capture_mode,
                "is_synthetic": use_synthetic,
                "capture_error": capture_error,
                "message": (
                    "Real physical capture active" 
                    if not use_synthetic 
                    else ("Synthetic demonstration capture active" if not capture_error else capture_error)
                )
            }

    def stop(self) -> dict:
        with self._lock:
            if not global_state.is_monitoring:
                return {"status": "not_running", "capture_mode": "STOPPED"}

            self._stop_event.set()
            global_state.is_monitoring = False
            global_state.capture_mode = "STOPPED"
            global_state.recent_packet_times.clear()

            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=2.0)
            self._thread = None

            return {
                "status": "stopped",
                "interface": global_state.active_interface,
                "capture_mode": "STOPPED"
            }

    def _run_loop(self, is_synthetic: bool, iface: str):
        if is_synthetic:
            self._run_synthetic_loop()
        else:
            self._run_scapy_loop(iface)

    def _run_scapy_loop(self, iface: str):
        try:
            from scapy.all import sniff
            def on_packet(pkt):
                if self._stop_event.is_set():
                    return
                global_state.packets_captured_count += 1
                # Extract basic packet info from Scapy packet
                proto = "TCP"
                sport = 0
                dport = 0
                flags = []
                src = "0.0.0.0"
                dst = "0.0.0.0"

                if pkt.haslayer("IP"):
                    src = pkt["IP"].src
                    dst = pkt["IP"].dst
                elif pkt.haslayer("IPv6"):
                    src = pkt["IPv6"].src
                    dst = pkt["IPv6"].dst

                if pkt.haslayer("TCP"):
                    proto = "TCP"
                    sport = pkt["TCP"].sport
                    dport = pkt["TCP"].dport
                    f = str(pkt["TCP"].flags)
                    for char, name in [("S", "SYN"), ("A", "ACK"), ("P", "PSH"), ("F", "FIN"), ("R", "RST")]:
                        if char in f:
                            flags.append(name)
                elif pkt.haslayer("UDP"):
                    proto = "DNS" if (pkt["UDP"].sport == 53 or pkt["UDP"].dport == 53) else "UDP"
                    sport = pkt["UDP"].sport
                    dport = pkt["UDP"].dport
                elif pkt.haslayer("ICMP"):
                    proto = "ICMP"
                elif pkt.haslayer("ARP"):
                    proto = "ARP"

                size = len(pkt)
                now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                
                live_pkt = LivePacket(
                    id=f"PKT-{int(time.time() * 1000) % 1000000:06d}",
                    timestamp=now_str,
                    sourceIp=src,
                    destinationIp=dst,
                    protocol=proto if proto in ["TCP", "UDP", "ICMP", "ARP", "DNS", "TLS"] else "TCP",
                    sourcePort=sport,
                    destinationPort=dport,
                    size=size,
                    flags=flags,
                    info=f"{sport} → {dport} [{proto}] Len={size}",
                    isSuspicious=False,
                    isSynthetic=False
                )

                self._process_incoming_packet(live_pkt, size)

            while not self._stop_event.is_set():
                sniff(
                    iface=iface if iface != "All" else None,
                    prn=on_packet,
                    store=False,
                    timeout=2,
                    stop_filter=lambda x: self._stop_event.is_set()
                )
        except Exception as e:
            err_msg = f"Scapy capture error on interface '{iface}': {str(e)}. Operating in synthetic fallback."
            print(f"[Sniffer] {err_msg}")
            global_state.capture_error = err_msg
            global_state.capture_mode = "SYNTHETIC"
            global_state.is_synthetic = True
            global_state.active_interface = "Synthetic Mode"
            self._run_synthetic_loop()

    def _run_synthetic_loop(self):
        pool = [
            "192.168.1.15", "192.168.1.20", "192.168.1.10", "192.168.1.1",
            "192.168.1.30", "192.168.1.5", "10.0.0.24", "172.16.4.12"
        ]
        protocols = ["TCP", "TCP", "UDP", "DNS", "TLS", "TCP", "ICMP", "ARP"]
        common_ports = [80, 443, 22, 53, 8080, 3306, 21, 8883]

        while not self._stop_event.is_set():
            # Generate 1 to 3 packets per tick
            batch_size = random.randint(1, 3)
            for _ in range(batch_size):
                if self._stop_event.is_set():
                    break
                global_state.packets_captured_count += 1
                proto = random.choice(protocols)
                src = random.choice(pool)
                dst = random.choice([ip for ip in pool if ip != src])
                sport = random.randint(40000, 65000)
                dport = random.choice(common_ports)
                size = random.randint(64, 1420)
                
                is_attacker = src == "192.168.1.15"
                flags = ["SYN"] if (proto == "TCP" and is_attacker) else (["ACK", "PSH"] if proto == "TCP" else [])
                
                info = (
                    f"{sport} → {dport} [SYN] Seq={random.randint(100000, 999999)} Win=1024 Len=0"
                    if is_attacker and proto == "TCP"
                    else f"{sport} → {dport} {proto} Flow Data [Len={size}]"
                )

                now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                pkt_id = f"PKT-{int(time.time() * 1000) % 1000000:06d}"

                live_pkt = LivePacket(
                    id=pkt_id,
                    timestamp=now_str,
                    sourceIp=src,
                    destinationIp=dst,
                    protocol=proto,
                    sourcePort=sport,
                    destinationPort=dport,
                    size=size,
                    flags=flags,
                    info=info,
                    isSuspicious=is_attacker,
                    hexPreview="45 00 00 3c " + " ".join(f"{random.randint(0,255):02x}" for _ in range(16)),
                    isSynthetic=True
                )

                self._process_incoming_packet(live_pkt, size)

            time.sleep(random.uniform(0.15, 0.45))

    def _process_incoming_packet(self, live_pkt: LivePacket, size: int):
        global_state.add_packet(live_pkt, size)

        # Broadcast via WebSocket if callback registered
        if self._broadcast_callback:
            self._broadcast_callback({
                "type": "packet",
                "data": live_pkt.model_dump()
            })

        # Window detection check every 30 packets
        parsed = ParsedPacket(
            id_str=live_pkt.id,
            timestamp=time.time(),
            source_ip=live_pkt.sourceIp,
            dest_ip=live_pkt.destinationIp,
            protocol=live_pkt.protocol,
            source_port=live_pkt.sourcePort,
            dest_port=live_pkt.destinationPort,
            size=live_pkt.size,
            flags=live_pkt.flags,
            info=live_pkt.info,
            is_synthetic=live_pkt.isSynthetic or False
        )
        self._packet_window.append(parsed)
        if len(self._packet_window) >= 40:
            features, _ = extract_features(self._packet_window)
            # Only persist to database for real physical traffic capture, not synthetic demonstration loops
            persist = not getattr(global_state, "is_synthetic", True)
            new_alerts = detection_engine.analyze(
                features,
                self._packet_window,
                persist_to_db=persist,
                apply_cooldown=True
            )
            if new_alerts and self._broadcast_callback:
                for a in new_alerts:
                    self._broadcast_callback({
                        "type": "alert",
                        "data": a.model_dump()
                    })
            self._packet_window = self._packet_window[-15:]  # slide window

sniffer_manager = SnifferManager()
