import time
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, wrpcap
from ..config import settings

def ensure_sample_pcaps():
    """Generates valid, RFC-compliant synthetic sample PCAPs for testing."""
    samples_dir = settings.SAMPLES_DIR
    samples_dir.mkdir(parents=True, exist_ok=True)

    syn_flood_pcap = samples_dir / "sample_syn_flood.pcap"
    if not syn_flood_pcap.exists():
        pkts = []
        base_time = time.time() - 300
        # 100 SYN packets targeting port 80
        for i in range(120):
            ts = base_time + (i * 0.02)
            p = Ether() / IP(src="192.168.1.15", dst="192.168.1.20") / TCP(sport=40000 + i, dport=80, flags="S", seq=1000 + i)
            p.time = ts
            pkts.append(p)
        # 3 ACK responses
        for j in range(4):
            ts = base_time + (j * 0.5)
            p = Ether() / IP(src="192.168.1.20", dst="192.168.1.15") / TCP(sport=80, dport=40000 + j, flags="SA", seq=5000 + j, ack=1001 + j)
            p.time = ts
            pkts.append(p)
        wrpcap(str(syn_flood_pcap), pkts)

    portscan_pcap = samples_dir / "sample_portscan.pcap"
    if not portscan_pcap.exists():
        pkts = []
        base_time = time.time() - 600
        # Probe ports 20 to 45
        for idx, port in enumerate(range(20, 45)):
            ts = base_time + (idx * 0.08)
            p = Ether() / IP(src="192.168.1.31", dst="192.168.1.20") / TCP(sport=51000 + idx, dport=port, flags="S")
            p.time = ts
            pkts.append(p)
            # Response RST for closed ports
            if port not in [22, 80]:
                resp = Ether() / IP(src="192.168.1.20", dst="192.168.1.31") / TCP(sport=port, dport=51000 + idx, flags="R")
                resp.time = ts + 0.005
                pkts.append(resp)
        wrpcap(str(portscan_pcap), pkts)

    arp_pcap = samples_dir / "sample_arp_spoof.pcap"
    if not arp_pcap.exists():
        pkts = []
        base_time = time.time() - 900
        # Legitimate router ARP
        p1 = Ether(src="00:1A:2B:3C:4D:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc="00:1A:2B:3C:4D:01", psrc="192.168.1.1", hwdst="00:00:00:00:00:00", pdst="192.168.1.10")
        p1.time = base_time
        pkts.append(p1)
        # Poisoned attacker ARP claiming 192.168.1.1 with attacker MAC
        for k in range(15):
            ts = base_time + 1.0 + (k * 0.1)
            p2 = Ether(src="00:0C:29:4F:8E:15", dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc="00:0C:29:4F:8E:15", psrc="192.168.1.1", hwdst="3C:07:54:66:88:10", pdst="192.168.1.10")
            p2.time = ts
            pkts.append(p2)
        wrpcap(str(arp_pcap), pkts)

    ml_anomaly_pcap = samples_dir / "sample_ml_anomaly.pcap"
    if not ml_anomaly_pcap.exists():
        pkts = []
        base_time = time.time() - 1200
        # Normal background traffic
        for n in range(5):
            p = Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=53000 + n, dport=53) / (b"X" * 64)
            p.time = base_time + (n * 2.5)
            pkts.append(p)

        # Anomalous high-volume flow: rapid burst with large payloads and microsecond IATs
        for m in range(80):
            ts = base_time + 15.0 + (m * 0.005)
            # 1400 byte packets in a sustained unidirectional burst
            p = Ether() / IP(src="192.168.1.99", dst="10.0.0.5") / TCP(sport=4433, dport=8443, flags="PA", seq=1000 + (m * 1400)) / (b"A" * 1350)
            p.time = ts
            pkts.append(p)
            if m % 5 == 0:
                resp = Ether() / IP(src="10.0.0.5", dst="192.168.1.99") / TCP(sport=8443, dport=4433, flags="A", ack=1000 + (m * 1400))
                resp.time = ts + 0.001
                pkts.append(resp)
        wrpcap(str(ml_anomaly_pcap), pkts)

    icmp_flood_pcap = samples_dir / "sample_icmp_flood.pcap"
    if not icmp_flood_pcap.exists():
        pkts = []
        base_time = time.time() - 1500
        # 30 high-rate ICMP Echo requests (400+ pps)
        for c in range(30):
            ts = base_time + (c * 0.002)
            p = Ether(src="02:00:00:00:07:77", dst="02:00:00:00:05:50") / IP(src="192.168.1.77", dst="192.168.1.50") / ICMP(type=8, code=0) / (b"Q" * 32)
            p.time = ts
            pkts.append(p)
        wrpcap(str(icmp_flood_pcap), pkts)
