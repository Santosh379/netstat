import socket
import datetime
import logging
from pathlib import Path
from typing import Generator, Optional
import dpkt
from ..schemas.packet import LivePacket

logger = logging.getLogger("netscope.pcap_parser")

class ParsedPacket:
    def __init__(
        self,
        id_str: str,
        timestamp: float,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        source_port: int,
        dest_port: int,
        size: int,
        flags: list[str],
        info: str,
        mac_src: str = "",
        mac_dst: str = "",
        raw_bytes: bytes = b"",
        is_synthetic: bool = False
    ):
        self.id = id_str
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.source_port = source_port
        self.dest_port = dest_port
        self.size = size
        self.flags = flags
        self.info = info
        self.mac_src = mac_src
        self.mac_dst = mac_dst
        self.raw_bytes = raw_bytes
        self.is_synthetic = is_synthetic

    def to_live_packet(self) -> LivePacket:
        dt = datetime.datetime.fromtimestamp(self.timestamp)
        time_str = dt.strftime("%H:%M:%S") + f".{int(dt.microsecond / 1000):03d}"
        
        hex_preview = " ".join(f"{b:02x}" for b in self.raw_bytes[:20]) if self.raw_bytes else ""
        
        return LivePacket(
            id=self.id,
            timestamp=time_str,
            sourceIp=self.source_ip,
            destinationIp=self.dest_ip,
            protocol=self.protocol if self.protocol in ["TCP", "UDP", "ICMP", "ARP", "DNS", "TLS"] else "TCP",
            sourcePort=self.source_port,
            destinationPort=self.dest_port,
            size=self.size,
            flags=self.flags,
            info=self.info,
            isSuspicious=False,
            hexPreview=hex_preview,
            isSynthetic=self.is_synthetic
        )

def _mac_addr(address: bytes) -> str:
    """Convert a MAC address to a readable string."""
    return ":".join(f"{b:02x}" for b in address)

def _inet_to_str(inet: bytes) -> str:
    """Convert inet object to string format (IPv4 or IPv6)."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return "unknown"

def parse_pcap_file(file_path: Path, max_packets: int = 100_000) -> Generator[ParsedPacket, None, None]:
    """
    Parses a PCAP or PCAPNG file and yields ParsedPacket instances.
    Handles standard PCAP via dpkt.pcap and PCAPNG via dpkt.pcapng.
    """
    with open(file_path, "rb") as f:
        # Detect pcap vs pcapng
        magic = f.read(4)
        f.seek(0)
        
        if magic == b"\x0a\x0d\x0d\x0a":
            reader = dpkt.pcapng.Reader(f)
        else:
            reader = dpkt.pcap.Reader(f)

        count = 0
        for ts, buf in reader:
            count += 1
            if count > max_packets:
                break

            pkt_id = f"PKT-{count:06d}"
            size = len(buf)
            
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            mac_src = _mac_addr(eth.src) if hasattr(eth, "src") else ""
            mac_dst = _mac_addr(eth.dst) if hasattr(eth, "dst") else ""

            # Check for ARP
            if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                arp = eth.data
                try:
                    src_ip = _inet_to_str(arp.spa)
                    dst_ip = _inet_to_str(arp.tpa)
                    op_name = "Request" if arp.op == dpkt.arp.ARP_OP_REQUEST else "Reply"
                    info = f"ARP {op_name}: who-has {dst_ip} tell {src_ip}"
                    yield ParsedPacket(
                        id_str=pkt_id,
                        timestamp=float(ts),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol="ARP",
                        source_port=0,
                        dest_port=0,
                        size=size,
                        flags=[],
                        info=info,
                        mac_src=mac_src,
                        mac_dst=mac_dst,
                        raw_bytes=buf
                    )
                except Exception:
                    pass
                continue

            # Check for IP
            if eth.type in [dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6]:
                ip = eth.data
                if not hasattr(ip, "src") or not hasattr(ip, "dst"):
                    continue

                src_ip = _inet_to_str(ip.src)
                dst_ip = _inet_to_str(ip.dst)

                # TCP
                if ip.p == dpkt.ip.IP_PROTO_TCP and hasattr(ip, "tcp"):
                    tcp = ip.tcp
                    sport = tcp.sport
                    dport = tcp.dport
                    
                    flags = []
                    if tcp.flags & dpkt.tcp.TH_SYN:
                        flags.append("SYN")
                    if tcp.flags & dpkt.tcp.TH_ACK:
                        flags.append("ACK")
                    if tcp.flags & dpkt.tcp.TH_PUSH:
                        flags.append("PSH")
                    if tcp.flags & dpkt.tcp.TH_FIN:
                        flags.append("FIN")
                    if tcp.flags & dpkt.tcp.TH_RST:
                        flags.append("RST")
                    if tcp.flags & dpkt.tcp.TH_URG:
                        flags.append("URG")

                    proto = "TLS" if dport == 443 or sport == 443 else "TCP"
                    flag_str = f"[{', '.join(flags)}]" if flags else ""
                    info = f"{sport} → {dport} {flag_str} Seq={tcp.seq} Ack={tcp.ack} Len={len(tcp.data)}"

                    yield ParsedPacket(
                        id_str=pkt_id,
                        timestamp=float(ts),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol=proto,
                        source_port=sport,
                        dest_port=dport,
                        size=size,
                        flags=flags,
                        info=info,
                        mac_src=mac_src,
                        mac_dst=mac_dst,
                        raw_bytes=buf
                    )

                # UDP
                elif ip.p == dpkt.ip.IP_PROTO_UDP and hasattr(ip, "udp"):
                    udp = ip.udp
                    sport = udp.sport
                    dport = udp.dport
                    proto = "DNS" if dport == 53 or sport == 53 else "UDP"
                    info = f"{sport} → {dport} {proto} Len={len(udp.data)}"

                    yield ParsedPacket(
                        id_str=pkt_id,
                        timestamp=float(ts),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol=proto,
                        source_port=sport,
                        dest_port=dport,
                        size=size,
                        flags=[],
                        info=info,
                        mac_src=mac_src,
                        mac_dst=mac_dst,
                        raw_bytes=buf
                    )

                # ICMP
                elif ip.p in [dpkt.ip.IP_PROTO_ICMP, dpkt.ip.IP_PROTO_ICMP6]:
                    icmp_data = getattr(ip, "icmp", getattr(ip, "data", None))
                    info = "ICMP Packet"
                    if icmp_data and hasattr(icmp_data, "type"):
                        if icmp_data.type == 8:
                            info = "ICMP Echo (ping) Request"
                        elif icmp_data.type == 0:
                            info = "ICMP Echo (ping) Reply"

                    yield ParsedPacket(
                        id_str=pkt_id,
                        timestamp=float(ts),
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol="ICMP",
                        source_port=0,
                        dest_port=0,
                        size=size,
                        flags=[],
                        info=info,
                        mac_src=mac_src,
                        mac_dst=mac_dst,
                        raw_bytes=buf
                    )

        logger.info("[PcapParser] Parsed %d packets from '%s'", count, file_path.name if hasattr(file_path, "name") else file_path)
