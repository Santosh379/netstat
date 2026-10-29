from collections import defaultdict
from typing import Iterable
from .pcap_parser import ParsedPacket
from ..schemas.pcap import TopProtocol

class FeatureExtractionResult:
    def __init__(self):
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.duration_seconds: float = 0.0
        self.unique_hosts: set[str] = set()
        self.unique_macs: dict[str, str] = {}  # ip -> mac
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.flows: dict[tuple, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0, "syn": 0, "ack": 0, "rst": 0})
        self.host_stats: dict[str, dict] = defaultdict(lambda: {
            "packets_in": 0, "packets_out": 0, "bytes_in": 0, "bytes_out": 0,
            "dest_ports_contacted": set(), "open_ports_observed": set(), "mac": "",
            "syn_sent": 0, "ack_received": 0, "failed_auth": 0
        })
        self.timeline_buckets: dict[str, int] = defaultdict(int)

    def get_top_protocols(self) -> list[TopProtocol]:
        if not self.total_packets:
            return []
        sorted_protos = sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)
        return [
            TopProtocol(name=proto, percentage=round((count / self.total_packets) * 100, 1))
            for proto, count in sorted_protos
        ]

def extract_features(packets: Iterable[ParsedPacket]) -> tuple[FeatureExtractionResult, list[ParsedPacket]]:
    """
    Extracts high-level statistical features and flow indicators from a stream of parsed packets.
    Returns: (FeatureExtractionResult, list_of_packets)
    """
    res = FeatureExtractionResult()
    packet_list: list[ParsedPacket] = []

    for pkt in packets:
        packet_list.append(pkt)
        res.total_packets += 1
        res.total_bytes += pkt.size
        
        if res.start_time == 0.0 or pkt.timestamp < res.start_time:
            res.start_time = pkt.timestamp
        if pkt.timestamp > res.end_time:
            res.end_time = pkt.timestamp

        res.unique_hosts.add(pkt.source_ip)
        res.unique_hosts.add(pkt.dest_ip)

        if pkt.mac_src:
            res.unique_macs[pkt.source_ip] = pkt.mac_src

        # Protocol accounting
        res.protocol_counts[pkt.protocol] += 1

        # Host statistics
        src_stat = res.host_stats[pkt.source_ip]
        src_stat["packets_out"] += 1
        src_stat["bytes_out"] += pkt.size
        if pkt.mac_src:
            src_stat["mac"] = pkt.mac_src
        if pkt.dest_port:
            src_stat["dest_ports_contacted"].add(pkt.dest_port)

        dst_stat = res.host_stats[pkt.dest_ip]
        dst_stat["packets_in"] += 1
        dst_stat["bytes_in"] += pkt.size

        # Flow tracking (source, dest, sport, dport, protocol)
        flow_key = (pkt.source_ip, pkt.dest_ip, pkt.source_port, pkt.dest_port, pkt.protocol)
        flow = res.flows[flow_key]
        flow["packets"] += 1
        flow["bytes"] += pkt.size

        if "SYN" in pkt.flags:
            flow["syn"] += 1
            src_stat["syn_sent"] += 1
        if "ACK" in pkt.flags:
            flow["ack"] += 1
            dst_stat["ack_received"] += 1
        if "RST" in pkt.flags:
            flow["rst"] += 1
            # If server sends RST to SSH port probe, mark potential rejected connection
            if pkt.source_port in [22, 23]:
                dst_stat["failed_auth"] += 1

        if "SYN" in pkt.flags and "ACK" in pkt.flags:
            # Server responded SYN-ACK: port is open!
            res.host_stats[pkt.source_ip]["open_ports_observed"].add(pkt.source_port)

        # 1-minute timeline buckets
        minute_key = f"{int(pkt.timestamp // 60) * 60}"
        res.timeline_buckets[minute_key] += 1

    if res.end_time >= res.start_time:
        res.duration_seconds = round(res.end_time - res.start_time, 2)
    else:
        res.duration_seconds = 0.0

    return res, packet_list
