"""
Flow Aggregator for NetScope AI.
Transforms raw ParsedPacket streams into structured, validated FlowFeatures.
"""

from collections import defaultdict
from typing import Iterable, Optional
import logging
import numpy as np

from ..ingestion.pcap_parser import ParsedPacket
from .schema import FlowFeatures

logger = logging.getLogger("netscope.flow_aggregator")

class RawFlowAccumulator:
    """
    Accumulator for a single directional/bidirectional flow conversation.
    """
    def __init__(self, initiator_ip: str, source_port: Optional[int], dest_port: Optional[int], protocol: str):
        self.initiator_ip = initiator_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.protocol = protocol
        
        self.start_timestamp: float = 0.0
        self.last_timestamp: float = 0.0
        self.timestamps: list[float] = []
        
        self.fwd_packets: int = 0
        self.bwd_packets: int = 0
        self.fwd_bytes: int = 0
        self.bwd_bytes: int = 0
        
        self.packet_lengths: list[int] = []
        self.syn_count: int = 0
        self.rst_count: int = 0
        self.ack_count: int = 0
        self.fin_count: int = 0

    def add_packet(self, pkt: ParsedPacket) -> None:
        if self.start_timestamp == 0.0 or pkt.timestamp < self.start_timestamp:
            self.start_timestamp = pkt.timestamp
        if pkt.timestamp > self.last_timestamp:
            self.last_timestamp = pkt.timestamp

        self.timestamps.append(pkt.timestamp)
        self.packet_lengths.append(pkt.size)

        # Check direction
        if pkt.source_ip == self.initiator_ip:
            self.fwd_packets += 1
            self.fwd_bytes += pkt.size
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt.size

        # Flag accounting
        flags = set(pkt.flags)
        if "SYN" in flags:
            self.syn_count += 1
        if "RST" in flags:
            self.rst_count += 1
        if "ACK" in flags:
            self.ack_count += 1
        if "FIN" in flags:
            self.fin_count += 1

    def to_flow_features(self, src_ip: str, dst_ip: str) -> Optional[FlowFeatures]:
        total_packets = self.fwd_packets + self.bwd_packets
        if total_packets < 1:
            return None

        total_bytes = self.fwd_bytes + self.bwd_bytes
        duration_sec = max(self.last_timestamp - self.start_timestamp, 0.0)
        duration_us = duration_sec * 1_000_000.0

        # Rate calculations (using safe divisor)
        safe_duration = max(duration_sec, 0.0005)
        flow_bytes_per_sec = float(total_bytes) / safe_duration
        flow_packets_per_sec = float(total_packets) / safe_duration

        # Inter-arrival times (in microseconds)
        if len(self.timestamps) > 1:
            sorted_ts = sorted(self.timestamps)
            iats = np.diff(sorted_ts) * 1_000_000.0  # in microseconds
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
        else:
            iat_mean = 0.0
            iat_std = 0.0

        # Packet length statistics
        lengths_arr = np.array(self.packet_lengths, dtype=np.float64)
        min_len = float(np.min(lengths_arr))
        max_len = float(np.max(lengths_arr))
        mean_len = float(np.mean(lengths_arr))
        std_len = float(np.std(lengths_arr)) if len(lengths_arr) > 1 else 0.0
        avg_pkt_size = float(total_bytes) / total_packets

        features = FlowFeatures(
            flow_duration=duration_us,
            total_fwd_packets=float(self.fwd_packets),
            total_bwd_packets=float(self.bwd_packets),
            total_fwd_bytes=float(self.fwd_bytes),
            total_bwd_bytes=float(self.bwd_bytes),
            flow_bytes_per_sec=flow_bytes_per_sec,
            flow_packets_per_sec=flow_packets_per_sec,
            flow_iat_mean=iat_mean,
            flow_iat_std=iat_std,
            min_packet_length=min_len,
            max_packet_length=max_len,
            packet_length_mean=mean_len,
            packet_length_std=std_len,
            syn_flag_count=float(self.syn_count),
            rst_flag_count=float(self.rst_count),
            ack_flag_count=float(self.ack_count),
            average_packet_size=avg_pkt_size,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=self.source_port,
            destination_port=self.dest_port,
            protocol=self.protocol,
            start_timestamp=self.start_timestamp,
            end_timestamp=self.last_timestamp
        )

        valid, _ = features.validate()
        return features if valid else None


def aggregate_flows(packets: Iterable[ParsedPacket]) -> list[FlowFeatures]:
    """
    Groups a stream of ParsedPackets into bidirectional flows and extracts FlowFeatures.
    Canonical 5-tuple: (min(ip1, ip2), max(ip1, ip2), min(port1, port2), max(port1, port2), protocol)
    """
    flow_map: dict[tuple, RawFlowAccumulator] = {}
    pair_endpoints: dict[tuple, tuple[str, str]] = {}

    for pkt in packets:
        # Ignore non-IP or empty endpoints
        if not pkt.source_ip or not pkt.dest_ip:
            continue

        ip1, ip2 = sorted([pkt.source_ip, pkt.dest_ip])
        p1, p2 = sorted([pkt.source_port or 0, pkt.dest_port or 0])
        key = (ip1, ip2, p1, p2, pkt.protocol)

        if key not in flow_map:
            flow_map[key] = RawFlowAccumulator(
                initiator_ip=pkt.source_ip,
                source_port=pkt.source_port,
                dest_port=pkt.dest_port,
                protocol=pkt.protocol
            )
            pair_endpoints[key] = (pkt.source_ip, pkt.dest_ip)

        flow_map[key].add_packet(pkt)

    flow_features_list: list[FlowFeatures] = []
    for key, acc in flow_map.items():
        src, dst = pair_endpoints[key]
        features = acc.to_flow_features(src, dst)
        if features is not None:
            flow_features_list.append(features)

    logger.info("[FlowAggregator] Generated %d bidirectional flows from input packets", len(flow_features_list))
    return flow_features_list
