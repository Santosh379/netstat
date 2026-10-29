"""
Feature schema definition and validation for NetScope AI ML Anomaly Detection.
Version: 1.0.0
"""

from typing import Any, Optional
from dataclasses import dataclass, asdict
import numpy as np

SCHEMA_VERSION = "1.0.0"

# Exact ordered feature list matching CIC-IDS2017 flow attributes
FEATURE_NAMES: list[str] = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Average Packet Size"
]

@dataclass
class FlowFeatures:
    """
    Representation of statistical flow-level features calculated from packet observations.
    """
    flow_duration: float = 0.0               # Flow Duration in microseconds
    total_fwd_packets: float = 0.0           # Total forward packets
    total_bwd_packets: float = 0.0           # Total backward packets
    total_fwd_bytes: float = 0.0             # Total length of forward packets
    total_bwd_bytes: float = 0.0             # Total length of backward packets
    flow_bytes_per_sec: float = 0.0          # Flow Bytes/s
    flow_packets_per_sec: float = 0.0        # Flow Packets/s
    flow_iat_mean: float = 0.0               # Mean inter-arrival time in microseconds
    flow_iat_std: float = 0.0                # Std dev of inter-arrival time in microseconds
    min_packet_length: float = 0.0           # Minimum observed packet size
    max_packet_length: float = 0.0           # Maximum observed packet size
    packet_length_mean: float = 0.0          # Mean packet size
    packet_length_std: float = 0.0           # Std dev of packet size
    syn_flag_count: float = 0.0              # Packets with SYN flag
    rst_flag_count: float = 0.0              # Packets with RST flag
    ack_flag_count: float = 0.0              # Packets with ACK flag
    average_packet_size: float = 0.0         # Average packet size (bytes / packets)

    # Identifiers for tracking (not fed into the model)
    source_ip: str = ""
    destination_ip: str = ""
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "TCP"
    start_timestamp: float = 0.0
    end_timestamp: float = 0.0

    def to_feature_array(self) -> np.ndarray:
        """
        Converts flow features to a 1D numpy array with the exact ordered feature columns.
        """
        values = [
            float(self.flow_duration),
            float(self.total_fwd_packets),
            float(self.total_bwd_packets),
            float(self.total_fwd_bytes),
            float(self.total_bwd_bytes),
            float(self.flow_bytes_per_sec),
            float(self.flow_packets_per_sec),
            float(self.flow_iat_mean),
            float(self.flow_iat_std),
            float(self.min_packet_length),
            float(self.max_packet_length),
            float(self.packet_length_mean),
            float(self.packet_length_std),
            float(self.syn_flag_count),
            float(self.rst_flag_count),
            float(self.ack_flag_count),
            float(self.average_packet_size)
        ]
        return np.array(values, dtype=np.float64)

    def to_feature_dict(self) -> dict[str, float]:
        """
        Returns a dictionary mapping official feature names to their float values.
        """
        arr = self.to_feature_array()
        return {name: float(arr[i]) for i, name in enumerate(FEATURE_NAMES)}

    def validate(self) -> tuple[bool, Optional[str]]:
        """
        Validates feature values for completeness and realistic bounds.
        """
        if self.total_fwd_packets + self.total_bwd_packets < 1:
            return False, "Flow has 0 packets."
        if self.flow_duration < 0:
            return False, "Flow duration cannot be negative."
        if self.min_packet_length < 0 or self.max_packet_length < 0:
            return False, "Packet length cannot be negative."
        return True, None
