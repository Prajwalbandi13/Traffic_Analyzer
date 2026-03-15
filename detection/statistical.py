"""
Module: statistical.py

Responsibility:
- Detect statistical anomalies in traffic flows
- Identify abnormal spikes in packet volume

This module focuses on BEHAVIOR, not signatures.
"""

import statistics

# Absolute minimum packets required to consider a spike
MIN_PACKET_THRESHOLD = 60

# Multiplier over average traffic to qualify as abnormal
PACKET_SPIKE_MULTIPLIER = 3


def detect_traffic_spike(flows):
    """
    Detects traffic spikes using statistical analysis.

    Logic:
    - Establish average packet count per flow
    - Flag flows that are:
        1. Significantly higher than average
        2. Exceed an absolute minimum threshold

    Returns:
        List of alert dictionaries
    """
    alerts = []

    # Collect packet counts from all flows
    packet_counts = [flow["packet_count"] for flow in flows.values()]

    # Not enough data to build a meaningful baseline
    if len(packet_counts) < 5:
        return alerts

    avg_packets = statistics.mean(packet_counts)

    for (src_ip, dst_ip, window_start), flow in flows.items():
        packet_count = flow["packet_count"]

        # Statistical + absolute threshold check
        if (
            packet_count >= MIN_PACKET_THRESHOLD
            and packet_count > avg_packets * PACKET_SPIKE_MULTIPLIER
        ):
            alert = {
                "type": "Traffic Spike",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": "Medium",
                "reason": (
                    f"Packet count {packet_count} exceeds "
                    f"normal average {avg_packets:.2f}"
                ),
                "time_window": window_start
            }
            alerts.append(alert)

    return alerts
