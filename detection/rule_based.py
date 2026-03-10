"""
Module: rule_based.py

Responsibility:
- Apply simple rule-based detection on flows
- Identify suspicious behavior patterns

This module does NOT modify data.
"""

from preprocessing.flow_builder import TIME_WINDOW

PORT_SCAN_THRESHOLD = 10  # number of unique ports in one window
DOS_PACKET_THRESHOLD = 400  # packets per flow in one window
FAILED_CONNECTION_SYN_THRESHOLD = 30
FAILED_CONNECTION_RST_THRESHOLD = 20


def detect_port_scan(flows):
    """
    Detects port-scan-like behavior from flow data.

    Returns a list of alerts.
    """
    alerts = []

    for (src_ip, dst_ip, window_start), flow in flows.items():
        unique_ports = len(flow["ports"])

        if unique_ports >= PORT_SCAN_THRESHOLD:
            alert = {
                "type": "Possible Port Scan",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": "High",
                "reason": f"{unique_ports} unique ports accessed in {TIME_WINDOW} seconds",
                "time_window": window_start
            }
            alerts.append(alert)

    return alerts


def detect_dos_burst(flows):
    """
    Detects potential DoS burst based on high packet rate per flow.
    Returns a list of alerts.
    """
    alerts = []

    for (src_ip, dst_ip, window_start), flow in flows.items():
        packet_count = flow["packet_count"]

        if packet_count >= DOS_PACKET_THRESHOLD:
            alert = {
                "type": "Possible DoS Burst",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": "High",
                "reason": (
                    f"{packet_count} packets in {TIME_WINDOW} seconds "
                    f"from {src_ip} to {dst_ip}"
                ),
                "time_window": window_start
            }
            alerts.append(alert)

    return alerts


def detect_repeated_failed_connections(flows):
    """
    Detects repeated failed connection attempts using TCP flags.
    """
    alerts = []
    for (src_ip, dst_ip, window_start), flow in flows.items():
        syn_count = flow.get("syn_count", 0)
        ack_count = flow.get("ack_count", 0)
        rst_count = flow.get("rst_count", 0)

        if syn_count >= FAILED_CONNECTION_SYN_THRESHOLD and ack_count == 0:
            alerts.append({
                "type": "Repeated Failed Connections",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": "High",
                "reason": (
                    f"{syn_count} SYN packets with no ACK in {TIME_WINDOW} seconds"
                ),
                "time_window": window_start,
            })
            continue

        if rst_count >= FAILED_CONNECTION_RST_THRESHOLD:
            alerts.append({
                "type": "Repeated Failed Connections",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": "Medium",
                "reason": (
                    f"{rst_count} RST packets observed in {TIME_WINDOW} seconds"
                ),
                "time_window": window_start,
            })

    return alerts
