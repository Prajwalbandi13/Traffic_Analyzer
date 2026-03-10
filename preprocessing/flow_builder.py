"""
Module: flow_builder.py

Responsibility:
- Read packet data from database
- Group packets into time windows (flows)
- Generate behavior summaries for analysis

This module does NOT perform detection.
"""

from storage.database import get_connection
from collections import defaultdict


TIME_WINDOW = 5  # seconds


def fetch_packets():
    """
    Fetch all packets from database.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, src_ip, dst_ip, dst_port, protocol, tcp_flags
        FROM packets
        ORDER BY timestamp
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows


def build_flows():
    """
    Groups packets into flows based on time windows.
    """
    packets = fetch_packets()

    flows = defaultdict(lambda: {
        "packet_count": 0,
        "ports": set(),
        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "start_time": None,
        "end_time": None
    })

    for timestamp, src_ip, dst_ip, dst_port, protocol, tcp_flags in packets:
        window_start = int(timestamp // TIME_WINDOW) * TIME_WINDOW
        key = (src_ip, dst_ip, window_start)

        flow = flows[key]
        flow["packet_count"] += 1
        flow["ports"].add(dst_port)

        if protocol == "TCP" and tcp_flags:
            flags = set(str(tcp_flags))
            flow["syn_count"] += 1 if "S" in flags else 0
            flow["ack_count"] += 1 if "A" in flags else 0
            flow["rst_count"] += 1 if "R" in flags else 0

        if flow["start_time"] is None:
            flow["start_time"] = window_start

        flow["end_time"] = window_start + TIME_WINDOW

    return flows
