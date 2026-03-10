"""
Window-based feature extraction for ML anomaly detection.
"""

import statistics
from collections import defaultdict

from storage.database import fetch_packets_for_feature_extraction, insert_feature_vector


FEATURE_WINDOW = 10  # seconds


def _safe_variance(values):
    if len(values) < 2:
        return 0.0
    return float(statistics.pvariance(values))


def _parse_flags(flag_text):
    if not flag_text:
        return set()
    return set(flag_text)


def build_window_features():
    """
    Aggregates packets into 10-second windows and computes numerical features.
    Returns dict: {window_start: feature_vector}
    """
    rows = fetch_packets_for_feature_extraction()
    buckets = defaultdict(list)

    for row in rows:
        ts = row[0]
        window_start = int(ts // FEATURE_WINDOW) * FEATURE_WINDOW
        buckets[window_start].append({
            "timestamp": row[0],
            "src_ip": row[1],
            "dst_ip": row[2],
            "protocol": row[3],
            "dst_port": row[4],
            "size": row[5] or 0,
            "tcp_flags": row[6],
        })

    features_by_window = {}
    for window_start, packets in buckets.items():
        packet_count = len(packets)
        if packet_count == 0:
            continue

        sizes = [p["size"] for p in packets]
        total_bytes = sum(sizes)
        src_ips = {p["src_ip"] for p in packets if p["src_ip"]}
        dst_ips = {p["dst_ip"] for p in packets if p["dst_ip"]}
        dst_ports = {p["dst_port"] for p in packets if p["dst_port"] is not None}

        tcp_count = sum(1 for p in packets if p["protocol"] == "TCP")
        udp_count = sum(1 for p in packets if p["protocol"] == "UDP")
        icmp_count = sum(1 for p in packets if p["protocol"] == "ICMP")

        syn_count = 0
        ack_count = 0
        fin_count = 0
        rst_count = 0
        for p in packets:
            flags = _parse_flags(p["tcp_flags"])
            syn_count += 1 if "S" in flags else 0
            ack_count += 1 if "A" in flags else 0
            fin_count += 1 if "F" in flags else 0
            rst_count += 1 if "R" in flags else 0

        timestamps = sorted(p["timestamp"] for p in packets)
        inter_arrivals = [
            timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))
        ]

        feature_vector = {
            "packet_count": float(packet_count),
            "packet_rate": float(packet_count / FEATURE_WINDOW),
            "byte_rate": float(total_bytes / FEATURE_WINDOW),
            "avg_packet_size": float(statistics.mean(sizes)),
            "max_packet_size": float(max(sizes)),
            "packet_size_variance": _safe_variance(sizes),
            "unique_src_ips": float(len(src_ips)),
            "unique_dst_ips": float(len(dst_ips)),
            "unique_dst_ports": float(len(dst_ports)),
            "tcp_count": float(tcp_count),
            "udp_count": float(udp_count),
            "icmp_count": float(icmp_count),
            "tcp_ratio": float(tcp_count / packet_count),
            "udp_ratio": float(udp_count / packet_count),
            "icmp_ratio": float(icmp_count / packet_count),
            "syn_count": float(syn_count),
            "ack_count": float(ack_count),
            "fin_count": float(fin_count),
            "rst_count": float(rst_count),
            "avg_inter_arrival": float(statistics.mean(inter_arrivals)) if inter_arrivals else 0.0,
            "inter_arrival_variance": _safe_variance(inter_arrivals),
        }
        features_by_window[window_start] = feature_vector

    return features_by_window


def persist_window_features(features_by_window):
    """
    Stores computed feature vectors for ML training.
    """
    for window_start, feature_vector in features_by_window.items():
        insert_feature_vector(window_start, feature_vector)
