"""
SQLite storage helpers for packets, alerts, host metadata, and reporting.
"""

import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from time import time


DB_PATH = Path(__file__).parent / "network_traffic.db"
ALERT_GROUP_LOOKBACK_SECONDS = 60 * 60


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            domain TEXT,
            tcp_flags TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            reason TEXT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            time_window REAL,
            status TEXT DEFAULT 'new',
            owner TEXT,
            notes TEXT,
            resolution TEXT,
            first_seen REAL,
            last_seen REAL,
            event_count INTEGER DEFAULT 1,
            what TEXT,
            possible_causes TEXT,
            impact TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic_features (
            window_start REAL PRIMARY KEY,
            packet_count REAL,
            packet_rate REAL,
            byte_rate REAL,
            avg_packet_size REAL,
            max_packet_size REAL,
            packet_size_variance REAL,
            unique_src_ips REAL,
            unique_dst_ips REAL,
            unique_dst_ports REAL,
            tcp_count REAL,
            udp_count REAL,
            icmp_count REAL,
            tcp_ratio REAL,
            udp_ratio REAL,
            icmp_ratio REAL,
            syn_count REAL,
            ack_count REAL,
            fin_count REAL,
            rst_count REAL,
            avg_inter_arrival REAL,
            inter_arrival_variance REAL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS host_profiles (
            ip TEXT PRIMARY KEY,
            display_name TEXT,
            role TEXT,
            owner TEXT,
            notes TEXT,
            is_allowlisted INTEGER DEFAULT 0,
            updated_at REAL
        )
        """
    )

    conn.commit()

    _safe_add_column(cursor, conn, "packets", "domain TEXT")
    _safe_add_column(cursor, conn, "packets", "tcp_flags TEXT")
    for column_sql in (
        "src_ip TEXT",
        "dst_ip TEXT",
        "time_window REAL",
        "status TEXT DEFAULT 'new'",
        "owner TEXT",
        "notes TEXT",
        "resolution TEXT",
        "first_seen REAL",
        "last_seen REAL",
        "event_count INTEGER DEFAULT 1",
        "what TEXT",
        "possible_causes TEXT",
        "impact TEXT",
    ):
        _safe_add_column(cursor, conn, "alerts", column_sql)

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)"
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_type_pair ON alerts(alert_type, src_ip, dst_ip)"
    )
    conn.commit()
    conn.close()


def _safe_add_column(cursor, conn, table_name, column_sql):
    try:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")
        conn.commit()
    except sqlite3.OperationalError:
        pass


def insert_packet(packet_data):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO packets (
            timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, domain, tcp_flags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            packet_data["timestamp"],
            packet_data["src_ip"],
            packet_data["dst_ip"],
            packet_data["protocol"],
            packet_data["src_port"],
            packet_data["dst_port"],
            packet_data["size"],
            packet_data.get("domain"),
            packet_data.get("tcp_flags"),
        ),
    )
    conn.commit()
    conn.close()


def get_packet_count():
    conn = get_connection()
    row = conn.execute("SELECT COUNT(*) AS count FROM packets").fetchone()
    conn.close()
    return row["count"] if row else 0


def insert_alert(alert):
    now = float(alert.get("time_window") or time())
    src_ip = alert.get("src_ip", "N/A")
    dst_ip = alert.get("dst_ip", "N/A")

    conn = get_connection()
    cursor = conn.cursor()
    existing = cursor.execute(
        """
        SELECT id, event_count, status, notes, owner, resolution
        FROM alerts
        WHERE alert_type = ?
          AND COALESCE(src_ip, 'N/A') = ?
          AND COALESCE(dst_ip, 'N/A') = ?
          AND COALESCE(last_seen, timestamp, 0) >= ?
          AND status NOT IN ('resolved', 'false_positive')
        ORDER BY COALESCE(last_seen, timestamp, 0) DESC
        LIMIT 1
        """,
        (alert["type"], src_ip, dst_ip, now - ALERT_GROUP_LOOKBACK_SECONDS),
    ).fetchone()

    if existing:
        cursor.execute(
            """
            UPDATE alerts
            SET severity = ?,
                reason = ?,
                timestamp = ?,
                time_window = ?,
                last_seen = ?,
                event_count = COALESCE(event_count, 1) + 1,
                what = ?,
                possible_causes = ?,
                impact = ?
            WHERE id = ?
            """,
            (
                alert["severity"],
                alert["reason"],
                now,
                alert.get("time_window"),
                now,
                alert.get("what"),
                alert.get("possible_causes"),
                alert.get("impact"),
                existing["id"],
            ),
        )
        alert_id = existing["id"]
    else:
        cursor.execute(
            """
            INSERT INTO alerts (
                alert_type, severity, reason, timestamp, src_ip, dst_ip, time_window,
                status, owner, notes, resolution, first_seen, last_seen, event_count,
                what, possible_causes, impact
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'new', '', '', '', ?, ?, 1, ?, ?, ?)
            """,
            (
                alert["type"],
                alert["severity"],
                alert["reason"],
                now,
                src_ip,
                dst_ip,
                alert.get("time_window"),
                now,
                now,
                alert.get("what"),
                alert.get("possible_causes"),
                alert.get("impact"),
            ),
        )
        alert_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return alert_id


def fetch_alerts(limit=100, range_seconds=3600, status=None, severity=None, query=None):
    conn = get_connection()
    sql = """
        SELECT *
        FROM alerts
        WHERE COALESCE(last_seen, timestamp, 0) >= ?
    """
    params = [time() - range_seconds]

    if status and status != "all":
        sql += " AND status = ?"
        params.append(status)
    if severity and severity != "all":
        sql += " AND severity = ?"
        params.append(severity)
    if query:
        sql += """
            AND (
                alert_type LIKE ?
                OR reason LIKE ?
                OR COALESCE(src_ip, '') LIKE ?
                OR COALESCE(dst_ip, '') LIKE ?
                OR COALESCE(owner, '') LIKE ?
                OR COALESCE(notes, '') LIKE ?
            )
        """
        like = f"%{query}%"
        params.extend([like, like, like, like, like, like])

    sql += " ORDER BY COALESCE(last_seen, timestamp, 0) DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [_row_to_alert_dict(row) for row in rows]


def fetch_alert_by_id(alert_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    return _row_to_alert_dict(row) if row else None


def update_alert(alert_id, status=None, owner=None, notes=None, resolution=None):
    existing = fetch_alert_by_id(alert_id)
    if not existing:
        return None

    payload = {
        "status": existing["status"] if status is None else status,
        "owner": existing["owner"] if owner is None else owner,
        "notes": existing["notes"] if notes is None else notes,
        "resolution": existing["resolution"] if resolution is None else resolution,
    }

    conn = get_connection()
    conn.execute(
        """
        UPDATE alerts
        SET status = ?, owner = ?, notes = ?, resolution = ?
        WHERE id = ?
        """,
        (payload["status"], payload["owner"], payload["notes"], payload["resolution"], alert_id),
    )
    conn.commit()
    conn.close()
    return fetch_alert_by_id(alert_id)


def fetch_alert_status_breakdown(range_seconds=3600):
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT status, COUNT(*) AS count
        FROM alerts
        WHERE COALESCE(last_seen, timestamp, 0) >= ?
        GROUP BY status
        """,
        (time() - range_seconds,),
    ).fetchall()
    conn.close()
    result = {"new": 0, "acknowledged": 0, "investigating": 0, "resolved": 0, "false_positive": 0}
    for row in rows:
        result[row["status"] or "new"] = row["count"]
    return result


def fetch_recent_packets(limit=200, range_seconds=3600, query=None, protocol=None):
    conn = get_connection()
    sql = """
        SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, domain
        FROM packets
        WHERE timestamp >= ?
    """
    params = [time() - range_seconds]
    if protocol and protocol != "all":
        sql += " AND protocol = ?"
        params.append(protocol)
    if query:
        like = f"%{query}%"
        sql += """
            AND (
                COALESCE(src_ip, '') LIKE ?
                OR COALESCE(dst_ip, '') LIKE ?
                OR COALESCE(domain, '') LIKE ?
                OR COALESCE(protocol, '') LIKE ?
            )
        """
        params.extend([like, like, like, like])
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_packets_for_feature_extraction():
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT timestamp, src_ip, dst_ip, protocol, dst_port, size, tcp_flags
        FROM packets
        ORDER BY timestamp ASC
        """
    ).fetchall()
    conn.close()
    return [tuple(row) for row in rows]


def insert_feature_vector(window_start, feature_vector):
    conn = get_connection()
    conn.execute(
        """
        INSERT OR REPLACE INTO traffic_features (
            window_start, packet_count, packet_rate, byte_rate, avg_packet_size, max_packet_size,
            packet_size_variance, unique_src_ips, unique_dst_ips, unique_dst_ports, tcp_count,
            udp_count, icmp_count, tcp_ratio, udp_ratio, icmp_ratio, syn_count, ack_count,
            fin_count, rst_count, avg_inter_arrival, inter_arrival_variance
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            window_start,
            feature_vector["packet_count"],
            feature_vector["packet_rate"],
            feature_vector["byte_rate"],
            feature_vector["avg_packet_size"],
            feature_vector["max_packet_size"],
            feature_vector["packet_size_variance"],
            feature_vector["unique_src_ips"],
            feature_vector["unique_dst_ips"],
            feature_vector["unique_dst_ports"],
            feature_vector["tcp_count"],
            feature_vector["udp_count"],
            feature_vector["icmp_count"],
            feature_vector["tcp_ratio"],
            feature_vector["udp_ratio"],
            feature_vector["icmp_ratio"],
            feature_vector["syn_count"],
            feature_vector["ack_count"],
            feature_vector["fin_count"],
            feature_vector["rst_count"],
            feature_vector["avg_inter_arrival"],
            feature_vector["inter_arrival_variance"],
        ),
    )
    conn.commit()
    conn.close()


def fetch_feature_dataset():
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT
            window_start, packet_count, packet_rate, byte_rate, avg_packet_size, max_packet_size,
            packet_size_variance, unique_src_ips, unique_dst_ips, unique_dst_ports, tcp_count,
            udp_count, icmp_count, tcp_ratio, udp_ratio, icmp_ratio, syn_count, ack_count,
            fin_count, rst_count, avg_inter_arrival, inter_arrival_variance
        FROM traffic_features
        ORDER BY window_start ASC
        """
    ).fetchall()
    conn.close()
    return [tuple(row) for row in rows]


def fetch_non_ml_alert_windows():
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT time_window
        FROM alerts
        WHERE alert_type NOT LIKE 'ML Anomaly%'
          AND time_window IS NOT NULL
        """
    ).fetchall()
    conn.close()
    return [int(row["time_window"]) for row in rows]


def clear_packets_and_alerts(clear_features=False):
    conn = get_connection()
    conn.execute("DELETE FROM packets")
    conn.execute("DELETE FROM alerts")
    if clear_features:
        conn.execute("DELETE FROM traffic_features")
    conn.commit()
    conn.close()


def fetch_dashboard_summary(range_seconds=3600):
    cutoff = time() - range_seconds
    conn = get_connection()
    packet_row = conn.execute(
        """
        SELECT
            COUNT(*) AS packet_count,
            COALESCE(SUM(size), 0) AS total_bytes,
            COUNT(DISTINCT src_ip) + COUNT(DISTINCT dst_ip) AS host_touch_count,
            COUNT(DISTINCT domain) AS unique_domains
        FROM packets
        WHERE timestamp >= ?
        """,
        (cutoff,),
    ).fetchone()
    alert_row = conn.execute(
        """
        SELECT COUNT(*) AS alert_count
        FROM alerts
        WHERE COALESCE(last_seen, timestamp, 0) >= ?
        """,
        (cutoff,),
    ).fetchone()
    conn.close()

    return {
        "packet_count": packet_row["packet_count"] if packet_row else 0,
        "total_bytes": packet_row["total_bytes"] if packet_row else 0,
        "host_touch_count": packet_row["host_touch_count"] if packet_row else 0,
        "unique_domains": packet_row["unique_domains"] if packet_row else 0,
        "alert_count": alert_row["alert_count"] if alert_row else 0,
    }


def fetch_traffic_timeline(range_seconds=3600, bucket_seconds=300):
    cutoff = time() - range_seconds
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT timestamp, size
        FROM packets
        WHERE timestamp >= ?
        ORDER BY timestamp ASC
        """,
        (cutoff,),
    ).fetchall()
    conn.close()

    buckets = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for row in rows:
        bucket = int(row["timestamp"] // bucket_seconds) * bucket_seconds
        buckets[bucket]["packets"] += 1
        buckets[bucket]["bytes"] += row["size"] or 0

    return [
        {"bucket_start": bucket, "packets": data["packets"], "bytes": data["bytes"]}
        for bucket, data in sorted(buckets.items())
    ]


def fetch_alert_timeline(range_seconds=3600, bucket_seconds=300):
    cutoff = time() - range_seconds
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT COALESCE(last_seen, timestamp, 0) AS seen_at, severity
        FROM alerts
        WHERE COALESCE(last_seen, timestamp, 0) >= ?
        ORDER BY seen_at ASC
        """,
        (cutoff,),
    ).fetchall()
    conn.close()

    buckets = defaultdict(lambda: {"count": 0, "high": 0, "medium": 0, "low": 0})
    for row in rows:
        bucket = int(row["seen_at"] // bucket_seconds) * bucket_seconds
        severity = (row["severity"] or "Low").lower()
        buckets[bucket]["count"] += 1
        if severity in buckets[bucket]:
            buckets[bucket][severity] += 1

    return [
        {
            "bucket_start": bucket,
            "count": data["count"],
            "high": data["high"],
            "medium": data["medium"],
            "low": data["low"],
        }
        for bucket, data in sorted(buckets.items())
    ]


def fetch_protocol_mix(range_seconds=3600):
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT COALESCE(protocol, 'OTHER') AS protocol, COUNT(*) AS count
        FROM packets
        WHERE timestamp >= ?
        GROUP BY protocol
        ORDER BY count DESC
        """,
        (time() - range_seconds,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_top_domains(range_seconds=3600, limit=8):
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT domain, COUNT(*) AS count
        FROM packets
        WHERE timestamp >= ?
          AND domain IS NOT NULL
          AND domain != ''
        GROUP BY domain
        ORDER BY count DESC
        LIMIT ?
        """,
        (time() - range_seconds, limit),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def fetch_host_inventory(range_seconds=3600, limit=50, query=None):
    rows = _fetch_packet_rows_for_range(range_seconds, query=query)
    host_profiles = fetch_host_profiles()
    alert_counts = _fetch_host_alert_counts(range_seconds)

    hosts = {}
    for row in rows:
        ts = row["timestamp"]
        protocol = row["protocol"] or "OTHER"
        domain = row["domain"]
        size = row["size"] or 0
        for ip, peer, direction in (
            (row["src_ip"], row["dst_ip"], "outbound"),
            (row["dst_ip"], row["src_ip"], "inbound"),
        ):
            if not ip:
                continue
            host = hosts.setdefault(
                ip,
                {
                    "ip": ip,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "first_seen": ts,
                    "last_seen": ts,
                    "peers": set(),
                    "domains": Counter(),
                    "protocols": Counter(),
                    "inbound_packets": 0,
                    "outbound_packets": 0,
                },
            )
            host["packet_count"] += 1
            host["total_bytes"] += size
            host["first_seen"] = min(host["first_seen"], ts)
            host["last_seen"] = max(host["last_seen"], ts)
            if peer:
                host["peers"].add(peer)
            if domain:
                host["domains"][domain] += 1
            host["protocols"][protocol] += 1
            host[f"{direction}_packets"] += 1

    results = []
    for ip, host in hosts.items():
        profile = host_profiles.get(ip, {})
        top_protocol = host["protocols"].most_common(1)
        top_domain = host["domains"].most_common(1)
        results.append(
            {
                "ip": ip,
                "display_name": profile.get("display_name") or ip,
                "role": profile.get("role") or "unknown",
                "owner": profile.get("owner") or "",
                "notes": profile.get("notes") or "",
                "is_allowlisted": bool(profile.get("is_allowlisted")),
                "packet_count": host["packet_count"],
                "total_bytes": host["total_bytes"],
                "peer_count": len(host["peers"]),
                "top_protocol": top_protocol[0][0] if top_protocol else "OTHER",
                "top_domain": top_domain[0][0] if top_domain else "-",
                "inbound_packets": host["inbound_packets"],
                "outbound_packets": host["outbound_packets"],
                "first_seen": host["first_seen"],
                "last_seen": host["last_seen"],
                "alert_count": alert_counts.get(ip, 0),
            }
        )

    results.sort(key=lambda item: (item["alert_count"], item["packet_count"]), reverse=True)
    return results[:limit]


def fetch_host_profiles():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM host_profiles").fetchall()
    conn.close()
    return {row["ip"]: dict(row) for row in rows}


def upsert_host_profile(ip, display_name="", role="", owner="", notes="", is_allowlisted=False):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO host_profiles (ip, display_name, role, owner, notes, is_allowlisted, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            display_name = excluded.display_name,
            role = excluded.role,
            owner = excluded.owner,
            notes = excluded.notes,
            is_allowlisted = excluded.is_allowlisted,
            updated_at = excluded.updated_at
        """,
        (ip, display_name, role, owner, notes, 1 if is_allowlisted else 0, time()),
    )
    conn.commit()
    conn.close()
    return fetch_host_profiles().get(ip)


def fetch_host_details(ip, range_seconds=3600):
    rows = _fetch_packet_rows_for_range(range_seconds, host_ip=ip)
    profile = fetch_host_profiles().get(ip, {})
    alerts = fetch_alerts(limit=25, range_seconds=range_seconds, query=ip)

    peers = Counter()
    domains = Counter()
    ports = Counter()
    protocols = Counter()
    packet_count = 0
    total_bytes = 0
    first_seen = None
    last_seen = None

    for row in rows:
        packet_count += 1
        total_bytes += row["size"] or 0
        ts = row["timestamp"]
        first_seen = ts if first_seen is None else min(first_seen, ts)
        last_seen = ts if last_seen is None else max(last_seen, ts)
        peer = row["dst_ip"] if row["src_ip"] == ip else row["src_ip"]
        if peer:
            peers[peer] += 1
        if row["domain"]:
            domains[row["domain"]] += 1
        if row["dst_port"] is not None:
            ports[str(row["dst_port"])] += 1
        protocols[row["protocol"] or "OTHER"] += 1

    return {
        "ip": ip,
        "profile": {
            "display_name": profile.get("display_name") or ip,
            "role": profile.get("role") or "unknown",
            "owner": profile.get("owner") or "",
            "notes": profile.get("notes") or "",
            "is_allowlisted": bool(profile.get("is_allowlisted")),
        },
        "summary": {
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "peer_count": len(peers),
            "first_seen": first_seen,
            "last_seen": last_seen,
        },
        "top_peers": [{"value": value, "count": count} for value, count in peers.most_common(8)],
        "top_domains": [{"value": value, "count": count} for value, count in domains.most_common(8)],
        "top_ports": [{"value": value, "count": count} for value, count in ports.most_common(8)],
        "protocol_mix": [{"protocol": value, "count": count} for value, count in protocols.most_common()],
        "recent_alerts": alerts,
        "recent_packets": [dict(row) for row in rows[-25:]][::-1],
    }


def build_report_summary(range_seconds=86400):
    alerts = fetch_alerts(limit=500, range_seconds=range_seconds)
    hosts = fetch_host_inventory(range_seconds=range_seconds, limit=10)
    traffic = fetch_traffic_timeline(range_seconds=range_seconds, bucket_seconds=_bucket_for_range(range_seconds))
    protocol_mix = fetch_protocol_mix(range_seconds=range_seconds)

    return {
        "range_seconds": range_seconds,
        "generated_at": time(),
        "summary": fetch_dashboard_summary(range_seconds),
        "status_breakdown": fetch_alert_status_breakdown(range_seconds),
        "top_alerts": alerts[:10],
        "top_hosts": hosts,
        "traffic_timeline": traffic,
        "protocol_mix": protocol_mix,
        "top_domains": fetch_top_domains(range_seconds=range_seconds, limit=10),
    }


def _row_to_alert_dict(row):
    if row is None:
        return None
    data = dict(row)
    data["type"] = data.pop("alert_type")
    return data


def _fetch_packet_rows_for_range(range_seconds, query=None, host_ip=None):
    conn = get_connection()
    sql = """
        SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, domain
        FROM packets
        WHERE timestamp >= ?
    """
    params = [time() - range_seconds]
    if query:
        like = f"%{query}%"
        sql += """
            AND (
                COALESCE(src_ip, '') LIKE ?
                OR COALESCE(dst_ip, '') LIKE ?
                OR COALESCE(domain, '') LIKE ?
                OR COALESCE(protocol, '') LIKE ?
            )
        """
        params.extend([like, like, like, like])
    if host_ip:
        sql += " AND (src_ip = ? OR dst_ip = ?)"
        params.extend([host_ip, host_ip])
    sql += " ORDER BY timestamp ASC"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


def _fetch_host_alert_counts(range_seconds):
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT src_ip, dst_ip, COUNT(*) AS count
        FROM alerts
        WHERE COALESCE(last_seen, timestamp, 0) >= ?
        GROUP BY src_ip, dst_ip
        """,
        (time() - range_seconds,),
    ).fetchall()
    conn.close()

    counts = Counter()
    for row in rows:
        if row["src_ip"]:
            counts[row["src_ip"]] += row["count"]
        if row["dst_ip"]:
            counts[row["dst_ip"]] += row["count"]
    return counts


def _bucket_for_range(range_seconds):
    if range_seconds <= 3600:
        return 60
    if range_seconds <= 6 * 3600:
        return 300
    if range_seconds <= 24 * 3600:
        return 900
    return 3600
