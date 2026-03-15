"""
Module: live_capture.py

Purpose:
- Capture live network packets in real time
- Extract header-level metadata
- Store structured packet data into SQLite database

NOTE:
- This module does NOT perform detection
- This module does NOT analyze traffic
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSRR, Raw
from storage.database import insert_packet
from analysis.engine import run_detection_cycle

_IP_TO_DOMAIN = {}
_TLS_BUFFER = {}
_TLS_BUFFER_TS = {}
_HTTP_BUFFER = {}


def _normalize_domain(name):
    if not name:
        return None
    if isinstance(name, bytes):
        name = name.decode(errors="ignore")
    return name.rstrip(".").lower()


def _update_dns_mappings(packet):
    if DNS not in packet:
        return

    dns = packet[DNS]
    if dns.qr != 1 or dns.ancount == 0:
        return

    for i in range(dns.ancount):
        rr = dns.an[i]
        if not isinstance(rr, DNSRR):
            continue

        if rr.type in (1, 28):  # A or AAAA
            full_domain = _normalize_domain(rr.rrname)
            if not full_domain:
                continue
            ip_value = rr.rdata
            if isinstance(ip_value, bytes):
                ip_value = ip_value.decode(errors="ignore")
            _IP_TO_DOMAIN[str(ip_value)] = full_domain


def _extract_sni_from_client_hello(body):
    if not body or len(body) < 42:
        return None

    # ClientHello: version(2) + random(32) + session_id
    idx = 2 + 32
    if idx + 1 > len(body):
        return None
    session_id_len = body[idx]
    idx += 1 + session_id_len

    if idx + 2 > len(body):
        return None
    cipher_suites_len = int.from_bytes(body[idx:idx + 2], "big")
    idx += 2 + cipher_suites_len

    if idx + 1 > len(body):
        return None
    comp_methods_len = body[idx]
    idx += 1 + comp_methods_len

    if idx + 2 > len(body):
        return None
    ext_len = int.from_bytes(body[idx:idx + 2], "big")
    idx += 2
    end = idx + ext_len

    while idx + 4 <= len(body) and idx + 4 <= end:
        ext_type = int.from_bytes(body[idx:idx + 2], "big")
        ext_size = int.from_bytes(body[idx + 2:idx + 4], "big")
        idx += 4

        if ext_type == 0x0000:  # SNI
            if idx + 2 > len(body):
                return None
            list_len = int.from_bytes(body[idx:idx + 2], "big")
            idx += 2
            list_end = idx + list_len

            while idx + 3 <= len(body) and idx + 3 <= list_end:
                name_type = body[idx]
                name_len = int.from_bytes(body[idx + 1:idx + 3], "big")
                idx += 3
                name_bytes = body[idx:idx + name_len]
                idx += name_len
                if name_type == 0:
                    try:
                        return name_bytes.decode("utf-8").lower()
                    except UnicodeDecodeError:
                        return None
            return None

        idx += ext_size

    return None


def _extract_sni_from_tls(payload):
    """
    Minimal TLS ClientHello parser to extract SNI without extra deps.
    Returns hostname or None.
    """
    if not payload or len(payload) < 5:
        return None

    # TLS record header
    content_type = payload[0]
    if content_type != 0x16:  # Handshake
        return None

    # Skip record header: type(1) + version(2) + length(2)
    if len(payload) < 5:
        return None
    record_len = int.from_bytes(payload[3:5], "big")
    record = payload[5:5 + record_len]

    # Handshake header
    if len(record) < 4:
        return None
    hs_type = record[0]
    if hs_type != 0x01:  # ClientHello
        return None

    hs_len = int.from_bytes(record[1:4], "big")
    body = record[4:4 + hs_len]
    return _extract_sni_from_client_hello(body)


def _extract_sni_from_quic(payload):
    """
    Best-effort QUIC ClientHello parser (no decryption).
    Scans for TLS ClientHello inside CRYPTO frames.
    """
    if not payload or len(payload) < 6:
        return None

    # Heuristic: look for handshake type 0x01 and a plausible length
    for i in range(0, min(len(payload) - 4, 1200)):
        if payload[i] != 0x01:
            continue
        hs_len = int.from_bytes(payload[i + 1:i + 4], "big")
        if hs_len <= 0 or hs_len > 4096:
            continue
        body = payload[i + 4:i + 4 + hs_len]
        sni = _extract_sni_from_client_hello(body)
        if sni:
            return sni
    return None


def _update_sni_mappings(packet):
    if TCP not in packet:
        return
    tcp = packet[TCP]
    if tcp.dport != 443:
        return

    if Raw not in packet:
        return

    payload = bytes(packet[Raw].load)
    if not payload:
        return

    key = (packet[IP].src, packet[IP].dst, tcp.sport, tcp.dport)
    buf = _TLS_BUFFER.get(key, b"")
    buf += payload

    # Cap buffer to avoid memory growth
    if len(buf) > 4096:
        buf = buf[-4096:]

    _TLS_BUFFER[key] = buf
    _TLS_BUFFER_TS[key] = packet.time if hasattr(packet, "time") else None

    sni = _extract_sni_from_tls(buf)
    if not sni:
        return
    _IP_TO_DOMAIN[str(packet[IP].dst)] = sni

    # Clean up once resolved
    _TLS_BUFFER.pop(key, None)
    _TLS_BUFFER_TS.pop(key, None)


def _update_http_host_mappings(packet):
    if TCP not in packet:
        return
    tcp = packet[TCP]
    if Raw not in packet:
        return

    if tcp.dport not in (80, 8080, 8000, 3000, 5000) and tcp.sport not in (
        80, 8080, 8000, 3000, 5000
    ):
        return

    payload = bytes(packet[Raw].load)
    if not payload:
        return

    key = (packet[IP].src, packet[IP].dst, tcp.sport, tcp.dport)
    buf = _HTTP_BUFFER.get(key, b"") + payload
    if len(buf) > 4096:
        buf = buf[-4096:]
    _HTTP_BUFFER[key] = buf

    if b"\r\n\r\n" not in buf:
        return

    headers = buf.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    for line in headers:
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().decode(errors="ignore").lower()
            if host:
                _IP_TO_DOMAIN[str(packet[IP].dst)] = host
            break


def _update_quic_mappings(packet):
    if UDP not in packet or Raw not in packet:
        return
    udp = packet[UDP]
    if udp.dport != 443 and udp.sport != 443:
        return

    payload = bytes(packet[Raw].load)
    sni = _extract_sni_from_quic(payload)
    if not sni:
        return
    _IP_TO_DOMAIN[str(packet[IP].dst)] = sni


def process_packet(packet):
    """
    Converts a captured packet into structured data
    and stores it in the database.
    """

    # Ignore non-IP packets
    if IP not in packet:
        return

    _update_dns_mappings(packet)
    _update_sni_mappings(packet)
    _update_http_host_mappings(packet)
    _update_quic_mappings(packet)

    packet_data = {
        "timestamp": float(getattr(packet, "time", 0.0) or 0.0),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "size": len(packet),
        "domain": None,
        "tcp_flags": None,
    }

    # TCP packet
    if TCP in packet:
        packet_data["protocol"] = "TCP"
        packet_data["src_port"] = packet[TCP].sport
        packet_data["dst_port"] = packet[TCP].dport
        packet_data["tcp_flags"] = str(packet[TCP].flags)

    # UDP packet
    elif UDP in packet:
        packet_data["protocol"] = "UDP"
        packet_data["src_port"] = packet[UDP].sport
        packet_data["dst_port"] = packet[UDP].dport

    # Other protocols
    else:
        packet_data["protocol"] = "OTHER"

    # Attach domain if we have a recent DNS/SNI mapping
    packet_data["domain"] = (
        _IP_TO_DOMAIN.get(packet_data["dst_ip"])
        or _IP_TO_DOMAIN.get(packet_data["src_ip"])
    )

    # Show domain on DNS packets themselves (query/answer)
    if packet_data["domain"] is None and DNS in packet:
        dns = packet[DNS]
        if dns.qd is not None and hasattr(dns.qd, "qname"):
            packet_data["domain"] = _normalize_domain(dns.qd.qname)
        elif dns.ancount and dns.an is not None and hasattr(dns.an, "rrname"):
            packet_data["domain"] = _normalize_domain(dns.an.rrname)

    if not packet_data["timestamp"]:
        return

    insert_packet(packet_data)

    # Run coordinated detection periodically while capture is live
    new_alerts = run_detection_cycle()


def start_live_capture():
    """
    Starts live packet capture.
    Press CTRL+C to stop.
    """
    print("Starting live packet capture...")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_live_capture()
