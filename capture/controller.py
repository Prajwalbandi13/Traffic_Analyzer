"""
Module: controller.py

Responsibility:
- Manage live capture lifecycle (start/stop/restart)
"""

from threading import Lock
from time import time

from scapy.all import AsyncSniffer

from analysis.engine import auto_train_ml_with_terminal_report
from capture.live_capture import process_packet
from storage.database import clear_packets_and_alerts, get_packet_count


_LOCK = Lock()
_SNIFFER = None
_STARTED_AT = None


def is_running():
    return _SNIFFER is not None and _SNIFFER.running


def start_capture():
    """
    Starts packet capture in the background.
    Returns True if started, False if already running.
    """
    global _SNIFFER, _STARTED_AT

    with _LOCK:
        if is_running():
            return False

        _SNIFFER = AsyncSniffer(prn=process_packet, store=False)
        _SNIFFER.start()
        _STARTED_AT = time()
        return True


def stop_capture():
    """
    Stops packet capture if running.
    Returns True if stopped, False if it was not running.
    """
    global _SNIFFER

    with _LOCK:
        if not is_running():
            return False

        _SNIFFER.stop()
        _SNIFFER = None
        auto_train_ml_with_terminal_report()
        return True


def get_status():
    return {
        "running": is_running(),
        "started_at": _STARTED_AT,
        "packet_count": get_packet_count(),
    }


def restart_capture(clear_history=False):
    """
    Restarts capture and optionally clears stored history.
    Returns True if capture is running at the end.
    """
    stop_capture()
    if clear_history:
        clear_packets_and_alerts(clear_features=True)
    start_capture()
    return is_running()
