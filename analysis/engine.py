"""
Module: engine.py

Responsibility:
- Coordinate rule-based and statistical detection
- Run detections on built flows at a safe interval
- Store new alerts without duplicate spam
"""

from threading import Lock
from time import time

from detection.rule_based import (
    detect_port_scan,
    detect_dos_burst,
    detect_repeated_failed_connections,
)
from detection.statistical import detect_traffic_spike
from detection.ml_based import (
    MIN_TRAIN_SAMPLES,
    detect_anomalies_for_rows,
    get_model_metadata,
    is_ml_supported,
    load_model,
    model_exists,
    train_isolation_forest,
)
from preprocessing.feature_extractor import build_window_features, persist_window_features
from preprocessing.flow_builder import build_flows, TIME_WINDOW
from storage.database import fetch_feature_dataset, insert_alert


_LOCK = Lock()
_LAST_RUN = 0.0
_SEEN_ALERT_KEYS = set()
RECENT_WINDOW_LOOKBACK_SECONDS = 60
ML_RECENT_WINDOWS = 12

ALERT_EXPLANATIONS = {
    "Possible Port Scan": {
        "what": "Many different destination ports were probed in a short window.",
        "possible_causes": "Automated scan, service discovery, or aggressive health-check tools.",
        "impact": "May indicate reconnaissance before targeted attacks.",
    },
    "Possible DoS Burst": {
        "what": "Very high packet volume from one source to one destination.",
        "possible_causes": "Traffic flood, stress testing, retry storms, or misconfigured clients.",
        "impact": "Can degrade service availability.",
    },
    "Repeated Failed Connections": {
        "what": "Repeated SYN-without-ACK or high RST pattern observed.",
        "possible_causes": "Unreachable service, blocked ports, firewall resets, or brute-force attempts.",
        "impact": "May indicate unauthorized access attempts or unstable connectivity.",
    },
    "Traffic Spike": {
        "what": "Traffic volume in a flow exceeded normal baseline significantly.",
        "possible_causes": "Bulk transfer, update/download bursts, or suspicious traffic surges.",
        "impact": "Could hide abuse in high-volume windows.",
    },
    "ML Anomaly (Isolation Forest)": {
        "what": "Window behavior deviated from learned normal profile.",
        "possible_causes": "Rare but benign behavior, new application pattern, or suspicious activity.",
        "impact": "Requires correlation with rule/stat alerts.",
    },
}


def _dedupe_alerts(alerts):
    """
    Filters out alerts that were already stored for the same
    (type, src_ip, dst_ip, time_window).
    """
    global _SEEN_ALERT_KEYS
    new_alerts = []

    for alert in alerts:
        key = (alert["type"], alert["src_ip"], alert["dst_ip"], alert["time_window"])
        if key in _SEEN_ALERT_KEYS:
            continue
        _SEEN_ALERT_KEYS.add(key)
        new_alerts.append(alert)

    # Simple cleanup to avoid unbounded memory growth
    if len(_SEEN_ALERT_KEYS) > 5000:
        cutoff_window = int(time() // TIME_WINDOW - 2) * TIME_WINDOW
        _SEEN_ALERT_KEYS = {
            key for key in _SEEN_ALERT_KEYS if key[3] >= cutoff_window
        }

    return new_alerts


def run_detectors(flows):
    """
    Runs both rule-based and statistical detectors on the same flows.
    """
    rule_alerts = (
        detect_port_scan(flows)
        + detect_dos_burst(flows)
        + detect_repeated_failed_connections(flows)
    )
    stat_alerts = detect_traffic_spike(flows)
    return rule_alerts + stat_alerts


def run_detection_cycle(force=False):
    """
    Runs detection at most once per TIME_WINDOW unless forced.
    Returns only newly stored alerts.
    """
    global _LAST_RUN
    now = time()

    if not force and (now - _LAST_RUN) < TIME_WINDOW:
        return []

    with _LOCK:
        if not force and (now - _LAST_RUN) < TIME_WINDOW:
            return []

        flows = build_flows()
        alerts = run_detectors(flows)
        new_alerts = _dedupe_alerts(alerts)

        for alert in new_alerts:
            insert_alert(_enrich_alert(alert))

        _LAST_RUN = now
        return new_alerts


def _enrich_alert(alert):
    info = ALERT_EXPLANATIONS.get(alert["type"], {})
    enriched = dict(alert)
    enriched["what"] = info.get("what", "Suspicious behavior pattern observed.")
    enriched["possible_causes"] = info.get("possible_causes", "Requires further investigation.")
    enriched["impact"] = info.get("impact", "Potential security relevance.")
    enriched["where"] = f"{alert.get('src_ip', 'N/A')} -> {alert.get('dst_ip', 'N/A')}"
    return enriched


def _filter_recent_alerts(alerts, latest_window, lookback_seconds=RECENT_WINDOW_LOOKBACK_SECONDS):
    threshold = latest_window - lookback_seconds
    return [a for a in alerts if float(a.get("time_window", 0)) >= threshold]


def _risk_from_alerts(alerts):
    """
    Calibrated score: weighted recent alerts with category caps.
    """
    severity_weight = {"High": 18, "Medium": 8, "Low": 3}
    rule_alerts = [a for a in alerts if a["type"] not in ("Traffic Spike", "ML Anomaly (Isolation Forest)")]
    stat_alerts = [a for a in alerts if a["type"] == "Traffic Spike"]
    ml_alerts = [a for a in alerts if "ML Anomaly" in a["type"]]

    rule_count = len(rule_alerts)
    stat_count = len(stat_alerts)
    ml_count = len(ml_alerts)

    rule_score = sum(severity_weight.get(a.get("severity"), 0) for a in rule_alerts)
    stat_score = int(sum(severity_weight.get(a.get("severity"), 0) for a in stat_alerts) * 0.7)

    # ML is anomaly-only; keep it as supportive signal unless corroborated.
    if (rule_count + stat_count) > 0:
        ml_score = min(ml_count * 3, 15)
    else:
        ml_score = min(ml_count * 1, 8)

    score = rule_score + stat_score + ml_score

    # Additional caps for practical interpretability.
    if rule_count == 0 and stat_count == 0:
        score = min(score, 25)
    elif rule_count == 0:
        score = min(score, 45)
    else:
        score = min(score, 85)

    if score < 15:
        level = "Low"
    elif score < 40:
        level = "Moderate"
    elif score < 70:
        level = "Elevated"
    else:
        level = "High"

    return int(min(score, 100)), level, {
        "rule_alerts": rule_count,
        "statistical_alerts": stat_count,
        "ml_alerts": ml_count,
    }


def _build_threat_insights(alerts):
    by_type = {}
    for alert in alerts:
        alert_type = alert["type"]
        by_type.setdefault(alert_type, {"count": 0, "sample": alert})
        by_type[alert_type]["count"] += 1

    insights = []
    for alert_type, meta in by_type.items():
        sample = _enrich_alert(meta["sample"])
        insights.append({
            "type": alert_type,
            "count": meta["count"],
            "what": sample["what"],
            "possible_causes": sample["possible_causes"],
            "impact": sample["impact"],
            "where": sample["where"],
            "window": sample.get("time_window"),
        })
    return insights


def analyze_current_flows(store_alerts=True, persist_features_for_ml=True, auto_train_ml=True):
    """
    Runs rule-based + statistical analysis on current flows
    and returns alerts + a risk score.
    """
    flows = build_flows()
    rule_alerts = (
        detect_port_scan(flows)
        + detect_dos_burst(flows)
        + detect_repeated_failed_connections(flows)
    )
    stat_alerts = detect_traffic_spike(flows)
    window_features = build_window_features()
    if persist_features_for_ml:
        persist_window_features(window_features)

    dataset_rows = fetch_feature_dataset()
    loaded_model = load_model()
    model_metadata = get_model_metadata() if model_exists() else None
    ml_status = {
        "supported": is_ml_supported(),
        "model_trained": loaded_model is not None,
        "training": None,
        "model_metadata": model_metadata,
    }

    # Keep ML training backend-driven so the UI does not expose model management.
    if ml_status["supported"] and auto_train_ml and len(dataset_rows) >= MIN_TRAIN_SAMPLES:
        ml_status["training"] = train_isolation_forest(min_samples=MIN_TRAIN_SAMPLES)
        ml_status["model_trained"] = load_model() is not None
        dataset_rows = fetch_feature_dataset()
        model_metadata = get_model_metadata() if model_exists() else None
        ml_status["model_metadata"] = model_metadata

    ml_rows = dataset_rows[-ML_RECENT_WINDOWS:] if dataset_rows else []
    ml_alerts = detect_anomalies_for_rows(ml_rows) if ml_status["model_trained"] else []

    latest_flow_window = max((key[2] for key in flows.keys()), default=0)
    recent_rule_alerts = _filter_recent_alerts(rule_alerts, latest_flow_window)
    recent_stat_alerts = _filter_recent_alerts(stat_alerts, latest_flow_window)
    recent_alerts = recent_rule_alerts + recent_stat_alerts + ml_alerts

    new_alerts = _dedupe_alerts(recent_alerts)

    if store_alerts:
        for alert in new_alerts:
            insert_alert(_enrich_alert(alert))

    enriched_alerts = [_enrich_alert(a) for a in recent_alerts]
    score, risk_level, breakdown = _risk_from_alerts(recent_alerts)
    insights = _build_threat_insights(recent_alerts)
    top_ml_features = []
    for alert in ml_alerts:
        for feat in alert.get("top_abnormal_features", []):
            top_ml_features.append(feat)
    top_ml_features = sorted(top_ml_features, key=lambda x: abs(x.get("z_score", 0)), reverse=True)[:6]

    if ml_status["training"] is None:
        if ml_status["model_trained"]:
            ml_status["last_training_state"] = "Model already trained and loaded"
        else:
            ml_status["last_training_state"] = "Awaiting enough samples to train"
    elif ml_status["training"].get("trained"):
        ml_status["last_training_state"] = "Trained in this analysis cycle"
    else:
        ml_status["last_training_state"] = ml_status["training"].get("reason", "Training skipped")

    return {
        "alerts": enriched_alerts,
        "rule_alerts": [_enrich_alert(a) for a in recent_rule_alerts],
        "stat_alerts": [_enrich_alert(a) for a in recent_stat_alerts],
        "ml_alerts": ml_alerts,
        "threat_insights": insights,
        "top_abnormal_features": top_ml_features,
        "detector_breakdown": breakdown,
        "feature_windows": len(window_features),
        "feature_dataset_size": len(dataset_rows),
        "ml_status": ml_status,
        "risk_score": score,
        "risk_level": risk_level,
        "alert_count": len(recent_alerts),
        "new_alert_count": len(new_alerts),
    }


def train_ml_from_current_packets():
    """
    Builds/persists feature windows from current packets and trains ML model.
    Returns training result payload.
    """
    window_features = build_window_features()
    persist_window_features(window_features)
    result = train_isolation_forest(min_samples=MIN_TRAIN_SAMPLES)
    result["feature_windows_processed"] = len(window_features)
    result["feature_dataset_size"] = len(fetch_feature_dataset())
    return result


def auto_train_ml_with_terminal_report():
    """
    Triggers ML training and prints a terminal report.
    """
    print("[ML] Auto-training started...")
    result = train_ml_from_current_packets()
    print(f"[ML] Feature windows processed: {result.get('feature_windows_processed', 0)}")
    print(f"[ML] Feature dataset size: {result.get('feature_dataset_size', 0)}")

    if result.get("trained"):
        print(f"[ML] Model trained successfully on {result.get('sample_count', 0)} samples")
    else:
        print(f"[ML] Training skipped: {result.get('reason', 'unknown reason')}")

    evaluation = result.get("evaluation")
    if evaluation and evaluation.get("available"):
        print(
            "[ML] Weak-label metrics "
            f"(precision={evaluation['precision']:.4f}, "
            f"recall={evaluation['recall']:.4f}, "
            f"f1={evaluation['f1_score']:.4f})"
        )
        print("[ML] Label source: non-ML alert windows (proxy, not ground truth)")
    elif evaluation:
        print(f"[ML] Metrics unavailable: {evaluation.get('reason', 'unknown reason')}")

    return result
