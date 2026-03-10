"""
Isolation Forest based anomaly detection on windowed traffic features.
"""

from pathlib import Path
import pickle
import time
import warnings

from storage.database import fetch_feature_dataset, fetch_non_ml_alert_windows

try:
    from sklearn.ensemble import IsolationForest
    try:
        from sklearn.exceptions import InconsistentVersionWarning
    except Exception:  # pragma: no cover - sklearn version dependent
        InconsistentVersionWarning = Warning
except Exception:  # pragma: no cover - runtime environment dependent
    IsolationForest = None
    InconsistentVersionWarning = Warning


MODEL_PATH = Path(__file__).parent / "models" / "isolation_forest.pkl"
MIN_TRAIN_SAMPLES = 30
DEFAULT_CONTAMINATION = 0.1

FEATURE_COLUMNS = [
    "packet_count",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "max_packet_size",
    "packet_size_variance",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_dst_ports",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "avg_inter_arrival",
    "inter_arrival_variance",
]


def _ensure_model_dir():
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)


def _row_to_feature_vector(row):
    # row[0] is window_start
    return [float(v) for v in row[1:]]


def _rows_to_matrix(rows):
    return [_row_to_feature_vector(row) for row in rows]


def is_ml_supported():
    return IsolationForest is not None


def model_exists():
    return MODEL_PATH.exists()


def load_model():
    if not model_exists():
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            with MODEL_PATH.open("rb") as f:
                payload = pickle.load(f)
    except Exception:
        return None
    if isinstance(payload, dict) and "model" in payload:
        return payload["model"]
    return payload


def get_model_metadata():
    if not model_exists():
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InconsistentVersionWarning)
            with MODEL_PATH.open("rb") as f:
                payload = pickle.load(f)
    except Exception as exc:
        return {"format": "unreadable_model_pickle", "error": str(exc)}
    if isinstance(payload, dict) and "model" in payload:
        return payload.get("metadata", {})
    # Backward compatibility with old model-only pickle
    return {"format": "legacy_model_pickle"}


def train_isolation_forest(min_samples=MIN_TRAIN_SAMPLES, contamination=DEFAULT_CONTAMINATION):
    """
    Trains and stores an Isolation Forest model using stored feature vectors.
    """
    if not is_ml_supported():
        return {
            "trained": False,
            "reason": "scikit-learn is not installed",
            "sample_count": 0,
        }

    rows = fetch_feature_dataset()
    if len(rows) < min_samples:
        return {
            "trained": False,
            "reason": f"insufficient samples ({len(rows)}/{min_samples})",
            "sample_count": len(rows),
        }

    X = _rows_to_matrix(rows)
    model = IsolationForest(
        n_estimators=120,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)

    _ensure_model_dir()
    report = _compute_weak_label_metrics(model, rows)
    metadata = {
        "trained_at_epoch": time.time(),
        "sample_count": len(rows),
        "evaluation": report,
    }
    with MODEL_PATH.open("wb") as f:
        pickle.dump({"model": model, "metadata": metadata}, f)

    return {
        "trained": True,
        "sample_count": len(rows),
        "model_path": str(MODEL_PATH),
        "evaluation": report,
        "metadata": metadata,
    }


def detect_anomalies_for_rows(rows):
    """
    Returns ML anomaly alerts for provided feature rows.
    """
    model = load_model()
    if model is None or not rows:
        return []

    X = _rows_to_matrix(rows)
    predictions = model.predict(X)  # -1 anomaly, 1 normal
    scores = model.decision_function(X)  # lower means more anomalous

    means, stds = _feature_stats(rows)
    alerts = []
    for idx, pred in enumerate(predictions):
        if pred != -1:
            continue
        row = rows[idx]
        window_start = row[0]
        score = float(scores[idx])
        alerts.append({
            "type": "ML Anomaly (Isolation Forest)",
            "src_ip": "N/A",
            "dst_ip": "N/A",
            "severity": "Medium",
            "reason": f"Anomalous traffic behavior detected (score={score:.4f})",
            "time_window": window_start,
            "anomaly_score": score,
            "top_abnormal_features": _top_abnormal_features(row, means, stds),
        })
    return alerts


def _feature_stats(rows):
    matrix = _rows_to_matrix(rows)
    if not matrix:
        return [0.0] * len(FEATURE_COLUMNS), [1.0] * len(FEATURE_COLUMNS)
    cols = list(zip(*matrix))
    means = [sum(c) / len(c) for c in cols]
    stds = []
    for c, m in zip(cols, means):
        if len(c) < 2:
            stds.append(1.0)
            continue
        var = sum((x - m) ** 2 for x in c) / len(c)
        stds.append(var ** 0.5 if var > 0 else 1.0)
    return means, stds


def _top_abnormal_features(row, means, stds, top_n=3):
    values = _row_to_feature_vector(row)
    scored = []
    for idx, value in enumerate(values):
        z = (value - means[idx]) / stds[idx] if stds[idx] else 0.0
        scored.append((abs(z), z, FEATURE_COLUMNS[idx], value))
    scored.sort(reverse=True, key=lambda item: item[0])
    top = scored[:top_n]
    return [
        {
            "feature": feature,
            "z_score": round(z_value, 3),
            "value": round(raw_value, 3),
        }
        for _, z_value, feature, raw_value in top
    ]


def _compute_weak_label_metrics(model, rows):
    """
    Computes weak-label metrics using existing non-ML alert windows as anomaly labels.
    These are monitoring metrics, not ground-truth security benchmarks.
    """
    if not rows:
        return {
            "label_source": "non_ml_alert_windows",
            "available": False,
            "reason": "no feature rows",
        }

    alert_windows = set(fetch_non_ml_alert_windows())
    if not alert_windows:
        return {
            "label_source": "non_ml_alert_windows",
            "available": False,
            "reason": "no non-ML alerts available for weak labels",
        }

    X = _rows_to_matrix(rows)
    preds = model.predict(X)  # -1 anomaly

    tp = fp = fn = 0
    positives = 0
    for idx, row in enumerate(rows):
        window_start = int(row[0])
        actual_anomaly = window_start in alert_windows
        predicted_anomaly = preds[idx] == -1

        positives += 1 if actual_anomaly else 0
        if predicted_anomaly and actual_anomaly:
            tp += 1
        elif predicted_anomaly and not actual_anomaly:
            fp += 1
        elif (not predicted_anomaly) and actual_anomaly:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "label_source": "non_ml_alert_windows",
        "available": True,
        "support": positives,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
    }
