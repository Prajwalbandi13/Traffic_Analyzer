"""
Web UI + API for live packet capture, incident triage, host inventory, and reporting.
"""

from flask import Flask, jsonify, render_template, request

from analysis.engine import analyze_current_flows
from capture.controller import get_status, restart_capture, start_capture, stop_capture
from detection.ml_based import MIN_TRAIN_SAMPLES, model_exists, train_isolation_forest
from preprocessing.feature_extractor import FEATURE_WINDOW
from preprocessing.flow_builder import TIME_WINDOW
from storage.database import (
    build_report_summary,
    clear_packets_and_alerts,
    fetch_alert_by_id,
    fetch_alert_status_breakdown,
    fetch_alert_timeline,
    fetch_alerts,
    fetch_dashboard_summary,
    fetch_host_details,
    fetch_host_inventory,
    fetch_protocol_mix,
    fetch_recent_packets,
    fetch_top_domains,
    fetch_traffic_timeline,
    initialize_database,
    update_alert,
    upsert_host_profile,
)


app = Flask(__name__, template_folder="templates", static_folder="static")
initialize_database()


def _range_seconds(default=3600):
    try:
        return max(int(request.args.get("range", default)), 300)
    except (TypeError, ValueError):
        return default


def _limit(default=50, maximum=500):
    try:
        return min(max(int(request.args.get("limit", default)), 1), maximum)
    except (TypeError, ValueError):
        return default


def _bucket_for_range(range_seconds):
    if range_seconds <= 3600:
        return 60
    if range_seconds <= 6 * 3600:
        return 300
    if range_seconds <= 24 * 3600:
        return 900
    return 3600


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analysis")
def analysis_page():
    return render_template("analysis.html")


@app.route("/api/status")
def status():
    return jsonify(get_status())


@app.route("/api/start", methods=["POST"])
def api_start():
    started = start_capture()
    return jsonify({"started": started, "status": get_status()})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    stopped = stop_capture()
    return jsonify({"stopped": stopped, "status": get_status()})


@app.route("/api/restart", methods=["POST"])
def api_restart():
    payload = request.get_json(silent=True) or {}
    running = restart_capture(clear_history=bool(payload.get("clear_history")))
    return jsonify({"running": running, "status": get_status()})


@app.route("/api/history/reset", methods=["POST"])
def api_reset_history():
    payload = request.get_json(silent=True) or {}
    clear_packets_and_alerts(clear_features=bool(payload.get("clear_features")))
    return jsonify({"cleared": True, "status": get_status()})


@app.route("/api/packets")
def packets():
    return jsonify(
        fetch_recent_packets(
            limit=_limit(default=100, maximum=500),
            range_seconds=_range_seconds(),
            query=request.args.get("query"),
            protocol=request.args.get("protocol"),
        )
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    result = analyze_current_flows(store_alerts=True)
    result["parameters"] = [
        {"id": 1, "name": "Flow Time Window (seconds)", "value": TIME_WINDOW},
        {"id": 2, "name": "Feature Window (seconds)", "value": FEATURE_WINDOW},
        {"id": 3, "name": "ML Min Training Samples", "value": MIN_TRAIN_SAMPLES},
    ]
    result["capture_status"] = get_status()
    return jsonify(result)


@app.route("/api/ml/train", methods=["POST"])
def api_ml_train():
    result = train_isolation_forest(min_samples=MIN_TRAIN_SAMPLES)
    result["model_trained"] = model_exists()
    return jsonify(result)


@app.route("/api/dashboard")
def api_dashboard():
    range_seconds = _range_seconds()
    query = request.args.get("query")
    protocol = request.args.get("protocol")
    severity = request.args.get("severity")
    alert_status = request.args.get("alert_status")

    live_analysis = analyze_current_flows(store_alerts=False, persist_features_for_ml=False)
    return jsonify(
        {
            "status": get_status(),
            "range_seconds": range_seconds,
            "summary": fetch_dashboard_summary(range_seconds),
            "risk": {
                "score": live_analysis["risk_score"],
                "level": live_analysis["risk_level"],
                "detector_breakdown": live_analysis["detector_breakdown"],
                "threat_insights": live_analysis["threat_insights"],
            },
            "alerts": fetch_alerts(
                limit=_limit(default=20, maximum=100),
                range_seconds=range_seconds,
                status=alert_status,
                severity=severity,
                query=query,
            ),
            "status_breakdown": fetch_alert_status_breakdown(range_seconds),
            "hosts": fetch_host_inventory(
                range_seconds=range_seconds,
                limit=_limit(default=12, maximum=100),
                query=query,
            ),
            "packets": fetch_recent_packets(
                limit=_limit(default=50, maximum=200),
                range_seconds=range_seconds,
                query=query,
                protocol=protocol,
            ),
            "traffic_timeline": fetch_traffic_timeline(
                range_seconds=range_seconds, bucket_seconds=_bucket_for_range(range_seconds)
            ),
            "alert_timeline": fetch_alert_timeline(
                range_seconds=range_seconds, bucket_seconds=_bucket_for_range(range_seconds)
            ),
            "protocol_mix": fetch_protocol_mix(range_seconds),
            "top_domains": fetch_top_domains(range_seconds, limit=8),
        }
    )


@app.route("/api/alerts")
def api_alerts():
    return jsonify(
        fetch_alerts(
            limit=_limit(default=100, maximum=500),
            range_seconds=_range_seconds(default=24 * 3600),
            status=request.args.get("status"),
            severity=request.args.get("severity"),
            query=request.args.get("query"),
        )
    )


@app.route("/api/alerts/<int:alert_id>")
def api_alert_detail(alert_id):
    alert = fetch_alert_by_id(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert)


@app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
def api_update_alert(alert_id):
    payload = request.get_json(silent=True) or {}
    alert = update_alert(
        alert_id,
        status=payload.get("status"),
        owner=payload.get("owner"),
        notes=payload.get("notes"),
        resolution=payload.get("resolution"),
    )
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert)


@app.route("/api/hosts")
def api_hosts():
    return jsonify(
        fetch_host_inventory(
            range_seconds=_range_seconds(default=24 * 3600),
            limit=_limit(default=100, maximum=500),
            query=request.args.get("query"),
        )
    )


@app.route("/api/hosts/<path:host_ip>")
def api_host_detail(host_ip):
    return jsonify(fetch_host_details(host_ip, range_seconds=_range_seconds(default=24 * 3600)))


@app.route("/api/hosts/<path:host_ip>", methods=["PATCH"])
def api_host_update(host_ip):
    payload = request.get_json(silent=True) or {}
    profile = upsert_host_profile(
        host_ip,
        display_name=payload.get("display_name", ""),
        role=payload.get("role", ""),
        owner=payload.get("owner", ""),
        notes=payload.get("notes", ""),
        is_allowlisted=bool(payload.get("is_allowlisted")),
    )
    return jsonify(profile)


@app.route("/api/trends")
def api_trends():
    range_seconds = _range_seconds(default=24 * 3600)
    bucket_seconds = _bucket_for_range(range_seconds)
    return jsonify(
        {
            "range_seconds": range_seconds,
            "traffic_timeline": fetch_traffic_timeline(range_seconds, bucket_seconds),
            "alert_timeline": fetch_alert_timeline(range_seconds, bucket_seconds),
            "protocol_mix": fetch_protocol_mix(range_seconds),
            "top_domains": fetch_top_domains(range_seconds, limit=10),
            "status_breakdown": fetch_alert_status_breakdown(range_seconds),
        }
    )


@app.route("/api/report/summary")
def api_report_summary():
    return jsonify(build_report_summary(range_seconds=_range_seconds(default=24 * 3600)))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
