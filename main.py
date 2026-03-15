from analysis.engine import analyze_current_flows
from storage.database import initialize_database

def main():
    initialize_database()
    result = analyze_current_flows(store_alerts=True)
    alerts = result["alerts"]

    if not alerts:
        print("No suspicious behavior detected.")
    else:
        for alert in alerts:
            print("ALERT STORED:", alert)

    print("Risk Score:", result["risk_score"])
    print("Rule Alerts:", len(result["rule_alerts"]))
    print("Statistical Alerts:", len(result["stat_alerts"]))
    print("ML Alerts:", len(result["ml_alerts"]))

if __name__ == "__main__":
    main()
