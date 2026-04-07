from ingestion.log_parser import parse_auth_log
from detection.brute_force import detect_brute_force
from detection.suspicious_behavior import detect_suspicious_behavior
from detection.risk_scoring import calculate_risk_scores
from alerts.alert_manager import generate_alerts

def main():
    logs = parse_auth_log("data/auth.log")

    brute_force_results = detect_brute_force(logs)
    suspicious_results = detect_suspicious_behavior(logs)

    risk_scores = calculate_risk_scores(
        brute_force_results,
        suspicious_results
    )

    alerts = generate_alerts(risk_scores)

    print("\n=== RISK-BASED ALERTS ===\n")
    for alert in alerts:
        print(alert)

if __name__ == "__main__":
    main()