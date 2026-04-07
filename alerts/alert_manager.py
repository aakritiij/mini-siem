from datetime import datetime
from detection.risk_scoring import get_severity

def generate_alerts(risk_scores):
    alerts = []

    for ip, data in risk_scores.items():
        score = data["score"]
        severity = get_severity(score)

        alert = {
            "alert_type": "Security Incident",
            "ip": ip,
            "severity": severity,
            "risk_score": score,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": ", ".join(data["reasons"])
        }

        alerts.append(alert)

    return alerts