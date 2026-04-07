def correlate_alerts(risk_scores):
    correlated = []

    for ip, data in risk_scores.items():
        score = data["score"]

        # only escalate high-risk entities
        if score >= 8:
            correlated.append({
                "alert_type": "High Risk Security Incident",
                "ip": ip,
                "severity": "Critical" if score >= 12 else "High",
                "risk_score": score,
                "details": ", ".join(data["reasons"])
            })

    return correlated