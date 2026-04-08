def generate_alerts(risk_scores):
    alerts = []
    seen_ips = {}

    for ip, data in risk_scores.items():
        score = data["score"]
        reasons = data["reasons"]

        # ---------------- SEVERITY ----------------
        if score >= 15:
            severity = "High"
        elif score >= 8:
            severity = "Medium"
        elif score > 0:
            severity = "Low"
        else:
            continue

        # ---------------- DEDUPLICATION ----------------
        if ip in seen_ips:
            seen_ips[ip]["count"] += 1

            # merge reasons (avoid duplicates)
            existing_reasons = set(seen_ips[ip]["details"].split(", "))
            new_reasons = set(reasons)
            combined = existing_reasons.union(new_reasons)

            seen_ips[ip]["details"] = ", ".join(combined)

        else:
            seen_ips[ip] = {
                "ip": ip,
                "risk_score": score,
                "severity": severity,
                "count": 1,
                "details": ", ".join(reasons)
            }

    alerts = list(seen_ips.values())

    return alerts