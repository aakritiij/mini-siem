def calculate_risk_scores(brute_force_results, suspicious_results):
    risk_scores = {}

    # initialize scores
    for result in brute_force_results:
        ip = result["ip"]
        risk_scores[ip] = {
            "score": 0,
            "reasons": []
        }

    # apply brute force logic
    for result in brute_force_results:
        ip = result["ip"]
        attempts = result["failed_attempts"]

        if result["is_malicious"]:
            risk_scores[ip]["score"] += 5
            risk_scores[ip]["reasons"].append("Brute force detected")

        if attempts >= 10:
            risk_scores[ip]["score"] += 3
            risk_scores[ip]["reasons"].append("High number of failed attempts")

        if attempts >= 20:
            risk_scores[ip]["score"] += 5
            risk_scores[ip]["reasons"].append("Very aggressive attack")

    # apply suspicious behavior logic
    for result in suspicious_results:
        ip = result["ip"]
        unique_users = result["unique_users"]

        if ip not in risk_scores:
            risk_scores[ip] = {"score": 0, "reasons": []}

        if unique_users >= 5:
            risk_scores[ip]["score"] += 5
            risk_scores[ip]["reasons"].append("Multiple username attempts")

    return risk_scores

def get_severity(score):
    if score >= 12:
        return "Critical"
    elif score >= 8:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"