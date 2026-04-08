from utils.threat_intel_api import check_ip_abuse
from analysis.anomaly_detection import detect_time_anomalies

def calculate_risk_scores(brute_force_results, suspicious_results, logs):
    risk_scores = {}

    all_ips = set(brute_force_results.keys()) | set(suspicious_results.keys())
    anomaly_results = detect_time_anomalies(logs)

    for ip in all_ips:
        score = 0
        reasons = []

        # ---------------- TIME ANOMALY ----------------
        if ip in anomaly_results:
            bursts = anomaly_results[ip]
            score += bursts * 2
            reasons.append(f"rapid login bursts detected ({bursts})")

        # ---------------- BRUTE FORCE ----------------
        if ip in brute_force_results:
            attempts = brute_force_results[ip]
            score += attempts * 1.5
            reasons.append(f"{attempts} failed attempts")

        # ---------------- SUSPICIOUS ----------------
        if ip in suspicious_results:
            user_count = suspicious_results[ip]
            score += 5
            reasons.append(f"{user_count} different usernames attempted")

        # ---------------- THREAT INTEL ----------------
        intel = check_ip_abuse(ip)

        reasons.append(f"IP reputation score: {intel['score']}")

        if intel["score"] >= 10:
            score += intel["score"] / 10
            reasons.append("flagged by threat intelligence")

        if intel["score"] == 0 and ip in brute_force_results:
            score += 3
            reasons.append("suspicious behavior despite low reputation")

        risk_scores[ip] = {
            "score": round(score, 2),
            "reasons": reasons
        }

    return risk_scores