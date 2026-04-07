from collections import defaultdict

def detect_brute_force(logs, threshold=5):
    failed_attempts = defaultdict(int)

    for log in logs:
        if log["status"] == "Failed":
            failed_attempts[log["ip"]] += 1

    results = []

    for ip, count in failed_attempts.items():
        is_malicious = count >= threshold

        results.append({
            "ip": ip,
            "failed_attempts": count,
            "is_malicious": is_malicious,
            "type": "Brute Force"
        })

    return results