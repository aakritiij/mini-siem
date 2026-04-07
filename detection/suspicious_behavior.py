from collections import defaultdict

def detect_suspicious_behavior(logs, threshold=5):
    ip_user_map = defaultdict(set)

    for log in logs:
        if log["status"] == "Failed":
            ip_user_map[log["ip"]].add(log["user"])

    results = []

    for ip, users in ip_user_map.items():
        if len(users) >= threshold:
            results.append({
                "ip": ip,
                "unique_users": len(users),
                "type": "Suspicious Behavior"
            })

    return results