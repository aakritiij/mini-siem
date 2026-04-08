def detect_suspicious_behavior(logs):
    ip_users = {}

    for log in logs:
        if log["status"] == "Failed":
            ip = log["ip"]
            user = log["user"]

            if ip not in ip_users:
                ip_users[ip] = set()

            ip_users[ip].add(user)

    result = {}

    for ip, users in ip_users.items():
        if len(users) >= 3:  # threshold
            result[ip] = len(users)

    return result