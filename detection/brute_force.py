def detect_brute_force(logs):
    ip_fail_count = {}

    for log in logs:
        if log["status"] == "Failed":
            ip = log["ip"]
            ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1

    # Only keep suspicious IPs (threshold = 5)
    result = {}

    for ip, count in ip_fail_count.items():
        if count >= 5:
            result[ip] = count

    return result