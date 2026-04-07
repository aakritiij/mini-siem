def generate_timeline(logs, ip):
    timeline = []

    for log in logs:
        if log["ip"] == ip:
            timeline.append({
                "timestamp": log["timestamp"],
                "event": "Login Attempt",
                "user": log["user"],
                "status": log["status"]
            })

    # sort by timestamp
    timeline = sorted(timeline, key=lambda x: x["timestamp"])

    return timeline