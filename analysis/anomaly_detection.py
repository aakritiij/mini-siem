from datetime import datetime

def detect_time_anomalies(logs):
    ip_timestamps = {}

    # ---------------- PARSE TIMESTAMPS ----------------
    for log in logs:
        if log["status"] == "Failed":
            ip = log["ip"]

            try:
                timestamp = datetime.strptime(log["timestamp"], "%b %d %H:%M:%S")
            except:
                continue

            if ip not in ip_timestamps:
                ip_timestamps[ip] = []

            ip_timestamps[ip].append(timestamp)

    # ---------------- DETECT BURSTS ----------------
    anomaly_results = {}

    for ip, times in ip_timestamps.items():
        times.sort()

        burst_count = 0

        for i in range(len(times) - 1):
            diff = (times[i + 1] - times[i]).total_seconds()

            # if events are too close → suspicious
            if diff <= 5:
                burst_count += 1

        if burst_count >= 3:
            anomaly_results[ip] = burst_count

    return anomaly_results