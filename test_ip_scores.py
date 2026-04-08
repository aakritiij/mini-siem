from utils.threat_intel_api import check_ip_abuse

# sample IP pool (real-world suspicious ranges)
test_ips = [
    "45.148.10.12",
    "89.248.165.74",
    "103.145.13.90",
    "185.220.101.1",
    "198.20.99.130",
    "5.188.10.176",
    "212.129.2.219",
    "91.134.183.12",
    "185.190.58.108",
    "192.168.1.1"  # control (should be low)
]

print("\n--- Threat Intel Scan ---\n")

for ip in test_ips:
    result = check_ip_abuse(ip)
    print(f"{ip} -> Score: {result['score']} | Malicious: {result['is_malicious']}")