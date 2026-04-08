import requests

API_KEY = "842f7293f6d6ad5b61249a7e47597f99b7d9481288676837b7c016f1fe58590283df2c0c57154771"
URL = "https://api.abuseipdb.com/api/v2/check"

# simple cache to avoid repeated API calls
cache = {}

def check_ip_abuse(ip):
    if ip in cache:
        return cache[ip]

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(URL, headers=headers, params=params)
        data = response.json()

        abuse_score = data["data"]["abuseConfidenceScore"]

        result = {
            "is_malicious": abuse_score > 50,
            "score": abuse_score
        }

        cache[ip] = result
        return result

    except Exception as e:
        print(f"Threat Intel API error for {ip}: {e}")

        # fallback safe response
        return {
            "is_malicious": False,
            "score": 0
        }