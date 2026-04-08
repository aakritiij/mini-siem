import re
import urllib.parse

def decode_url_encoding(text):
    try:
        return urllib.parse.unquote(text)
    except:
        return text

def decode_hex_encoding(text):
    try:
        return re.sub(
            r'\\x([0-9a-fA-F]{2})',
            lambda m: chr(int(m.group(1), 16)),
            text
        )
    except:
        return text

def remove_extra_spaces(text):
    return text.replace(" ", "")

def normalize_user(user):
    if not user:
        return user

    user = decode_url_encoding(user)
    user = decode_hex_encoding(user)
    user = remove_extra_spaces(user)

    return user.lower()

def normalize_log(log):
    log["user"] = normalize_user(log.get("user", ""))
    return log

def normalize_logs(logs):
    return [normalize_log(log) for log in logs]