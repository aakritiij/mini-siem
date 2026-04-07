import re

def parse_auth_log(file_path):
    logs = []

    pattern = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*sshd.*: '
        r'(?P<status>Failed|Accepted)\s+(password|none) for (invalid user )?'
        r'(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    with open(file_path, "r") as file:
        for line in file:
            match = pattern.search(line)
            if match:
                log = {
                    "timestamp": f"{match.group('month')} {match.group('day')} {match.group('time')}",
                    "ip": match.group("ip"),
                    "user": match.group("user"),
                    "status": match.group("status")
                }
                logs.append(log)

    return logs

def parse_single_log(line):
    import re

    pattern = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*sshd.*: '
        r'(?P<status>Failed|Accepted)\s+(password|none) for (invalid user )?'
        r'(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    match = pattern.search(line)
    if match:
        return {
            "timestamp": f"{match.group('month')} {match.group('day')} {match.group('time')}",
            "ip": match.group("ip"),
            "user": match.group("user"),
            "status": match.group("status")
        }

    return None