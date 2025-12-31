import re
from datetime import datetime
from app.models import LogEvent

# Regex patterns for different log types
APACHE_REGEX = re.compile(
    r'(?P<ip>\S+) .* \[(?P<time>.*?)\] "(?P<req>.*?)" (?P<status>\d+)'
)

LINUX_AUTH_REGEX = re.compile(
    r'(?P<time>\w{3} \d+ \d+:\d+:\d+) .* (?P<service>\S+)\[\d+\]: (?P<msg>.*)'
)

SYSLOG_GENERIC_REGEX = re.compile(
    r'(?P<time>\w{3} \d+ \d+:\d+:\d+) (?P<host>\S+) (?P<service>\S+)(?:\[\d+\])?: (?P<msg>.*)'
)

IP_REGEX = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

def parse_log(lines: list[str], log_type: str) -> list[LogEvent]:
    events = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Apache logs
        if log_type == "apache_access":
            m = APACHE_REGEX.search(line)
            if m:
                try:
                    ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
                except Exception:
                    ts = None
                events.append(LogEvent(
                    timestamp=ts,
                    ip=m.group("ip"),
                    username=None,
                    action=m.group("req"),
                    status=m.group("status"),
                    raw=line
                ))
            continue

        # Linux auth / secure logs
        elif log_type == "linux_auth":
            m = LINUX_AUTH_REGEX.search(line)
            if m:
                msg = m.group("msg")
                ip = extract_ip(msg)
                status = "FAILED" if "failure" in msg.lower() else "SUCCESS"
                user = None
                user_match = re.search(r'user[=\s]+(\S+)', msg)
                if user_match:
                    user = user_match.group(1)
                events.append(LogEvent(
                    timestamp=None,
                    ip=ip,
                    username=user,
                    action="ssh_login" if "ssh" in m.group("service").lower() else "auth",
                    status=status,
                    raw=line
                ))
            continue

        # Syslog / generic logs
        else:
            m = SYSLOG_GENERIC_REGEX.search(line)
            if m:
                ip = extract_ip(m.group("msg"))
                events.append(LogEvent(
                    timestamp=None,
                    ip=ip,
                    username=None,
                    action=m.group("service"),
                    status="unknown",
                    raw=line
                ))
            else:
                # Fallback
                events.append(LogEvent(
                    timestamp=None,
                    ip=None,
                    username=None,
                    action="unknown",
                    status="unknown",
                    raw=line
                ))

    return events


def extract_ip(text: str):
    m = IP_REGEX.search(text)
    return m.group(1) if m else None
