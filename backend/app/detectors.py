import re

def detect_log_type(lines: list[str]) -> str:
    sample = "\n".join(lines[:20])

    if re.search(r'\"(GET|POST|PUT|DELETE).*HTTP/', sample):
        return "apache_access"

    if re.search(r'sshd\[\d+\]:', sample):
        return "linux_auth"

    return "unknown"
