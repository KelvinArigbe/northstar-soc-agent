
import re
import json

from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta

LOG_FILE = Path("logs/auth.log")

BRUTE_FORCE_THRESHOLD = 3
DETECTION_WINDOW_MINUTES = 5


def parse_timestamp(value):
    return datetime.strptime(value, "%b %d %H:%M:%S")


def analyze_logs():

    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    logs = LOG_FILE.read_text(encoding="utf-8").splitlines()

    failed_logins = []
    successful_logins = []
    sudo_commands = []

    for line in logs:

        failed = re.search(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password for (\S+) from ([\d.]+)",
            line
        )

        successful = re.search(
            r"Accepted publickey for (\S+) from ([\d.]+)",
            line
        )

        sudo = re.search(
            r"sudo: (\S+) : COMMAND=(.*)",
            line
        )

        if failed:
            failed_logins.append({
                "timestamp": failed.group(1),
                "username": failed.group(2),
                "source_ip": failed.group(3)
            })

        if successful:
            successful_logins.append({
                "username": successful.group(1),
                "source_ip": successful.group(2)
            })

        if sudo:
            sudo_commands.append({
                "username": sudo.group(1),
                "command": sudo.group(2)
            })

    return {
        "total_log_lines": len(logs),
        "failed_login_count": len(failed_logins),
        "failed_login_sources": dict(
            Counter(event["source_ip"] for event in failed_logins)
        ),
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "sudo_commands": sudo_commands
    }


def detect_brute_force(
    evidence,
    threshold=BRUTE_FORCE_THRESHOLD,
    window_minutes=DETECTION_WINDOW_MINUTES
):

    alerts = []
    events_by_ip = {}

    for event in evidence["failed_logins"]:
        ip = event["source_ip"]
        events_by_ip.setdefault(ip, []).append(event)

    for ip, events in events_by_ip.items():

        events.sort(
            key=lambda event: parse_timestamp(event["timestamp"])
        )

        left = 0
        max_count = 0
        matched_events = []

        for right, event in enumerate(events):

            current_time = parse_timestamp(event["timestamp"])

            while left <= right:
                first_time = parse_timestamp(
                    events[left]["timestamp"]
                )

                if current_time - first_time > timedelta(
                    minutes=window_minutes
                ):
                    left += 1
                else:
                    break

            current_count = right - left + 1

            if current_count > max_count:
                max_count = current_count
                matched_events = events[left:right + 1]

        if max_count >= threshold:
            alerts.append({
                "rule_id": "DET-001",
                "alert": "SSH brute-force activity detected",
                "source_ip": ip,
                "failed_attempts": max_count,
                "threshold": threshold,
                "window_minutes": window_minutes,
                "first_attempt": matched_events[0]["timestamp"],
                "last_attempt": matched_events[-1]["timestamp"],
                "severity": "Medium"
            })

    return alerts


if __name__ == "__main__":

    evidence = analyze_logs()
    alerts = detect_brute_force(evidence)

    print(json.dumps({
        "evidence": evidence,
        "alerts": alerts
    }, indent=4))
