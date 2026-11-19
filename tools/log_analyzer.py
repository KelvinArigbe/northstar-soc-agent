
import re
import json

from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta

LOG_FILE = Path("logs/auth.log")

BRUTE_FORCE_THRESHOLD = 3
DETECTION_WINDOW_MINUTES = 5


def parse_timestamp(value):
    return datetime.strptime(
        f"{value} 2026",
        "%b %d %H:%M:%S %Y"
    )


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
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Accepted publickey for (\S+) from ([\d.]+)",
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
                "timestamp": successful.group(1),
                "username": successful.group(2),
                "source_ip": successful.group(3)
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
            Counter(
                event["source_ip"]
                for event in failed_logins
            )
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
        events_by_ip.setdefault(
            event["source_ip"], []
        ).append(event)

    for ip, events in events_by_ip.items():

        events.sort(
            key=lambda event: parse_timestamp(event["timestamp"])
        )

        left = 0
        max_count = 0

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

        if max_count >= threshold:
            alerts.append({
                "rule_id": "DET-001",
                "alert": "SSH brute-force activity detected",
                "source_ip": ip,
                "failed_attempts": max_count,
                "threshold": threshold,
                "window_minutes": window_minutes,
                "severity": "Medium"
            })

    return alerts


def detect_success_after_failures(
    evidence,
    threshold=BRUTE_FORCE_THRESHOLD,
    window_minutes=DETECTION_WINDOW_MINUTES
):

    alerts = []
    failed_by_ip = {}

    for event in evidence["failed_logins"]:
        failed_by_ip.setdefault(
            event["source_ip"], []
        ).append(event)

    for login in evidence["successful_logins"]:

        ip = login["source_ip"]

        if ip not in failed_by_ip:
            continue

        success_time = parse_timestamp(login["timestamp"])

        recent_failures = []

        for failure in failed_by_ip[ip]:

            failure_time = parse_timestamp(
                failure["timestamp"]
            )

            time_difference = success_time - failure_time

            if timedelta(0) <= time_difference <= timedelta(
                minutes=window_minutes
            ):
                recent_failures.append(failure)

        if len(recent_failures) >= threshold:

            alerts.append({
                "rule_id": "DET-002",
                "alert": "Successful SSH login after repeated failures",
                "source_ip": ip,
                "username": login["username"],
                "failed_attempts": len(recent_failures),
                "window_minutes": window_minutes,
                "severity": "High"
            })

    return alerts


def detect_privilege_escalation(evidence):

    alerts = []

    for event in evidence["sudo_commands"]:

        command = event["command"].lower()

        indicator = None

        if (
            "usermod" in command
            and "sudo" in command
            and ("-ag" in command or "--append" in command)
        ):
            indicator = "User added to sudo group"

        elif (
            "adduser" in command
            and "sudo" in command
        ):
            indicator = "User added to sudo group"

        elif (
            "gpasswd" in command
            and "-a" in command
            and "sudo" in command
        ):
            indicator = "User added to sudo group"

        elif (
            "useradd" in command
            and "sudo" in command
            and ("-g" in command or "-g=" in command or "-g sudo" in command)
        ):
            indicator = "Privileged account creation suspected"

        elif re.search(r"\bpasswd\s+root\b", command):
            indicator = "Root password modification"

        elif re.search(r"\bvisudo\b", command):
            indicator = "Sudoers configuration accessed"

        elif (
            "/etc/sudoers" in command
            and any(marker in command for marker in [
                ">", "tee", "chmod", "chown", "sed", "nano", "vim", "vi "
            ])
        ):
            indicator = "Sudoers configuration modification suspected"

        if indicator:

            alerts.append({
                "rule_id": "DET-003",
                "alert": "Suspicious privilege escalation activity",
                "username": event["username"],
                "command": event["command"],
                "indicator": indicator,
                "severity": "High"
            })

    return alerts


if __name__ == "__main__":

    evidence = analyze_logs()

    alerts = detect_brute_force(evidence)
    alerts += detect_success_after_failures(evidence)
    alerts += detect_privilege_escalation(evidence)

    print(json.dumps({
        "evidence": evidence,
        "alerts": alerts
    }, indent=4))
