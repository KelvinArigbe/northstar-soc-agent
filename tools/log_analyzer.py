
import re
import json

from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta

LOG_FILE = Path("logs/auth.log")

BRUTE_FORCE_THRESHOLD = 3
DETECTION_WINDOW_MINUTES = 5

MULTI_ACCOUNT_THRESHOLD = 3
NORMAL_LOGIN_START = 6
NORMAL_LOGIN_END = 20

SENSITIVE_ACCOUNTS = {"root", "admin"}

SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4
}


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

            max_count = max(max_count, current_count)

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
    failed_by_identity = {}

    # Group failed logins by source IP AND username.
    for event in evidence["failed_logins"]:

        identity = (
            event["source_ip"],
            event["username"].lower()
        )

        failed_by_identity.setdefault(
            identity, []
        ).append(event)

    # Check every successful login against matching failures.
    for login in evidence["successful_logins"]:

        identity = (
            login["source_ip"],
            login["username"].lower()
        )

        if identity not in failed_by_identity:
            continue

        success_time = parse_timestamp(login["timestamp"])

        recent_failures = []

        for failure in failed_by_identity[identity]:

            failure_time = parse_timestamp(
                failure["timestamp"]
            )

            difference = success_time - failure_time

            if timedelta(0) <= difference <= timedelta(
                minutes=window_minutes
            ):
                recent_failures.append(failure)

        if len(recent_failures) >= threshold:

            alerts.append({
                "rule_id": "DET-002",
                "alert": "Successful SSH login after repeated failures",
                "source_ip": login["source_ip"],
                "username": login["username"],
                "failed_attempts": len(recent_failures),
                "matched_failure_timestamps": [
                    event["timestamp"]
                    for event in recent_failures
                ],
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
            indicator = "Attempted addition of user to sudo group"

        elif "adduser" in command and "sudo" in command:
             indicator = "Attempted addition of user to sudo group"
        elif (
            "gpasswd" in command
            and "-a" in command
            and "sudo" in command
        ):
            indicator = "Attempted addition of user to sudo group"

        elif (
            "useradd" in command
            and "sudo" in command
            and ("-g" in command or "-g sudo" in command)
        ):
            indicator = "Attempted creation of privileged account"
        elif re.search(r"\bpasswd\s+root\b", command):
            indicator = "Root password modification"

        elif re.search(r"\bvisudo\b", command):
            indicator = "Sudoers configuration accessed"

        elif (
            "/etc/sudoers" in command
            and any(marker in command for marker in [
                ">", "tee", "chmod", "chown",
                "sed", "nano", "vim", "vi "
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


def detect_multiple_account_access(
    evidence,
    threshold=MULTI_ACCOUNT_THRESHOLD,
    window_minutes=DETECTION_WINDOW_MINUTES
):

    alerts = []
    events_by_ip = {}

    for event in evidence["successful_logins"]:
        events_by_ip.setdefault(
            event["source_ip"], []
        ).append(event)

    for ip, events in events_by_ip.items():

        events.sort(
            key=lambda event: parse_timestamp(event["timestamp"])
        )

        for right, event in enumerate(events):

            current_time = parse_timestamp(event["timestamp"])
            accounts = set()

            for candidate in events[:right + 1]:

                candidate_time = parse_timestamp(
                    candidate["timestamp"]
                )

                if (
                    timedelta(0)
                    <= current_time - candidate_time
                    <= timedelta(minutes=window_minutes)
                ):
                    accounts.add(candidate["username"])

            if len(accounts) >= threshold:

                alerts.append({
                    "rule_id": "DET-004A",
                    "alert": "Multiple accounts accessed from one IP",
                    "source_ip": ip,
                    "usernames": sorted(accounts),
                    "account_count": len(accounts),
                    "window_minutes": window_minutes,
                    "severity": "High"
                })

                break

    return alerts


def detect_unusual_login_hours(evidence):

    alerts = []

    for login in evidence["successful_logins"]:

        login_time = parse_timestamp(login["timestamp"])
        hour = login_time.hour

        if hour < NORMAL_LOGIN_START or hour >= NORMAL_LOGIN_END:

            alerts.append({
                "rule_id": "DET-004B",
                "alert": "Successful SSH login outside normal hours",
                "source_ip": login["source_ip"],
                "username": login["username"],
                "login_time": login["timestamp"],
                "severity": "Medium"
            })

    return alerts


def detect_sensitive_account_access(evidence):

    alerts = []

    for login in evidence["successful_logins"]:

        if login["username"].lower() in SENSITIVE_ACCOUNTS:

            alerts.append({
                "rule_id": "DET-004C",
                "alert": "Sensitive account SSH login detected",
                "source_ip": login["source_ip"],
                "username": login["username"],
                "login_time": login["timestamp"],
                "severity": "High"
            })

    return alerts


def correlate_incidents(alerts):

    incidents = []
    visited = set()

    def identities(alert):

        usernames = set()

        if alert.get("username"):
            usernames.add(alert["username"])

        usernames.update(alert.get("usernames", []))

        return {
            "ips": {alert["source_ip"]}
            if alert.get("source_ip") else set(),
            "usernames": usernames
        }

    alert_identities = [
        identities(alert) for alert in alerts
    ]

    for start in range(len(alerts)):

        if start in visited:
            continue

        component = []
        queue = [start]
        visited.add(start)

        while queue:

            current = queue.pop(0)
            component.append(alerts[current])

            current_identity = alert_identities[current]

            for other in range(len(alerts)):

                if other in visited:
                    continue

                other_identity = alert_identities[other]

                shared_ip = bool(
                    current_identity["ips"]
                    & other_identity["ips"]
                )

                shared_user = bool(
                    current_identity["usernames"]
                    & other_identity["usernames"]
                )

                if shared_ip or shared_user:
                    visited.add(other)
                    queue.append(other)

        if len(component) < 2:
            continue

        highest_severity = max(
            component,
            key=lambda alert: SEVERITY_RANK.get(
                alert["severity"], 0
            )
        )["severity"]

        source_ips = sorted({
            alert["source_ip"]
            for alert in component
            if alert.get("source_ip")
        })

        usernames = set()

        for alert in component:
            if alert.get("username"):
                usernames.add(alert["username"])

            usernames.update(alert.get("usernames", []))

        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:03d}",
            "title": "Correlated suspicious authentication activity",
            "severity": highest_severity,
            "alert_count": len(component),
            "detection_rules": sorted({
                alert["rule_id"]
                for alert in component
            }),
            "source_ips": source_ips,
            "usernames": sorted(usernames),
            "alerts": component
        })

    return incidents


if __name__ == "__main__":

    evidence = analyze_logs()

    alerts = detect_brute_force(evidence)
    alerts += detect_success_after_failures(evidence)
    alerts += detect_privilege_escalation(evidence)
    alerts += detect_multiple_account_access(evidence)
    alerts += detect_unusual_login_hours(evidence)
    alerts += detect_sensitive_account_access(evidence)

    incidents = correlate_incidents(alerts)

    print(json.dumps({
        "evidence": evidence,
        "alerts": alerts,
        "incidents": incidents
    }, indent=4))
