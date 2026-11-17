
import re
from pathlib import Path
from collections import Counter

LOG_FILE = Path("logs/auth.log")


def analyze_logs():
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    logs = LOG_FILE.read_text(encoding="utf-8").splitlines()

    failed_logins = []
    successful_logins = []
    sudo_commands = []

    for line in logs:

        failed = re.search(
            r"Failed password for (\S+) from ([\d.]+)",
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
                "username": failed.group(1),
                "source_ip": failed.group(2)
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


if __name__ == "__main__":
    import json

    results = analyze_logs()
    print(json.dumps(results, indent=4))
