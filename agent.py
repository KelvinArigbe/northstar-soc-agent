
import requests
import json

from pathlib import Path

from tools.log_analyzer import (
    analyze_logs,
    detect_brute_force,
    detect_success_after_failures,
    detect_privilege_escalation,
    detect_multiple_account_access,
    detect_unusual_login_hours,
    detect_sensitive_account_access,
    correlate_incidents
)

MODEL = "llama3"
LOG_FILE = Path("logs/auth.log")
OLLAMA_URL = "http://localhost:11434/api/generate"

SYSTEM_PROMPT = """
You are Northstar SOC Agent, a cybersecurity investigation assistant.

Rules:
- Use only supplied evidence.
- Never invent events or timestamps.
- Do not claim compromise without evidence.
- Do not claim data theft without evidence.
- A logged command does not prove successful execution.
- Separate confirmed observations from suspicions.
- Python-generated detection alerts are authoritative.
- Explain why detection rules triggered.
- Explain correlated incidents using their supporting alerts.
- Keep reports concise.
"""


def read_logs():

    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    return LOG_FILE.read_text(encoding="utf-8")


def investigate(log_data, evidence, alerts, incidents):

    prompt = f"""
{SYSTEM_PROMPT}

RAW AUTHENTICATION LOGS:
{log_data}

STRUCTURED EVIDENCE:
{json.dumps(evidence, indent=2)}

DETECTION ALERTS:
{json.dumps(alerts, indent=2)}

CORRELATED INCIDENTS:
{json.dumps(incidents, indent=2)}

Prepare a report with these headings:

1. Observed Activity
2. Suspicious Indicators
3. Correlated Security Incidents
4. Potential Impact
5. Recommended Next Steps
6. Evidence Limitations
7. Detection Alert Analysis

Clearly distinguish attempted commands from confirmed successful actions.
"""


    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": 1000}
        },
        timeout=(10, 600)
    )

    response.raise_for_status()

    return response.json()["response"]



def build_fallback_report(evidence, alerts, incidents, error):
    """Build an evidence-based report when AI investigation is unavailable."""

    return f"""# Northstar SOC Agent Report

## Investigation Status
AI-assisted investigation unavailable: {error}

This report was generated using Python detection results.

## Observed Activity
- Total authentication log lines: {evidence.get("total_log_lines", 0)}
- Failed SSH logins: {evidence.get("failed_login_count", 0)}
- Successful SSH logins: {len(evidence.get("successful_logins", []))}
- Recorded sudo commands: {len(evidence.get("sudo_commands", []))}

## Detection Alert Analysis

{json.dumps(alerts, indent=2)}

## Correlated Security Incidents

{json.dumps(incidents, indent=2)}

## Evidence Limitations
- A recorded command does not prove successful execution.
- Detection alerts identify suspicious patterns, not confirmed compromise.
- The investigation has not received AI-assisted analysis.
- Further investigation is required to establish the full impact.

## Recommended Next Steps
- Review the source IP addresses associated with the alerts.
- Verify whether suspicious account access was authorized.
- Check whether recorded privilege escalation commands succeeded.
- Review additional authentication and system logs.
"""



def save_report(findings):

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    report_file = output_dir / "investigation-report.txt"

    report_file.write_text(
        findings,
        encoding="utf-8"
    )

    return report_file


def main():

    print("\nNORTHSTAR SOC AGENT")
    print("=" * 40)

    try:

        logs = read_logs()
        evidence = analyze_logs()

        alerts = detect_brute_force(evidence)
        alerts += detect_success_after_failures(evidence)
        alerts += detect_privilege_escalation(evidence)
        alerts += detect_multiple_account_access(evidence)
        alerts += detect_unusual_login_hours(evidence)
        alerts += detect_sensitive_account_access(evidence)

        incidents = correlate_incidents(alerts)

        print("[+] Raw logs loaded")
        print("[+] Structured evidence extracted")
        print(f"[+] Detection alerts generated: {len(alerts)}")
        print(f"[+] Correlated incidents generated: {len(incidents)}")
        print("[+] Sending evidence to local AI model...\n")

        try:
            findings = investigate(
                logs,
                evidence,
                alerts,
                incidents
            )
        except requests.exceptions.RequestException as error:
            print(f"[!] AI investigation unavailable: {error}")
            print("[+] Generating deterministic fallback report...")
            findings = build_fallback_report(
                evidence,
                alerts,
                incidents,
                error
            )

        print("\nINVESTIGATION REPORT")
        print("=" * 40)
        print(findings)

        report_file = save_report(findings)

        print(f"\n[+] Report saved to {report_file}")

    except requests.exceptions.Timeout:
        print("[!] Ollama request timed out.")

    except requests.exceptions.ConnectionError:
        print("[!] Cannot connect to Ollama.")

    except Exception as error:
        print(f"[!] Error: {error}")


if __name__ == "__main__":
    main()
