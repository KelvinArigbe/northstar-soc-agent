import requests
import json

from pathlib import Path

from tools.log_analyzer import (
    analyze_logs,
    detect_brute_force,
    detect_success_after_failures,
    detect_privilege_escalation
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
- Separate confirmed observations from suspicions.
- Python-generated detection counts are authoritative.
- Explain why each detection rule triggered.
- Keep reports concise.
"""


def read_logs():
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    return LOG_FILE.read_text(encoding="utf-8")


def investigate(log_data, evidence, alerts):
    prompt = f"""
{SYSTEM_PROMPT}

RAW AUTHENTICATION LOGS:
{log_data}

STRUCTURED EVIDENCE:
{json.dumps(evidence, indent=2)}

PYTHON DETECTION ALERTS:
{json.dumps(alerts, indent=2)}

Prepare a report with these headings:

1. Observed Activity
2. Suspicious Indicators
3. Potential Impact
4. Recommended Next Steps
5. Evidence Limitations
6. Detection Alert Analysis
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": 800}
        },
        timeout=(10, 600)
    )

    response.raise_for_status()
    return response.json()["response"]


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

        print("[+] Raw logs loaded")
        print("[+] Structured evidence extracted")
        print(f"[+] Detection alerts generated: {len(alerts)}")
        print("[+] Sending evidence to local AI model...\n")

        findings = investigate(logs, evidence, alerts)

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

