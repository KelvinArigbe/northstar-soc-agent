
import requests
import json

from pathlib import Path
from tools.log_analyzer import analyze_logs


MODEL = "llama3"
LOG_FILE = Path("logs/auth.log")


SYSTEM_PROMPT = """
You are Northstar SOC Agent, a cybersecurity investigation assistant.

Your responsibilities:
1. Identify suspicious authentication activity.
2. Identify source IP addresses and targeted accounts.
3. Distinguish failed and successful logins.
4. Identify possible attack patterns.
5. Explain security risks.
6. Recommend investigation steps.

Rules:
- Use only evidence supplied in the investigation.
- Never invent events.
- Do not claim an account was compromised without evidence.
- Separate confirmed observations from suspicions.
- Do not invent confidence percentages.
- Do not assume failed logins caused account lockouts.
- Keep reports concise and structured.
"""


def read_logs():
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    return LOG_FILE.read_text(encoding="utf-8")


def investigate(log_data, evidence):

    prompt = f"""
{SYSTEM_PROMPT}

INVESTIGATION EVIDENCE

Raw authentication logs:

{log_data}

Structured evidence extracted by Python:

{json.dumps(evidence, indent=2)}

Prepare your investigation report under these headings:

1. Observed Activity
2. Suspicious Indicators
3. Potential Impact
4. Recommended Next Steps
5. Confidence and Evidence Limitations

Remember:
Only report facts supported by the supplied evidence.
"""


    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 300
            }
        },
        timeout=(10, 600)
    )

    response.raise_for_status()

    return response.json()["response"]


def main():

    print("\nNORTHSTAR SOC AGENT")
    print("=" * 40)

    logs = read_logs()
    evidence = analyze_logs()

    print("[+] Raw logs loaded")
    print("[+] Structured evidence extracted")
    print("[+] Sending evidence to local AI model...\n")

    findings = investigate(logs, evidence)

    print("\nINVESTIGATION REPORT")
    print("=" * 40)

    print(findings)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    report_file = output_dir / "investigation-report.txt"

    report_file.write_text(
        findings,
        encoding="utf-8"
    )

    print(f"\n[+] Report saved to {report_file}")


if __name__ == "__main__":
    main()
