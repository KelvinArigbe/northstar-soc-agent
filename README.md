# Northstar SOC Agent

**A Python-based Security Operations Center (SOC) investigation tool with rule-based detection, incident correlation, and local AI-assisted security analysis.**

## 1. Overview

Northstar SOC Agent is a security monitoring and investigation project designed to analyse Linux authentication logs, identify suspicious activity, generate detection alerts, correlate related security events, and produce investigation reports.

It combines deterministic Python detection logic with a locally hosted Large Language Model (LLM) through Ollama.

The project demonstrates practical skills in:

- Security log analysis
- Threat detection engineering
- Authentication monitoring
- Incident correlation
- Python security automation
- AI-assisted security investigations
- Linux security operations

## 2. Architecture

Northstar follows this investigation workflow:

1. **Log ingestion:** Reads Linux authentication logs.
2. **Evidence extraction:** Parses failed logins, successful SSH authentication and sudo commands.
3. **Detection engine:** Executes predefined security detection rules.
4. **Incident correlation:** Groups related alerts into security incidents.
5. **AI investigation:** Sends evidence and detection results to a locally hosted Llama 3 model.
6. **Report generation:** Produces a structured investigation report.
7. **Fallback reporting:** Generates a deterministic Python-based report if AI investigation is unavailable.

## 3. Detection Capabilities

| Rule | Detection | Description |
|---|---|---|
| DET-001 | SSH brute-force activity | Identifies repeated failed SSH authentication attempts. |
| DET-002 | Successful login after failures | Detects successful authentication following repeated failures against the same account and source IP. |
| DET-003 | Suspicious privilege escalation | Identifies potentially dangerous commands involving privileged accounts and sudo configuration. |
| DET-004A | Multiple account access | Identifies multiple accounts accessed from one source IP within a defined time window. |
| DET-004B | Unusual login hours | Identifies successful SSH logins outside configured normal hours. |
| DET-004C | Sensitive account access | Detects SSH logins involving sensitive accounts such as root and admin. |

## 4. Technology Stack

- **Language:** Python 3
- **Operating environment:** Linux / Kali Linux
- **AI integration:** Ollama
- **Language model:** Llama 3
- **HTTP integration:** Python Requests
- **Testing:** Python unittest

## 5. Project Structure

```text
northstar-soc-agent/
│
├── agent.py
│
├── tools/
│   └── log_analyzer.py
│
├── logs/
│   └── auth.log
│
├── output/
│   └── investigation-report.txt
│
├── tests/
│   ├── __init__.py
│   └── test_auth_detection.py
│
├── README.md
└── .gitignore
```

## 6. Installation

### Requirements

- Python 3
- Ollama
- Llama 3 model
- Linux environment

### Clone the repository

```bash
git clone https://github.com/KelvinArigbe/northstar-soc-agent.git

cd northstar-soc-agent
```

### Install Python dependency

```bash
python3 -m pip install requests
```

### Install the AI model

Install Ollama and download the model:

```bash
ollama pull llama3
```

Ensure the Ollama service is running before executing the agent.

## 7. Running Northstar

From the project root directory:

```bash
python3 agent.py
```

Northstar will:

- Load authentication logs.
- Extract structured evidence.
- Execute detection rules.
- Correlate security alerts.
- Request AI-assisted investigation.
- Save the investigation report.

Generated reports are stored in:

```text
output/investigation-report.txt
```

## 8. Running Tests

Execute the automated tests:

```bash
python3 -m unittest discover -s tests -v
```

The current automated test suite validates the successful-login-after-failures detection logic, including different source IPs, different usernames and detection-window boundaries.

## 9. Sample Investigation

A sample investigation demonstrated:

- Three successful SSH logins.
- Three different accounts accessed from one source IP.
- Successful access to sensitive accounts.
- One suspicious sudo-related command.
- Seven detection alerts.
- One correlated security incident.

Northstar also successfully generated an investigation report when the AI service was unavailable.

## 10. Security Considerations and Limitations

Northstar is an educational and practical security engineering project.

Important limitations:

- Detection alerts indicate suspicious activity, not confirmed compromise.
- A recorded sudo command does not establish successful execution.
- Unusual login hours may be legitimate depending on operational schedules.
- Multiple account access from one IP may involve legitimate administrative infrastructure.
- Incident correlation uses heuristic identity relationships and may group unrelated alerts.
- The current automated test coverage does not yet cover every detection rule.
- AI-generated findings must be checked against the underlying evidence.

## 11. Future Improvements

Potential areas for future development include:

- Additional authentication and system detection rules.
- Expanded automated testing.
- Improved incident correlation.
- Support for additional Linux log sources.
- Structured JSON reporting.
- Integration with Microsoft Sentinel.
- Alert prioritisation and investigation workflows.

## 12. Author

**Kelvin Arigbe**

GitHub: https://github.com/KelvinArigbe

Project: Northstar SOC Agent

---

*Northstar SOC Agent demonstrates practical security detection engineering, Python automation, incident investigation and local AI integration.*
