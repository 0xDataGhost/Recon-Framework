# Recon Framework

A modular, production-ready reconnaissance automation framework for bug bounty hunters and ethical hackers.

Runs the full recon pipeline — subdomain enumeration, live host detection, port scanning, URL collection, JS analysis, vulnerability pattern detection, and attack chain correlation — then produces a prioritised, human-readable attack plan for each target.

> **For authorised security testing and bug bounty programs only.**

---

## Features

- **Full recon pipeline** — subfinder, amass, httpx, naabu, gau, waybackurls, nuclei
- **Intelligence layer** — JS secret detection, GraphQL discovery, IDOR/SSRF/open redirect pattern matching, attack chain correlation across findings
- **Exploit scenario generator** — copy-paste curl/ffuf commands per high-value endpoint
- **Continuous monitoring** — periodic diff-based change detection with Telegram/Discord alerts
- **Web dashboard** — Flask UI for browsing results and attack chains
- **Resume support** — interrupted scans continue from the last completed stage
- **Structured JSON logging** — every error carries `error_code`, `message`, and `context`

---

## Installation

**Requirements:** Python 3.10+, Go 1.21+, Linux or macOS

```bash
git clone https://github.com/your-handle/recon-framework.git
cd recon-framework
pip install -r requirements.txt
python main.py --install-tools
```

`--install-tools` detects and installs any missing recon tools automatically.

---

## Quick Usage

```bash
# Full scan
python main.py --target example.com --scan

# Skip nuclei (faster)
python main.py --target example.com --scan --no-nuclei

# Multiple targets
python main.py --targets targets.txt --scan

# Resume an interrupted scan
python main.py --target example.com --scan --resume

# Continuous monitoring (runs every 60 minutes)
python main.py --target example.com --monitor --interval 60

# Launch web dashboard
python main.py --dashboard
```

Results are written to `output/{target}/`, including `attack_plan.md` — a prioritised exploitation guide with ready-to-run commands.

---

## Configuration

Edit `config.json` to set API keys and notification settings:

```json
{
  "api_keys": {
    "shodan": "YOUR_KEY",
    "securitytrails": "",
    "virustotal": ""
  },
  "notifications": {
    "telegram": {
      "enabled": true,
      "bot_token": "123456:ABC...",
      "chat_id": "-100123456789",
      "min_severity": "MEDIUM"
    },
    "discord": {
      "enabled": false,
      "webhook_url": ""
    }
  }
}
```

---

## Structured Error Logging

All exceptions extend `ReconBaseError` and expose a `.to_dict()` method for JSON-compatible logging:

```python
from core.exceptions import ToolExecutionError
import logging

logger = logging.getLogger("recon.live_hosts")

try:
    result = run_httpx(subdomains)
except ToolExecutionError as e:
    logger.error("tool_execution_failed", extra=e.to_dict())
```

Log output:

```json
{
  "level": "ERROR",
  "event": "tool_execution_failed",
  "error_code": "TOOL_EXECUTION_FAILED",
  "message": "'httpx' exited with code 1",
  "context": {
    "tool_name": "httpx",
    "command": "httpx -l subdomains.txt -o live.txt",
    "return_code": 1,
    "stderr_snippet": "dial tcp: lookup example.com: no such host"
  }
}
```

---

## Output Structure

```
output/{target}/
  subdomains.txt     subdomains discovered
  live.txt           live hosts with status codes
  ports.txt          open ports per host
  urls.txt           collected URLs
  nuclei.txt         vulnerability scan findings
  js_findings.txt    JS analysis: endpoints, secrets, GraphQL
  top_targets.txt    scored attack surface
  scan_report.json   full machine-readable report
  attack_plan.md     human-friendly exploitation guide
```

---

## Documentation

Full documentation, including all exception types, context fields, structured logging patterns, and pipeline error handling best practices:

**[docs/usage.md](docs/usage.md)**

---

## Disclaimer

This tool is intended for use against systems you own or have explicit written permission to test. Unauthorised use is illegal.
