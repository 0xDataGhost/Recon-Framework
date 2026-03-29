# Recon Framework

A modular, production-ready reconnaissance automation framework for bug bounty hunters and ethical hackers.

Runs the complete recon pipeline — subdomain enumeration through vulnerability scanning — then analyses findings across layers to surface prioritised attack surfaces, detect multi-step attack chains, and generate a human-readable exploitation guide for each target.

> **For authorised security testing and bug bounty programs only.**

---

## How It Works

```
Target input
    │
    ▼
┌─────────────────── Recon Pipeline ───────────────────┐
│  subfinder + amass  →  httpx  →  naabu               │
│  gau + waybackurls  →  endpoint classification        │
│  nuclei (optional)                                    │
└──────────────────────────────────────────────────────┘
    │ PipelineResult
    ▼
┌─────────────────── Intelligence Layer ───────────────┐
│  JS analysis  ·  vuln patterns  ·  param discovery   │
│  change detection  ·  attack chain correlation        │
│  exploit scenario generator  ·  target scoring v2    │
└──────────────────────────────────────────────────────┘
    │
    ├──▶  output/{target}/attack_plan.md   (human guide)
    ├──▶  output/{target}/scan_report.json (machine data)
    ├──▶  SQLite database                  (queryable)
    ├──▶  Telegram / Discord alerts
    └──▶  Flask dashboard  →  http://127.0.0.1:5000
```

---

## Features

| Area | Capability |
|---|---|
| **Recon** | subfinder, amass, httpx, naabu, gau, waybackurls, nuclei |
| **Intelligence** | JS secret detection, GraphQL discovery, IDOR/SSRF/redirect pattern matching |
| **Attack chains** | Cross-source correlation (e.g. dev subdomain + unauthenticated API → CRITICAL) |
| **Exploit guidance** | Per-endpoint scenarios with copy-paste curl/ffuf commands |
| **Monitoring** | Periodic diff-based change detection with severity-filtered alerts |
| **Dashboard** | Flask UI — targets, findings, attack chains, live log stream |
| **Reliability** | Resume support, structured JSON logging, tool auto-install |

---

## Project Structure

```
recon-framework/
├── main.py                  CLI entry point (implemented ✓)
├── config.example.json      Config template — copy to config.json
├── pyproject.toml           Package metadata and tool config
├── requirements.txt         Runtime dependencies
├── requirements-dev.txt     Dev/test dependencies
├── LICENSE                  MIT
│
├── core/                    Shared infrastructure
│   ├── exceptions.py        Structured exception hierarchy (implemented ✓)
│   ├── config_manager.py    Config load/validate/write (planned)
│   ├── logger.py            JSON log formatter + rotating file handler (planned)
│   ├── database.py          SQLite schema and query layer (planned)
│   ├── checkpoint.py        Per-stage resume state (planned)
│   └── tool_manager.py      Tool detection and auto-install (planned)
│
├── recon/                   Pipeline stages — each wraps one or more CLI tools (planned)
├── intelligence/            Analysis layer (planned)
├── monitoring/              Continuous mode scheduler (planned)
├── notifications/           Alert dispatch — never blocks pipeline (planned)
├── api/                     Flask REST API + WebSocket (planned)
├── dashboard/               HTML/CSS/JS frontend (planned)
│
├── output/                  Scan results written here at runtime (gitignored)
├── data/                    SQLite database + logs + checkpoints (gitignored)
├── tests/                   Unit and integration tests
└── docs/                    Detailed documentation
```

---

## Requirements

- Python 3.11+
- Go 1.21+ *(for auto-installing recon tools)*
- Linux or macOS

---

## Installation

```bash
git clone https://github.com/your-handle/recon-framework.git
cd recon-framework

# Runtime dependencies
pip install -r requirements.txt

# Development/test dependencies (optional)
pip install -r requirements-dev.txt

# Check and install recon tools
python main.py --install-tools
```

`--install-tools` checks PATH for each required tool (subfinder, amass, httpx, naabu, nuclei, gau, waybackurls) and installs any that are missing via `go install` or a prebuilt GitHub release binary.

---

## Configuration

Copy the example config and edit it before your first scan:

```bash
cp config.example.json config.json
```

> `config.json` is in `.gitignore` and will never be committed. Your API keys and notification tokens are safe.

Key settings:

```json
{
  "notifications": {
    "telegram": { "enabled": false, "bot_token": "", "chat_id": "" },
    "discord":  { "enabled": false, "webhook_url": "" }
  },
  "scan": {
    "nuclei_enabled": true,
    "nuclei_severity": ["critical", "high", "medium"]
  },
  "intelligence": {
    "top_targets_count": 10,
    "enable_exploit_generator": true,
    "enable_correlation_engine": true
  }
}
```

All API keys are optional — the framework runs without them. See [`docs/usage.md`](docs/usage.md#2-configuration-reference) for the full schema.

---

## Usage

```bash
# Full scan
python main.py --target example.com --scan

# Skip nuclei (faster for large scope)
python main.py --target example.com --scan --no-nuclei

# Multiple targets from file
python main.py --targets targets.txt --scan

# Resume an interrupted scan
python main.py --target example.com --scan --resume

# Continuous monitoring, check every 60 minutes
python main.py --target example.com --monitor --interval 60

# Web dashboard only (view previous scan results)
python main.py --dashboard
```

---

## Output

Each scan produces:

```
output/{target}/
  subdomains.txt      all discovered subdomains
  live.txt            live hosts (URL, status code, title)
  ports.txt           open ports per host
  urls.txt            collected URLs (gau + waybackurls)
  nuclei.txt          vulnerability findings
  js_findings.txt     endpoints, secrets, and GraphQL found in JS files
  top_targets.txt     scored attack surface (Top 10)
  scan_report.json    full machine-readable report
  attack_plan.md      prioritised exploitation guide with ready-to-run commands
```

`attack_plan.md` contains the intelligence layer's human-readable output — why each target is interesting, what to test, and how to test it, including copy-paste `curl`/`ffuf` commands.

---

## Documentation

Full documentation — module reference, exception system, structured logging, pipeline workflow, scoring system, and attack chain patterns:

**[docs/usage.md](docs/usage.md)**

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **Fork and branch** — create a feature branch from `main` (`git checkout -b feature/my-change`)
2. **One concern per PR** — keep pull requests focused; don't bundle unrelated changes
3. **Type hints** — all Python must use type hints and be compatible with Python 3.11+
4. **Exceptions** — use the structured exception hierarchy in `core/exceptions.py`; never raise bare `Exception`
5. **Logging** — use `logger.error(..., extra=exc.to_dict())` for framework exceptions; never `print()` to stderr in library code
6. **Tests** — add or update tests in `tests/` for any changed behaviour
7. **Docs** — update `docs/usage.md` if you change a public interface or add a new module

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests (unit tests for core/exceptions.py run immediately)
pytest tests/ -v --cov=core --cov-report=term-missing

# Integration tests are skipped until pipeline modules are implemented
# pytest -m integration tests/integration/

# Verify CLI loads correctly
python main.py --help
python main.py --version
```

Please open an issue before starting large changes so the approach can be agreed upfront.

---

## Disclaimer

This tool is intended for use against systems you own or have explicit written permission to test. Unauthorised use is illegal and unethical. Always operate within the scope of an agreed bug bounty programme or penetration testing engagement.
