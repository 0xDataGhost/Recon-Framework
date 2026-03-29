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
├── main.py                  CLI entry point
├── config.json              API keys, scan settings, notification config
├── requirements.txt
│
├── core/                    Shared infrastructure
│   ├── exceptions.py        Structured exception hierarchy
│   ├── config_manager.py    Config load/validate/write
│   ├── logger.py            JSON log formatter + rotating file handler
│   ├── database.py          SQLite schema and query layer
│   ├── checkpoint.py        Per-stage resume state
│   └── tool_manager.py      Tool detection and auto-install
│
├── recon/                   Pipeline stages (each wraps one or more CLI tools)
│   ├── pipeline.py          Stage orchestrator
│   ├── subdomain_enum.py    subfinder + amass
│   ├── live_hosts.py        httpx
│   ├── port_scan.py         naabu
│   ├── url_collection.py    gau + waybackurls
│   ├── endpoint_filter.py   URL classification
│   └── nuclei_scan.py       nuclei
│
├── intelligence/            Analysis layer (no subprocess calls except JS fetches)
│   ├── analyzer.py          Parallel orchestrator
│   ├── js_analyzer.py       JS endpoint/secret/GraphQL extraction
│   ├── vuln_patterns.py     IDOR, SSRF, open redirect, upload detection
│   ├── param_discoverer.py  Parameter extraction + ffuf command generation
│   ├── target_prioritizer.py  Scoring v2
│   ├── change_detector.py   Snapshot diff + subdomain classification
│   ├── correlation_engine.py  Attack chain detection
│   ├── exploit_generator.py   Per-endpoint attack scenarios
│   └── top_targets.py       Top 10 aggregation
│
├── monitoring/              Continuous mode
│   ├── monitor.py           APScheduler-based scan loop
│   └── diff_engine.py       Structured diff between snapshots
│
├── notifications/           Alert dispatch (never blocks pipeline)
│   ├── dispatcher.py        queue.Queue + daemon thread
│   ├── telegram.py          Bot API sender
│   ├── discord.py           Webhook sender
│   └── formatters.py        Message builders
│
├── api/                     Flask REST API + WebSocket
├── dashboard/               HTML/CSS/JS frontend
├── output/                  Scan results (created at runtime)
├── data/                    SQLite database + checkpoints
├── tests/                   Unit and integration tests
└── docs/                    Detailed documentation
```

---

## Requirements

- Python 3.10+
- Go 1.21+ *(for auto-installing recon tools)*
- Linux or macOS

---

## Installation

```bash
git clone https://github.com/your-handle/recon-framework.git
cd recon-framework
pip install -r requirements.txt
python main.py --install-tools
```

`--install-tools` checks PATH for each required tool (subfinder, amass, httpx, naabu, nuclei, gau, waybackurls) and installs any that are missing via `go install` or a prebuilt GitHub release binary.

---

## Configuration

Edit `config.json` before your first scan:

```json
{
  "api_keys": {
    "shodan": "",
    "securitytrails": "",
    "virustotal": ""
  },
  "notifications": {
    "telegram": {
      "enabled": false,
      "bot_token": "123456:ABC...",
      "chat_id": "-100123456789",
      "min_severity": "MEDIUM"
    },
    "discord": {
      "enabled": false,
      "webhook_url": ""
    }
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

All API keys are optional — the framework runs without them. See [`docs/usage.md`](docs/usage.md#configuration) for the full schema.

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

## Disclaimer

This tool is intended for use against systems you own or have explicit written permission to test. Unauthorised use is illegal and unethical. Always operate within the scope of an agreed bug bounty programme or penetration testing engagement.
