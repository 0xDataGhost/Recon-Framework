# Framework Usage Guide

## Table of Contents

1. [What This Framework Does](#1-what-this-framework-does)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Exception System](#4-exception-system)
   - [Base Exception](#41-reconbaseerror)
   - [Tool Management Exceptions](#42-tool-management-exceptions)
   - [Pipeline Exceptions](#43-pipeline-exceptions)
   - [Intelligence Layer Exceptions](#44-intelligence-layer-exceptions)
   - [Infrastructure Exceptions](#45-infrastructure-exceptions)
5. [Structured Logging](#5-structured-logging)
6. [Error Handling Best Practices](#6-error-handling-best-practices)

---

## 1. What This Framework Does

This is a modular reconnaissance automation framework built for bug bounty hunters and ethical hackers. It automates the full recon pipeline:

- **Subdomain enumeration** (subfinder, amass)
- **Live host detection** (httpx)
- **Port scanning** (naabu)
- **URL and endpoint collection** (gau, waybackurls)
- **Vulnerability scanning** (nuclei)
- **Intelligence analysis** — JS analysis, parameter discovery, vulnerability pattern detection, attack chain correlation, and exploit scenario generation
- **Notifications** — Telegram and Discord alerts
- **Continuous monitoring** — periodic diff-based change detection
- **Web dashboard** — Flask-based UI for browsing results

The framework is designed around a strict separation of concerns:

| Layer | Responsibility |
|---|---|
| `recon/` | Run external tools, collect raw data |
| `intelligence/` | Analyse and score findings, detect attack chains |
| `notifications/` | Dispatch alerts without blocking the pipeline |
| `api/` + `dashboard/` | Serve and visualise results |

---

## 2. Installation

### Requirements

- Python 3.10+
- Go 1.21+ (for auto-installing recon tools)
- Linux or macOS

### Install Python dependencies

```bash
git clone https://github.com/your-handle/recon-framework.git
cd recon-framework
pip install -r requirements.txt
```

### Install recon tools automatically

```bash
python main.py --install-tools
```

This detects and installs any missing tools (subfinder, amass, httpx, naabu, nuclei, gau, waybackurls). Optional: ffuf.

### Configure API keys and notifications

Copy and edit the config file:

```bash
cp config.json config.local.json   # optional — config.json is read by default
```

Open `config.json` and fill in your keys and notification settings:

```json
{
  "api_keys": {
    "shodan": "YOUR_KEY_HERE",
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

## 3. Quick Start

### Run a full scan

```bash
python main.py --target example.com --scan
```

### Run without nuclei (faster)

```bash
python main.py --target example.com --scan --no-nuclei
```

### Scan multiple targets

```bash
python main.py --targets targets.txt --scan
```

### Resume an interrupted scan

```bash
python main.py --target example.com --scan --resume
```

### Start continuous monitoring

```bash
python main.py --target example.com --monitor --interval 60
```

### Launch the web dashboard

```bash
python main.py --dashboard
# Open http://127.0.0.1:5000
```

### Output

Every scan writes results to `output/{target}/`:

```
output/example.com/
  subdomains.txt       — all discovered subdomains
  live.txt             — live hosts with status codes
  ports.txt            — open ports per host
  urls.txt             — collected URLs
  nuclei.txt           — vulnerability findings
  js_findings.txt      — JS analysis results
  top_targets.txt      — scored attack surface
  scan_report.json     — full machine-readable report
  attack_plan.md       — human-friendly exploitation guide
```

---

## 4. Exception System

All exceptions live in `core/exceptions.py`. Every exception:

- Has a fixed `error_code` string for log aggregation
- Carries a `context` dict with structured debugging data
- Exposes a `.to_dict()` method that returns a JSON-serialisable dict
- Prints useful information with plain `str(e)` or `repr(e)`

### 4.1 `ReconBaseError`

The base class for all framework exceptions. Rarely raised directly — use a subclass.

```python
from core.exceptions import ReconBaseError

raise ReconBaseError("Something went wrong", context={"target": "example.com"})
```

**`.to_dict()` output:**

```json
{
  "error_code": "RECON_ERROR",
  "error_type": "ReconBaseError",
  "message": "Something went wrong",
  "context": {"target": "example.com"}
}
```

**`str(e)` output:**

```
[RECON_ERROR] Something went wrong | context={"target": "example.com"}
```

---

### 4.2 Tool Management Exceptions

#### `ToolNotAvailableError`

Raised when a required tool cannot be found and auto-installation is not possible (e.g. Go is not installed, or the download failed).

**Key context fields:** `tool_name`, `reason`

```python
from core.exceptions import ToolNotAvailableError

raise ToolNotAvailableError(
    tool_name="subfinder",
    reason="Go is not installed and no prebuilt binary was found",
)
```

**`.to_dict()` output:**

```json
{
  "error_code": "TOOL_NOT_AVAILABLE",
  "error_type": "ToolNotAvailableError",
  "message": "Tool 'subfinder' is not available: Go is not installed and no prebuilt binary was found",
  "context": {
    "tool_name": "subfinder",
    "reason": "Go is not installed and no prebuilt binary was found"
  }
}
```

---

#### `ToolInstallError`

Raised when auto-installation was attempted but failed (e.g. network error, permission denied).

**Key context fields:** `tool_name`, `reason`

```python
from core.exceptions import ToolInstallError

raise ToolInstallError(
    tool_name="nuclei",
    reason="go install returned exit code 1 — check Go module proxy",
)
```

---

#### `ToolExecutionError`

Raised when a tool subprocess exits with a non-zero return code or times out. This is the most commonly raised exception in the recon layer. It stores the exact command so failures can be reproduced manually.

**Key context fields:** `tool_name`, `command`, `return_code`, `stderr_snippet` (capped at 500 chars)

```python
from core.exceptions import ToolExecutionError

raise ToolExecutionError(
    tool_name="httpx",
    command=["httpx", "-l", "subdomains.txt", "-o", "live.txt"],
    return_code=1,
    stderr="dial tcp: lookup example.com: no such host",
)
```

**`.to_dict()` output:**

```json
{
  "error_code": "TOOL_EXECUTION_FAILED",
  "error_type": "ToolExecutionError",
  "message": "'httpx' exited with code 1",
  "context": {
    "tool_name": "httpx",
    "command": "httpx -l subdomains.txt -o live.txt",
    "return_code": 1,
    "stderr_snippet": "dial tcp: lookup example.com: no such host"
  }
}
```

To reproduce the failure manually, copy `context.command` directly into your terminal.

---

### 4.3 Pipeline Exceptions

#### `PipelineStageError`

Raised when a recon stage fails in a way that prevents it from returning any useful partial data. Includes the stage name so dashboards and log aggregators can group failures by stage.

**Key context fields:** `stage`

```python
from core.exceptions import PipelineStageError

raise PipelineStageError(
    stage="subdomain_enum",
    reason="Both subfinder and amass returned empty results",
    context={"target": "example.com", "elapsed_seconds": 42},
)
```

**`.to_dict()` output:**

```json
{
  "error_code": "PIPELINE_STAGE_ERROR",
  "error_type": "PipelineStageError",
  "message": "Stage 'subdomain_enum' failed: Both subfinder and amass returned empty results",
  "context": {
    "stage": "subdomain_enum",
    "target": "example.com",
    "elapsed_seconds": 42
  }
}
```

---

#### `ParsingError`

Raised when tool output cannot be parsed — for example, when a tool outputs unexpected JSON or an empty file. The first 300 characters of raw output are stored so the cause can be diagnosed from logs without access to the original file.

**Key context fields:** `tool_name`, `raw_output_snippet`, `reason`

```python
from core.exceptions import ParsingError

raise ParsingError(
    tool_name="nuclei",
    raw_output='{"template-id": null, "severity":',  # truncated / malformed JSON
    reason="JSONDecodeError on line 1",
)
```

**`.to_dict()` output:**

```json
{
  "error_code": "PARSE_ERROR",
  "error_type": "ParsingError",
  "message": "Failed to parse output from 'nuclei': JSONDecodeError on line 1",
  "context": {
    "tool_name": "nuclei",
    "raw_output_snippet": "{\"template-id\": null, \"severity\":",
    "reason": "JSONDecodeError on line 1"
  }
}
```

---

### 4.4 Intelligence Layer Exceptions

#### `IntelligenceError`

Raised when an intelligence analysis sub-module fails. Because all analyzers run in parallel, this exception is caught per-analyzer so a failure in one (e.g. the JS analyzer) does not prevent the others from completing.

**Key context fields:** `analyzer`

```python
from core.exceptions import IntelligenceError

raise IntelligenceError(
    analyzer="js_analyzer",
    reason="requests.ConnectionError fetching https://example.com/app.js",
    context={"js_url": "https://example.com/app.js", "timeout": 10},
)
```

**`.to_dict()` output:**

```json
{
  "error_code": "INTELLIGENCE_ERROR",
  "error_type": "IntelligenceError",
  "message": "Analyzer 'js_analyzer' failed: requests.ConnectionError fetching https://example.com/app.js",
  "context": {
    "analyzer": "js_analyzer",
    "js_url": "https://example.com/app.js",
    "timeout": 10
  }
}
```

---

### 4.5 Infrastructure Exceptions

These are raised for configuration, database, checkpoint, and notification failures.

| Exception | `error_code` | When raised |
|---|---|---|
| `ConfigError` | `CONFIG_ERROR` | Required config key is missing or invalid |
| `DatabaseError` | `DATABASE_ERROR` | SQLite operation fails |
| `CheckpointError` | `CHECKPOINT_ERROR` | Checkpoint file cannot be read or written |
| `NotificationError` | `NOTIFICATION_ERROR` | Telegram/Discord message cannot be sent |

```python
from core.exceptions import ConfigError

required_keys = ["notifications.telegram.bot_token", "notifications.telegram.chat_id"]
missing = [k for k in required_keys if not config.get(k)]
if missing:
    raise ConfigError(
        f"Missing required config keys: {missing}",
        context={"missing_keys": missing},
    )
```

---

## 5. Structured Logging

The framework uses Python's standard `logging` module with a JSON formatter. Every exception's `.to_dict()` maps directly to a log record's `extra` dict.

### Basic pattern

```python
import logging
from core.exceptions import ToolExecutionError

logger = logging.getLogger("recon.live_hosts")

try:
    result = run_httpx(subdomains)
except ToolExecutionError as e:
    logger.error("tool_execution_failed", extra=e.to_dict())
    # continues — partial results are used
```

### JSON log output

When the JSON formatter is active (configured in `core/logger.py`), the log record looks like:

```json
{
  "timestamp": "2026-03-29T14:22:01Z",
  "level": "ERROR",
  "logger": "recon.live_hosts",
  "event": "tool_execution_failed",
  "error_code": "TOOL_EXECUTION_FAILED",
  "error_type": "ToolExecutionError",
  "message": "'httpx' exited with code 1",
  "context": {
    "tool_name": "httpx",
    "command": "httpx -l subdomains.txt -o live.txt",
    "return_code": 1,
    "stderr_snippet": "dial tcp: lookup example.com: no such host"
  }
}
```

### Logging an arbitrary exception with context

For exceptions that are not `ReconBaseError` subclasses (e.g. `requests.Timeout`), wrap them before logging:

```python
from core.exceptions import IntelligenceError
import requests

try:
    response = requests.get(js_url, timeout=10)
except requests.Timeout as e:
    err = IntelligenceError(
        analyzer="js_analyzer",
        reason=f"Timeout fetching {js_url}",
        context={"js_url": js_url, "timeout": 10},
    )
    logger.warning("js_fetch_timeout", extra=err.to_dict())
```

---

## 6. Error Handling Best Practices

### 6.1 Never let a single tool failure abort the pipeline

Every scanner module must catch its own exceptions and return a `ScanResult(success=False, ...)` rather than propagating. The pipeline logs the failure and continues with partial data.

```python
def run(self, target: str) -> ScanResult:
    try:
        raw = self._execute_tool(["subfinder", "-d", target])
        data = self._parse_output(raw)
        return ScanResult(tool="subfinder", target=target, success=True, data=data)
    except ToolExecutionError as e:
        logger.error("subfinder_failed", extra=e.to_dict())
        return ScanResult(tool="subfinder", target=target, success=False, error=str(e), data=[])
    except Exception as e:
        logger.exception("subfinder_unexpected_error", extra={"target": target, "error": str(e)})
        return ScanResult(tool="subfinder", target=target, success=False, error=str(e), data=[])
```

### 6.2 Use specific exceptions, not generic ones

Always raise the most specific exception available. This makes log-based alerting (e.g. "alert on TOOL_EXECUTION_FAILED with return_code=124") possible without string matching.

```python
# Bad
raise Exception("httpx failed")

# Good
raise ToolExecutionError(tool_name="httpx", command=cmd, return_code=proc.returncode, stderr=stderr)
```

### 6.3 Pass context at the raise site, not later

Add all debugging data when constructing the exception, not when catching it. By the time the exception is caught, local variables may be out of scope.

```python
# Bad — context added at catch site, may be incomplete
try:
    run_naabu(hosts)
except Exception as e:
    raise PipelineStageError("port_scan", str(e))  # no context

# Good — context captured at raise site
raise ToolExecutionError(
    tool_name="naabu",
    command=cmd,
    return_code=proc.returncode,
    stderr=stderr,
    context={"hosts_count": len(hosts), "timeout": timeout},
)
```

### 6.4 Intelligence layer: isolate analyzer failures

Each analyzer runs in its own thread via `ThreadPoolExecutor`. Catch `IntelligenceError` (and unexpected exceptions) per future so one broken analyzer does not cancel the others.

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.exceptions import IntelligenceError

analyzers = {
    "js_analyzer": run_js_analysis,
    "vuln_patterns": run_vuln_detection,
    "correlation_engine": run_correlation,
}

results = {}
with ThreadPoolExecutor(max_workers=7) as pool:
    futures = {pool.submit(fn, pipeline_result): name for name, fn in analyzers.items()}
    for future in as_completed(futures):
        name = futures[future]
        try:
            results[name] = future.result()
        except IntelligenceError as e:
            logger.error("analyzer_failed", extra=e.to_dict())
            results[name] = None  # report continues without this module
        except Exception as e:
            logger.exception("analyzer_unexpected_error", extra={"analyzer": name, "error": str(e)})
            results[name] = None
```

### 6.5 Notifications: never raise, always log

Notification failures are non-fatal. The `NotificationDispatcher` daemon thread catches all exceptions and logs them without re-raising.

```python
def _send_to_channel(self, channel, event):
    try:
        channel.send(event)
    except NotificationError as e:
        logger.warning("notification_failed", extra=e.to_dict())
    except Exception as e:
        logger.warning("notification_unexpected_error", extra={"channel": type(channel).__name__, "error": str(e)})
```

### 6.6 CheckpointError is non-fatal

If a checkpoint cannot be read, log the error and re-run the stage. If it cannot be written, log and continue — the scan result is still saved to the database.

```python
try:
    checkpoint_data = checkpoint_manager.load(scan_id, stage="subdomain_enum")
except CheckpointError as e:
    logger.warning("checkpoint_load_failed", extra=e.to_dict())
    checkpoint_data = None  # will re-run the stage
```
