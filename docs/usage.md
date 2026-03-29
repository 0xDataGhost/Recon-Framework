# Framework Usage Guide

## Table of Contents

0. [CLI Reference](#cli-reference)
1. [Architecture Overview](#1-architecture-overview)
2. [Configuration Reference](#2-configuration-reference)
3. [Module Reference](#3-module-reference)
   - [core/exceptions.py](#31-coreexceptionspy)
   - [core/config_manager.py](#32-coreconfig_managerpy) *(planned)*
   - [core/logger.py](#33-coreloggerpy) *(planned)*
   - [core/database.py](#34-coredatabasepy) *(planned)*
   - [core/checkpoint.py](#35-corecheckpointpy) *(planned)*
   - [core/tool_manager.py](#36-coretool_managerpy) *(planned)*
   - [recon/pipeline.py](#37-reconpipelinepy) *(planned)*
   - [recon/ scanner modules](#38-recon-scanner-modules) *(planned)*
   - [intelligence/analyzer.py](#39-intelligenceanalyzerpy) *(planned)*
   - [intelligence/ sub-modules](#310-intelligence-sub-modules) *(planned)*
   - [notifications/dispatcher.py](#311-notificationsdispatcherpy) *(planned)*
   - [monitoring/monitor.py](#312-monitoringmonitorpy) *(planned)*
4. [Exception System](#4-exception-system)
5. [Structured Logging](#5-structured-logging)
6. [Pipeline Workflow](#6-pipeline-workflow) *(planned)*
7. [Intelligence Layer Deep Dive](#7-intelligence-layer-deep-dive) *(planned)*
8. [Attack Plan Output Format](#8-attack-plan-output-format) *(planned)*
9. [Error Handling Best Practices](#9-error-handling-best-practices)
10. [Docstring Recommendations](#10-docstring-recommendations)

---

## CLI Reference

### Synopsis

```
python main.py [TARGET] [MODE] [OPTIONS]
```

A mode flag is always required. Target flags are required for `--scan` and `--monitor`.

---

### Target Flags

| Flag | Argument | Description |
|---|---|---|
| `--target` | `DOMAIN` | Single domain to scan (e.g. `example.com`) |
| `--targets` | `FILE` | Path to a newline-delimited file of domains. Lines starting with `#` are ignored. |

`--target` and `--targets` are mutually exclusive. Domains are deduplicated before scanning.

**`targets.txt` format:**
```
# Primary scope
example.com
api.example.com

# Acquired subsidiary
subsidiary.io
```

---

### Mode Flags

Exactly one mode must be chosen. Modes are mutually exclusive.

#### `--scan`

Run the full six-stage recon pipeline once, then run the intelligence pass and write all output files.

```bash
python main.py --target example.com --scan
python main.py --targets targets.txt --scan
```

**What runs:**
1. Subdomain enumeration (subfinder + amass)
2. Live host detection (httpx)
3. Port scanning (naabu)
4. URL collection (gau + waybackurls)
5. Endpoint classification
6. Vulnerability scanning (nuclei) — skipped if `--no-nuclei`

Then: JS analysis, vuln pattern detection, attack chain correlation, exploit generation, Top 10 scoring.

**Output:** `output/{target}/` — see [Output Files](#output-files) below.

---

#### `--monitor`

Start continuous monitoring mode. Runs the full pipeline on a repeating interval, diffs results against the previous snapshot, and dispatches alerts on changes.

```bash
python main.py --target example.com --monitor
python main.py --targets targets.txt --monitor --interval 30
```

Runs until interrupted with `Ctrl+C`. Each cycle:
- Runs the full recon pipeline
- Compares results to the last saved snapshot
- Sends Telegram/Discord alerts for new subdomains, new ports, and new nuclei findings
- Saves the new snapshot to the database

---

#### `--install-tools`

Check for required tools and install any that are missing. Does not require a target.

```bash
python main.py --install-tools
```

Checks: `subfinder`, `amass`, `httpx`, `naabu`, `nuclei`, `gau`, `waybackurls`
Optional: `ffuf` (used only for generating ffuf commands in the attack plan)

**Install strategy (in order):**
1. Check `PATH` and `~/.local/bin/`
2. If Go is available: `go install <module>@latest`
3. Otherwise: download prebuilt binary from GitHub Releases

Prints a status table on completion. Exits non-zero if any required tool could not be installed.

---

#### `--dashboard`

Launch the Flask web dashboard to browse scan results from the database.

```bash
python main.py --dashboard
```

The dashboard reads from `data/recon.db`. No active scan is required — you can run `--dashboard` after a `--scan` completes. Default URL: `http://127.0.0.1:5000`

---

### Scan Options

These flags modify the behaviour of `--scan`.

#### `--no-nuclei`

Skip Stage 6 (nuclei vulnerability scanning). Reduces scan time significantly for large scopes or when vulnerability scanning is handled separately.

```bash
python main.py --target example.com --scan --no-nuclei
```

All other stages (subdomain enum through intelligence pass) run as normal.

---

#### `--resume`

Resume an interrupted scan. The framework saves a JSON checkpoint after each stage completes in `data/checkpoints/`. With `--resume`, completed stages are loaded from their checkpoints instead of re-running.

```bash
# First run — interrupted after Stage 3
python main.py --target example.com --scan

# Resume — Stages 1–3 are loaded from checkpoints, Stages 4–6 re-run
python main.py --target example.com --scan --resume
```

If no checkpoint exists for the target, `--resume` is silently ignored and the scan starts fresh.

> **Note:** checkpoints are keyed by target domain, not by scan UUID. Running `--resume` always resumes the most recent interrupted scan for that target.

---

### Monitor Options

#### `--interval MINUTES`

Set the monitoring interval in minutes. Only used with `--monitor`. Default: `60`.

```bash
python main.py --target example.com --monitor --interval 15
```

Minimum value: 1 minute. The interval timer starts after the previous cycle completes, so actual wall-clock time between alerts may exceed the interval if the scan itself takes longer than `--interval` minutes.

---

### Global Options

#### `--config PATH`

Path to the config file. Default: `config.json` in the current directory.

```bash
python main.py --target example.com --scan --config /etc/recon/config.json
```

#### `--log-level LEVEL`

Set logging verbosity. Choices: `DEBUG`, `INFO`, `WARNING`, `ERROR`. Default: `INFO`.

```bash
# Show all subprocess output and internal state transitions
python main.py --target example.com --scan --log-level DEBUG
```

Logs are written to both stdout (human-readable) and `data/recon.log` (JSON, rotating).

---

### Output Files

Every `--scan` writes to `output/{target}/`:

| File | Contents |
|---|---|
| `subdomains.txt` | All discovered subdomains, one per line |
| `live.txt` | Live hosts: `URL STATUS_CODE TITLE` |
| `ports.txt` | Open ports: `HOST:PORT PROTOCOL SERVICE` |
| `urls.txt` | Collected URLs from gau + waybackurls |
| `nuclei.txt` | Nuclei findings: template ID, severity, matched URL |
| `js_findings.txt` | JS analysis: endpoints, secrets, GraphQL detections |
| `top_targets.txt` | Top 10 scored attack surfaces with reason tags |
| `scan_report.json` | Full machine-readable report (all findings) |
| `attack_plan.md` | Human-readable exploitation guide with copy-paste commands |

---

### Common Workflows

#### Quick scope assessment (no vuln scan)
```bash
python main.py --target example.com --scan --no-nuclei
```

#### Full scan with monitoring after
```bash
# Step 1: initial full scan
python main.py --target example.com --scan

# Step 2: watch for changes every 2 hours
python main.py --target example.com --monitor --interval 120
```

#### Large programme — multiple targets, no nuclei, debug logs
```bash
python main.py --targets scope.txt --scan --no-nuclei --log-level DEBUG
```

#### Check what the dashboard would show without re-scanning
```bash
python main.py --dashboard
# open http://127.0.0.1:5000
```

---

## 1. Architecture Overview

The framework enforces a strict three-layer separation. Data only flows forward — no layer reaches back into a previous one.

```
┌──────────────────────────────────────────────────────┐
│  RECON LAYER  (recon/)                               │
│  Runs external CLI tools. Produces PipelineResult.   │
│  No scoring, no notifications, no DB writes.         │
└──────────────────────────┬───────────────────────────┘
                           │ PipelineResult
┌──────────────────────────▼───────────────────────────┐
│  INTELLIGENCE LAYER  (intelligence/)                 │
│  Analyses PipelineResult. Produces IntelReport.      │
│  No subprocess calls (except JS HTTP fetches).       │
│  No DB access. No notifications.                     │
└──────────────────────────┬───────────────────────────┘
                           │ IntelReport
┌──────────────────────────▼───────────────────────────┐
│  OUTPUT / NOTIFICATION LAYER                         │
│  Writes files, inserts into DB, dispatches alerts.   │
│  Knows nothing about how findings were produced.     │
└──────────────────────────────────────────────────────┘
```

The Flask API and dashboard sit outside the pipeline — they only read from SQLite and never trigger scans directly.

---

## 2. Configuration Reference

`config.json` is the single configuration file. All keys are optional unless noted.

```json
{
  "api_keys": {
    "shodan": "",
    "securitytrails": "",
    "virustotal": "",
    "github": ""
  },

  "notifications": {
    "telegram": {
      "enabled": false,
      "bot_token": "",
      "chat_id": "",
      "min_severity": "MEDIUM"
    },
    "discord": {
      "enabled": false,
      "webhook_url": "",
      "min_severity": "MEDIUM"
    },
    "rate_limit_seconds": 30
  },

  "scan": {
    "default_timeout_seconds": 300,
    "httpx_batch_size": 100,
    "httpx_threads": 50,
    "naabu_rate": 1000,
    "naabu_top_ports": "1000",
    "subfinder_threads": 10,
    "amass_passive_only": true,
    "nuclei_enabled": true,
    "nuclei_severity": ["critical", "high", "medium"],
    "gau_threads": 5,
    "max_js_files_per_host": 20,
    "js_fetch_timeout_seconds": 10
  },

  "monitoring": {
    "enabled": false,
    "interval_minutes": 60,
    "targets": [],
    "alert_on_new_subdomain": true,
    "alert_on_new_port": true,
    "alert_on_new_nuclei_finding": true
  },

  "intelligence": {
    "top_targets_count": 10,
    "min_score_threshold": 10,
    "ffuf_wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "entropy_threshold_api_key": 3.5,
    "enable_exploit_generator": true,
    "enable_correlation_engine": true,
    "critical_score_threshold": 100,
    "chain_score_boost": 50
  },

  "output": {
    "base_dir": "output",
    "save_raw_tool_output": true
  },

  "dashboard": {
    "host": "127.0.0.1",
    "port": 5000,
    "secret_key": "change-me-in-production"
  },

  "database": {
    "path": "data/recon.db",
    "journal_mode": "WAL"
  },

  "logging": {
    "level": "INFO",
    "format": "json",
    "file": "data/recon.log",
    "max_bytes": 10485760,
    "backup_count": 5
  }
}
```

**Key notes:**
- `min_severity` for notifications accepts: `INFO`, `MEDIUM`, `HIGH`, `CRITICAL`
- `nuclei_severity` filters which nuclei templates run — omit `info` and `low` for speed
- `entropy_threshold_api_key` controls JS secret detection sensitivity (3.5 is a good default; lower = more false positives)
- `chain_score_boost` adds points to any endpoint that is part of a detected attack chain

---

## 3. Module Reference

> **Implementation status**
>
> Only `core/exceptions.py` is currently implemented. Sections 3.2 – 3.12
> document the **planned** module interfaces so contributors know exactly what
> to build. Code examples in these sections show the intended API but will raise
> `ModuleNotFoundError` until the modules are written.

### 3.1 `core/exceptions.py`

Central exception hierarchy. All exceptions extend `ReconBaseError` and carry:

- `error_code` — machine-readable string constant per exception class
- `message` — human-readable description
- `context` — structured dict for debugging
- `.to_dict()` — returns a JSON-serialisable dict, pass directly to `logger.error(..., extra=e.to_dict())`

See [Section 4](#4-exception-system) for the complete reference.

---

### 3.2 `core/config_manager.py`

Loads, validates, and provides access to `config.json`.

**Primary interface:**

```python
from core.config_manager import ConfigManager

config = ConfigManager("config.json")
config.load()                              # reads and validates the file
token = config.get("notifications.telegram.bot_token", default="")
config.set("scan.nuclei_enabled", False)  # runtime override (not persisted)
errors = config.validate_schema()          # returns list of missing/invalid keys
```

**Docstring recommendation:** The `get()` method should document that dot-notation keys traverse nested dicts (e.g. `"scan.httpx_threads"` reads `config["scan"]["httpx_threads"]`). This is not obvious from the signature alone.

---

### 3.3 `core/logger.py`

Sets up a rotating JSON log handler and configures the root logger. Called once at startup from `main.py`.

```python
from core.logger import setup_logging

setup_logging(level="INFO", log_file="data/recon.log")
```

After this call, all `logging.getLogger(...)` instances emit structured JSON to both stdout and the log file. See [Section 5](#5-structured-logging) for the output format.

**Logger naming convention used across the project:**

| Module | Logger name |
|---|---|
| `recon/subdomain_enum.py` | `recon.subdomain_enum` |
| `recon/live_hosts.py` | `recon.live_hosts` |
| `intelligence/js_analyzer.py` | `intelligence.js_analyzer` |
| `notifications/dispatcher.py` | `notifications.dispatcher` |
| `api/app.py` | `api` |

---

### 3.4 `core/database.py`

SQLite layer with WAL journal mode for concurrent read access. All query methods use thread-local connections, making the layer safe for both the Flask API threads and the background scan workers.

**Schema tables:**

| Table | Contents |
|---|---|
| `scans` | Scan metadata, status, options |
| `subdomains` | Discovered subdomains with classification |
| `live_hosts` | Live URLs, status codes, titles, tech |
| `port_results` | Host/port/service records |
| `urls` | Collected URLs with category and source |
| `nuclei_findings` | Template ID, severity, matched URL |
| `scored_targets` | Score, reason tags, attack vectors |
| `js_findings` | JS URL, finding type, value, severity |
| `vuln_hints` | URL, vuln type, confidence, suggestion |
| `attack_chains` | Chain ID, risk, components, attack path |
| `exploit_scenarios` | Per-endpoint attack guidance |
| `monitor_snapshots` | Serialised snapshots for diff comparison |
| `alerts` | Dispatched notification log |

**Docstring recommendation:** Each query method (e.g. `insert_subdomain`, `get_scored_targets_by_scan`) should document what columns are required, what is auto-generated, and what is returned. Without this, callers must read the schema separately.

---

### 3.5 `core/checkpoint.py`

Saves and loads per-stage scan state so interrupted scans can resume from the last completed stage rather than starting over.

```python
from core.checkpoint import CheckpointManager

cp = CheckpointManager(base_dir="data/checkpoints")

# Save after a stage completes
cp.save(scan_id="abc-123", stage="subdomain_enum", data={"subdomains": [...]})

# Check before running a stage
if cp.is_stage_complete(scan_id="abc-123", stage="subdomain_enum"):
    data = cp.load(scan_id="abc-123", stage="subdomain_enum")
    subdomains = data["subdomains"]
```

Checkpoint files are JSON stored at `data/checkpoints/{scan_id}/{stage}.json`. `CheckpointError` is raised on read/write failures but is treated as non-fatal — the stage re-runs.

---

### 3.6 `core/tool_manager.py`

Detects, versions, and installs external CLI tools.

```python
from core.tool_manager import ToolManager

tm = ToolManager(config)
statuses = tm.check_all()   # Dict[str, ToolStatus]

for name, status in statuses.items():
    print(f"{name}: {'OK' if status.installed else 'MISSING'} {status.version or ''}")

# Ensure a single tool is available (installs if missing)
available = tm.ensure_tool("nuclei")
path = tm.get_tool_path("subfinder")   # None if not found
```

**Install strategy:**
1. Check `PATH` and `~/.local/bin/`
2. If found, record path and version
3. If missing: attempt `go install <module>@latest`
4. If Go unavailable: download prebuilt binary from GitHub Releases API
5. If all attempts fail: raise `ToolNotAvailableError`

**Docstring recommendation:** `ensure_tool()` should document which tools are required (abort scan if missing) versus optional (ffuf — skips ffuf command generation if absent).

---

### 3.7 `recon/pipeline.py`

The central orchestrator. Sequences the six recon stages, manages parallelism within stages, integrates checkpoints, and assembles the `PipelineResult`.

**Stage sequence:**

```
Stage 1: SubdomainEnumerator   [subfinder ‖ amass — parallel threads]
Stage 2: LiveHostChecker       [httpx — batched in chunks of 100]
Stage 3: PortScanner           [naabu]
Stage 4: URLCollector          [gau ‖ waybackurls — parallel threads]
Stage 5: EndpointFilter        [pure Python classification]
Stage 6: NucleiScanner         [nuclei — skipped if disabled]
```

Each stage is a gate: it receives the output of the previous stage as input. If a stage returns empty data, the pipeline logs a warning and continues — downstream stages receive an empty list and complete quickly.

```python
from recon.pipeline import ReconPipeline, PipelineOptions
from core.config_manager import ConfigManager

config = ConfigManager("config.json").load()
pipeline = ReconPipeline(config)

result = pipeline.run(
    targets=["example.com"],
    options=PipelineOptions(
        enable_nuclei=True,
        resume=True,
        scan_id="abc-123",
    )
)
# result.subdomains, result.live_hosts, result.ports, result.urls, etc.
```

**Docstring recommendation:** `PipelineOptions` fields need docstrings. `resume=True` with no existing checkpoint is silently treated as a fresh scan — this should be documented explicitly.

---

### 3.8 `recon/` Scanner Modules

All scanner modules share the `BaseScanner` interface:

```python
class BaseScanner(ABC):
    def run(self, target: str, options: ScanOptions) -> ScanResult:
        ...
    def _execute_tool(self, cmd: list[str], timeout: int) -> str:
        ...  # raises ToolExecutionError on failure
    def _parse_output(self, raw: str) -> list[str]:
        ...  # raises ParsingError on invalid output
    def _handle_failure(self, error: Exception) -> ScanResult:
        ...  # always returns ScanResult(success=False), never raises
```

`_execute_tool` uses `subprocess.Popen` with `stdout=PIPE`, `stderr=PIPE`, and a hard timeout via `process.communicate(timeout=N)`. On timeout, `process.kill()` is called before raising `ToolExecutionError`.

**Module summaries:**

| Module | Tool(s) | Parallelism |
|---|---|---|
| `subdomain_enum.py` | subfinder, amass | 2 threads (concurrent) |
| `live_hosts.py` | httpx | batched: N/100 concurrent processes |
| `port_scan.py` | naabu | single process |
| `url_collection.py` | gau, waybackurls | 2 threads (concurrent) |
| `endpoint_filter.py` | — (Python regex) | single thread |
| `nuclei_scan.py` | nuclei | single process |

**Docstring recommendation:** Each module's `run()` method should document what it expects as input (a list of subdomains? live host URLs?), what format the data is in, and the shape of the returned `ScanResult.data`. This is the main integration point between pipeline stages and is not obvious from types alone.

---

### 3.9 `intelligence/analyzer.py`

Orchestrates all seven intelligence sub-modules in parallel using `ThreadPoolExecutor(max_workers=7)`. Receives a `PipelineResult` and returns an `IntelReport`.

```python
from intelligence.analyzer import IntelligenceAnalyzer

analyzer = IntelligenceAnalyzer(config)
report = analyzer.analyze(pipeline_result)

# report.top_targets        List[ScoredTarget]
# report.attack_chains      List[AttackChain]
# report.exploit_scenarios  List[ExploitScenario]
# report.js_findings        List[JSFinding]
# report.vuln_hints         List[VulnHint]
# report.ffuf_commands      List[str]
# report.change_alerts      List[ChangeAlert]
```

If any analyzer raises an exception, it is caught per-future, logged, and the corresponding field in `IntelReport` is set to an empty list. The report is always returned — never partial due to a single analyzer failure.

---

### 3.10 `intelligence/` Sub-modules

#### `js_analyzer.py`

Fetches JS files from live hosts and performs three regex passes:

1. **Endpoint extraction** — matches `/api/...` paths, fetch/axios/XHR call patterns, React Router and Vue Router route definitions
2. **Secret detection** — AWS keys (`AKIA[0-9A-Z]{16}`), Google API keys (`AIza...`), Stripe live keys (`sk_live_...`), JWT patterns, Shannon entropy > 3.5 for unknown 20+ character strings
3. **GraphQL detection** — `/graphql` and `/gql` paths, introspection query patterns, mutation/query keyword patterns in string literals

Each finding receives a sensitivity classification:

| Sensitivity | Examples |
|---|---|
| `CRITICAL` | Hardcoded API key, AWS secret |
| `HIGH` | Internal IP routes, GraphQL introspection endpoint, admin paths |
| `MEDIUM` | Hidden API endpoints, auth-related routes |
| `LOW` | General endpoint discovery |

Fetch constraints: 10s timeout, max 20 JS files per host, User-Agent spoofing, duplicate URL skipping.

---

#### `vuln_patterns.py`

Pure static URL analysis — no HTTP requests. Checks each URL against four pattern categories:

| Pattern | Detection logic |
|---|---|
| **IDOR** | Numeric/UUID segment in path, or `id=`, `user_id=`, `account=` parameters |
| **SSRF** | Parameters named `url`, `uri`, `path`, `host`, `dest`, `redirect`, `link`, `callback`, `webhook` |
| **Open Redirect** | Parameters named `next`, `redirect`, `return`, `to`, `continue`, `forward` |
| **File Upload** | URL path contains `upload`, `import`, `attach`, or `file` |

Each detection produces a `VulnHint` with a `suggestion` field containing plain-text testing guidance — what to check and example bypass techniques.

---

#### `target_prioritizer.py` — Scoring v2

Additive integer score per endpoint. Higher score = higher priority in `attack_plan.md`.

| Factor | Points |
|---|---|
| Admin panel pattern | +40 |
| File upload endpoint | +35 |
| Login page pattern | +30 |
| Unauthenticated API | +25 |
| Non-standard port | +20 |
| Technology fingerprint match | +15 |
| Staging/dev environment | +30 |
| Debug environment | +35 |
| No auth headers in collected traffic | +25 |
| JS secret on same host | +40 |
| GraphQL endpoint | +30 |
| **Part of attack chain (any)** | **+50** |

Endpoints automatically marked **CRITICAL** regardless of score:
- Staging/dev subdomain with login panel
- Admin panel on non-standard port (not 80/443/8080/8443/3000)
- API endpoint with no authentication indicator
- File upload endpoint with no content-type restriction hint

---

#### `correlation_engine.py`

Correlates findings across all recon layers to detect multi-step attack chains — combinations of conditions that individually score as MEDIUM but together represent a CRITICAL path.

**Detected chains:**

| Chain ID | Trigger conditions | Risk |
|---|---|---|
| `dev_api_exposure` | Dev/staging subdomain + API endpoint with no auth hint | CRITICAL |
| `login_idor_chain` | Login page + numeric IDs in same application's URL space | HIGH |
| `upload_path_traversal` | Upload endpoint + parameter named `path`, `dir`, or `filename` | CRITICAL |
| `admin_uncommon_port` | Admin panel URL + port not in {80, 443, 8080, 8443} | HIGH |
| `js_secret_active_endpoint` | Hardcoded secret in JS + active API endpoint on same host | CRITICAL |
| `graphql_introspection` | GraphQL endpoint + no auth header pattern detected | HIGH |
| `ssrf_internal_metadata` | SSRF-pattern parameter + cloud metadata IP in JS or URLs | CRITICAL |
| `open_redirect_oauth` | Open redirect parameter + `/oauth`, `/auth`, or `/login` in path | HIGH |

Each `AttackChain` contains an ordered `attack_path` list (the steps of the chain) and `target_urls` (the specific URLs to test).

---

#### `exploit_generator.py`

Generates rule-based (no LLM) exploitation guidance for every endpoint with `score >= critical_score_threshold` or that is part of an attack chain.

Each `ExploitScenario` contains:
- `why_interesting` — human-readable risk explanation
- `steps` — numbered testing procedure
- `bypass_techniques` — type-specific bypass list
- `example_commands` — copy-paste `curl`/`ffuf` commands with actual URL and parameter substituted in

Example for an SSRF finding:

```python
ExploitScenario(
    target_url="https://example.com/fetch?url=",
    vuln_type="SSRF",
    scenario_title="Server-Side Request Forgery via url= parameter",
    why_interesting="Parameter name 'url' commonly proxies requests server-side. "
                    "If unfiltered, allows internal network access.",
    steps=[
        "Send: https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
        "If response contains IAM metadata, AWS credentials are exposed",
        "Try http://127.0.0.1:8080 to probe internal services",
        "Try file:///etc/passwd for local file read",
    ],
    bypass_techniques=[
        "Octal IP: http://0177.0.0.1/",
        "IPv6 localhost: http://[::1]/",
        "URL encoding: http://%31%32%37%2e%30%2e%30%2e%31/",
        "DNS rebinding via custom domain",
    ],
    example_commands=[
        "curl 'https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/'",
        "ffuf -w ssrf_payloads.txt -u 'https://example.com/fetch?url=FUZZ'",
    ],
    severity="HIGH",
    chain_id=None,
)
```

---

#### `change_detector.py`

Compares the current scan's `Snapshot` against the most recent previous snapshot for the same target. Classifies new subdomains by keyword matching on the subdomain label:

| Classification | Keywords |
|---|---|
| `STAGING` | `staging`, `stg`, `stage` |
| `DEV` | `dev`, `development`, `test`, `qa` |
| `DEBUG` | `debug`, `internal` |
| `ADMIN` | `admin`, `manage`, `mgmt` |
| `UNKNOWN` | no keyword match |

Any newly discovered subdomain with a classification other than `UNKNOWN` sets `priority_flag=True` and triggers an immediate HIGH severity notification even before the intelligence pass completes.

---

### 3.11 `notifications/dispatcher.py`

Implements fire-and-forget notification dispatch using a `queue.Queue` and a dedicated daemon thread. The `dispatch()` method is always non-blocking — it enqueues the event and returns immediately so the pipeline is never delayed by slow or failing notification channels.

```python
from notifications.dispatcher import NotificationDispatcher
from notifications.telegram import TelegramNotifier
from notifications.discord import DiscordNotifier

dispatcher = NotificationDispatcher()
dispatcher.register_channel(TelegramNotifier(config))
dispatcher.register_channel(DiscordNotifier(config))

dispatcher.dispatch(NotificationEvent(
    event_type="NEW_SUBDOMAIN",
    severity="HIGH",
    target="example.com",
    message="New subdomain discovered: dev-api.example.com [DEV — priority]",
    data={"subdomain": "dev-api.example.com", "classification": "DEV"},
))
```

**Rate limiting:** each channel tracks `last_sent`. Events are silently dropped if less than `rate_limit_seconds` (default: 30) have elapsed since the last message to that channel.

**Severity filtering:** each channel has a configurable `min_severity`. Events below the threshold are silently dropped at the channel level, not at dispatch time.

---

### 3.12 `monitoring/monitor.py`

Uses APScheduler's `BackgroundScheduler` to run the full recon pipeline + intelligence pass on a configurable interval.

```python
from monitoring.monitor import MonitorScheduler

scheduler = MonitorScheduler(config, pipeline, analyzer, dispatcher)
scheduler.start(targets=["example.com"], interval_minutes=60)

# Later:
status = scheduler.get_status()   # MonitorStatus: next_run, last_run, targets
scheduler.stop()
```

Each cycle:
1. Runs `ReconPipeline.run()` for all configured targets
2. Runs `IntelligenceAnalyzer.analyze()` on results
3. Calls `DiffEngine.compute()` to compare with the previous snapshot
4. Dispatches alerts for any `added_subdomains`, `new_ports`, or `new_nuclei_findings`
5. Saves the new snapshot to the database

---

## 4. Exception System

All exceptions live in `core/exceptions.py`. Every exception:

- Has a fixed `error_code` class attribute for log aggregation and alerting rules
- Carries a `context` dict populated at the raise site (before scope is lost)
- Exposes `.to_dict()` returning a JSON-serialisable dict
- Produces readable output from plain `str(e)` or `repr(e)`

### Exception Hierarchy

```
ReconBaseError
├── ToolNotAvailableError      TOOL_NOT_AVAILABLE
├── ToolInstallError           TOOL_INSTALL_FAILED
├── ToolExecutionError         TOOL_EXECUTION_FAILED
├── PipelineStageError         PIPELINE_STAGE_ERROR
├── ParsingError               PARSE_ERROR
├── IntelligenceError          INTELLIGENCE_ERROR
├── ConfigError                CONFIG_ERROR
├── DatabaseError              DATABASE_ERROR
├── CheckpointError            CHECKPOINT_ERROR
└── NotificationError          NOTIFICATION_ERROR
```

### `ReconBaseError`

Base class. Rarely raised directly.

```python
e = ReconBaseError("Something went wrong", context={"target": "example.com"})

str(e)
# '[RECON_ERROR] Something went wrong | context={"target": "example.com"}'

repr(e)
# "ReconBaseError(error_code='RECON_ERROR', message='Something went wrong', context={'target': 'example.com'})"

e.to_dict()
# {
#   "error_code": "RECON_ERROR",
#   "error_type": "ReconBaseError",
#   "message": "Something went wrong",
#   "context": {"target": "example.com"}
# }
```

### `ToolExecutionError`

Most frequently raised in the recon layer. Stores the exact command for manual reproduction.

**Context fields:** `tool_name`, `command` (string), `return_code`, `stderr_snippet` (≤500 chars)

```python
raise ToolExecutionError(
    tool_name="httpx",
    command=["httpx", "-l", "subdomains.txt", "-o", "live.txt"],
    return_code=1,
    stderr="dial tcp: lookup example.com: no such host",
)
# context.command → "httpx -l subdomains.txt -o live.txt"
# Paste this into terminal to reproduce the failure.
```

### `PipelineStageError`

Raised when a stage cannot produce any useful partial data.

**Context fields:** `stage`, plus any extra fields passed via `context=`

```python
raise PipelineStageError(
    stage="subdomain_enum",
    reason="Both subfinder and amass returned empty results",
    context={"target": "example.com", "elapsed_seconds": 42},
)
```

### `ParsingError`

Raised when tool output is unparseable. Stores the first 300 characters of raw output.

**Context fields:** `tool_name`, `raw_output_snippet`, `reason`

```python
raise ParsingError(
    tool_name="nuclei",
    raw_output='{"template-id": null, "severity":',
    reason="JSONDecodeError on line 1",
)
```

### `IntelligenceError`

Raised by any intelligence sub-module. Caught per-analyzer so one failure does not affect others.

**Context fields:** `analyzer`, plus any extra fields passed via `context=`

```python
raise IntelligenceError(
    analyzer="js_analyzer",
    reason="requests.ConnectionError fetching app.js",
    context={"js_url": "https://example.com/app.js", "timeout": 10},
)
```

### `ToolNotAvailableError` / `ToolInstallError`

**Context fields:** `tool_name`, `reason`

```python
raise ToolNotAvailableError("subfinder", reason="Go not installed, no prebuilt binary found")
raise ToolInstallError("nuclei", reason="go install returned exit code 1")
```

### Infrastructure Exceptions

`ConfigError`, `DatabaseError`, `CheckpointError`, `NotificationError` all use the base `ReconBaseError.__init__(message, context)` signature directly:

```python
raise ConfigError(
    "Missing required keys",
    context={"missing_keys": ["notifications.telegram.bot_token"]},
)

raise DatabaseError(
    "INSERT failed on table subdomains",
    context={"scan_id": scan_id, "sqlite_error": str(e)},
)
```

---

## 5. Structured Logging

### Setup

Call once at startup:

```python
from core.logger import setup_logging
setup_logging(level="INFO", log_file="data/recon.log")
```

After this, all `logging.getLogger(...)` instances emit JSON to stdout and to the rotating log file.

### Logging exceptions

Pass `.to_dict()` directly to `extra=`:

```python
import logging
from core.exceptions import ToolExecutionError

logger = logging.getLogger("recon.live_hosts")

try:
    result = run_httpx(subdomains)
except ToolExecutionError as e:
    logger.error("tool_execution_failed", extra=e.to_dict())
```

**JSON log output:**

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

### Wrapping third-party exceptions

Wrap exceptions from `requests`, `sqlite3`, etc. before logging so they carry structured context:

```python
import requests
from core.exceptions import IntelligenceError

try:
    response = requests.get(js_url, timeout=10)
except requests.Timeout:
    err = IntelligenceError(
        analyzer="js_analyzer",
        reason=f"Timeout after 10s fetching {js_url}",
        context={"js_url": js_url, "timeout": 10},
    )
    logger.warning("js_fetch_timeout", extra=err.to_dict())
```

### Log levels used by this framework

| Level | When |
|---|---|
| `DEBUG` | Subprocess stdout/stderr, internal state transitions |
| `INFO` | Stage start/complete, scan started/finished, tool versions |
| `WARNING` | Non-fatal failures (checkpoint miss, notification fail, tool timeout recovered) |
| `ERROR` | Tool execution failed, stage produced no data, analyzer error |
| `CRITICAL` | Configuration is invalid, database is unwritable (scan cannot start) |

---

## 6. Pipeline Workflow

### Stage 1 — Subdomain Enumeration

**Input:** target domain string

**Tools:** subfinder + amass (passive mode), run as parallel threads

**Output:** deduplicated `List[str]` of subdomains

subfinder and amass run simultaneously. Results are merged with `set()` deduplication. If subfinder fails, amass results are used alone, and vice versa. Both failing raises `PipelineStageError`.

---

### Stage 2 — Live Host Detection

**Input:** `List[str]` subdomains from Stage 1

**Tool:** httpx

**Batching:** subdomains are split into chunks of `httpx_batch_size` (default 100). Each chunk spawns a separate httpx process. Up to 5 chunks run concurrently.

**Output:** `List[LiveHost]` — each with `url`, `status_code`, `title`, `technologies`

---

### Stage 3 — Port Scanning

**Input:** `List[str]` live host URLs from Stage 2

**Tool:** naabu (top 1000 ports by default)

**Output:** `List[PortResult]` — each with `host`, `port`, `protocol`, `service`

---

### Stage 4 — URL Collection

**Input:** target domain (not live hosts — gau/waybackurls work on the root domain)

**Tools:** gau + waybackurls, run as parallel threads

**Output:** merged, deduplicated `List[str]` of URLs

---

### Stage 5 — Endpoint Classification

**Input:** URL list from Stage 4 + live host list from Stage 2

**Tool:** pure Python regex matching

**Output:** `FilteredEndpoints` with categorised sublists:

| Category | Pattern |
|---|---|
| `admin_panels` | `/admin`, `/administrator`, `/manage`, `/dashboard`, `/control` |
| `login_pages` | `/login`, `/signin`, `/auth`, `/sso` |
| `api_endpoints` | `/api/`, `/v1/`, `/v2/`, `/graphql`, `/gql` |
| `upload_endpoints` | `/upload`, `/import`, `/attach`, `/file` |
| `js_files` | `.js` extension, `/static/`, `/assets/` |
| `other` | everything else |

Static assets (images, fonts, stylesheets, media) are filtered out entirely before classification using the `url_filter_extensions_exclude` list from config.

---

### Stage 6 — Vulnerability Scanning (optional)

**Input:** `List[str]` live host URLs from Stage 2

**Tool:** nuclei

**Output:** `List[NucleiFinding]` — each with `template_id`, `severity`, `host`, `matched_at`, `description`

Skipped if `nuclei_enabled: false` or `--no-nuclei` flag is passed. Only templates matching the configured severity list (`nuclei_severity`) are executed.

---

## 7. Intelligence Layer Deep Dive

### Execution Model

All seven analyzers run simultaneously in a `ThreadPoolExecutor(max_workers=7)`. The `CorrelationEngine` and `ExploitGenerator` run last (they depend on outputs from the other five) by using a two-phase execution inside `analyzer.py`:

```
Phase 1 (parallel):
  JSAnalyzer, TargetPrioritizer, ParamDiscoverer, VulnPatternDetector, ChangeDetector

Phase 2 (parallel, after Phase 1):
  CorrelationEngine    (needs VulnPatternDetector + JSAnalyzer outputs)
  ExploitGenerator     (needs TargetPrioritizer + CorrelationEngine outputs)
```

### Score Interpretation

| Score | Interpretation |
|---|---|
| < 10 | Low interest — filtered out of Top 10 |
| 10–40 | Moderate — worth a manual look |
| 40–80 | High — should be tested |
| 80–120 | Very high — likely a real finding |
| 120+ | Critical — test this first |
| Any + `CRITICAL` flag | Auto-escalated regardless of numeric score |

---

## 8. Attack Plan Output Format

`output/{target}/attack_plan.md` is generated by `output/writer.py` after the intelligence pass completes. It is designed to be opened directly — no further processing needed.

```text
# Attack Plan: example.com — 2026-03-29

Executive Summary
-----------------
- 47 subdomains discovered, 31 live hosts
- 3 CRITICAL attack surfaces identified
- Top chains: js_secret_active_endpoint, dev_api_exposure

Top 10 Most Promising Targets
------------------------------

#1 — https://dev-api.example.com/v2/upload   [Score: 195]  [CRITICAL]

  WHY IT'S INTERESTING:
    • Development API with unrestricted file upload endpoint
    • No authentication headers detected in collected traffic
    • Part of chain: dev_api_exposure + upload_path_traversal
    • JS on same host contains hardcoded AWS access key

  WHAT TO TEST:
    • Unauthenticated file upload
    • Path traversal via filename parameter
    • AWS metadata SSRF via url parameters

  HOW TO TEST:
    • curl -X POST https://dev-api.example.com/v2/upload \
           -F "file=@shell.php;type=image/jpeg"
    • ffuf -w traversal.txt \
           -u "https://dev-api.example.com/v2/upload?path=FUZZ"

  ATTACK CHAIN:
    dev subdomain → no-auth API → upload endpoint → webshell → RCE

Attack Chains Detected
-----------------------

  Chain: dev_api_exposure  [CRITICAL]
  Components: dev-api.example.com + /v2/users (no Authorization header)
  Path:
    1. Enumerate /v2/users without credentials
    2. Extract user IDs from response
    3. Test IDOR on /v2/users/{id} with other IDs

Potential Vulnerabilities
--------------------------
  [grouped by type: IDOR, SSRF, OPEN_REDIRECT, FILE_UPLOAD]

Testing Checklist
------------------
  [ ] IDOR on /v2/users/{id}
  [ ] File upload bypass at /v2/upload
  [ ] SSRF via url= at /fetch

Ready-to-Run Commands
----------------------
  # Test IDOR
  curl -H "Authorization: Bearer <token>" https://example.com/v2/users/2

  # Test SSRF
  curl "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/"

  # File upload bypass
  curl -X POST https://example.com/v2/upload \
       -F "file=@shell.php;type=image/jpeg"
```

---

## 9. Error Handling Best Practices

### Never abort the pipeline on a single tool failure

Every scanner's `run()` method catches all exceptions and returns `ScanResult(success=False)`. The pipeline continues with partial data.

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
        logger.exception("subfinder_unexpected", extra={"target": target, "error": str(e)})
        return ScanResult(tool="subfinder", target=target, success=False, error=str(e), data=[])
```

### Raise specific exceptions, not `Exception`

Using specific exceptions enables log-based alerting rules without string matching:

```python
# Bad
raise Exception("httpx failed")

# Good — allows "alert when TOOL_EXECUTION_FAILED with return_code=124 (timeout)"
raise ToolExecutionError(
    tool_name="httpx",
    command=cmd,
    return_code=proc.returncode,
    stderr=stderr,
)
```

### Populate context at the raise site

Local variables may be out of scope by the time the exception is caught:

```python
# Bad — context added too late, command and hosts_count may not be accessible
try:
    run_naabu(hosts)
except Exception as e:
    raise PipelineStageError("port_scan", str(e))

# Good — all debugging data captured immediately
raise ToolExecutionError(
    tool_name="naabu",
    command=cmd,
    return_code=proc.returncode,
    stderr=stderr,
    context={"hosts_count": len(hosts), "timeout": timeout},
)
```

### Isolate intelligence analyzer failures

Each future is caught individually — one broken analyzer does not cancel the others:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.exceptions import IntelligenceError

results = {}
with ThreadPoolExecutor(max_workers=7) as pool:
    futures = {pool.submit(fn, pipeline_result): name for name, fn in analyzers.items()}
    for future in as_completed(futures):
        name = futures[future]
        try:
            results[name] = future.result()
        except IntelligenceError as e:
            logger.error("analyzer_failed", extra=e.to_dict())
            results[name] = None
        except Exception as e:
            logger.exception("analyzer_unexpected", extra={"analyzer": name, "error": str(e)})
            results[name] = None
```

### Notifications: log, never raise

```python
def _send_to_channel(self, channel, event):
    try:
        channel.send(event)
    except NotificationError as e:
        logger.warning("notification_failed", extra=e.to_dict())
    except Exception as e:
        logger.warning("notification_unexpected", extra={
            "channel": type(channel).__name__, "error": str(e)
        })
```

### CheckpointError is non-fatal

If a checkpoint cannot be loaded, re-run the stage. If it cannot be saved, continue — the scan result is still committed to the database.

```python
try:
    data = cp.load(scan_id, stage="subdomain_enum")
except CheckpointError as e:
    logger.warning("checkpoint_load_failed", extra=e.to_dict())
    data = None   # stage will re-run
```

---

## 10. Docstring Recommendations

The following specific improvements are recommended before this codebase is shared or extended.

### `core/config_manager.py` — `get()` method

The dot-notation traversal behaviour (e.g. `config.get("scan.httpx_threads")`) is not documented anywhere. This must be explicit:

```python
def get(self, key: str, default: Any = None) -> Any:
    """
    Retrieve a config value by dot-notation key.

    Traverses nested dicts using '.' as separator. Returns `default` if any
    segment in the path is missing.

    Examples:
        config.get("scan.httpx_threads")         → int
        config.get("notifications.telegram.enabled") → bool
        config.get("missing.key", default=False) → False
    """
```

### `core/tool_manager.py` — `ensure_tool()` method

The distinction between required and optional tools should be documented:

```python
def ensure_tool(self, name: str) -> bool:
    """
    Ensure a tool is available, installing it if necessary.

    Required tools (subfinder, amass, httpx, naabu, nuclei, gau, waybackurls):
        Raises ToolNotAvailableError if the tool cannot be found or installed.

    Optional tools (ffuf):
        Returns False without raising if unavailable. Callers should check
        the return value and skip ffuf command generation gracefully.

    Returns:
        True if the tool is available after this call.

    Raises:
        ToolNotAvailableError: if the tool is required and unavailable.
        ToolInstallError: if installation was attempted and failed.
    """
```

### `recon/pipeline.py` — `PipelineOptions` dataclass

Fields need docstrings — `resume=True` with no existing checkpoint is silent:

```python
@dataclass
class PipelineOptions:
    """
    Options controlling a single pipeline run.

    Attributes:
        enable_nuclei: Run nuclei in Stage 6. Set to False for faster scans.
        resume:        Load stage outputs from checkpoint if available.
                       If no checkpoint exists for this scan_id, the run
                       proceeds as a fresh scan without error.
        scan_id:       UUID for this run. Used as the checkpoint directory
                       name and as the primary key in the scans table.
                       Auto-generated if not provided.
    """
    enable_nuclei: bool = True
    resume: bool = False
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
```

### `recon/` scanner modules — `run()` methods

Every `run()` should document its input type precisely:

```python
def run(self, subdomains: list[str], options: ScanOptions) -> ScanResult:
    """
    Run httpx against a list of subdomains to identify live hosts.

    Args:
        subdomains: Bare hostnames (e.g. "api.example.com"), not URLs.
                    httpx will probe both http:// and https:// for each.
        options:    Scan configuration including timeout and rate limits.

    Returns:
        ScanResult where data is a list of LiveHost objects. On failure,
        success=False and data=[] — the pipeline continues with no live hosts.
    """
```

### `intelligence/analyzer.py` — two-phase execution

The dependency ordering between Phase 1 and Phase 2 analyzers is a non-obvious constraint that must be documented at the class level:

```python
class IntelligenceAnalyzer:
    """
    Orchestrates all intelligence sub-modules against a completed PipelineResult.

    Execution is split into two sequential phases to satisfy data dependencies:

    Phase 1 (parallel, 5 workers):
        JSAnalyzer, TargetPrioritizer, ParamDiscoverer,
        VulnPatternDetector, ChangeDetector

    Phase 2 (parallel, 2 workers, after Phase 1 completes):
        CorrelationEngine  — requires VulnPatternDetector + JSAnalyzer outputs
        ExploitGenerator   — requires TargetPrioritizer + CorrelationEngine outputs

    If any analyzer raises an exception, the corresponding IntelReport field
    is set to [] and analysis continues. A partial IntelReport is always returned.
    """
```

### `notifications/dispatcher.py` — `dispatch()` method

The fire-and-forget behaviour (no delivery guarantee) should be explicit:

```python
def dispatch(self, event: NotificationEvent) -> None:
    """
    Enqueue a notification event for delivery. Non-blocking.

    This method returns immediately after placing the event on the internal
    queue. Delivery is handled by a background daemon thread and is not
    guaranteed — network failures, rate limits, and disabled channels will
    silently drop the event after logging a WARNING.

    Do not call this method if you require confirmed delivery.
    """
```
