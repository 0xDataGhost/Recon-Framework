"""
main.py — CLI entry point for the recon framework.

Usage:
    python main.py --target example.com --scan
    python main.py --targets targets.txt --scan --no-nuclei
    python main.py --target example.com --monitor --interval 60
    python main.py --target example.com --scan --resume
    python main.py --install-tools
    python main.py --dashboard
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import sys
import uuid
from pathlib import Path
from typing import Any

# ── Framework imports ─────────────────────────────────────────────────────────
# Modules beyond core/exceptions.py are imported lazily inside each command
# function so that missing modules produce clear, targeted errors instead of
# crashing immediately at startup.
from core.exceptions import (
    CheckpointError,
    ConfigError,
    ReconBaseError,
    ToolNotAvailableError,
)

# ── Constants ─────────────────────────────────────────────────────────────────

CONFIG_PATH = Path("config.json")
LOG_DIR = Path("data")
LOG_FILE = LOG_DIR / "recon.log"
OUTPUT_DIR = Path("output")

DEFAULT_MONITOR_INTERVAL = 60  # minutes


# ── Logging ───────────────────────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        # Merge any extra= kwargs passed by callers (e.g. exception .to_dict())
        for key, value in record.__dict__.items():
            if key not in {
                "args", "created", "exc_info", "exc_text", "filename",
                "funcName", "levelname", "levelno", "lineno", "message",
                "module", "msecs", "msg", "name", "pathname", "process",
                "processName", "relativeCreated", "stack_info", "thread",
                "threadName",
            }:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _setup_logging(level: str = "INFO", json_output: bool = True) -> None:
    """
    Configure the root logger with a rotating file handler and a console handler.

    Args:
        level:       Logging level string ("DEBUG", "INFO", "WARNING", "ERROR").
        json_output: If True, emit JSON to the log file. Console output always
                     uses a human-readable format.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Rotating file handler — JSON format
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(_JsonFormatter() if json_output else logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
    ))
    root.addHandler(file_handler)

    # Console handler — human-readable
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s — %(message)s",
                          datefmt="%H:%M:%S")
    )
    root.addHandler(console_handler)


logger = logging.getLogger("recon.main")


# ── Config helpers ────────────────────────────────────────────────────────────

def _load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """
    Load config.json. Returns an empty dict if the file does not exist so the
    framework can run with defaults before a config file is created.

    Raises:
        ConfigError: if the file exists but is not valid JSON.
    """
    if not path.exists():
        logger.warning("config_not_found", extra={"path": str(path)})
        return {}
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"config.json is not valid JSON: {exc}",
            context={"path": str(path), "json_error": str(exc)},
        ) from exc


def _resolve_targets(
    target: str | None,
    targets_file: str | None,
) -> list[str]:
    """
    Resolve --target / --targets into a deduplicated list of domain strings.

    Raises:
        SystemExit: if neither argument is provided, or the targets file is
                    missing or empty.
    """
    domains: list[str] = []

    if target:
        domains.append(target.strip())

    if targets_file:
        path = Path(targets_file)
        if not path.exists():
            logger.error("targets_file_not_found", extra={"path": targets_file})
            sys.exit(f"[ERROR] Targets file not found: {targets_file}")
        lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()]
        domains.extend(ln for ln in lines if ln and not ln.startswith("#"))

    if not domains:
        sys.exit("[ERROR] Provide --target <domain> or --targets <file>.")

    # Deduplicate while preserving insertion order
    seen: set[str] = set()
    unique: list[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)

    return unique


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_install_tools(config: dict[str, Any]) -> None:
    """Check for required tools and install any that are missing."""
    try:
        from core.tool_manager import ToolManager
    except ImportError:
        sys.exit("[ERROR] core/tool_manager.py is not yet implemented.")

    from rich.table import Table
    from rich.console import Console

    console = Console()
    tm = ToolManager(config)
    statuses = tm.check_all()

    table = Table(title="Tool Status", show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="white")
    table.add_column("Status")
    table.add_column("Version", style="dim")
    table.add_column("Path", style="dim")

    all_ok = True
    for name, status in statuses.items():
        if status.installed:
            table.add_row(name, "[green]OK[/green]", status.version or "—", status.path or "—")
        else:
            all_ok = False
            # Attempt installation
            console.print(f"[yellow]Installing {name}…[/yellow]")
            try:
                tm.ensure_tool(name)
                table.add_row(name, "[green]INSTALLED[/green]", "—", "—")
            except (ToolNotAvailableError, ReconBaseError) as exc:
                logger.error("tool_install_failed", extra=exc.to_dict())
                table.add_row(name, "[red]FAILED[/red]", "—", str(exc.context.get("reason", "")))

    console.print(table)
    if all_ok:
        console.print("[green]All tools are available.[/green]")
    else:
        console.print("[yellow]Some tools could not be installed — see log for details.[/yellow]")


def cmd_scan(
    targets: list[str],
    config: dict[str, Any],
    enable_nuclei: bool = True,
    resume: bool = False,
) -> None:
    """
    Run the full recon pipeline + intelligence pass for each target.

    Args:
        targets:       List of domain strings to scan.
        config:        Loaded config dict.
        enable_nuclei: Run nuclei in Stage 6 when True.
        resume:        Load per-stage checkpoints when True; fresh scan otherwise.
    """
    # Lazy imports — modules may not be implemented yet
    missing: list[str] = []
    for module in ("core.tool_manager", "recon.pipeline", "intelligence.analyzer",
                   "notifications.dispatcher", "output.writer"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)

    if missing:
        sys.exit(
            "[ERROR] The following modules are not yet implemented:\n"
            + "\n".join(f"  • {m}" for m in missing)
        )

    from core.tool_manager import ToolManager
    from recon.pipeline import ReconPipeline, PipelineOptions
    from intelligence.analyzer import IntelligenceAnalyzer
    from notifications.dispatcher import NotificationDispatcher
    from output.writer import OutputWriter
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn

    console = Console()

    # Verify required tools before starting
    tm = ToolManager(config)
    try:
        statuses = tm.check_all()
        missing_tools = [n for n, s in statuses.items() if not s.installed]
        if missing_tools:
            console.print(
                f"[yellow]Missing tools: {', '.join(missing_tools)}. "
                f"Run --install-tools first.[/yellow]"
            )
    except ReconBaseError as exc:
        logger.warning("tool_check_failed", extra=exc.to_dict())

    pipeline = ReconPipeline(config)
    analyzer = IntelligenceAnalyzer(config)
    dispatcher = NotificationDispatcher(config)
    writer = OutputWriter(base_dir=OUTPUT_DIR)

    for target in targets:
        scan_id = str(uuid.uuid4())
        console.rule(f"[bold cyan]Scanning: {target}[/bold cyan]")
        logger.info("scan_started", extra={
            "scan_id": scan_id, "target": target,
            "enable_nuclei": enable_nuclei, "resume": resume,
        })

        options = PipelineOptions(
            enable_nuclei=enable_nuclei,
            resume=resume,
            scan_id=scan_id,
        )

        # ── Recon pipeline ────────────────────────────────────────────────────
        pipeline_result = None
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task("Running recon pipeline…")
            try:
                pipeline_result = pipeline.run(targets=[target], options=options)
                progress.update(task, description="[green]Recon pipeline complete.[/green]")
                logger.info("pipeline_complete", extra={
                    "scan_id": scan_id,
                    "subdomains": len(pipeline_result.subdomains),
                    "live_hosts": len(pipeline_result.live_hosts),
                })
            except CheckpointError as exc:
                logger.warning("checkpoint_error", extra=exc.to_dict())
                console.print(f"[yellow]Checkpoint warning: {exc.message}[/yellow]")
            except ReconBaseError as exc:
                logger.error("pipeline_failed", extra=exc.to_dict())
                console.print(f"[red]Pipeline error: {exc}[/red]")
                continue  # move to next target
            except Exception as exc:
                logger.exception("pipeline_unexpected_error", extra={
                    "scan_id": scan_id, "target": target, "error": str(exc),
                })
                console.print(f"[red]Unexpected error during pipeline: {exc}[/red]")
                continue

        if pipeline_result is None:
            continue

        # ── Intelligence pass ─────────────────────────────────────────────────
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task("Running intelligence analysis…")
            try:
                intel_report = analyzer.analyze(pipeline_result)
                progress.update(task, description="[green]Intelligence analysis complete.[/green]")
                logger.info("intelligence_complete", extra={
                    "scan_id": scan_id,
                    "top_targets": len(intel_report.top_targets),
                    "attack_chains": len(intel_report.attack_chains),
                })
            except ReconBaseError as exc:
                logger.error("intelligence_failed", extra=exc.to_dict())
                console.print(f"[yellow]Intelligence analysis partial: {exc}[/yellow]")
                intel_report = None
            except Exception as exc:
                logger.exception("intelligence_unexpected_error", extra={
                    "scan_id": scan_id, "target": target, "error": str(exc),
                })
                intel_report = None

        # ── Write output ──────────────────────────────────────────────────────
        try:
            writer.write(target, pipeline_result, intel_report)
            out_dir = OUTPUT_DIR / target
            console.print(f"[green]Results saved to:[/green] {out_dir}/")
            if intel_report:
                console.print(f"[bold green]Attack plan:[/bold green] {out_dir}/attack_plan.md")
        except Exception as exc:
            logger.error("output_write_failed", extra={"target": target, "error": str(exc)})
            console.print(f"[red]Failed to write output: {exc}[/red]")

        # ── Dispatch summary notification ─────────────────────────────────────
        try:
            dispatcher.dispatch_scan_complete(target, pipeline_result, intel_report)
        except ReconBaseError as exc:
            logger.warning("notification_dispatch_failed", extra=exc.to_dict())

        logger.info("scan_complete", extra={"scan_id": scan_id, "target": target})


def cmd_monitor(
    targets: list[str],
    config: dict[str, Any],
    interval_minutes: int = DEFAULT_MONITOR_INTERVAL,
) -> None:
    """
    Start continuous monitoring mode: run the full pipeline on a fixed interval,
    diff results against the previous snapshot, and alert on changes.

    Args:
        targets:          List of domains to monitor.
        config:           Loaded config dict.
        interval_minutes: How often to re-run the scan.
    """
    try:
        from monitoring.monitor import MonitorScheduler
    except ImportError:
        sys.exit("[ERROR] monitoring/monitor.py is not yet implemented.")

    from rich.console import Console
    console = Console()

    try:
        from recon.pipeline import ReconPipeline
        from intelligence.analyzer import IntelligenceAnalyzer
        from notifications.dispatcher import NotificationDispatcher
    except ImportError as exc:
        sys.exit(f"[ERROR] Required module not implemented: {exc}")

    pipeline = ReconPipeline(config)
    analyzer = IntelligenceAnalyzer(config)
    dispatcher = NotificationDispatcher(config)

    scheduler = MonitorScheduler(config, pipeline, analyzer, dispatcher)

    console.print(
        f"[cyan]Starting monitor for {len(targets)} target(s) "
        f"— interval: {interval_minutes}m[/cyan]"
    )
    logger.info("monitor_started", extra={
        "targets": targets, "interval_minutes": interval_minutes,
    })

    try:
        scheduler.start(targets=targets, interval_minutes=interval_minutes)
        # Block until interrupted
        import time
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitor…[/yellow]")
        scheduler.stop()
        logger.info("monitor_stopped")


def cmd_dashboard(config: dict[str, Any]) -> None:
    """
    Launch the Flask web dashboard. Scan results are served from the SQLite
    database — no active scan is required.

    Args:
        config: Loaded config dict.
    """
    try:
        from api.app import create_app
    except ImportError:
        sys.exit("[ERROR] api/app.py is not yet implemented.")

    host: str = config.get("dashboard", {}).get("host", "127.0.0.1")
    port: int = config.get("dashboard", {}).get("port", 5000)
    debug: bool = config.get("dashboard", {}).get("debug", False)

    app = create_app(config)

    print(f"Dashboard running at http://{host}:{port}")
    logger.info("dashboard_started", extra={"host": host, "port": port})

    try:
        from flask_socketio import SocketIO
        socketio: SocketIO = app.extensions["socketio"]
        socketio.run(app, host=host, port=port, debug=debug)
    except KeyError:
        # SocketIO not attached — fall back to plain Flask (dev mode)
        app.run(host=host, port=port, debug=debug)


# ── Argument parser ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon",
        description=(
            "Advanced reconnaissance framework for bug bounty and ethical hacking.\n"
            "Automates subdomain enumeration, live host detection, port scanning,\n"
            "URL collection, JS analysis, attack chain correlation, and exploit\n"
            "scenario generation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --target example.com --scan\n"
            "  python main.py --targets targets.txt --scan --no-nuclei\n"
            "  python main.py --target example.com --scan --resume\n"
            "  python main.py --target example.com --monitor --interval 30\n"
            "  python main.py --install-tools\n"
            "  python main.py --dashboard\n\n"
            "For authorised security testing and bug bounty programs only."
        ),
    )

    # ── Target selection (mutually exclusive) ─────────────────────────────────
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "--target",
        metavar="DOMAIN",
        help="Single target domain (e.g. example.com).",
    )
    target_group.add_argument(
        "--targets",
        metavar="FILE",
        help="Path to a file containing one domain per line. Lines starting with # are ignored.",
    )

    # ── Mode flags ────────────────────────────────────────────────────────────
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--scan",
        action="store_true",
        help="Run the full recon pipeline once and generate an attack plan.",
    )
    mode_group.add_argument(
        "--monitor",
        action="store_true",
        help=(
            "Run in continuous monitoring mode. Re-runs the pipeline on a fixed "
            "interval and alerts on new subdomains, ports, and findings."
        ),
    )
    mode_group.add_argument(
        "--install-tools",
        action="store_true",
        dest="install_tools",
        help=(
            "Check for required tools (subfinder, amass, httpx, naabu, nuclei, "
            "gau, waybackurls) and install any that are missing."
        ),
    )
    mode_group.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the Flask web dashboard to browse previous scan results.",
    )

    # ── Scan options ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        dest="no_nuclei",
        help=(
            "Skip the nuclei vulnerability scan (Stage 6). Useful for faster "
            "recon on large scopes where vuln scanning is done separately."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume an interrupted scan. Completed stages are loaded from "
            "checkpoints in data/checkpoints/ instead of being re-run. "
            "If no checkpoint exists, the scan starts fresh without error."
        ),
    )

    # ── Monitor options ───────────────────────────────────────────────────────
    parser.add_argument(
        "--interval",
        type=int,
        metavar="MINUTES",
        default=DEFAULT_MONITOR_INTERVAL,
        help=f"Monitoring interval in minutes (default: {DEFAULT_MONITOR_INTERVAL}). Only used with --monitor.",
    )

    # ── Global options ────────────────────────────────────────────────────────
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=str(CONFIG_PATH),
        help=f"Path to config.json (default: {CONFIG_PATH}).",
    )
    parser.add_argument(
        "--log-level",
        metavar="LEVEL",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )

    return parser


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Logging must be set up before any framework code runs so that exception
    # handlers can log structured output from the first possible moment.
    _setup_logging(level=args.log_level)

    # ── Load config ───────────────────────────────────────────────────────────
    try:
        config = _load_config(Path(args.config))
    except ConfigError as exc:
        logger.critical("config_load_failed", extra=exc.to_dict())
        sys.exit(f"[CRITICAL] {exc}")

    # ── Validate that a mode was chosen ───────────────────────────────────────
    if not any([args.scan, args.monitor, args.install_tools, args.dashboard]):
        parser.print_help()
        sys.exit(0)

    # ── Dispatch ──────────────────────────────────────────────────────────────
    try:
        if args.install_tools:
            cmd_install_tools(config)

        elif args.dashboard:
            cmd_dashboard(config)

        elif args.scan:
            targets = _resolve_targets(args.target, args.targets)
            cmd_scan(
                targets=targets,
                config=config,
                enable_nuclei=not args.no_nuclei,
                resume=args.resume,
            )

        elif args.monitor:
            targets = _resolve_targets(args.target, args.targets)
            if args.interval < 1:
                sys.exit("[ERROR] --interval must be at least 1 minute.")
            cmd_monitor(targets=targets, config=config, interval_minutes=args.interval)

    except KeyboardInterrupt:
        print("\nInterrupted.")
        logger.info("interrupted_by_user")
        sys.exit(0)

    except ReconBaseError as exc:
        # Top-level catch for any unhandled framework exception.
        # Individual command functions are expected to handle their own exceptions
        # and continue — reaching here means something went badly wrong.
        logger.critical("unhandled_framework_error", extra=exc.to_dict())
        sys.exit(f"[{exc.error_code}] {exc.message}")

    except Exception as exc:
        logger.exception("unhandled_unexpected_error", extra={"error": str(exc)})
        sys.exit(f"[ERROR] Unexpected error: {exc}")


if __name__ == "__main__":
    main()
