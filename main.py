"""
main.py — CLI entry point for the recon framework.

Usage
-----
    python main.py --target example.com --scan
    python main.py --targets targets.txt --scan --no-nuclei
    python main.py --target example.com --scan --resume
    python main.py --target example.com --monitor --interval 60
    python main.py --install-tools
    python main.py --dashboard

For authorised security testing and bug bounty programs only.
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

# Ensure the project root is on sys.path regardless of how/where the script
# is invoked (e.g. via an alias, from a different cwd, or through a wrapper).
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Framework imports ─────────────────────────────────────────────────────────
# Only core/exceptions.py is fully implemented. All other modules are imported
# lazily inside command functions so a missing module produces a targeted error
# message rather than crashing the CLI at startup.
from core.exceptions import (
    CheckpointError,
    ConfigError,
    ReconBaseError,
    ToolInstallError,
    ToolNotAvailableError,
)

# ── Constants ─────────────────────────────────────────────────────────────────

VERSION = "0.1.0"
CONFIG_PATH = Path("config.json")
LOG_DIR = Path("data")
LOG_FILE = LOG_DIR / "recon.log"
OUTPUT_DIR = Path("output")
CHECKPOINT_DIR = LOG_DIR / "checkpoints"

DEFAULT_MONITOR_INTERVAL = 60  # minutes


# ── Logging ───────────────────────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    # Standard LogRecord attributes that are not extra user data.
    _SKIP: frozenset[str] = frozenset({
        "args", "created", "exc_info", "exc_text", "filename", "funcName",
        "levelname", "levelno", "lineno", "message", "module", "msecs",
        "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName",
    })

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._SKIP:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def _setup_logging(level: str = "INFO") -> None:
    """
    Configure the root logger with a rotating JSON file handler and a
    human-readable console handler.

    Args:
        level: Logging level string — ``"DEBUG"``, ``"INFO"``, ``"WARNING"``,
               or ``"ERROR"``.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Rotating file handler — JSON format, one object per line.
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(_JsonFormatter())
    root.addHandler(file_handler)

    # Console handler — human-readable, no JSON noise.
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root.addHandler(console_handler)


logger = logging.getLogger("recon.main")


# ── Config helpers ────────────────────────────────────────────────────────────

def _load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """
    Load and return the config file as a dict.

    Returns an empty dict (safe defaults) when the file does not exist, so
    the CLI remains usable before a config file has been created.

    Args:
        path: Path to the JSON config file.

    Raises:
        ConfigError: The file exists but is not valid JSON.
    """
    if not path.exists():
        logger.warning(
            "config_not_found",
            extra={"path": str(path), "hint": f"cp config.example.json {path}"},
        )
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
    Build a deduplicated list of domain strings from CLI arguments.

    Args:
        target:       Value of ``--target``, or ``None``.
        targets_file: Value of ``--targets``, or ``None``.

    Returns:
        Non-empty list of domain strings.

    Exits:
        With a message if no valid targets can be resolved.
    """
    domains: list[str] = []

    if target:
        domains.append(target.strip())

    if targets_file:
        fpath = Path(targets_file)
        if not fpath.exists():
            logger.error("targets_file_not_found", extra={"path": targets_file})
            sys.exit(f"[ERROR] Targets file not found: {targets_file}")
        lines = fpath.read_text(encoding="utf-8").splitlines()
        domains.extend(
            ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")
        )

    if not domains:
        sys.exit("[ERROR] Provide --target <domain> or --targets <file>.")

    # Deduplicate while preserving insertion order.
    seen: set[str] = set()
    unique: list[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)

    return unique


def _find_latest_scan_id(target: str) -> str | None:
    """
    Look for the most recent checkpoint directory belonging to ``target``.

    Each scan writes a ``target.txt`` marker into its checkpoint directory
    when the first stage completes. This function finds the newest such
    directory for the given target so ``--resume`` can reuse its ``scan_id``.

    Args:
        target: Domain string (e.g. ``"example.com"``).

    Returns:
        The scan UUID string if a checkpoint exists, otherwise ``None``.
    """
    if not CHECKPOINT_DIR.exists():
        return None

    candidates: list[tuple[float, str]] = []
    for scan_dir in CHECKPOINT_DIR.iterdir():
        if not scan_dir.is_dir():
            continue
        marker = scan_dir / "target.txt"
        if marker.exists() and marker.read_text(encoding="utf-8").strip() == target:
            candidates.append((scan_dir.stat().st_mtime, scan_dir.name))

    if not candidates:
        return None

    candidates.sort(reverse=True)  # newest first
    return candidates[0][1]


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_install_tools(config: dict[str, Any]) -> None:
    """
    Check for all required tools and install any that are missing.

    Args:
        config: Loaded config dict.
    """
    try:
        from core.tool_manager import ToolManager
    except ImportError:
        sys.exit("[ERROR] core/tool_manager.py is not yet implemented.")

    from rich.console import Console
    from rich.table import Table

    console = Console()
    tm = ToolManager(config)
    statuses = tm.check_all()

    table = Table(title="Tool Status", show_header=True, header_style="bold cyan")
    table.add_column("Tool", style="white")
    table.add_column("Status")
    table.add_column("Version", style="dim")
    table.add_column("Path", style="dim")

    any_failed = False
    for name, status in statuses.items():
        if status.installed:
            table.add_row(
                name, "[green]OK[/green]", status.version or "—", status.path or "—"
            )
        else:
            console.print(f"[yellow]Installing {name}…[/yellow]")
            try:
                tm.ensure_tool(name)
                table.add_row(name, "[green]INSTALLED[/green]", "—", "—")
            except (ToolNotAvailableError, ToolInstallError) as exc:
                any_failed = True
                logger.error("tool_install_failed", extra=exc.to_dict())
                table.add_row(
                    name,
                    "[red]FAILED[/red]",
                    "—",
                    str(exc.context.get("reason", "")),
                )

    console.print(table)
    if not any_failed:
        console.print("[green]All tools are available.[/green]")
    else:
        console.print(
            "[yellow]Some tools could not be installed — check data/recon.log.[/yellow]"
        )


def _build_pipeline_components(
    config: dict[str, Any],
) -> tuple[Any, Any, Any]:
    """
    Import and instantiate the three objects shared by ``cmd_scan`` and
    ``cmd_monitor``.

    Returns:
        ``(ReconPipeline, IntelligenceAnalyzer, NotificationDispatcher)``

    Exits:
        With a clear message listing any modules that are not yet implemented.
    """
    required = {
        "recon.pipeline": ("ReconPipeline",),
        "intelligence.analyzer": ("IntelligenceAnalyzer",),
        "notifications.dispatcher": ("NotificationDispatcher",),
    }
    missing: list[str] = []
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)

    if missing:
        sys.exit(
            "[ERROR] The following modules are not yet implemented:\n"
            + "\n".join(f"  • {m}" for m in missing)
        )

    from recon.pipeline import ReconPipeline
    from intelligence.analyzer import IntelligenceAnalyzer
    from notifications.dispatcher import NotificationDispatcher

    return ReconPipeline(config), IntelligenceAnalyzer(config), NotificationDispatcher(config)


def cmd_scan(
    targets: list[str],
    config: dict[str, Any],
    enable_nuclei: bool = True,
    resume: bool = False,
) -> None:
    """
    Run the full recon pipeline + intelligence pass for each target and write
    all output files.

    Args:
        targets:       List of domain strings to scan.
        config:        Loaded config dict.
        enable_nuclei: Run nuclei (Stage 6) when True.
        resume:        Load stage checkpoints when True; fresh scan otherwise.
    """
    try:
        from output.writer import OutputWriter
    except ImportError as _e:
        sys.exit(f"[ERROR] output/writer.py is not yet implemented. ({_e})")

    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn

    pipeline, analyzer, dispatcher = _build_pipeline_components(config)
    writer = OutputWriter(base_dir=OUTPUT_DIR)
    console = Console()

    for target in targets:
        # Resolve scan_id — reuse existing checkpoint dir when resuming.
        if resume:
            scan_id = _find_latest_scan_id(target) or str(uuid.uuid4())
            if not _find_latest_scan_id(target):
                logger.info(
                    "no_checkpoint_found_starting_fresh",
                    extra={"target": target},
                )
        else:
            scan_id = str(uuid.uuid4())

        console.rule(f"[bold cyan]Scanning: {target}[/bold cyan]")
        logger.info("scan_started", extra={
            "scan_id": scan_id,
            "target": target,
            "enable_nuclei": enable_nuclei,
            "resume": resume,
        })

        from recon.pipeline import PipelineOptions

        options = PipelineOptions(
            enable_nuclei=enable_nuclei,
            resume=resume,
            scan_id=scan_id,
        )

        # ── Stage: recon pipeline ─────────────────────────────────────────────
        pipeline_result = None
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), console=console
        ) as progress:
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
                console.print(f"[yellow]Checkpoint warning (scan continues): {exc.message}[/yellow]")
            except ReconBaseError as exc:
                logger.error("pipeline_failed", extra=exc.to_dict())
                console.print(f"[red]Pipeline error: {exc}[/red]")
                continue
            except Exception as exc:
                logger.exception("pipeline_unexpected_error", extra={
                    "scan_id": scan_id, "target": target, "error": str(exc),
                })
                console.print(f"[red]Unexpected pipeline error: {exc}[/red]")
                continue

        if pipeline_result is None:
            continue

        # ── Stage: intelligence pass ──────────────────────────────────────────
        intel_report = None
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"), console=console
        ) as progress:
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
                console.print(
                    f"[yellow]Intelligence analysis partial (continuing): {exc}[/yellow]"
                )
            except Exception as exc:
                logger.exception("intelligence_unexpected_error", extra={
                    "scan_id": scan_id, "target": target, "error": str(exc),
                })

        # ── Write output files ────────────────────────────────────────────────
        try:
            writer.write(target, pipeline_result, intel_report)
            out_dir = OUTPUT_DIR / target
            console.print(f"[green]Results saved →[/green] {out_dir}/")
            if intel_report:
                console.print(
                    f"[bold green]Attack plan →[/bold green] {out_dir}/attack_plan.md"
                )
        except Exception as exc:
            logger.error("output_write_failed", extra={"target": target, "error": str(exc)})
            console.print(f"[red]Failed to write output: {exc}[/red]")

        # ── Dispatch scan-complete notification ───────────────────────────────
        try:
            from notifications.dispatcher import NotificationEvent
            summary_msg = (
                f"Scan complete for {target}: "
                f"{len(pipeline_result.subdomains)} subdomains, "
                f"{len(pipeline_result.live_hosts)} live hosts"
                + (
                    f", {len(intel_report.top_targets)} top targets"
                    if intel_report else ""
                )
            )
            event = NotificationEvent(
                event_type="SCAN_COMPLETE",
                severity="INFO",
                target=target,
                message=summary_msg,
                data={
                    "scan_id": scan_id,
                    "subdomains": len(pipeline_result.subdomains),
                    "live_hosts": len(pipeline_result.live_hosts),
                },
            )
            dispatcher.dispatch(event)
        except ReconBaseError as exc:
            logger.warning("notification_dispatch_failed", extra=exc.to_dict())
        except Exception as exc:
            logger.warning("notification_dispatch_unexpected", extra={"error": str(exc)})

        logger.info("scan_complete", extra={"scan_id": scan_id, "target": target})


def cmd_monitor(
    targets: list[str],
    config: dict[str, Any],
    interval_minutes: int = DEFAULT_MONITOR_INTERVAL,
) -> None:
    """
    Start continuous monitoring mode.

    Re-runs the full pipeline on a fixed interval, diffs results against the
    previous snapshot, and dispatches alerts on new subdomains, ports, and
    findings.

    Args:
        targets:          List of domains to monitor.
        config:           Loaded config dict.
        interval_minutes: How often to re-run, in minutes.
    """
    try:
        from monitoring.monitor import MonitorScheduler
    except ImportError:
        sys.exit("[ERROR] monitoring/monitor.py is not yet implemented.")

    from rich.console import Console

    pipeline, analyzer, dispatcher = _build_pipeline_components(config)
    console = Console()

    scheduler = MonitorScheduler(config, pipeline, analyzer, dispatcher)
    console.print(
        f"[cyan]Monitoring {len(targets)} target(s) every {interval_minutes} minute(s). "
        f"Press Ctrl+C to stop.[/cyan]"
    )
    logger.info("monitor_started", extra={
        "targets": targets,
        "interval_minutes": interval_minutes,
    })

    try:
        scheduler.start(targets=targets, interval_minutes=interval_minutes)
        import time
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitor…[/yellow]")
        scheduler.stop()
        logger.info("monitor_stopped")


def cmd_dashboard(config: dict[str, Any]) -> None:
    """
    Launch the Flask web dashboard.

    Reads scan results from the SQLite database. No active scan is required.

    Args:
        config: Loaded config dict.
    """
    try:
        from api.app import create_app
    except ImportError:
        sys.exit("[ERROR] api/app.py is not yet implemented.")

    dashboard_cfg: dict[str, Any] = config.get("dashboard", {})
    host: str = dashboard_cfg.get("host", "127.0.0.1")
    port: int = int(dashboard_cfg.get("port", 5000))
    debug: bool = bool(dashboard_cfg.get("debug", False))

    app = create_app(config)
    print(f"Dashboard → http://{host}:{port}")
    logger.info("dashboard_started", extra={"host": host, "port": port})

    # Use Flask-SocketIO if it was registered inside create_app(), otherwise
    # fall back to plain Flask so the dashboard still starts.
    socketio = app.extensions.get("socketio")
    if socketio is not None:
        socketio.run(app, host=host, port=port, debug=debug)
    else:
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

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
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
        help=(
            "Path to a file with one domain per line. "
            "Lines starting with '#' are ignored."
        ),
    )

    # ── Mode flags (mutually exclusive) ──────────────────────────────────────
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
            "Continuous monitoring mode: re-run on a fixed interval and "
            "alert on new subdomains, ports, and findings."
        ),
    )
    mode_group.add_argument(
        "--install-tools",
        action="store_true",
        dest="install_tools",
        help=(
            "Check for required tools (subfinder, amass, httpx, naabu, "
            "nuclei, gau, waybackurls) and install any that are missing."
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
        help="Skip nuclei vulnerability scanning (Stage 6). Faster for large scopes.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume an interrupted scan by loading stage checkpoints from "
            "data/checkpoints/. Starts a fresh scan if no checkpoint exists "
            "for the target."
        ),
    )

    # ── Monitor options ───────────────────────────────────────────────────────
    parser.add_argument(
        "--interval",
        type=int,
        metavar="MINUTES",
        default=DEFAULT_MONITOR_INTERVAL,
        help=f"Monitoring re-run interval in minutes (default: {DEFAULT_MONITOR_INTERVAL}).",
    )

    # ── Global options ────────────────────────────────────────────────────────
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=str(CONFIG_PATH),
        help=f"Path to config.json (default: {CONFIG_PATH}). "
             f"Create from template: cp config.example.json config.json",
    )
    parser.add_argument(
        "--log-level",
        metavar="LEVEL",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity (default: INFO). DEBUG shows subprocess output.",
    )

    return parser


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    """Parse arguments and dispatch to the appropriate command handler."""
    parser = _build_parser()
    args = parser.parse_args()

    # Set up logging before any framework code runs so that exceptions raised
    # during config load are still captured in the log file.
    _setup_logging(level=args.log_level)

    # ── Load config ───────────────────────────────────────────────────────────
    try:
        config = _load_config(Path(args.config))
    except ConfigError as exc:
        logger.critical("config_load_failed", extra=exc.to_dict())
        sys.exit(f"[CRITICAL] {exc}")

    # ── Require a mode ────────────────────────────────────────────────────────
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
            cmd_monitor(
                targets=targets,
                config=config,
                interval_minutes=args.interval,
            )

    except KeyboardInterrupt:
        print("\nInterrupted.")
        logger.info("interrupted_by_user")
        sys.exit(0)

    except ReconBaseError as exc:
        # Last-resort handler for any unhandled framework exception.
        # Command functions are expected to handle their own errors — reaching
        # here indicates something went unexpectedly wrong at a top level.
        logger.critical("unhandled_framework_error", extra=exc.to_dict())
        sys.exit(f"[{exc.error_code}] {exc.message}")

    except Exception as exc:
        logger.exception("unhandled_unexpected_error", extra={"error": str(exc)})
        sys.exit(f"[ERROR] Unexpected error: {exc}")


if __name__ == "__main__":
    main()
