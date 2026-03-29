"""
recon/pipeline.py — orchestrates all reconnaissance stages.

Stage order
-----------
  1  subdomain_enum     subfinder + amass (parallel)
  2  live_hosts         httpx — HTTP probe with tech detection
  3  port_scan          naabu — top-1000 ports
  4  url_collection     multi-layer URL discovery (tools → robots → crawl → JS → probe)
  5  crawl              katana — active crawler (depth-limited)
  6  js_analysis        download JS files, extract secrets + endpoints
  7  vuln_scan          nuclei — vulnerability templates

Each stage is checkpointed so ``--resume`` can skip completed stages.
All external tool invocations use browser-like headers by default so
basic bot-detection / Cloudflare checks are less likely to block them.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.checkpoint import CheckpointManager
from core.exceptions import PipelineStageError
from recon.subdomain_enum import SubdomainEnumerator
from recon.url_discovery import URLDiscovery
from recon.crawler import Crawler
from recon.js_analyzer import JSAnalyzer, JSFinding
from recon.vuln_scanner import VulnScanner, NucleiFinding
from recon.wordpress import WordPressScanner, WPResult

logger = logging.getLogger(__name__)

CHECKPOINT_DIR = Path("data") / "checkpoints"
_FALLBACK_BIN = Path.home() / ".local" / "bin"

# Browser-like headers used for all tool invocations that accept -H flags.
# Helps bypass trivial Cloudflare / WAF bot checks.
_CF_BYPASS_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}


def _bin(name: str) -> str | None:
    p = shutil.which(name)
    if p:
        return p
    fb = _FALLBACK_BIN / name
    return str(fb) if fb.is_file() else None


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class PipelineOptions:
    enable_nuclei: bool = True
    resume: bool = False
    scan_id: str = ""


@dataclass
class PipelineResult:
    target: str
    scan_id: str
    # Stage outputs
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict[str, Any]] = field(default_factory=list)
    ports: dict[str, list[int]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)            # passive (gau/waybackurls)
    crawled_urls: list[str] = field(default_factory=list)    # active (katana)
    js_files: list[str] = field(default_factory=list)        # JS URLs to analyze
    js_findings: list[dict[str, Any]] = field(default_factory=list)   # secrets/endpoints
    nuclei_findings: list[dict[str, Any]] = field(default_factory=list)
    wp_findings: list[dict[str, Any]] = field(default_factory=list)   # per-WP-host results

    @property
    def all_urls(self) -> list[str]:
        """Union of passive + crawled URLs, deduplicated."""
        return sorted(set(self.urls) | set(self.crawled_urls))


# ── Pipeline ───────────────────────────────────────────────────────────────────

class ReconPipeline:
    """
    Run all recon stages for a target and return a :class:`PipelineResult`.

    Args:
        config: Loaded framework config dict.  Relevant top-level keys:
            proxy (str):    HTTP/HTTPS proxy URL passed to all tools.
            headers (dict): Extra HTTP headers merged over CF bypass defaults.

    Config sub-sections respected by each stage module (see their docstrings):
        url_discovery, crawler, js_analysis, nuclei
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        # Merge CF bypass headers with any user-supplied ones
        self._headers: dict[str, str] = {
            **_CF_BYPASS_HEADERS,
            **config.get("headers", {}),
        }
        # Inject merged headers so stage modules pick them up
        config_with_headers = {**config, "headers": self._headers}

        self._enum = SubdomainEnumerator(config_with_headers)
        self._url_discovery = URLDiscovery(config_with_headers)
        self._crawler = Crawler(config_with_headers)
        self._js_analyzer = JSAnalyzer(config_with_headers)
        self._vuln_scanner = VulnScanner(config_with_headers)
        self._wp_scanner = WordPressScanner(config_with_headers)

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self, targets: list[str], options: PipelineOptions) -> PipelineResult:
        """
        Run all pipeline stages for ``targets[0]``.

        (Multiple targets are iterated at the ``cmd_scan`` level; each call
        to ``run`` processes exactly one target.)
        """
        target = targets[0]
        cp = CheckpointManager(CHECKPOINT_DIR, options.scan_id)
        result = PipelineResult(target=target, scan_id=options.scan_id)

        # ── Stage 1: subdomain enumeration ────────────────────────────────────
        result.subdomains = self._stage(
            name="subdomain_enum",
            cp=cp,
            resume=options.resume,
            run=lambda: self._enum.run(target),
            serialize=lambda d: {"subdomains": d},
            deserialize=lambda d: d.get("subdomains", []),
        )

        # ── Stage 2: live host detection ──────────────────────────────────────
        result.live_hosts = self._stage(
            name="live_hosts",
            cp=cp,
            resume=options.resume,
            run=lambda: self._run_httpx(result.subdomains),
            serialize=lambda d: {"live_hosts": d},
            deserialize=lambda d: d.get("live_hosts", []),
        )

        # ── Stage 3: port scanning ────────────────────────────────────────────
        result.ports = self._stage(
            name="port_scan",
            cp=cp,
            resume=options.resume,
            run=lambda: self._run_naabu(result.live_hosts),
            serialize=lambda d: {"ports": d},
            deserialize=lambda d: d.get("ports", {}),
        )

        # ── Stage 4: URL discovery (multi-layer fallback) ─────────────────────
        result.urls = self._stage(
            name="url_collection",
            cp=cp,
            resume=options.resume,
            run=lambda: self._url_discovery.run(target, result.live_hosts),
            serialize=lambda d: {"urls": d},
            deserialize=lambda d: d.get("urls", []),
        )

        # ── Stage 5: active crawling ──────────────────────────────────────────
        crawl_result = self._stage(
            name="crawl",
            cp=cp,
            resume=options.resume,
            run=lambda: self._run_crawl(result.live_hosts),
            serialize=lambda d: {"crawled_urls": d[0], "js_files": d[1]},
            deserialize=lambda d: (d.get("crawled_urls", []), d.get("js_files", [])),
        )
        result.crawled_urls, js_from_crawler = crawl_result

        # ── Build JS file list: crawler + passive URLs ending in .js ──────────
        js_from_passive = [u for u in result.urls if u.split("?")[0].endswith(".js")]
        result.js_files = sorted(set(js_from_crawler) | set(js_from_passive))

        # ── Stage 6: JS analysis ──────────────────────────────────────────────
        result.js_findings = self._stage(
            name="js_analysis",
            cp=cp,
            resume=options.resume,
            run=lambda: [f.to_dict() for f in self._js_analyzer.analyze(result.js_files)],
            serialize=lambda d: {"js_findings": d},
            deserialize=lambda d: d.get("js_findings", []),
        )

        # ── Stage 7: WordPress scan (auto-activated) ─────────────────────────
        wp_hosts = self._wordpress_hosts(result.live_hosts)
        if wp_hosts:
            logger.info("wp_hosts_detected", extra={"count": len(wp_hosts)})
            result.wp_findings = self._stage(
                name="wp_scan",
                cp=cp,
                resume=options.resume,
                run=lambda: self._run_wp_scan(wp_hosts),
                serialize=lambda d: {"wp_findings": d},
                deserialize=lambda d: d.get("wp_findings", []),
            )
        else:
            logger.info("wp_not_detected", extra={"target": target})

        # ── Stage 8: vulnerability scan ───────────────────────────────────────
        if options.enable_nuclei:
            result.nuclei_findings = self._stage(
                name="vuln_scan",
                cp=cp,
                resume=options.resume,
                run=lambda: [f.to_dict() for f in self._vuln_scanner.run(result.all_urls)],
                serialize=lambda d: {"findings": d},
                deserialize=lambda d: d.get("findings", []),
            )
        else:
            logger.info("nuclei_skipped", extra={"target": target})

        return result

    # ── Generic stage runner ───────────────────────────────────────────────────

    def _stage(
        self,
        *,
        name: str,
        cp: CheckpointManager,
        resume: bool,
        run: Any,
        serialize: Any,
        deserialize: Any,
    ) -> Any:
        """
        Execute one pipeline stage with checkpoint support.

        On resume, loads from checkpoint if the stage already completed.
        Otherwise runs *run*, saves the result, and returns it.
        """
        if resume and cp.is_complete(name):
            data = cp.load(name) or {}
            result = deserialize(data)
            _count = len(result) if hasattr(result, "__len__") else "?"
            logger.info("stage_resumed", extra={"stage": name, "items": _count})
            return result

        logger.info("stage_started", extra={"stage": name})
        try:
            result = run()
        except PipelineStageError:
            raise
        except Exception as exc:
            raise PipelineStageError(name, str(exc)) from exc

        try:
            cp.save(name, serialize(result))
        except Exception as exc:
            logger.warning("checkpoint_save_failed", extra={"stage": name, "error": str(exc)})

        _count = len(result) if hasattr(result, "__len__") else "?"
        logger.info("stage_complete", extra={"stage": name, "items": _count})
        return result

    # ── Stage implementations ──────────────────────────────────────────────────

    def _run_httpx(self, subdomains: list[str]) -> list[dict[str, Any]]:
        if not subdomains:
            return []

        httpx = _bin("httpx")
        if not httpx:
            logger.warning("httpx_not_found", extra={"hint": "run --install-tools"})
            return []

        hosts: list[dict[str, Any]] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(subdomains))
            tmp_path = tmp.name

        try:
            cmd = [
                httpx,
                "-l", tmp_path,
                "-json", "-silent",
                "-title", "-td",    # tech detection
                "-sc",              # status code
                "-timeout", "15",
                "-threads", "25",
                "-retries", "1",
                "-no-color",
            ]
            # Pass CF bypass headers
            for key, value in self._headers.items():
                cmd += ["-H", f"{key}: {value}"]

            proxy = self._config.get("proxy")
            if proxy:
                cmd += ["-http-proxy", proxy]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,   # 10 min hard cap for large subdomain lists
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    hosts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        except subprocess.TimeoutExpired:
            logger.warning("httpx_timeout")
        except Exception as exc:
            logger.warning("httpx_error", extra={"error": str(exc)})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return hosts

    def _run_naabu(self, live_hosts: list[dict[str, Any]]) -> dict[str, list[int]]:
        if not live_hosts:
            return {}

        naabu = _bin("naabu")
        if not naabu:
            logger.warning("naabu_not_found", extra={"hint": "run --install-tools"})
            return {}

        hostnames = sorted({
            (h.get("host") or h.get("url", "").split("://")[-1].split("/")[0]).split(":")[0]
            for h in live_hosts
            if h.get("host") or h.get("url")
        })
        if not hostnames:
            return {}

        ports: dict[str, list[int]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(hostnames))
            tmp_path = tmp.name

        try:
            cmd = [
                naabu,
                "-l", tmp_path,
                "-json", "-silent",
                "-top-ports", "1000",
                "-timeout", "500",   # ms per port
                "-retries", "1",
                "-no-color",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    host = rec.get("host", "")
                    port = rec.get("port")
                    if host and port:
                        ports.setdefault(host, []).append(int(port))
                except (json.JSONDecodeError, ValueError):
                    pass

        except subprocess.TimeoutExpired:
            logger.warning("naabu_timeout")
        except Exception as exc:
            logger.warning("naabu_error", extra={"error": str(exc)})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return ports

    def _run_crawl(
        self,
        live_hosts: list[dict[str, Any]],
    ) -> tuple[list[str], list[str]]:
        return self._crawler.run(live_hosts)

    @staticmethod
    def _wordpress_hosts(live_hosts: list[dict[str, Any]]) -> list[str]:
        """
        Return URLs of hosts where WordPress was detected by httpx tech detection.

        httpx encodes tech as either a list of strings or a list of dicts
        depending on version. We handle both.
        """
        wp_urls: list[str] = []
        for h in live_hosts:
            url = h.get("url", "")
            if not url:
                continue
            tech_raw = h.get("tech") or h.get("technologies") or []
            tech_names: list[str] = []
            for t in tech_raw:
                if isinstance(t, str):
                    tech_names.append(t.lower())
                elif isinstance(t, dict):
                    tech_names.append(t.get("name", "").lower())
            if any("wordpress" in t for t in tech_names):
                wp_urls.append(url.rstrip("/"))
        return wp_urls

    def _run_wp_scan(self, wp_urls: list[str]) -> list[dict[str, Any]]:
        """Run WordPressScanner on each detected WP host and return serialised results."""
        results: list[dict[str, Any]] = []
        for url in wp_urls:
            try:
                wp_result = self._wp_scanner.scan(url)
                results.append(wp_result.to_dict())
            except Exception as exc:
                logger.warning("wp_scan_error", extra={"url": url, "error": str(exc)})
        return results
