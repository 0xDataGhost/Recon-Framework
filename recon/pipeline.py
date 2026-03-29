"""
recon/pipeline.py — multi-stage reconnaissance pipeline.

Stages
------
  1  subdomain_enum   subfinder + amass (parallel)
  2  live_hosts       httpx  — HTTP probe, title, tech detection
  3  port_scan        naabu  — top-1000 ports
  4  url_collection   gau + waybackurls (parallel)
  5  js_analysis      extract JS URLs from live hosts
  6  nuclei           vulnerability scan (optional, --no-nuclei to skip)

Each stage is checkpointed so a scan can be resumed with --resume.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.checkpoint import CheckpointManager
from core.exceptions import PipelineStageError
from recon.subdomain_enum import SubdomainEnumerator

logger = logging.getLogger(__name__)

CHECKPOINT_DIR = Path("data") / "checkpoints"
_FALLBACK_BIN = Path.home() / ".local" / "bin"


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
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict[str, Any]] = field(default_factory=list)
    ports: dict[str, list[int]] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    nuclei_findings: list[dict[str, Any]] = field(default_factory=list)


# ── Pipeline ───────────────────────────────────────────────────────────────────

class ReconPipeline:
    """
    Orchestrates all reconnaissance stages for a list of targets.

    Args:
        config: Loaded framework config dict.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._enum = SubdomainEnumerator(config)

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self, targets: list[str], options: PipelineOptions) -> PipelineResult:
        """
        Run all pipeline stages for the first target in *targets*.

        Multiple targets are supported at the caller level (``cmd_scan``
        iterates and calls ``run`` once per target).

        Returns:
            Populated :class:`PipelineResult`.
        """
        target = targets[0]
        cp = CheckpointManager(CHECKPOINT_DIR, options.scan_id)
        result = PipelineResult(target=target, scan_id=options.scan_id)

        result.subdomains = self._stage_subdomains(target, cp, options.resume)
        result.live_hosts = self._stage_live_hosts(result.subdomains, cp, options.resume)
        result.ports = self._stage_ports(result.live_hosts, cp, options.resume)
        result.urls = self._stage_urls(target, cp, options.resume)
        result.js_files = self._stage_js(result.live_hosts, cp, options.resume)

        if options.enable_nuclei:
            result.nuclei_findings = self._stage_nuclei(result.live_hosts, cp, options.resume)
        else:
            logger.info("nuclei_skipped", extra={"target": target})

        return result

    # ── Stage 1: subdomain enumeration ────────────────────────────────────────

    def _stage_subdomains(
        self, target: str, cp: CheckpointManager, resume: bool
    ) -> list[str]:
        stage = "subdomain_enum"
        if resume and cp.is_complete(stage):
            data = cp.load(stage) or {}
            subs = data.get("subdomains", [])
            logger.info("stage_resumed", extra={"stage": stage, "count": len(subs)})
            return subs

        logger.info("stage_started", extra={"stage": stage, "target": target})
        try:
            subs = self._enum.run(target)
        except Exception as exc:
            raise PipelineStageError(stage, str(exc)) from exc

        cp.save(stage, {"target": target, "subdomains": subs})
        logger.info("stage_complete", extra={"stage": stage, "count": len(subs)})
        return subs

    # ── Stage 2: live host detection ──────────────────────────────────────────

    def _stage_live_hosts(
        self,
        subdomains: list[str],
        cp: CheckpointManager,
        resume: bool,
    ) -> list[dict[str, Any]]:
        stage = "live_hosts"
        if resume and cp.is_complete(stage):
            data = cp.load(stage) or {}
            hosts = data.get("live_hosts", [])
            logger.info("stage_resumed", extra={"stage": stage, "count": len(hosts)})
            return hosts

        logger.info("stage_started", extra={"stage": stage, "count": len(subdomains)})

        if not subdomains:
            cp.save(stage, {"live_hosts": []})
            return []

        httpx_bin = _bin("httpx")
        if not httpx_bin:
            logger.warning("httpx_not_found", extra={"stage": stage})
            cp.save(stage, {"live_hosts": []})
            return []

        hosts: list[dict[str, Any]] = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(subdomains))
            tmp_path = tmp.name

        try:
            cmd = [
                httpx_bin, "-l", tmp_path,
                "-json", "-silent",
                "-title", "-tech-detect", "-status-code",
                "-timeout", "10",
                "-threads", "50",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    hosts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            logger.warning("httpx_timeout", extra={"stage": stage})
        except Exception as exc:
            logger.warning("httpx_error", extra={"stage": stage, "error": str(exc)})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        cp.save(stage, {"live_hosts": hosts})
        logger.info("stage_complete", extra={"stage": stage, "count": len(hosts)})
        return hosts

    # ── Stage 3: port scanning ────────────────────────────────────────────────

    def _stage_ports(
        self,
        live_hosts: list[dict[str, Any]],
        cp: CheckpointManager,
        resume: bool,
    ) -> dict[str, list[int]]:
        stage = "port_scan"
        if resume and cp.is_complete(stage):
            data = cp.load(stage) or {}
            ports = data.get("ports", {})
            logger.info("stage_resumed", extra={"stage": stage})
            return ports

        logger.info("stage_started", extra={"stage": stage, "count": len(live_hosts)})

        if not live_hosts:
            cp.save(stage, {"ports": {}})
            return {}

        naabu_bin = _bin("naabu")
        if not naabu_bin:
            logger.warning("naabu_not_found", extra={"stage": stage})
            cp.save(stage, {"ports": {}})
            return {}

        hostnames = list({h.get("host", h.get("url", "")).split("://")[-1].split("/")[0]
                         for h in live_hosts if h.get("host") or h.get("url")})
        if not hostnames:
            cp.save(stage, {"ports": {}})
            return {}

        ports: dict[str, list[int]] = {}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(hostnames))
            tmp_path = tmp.name

        try:
            cmd = [naabu_bin, "-l", tmp_path, "-json", "-silent", "-top-ports", "1000"]
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
            logger.warning("naabu_timeout", extra={"stage": stage})
        except Exception as exc:
            logger.warning("naabu_error", extra={"stage": stage, "error": str(exc)})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        cp.save(stage, {"ports": ports})
        logger.info("stage_complete", extra={"stage": stage, "hosts_with_ports": len(ports)})
        return ports

    # ── Stage 4: URL collection ───────────────────────────────────────────────

    def _stage_urls(
        self, target: str, cp: CheckpointManager, resume: bool
    ) -> list[str]:
        stage = "url_collection"
        if resume and cp.is_complete(stage):
            data = cp.load(stage) or {}
            urls = data.get("urls", [])
            logger.info("stage_resumed", extra={"stage": stage, "count": len(urls)})
            return urls

        logger.info("stage_started", extra={"stage": stage, "target": target})

        urls: list[str] = []

        def _run_gau() -> list[str]:
            gau = _bin("gau")
            if not gau:
                logger.warning("gau_not_found")
                return []
            try:
                proc = subprocess.run(
                    [gau, "--subs", target],
                    capture_output=True, text=True, timeout=120,
                )
                return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            except Exception as exc:
                logger.warning("gau_error", extra={"error": str(exc)})
                return []

        def _run_wayback() -> list[str]:
            wb = _bin("waybackurls")
            if not wb:
                logger.warning("waybackurls_not_found")
                return []
            try:
                proc = subprocess.run(
                    [wb, target],
                    capture_output=True, text=True, timeout=120,
                )
                return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            except Exception as exc:
                logger.warning("waybackurls_error", extra={"error": str(exc)})
                return []

        with ThreadPoolExecutor(max_workers=2) as ex:
            futures = [ex.submit(_run_gau), ex.submit(_run_wayback)]
            for f in as_completed(futures):
                try:
                    urls.extend(f.result())
                except Exception:
                    pass

        urls = sorted(set(urls))
        cp.save(stage, {"urls": urls})
        logger.info("stage_complete", extra={"stage": stage, "count": len(urls)})
        return urls

    # ── Stage 5: JS file extraction ───────────────────────────────────────────

    def _stage_js(
        self,
        live_hosts: list[dict[str, Any]],
        cp: CheckpointManager,
        resume: bool,
    ) -> list[str]:
        stage = "js_analysis"
        if resume and cp.is_complete(stage):
            data = cp.load(stage) or {}
            js = data.get("js_files", [])
            logger.info("stage_resumed", extra={"stage": stage, "count": len(js)})
            return js

        logger.info("stage_started", extra={"stage": stage})

        js_files: list[str] = []
        for host_rec in live_hosts:
            # httpx JSON may include a "body" or we scan urls ending in .js
            url = host_rec.get("url", "")
            if url.endswith(".js"):
                js_files.append(url)

        js_files = sorted(set(js_files))
        cp.save(stage, {"js_files": js_files})
        logger.info("stage_complete", extra={"stage": stage, "count": len(js_files)})
        return js_files

    # ── Stage 6: nuclei ───────────────────────────────────────────────────────

    def _stage_nuclei(
        self,
        live_hosts: list[dict[str, Any]],
        cp: CheckpointManager,
        resume: bool,
    ) -> list[dict[str, Any]]:
        stage = "nuclei"
        if resume and cp.is_complete(stage):
            data = cp.load(stage) or {}
            findings = data.get("findings", [])
            logger.info("stage_resumed", extra={"stage": stage, "count": len(findings)})
            return findings

        logger.info("stage_started", extra={"stage": stage, "count": len(live_hosts)})

        if not live_hosts:
            cp.save(stage, {"findings": []})
            return []

        nuclei_bin = _bin("nuclei")
        if not nuclei_bin:
            logger.warning("nuclei_not_found", extra={"stage": stage})
            cp.save(stage, {"findings": []})
            return []

        urls = [h.get("url", "") for h in live_hosts if h.get("url")]
        if not urls:
            cp.save(stage, {"findings": []})
            return []

        findings: list[dict[str, Any]] = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(urls))
            tmp_path = tmp.name

        try:
            cmd = [
                nuclei_bin, "-l", tmp_path,
                "-json", "-silent",
                "-severity", "medium,high,critical",
                "-timeout", "10",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            logger.warning("nuclei_timeout", extra={"stage": stage})
        except Exception as exc:
            logger.warning("nuclei_error", extra={"stage": stage, "error": str(exc)})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        cp.save(stage, {"findings": findings})
        logger.info("stage_complete", extra={"stage": stage, "count": len(findings)})
        return findings
