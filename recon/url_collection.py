"""
recon/url_collection.py — passive URL harvesting.

Tools
-----
  gau          — GetAllUrls (AlienVault, Common Crawl, Wayback, URLScan)
  waybackurls  — Wayback Machine CDX API

Both tools read the target from stdin. Results are merged, deduplicated,
and filtered to remove static assets that add noise without recon value.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FALLBACK_BIN = Path.home() / ".local" / "bin"

_NOISE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".webm", ".ogg",
    ".pdf", ".zip", ".gz", ".tar", ".rar",
    ".css",
})


def _bin(name: str) -> str | None:
    p = shutil.which(name)
    if p:
        return p
    fb = _FALLBACK_BIN / name
    return str(fb) if fb.is_file() else None


def _is_noise(url: str) -> bool:
    path = url.split("?")[0].lower()
    return any(path.endswith(ext) for ext in _NOISE_EXTENSIONS)


class URLCollector:
    """
    Harvest passive URLs for a target domain.

    Args:
        config: Framework config. Relevant keys under ``url_collection``:
            timeout (int, default 180):   Per-tool subprocess timeout in seconds.
            threads (int, default 5):     gau worker threads.
            providers (list[str]):        gau providers override.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("url_collection", {})
        self._timeout: int = cfg.get("timeout", 180)
        self._threads: int = cfg.get("threads", 5)
        self._providers: list[str] = cfg.get("providers", [])

    def run(self, target: str) -> list[str]:
        """
        Run gau and waybackurls in parallel.

        Args:
            target: Root domain (e.g. ``"example.com"``).

        Returns:
            Sorted, deduplicated list of URLs (static assets removed).
        """
        urls: list[str] = []

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(self._run_gau, target): "gau",
                pool.submit(self._run_waybackurls, target): "waybackurls",
            }
            for fut in as_completed(futures):
                tool = futures[fut]
                try:
                    batch = fut.result()
                    urls.extend(batch)
                    logger.info(
                        "url_tool_done",
                        extra={"tool": tool, "count": len(batch), "target": target},
                    )
                except Exception as exc:
                    logger.warning(
                        "url_tool_error",
                        extra={"tool": tool, "error": str(exc)},
                    )

        filtered = sorted({u for u in urls if u.startswith("http") and not _is_noise(u)})
        logger.info("url_collection_done", extra={"total": len(filtered), "target": target})
        return filtered

    # ── Private helpers ────────────────────────────────────────────────────────

    def _run_gau(self, target: str) -> list[str]:
        gau = _bin("gau")
        if not gau:
            logger.warning("gau_not_found", extra={"hint": "run --install-tools"})
            return []

        cmd = [gau, "--subs", "--threads", str(self._threads)]
        if self._providers:
            cmd += ["--providers", ",".join(self._providers)]

        try:
            # gau reads the target domain from stdin
            proc = subprocess.run(
                cmd,
                input=target,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        except subprocess.TimeoutExpired:
            logger.warning("gau_timeout", extra={"target": target})
            return []
        except Exception as exc:
            logger.warning("gau_error", extra={"error": str(exc)})
            return []

    def _run_waybackurls(self, target: str) -> list[str]:
        wb = _bin("waybackurls")
        if not wb:
            logger.warning("waybackurls_not_found", extra={"hint": "run --install-tools"})
            return []

        try:
            # waybackurls also reads from stdin
            proc = subprocess.run(
                [wb],
                input=target,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        except subprocess.TimeoutExpired:
            logger.warning("waybackurls_timeout", extra={"target": target})
            return []
        except Exception as exc:
            logger.warning("waybackurls_error", extra={"error": str(exc)})
            return []
