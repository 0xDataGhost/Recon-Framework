"""
recon/crawler.py — active web crawler using katana.

Katana crawls live hosts to discover URLs, forms, and JS file paths
that passive sources miss. Supports configurable depth, concurrency,
custom headers for Cloudflare bypass, and optional proxy routing.

If katana is not installed, the stage is skipped gracefully.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FALLBACK_BIN = Path.home() / ".local" / "bin"

# Default headers that mimic a real browser — helps bypass basic bot checks
_DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


def _bin(name: str) -> str | None:
    p = shutil.which(name)
    if p:
        return p
    fb = _FALLBACK_BIN / name
    return str(fb) if fb.is_file() else None


class Crawler:
    """
    Crawl live hosts with katana and extract URLs and JS file paths.

    Args:
        config: Framework config. Relevant keys under ``crawler``:
            depth (int, default 3):          Crawl depth.
            concurrency (int, default 10):   Parallel requests.
            timeout (int, default 300):      Total subprocess timeout (s).
            js_crawl (bool, default True):   Follow and crawl JS files.
            known_files (bool, default True): Parse robots.txt, sitemap.xml.
        config["proxy"] (str, optional): HTTP/HTTPS proxy URL.
        config["headers"] (dict, optional): Additional headers merged over defaults.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("crawler", {})
        self._depth: int = cfg.get("depth", 3)
        self._concurrency: int = cfg.get("concurrency", 10)
        self._timeout: int = cfg.get("timeout", 300)
        self._js_crawl: bool = cfg.get("js_crawl", True)
        self._known_files: bool = cfg.get("known_files", True)
        self._proxy: str | None = config.get("proxy")
        self._headers: dict[str, str] = {
            **_DEFAULT_HEADERS,
            **config.get("headers", {}),
        }

    def run(
        self,
        live_hosts: list[dict[str, Any]],
    ) -> tuple[list[str], list[str]]:
        """
        Crawl all live hosts.

        Args:
            live_hosts: httpx result records — must contain a ``url`` key.

        Returns:
            ``(urls, js_files)`` — both sorted and deduplicated.
        """
        targets = [h.get("url", "").strip() for h in live_hosts if h.get("url")]
        if not targets:
            return [], []

        katana = _bin("katana")
        if not katana:
            logger.warning("katana_not_found", extra={"hint": "go install github.com/projectdiscovery/katana/cmd/katana@latest"})
            return [], []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(targets))
            tmp_path = tmp.name

        urls: list[str] = []
        js_files: list[str] = []

        try:
            cmd = self._build_cmd(tmp_path)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

            for raw_line in proc.stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue

                url = self._extract_url(line)
                if not url:
                    continue

                urls.append(url)
                if self._is_js(url):
                    js_files.append(url)

            if proc.returncode not in (0, 1) and proc.stderr:
                logger.debug("katana_stderr", extra={"stderr": proc.stderr[:300]})

            logger.info("crawler_done", extra={
                "urls": len(urls), "js_files": len(js_files),
            })

        except subprocess.TimeoutExpired:
            logger.warning("katana_timeout", extra={"timeout": self._timeout})
        except Exception as exc:
            logger.warning("katana_error", extra={"error": str(exc)})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return sorted(set(urls)), sorted(set(js_files))

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_cmd(self, list_file: str) -> list[str]:
        katana = _bin("katana")
        cmd = [
            katana,
            "-list", list_file,
            "-depth", str(self._depth),
            "-concurrency", str(self._concurrency),
            "-silent",
            "-timeout", "10",
            "-retry", "1",
            "-no-color",
        ]

        if self._js_crawl:
            cmd.append("-js-crawl")

        if self._known_files:
            cmd += ["-known-files", "all"]

        for key, value in self._headers.items():
            cmd += ["-H", f"{key}: {value}"]

        if self._proxy:
            cmd += ["-proxy", self._proxy]

        return cmd

    @staticmethod
    def _extract_url(line: str) -> str | None:
        """Parse a URL from either JSON output or plain text."""
        if line.startswith("{"):
            try:
                rec = json.loads(line)
                return (
                    rec.get("request", {}).get("endpoint")
                    or rec.get("endpoint")
                    or rec.get("url")
                )
            except json.JSONDecodeError:
                pass
        if line.startswith("http"):
            return line
        return None

    @staticmethod
    def _is_js(url: str) -> bool:
        path = url.split("?")[0].lower()
        return path.endswith(".js") or ".js?" in url
