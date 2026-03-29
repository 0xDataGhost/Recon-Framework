"""
recon/vuln_scanner.py — nuclei vulnerability scanner integration.

Runs nuclei against a deduplicated URL list, parses the JSONL output, and
returns structured :class:`NucleiFinding` objects sorted by severity.

Cloudflare / WAF bypass options
--------------------------------
  - Custom headers (User-Agent, etc.) via config["headers"]
  - HTTP proxy via config["proxy"]
  - Rate limiting via config["nuclei"]["rate_limit"]
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

logger = logging.getLogger(__name__)

_FALLBACK_BIN = Path.home() / ".local" / "bin"
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _bin(name: str) -> str | None:
    p = shutil.which(name)
    if p:
        return p
    fb = _FALLBACK_BIN / name
    return str(fb) if fb.is_file() else None


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "host": self.host,
            "matched_at": self.matched_at,
            "description": self.description,
            "tags": self.tags,
        }


class VulnScanner:
    """
    Run nuclei and return structured findings.

    Args:
        config: Framework config. Relevant keys under ``nuclei``:
            severity (str, default "low,medium,high,critical"):
                Comma-separated severity filter.
            rate_limit (int, default 150):
                Max requests per second.
            timeout (int, default 600):
                Total subprocess timeout in seconds.
            retries (int, default 1):
                Per-request retry count.
            templates (list[str], optional):
                Explicit template IDs or paths to run instead of defaults.
        config["proxy"] (str):    HTTP proxy URL.
        config["headers"] (dict): Extra headers for every request.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("nuclei", {})
        self._severity: str = cfg.get("severity", "low,medium,high,critical")
        self._rate_limit: int = cfg.get("rate_limit", 150)
        self._timeout: int = cfg.get("timeout", 600)
        self._retries: int = cfg.get("retries", 1)
        self._templates: list[str] = cfg.get("templates", [])
        self._proxy: str | None = config.get("proxy")
        self._headers: dict[str, str] = config.get("headers", {})

    def run(self, urls: list[str]) -> list[NucleiFinding]:
        """
        Scan *urls* with nuclei.

        Args:
            urls: Target URLs (deduplicated before passing to nuclei).

        Returns:
            :class:`NucleiFinding` list sorted by severity (critical first).
        """
        if not urls:
            return []

        nuclei = _bin("nuclei")
        if not nuclei:
            logger.warning("nuclei_not_found", extra={"hint": "run --install-tools"})
            return []

        unique_urls = list(dict.fromkeys(u for u in urls if u.startswith("http")))
        if not unique_urls:
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(unique_urls))
            tmp_path = tmp.name

        findings: list[NucleiFinding] = []

        try:
            cmd = self._build_cmd(tmp_path)
            logger.info("nuclei_started", extra={
                "targets": len(unique_urls),
                "severity": self._severity,
            })
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )

            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                    findings.append(self._parse(rec))
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass

            if proc.returncode not in (0, 1):
                logger.warning("nuclei_exit", extra={
                    "code": proc.returncode,
                    "stderr": proc.stderr[:300],
                })

        except subprocess.TimeoutExpired:
            logger.warning("nuclei_timeout", extra={"timeout": self._timeout})
        except Exception as exc:
            logger.warning("nuclei_error", extra={"error": str(exc)})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        findings.sort(key=lambda f: _SEV_ORDER.get(f.severity.lower(), 0), reverse=True)
        logger.info("nuclei_done", extra={"findings": len(findings)})
        return findings

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_cmd(self, list_file: str) -> list[str]:
        nuclei = _bin("nuclei")
        cmd = [
            nuclei,
            "-l", list_file,
            "-json-export", "/dev/stdout",   # explicit JSONL to stdout
            "-silent",
            "-severity", self._severity,
            "-rate-limit", str(self._rate_limit),
            "-timeout", "10",
            "-retries", str(self._retries),
            "-no-color",
        ]

        if self._templates:
            for tmpl in self._templates:
                cmd += ["-t", tmpl]

        for key, value in self._headers.items():
            cmd += ["-H", f"{key}: {value}"]

        if self._proxy:
            cmd += ["-proxy", self._proxy]

        return cmd

    @staticmethod
    def _parse(rec: dict[str, Any]) -> NucleiFinding:
        info: dict[str, Any] = rec.get("info", {})
        tags_raw = info.get("tags", [])
        tags: list[str] = (
            tags_raw if isinstance(tags_raw, list)
            else [t.strip() for t in str(tags_raw).split(",") if t.strip()]
        )
        return NucleiFinding(
            template_id=rec.get("template-id", ""),
            name=info.get("name", rec.get("template-id", "unknown")),
            severity=info.get("severity", "info").lower(),
            host=rec.get("host", ""),
            matched_at=rec.get("matched-at", rec.get("host", "")),
            description=info.get("description", ""),
            tags=tags,
            raw=rec,
        )
