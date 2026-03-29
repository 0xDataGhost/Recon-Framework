"""
recon/js_analyzer.py — extract secrets and endpoints from JavaScript files.

Detection patterns
------------------
  High severity:
    AWS keys, Stripe/Twilio/SendGrid keys, generic API keys, private keys,
    hardcoded passwords, Google API keys

  Medium severity:
    Firebase URLs, JWT tokens, internal IPs, S3 bucket references

  Info:
    API endpoint paths, relative fetch() / axios calls, GraphQL queries

JS files are downloaded with a browser User-Agent, TLS verification disabled
(common for self-signed internal certs), and capped at a configurable size
to avoid processing huge minified bundles that time out.
"""

from __future__ import annotations

import logging
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# ── Detection patterns ─────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str, str]] = [
    # (name, regex, severity)
    ("aws_access_key",    r"AKIA[0-9A-Z]{16}",                                    "high"),
    ("aws_secret_key",    r'(?i)aws.{0,20}(?:secret|key).{0,10}["\']([A-Za-z0-9/+]{40})["\']', "high"),
    ("google_api_key",    r"AIza[0-9A-Za-z\-_]{35}",                             "high"),
    ("firebase_url",      r"https://[a-z0-9\-]+\.firebaseio\.com",               "medium"),
    ("firebase_config",   r'(?i)firebaseConfig\s*=\s*\{[^}]+\}',                 "medium"),
    ("stripe_key",        r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",           "high"),
    ("twilio_key",        r"SK[0-9a-fA-F]{32}",                                   "high"),
    ("sendgrid_key",      r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",        "high"),
    ("mailgun_key",       r"key-[0-9a-zA-Z]{32}",                                 "high"),
    ("jwt_token",         r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_._+/=]*", "medium"),
    ("private_key",       r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",       "high"),
    ("generic_api_key",   r'(?i)(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token)["\s]*[:=]["\s]*["\']([a-zA-Z0-9\-_.]{20,})["\']', "high"),
    ("generic_secret",    r'(?i)(?:secret|password|passwd|pwd)["\s]*[:=]["\s]*["\']([^"\']{8,})["\']', "high"),
    ("bearer_token",      r'(?i)bearer\s+([a-zA-Z0-9\-_.]{20,})',                 "medium"),
    ("internal_ip",       r"(?:192\.168\.|10\.\d{1,3}\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}", "medium"),
    ("s3_bucket",         r"(?:https?://)?([a-z0-9\-\.]+)\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com", "medium"),
    ("api_path",          r'["\`](/(?:api|v\d+|graphql|rest|admin|auth|login|oauth|internal|private)[^\s"\'`<>\[\]]{0,120})["\`]', "info"),
    ("fetch_call",        r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["\`]([^"\'`]+)["\`]', "info"),
    ("graphql_query",     r'(?:gql|graphql)\s*`[^`]{10,}query\s+\w+',            "info"),
    ("ws_endpoint",       r'(?:new WebSocket|io\.connect)\s*\(\s*["\']([^"\']+)["\']', "info"),
    ("source_map",        r'//[#@]\s*sourceMappingURL=(.+\.map)',                  "info"),
]

_COMPILED: list[tuple[str, re.Pattern[str], str]] = [
    (name, re.compile(pat, re.MULTILINE), sev)
    for name, pat, sev in _PATTERNS
]


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class JSFinding:
    js_url: str
    finding_type: str
    match: str
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "js_url": self.js_url,
            "type": self.finding_type,
            "match": self.match[:300],
            "severity": self.severity,
        }


# ── Analyzer ──────────────────────────────────────────────────────────────────

class JSAnalyzer:
    """
    Download JS files and scan their content for secrets and endpoints.

    Args:
        config: Framework config. Relevant keys under ``js_analysis``:
            timeout (int, default 15):        Per-file fetch timeout (s).
            max_size_kb (int, default 4096):  Skip files larger than this.
            max_files (int, default 100):     Cap on number of files to fetch.
        config["headers"] (dict):  Extra headers merged over defaults.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("js_analysis", {})
        self._timeout: int = cfg.get("timeout", 15)
        self._max_bytes: int = cfg.get("max_size_kb", 4096) * 1024
        self._max_files: int = cfg.get("max_files", 100)
        self._headers: dict[str, str] = {
            "User-Agent": _DEFAULT_UA,
            "Accept": "*/*",
            "Referer": "",
            **config.get("headers", {}),
        }
        # Shared SSL context — skip verification for self-signed/internal certs
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def analyze(self, js_urls: list[str]) -> list[JSFinding]:
        """
        Fetch and scan each JS URL.

        Args:
            js_urls: List of JavaScript file URLs.

        Returns:
            List of :class:`JSFinding` objects, highest severity first.
        """
        findings: list[JSFinding] = []
        processed = 0

        for url in dict.fromkeys(js_urls):  # deduplicate, preserve order
            if processed >= self._max_files:
                logger.info("js_max_files_reached", extra={"limit": self._max_files})
                break

            content = self._fetch(url)
            processed += 1

            if content:
                batch = self._scan(url, content)
                findings.extend(batch)
                if batch:
                    logger.debug("js_findings", extra={"url": url, "count": len(batch)})

        _SEV = {"high": 3, "medium": 2, "info": 1}
        findings.sort(key=lambda f: _SEV.get(f.severity, 0), reverse=True)

        logger.info("js_analysis_done", extra={
            "files": processed,
            "findings": len(findings),
        })
        return findings

    # ── Private helpers ────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> str | None:
        try:
            req = urllib.request.Request(url, headers=self._headers)
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_ctx) as resp:
                ct = resp.headers.get("Content-Type", "")
                # Skip if server serves HTML (redirected to error page, etc.)
                if "text/html" in ct and "javascript" not in ct:
                    return None
                raw = resp.read(self._max_bytes)
                return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
            return None
        except Exception as exc:
            logger.debug("js_fetch_error", extra={"url": url, "error": str(exc)})
            return None

    @staticmethod
    def _scan(url: str, content: str) -> list[JSFinding]:
        findings: list[JSFinding] = []
        seen: set[str] = set()

        for name, pattern, severity in _COMPILED:
            for m in pattern.finditer(content):
                value = m.group(1) if m.lastindex else m.group(0)
                value = value.strip()
                if not value:
                    continue
                dedup_key = f"{name}:{value[:80]}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(JSFinding(
                    js_url=url,
                    finding_type=name,
                    match=value,
                    severity=severity,
                ))

        return findings
