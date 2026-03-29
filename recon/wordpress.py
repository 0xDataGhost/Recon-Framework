"""
recon/wordpress.py — automated WordPress reconnaissance module.

Activated automatically when WordPress is detected in a host's tech stack.

Checks performed
----------------
  REST API          GET /wp-json/                        — version, routes, auth status
  User enumeration  GET /wp-json/wp/v2/users             — username/email/avatar leak
  Author redirect   GET /?author=1..10                   — fallback user enum via redirect
  Login page        GET /wp-login.php                    — exposed / captcha present
  XMLRPC            POST /xmlrpc.php (system.listMethods) — enabled / multicall possible
  Endpoints probe   HEAD on 5 known sensitive paths       — existence check
  Plugin detection  regex on homepage HTML                — /wp-content/plugins/<slug>/
  Theme detection   regex on homepage HTML                — /wp-content/themes/<slug>/
  WP version        homepage meta generator tag           — version leak

All requests are authorised-testing-only: read-only GET/HEAD/POST probes.
No exploitation, no credential stuffing, no write operations.
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Paths to probe for existence (HEAD requests)
_SENSITIVE_PATHS: list[dict[str, str]] = [
    {"path": "/wp-login.php",                 "label": "Login page",              "severity": "medium"},
    {"path": "/xmlrpc.php",                   "label": "XMLRPC endpoint",         "severity": "high"},
    {"path": "/wp-cron.php",                  "label": "WP-Cron exposed",         "severity": "low"},
    {"path": "/wp-config.php.bak",            "label": "Config backup file",      "severity": "critical"},
    {"path": "/wp-config.php~",               "label": "Config temp file",        "severity": "critical"},
    {"path": "/.git/HEAD",                    "label": "Git repository exposed",  "severity": "critical"},
    {"path": "/wp-content/debug.log",         "label": "Debug log exposed",       "severity": "medium"},
    {"path": "/wp-content/uploads/",          "label": "Uploads directory",       "severity": "low"},
    {"path": "/wp-includes/",                 "label": "Includes directory listing","severity": "low"},
    {"path": "/readme.html",                  "label": "Readme (version leak)",   "severity": "low"},
    {"path": "/license.txt",                  "label": "License (version leak)",  "severity": "info"},
    {"path": "/wp-json/wp/v2/users",          "label": "User REST API open",      "severity": "medium"},
    {"path": "/wp-json/wp/v2/posts?per_page=1","label": "Posts REST API open",    "severity": "info"},
    {"path": "/wp-json/",                     "label": "REST API root open",      "severity": "info"},
    {"path": "/wp-admin/",                    "label": "Admin panel accessible",  "severity": "medium"},
]

# Known plugins to probe for existence — sample of high-value targets
_KNOWN_PLUGINS: list[str] = [
    "contact-form-7",
    "woocommerce",
    "elementor",
    "yoast-seo",
    "wordfence",
    "all-in-one-wp-security-and-firewall",
    "wp-file-manager",
    "wp-super-cache",
    "w3-total-cache",
    "revslider",
    "gravityforms",
    "duplicator",
    "backup-buddy",
    "wp-db-backup",
    "wp-symposium",
    "simple-ads-manager",
    "mail-masta",
    "wp-ultimate-csv-importer",
]

# Regex patterns
_PLUGIN_RE  = re.compile(r'/wp-content/plugins/([a-zA-Z0-9_\-]+)/')
_THEME_RE   = re.compile(r'/wp-content/themes/([a-zA-Z0-9_\-]+)/')
_VERSION_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', re.I)
_AUTHOR_RE  = re.compile(r'/author/([a-zA-Z0-9_\-\.]+)/?', re.I)

# XMLRPC system.listMethods payload
_XMLRPC_PAYLOAD = (
    b'<?xml version="1.0"?>'
    b'<methodCall>'
    b'<methodName>system.listMethods</methodName>'
    b'<params></params>'
    b'</methodCall>'
)


# ── Data class ─────────────────────────────────────────────────────────────────

@dataclass
class WPFinding:
    check: str
    label: str
    severity: str
    url: str
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "label": self.label,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            **({k: v for k, v in self.data.items()} if self.data else {}),
        }


@dataclass
class WPResult:
    site_url: str
    wp_version: str = ""
    users: list[dict[str, Any]] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    themes: list[str] = field(default_factory=list)
    findings: list[WPFinding] = field(default_factory=list)
    rest_routes: list[str] = field(default_factory=list)
    xmlrpc_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_url": self.site_url,
            "wp_version": self.wp_version,
            "users": self.users,
            "plugins": self.plugins,
            "themes": self.themes,
            "xmlrpc_enabled": self.xmlrpc_enabled,
            "rest_routes": self.rest_routes,
            "findings": [f.to_dict() for f in self.findings],
        }


# ── Scanner ────────────────────────────────────────────────────────────────────

class WordPressScanner:
    """
    Perform read-only WordPress reconnaissance against a single URL.

    Args:
        config: Framework config. Relevant keys:
            wp_scanner.timeout (int, default 15): Per-request timeout (s).
            wp_scanner.probe_plugins (bool, default True): Probe known plugin paths.
            wp_scanner.max_author_ids (int, default 10): Author ID range to test.
            headers (dict): Extra HTTP headers (CF bypass headers injected by pipeline).
            proxy (str): Optional HTTP proxy.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("wp_scanner", {})
        self._timeout: int = cfg.get("timeout", 15)
        self._probe_plugins: bool = cfg.get("probe_plugins", True)
        self._max_author_ids: int = cfg.get("max_author_ids", 10)
        self._headers: dict[str, str] = {
            "User-Agent": _DEFAULT_UA,
            **config.get("headers", {}),
        }
        self._proxy: str | None = config.get("proxy")

        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self, site_url: str) -> WPResult:
        """
        Run all WordPress checks against *site_url*.

        Args:
            site_url: Full base URL, e.g. ``"https://example.com"``.

        Returns:
            Populated :class:`WPResult`.
        """
        base = site_url.rstrip("/")
        result = WPResult(site_url=base)

        logger.info("wp_scan_started", extra={"url": base})

        # Fetch homepage once — used for version, plugin, theme detection
        homepage = self._get(base + "/")
        if homepage:
            result.wp_version = self._detect_version(homepage)
            result.plugins = self._detect_plugins_from_html(homepage)
            result.themes = self._detect_themes_from_html(homepage)

        # Probe sensitive paths
        for path_info in _SENSITIVE_PATHS:
            self._probe_path(base, path_info, result)

        # REST API — route listing
        self._check_rest_api(base, result)

        # User enumeration — REST API
        self._enumerate_users_rest(base, result)

        # User enumeration — author ID redirect fallback
        if not result.users:
            self._enumerate_users_author(base, result)

        # XMLRPC
        self._check_xmlrpc(base, result)

        # Plugin path probing
        if self._probe_plugins:
            detected = set(result.plugins)
            for slug in _KNOWN_PLUGINS:
                if slug not in detected:
                    url = f"{base}/wp-content/plugins/{slug}/"
                    status = self._head_status(url)
                    if status in (200, 403):  # 403 = exists but listing disabled
                        result.plugins.append(slug)
                        result.findings.append(WPFinding(
                            check="plugin_probe",
                            label=f"Plugin detected: {slug}",
                            severity="low",
                            url=url,
                            detail=f"HTTP {status}",
                        ))

        result.plugins = sorted(set(result.plugins))
        result.themes = sorted(set(result.themes))

        logger.info("wp_scan_complete", extra={
            "url": base,
            "findings": len(result.findings),
            "users": len(result.users),
            "plugins": len(result.plugins),
        })
        return result

    # ── Check implementations ──────────────────────────────────────────────────

    def _probe_path(
        self,
        base: str,
        path_info: dict[str, str],
        result: WPResult,
    ) -> None:
        url = base + path_info["path"]
        status = self._head_status(url)
        if status and status not in (404, 410):
            result.findings.append(WPFinding(
                check="path_probe",
                label=path_info["label"],
                severity=path_info["severity"],
                url=url,
                detail=f"HTTP {status}",
            ))
            logger.debug("wp_path_found", extra={"url": url, "status": status})

    def _check_rest_api(self, base: str, result: WPResult) -> None:
        body = self._get(base + "/wp-json/")
        if not body:
            return
        try:
            data = json.loads(body)
            # Extract available route namespaces
            routes = list(data.get("routes", {}).keys())
            result.rest_routes = routes[:50]  # cap for readability
            name = data.get("name", "")
            description = data.get("description", "")
            gmt_offset = data.get("gmt_offset")
            result.findings.append(WPFinding(
                check="rest_api",
                label="WordPress REST API exposed",
                severity="info",
                url=base + "/wp-json/",
                detail=f"Site: {name} | Routes: {len(routes)}",
                data={"site_name": name, "description": description, "gmt_offset": gmt_offset},
            ))
        except (json.JSONDecodeError, AttributeError):
            pass

    def _enumerate_users_rest(self, base: str, result: WPResult) -> None:
        body = self._get(base + "/wp-json/wp/v2/users?per_page=100&context=embed")
        if not body:
            return
        try:
            users_raw = json.loads(body)
            if not isinstance(users_raw, list):
                return
            for u in users_raw:
                user = {
                    "id":          u.get("id"),
                    "username":    u.get("slug", ""),
                    "name":        u.get("name", ""),
                    "description": u.get("description", ""),
                    "avatar_url":  (u.get("avatar_urls") or {}).get("96", ""),
                    "link":        u.get("link", ""),
                }
                result.users.append(user)

            if result.users:
                usernames = [u["username"] for u in result.users]
                result.findings.append(WPFinding(
                    check="user_enum_rest",
                    label=f"User enumeration via REST API ({len(result.users)} users)",
                    severity="medium",
                    url=base + "/wp-json/wp/v2/users",
                    detail=", ".join(usernames[:10]),
                    data={"users": result.users},
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    def _enumerate_users_author(self, base: str, result: WPResult) -> None:
        """
        Probe /?author=N for N in 1..max_author_ids.

        WordPress redirects these to /author/<slug>/ revealing usernames.
        We follow the redirect manually to extract the slug without making
        the final page request.
        """
        found: list[dict[str, Any]] = []

        for author_id in range(1, self._max_author_ids + 1):
            url = f"{base}/?author={author_id}"
            location = self._head_redirect_location(url)
            if not location:
                continue
            m = _AUTHOR_RE.search(location)
            if m:
                slug = m.group(1)
                found.append({"id": author_id, "username": slug})
                logger.debug("wp_author_found", extra={"id": author_id, "slug": slug})

        if found:
            result.users.extend(found)
            result.findings.append(WPFinding(
                check="user_enum_author",
                label=f"User enumeration via author redirect ({len(found)} users)",
                severity="medium",
                url=base + "/?author=1",
                detail=", ".join(u["username"] for u in found),
                data={"users": found},
            ))

    def _check_xmlrpc(self, base: str, result: WPResult) -> None:
        url = base + "/xmlrpc.php"
        try:
            req = urllib.request.Request(
                url,
                data=_XMLRPC_PAYLOAD,
                headers={
                    **self._headers,
                    "Content-Type": "text/xml",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                if "methodResponse" in body or "system." in body:
                    result.xmlrpc_enabled = True
                    # Check if system.multicall is listed (amplification risk)
                    multicall_exposed = "system.multicall" in body
                    result.findings.append(WPFinding(
                        check="xmlrpc_enabled",
                        label="XMLRPC enabled" + (" (multicall exposed)" if multicall_exposed else ""),
                        severity="high" if multicall_exposed else "medium",
                        url=url,
                        detail="system.multicall available — brute force amplification possible" if multicall_exposed else "XMLRPC responds to system.listMethods",
                        data={"multicall": multicall_exposed},
                    ))
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass
        except Exception as exc:
            logger.debug("xmlrpc_check_error", extra={"url": url, "error": str(exc)})

    # ── Detection helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _detect_version(html: str) -> str:
        m = _VERSION_RE.search(html)
        return m.group(1) if m else ""

    @staticmethod
    def _detect_plugins_from_html(html: str) -> list[str]:
        return sorted(set(_PLUGIN_RE.findall(html)))

    @staticmethod
    def _detect_themes_from_html(html: str) -> list[str]:
        return sorted(set(_THEME_RE.findall(html)))

    # ── HTTP helpers ───────────────────────────────────────────────────────────

    def _get(self, url: str) -> str | None:
        """GET *url*, return body as str or None on error."""
        try:
            req = urllib.request.Request(url, headers=self._headers)
            if self._proxy:
                req.set_proxy(self._proxy, urllib.parse.urlparse(url).scheme)
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_ctx) as resp:
                return resp.read(512_000).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _head_status(self, url: str) -> int | None:
        """HEAD *url*, return HTTP status code or None."""
        try:
            req = urllib.request.Request(url, headers=self._headers, method="HEAD")
            if self._proxy:
                req.set_proxy(self._proxy, urllib.parse.urlparse(url).scheme)
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_ctx) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    def _head_redirect_location(self, url: str) -> str | None:
        """
        HEAD *url* without following redirects.

        Returns the ``Location`` header value if the response is a redirect,
        otherwise None.
        """
        try:
            # Disable automatic redirect following
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler.__new__(urllib.request.HTTPRedirectHandler)
            )

            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *_a: Any, **_kw: Any) -> None:  # type: ignore[override]
                    return None

            opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=self._ssl_ctx))
            req = urllib.request.Request(url, headers=self._headers, method="HEAD")
            with opener.open(req, timeout=self._timeout) as resp:
                return resp.headers.get("Location")
        except urllib.error.HTTPError as e:
            return e.headers.get("Location")
        except Exception:
            return None
