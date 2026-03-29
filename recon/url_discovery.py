"""
recon/url_discovery.py — multi-layer URL discovery with fallback and diagnostics.

Discovery layers (executed in order, each feeding into the next)
----------------------------------------------------------------
  Layer 1  passive_tools     gau + waybackurls via stdin (parallel)
  Layer 2  robots_sitemap    robots.txt → Sitemap: directives + /sitemap.xml
                              Recursive sitemap index traversal
  Layer 3  homepage          Fetch live host homepages, extract <a href>,
                              <form action>, <script src> and <link href>
  Layer 4  js_endpoints      Fetch discovered JS files, extract URL paths
                              via regex (fetch/axios/relative paths)
  Layer 5  aggressive        HEAD-probe a curated list of common paths
                              WordPress-specific paths added when WP detected

Cloudflare / WAF bypass
-----------------------
  - 20-UA rotation pool (real Chrome/Firefox/Safari/Edge strings)
  - Full browser fingerprint headers (Sec-CH-UA, Sec-Fetch-*, Referer)
  - Per-request random delay (configurable min/max)
  - Retry with fresh UA on 403 / 429 / connection errors
  - Optional HTTP proxy

Diagnostics
-----------
  Every layer logs its contribution:
      layer_passive_tools   gau=12  waybackurls=8   total=18
      layer_robots_sitemap  new=47  total=65
      layer_homepage        new=23  total=88
      layer_js_endpoints    new=11  total=99
      layer_aggressive      new=5   total=104
  If total remains 0 after all layers, a final diagnostic summary
  is logged at WARNING level listing exactly which steps produced
  nothing and why.
"""

from __future__ import annotations

import logging
import random
import re
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FALLBACK_BIN = Path.home() / ".local" / "bin"

# ── User-Agent rotation pool ───────────────────────────────────────────────────

_USER_AGENTS: list[str] = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    # Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    # Googlebot (some sites whitelist crawlers)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    # Bingbot
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# ── Noise filter — extensions that add zero attack surface ────────────────────

_NOISE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".webm", ".ogg", ".avi", ".mov",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
    ".css",
})

# ── Common paths for aggressive discovery ────────────────────────────────────

_COMMON_PATHS: list[str] = [
    # Auth / sessions
    "/login", "/logout", "/signin", "/signout", "/register", "/signup",
    "/forgot-password", "/reset-password", "/auth", "/oauth",
    # Admin surfaces
    "/admin", "/admin/login", "/administrator", "/dashboard", "/panel",
    "/console", "/manage", "/management", "/cp", "/controlpanel",
    # API / docs
    "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rpc",
    "/graphql", "/graphiql", "/playground",
    "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/docs",
    # Debug / monitoring
    "/health", "/healthz", "/status", "/version", "/info", "/ping",
    "/metrics", "/actuator", "/actuator/env", "/actuator/health",
    "/debug", "/.env", "/config",
    # Common files
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    "/humans.txt", "/ads.txt", "/app-ads.txt",
    # Framework leaks
    "/phpinfo.php", "/info.php", "/test.php",
    "/trace.axd", "/elmah.axd",
    "/_debugbar/", "/telescope", "/horizon",
    "/server-status", "/server-info",
    # Upload / file serving
    "/upload", "/uploads", "/files", "/static", "/assets", "/media",
    "/download", "/downloads",
    # Source / git
    "/.git/HEAD", "/.git/config",
    "/.svn/entries", "/.hg/hgrc",
]

_WP_SPECIFIC_PATHS: list[str] = [
    "/wp-json/", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages", "/wp-json/wp/v2/media",
    "/wp-login.php", "/wp-admin/", "/wp-admin/admin-ajax.php",
    "/xmlrpc.php", "/wp-cron.php",
    "/wp-content/plugins/", "/wp-content/themes/",
    "/wp-content/uploads/", "/wp-content/debug.log",
    "/wp-includes/", "/wp-config.php.bak", "/readme.html",
]

# ── Regex for HTML and JS parsing ─────────────────────────────────────────────

_HREF_RE   = re.compile(r'href=["\']([^"\'#\s]+)["\']',   re.I)
_ACTION_RE = re.compile(r'action=["\']([^"\'#\s]+)["\']', re.I)
_SRC_RE    = re.compile(r'src=["\']([^"\'#\s]+\.js[^"\']*)["\']', re.I)
_SITEMAP_LOC_RE = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.I)
_SITEMAP_DIRECTIVE_RE = re.compile(r'^Sitemap:\s*(.+)$', re.I | re.M)
_DISALLOW_RE = re.compile(r'^(?:Disallow|Allow):\s*(\S+)', re.I | re.M)

# JS endpoint extraction (path-focused, not secret-focused)
_JS_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'["\`](/(?:api|v\d+|rest|graphql|admin|auth|oauth|login|internal|private|public)[^"\'`<>\s\[\]]{0,120})["\`]'),
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["\`]([^"\'`\s]{4,120})["\`]'),
    re.compile(r'url\s*[:=]\s*["\`]([^"\'`\s]{4,120})["\`]'),
    re.compile(r'path\s*[:=]\s*["\`](/[^"\'`\s]{2,80})["\`]'),
]


# ── HTTP helper ────────────────────────────────────────────────────────────────

class _HTTPSession:
    """
    Stateless HTTP helper with UA rotation, realistic headers, retry, and delay.

    Args:
        timeout:       Per-request timeout in seconds.
        retries:       How many times to retry on 403/429/network errors.
        delay_range:   (min, max) seconds to sleep between requests.
        proxy:         Optional HTTP/HTTPS proxy URL.
        extra_headers: Additional headers merged into every request.
    """

    def __init__(
        self,
        timeout: int = 12,
        retries: int = 2,
        delay_range: tuple[float, float] = (0.5, 1.5),
        proxy: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._timeout = timeout
        self._retries = retries
        self._delay_min, self._delay_max = delay_range
        self._proxy = proxy
        self._extra = extra_headers or {}

        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def get(self, url: str, *, method: str = "GET") -> tuple[int, str]:
        """
        Fetch *url* with a random UA and browser-fingerprint headers.

        Returns:
            ``(status_code, body_text)`` — body is empty string on error.
        """
        last_exc: Exception | None = None

        for attempt in range(self._retries + 1):
            if attempt > 0:
                sleep = random.uniform(self._delay_min * 2, self._delay_max * 2)
                time.sleep(sleep)

            ua = random.choice(_USER_AGENTS)
            headers = self._build_headers(ua, url)

            try:
                req = urllib.request.Request(url, headers=headers, method=method)
                if self._proxy:
                    parsed = urllib.parse.urlparse(url)
                    req.set_proxy(self._proxy, parsed.scheme)

                with urllib.request.urlopen(
                    req, timeout=self._timeout, context=self._ssl_ctx
                ) as resp:
                    body = resp.read(1_048_576).decode("utf-8", errors="replace")
                    return resp.status, body

            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429) and attempt < self._retries:
                    logger.debug("http_retry", extra={
                        "url": url, "status": exc.code, "attempt": attempt + 1,
                    })
                    last_exc = exc
                    continue
                return exc.code, ""

            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last_exc = exc
                continue

            finally:
                delay = random.uniform(self._delay_min, self._delay_max)
                time.sleep(delay)

        logger.debug("http_failed", extra={"url": url, "error": str(last_exc)})
        return 0, ""

    def head_status(self, url: str) -> int:
        """Return HTTP status for a HEAD request, 0 on network error."""
        status, _ = self.get(url, method="HEAD")
        return status

    def _build_headers(self, ua: str, url: str) -> dict[str, str]:
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        is_chrome = "Chrome" in ua and "Edg" not in ua and "OPR" not in ua
        is_firefox = "Firefox" in ua

        headers: dict[str, str] = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

        if is_chrome:
            # Chrome-specific security headers
            headers.update({
                "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            })
        elif is_firefox:
            headers.update({
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            })

        headers.update(self._extra)
        return headers


# ── Discovery result ───────────────────────────────────────────────────────────

@dataclass
class _LayerResult:
    name: str
    new_urls: int
    total_after: int
    tool_status: dict[str, str] = field(default_factory=dict)   # tool → "ok"/"timeout"/"missing"
    notes: list[str] = field(default_factory=list)


@dataclass
class URLDiscoveryResult:
    urls: list[str] = field(default_factory=list)
    layers: list[_LayerResult] = field(default_factory=list)

    def diagnostic_summary(self) -> str:
        """Return a human-readable summary of each layer's contribution."""
        lines = ["URL Discovery Summary:"]
        for lr in self.layers:
            status_parts = [f"{k}={v}" for k, v in lr.tool_status.items()]
            status_str = f"  [{', '.join(status_parts)}]" if status_parts else ""
            lines.append(
                f"  {lr.name:<25} +{lr.new_urls:<6} total={lr.total_after}{status_str}"
            )
            for note in lr.notes:
                lines.append(f"    ↳ {note}")
        if not self.urls:
            lines.append("  ⚠  All layers returned 0 URLs — target may be heavily filtered")
            lines.append("     Suggestion: try --proxy or verify the target is reachable")
        return "\n".join(lines)


# ── Main class ────────────────────────────────────────────────────────────────

class URLDiscovery:
    """
    Multi-layer URL discovery for a single target domain.

    Args:
        config: Framework config. Relevant keys:
            url_collection.timeout (int, 180):      Tool subprocess timeout.
            url_collection.threads (int, 5):        gau threads.
            url_collection.delay_min (float, 0.3):  Min delay between HTTP reqs.
            url_collection.delay_max (float, 1.0):  Max delay between HTTP reqs.
            url_collection.aggressive (bool, True): Enable layer 5 path probing.
            url_collection.max_sitemap_urls (int, 500): Cap on sitemap URLs.
            url_collection.max_js_files (int, 20):  Cap on JS files to fetch.
            headers (dict):  Extra headers merged into all requests.
            proxy (str):     HTTP/HTTPS proxy URL.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("url_collection", {})
        self._tool_timeout: int = cfg.get("timeout", 180)
        self._gau_threads: int = cfg.get("threads", 5)
        self._aggressive: bool = cfg.get("aggressive", True)
        self._max_sitemap_urls: int = cfg.get("max_sitemap_urls", 500)
        self._max_js_files: int = cfg.get("max_js_files", 20)

        self._http = _HTTPSession(
            timeout=cfg.get("http_timeout", 12),
            retries=cfg.get("retries", 2),
            delay_range=(cfg.get("delay_min", 0.3), cfg.get("delay_max", 1.0)),
            proxy=config.get("proxy"),
            extra_headers=config.get("headers", {}),
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        live_hosts: list[dict[str, Any]] | None = None,
    ) -> list[str]:
        """
        Run all discovery layers and return deduplicated, filtered URLs.

        Args:
            target:     Root domain (e.g. ``"example.com"``).
            live_hosts: httpx records — used to determine base URLs and
                        detect technologies (e.g. WordPress) for layer 5.
        """
        live_hosts = live_hosts or []
        base_urls = self._extract_base_urls(target, live_hosts)
        is_wordpress = self._detect_wordpress(live_hosts)

        accumulated: set[str] = set()
        layer_log: list[_LayerResult] = []

        # ── Layer 1: passive tools ─────────────────────────────────────────────
        layer_log.append(
            self._layer_passive_tools(target, accumulated)
        )

        # ── Layer 2: robots.txt + sitemap ─────────────────────────────────────
        layer_log.append(
            self._layer_robots_sitemap(base_urls, accumulated)
        )

        # ── Layer 3: homepage HTML parsing ────────────────────────────────────
        layer_log.append(
            self._layer_homepage(base_urls, accumulated)
        )

        # ── Layer 4: JS endpoint extraction ───────────────────────────────────
        layer_log.append(
            self._layer_js_endpoints(base_urls, accumulated)
        )

        # ── Layer 5: aggressive path discovery ────────────────────────────────
        if self._aggressive:
            layer_log.append(
                self._layer_aggressive(base_urls, accumulated, is_wordpress)
            )

        result = URLDiscoveryResult(
            urls=self._filter_and_sort(accumulated),
            layers=layer_log,
        )

        # Log full diagnostic summary at INFO level
        logger.info("url_discovery_complete", extra={
            "target": target,
            "total": len(result.urls),
        })
        for line in result.diagnostic_summary().splitlines():
            if "⚠" in line:
                logger.warning(line)
            else:
                logger.info(line)

        return result.urls

    # ── Layer 1: passive tools ─────────────────────────────────────────────────

    def _layer_passive_tools(
        self, target: str, acc: set[str]
    ) -> _LayerResult:
        before = len(acc)
        tool_status: dict[str, str] = {}

        def run_gau() -> tuple[str, list[str]]:
            gau = self._bin("gau")
            if not gau:
                return "missing", []
            try:
                proc = subprocess.run(
                    [gau, "--subs", "--threads", str(self._gau_threads)],
                    input=target,
                    capture_output=True,
                    text=True,
                    timeout=self._tool_timeout,
                )
                urls = [l.strip() for l in proc.stdout.splitlines() if l.strip().startswith("http")]
                return "ok" if urls else "empty", urls
            except subprocess.TimeoutExpired:
                return "timeout", []
            except Exception as exc:
                return f"error:{exc}", []

        def run_wayback() -> tuple[str, list[str]]:
            wb = self._bin("waybackurls")
            if not wb:
                return "missing", []
            try:
                proc = subprocess.run(
                    [wb],
                    input=target,
                    capture_output=True,
                    text=True,
                    timeout=self._tool_timeout,
                )
                urls = [l.strip() for l in proc.stdout.splitlines() if l.strip().startswith("http")]
                return "ok" if urls else "empty", urls
            except subprocess.TimeoutExpired:
                return "timeout", []
            except Exception as exc:
                return f"error:{exc}", []

        with ThreadPoolExecutor(max_workers=2) as pool:
            gau_fut = pool.submit(run_gau)
            wb_fut  = pool.submit(run_wayback)
            gau_status, gau_urls   = gau_fut.result()
            wb_status,  wb_urls    = wb_fut.result()

        tool_status["gau"] = f"{gau_status}({len(gau_urls)})"
        tool_status["waybackurls"] = f"{wb_status}({len(wb_urls)})"

        acc.update(u for u in gau_urls  if u.startswith("http"))
        acc.update(u for u in wb_urls   if u.startswith("http"))

        return _LayerResult("passive_tools", len(acc) - before, len(acc), tool_status)

    # ── Layer 2: robots.txt + sitemap ─────────────────────────────────────────

    def _layer_robots_sitemap(
        self, base_urls: list[str], acc: set[str]
    ) -> _LayerResult:
        before = len(acc)
        notes: list[str] = []
        sitemap_urls_to_check: set[str] = set()

        for base in base_urls:
            # Fetch robots.txt
            status, body = self._http.get(f"{base}/robots.txt")
            if status == 200 and body:
                # Extract disallowed/allowed paths from robots.txt
                for m in _DISALLOW_RE.finditer(body):
                    path = m.group(1).strip()
                    if path and path != "/" and not path.startswith("*"):
                        full = urllib.parse.urljoin(base + "/", path.lstrip("/"))
                        acc.add(full)

                # Extract Sitemap: directives
                for m in _SITEMAP_DIRECTIVE_RE.finditer(body):
                    sm_url = m.group(1).strip()
                    if sm_url.startswith("http"):
                        sitemap_urls_to_check.add(sm_url)
                        notes.append(f"Found sitemap in robots.txt: {sm_url}")

            # Default sitemap paths
            for sm_path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt",
                            "/wp-sitemap.xml", "/news-sitemap.xml"):
                sitemap_urls_to_check.add(base + sm_path)

        # Parse sitemaps recursively
        visited_sitemaps: set[str] = set()
        sm_queue = list(sitemap_urls_to_check)
        depth = 0

        while sm_queue and depth < 4 and len(acc) < self._max_sitemap_urls + before:
            depth += 1
            next_queue: list[str] = []
            for sm_url in sm_queue:
                if sm_url in visited_sitemaps:
                    continue
                visited_sitemaps.add(sm_url)

                status, body = self._http.get(sm_url)
                if status != 200 or not body.strip():
                    continue

                extracted = self._parse_sitemap(body)
                page_urls: list[str] = []
                child_sitemaps: list[str] = []

                for url in extracted:
                    if url.endswith(".xml") or "sitemap" in url.lower():
                        child_sitemaps.append(url)
                    else:
                        page_urls.append(url)

                acc.update(page_urls)
                next_queue.extend(child_sitemaps)

                if page_urls:
                    notes.append(f"sitemap {sm_url} → {len(page_urls)} URLs")

            sm_queue = next_queue

        return _LayerResult("robots_sitemap", len(acc) - before, len(acc), notes=notes)

    # ── Layer 3: homepage HTML ─────────────────────────────────────────────────

    def _layer_homepage(
        self, base_urls: list[str], acc: set[str]
    ) -> _LayerResult:
        before = len(acc)
        notes: list[str] = []

        for base in base_urls:
            status, html = self._http.get(base + "/")
            if status not in (200, 301, 302, 403) or not html:
                notes.append(f"{base}/ → HTTP {status}")
                continue

            count_before = len(acc)
            acc.update(self._extract_html_links(html, base))
            added = len(acc) - count_before
            if added:
                notes.append(f"{base}/ → +{added} links from HTML")

        return _LayerResult("homepage", len(acc) - before, len(acc), notes=notes)

    # ── Layer 4: JS endpoint extraction ───────────────────────────────────────

    def _layer_js_endpoints(
        self, base_urls: list[str], acc: set[str]
    ) -> _LayerResult:
        before = len(acc)
        notes: list[str] = []

        # Collect JS URLs from what we already know + script tags on homepage
        js_candidate_urls: set[str] = set()

        for base in base_urls:
            _, html = self._http.get(base + "/")
            if html:
                for m in _SRC_RE.finditer(html):
                    src = m.group(1)
                    full = urllib.parse.urljoin(base + "/", src)
                    if full.startswith("http"):
                        js_candidate_urls.add(full)

        # Also grab .js URLs already in acc
        js_from_acc = {u for u in acc if u.split("?")[0].endswith(".js")}
        js_candidate_urls.update(js_from_acc)

        fetched = 0
        for js_url in list(js_candidate_urls)[:self._max_js_files]:
            _, content = self._http.get(js_url)
            if not content:
                continue
            fetched += 1
            extracted = self._extract_js_paths(js_url, content, base_urls)
            acc.update(extracted)

        if fetched:
            notes.append(f"Fetched {fetched} JS files")

        return _LayerResult("js_endpoints", len(acc) - before, len(acc), notes=notes)

    # ── Layer 5: aggressive path discovery ────────────────────────────────────

    def _layer_aggressive(
        self,
        base_urls: list[str],
        acc: set[str],
        is_wordpress: bool,
    ) -> _LayerResult:
        before = len(acc)
        notes: list[str] = []
        paths = list(_COMMON_PATHS)

        if is_wordpress:
            paths.extend(_WP_SPECIFIC_PATHS)
            notes.append("WordPress detected — added WP-specific paths")

        confirmed: list[str] = []

        # Probe all paths across all base URLs with HEAD requests
        probe_tasks: list[tuple[str, str]] = [
            (base, path) for base in base_urls for path in paths
        ]

        def probe(task: tuple[str, str]) -> str | None:
            base, path = task
            url = base.rstrip("/") + path
            if url in acc:
                return None   # already known
            status = self._http.head_status(url)
            if status and status not in (404, 410, 0):
                return url
            return None

        # Use a thread pool to parallelise HEAD requests (still rate-limited by _HTTPSession)
        with ThreadPoolExecutor(max_workers=8) as pool:
            for url in pool.map(probe, probe_tasks):
                if url:
                    confirmed.append(url)
                    acc.add(url)

        if confirmed:
            notes.append(f"Confirmed {len(confirmed)} paths via HEAD probe")

        return _LayerResult("aggressive", len(acc) - before, len(acc), notes=notes)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _extract_html_links(self, html: str, base: str) -> list[str]:
        urls: list[str] = []
        for pattern in (_HREF_RE, _ACTION_RE):
            for m in pattern.finditer(html):
                href = m.group(1).strip()
                if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue
                full = urllib.parse.urljoin(base + "/", href)
                if full.startswith("http"):
                    urls.append(full)
        return urls

    def _extract_js_paths(
        self, js_url: str, content: str, base_urls: list[str]
    ) -> list[str]:
        found: list[str] = []
        base = base_urls[0] if base_urls else ""

        for pattern in _JS_PATH_PATTERNS:
            for m in pattern.finditer(content):
                path = m.group(1).strip()
                if not path or len(path) < 3:
                    continue
                if path.startswith("http"):
                    found.append(path)
                elif path.startswith("/") and base:
                    found.append(base.rstrip("/") + path)

        return found

    @staticmethod
    def _parse_sitemap(body: str) -> list[str]:
        """Extract <loc> URLs from an XML sitemap body."""
        # Try XML parser first, fall back to regex
        try:
            root = ET.fromstring(body)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            locs = [el.text.strip() for el in root.findall(".//sm:loc", ns) if el.text]
            if locs:
                return locs
        except ET.ParseError:
            pass
        # Regex fallback (handles malformed XML)
        return [m.group(1) for m in _SITEMAP_LOC_RE.finditer(body) if m.group(1)]

    @staticmethod
    def _extract_base_urls(
        target: str, live_hosts: list[dict[str, Any]]
    ) -> list[str]:
        """Build the list of base URLs to use for direct HTTP requests."""
        bases: list[str] = []
        for h in live_hosts:
            url = h.get("url", "").rstrip("/")
            if url:
                bases.append(url)

        # If no live hosts (httpx not run yet), fall back to https/http on the root domain
        if not bases:
            bases = [f"https://{target}", f"http://{target}"]

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for b in bases:
            if b not in seen:
                seen.add(b)
                unique.append(b)
        return unique

    @staticmethod
    def _detect_wordpress(live_hosts: list[dict[str, Any]]) -> bool:
        for h in live_hosts:
            tech = h.get("tech") or h.get("technologies") or []
            for t in tech:
                name = (t if isinstance(t, str) else t.get("name", "")).lower()
                if "wordpress" in name:
                    return True
        return False

    @staticmethod
    def _filter_and_sort(urls: set[str]) -> list[str]:
        result: list[str] = []
        for url in urls:
            if not url.startswith("http"):
                continue
            path = url.split("?")[0].lower()
            if any(path.endswith(ext) for ext in _NOISE_EXTENSIONS):
                continue
            result.append(url)
        return sorted(set(result))

    @staticmethod
    def _bin(name: str) -> str | None:
        p = shutil.which(name)
        if p:
            return p
        fb = _FALLBACK_BIN / name
        return str(fb) if fb.is_file() else None
