"""
output/writer.py — serialise scan results to organised flat files.

Directory layout
----------------
    output/<target>/
        subdomains.txt          one per line
        live_hosts.json         httpx records
        ports.json              {host: [port, ...]}
        urls.txt                passive URLs (gau / waybackurls)
        crawled_urls.txt        active URLs (katana)
        all_urls.txt            union of passive + crawled, deduplicated
        js_files.txt            JS file URLs
        js_findings.json        secrets and endpoints extracted from JS
        nuclei_findings.json    nuclei vulnerability records
        attack_plan.md          full markdown report with scoring + vectors
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class OutputWriter:
    """
    Write all scan artefacts for a single target.

    Args:
        base_dir: Root output directory (e.g. ``Path("output")``).
    """

    def __init__(self, base_dir: Path) -> None:
        self._base = Path(base_dir)

    def write(self, target: str, pipeline_result: Any, intel_report: Any) -> Path:
        """
        Serialise *pipeline_result* and *intel_report* to ``base_dir/<target>/``.

        Args:
            target:          Domain string.
            pipeline_result: :class:`recon.pipeline.PipelineResult`.
            intel_report:    :class:`intelligence.analyzer.IntelReport` or ``None``.

        Returns:
            Directory path where all files were written.
        """
        out = self._base / target
        out.mkdir(parents=True, exist_ok=True)

        r = pipeline_result

        self._lines(out / "subdomains.txt",      r.subdomains)
        self._json(out / "live_hosts.json",       r.live_hosts)
        self._json(out / "ports.json",            r.ports)
        self._lines(out / "urls.txt",             r.urls)
        self._lines(out / "crawled_urls.txt",     r.crawled_urls)
        self._lines(out / "all_urls.txt",         r.all_urls)
        self._lines(out / "js_files.txt",         r.js_files)
        self._json(out / "js_findings.json",        r.js_findings)
        self._json(out / "nuclei_findings.json",    r.nuclei_findings)
        self._json(out / "wordpress_findings.json", r.wp_findings)

        if r.wp_findings:
            self._wp_summary(out / "wordpress_report.md", r.wp_findings)

        if intel_report is not None:
            self._attack_plan(out / "attack_plan.md", r, intel_report)

        logger.info("output_written", extra={
            "target": target,
            "dir": str(out),
            "subdomains": len(r.subdomains),
            "live_hosts": len(r.live_hosts),
            "all_urls": len(r.all_urls),
            "js_findings": len(r.js_findings),
            "nuclei_findings": len(r.nuclei_findings),
            "wp_findings": len(r.wp_findings),
        })
        return out

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _lines(path: Path, items: list[str]) -> None:
        path.write_text(
            "\n".join(items) + ("\n" if items else ""),
            encoding="utf-8",
        )

    @staticmethod
    def _json(path: Path, data: Any) -> None:
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def _wp_summary(path: Path, wp_findings: list[dict[str, Any]]) -> None:
        """Write a dedicated wordpress_report.md with per-site findings."""
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        lines: list[str] = ["# WordPress Reconnaissance Report", ""]

        for wp in wp_findings:
            url = wp.get("site_url", "?")
            version = wp.get("wp_version", "")
            lines += [f"## {url}", ""]

            if version:
                lines.append(f"**WordPress Version:** `{version}`  ")
            lines.append(f"**XMLRPC Enabled:** {'Yes ⚠️' if wp.get('xmlrpc_enabled') else 'No'}  ")
            lines.append("")

            # Users
            users = wp.get("users", [])
            if users:
                lines += ["### Enumerated Users", ""]
                lines += ["| ID | Username | Display Name |", "|---|---|---|"]
                for u in users:
                    lines.append(f"| {u.get('id','?')} | `{u.get('username','?')}` | {u.get('name','')} |")
                lines.append("")

            # Plugins
            plugins = wp.get("plugins", [])
            if plugins:
                lines.append(f"### Detected Plugins ({len(plugins)})")
                lines.append("")
                for p in plugins:
                    lines.append(f"- `{p}`")
                lines.append("")

            # Themes
            themes = wp.get("themes", [])
            if themes:
                lines.append(f"### Detected Themes ({len(themes)})")
                lines.append("")
                for t in themes:
                    lines.append(f"- `{t}`")
                lines.append("")

            # REST routes
            routes = wp.get("rest_routes", [])
            if routes:
                lines.append(f"### REST API Routes ({len(routes)} namespaces)")
                lines.append("")
                for r_path in routes[:20]:
                    lines.append(f"- `{r_path}`")
                if len(routes) > 20:
                    lines.append(f"- … and {len(routes) - 20} more")
                lines.append("")

            # Findings table
            findings = wp.get("findings", [])
            if findings:
                lines += ["### Security Findings", ""]
                lines += ["| Severity | Check | Detail | URL |", "|---|---|---|---|"]
                for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","info"),5)):
                    icon = sev_emoji.get(f.get("severity","info"), "")
                    sev = f.get("severity","info").upper()
                    lines.append(
                        f"| {icon} {sev} | {f.get('label','?')} | {f.get('detail','')} | `{f.get('url','')}` |"
                    )
                lines.append("")

            lines.append("---\n")

        path.write_text("\n".join(lines), encoding="utf-8")

    def _attack_plan(
        self, path: Path, r: Any, report: Any
    ) -> None:
        lines: list[str] = []

        # Pre-built summary from the analyzer
        if getattr(report, "summary", ""):
            lines.append(report.summary)
        else:
            lines.append(f"# Attack Plan — {r.target}\n")

        # ── Per-target detailed section ────────────────────────────────────────
        top: list[dict[str, Any]] = getattr(report, "top_targets", [])
        if top:
            lines += ["\n---\n", "## Detailed Target Analysis\n"]
            for t in top[:10]:
                lines += self._target_section(t)

        path.write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _target_section(t: dict[str, Any]) -> list[str]:
        """Render a per-host section with ports, tech, findings, and vectors."""
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

        lines: list[str] = [
            f"### `{t['host']}` (score: {t['score']})",
            "",
        ]

        status = t.get("status_code")
        title = t.get("title", "")
        url = t.get("url", "")
        if url:
            lines.append(f"**URL:** {url}  ")
        if status:
            lines.append(f"**Status:** {status}  ")
        if title:
            lines.append(f"**Title:** {title}  ")
        lines.append("")

        tech = t.get("technologies", [])
        if tech:
            lines.append(f"**Technologies:** {', '.join(tech)}")
            lines.append("")

        ports = t.get("open_ports", [])
        if ports:
            lines.append(f"**Open Ports:** {', '.join(str(p) for p in ports)}")
            lines.append("")

        vectors: list[dict[str, Any]] = t.get("attack_vectors", [])
        crit_high = [v for v in vectors if v["severity"] in ("critical", "high")]
        if crit_high:
            lines.append("**Attack Surface (critical/high):**")
            for v in crit_high[:8]:
                icon = sev_emoji.get(v["severity"], "")
                path_str = f" → `{v['path']}`" if v.get("path") else ""
                src = f"port {v['port']}" if v.get("port") else v.get("technology", "")
                lines.append(f"- {icon} [{v['severity'].upper()}] {v['vector']} ({src}){path_str}")
            lines.append("")

        nuclei: list[dict[str, Any]] = t.get("nuclei_findings", [])
        if nuclei:
            lines.append("**Nuclei Findings:**")
            for f in nuclei[:5]:
                sev = f.get("severity", "info")
                icon = sev_emoji.get(sev, "")
                lines.append(
                    f"- {icon} [{sev.upper()}] **{f.get('name', '?')}** "
                    f"→ `{f.get('matched_at', '')}`"
                )
            lines.append("")

        js_findings: list[dict[str, Any]] = t.get("js_findings", [])
        high_js = [f for f in js_findings if f.get("severity") in ("high", "critical")]
        if high_js:
            lines.append("**High-Severity JS Findings:**")
            for f in high_js[:5]:
                icon = sev_emoji.get(f.get("severity", "info"), "")
                lines.append(
                    f"- {icon} **{f.get('type', '?')}** in `{f.get('js_url', '?')}`"
                )
            lines.append("")

        lines.append("---\n")
        return lines
