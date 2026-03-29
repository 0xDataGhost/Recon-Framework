"""
intelligence/analyzer.py — post-pipeline analysis layer.

Takes a PipelineResult and produces an IntelReport containing:
  - top_targets    : hosts scored and ranked by attack surface breadth
  - attack_chains  : correlated finding sequences per host
  - attack_vectors : tech/port-based attack surface suggestions per host
  - summary        : markdown summary for the attack_plan.md report
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from core.exceptions import IntelligenceError
from intelligence.attack_vectors import suggest

logger = logging.getLogger(__name__)

_SEV_SCORE = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


@dataclass
class IntelReport:
    top_targets: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


class IntelligenceAnalyzer:
    """
    Analyse a :class:`recon.pipeline.PipelineResult` and produce an
    :class:`IntelReport`.

    Args:
        config: Framework config (reserved for future enrichment modules).
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    def analyze(self, result: Any) -> IntelReport:
        try:
            top_targets = self._rank_targets(result)
            attack_chains = self._build_attack_chains(result)
            summary = self._build_summary(result, top_targets, attack_chains)
            return IntelReport(
                top_targets=top_targets,
                attack_chains=attack_chains,
                summary=summary,
            )
        except Exception as exc:
            raise IntelligenceError(
                analyzer="core",
                reason=str(exc),
                context={"target": getattr(result, "target", "unknown")},
            ) from exc

    # ── Ranking ────────────────────────────────────────────────────────────────

    def _rank_targets(self, result: Any) -> list[dict[str, Any]]:
        """Score each live host by open ports, nuclei findings, JS secrets, and tech stack."""
        hosts: dict[str, dict[str, Any]] = {}

        for rec in result.live_hosts:
            host = self._extract_host(rec)
            if not host:
                continue

            tech: list[str] = (
                rec.get("tech")
                or rec.get("technologies")
                or []
            )
            if isinstance(tech, list):
                tech = [t.split(":")[0] for t in tech]   # strip version info

            entry = hosts.setdefault(host, {
                "host": host,
                "url": rec.get("url", f"https://{host}"),
                "status_code": rec.get("status-code") or rec.get("status_code"),
                "title": rec.get("title", ""),
                "technologies": tech,
                "open_ports": [],
                "nuclei_findings": [],
                "js_findings": [],
                "attack_vectors": [],
                "score": 0,
            })

            # Base score for being alive
            entry["score"] += 1
            entry["score"] += len(tech)

        # Attach port data
        for host, port_list in result.ports.items():
            if host in hosts:
                hosts[host]["open_ports"] = sorted(port_list)
                hosts[host]["score"] += len(port_list)

        # Attach nuclei findings
        for finding in result.nuclei_findings:
            host = self._extract_host_from_str(finding.get("host", ""))
            if host in hosts:
                hosts[host]["nuclei_findings"].append(finding)
                sev = finding.get("severity", "info").lower()
                hosts[host]["score"] += _SEV_SCORE.get(sev, 0)

        # Attach JS findings
        for finding in result.js_findings:
            js_host = self._extract_host_from_str(finding.get("js_url", ""))
            # Associate with the closest matching live host
            matched = self._best_host_match(js_host, list(hosts.keys()))
            if matched:
                hosts[matched]["js_findings"].append(finding)
                sev = finding.get("severity", "info").lower()
                hosts[matched]["score"] += _SEV_SCORE.get(sev, 0)

        # Attach WordPress findings to relevant hosts
        for wp in getattr(result, "wp_findings", []):
            wp_host = self._extract_host_from_str(wp.get("site_url", ""))
            if wp_host in hosts:
                hosts[wp_host]["wp_result"] = wp
                # Score boost: user enum = +5, xmlrpc = +3, per plugin = +1
                hosts[wp_host]["score"] += len(wp.get("users", [])) * 5
                hosts[wp_host]["score"] += 3 if wp.get("xmlrpc_enabled") else 0
                hosts[wp_host]["score"] += len(wp.get("plugins", []))
                for f in wp.get("findings", []):
                    sev = f.get("severity", "info").lower()
                    hosts[wp_host]["score"] += _SEV_SCORE.get(sev, 0)

        # Attach suggested attack vectors
        for entry in hosts.values():
            entry["attack_vectors"] = suggest(
                technologies=entry["technologies"],
                open_ports=entry["open_ports"],
            )
            # Critical attack vector = bonus score
            critical_count = sum(
                1 for v in entry["attack_vectors"] if v["severity"] == "critical"
            )
            entry["score"] += critical_count * 5

        ranked = sorted(hosts.values(), key=lambda x: x["score"], reverse=True)
        return ranked

    # ── Attack chains ──────────────────────────────────────────────────────────

    def _build_attack_chains(self, result: Any) -> list[dict[str, Any]]:
        """
        Build per-host attack chains from nuclei + JS findings.

        A chain is: initial recon surface → confirmed vulnerability →
        potential impact. Each host produces at most one chain entry.
        """
        chains: dict[str, dict[str, Any]] = {}

        # Nuclei-based chains
        for f in result.nuclei_findings:
            host = self._extract_host_from_str(f.get("host", ""))
            if not host:
                continue
            chain = chains.setdefault(host, {
                "host": host,
                "steps": [],
                "max_severity": "info",
                "finding_count": 0,
            })
            sev = f.get("severity", "info").lower()
            chain["steps"].append({
                "type": "nuclei",
                "name": f.get("name", f.get("template_id", "?")),
                "severity": sev,
                "matched_at": f.get("matched_at", ""),
            })
            chain["finding_count"] += 1
            if _SEV_SCORE.get(sev, 0) > _SEV_SCORE.get(chain["max_severity"], 0):
                chain["max_severity"] = sev

        # JS-based chains
        for f in result.js_findings:
            js_host = self._extract_host_from_str(f.get("js_url", ""))
            host = self._best_host_match(
                js_host,
                list(chains.keys()) or [self._extract_host_from_str(h.get("url", "")) for h in result.live_hosts],
            ) or js_host
            if not host:
                continue
            chain = chains.setdefault(host, {
                "host": host,
                "steps": [],
                "max_severity": "info",
                "finding_count": 0,
            })
            sev = f.get("severity", "info").lower()
            if sev in ("high", "medium"):   # only include meaningful JS findings
                chain["steps"].append({
                    "type": "js_secret",
                    "name": f.get("type", "secret"),
                    "severity": sev,
                    "matched_at": f.get("js_url", ""),
                })
                chain["finding_count"] += 1
                if _SEV_SCORE.get(sev, 0) > _SEV_SCORE.get(chain["max_severity"], 0):
                    chain["max_severity"] = sev

        result_chains = [c for c in chains.values() if c["finding_count"] > 0]
        result_chains.sort(
            key=lambda c: _SEV_SCORE.get(c["max_severity"], 0),
            reverse=True,
        )
        return result_chains

    # ── Summary ────────────────────────────────────────────────────────────────

    def _build_summary(
        self,
        result: Any,
        top_targets: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
    ) -> str:
        all_urls_count = len(getattr(result, "all_urls", result.urls))
        high_js = [f for f in result.js_findings if f.get("severity") in ("high", "critical")]
        total_vectors = sum(len(t.get("attack_vectors", [])) for t in top_targets)
        wp_findings = getattr(result, "wp_findings", [])
        wp_hosts = len(wp_findings)
        wp_users = sum(len(w.get("users", [])) for w in wp_findings)
        wp_plugins = sum(len(w.get("plugins", [])) for w in wp_findings)

        lines: list[str] = [
            f"# Recon Report — {result.target}",
            "",
            "## Statistics",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Subdomains | {len(result.subdomains)} |",
            f"| Live hosts | {len(result.live_hosts)} |",
            f"| Passive URLs (gau/waybackurls) | {len(result.urls)} |",
            f"| Crawled URLs (katana) | {len(result.crawled_urls)} |",
            f"| Total unique URLs | {all_urls_count} |",
            f"| JS files analysed | {len(result.js_files)} |",
            f"| JS findings (secrets/endpoints) | {len(result.js_findings)} |",
            f"| High/critical JS findings | {len(high_js)} |",
            f"| Nuclei findings | {len(result.nuclei_findings)} |",
            f"| Attack vectors identified | {total_vectors} |",
            f"| Attack chains | {len(attack_chains)} |",
        ]
        if wp_hosts:
            lines += [
                f"| WordPress sites scanned | {wp_hosts} |",
                f"| WP users enumerated | {wp_users} |",
                f"| WP plugins detected | {wp_plugins} |",
            ]
        lines += ["", ""]

        if top_targets:
            lines += [
                "## Top Targets (by score)",
                "",
                "| # | Host | Score | Ports | Technologies | Findings |",
                "|---|------|-------|-------|--------------|----------|",
            ]
            for i, t in enumerate(top_targets[:15], 1):
                ports_str = ", ".join(str(p) for p in t["open_ports"][:8]) or "—"
                tech_str = ", ".join(t["technologies"][:4]) or "—"
                findings = len(t["nuclei_findings"]) + len(t["js_findings"])
                lines.append(
                    f"| {i} | `{t['host']}` | {t['score']} | {ports_str} | {tech_str} | {findings} |"
                )
            lines.append("")

        if attack_chains:
            lines += ["## Attack Chains", ""]
            for chain in attack_chains[:8]:
                sev_badge = chain["max_severity"].upper()
                lines.append(f"### `{chain['host']}` [{sev_badge}] — {chain['finding_count']} finding(s)")
                lines.append("")
                for step in chain["steps"][:5]:
                    sev = step["severity"].upper()
                    lines.append(
                        f"- [{sev}] **{step['name']}** ({step['type']}) → `{step['matched_at']}`"
                    )
                lines.append("")

        if high_js:
            lines += ["## High-Severity JavaScript Findings", ""]
            for f in high_js[:10]:
                lines.append(
                    f"- **{f.get('type', '?')}** in `{f.get('js_url', '?')}`: "
                    f"`{str(f.get('match', ''))[:80]}`"
                )
            lines.append("")

        # Attack vector suggestions from the top 5 hosts
        shown_vectors: set[str] = set()
        vector_lines: list[str] = []
        for t in top_targets[:5]:
            for v in t.get("attack_vectors", []):
                if v["severity"] in ("critical", "high") and v["vector"] not in shown_vectors:
                    shown_vectors.add(v["vector"])
                    src = f"port {v['port']}" if v.get("port") else v.get("technology", "")
                    path = f" → `{v['path']}`" if v.get("path") else ""
                    vector_lines.append(
                        f"- [{v['severity'].upper()}] **{v['vector']}** ({src}){path}"
                    )

        if vector_lines:
            lines += ["## Suggested Attack Vectors (critical/high)", ""]
            lines += vector_lines[:20]
            lines.append("")

        return "\n".join(lines)

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_host(rec: dict[str, Any]) -> str:
        raw = rec.get("host") or rec.get("url", "")
        return raw.split("://")[-1].split("/")[0].split(":")[0]

    @staticmethod
    def _extract_host_from_str(s: str) -> str:
        return s.split("://")[-1].split("/")[0].split(":")[0]

    @staticmethod
    def _best_host_match(needle: str, haystack: list[str]) -> str | None:
        """Return the haystack entry that is a suffix-match for needle, or None."""
        if not needle:
            return None
        if needle in haystack:
            return needle
        for h in haystack:
            if needle.endswith(h) or h.endswith(needle):
                return h
        return None
