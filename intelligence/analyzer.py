"""
intelligence/analyzer.py — post-pipeline analysis layer.

Receives a PipelineResult and produces an IntelReport with:
  - top_targets  : hosts ranked by attack surface
  - attack_chains: correlated finding sequences
  - summary      : human-readable markdown summary
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from core.exceptions import IntelligenceError

logger = logging.getLogger(__name__)

# Severity ordering for nuclei findings
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class IntelReport:
    top_targets: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


class IntelligenceAnalyzer:
    """
    Analyse a completed PipelineResult and produce an IntelReport.

    Args:
        config: Loaded framework config dict (unused for now, reserved for
                future API-key based enrichment modules).
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, result: Any) -> IntelReport:
        """
        Run all analysis passes and return an :class:`IntelReport`.

        Args:
            result: A :class:`recon.pipeline.PipelineResult` instance.
        """
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

    # ── Analysis passes ────────────────────────────────────────────────────────

    def _rank_targets(self, result: Any) -> list[dict[str, Any]]:
        """Score each live host by open ports, nuclei findings, and tech stack."""
        scores: dict[str, dict[str, Any]] = {}

        for host_rec in result.live_hosts:
            url = host_rec.get("url", host_rec.get("host", ""))
            host = url.split("://")[-1].split("/")[0]
            if not host:
                continue
            entry = scores.setdefault(host, {
                "host": host,
                "url": url,
                "score": 0,
                "open_ports": [],
                "technologies": [],
                "status_code": host_rec.get("status-code", host_rec.get("status_code")),
                "title": host_rec.get("title", ""),
                "nuclei_findings": [],
            })
            # score: each open port = +1
            entry["open_ports"] = result.ports.get(host, [])
            entry["score"] += len(entry["open_ports"])

            # tech stack
            tech = host_rec.get("tech", host_rec.get("technologies", []))
            if isinstance(tech, list):
                entry["technologies"] = tech
                entry["score"] += len(tech)

        # attach nuclei findings
        for finding in result.nuclei_findings:
            host = finding.get("host", "").split("://")[-1].split("/")[0]
            if host in scores:
                scores[host]["nuclei_findings"].append(finding)
                sev = finding.get("info", {}).get("severity", "info").lower()
                scores[host]["score"] += _SEV_RANK.get(sev, 0) * 3

        ranked = sorted(scores.values(), key=lambda x: x["score"], reverse=True)
        return ranked

    def _build_attack_chains(self, result: Any) -> list[dict[str, Any]]:
        """Correlate findings into potential attack chains."""
        chains: list[dict[str, Any]] = []

        # Group nuclei findings by host
        by_host: dict[str, list[dict[str, Any]]] = {}
        for f in result.nuclei_findings:
            host = f.get("host", "unknown")
            by_host.setdefault(host, []).append(f)

        for host, findings in by_host.items():
            if not findings:
                continue
            sorted_findings = sorted(
                findings,
                key=lambda x: _SEV_RANK.get(
                    x.get("info", {}).get("severity", "info").lower(), 0
                ),
                reverse=True,
            )
            chains.append({
                "host": host,
                "entry_points": [f.get("matched-at", host) for f in sorted_findings[:3]],
                "finding_count": len(findings),
                "max_severity": sorted_findings[0].get("info", {}).get("severity", "info"),
                "findings": sorted_findings,
            })

        # Sort chains by max severity
        chains.sort(
            key=lambda c: _SEV_RANK.get(c["max_severity"].lower(), 0),
            reverse=True,
        )
        return chains

    def _build_summary(
        self,
        result: Any,
        top_targets: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
    ) -> str:
        lines = [
            f"# Recon Summary — {result.target}",
            "",
            f"- **Subdomains found:** {len(result.subdomains)}",
            f"- **Live hosts:** {len(result.live_hosts)}",
            f"- **URLs collected:** {len(result.urls)}",
            f"- **JS files:** {len(result.js_files)}",
            f"- **Nuclei findings:** {len(result.nuclei_findings)}",
            f"- **Attack chains:** {len(attack_chains)}",
            "",
        ]

        if top_targets:
            lines.append("## Top Targets")
            for t in top_targets[:10]:
                lines.append(
                    f"- `{t['host']}` — score {t['score']}, "
                    f"ports: {t['open_ports'] or 'none'}, "
                    f"tech: {', '.join(t['technologies']) or 'unknown'}"
                )
            lines.append("")

        if attack_chains:
            lines.append("## Attack Chains")
            for chain in attack_chains[:5]:
                lines.append(
                    f"- **{chain['host']}** [{chain['max_severity'].upper()}] "
                    f"— {chain['finding_count']} finding(s)"
                )
            lines.append("")

        return "\n".join(lines)
