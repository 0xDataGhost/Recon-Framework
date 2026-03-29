"""
output/writer.py — write per-target scan results to flat files.

Directory layout
----------------
    output/<target>/
        subdomains.txt          one subdomain per line
        live_hosts.json         httpx records
        ports.json              host -> [port, ...]
        urls.txt                one URL per line
        js_files.txt            one JS URL per line
        nuclei_findings.json    nuclei records
        attack_plan.md          human-readable attack plan (if intel_report available)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class OutputWriter:
    """
    Write all scan artefacts for a single target to ``base_dir/<target>/``.

    Args:
        base_dir: Root output directory (e.g. ``Path("output")``).
    """

    def __init__(self, base_dir: Path) -> None:
        self._base = Path(base_dir)

    # ── Public API ─────────────────────────────────────────────────────────────

    def write(self, target: str, pipeline_result: Any, intel_report: Any) -> Path:
        """
        Serialise *pipeline_result* and *intel_report* to disk.

        Args:
            target:          Domain string.
            pipeline_result: A :class:`recon.pipeline.PipelineResult` instance.
            intel_report:    A :class:`intelligence.analyzer.IntelReport` instance,
                             or ``None`` if the intelligence pass was skipped/failed.

        Returns:
            The directory where files were written.
        """
        out_dir = self._base / target
        out_dir.mkdir(parents=True, exist_ok=True)

        self._write_lines(out_dir / "subdomains.txt", pipeline_result.subdomains)
        self._write_json(out_dir / "live_hosts.json", pipeline_result.live_hosts)
        self._write_json(out_dir / "ports.json", pipeline_result.ports)
        self._write_lines(out_dir / "urls.txt", pipeline_result.urls)
        self._write_lines(out_dir / "js_files.txt", pipeline_result.js_files)
        self._write_json(out_dir / "nuclei_findings.json", pipeline_result.nuclei_findings)

        if intel_report is not None:
            self._write_attack_plan(out_dir / "attack_plan.md", intel_report)

        logger.info(
            "output_written",
            extra={
                "target": target,
                "directory": str(out_dir),
                "subdomains": len(pipeline_result.subdomains),
                "live_hosts": len(pipeline_result.live_hosts),
            },
        )
        return out_dir

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _write_lines(path: Path, items: list[str]) -> None:
        path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _write_attack_plan(self, path: Path, intel_report: Any) -> None:
        """Render an attack_plan.md from the IntelReport."""
        lines: list[str] = []

        # Use the pre-built summary if available
        summary = getattr(intel_report, "summary", "")
        if summary:
            lines.append(summary)
        else:
            lines.append("# Attack Plan\n")

        # Top targets table
        top_targets: list[dict[str, Any]] = getattr(intel_report, "top_targets", [])
        if top_targets:
            lines.append("\n## Priority Targets\n")
            lines.append("| Host | Score | Ports | Technologies | Nuclei Findings |")
            lines.append("|------|-------|-------|--------------|-----------------|")
            for t in top_targets[:20]:
                ports_str = ", ".join(str(p) for p in t.get("open_ports", [])) or "—"
                tech_str = ", ".join(t.get("technologies", [])) or "—"
                nuclei_count = len(t.get("nuclei_findings", []))
                lines.append(
                    f"| `{t['host']}` | {t['score']} | {ports_str} | {tech_str} | {nuclei_count} |"
                )

        # Attack chains
        attack_chains: list[dict[str, Any]] = getattr(intel_report, "attack_chains", [])
        if attack_chains:
            lines.append("\n## Attack Chains\n")
            for chain in attack_chains:
                sev = chain.get("max_severity", "info").upper()
                lines.append(f"### {chain['host']} [{sev}]\n")
                lines.append(f"- **Findings:** {chain['finding_count']}")
                for ep in chain.get("entry_points", []):
                    lines.append(f"- Entry point: `{ep}`")
                for finding in chain.get("findings", [])[:5]:
                    info = finding.get("info", {})
                    name = info.get("name", finding.get("template-id", "unknown"))
                    matched = finding.get("matched-at", "")
                    lines.append(f"  - [{info.get('severity','info').upper()}] **{name}** @ `{matched}`")
                lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
