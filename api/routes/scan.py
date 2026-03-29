"""api/routes/scan.py — REST endpoints for scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, jsonify

OUTPUT_DIR = Path("output")

bp = Blueprint("scan", __name__, url_prefix="/api")


def _target_dirs() -> list[Path]:
    if not OUTPUT_DIR.exists():
        return []
    return sorted(
        [d for d in OUTPUT_DIR.iterdir() if d.is_dir()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )


def _load_target(target_dir: Path) -> dict[str, Any]:
    def read_lines(name: str) -> list[str]:
        p = target_dir / name
        if not p.exists():
            return []
        return [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def read_json(name: str) -> Any:
        p = target_dir / name
        if not p.exists():
            return []
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def read_text(name: str) -> str:
        p = target_dir / name
        return p.read_text(encoding="utf-8") if p.exists() else ""

    return {
        "target": target_dir.name,
        "subdomains": read_lines("subdomains.txt"),
        "live_hosts": read_json("live_hosts.json"),
        "ports": read_json("ports.json"),
        "urls": read_lines("urls.txt"),
        "js_files": read_lines("js_files.txt"),
        "nuclei_findings": read_json("nuclei_findings.json"),
        "attack_plan": read_text("attack_plan.md"),
    }


@bp.get("/targets")
def list_targets():
    targets = []
    for d in _target_dirs():
        data = _load_target(d)
        targets.append({
            "target": data["target"],
            "subdomains": len(data["subdomains"]),
            "live_hosts": len(data["live_hosts"]),
            "urls": len(data["urls"]),
            "nuclei_findings": len(data["nuclei_findings"]),
            "scanned_at": d.stat().st_mtime,
        })
    return jsonify(targets)


@bp.get("/target/<target>")
def get_target(target: str):
    target_dir = OUTPUT_DIR / target
    if not target_dir.is_dir():
        abort(404)
    return jsonify(_load_target(target_dir))


@bp.get("/target/<target>/attack_plan")
def get_attack_plan(target: str):
    p = OUTPUT_DIR / target / "attack_plan.md"
    if not p.exists():
        abort(404)
    return p.read_text(encoding="utf-8"), 200, {"Content-Type": "text/plain; charset=utf-8"}
