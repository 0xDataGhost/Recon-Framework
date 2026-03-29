from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from core.exceptions import CheckpointError

logger = logging.getLogger(__name__)


class CheckpointManager:
    """Manages per-scan stage checkpoints stored as JSON files on disk."""

    def __init__(self, checkpoint_dir: Path, scan_id: str) -> None:
        self.scan_id = scan_id
        self.checkpoint_dir = Path(checkpoint_dir) / scan_id
        try:
            self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CheckpointError(
                f"Cannot create checkpoint directory: {self.checkpoint_dir}",
                context={"scan_id": scan_id, "path": str(self.checkpoint_dir), "os_error": str(exc)},
            ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, stage: str, data: dict[str, Any]) -> None:
        """Write *data* as JSON to ``<checkpoint_dir>/<scan_id>/<stage>.json``."""
        path = self.checkpoint_dir / f"{stage}.json"
        try:
            path.write_text(json.dumps(data, default=str), encoding="utf-8")
        except OSError as exc:
            raise CheckpointError(
                f"Failed to write checkpoint for stage '{stage}'",
                context={"scan_id": self.scan_id, "stage": stage, "os_error": str(exc)},
            ) from exc

        if "target" in data:
            try:
                self.write_target_marker(data["target"])
            except CheckpointError:
                # Non-fatal; already logged inside write_target_marker
                pass

    def load(self, stage: str) -> dict[str, Any] | None:
        """Return the checkpoint data for *stage*, or ``None`` if it does not exist."""
        path = self.checkpoint_dir / f"{stage}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CheckpointError(
                f"Failed to read checkpoint for stage '{stage}'",
                context={"scan_id": self.scan_id, "stage": stage, "os_error": str(exc)},
            ) from exc

    def is_complete(self, stage: str) -> bool:
        """Return ``True`` if the checkpoint file for *stage* exists."""
        return (self.checkpoint_dir / f"{stage}.json").exists()

    def write_target_marker(self, target: str) -> None:
        """Write ``target.txt`` inside the checkpoint directory."""
        path = self.checkpoint_dir / "target.txt"
        try:
            path.write_text(target, encoding="utf-8")
        except OSError as exc:
            raise CheckpointError(
                "Failed to write target marker",
                context={"scan_id": self.scan_id, "target": target, "os_error": str(exc)},
            ) from exc
