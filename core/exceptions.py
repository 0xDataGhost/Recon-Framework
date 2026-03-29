"""
Custom exception hierarchy for the recon framework.

All exceptions carry structured data (error_code, context) so they can be
logged as JSON directly without string parsing.
"""

from __future__ import annotations

import json
from typing import Any


class ReconBaseError(Exception):
    """
    Base for all recon framework exceptions.

    Attributes:
        error_code  -- machine-readable identifier (e.g. "TOOL_NOT_FOUND")
        message     -- human-readable description
        context     -- optional dict with extra debugging data
    """

    error_code: str = "RECON_ERROR"

    def __init__(self, message: str, context: dict[str, Any] | None = None):
        self.message = message
        self.context: dict[str, Any] = context or {}
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict — pass directly to loggers."""
        return {
            "error_code": self.error_code,
            "error_type": type(self).__name__,
            "message": self.message,
            "context": self.context,
        }

    def __str__(self) -> str:
        ctx = f" | context={json.dumps(self.context)}" if self.context else ""
        return f"[{self.error_code}] {self.message}{ctx}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(error_code={self.error_code!r}, message={self.message!r}, context={self.context!r})"


# ──────────────────────────────────────────────
# Tool management
# ──────────────────────────────────────────────

class ToolNotAvailableError(ReconBaseError):
    """A required tool cannot be found on PATH and could not be installed."""

    error_code = "TOOL_NOT_AVAILABLE"

    def __init__(self, tool_name: str, reason: str = "", context: dict[str, Any] | None = None):
        self.tool_name = tool_name
        ctx = {"tool_name": tool_name, "reason": reason, **(context or {})}
        super().__init__(f"Tool '{tool_name}' is not available: {reason}", context=ctx)


class ToolInstallError(ReconBaseError):
    """Auto-installation of a tool failed."""

    error_code = "TOOL_INSTALL_FAILED"

    def __init__(self, tool_name: str, reason: str = "", context: dict[str, Any] | None = None):
        self.tool_name = tool_name
        ctx = {"tool_name": tool_name, "reason": reason, **(context or {})}
        super().__init__(f"Failed to install '{tool_name}': {reason}", context=ctx)


class ToolExecutionError(ReconBaseError):
    """
    A tool subprocess exited with a non-zero return code or timed out.

    Captures the full command, return code and stderr so failures can be
    reproduced manually without re-running the scan.
    """

    error_code = "TOOL_EXECUTION_FAILED"

    def __init__(
        self,
        tool_name: str,
        command: list[str] | str,
        return_code: int,
        stderr: str = "",
        context: dict[str, Any] | None = None,
    ):
        self.tool_name = tool_name
        self.command = command if isinstance(command, str) else " ".join(command)
        self.return_code = return_code
        self.stderr = stderr

        ctx = {
            "tool_name": tool_name,
            "command": self.command,
            "return_code": return_code,
            "stderr_snippet": stderr[:500] if stderr else "",
            **(context or {}),
        }
        super().__init__(
            f"'{tool_name}' exited with code {return_code}",
            context=ctx,
        )


# ──────────────────────────────────────────────
# Pipeline
# ──────────────────────────────────────────────

class PipelineStageError(ReconBaseError):
    """
    A recon pipeline stage failed.

    Includes the stage name so log aggregators can group failures by stage
    without parsing free-text messages.
    """

    error_code = "PIPELINE_STAGE_ERROR"

    def __init__(
        self,
        stage: str,
        reason: str,
        context: dict[str, Any] | None = None,
    ):
        self.stage = stage
        ctx = {"stage": stage, **(context or {})}
        super().__init__(f"Stage '{stage}' failed: {reason}", context=ctx)


class ParsingError(ReconBaseError):
    """
    Failed to parse output from a tool.

    Stores the tool name and the first 300 characters of raw output so the
    cause can be diagnosed from logs alone.
    """

    error_code = "PARSE_ERROR"

    def __init__(
        self,
        tool_name: str,
        raw_output: str = "",
        reason: str = "",
        context: dict[str, Any] | None = None,
    ):
        self.tool_name = tool_name
        self.raw_output_snippet = raw_output[:300]

        ctx = {
            "tool_name": tool_name,
            "raw_output_snippet": self.raw_output_snippet,
            "reason": reason,
            **(context or {}),
        }
        super().__init__(
            f"Failed to parse output from '{tool_name}': {reason}",
            context=ctx,
        )


# ──────────────────────────────────────────────
# Intelligence layer
# ──────────────────────────────────────────────

class IntelligenceError(ReconBaseError):
    """
    An intelligence analysis sub-module encountered an error.

    Includes the analyzer name so failures can be isolated without affecting
    other parallel analyzers.
    """

    error_code = "INTELLIGENCE_ERROR"

    def __init__(
        self,
        analyzer: str,
        reason: str,
        context: dict[str, Any] | None = None,
    ):
        self.analyzer = analyzer
        ctx = {"analyzer": analyzer, **(context or {})}
        super().__init__(f"Analyzer '{analyzer}' failed: {reason}", context=ctx)


# ──────────────────────────────────────────────
# Infrastructure
# ──────────────────────────────────────────────

class ConfigError(ReconBaseError):
    """Configuration is missing required keys or has invalid values."""
    error_code = "CONFIG_ERROR"


class DatabaseError(ReconBaseError):
    """A SQLite operation failed."""
    error_code = "DATABASE_ERROR"


class CheckpointError(ReconBaseError):
    """Checkpoint read/write failed (non-fatal — scan will re-run the stage)."""
    error_code = "CHECKPOINT_ERROR"


class NotificationError(ReconBaseError):
    """A notification could not be dispatched (non-fatal, logged only)."""
    error_code = "NOTIFICATION_ERROR"
