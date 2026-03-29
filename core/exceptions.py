"""
core/exceptions.py — structured exception hierarchy for the recon framework.

All exceptions carry three fields so they can be logged as JSON directly:
  error_code  machine-readable string constant (used for alerting rules)
  message     human-readable description
  context     optional dict with debugging data captured at the raise site

Usage
-----
    raise ToolExecutionError(
        tool_name="httpx",
        command=["httpx", "-l", "hosts.txt"],
        return_code=1,
        stderr="dial tcp: no such host",
    )

Logging
-------
    logger.error("tool_failed", extra=exc.to_dict())
"""

from __future__ import annotations

import json
from typing import Any


# ── Base ──────────────────────────────────────────────────────────────────────

class ReconBaseError(Exception):
    """
    Base class for all recon framework exceptions.

    Attributes:
        error_code: Machine-readable identifier. Override in every subclass.
        message:    Human-readable description of the failure.
        context:    Optional dict with structured debugging data.

    Example::

        try:
            run_scan(target)
        except ReconBaseError as exc:
            logger.error("scan_failed", extra=exc.to_dict())
    """

    error_code: str = "RECON_ERROR"

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        self.message = message
        self.context: dict[str, Any] = context or {}
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a JSON-serialisable dict suitable for passing to ``logger.error``
        via ``extra=``.

        Returns:
            Dict with keys: ``error_code``, ``error_type``, ``error_message``, ``context``.
            Note: the key is ``error_message`` (not ``message``) to avoid
            conflicting with the reserved ``message`` key in
            :class:`logging.LogRecord` when passed via ``extra=``.
        """
        return {
            "error_code": self.error_code,
            "error_type": type(self).__name__,
            "error_message": self.message,
            "context": self.context,
        }

    def __str__(self) -> str:
        ctx_part = f" | context={json.dumps(self.context)}" if self.context else ""
        return f"[{self.error_code}] {self.message}{ctx_part}"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"error_code={self.error_code!r}, "
            f"message={self.message!r}, "
            f"context={self.context!r})"
        )


# ── Tool management ───────────────────────────────────────────────────────────

class ToolNotAvailableError(ReconBaseError):
    """
    A required tool cannot be found on PATH and could not be installed.

    Args:
        tool_name: Name of the missing tool (e.g. ``"subfinder"``).
        reason:    Why the tool is unavailable.
        context:   Optional extra fields merged into the error context.

    Context fields: ``tool_name``, ``reason``.
    """

    error_code: str = "TOOL_NOT_AVAILABLE"

    def __init__(
        self,
        tool_name: str,
        reason: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        self.tool_name = tool_name
        ctx: dict[str, Any] = {"tool_name": tool_name, "reason": reason, **(context or {})}
        super().__init__(f"Tool '{tool_name}' is not available: {reason}", context=ctx)


class ToolInstallError(ReconBaseError):
    """
    Auto-installation of a tool was attempted but failed.

    Args:
        tool_name: Name of the tool that failed to install.
        reason:    Description of the install failure.
        context:   Optional extra fields merged into the error context.

    Context fields: ``tool_name``, ``reason``.
    """

    error_code: str = "TOOL_INSTALL_FAILED"

    def __init__(
        self,
        tool_name: str,
        reason: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        self.tool_name = tool_name
        ctx: dict[str, Any] = {"tool_name": tool_name, "reason": reason, **(context or {})}
        super().__init__(f"Failed to install '{tool_name}': {reason}", context=ctx)


class ToolExecutionError(ReconBaseError):
    """
    A tool subprocess exited with a non-zero return code or timed out.

    Stores the exact command so failures can be reproduced manually from
    ``context["command"]`` without re-running the scan.

    Args:
        tool_name:   Name of the tool that failed.
        command:     The command that was run (list or pre-joined string).
        return_code: The process exit code.
        stderr:      Stderr output (truncated to 500 chars in context).
        context:     Optional extra fields merged into the error context.

    Context fields: ``tool_name``, ``command``, ``return_code``, ``stderr_snippet``.
    """

    error_code: str = "TOOL_EXECUTION_FAILED"

    def __init__(
        self,
        tool_name: str,
        command: list[str] | str,
        return_code: int,
        stderr: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.command: str = command if isinstance(command, str) else " ".join(command)
        self.return_code = return_code
        self.stderr = stderr

        ctx: dict[str, Any] = {
            "tool_name": tool_name,
            "command": self.command,
            "return_code": return_code,
            "stderr_snippet": stderr[:500] if stderr else "",
            **(context or {}),
        }
        super().__init__(f"'{tool_name}' exited with code {return_code}", context=ctx)


# ── Pipeline ──────────────────────────────────────────────────────────────────

class PipelineStageError(ReconBaseError):
    """
    A recon pipeline stage failed unrecoverably.

    The ``stage`` field lets log aggregators group failures by stage without
    parsing free-text messages.

    Args:
        stage:   Name of the failed stage (e.g. ``"subdomain_enum"``).
        reason:  Description of the failure.
        context: Optional extra fields merged into the error context.

    Context fields: ``stage``, plus any extra fields passed via ``context``.
    """

    error_code: str = "PIPELINE_STAGE_ERROR"

    def __init__(
        self,
        stage: str,
        reason: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.stage = stage
        ctx: dict[str, Any] = {"stage": stage, **(context or {})}
        super().__init__(f"Stage '{stage}' failed: {reason}", context=ctx)


class ParsingError(ReconBaseError):
    """
    Failed to parse output produced by an external tool.

    Stores the first 300 characters of raw output so failures can be
    diagnosed from logs alone, without access to the original output file.

    Args:
        tool_name:  Name of the tool whose output could not be parsed.
        raw_output: The raw string output (truncated to 300 chars in context).
        reason:     Description of the parse failure.
        context:    Optional extra fields merged into the error context.

    Context fields: ``tool_name``, ``raw_output_snippet``, ``reason``.
    """

    error_code: str = "PARSE_ERROR"

    def __init__(
        self,
        tool_name: str,
        raw_output: str = "",
        reason: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        self.tool_name = tool_name
        self.raw_output_snippet: str = raw_output[:300]

        ctx: dict[str, Any] = {
            "tool_name": tool_name,
            "raw_output_snippet": self.raw_output_snippet,
            "reason": reason,
            **(context or {}),
        }
        super().__init__(f"Failed to parse output from '{tool_name}': {reason}", context=ctx)


# ── Intelligence layer ────────────────────────────────────────────────────────

class IntelligenceError(ReconBaseError):
    """
    An intelligence analysis sub-module encountered an error.

    Because all analyzers run in parallel, this exception is caught
    per-analyzer so a failure in one module does not affect the others.

    Args:
        analyzer: Name of the failed analyzer (e.g. ``"js_analyzer"``).
        reason:   Description of the failure.
        context:  Optional extra fields merged into the error context.

    Context fields: ``analyzer``, plus any extra fields passed via ``context``.

    Example::

        except requests.Timeout:
            raise IntelligenceError(
                analyzer="js_analyzer",
                reason=f"Timeout fetching {js_url}",
                context={"js_url": js_url, "timeout": 10},
            )
    """

    error_code: str = "INTELLIGENCE_ERROR"

    def __init__(
        self,
        analyzer: str,
        reason: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.analyzer = analyzer
        ctx: dict[str, Any] = {"analyzer": analyzer, **(context or {})}
        super().__init__(f"Analyzer '{analyzer}' failed: {reason}", context=ctx)


# ── Infrastructure ────────────────────────────────────────────────────────────

class ConfigError(ReconBaseError):
    """
    Configuration is missing required keys or contains invalid values.

    Args:
        message: Description of the configuration problem.
        context: Optional extra fields — include ``missing_keys`` or
                 ``invalid_value`` to make the error actionable.

    Example::

        raise ConfigError(
            "Missing required keys",
            context={"missing_keys": ["notifications.telegram.bot_token"]},
        )
    """

    error_code: str = "CONFIG_ERROR"


class DatabaseError(ReconBaseError):
    """
    A SQLite operation failed.

    Args:
        message: Description of the database failure.
        context: Optional extra fields — include ``table`` and
                 ``sqlite_error`` for easier diagnosis.

    Example::

        raise DatabaseError(
            "INSERT failed",
            context={"table": "subdomains", "sqlite_error": str(exc)},
        )
    """

    error_code: str = "DATABASE_ERROR"


class CheckpointError(ReconBaseError):
    """
    A checkpoint file could not be read or written.

    This is **non-fatal**: callers should log a WARNING and re-run the
    stage rather than aborting the scan.

    Args:
        message: Description of the checkpoint failure.
        context: Optional extra fields — include ``scan_id`` and ``stage``.
    """

    error_code: str = "CHECKPOINT_ERROR"


class NotificationError(ReconBaseError):
    """
    A notification could not be dispatched to a channel.

    This is **non-fatal**: the ``NotificationDispatcher`` daemon thread logs
    a WARNING and continues — notification failures never affect scan results.

    Args:
        message: Description of the dispatch failure.
        context: Optional extra fields — include ``channel`` and
                 ``http_status`` for Telegram/Discord failures.
    """

    error_code: str = "NOTIFICATION_ERROR"
