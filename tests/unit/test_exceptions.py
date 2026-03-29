"""
Unit tests for core/exceptions.py.

These tests cover every exception class: constructor arguments, to_dict()
output, __str__ formatting, __repr__ formatting, and error_code values.
They run without any external dependencies and serve as a regression guard
for the exception contract that the rest of the codebase relies on.
"""

from __future__ import annotations

import json

import pytest

from core.exceptions import (
    CheckpointError,
    ConfigError,
    DatabaseError,
    IntelligenceError,
    NotificationError,
    ParsingError,
    PipelineStageError,
    ReconBaseError,
    ToolExecutionError,
    ToolInstallError,
    ToolNotAvailableError,
)


# ── ReconBaseError ────────────────────────────────────────────────────────────

class TestReconBaseError:
    def test_message_stored(self) -> None:
        e = ReconBaseError("something failed")
        assert e.message == "something failed"

    def test_context_defaults_to_empty_dict(self) -> None:
        e = ReconBaseError("msg")
        assert e.context == {}

    def test_context_stored(self) -> None:
        e = ReconBaseError("msg", context={"key": "value"})
        assert e.context == {"key": "value"}

    def test_to_dict_structure(self) -> None:
        e = ReconBaseError("msg", context={"a": 1})
        d = e.to_dict()
        assert d["error_code"] == "RECON_ERROR"
        assert d["error_type"] == "ReconBaseError"
        assert d["message"] == "msg"
        assert d["context"] == {"a": 1}

    def test_to_dict_is_json_serialisable(self) -> None:
        e = ReconBaseError("msg", context={"nested": {"x": [1, 2, 3]}})
        # Should not raise
        serialised = json.dumps(e.to_dict())
        assert "RECON_ERROR" in serialised

    def test_str_without_context(self) -> None:
        e = ReconBaseError("plain message")
        assert str(e) == "[RECON_ERROR] plain message"

    def test_str_with_context(self) -> None:
        e = ReconBaseError("plain message", context={"target": "example.com"})
        s = str(e)
        assert "[RECON_ERROR]" in s
        assert "plain message" in s
        assert "example.com" in s

    def test_repr_contains_key_fields(self) -> None:
        e = ReconBaseError("msg", context={"k": "v"})
        r = repr(e)
        assert "ReconBaseError" in r
        assert "RECON_ERROR" in r
        assert "msg" in r

    def test_is_exception_subclass(self) -> None:
        e = ReconBaseError("msg")
        assert isinstance(e, Exception)

    def test_error_code_class_attribute(self) -> None:
        assert ReconBaseError.error_code == "RECON_ERROR"


# ── ToolNotAvailableError ─────────────────────────────────────────────────────

class TestToolNotAvailableError:
    def test_error_code(self) -> None:
        assert ToolNotAvailableError.error_code == "TOOL_NOT_AVAILABLE"

    def test_tool_name_stored(self) -> None:
        e = ToolNotAvailableError("subfinder", "Go not installed")
        assert e.tool_name == "subfinder"

    def test_context_contains_tool_name_and_reason(self) -> None:
        e = ToolNotAvailableError("subfinder", "Go not installed")
        assert e.context["tool_name"] == "subfinder"
        assert e.context["reason"] == "Go not installed"

    def test_message_includes_tool_name(self) -> None:
        e = ToolNotAvailableError("subfinder", "Go not installed")
        assert "subfinder" in e.message

    def test_extra_context_merged(self) -> None:
        e = ToolNotAvailableError("naabu", "binary missing", context={"os": "linux"})
        assert e.context["os"] == "linux"
        assert e.context["tool_name"] == "naabu"

    def test_is_recon_base_error(self) -> None:
        e = ToolNotAvailableError("x", "y")
        assert isinstance(e, ReconBaseError)


# ── ToolInstallError ──────────────────────────────────────────────────────────

class TestToolInstallError:
    def test_error_code(self) -> None:
        assert ToolInstallError.error_code == "TOOL_INSTALL_FAILED"

    def test_tool_name_stored(self) -> None:
        e = ToolInstallError("nuclei", "go install failed")
        assert e.tool_name == "nuclei"

    def test_context_fields(self) -> None:
        e = ToolInstallError("nuclei", "go install failed")
        assert e.context["tool_name"] == "nuclei"
        assert e.context["reason"] == "go install failed"


# ── ToolExecutionError ────────────────────────────────────────────────────────

class TestToolExecutionError:
    def test_error_code(self) -> None:
        assert ToolExecutionError.error_code == "TOOL_EXECUTION_FAILED"

    def test_command_list_joined_to_string(self) -> None:
        e = ToolExecutionError("httpx", ["httpx", "-l", "hosts.txt"], 1, "")
        assert e.command == "httpx -l hosts.txt"

    def test_command_string_passed_through(self) -> None:
        e = ToolExecutionError("httpx", "httpx -l hosts.txt", 1, "")
        assert e.command == "httpx -l hosts.txt"

    def test_return_code_stored(self) -> None:
        e = ToolExecutionError("httpx", "cmd", 42, "")
        assert e.return_code == 42

    def test_stderr_stored(self) -> None:
        e = ToolExecutionError("httpx", "cmd", 1, "connection refused")
        assert e.stderr == "connection refused"

    def test_stderr_truncated_to_500_in_context(self) -> None:
        long_stderr = "x" * 600
        e = ToolExecutionError("httpx", "cmd", 1, long_stderr)
        assert len(e.context["stderr_snippet"]) == 500

    def test_context_contains_all_fields(self) -> None:
        e = ToolExecutionError("naabu", ["naabu", "-host", "x.com"], 2, "err")
        assert e.context["tool_name"] == "naabu"
        assert e.context["command"] == "naabu -host x.com"
        assert e.context["return_code"] == 2
        assert e.context["stderr_snippet"] == "err"

    def test_message_contains_tool_and_code(self) -> None:
        e = ToolExecutionError("httpx", "cmd", 1, "")
        assert "httpx" in e.message
        assert "1" in e.message

    def test_empty_stderr_gives_empty_snippet(self) -> None:
        e = ToolExecutionError("httpx", "cmd", 1)
        assert e.context["stderr_snippet"] == ""


# ── PipelineStageError ────────────────────────────────────────────────────────

class TestPipelineStageError:
    def test_error_code(self) -> None:
        assert PipelineStageError.error_code == "PIPELINE_STAGE_ERROR"

    def test_stage_stored(self) -> None:
        e = PipelineStageError("subdomain_enum", "both tools returned empty")
        assert e.stage == "subdomain_enum"

    def test_stage_in_context(self) -> None:
        e = PipelineStageError("live_hosts", "httpx timed out")
        assert e.context["stage"] == "live_hosts"

    def test_message_contains_stage_and_reason(self) -> None:
        e = PipelineStageError("port_scan", "naabu failed")
        assert "port_scan" in e.message
        assert "naabu failed" in e.message

    def test_extra_context_merged(self) -> None:
        e = PipelineStageError("url_collection", "gau error", context={"target": "x.com"})
        assert e.context["target"] == "x.com"
        assert e.context["stage"] == "url_collection"


# ── ParsingError ──────────────────────────────────────────────────────────────

class TestParsingError:
    def test_error_code(self) -> None:
        assert ParsingError.error_code == "PARSE_ERROR"

    def test_tool_name_stored(self) -> None:
        e = ParsingError("nuclei", '{"broken": }', "JSONDecodeError")
        assert e.tool_name == "nuclei"

    def test_raw_output_truncated_to_300(self) -> None:
        long_output = "x" * 500
        e = ParsingError("nuclei", long_output, "parse error")
        assert e.raw_output_snippet == "x" * 300
        assert len(e.context["raw_output_snippet"]) == 300

    def test_raw_output_shorter_than_300_not_padded(self) -> None:
        e = ParsingError("nuclei", "short", "reason")
        assert e.raw_output_snippet == "short"

    def test_empty_raw_output(self) -> None:
        e = ParsingError("nuclei")
        assert e.raw_output_snippet == ""
        assert e.context["raw_output_snippet"] == ""

    def test_context_fields(self) -> None:
        e = ParsingError("subfinder", "raw", "bad json")
        assert e.context["tool_name"] == "subfinder"
        assert e.context["reason"] == "bad json"


# ── IntelligenceError ─────────────────────────────────────────────────────────

class TestIntelligenceError:
    def test_error_code(self) -> None:
        assert IntelligenceError.error_code == "INTELLIGENCE_ERROR"

    def test_analyzer_stored(self) -> None:
        e = IntelligenceError("js_analyzer", "connection timeout")
        assert e.analyzer == "js_analyzer"

    def test_analyzer_in_context(self) -> None:
        e = IntelligenceError("vuln_patterns", "regex error")
        assert e.context["analyzer"] == "vuln_patterns"

    def test_message_contains_analyzer_and_reason(self) -> None:
        e = IntelligenceError("correlation_engine", "key error")
        assert "correlation_engine" in e.message
        assert "key error" in e.message

    def test_extra_context_merged(self) -> None:
        e = IntelligenceError("js_analyzer", "timeout", context={"js_url": "https://x.com/a.js"})
        assert e.context["js_url"] == "https://x.com/a.js"


# ── Infrastructure exceptions ─────────────────────────────────────────────────

class TestInfrastructureExceptions:
    @pytest.mark.parametrize("exc_class,expected_code", [
        (ConfigError,       "CONFIG_ERROR"),
        (DatabaseError,     "DATABASE_ERROR"),
        (CheckpointError,   "CHECKPOINT_ERROR"),
        (NotificationError, "NOTIFICATION_ERROR"),
    ])
    def test_error_codes(self, exc_class: type[ReconBaseError], expected_code: str) -> None:
        assert exc_class.error_code == expected_code

    @pytest.mark.parametrize("exc_class", [
        ConfigError, DatabaseError, CheckpointError, NotificationError,
    ])
    def test_inherits_base(self, exc_class: type[ReconBaseError]) -> None:
        e = exc_class("test message")
        assert isinstance(e, ReconBaseError)

    @pytest.mark.parametrize("exc_class", [
        ConfigError, DatabaseError, CheckpointError, NotificationError,
    ])
    def test_context_accepted(self, exc_class: type[ReconBaseError]) -> None:
        e = exc_class("msg", context={"detail": "extra"})
        assert e.context["detail"] == "extra"

    @pytest.mark.parametrize("exc_class", [
        ConfigError, DatabaseError, CheckpointError, NotificationError,
    ])
    def test_to_dict_json_serialisable(self, exc_class: type[ReconBaseError]) -> None:
        e = exc_class("msg", context={"k": "v"})
        json.dumps(e.to_dict())  # must not raise

    def test_config_error_to_dict(self) -> None:
        e = ConfigError("Missing key", context={"missing_keys": ["api_keys.shodan"]})
        d = e.to_dict()
        assert d["error_code"] == "CONFIG_ERROR"
        assert d["context"]["missing_keys"] == ["api_keys.shodan"]

    def test_database_error_str(self) -> None:
        e = DatabaseError("INSERT failed", context={"table": "subdomains"})
        s = str(e)
        assert "DATABASE_ERROR" in s
        assert "INSERT failed" in s


# ── Cross-cutting: to_dict contract ──────────────────────────────────────────

class TestToDictContract:
    """Every exception's to_dict() must have these four keys."""

    ALL_EXCEPTIONS = [
        ReconBaseError("m"),
        ToolNotAvailableError("t", "r"),
        ToolInstallError("t", "r"),
        ToolExecutionError("t", "cmd", 1, "err"),
        PipelineStageError("stage", "reason"),
        ParsingError("tool", "raw", "reason"),
        IntelligenceError("analyzer", "reason"),
        ConfigError("m"),
        DatabaseError("m"),
        CheckpointError("m"),
        NotificationError("m"),
    ]

    @pytest.mark.parametrize("exc", ALL_EXCEPTIONS)
    def test_required_keys_present(self, exc: ReconBaseError) -> None:
        d = exc.to_dict()
        assert "error_code" in d
        assert "error_type" in d
        assert "message" in d
        assert "context" in d

    @pytest.mark.parametrize("exc", ALL_EXCEPTIONS)
    def test_error_type_matches_class_name(self, exc: ReconBaseError) -> None:
        assert exc.to_dict()["error_type"] == type(exc).__name__

    @pytest.mark.parametrize("exc", ALL_EXCEPTIONS)
    def test_context_is_dict(self, exc: ReconBaseError) -> None:
        assert isinstance(exc.to_dict()["context"], dict)
