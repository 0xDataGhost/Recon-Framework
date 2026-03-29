"""
Integration smoke tests for the full recon pipeline.

These tests require the recon/, intelligence/, notifications/, and output/
modules to be implemented. Until then, every test is skipped with a clear
message explaining what needs to be built before it can run.

Add tests here as modules are implemented. Each test should:
- Use a safe, offline target (localhost or a controlled lab host)
- Assert on the shape of the result, not on specific findings
- Run without network access where possible (use fixtures/mocks)
"""

from __future__ import annotations

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _modules_available(*module_names: str) -> bool:
    """Return True only if every named module can be imported."""
    import importlib
    for name in module_names:
        try:
            importlib.import_module(name)
        except ImportError:
            return False
    return True


PIPELINE_AVAILABLE = _modules_available(
    "recon.pipeline",
    "intelligence.analyzer",
    "notifications.dispatcher",
    "output.writer",
)

SKIP_REASON = (
    "Pipeline modules are not yet implemented. "
    "Implement recon/, intelligence/, notifications/, and output/ first."
)


# ── Smoke tests ───────────────────────────────────────────────────────────────

@pytest.mark.skipif(not PIPELINE_AVAILABLE, reason=SKIP_REASON)
class TestPipelineSmokeOffline:
    """Tests that exercise the pipeline without network I/O."""

    def test_pipeline_returns_pipeline_result(self) -> None:
        """PipelineResult is returned even if all stages produce empty output."""
        from recon.pipeline import ReconPipeline, PipelineOptions

        config: dict = {}
        pipeline = ReconPipeline(config)
        result = pipeline.run(
            targets=["localhost"],
            options=PipelineOptions(enable_nuclei=False),
        )
        # Assert shape — not specific content
        assert hasattr(result, "subdomains")
        assert hasattr(result, "live_hosts")
        assert hasattr(result, "ports")
        assert hasattr(result, "urls")
        assert isinstance(result.subdomains, list)

    def test_pipeline_does_not_raise_on_empty_target(self) -> None:
        """An unresolvable target produces empty results, not an exception."""
        from recon.pipeline import ReconPipeline, PipelineOptions

        pipeline = ReconPipeline({})
        result = pipeline.run(
            targets=["this-domain-does-not-exist.invalid"],
            options=PipelineOptions(enable_nuclei=False),
        )
        assert result.subdomains == []
        assert result.live_hosts == []

    def test_intelligence_report_structure(self) -> None:
        """IntelReport always has the required fields, even on empty input."""
        from recon.pipeline import ReconPipeline, PipelineOptions
        from intelligence.analyzer import IntelligenceAnalyzer

        pipeline = ReconPipeline({})
        result = pipeline.run(
            targets=["localhost"],
            options=PipelineOptions(enable_nuclei=False),
        )
        analyzer = IntelligenceAnalyzer({})
        report = analyzer.analyze(result)

        assert hasattr(report, "top_targets")
        assert hasattr(report, "attack_chains")
        assert hasattr(report, "exploit_scenarios")
        assert hasattr(report, "js_findings")
        assert hasattr(report, "vuln_hints")
        assert isinstance(report.top_targets, list)
        assert isinstance(report.attack_chains, list)


@pytest.mark.skipif(not PIPELINE_AVAILABLE, reason=SKIP_REASON)
class TestOutputWriter:
    """Tests for the output file writer."""

    def test_output_files_created(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Writer creates expected files in the output directory."""
        from recon.pipeline import ReconPipeline, PipelineOptions
        from intelligence.analyzer import IntelligenceAnalyzer
        from output.writer import OutputWriter

        pipeline = ReconPipeline({})
        result = pipeline.run(
            targets=["localhost"],
            options=PipelineOptions(enable_nuclei=False),
        )
        analyzer = IntelligenceAnalyzer({})
        report = analyzer.analyze(result)

        writer = OutputWriter(base_dir=tmp_path)
        writer.write("localhost", result, report)

        out_dir = tmp_path / "localhost"
        assert out_dir.exists()

        expected_files = [
            "subdomains.txt",
            "live.txt",
            "ports.txt",
            "urls.txt",
            "scan_report.json",
        ]
        for filename in expected_files:
            assert (out_dir / filename).exists(), f"{filename} was not created"


# ── Placeholder for future network tests ─────────────────────────────────────

class TestNetworkIntegration:
    """
    Network-dependent integration tests.

    These require a controlled target and should only run in a dedicated
    test environment — never against production infrastructure.

    Mark with @pytest.mark.integration and run selectively:
        pytest -m integration tests/integration/
    """

    @pytest.mark.skip(reason="Requires a controlled lab target — not run by default.")
    def test_full_scan_against_lab_target(self) -> None:  # pragma: no cover
        """
        End-to-end scan against an intentionally vulnerable lab VM.

        Set LAB_TARGET env var to the VM's hostname before running.
        """
        import os
        lab_target = os.environ.get("LAB_TARGET", "")
        if not lab_target:
            pytest.skip("LAB_TARGET environment variable not set.")
        # Exercise the full pipeline once modules are available.
