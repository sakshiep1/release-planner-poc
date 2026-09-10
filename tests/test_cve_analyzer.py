"""Tests for the CVE analyzer orchestrator with mocked dependencies."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.services.cve_analyzer import (
    _run_govulncheck_for_cves,
    _parse_govulncheck_json,
    _analyze_cve_with_sdk,
    _get_api_key,
    filter_cves_for_analysis,
)


class TestGetApiKey:
    def test_returns_none_when_not_set(self):
        with patch("src.services.cve_analyzer.get_settings") as mock_settings, \
             patch.dict("os.environ", {}, clear=True):
            mock_settings.return_value.scanner.cursor_api_key = ""
            assert _get_api_key() is None

    def test_returns_env_var(self):
        with patch("src.services.cve_analyzer.get_settings") as mock_settings, \
             patch.dict("os.environ", {"CURSOR_API_KEY": "test-key-123"}):
            mock_settings.return_value.scanner.cursor_api_key = ""
            assert _get_api_key() == "test-key-123"

    def test_config_takes_precedence(self):
        with patch("src.services.cve_analyzer.get_settings") as mock_settings, \
             patch.dict("os.environ", {"CURSOR_API_KEY": "env-key"}):
            mock_settings.return_value.scanner.cursor_api_key = "config-key"
            assert _get_api_key() == "config-key"


class TestParseGovulncheckJson:
    """Test the raw_decode-based parser handles real govulncheck output."""

    def test_parses_pretty_printed_json(self):
        """govulncheck -json outputs multi-line pretty-printed objects, not NDJSON."""
        raw = """{
  "config": {
    "scanner_name": "govulncheck",
    "scanner_version": "v1.7.0"
  }
}
{
  "osv": {
    "id": "GO-2024-1234",
    "aliases": ["CVE-2024-12345"]
  }
}
{
  "osv": {
    "id": "GO-2024-5678",
    "aliases": ["CVE-2024-67890", "GHSA-xxxx"]
  }
}
{
  "finding": {
    "osv": "GO-2024-1234"
  }
}"""
        objects = _parse_govulncheck_json(raw)
        assert len(objects) == 4
        assert objects[0]["config"]["scanner_name"] == "govulncheck"
        assert objects[1]["osv"]["aliases"] == ["CVE-2024-12345"]
        assert objects[2]["osv"]["aliases"] == ["CVE-2024-67890", "GHSA-xxxx"]
        assert objects[3]["finding"]["osv"] == "GO-2024-1234"

    def test_handles_empty_input(self):
        assert _parse_govulncheck_json("") == []
        assert _parse_govulncheck_json("   \n  \n") == []

    def test_handles_ndjson_format_too(self):
        """Backwards compatible with single-line NDJSON format."""
        raw = '{"osv": {"id": "GO-1", "aliases": ["CVE-2024-111"]}}\n{"osv": {"id": "GO-2", "aliases": ["CVE-2024-222"]}}'
        objects = _parse_govulncheck_json(raw)
        assert len(objects) == 2

    def test_skips_non_dict_values(self):
        raw = '"just a string"\n42\n{"osv": {"id": "GO-1", "aliases": ["CVE-2024-111"]}}'
        objects = _parse_govulncheck_json(raw)
        assert len(objects) == 1
        assert objects[0]["osv"]["id"] == "GO-1"


class TestRunGovulncheckForCves:
    def test_parses_cve_ids_from_output(self):
        # Use pretty-printed JSON matching real govulncheck output
        osv_output = json.dumps({"osv": {"id": "GO-2026-5026", "aliases": ["CVE-2026-39821", "GHSA-w2q5"]}}, indent=2) + "\n" + \
            json.dumps({"osv": {"id": "GO-2026-5100", "aliases": ["CVE-2026-46597"]}}, indent=2) + "\n" + \
            json.dumps({"finding": {"osv": "GO-2026-5026"}}, indent=2)

        async def _test():
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                proc = AsyncMock()
                proc.communicate.return_value = (osv_output.encode(), b"")
                proc.returncode = 0
                mock_exec.return_value = proc

                cves = await _run_govulncheck_for_cves("/fake/repo")
                assert "CVE-2026-39821" in cves
                assert "CVE-2026-46597" in cves
                assert len(cves) == 2

        asyncio.run(_test())

    def test_handles_govulncheck_not_found(self):
        async def _test():
            with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("govulncheck")):
                cves = await _run_govulncheck_for_cves("/fake/repo")
                assert cves == []

        asyncio.run(_test())

    def test_handles_timeout(self):
        async def _test():
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                proc = AsyncMock()
                proc.communicate.side_effect = asyncio.TimeoutError()
                mock_exec.return_value = proc

                cves = await _run_govulncheck_for_cves("/fake/repo", timeout_s=1)
                assert cves == []

        asyncio.run(_test())


class TestFilterCvesForAnalysis:
    def test_filters_by_year(self):
        cves = ["CVE-2014-7189", "CVE-2025-1234", "CVE-2026-39821"]
        result = filter_cves_for_analysis(cves, min_cve_year=2024, max_analyze_per_branch=0)
        assert result == ["CVE-2025-1234", "CVE-2026-39821"]

    def test_respects_allowlist(self):
        cves = ["CVE-2025-1234", "CVE-2026-39821", "CVE-2026-46597"]
        result = filter_cves_for_analysis(
            cves,
            allowlist=["CVE-2026-39821"],
            max_analyze_per_branch=0,
        )
        assert result == ["CVE-2026-39821"]

    def test_caps_max_per_branch(self):
        cves = [f"CVE-2025-{i:04d}" for i in range(100)]
        result = filter_cves_for_analysis(cves, min_cve_year=2024, max_analyze_per_branch=10)
        assert len(result) == 10


class TestAnalyzeCveWithSdk:
    def test_returns_evidence_path_on_success(self, tmp_path):
        evidence_dir = tmp_path / ".work" / "compliance" / "analyze-cve" / "CVE-2026-39821"
        evidence_dir.mkdir(parents=True)
        evidence_file = evidence_dir / "evidence.json"
        evidence_file.write_text(json.dumps({"cve_id": "CVE-2026-39821"}))

        async def _test():
            mock_agent = MagicMock()
            mock_agent.prompt.return_value = MagicMock(status="completed")

            async def fake_to_thread(fn):
                return fn()

            with patch.dict("sys.modules", {"cursor_sdk": MagicMock(Agent=mock_agent)}), \
                 patch("src.services.cve_analyzer.asyncio.to_thread", side_effect=fake_to_thread):
                result = await _analyze_cve_with_sdk(
                    "CVE-2026-39821", str(tmp_path), "fake-api-key"
                )
                assert result is not None
                assert result.name == "evidence.json"

        asyncio.run(_test())

    def test_returns_none_when_sdk_not_installed(self):
        async def _test():
            with patch.dict("sys.modules", {"cursor_sdk": None}):
                import importlib
                with patch("builtins.__import__", side_effect=ImportError("No module named 'cursor_sdk'")):
                    result = await _analyze_cve_with_sdk(
                        "CVE-2026-39821", "/fake/repo", "fake-api-key"
                    )
                    assert result is None

        asyncio.run(_test())

    def test_returns_none_when_evidence_missing(self, tmp_path):
        async def _test():
            mock_agent = MagicMock()
            mock_agent.prompt.return_value = MagicMock(status="completed")

            async def fake_to_thread(fn):
                return fn()

            with patch.dict("sys.modules", {"cursor_sdk": MagicMock(Agent=mock_agent)}), \
                 patch("src.services.cve_analyzer.asyncio.to_thread", side_effect=fake_to_thread):
                result = await _analyze_cve_with_sdk(
                    "CVE-2026-39821", str(tmp_path), "fake-api-key"
                )
                assert result is None

        asyncio.run(_test())


class TestPostScanPipeline:
    def test_analyze_all_branches_calls_classify_and_estimate(self):
        async def _test():
            mock_db = AsyncMock()
            mock_scan = MagicMock()
            mock_scan.status = "completed"

            with patch("src.services.cve_analyzer._build_repo_manager") as mock_rm, \
                 patch("src.services.cve_analyzer.get_releases_config") as mock_cfg, \
                 patch("src.services.cve_analyzer.get_settings") as mock_settings, \
                 patch("src.services.cve_analyzer.analyze_branch", return_value=mock_scan), \
                 patch("src.services.fix_classifier.classify_all", new_callable=AsyncMock) as mock_classify, \
                 patch("src.services.effort_estimator.estimate_all", new_callable=AsyncMock) as mock_estimate, \
                 patch("src.services.cve_analyzer.sse_broker.publish", new_callable=AsyncMock):

                rm_instance = AsyncMock()
                rm_instance.get_repo_path.return_value = "/tmp/repo"
                rm_instance.is_auto_cloned = True
                rm_instance.cleanup = AsyncMock()
                mock_rm.return_value = rm_instance

                branch_cfg = MagicMock()
                branch_cfg.name = "cert-manager-1.18"
                mock_cfg.return_value.active_branches = [branch_cfg]
                mock_cfg.return_value.jira.enabled = True

                mock_settings.return_value.scanner.govulncheck_timeout_s = 300
                mock_settings.return_value.scanner.cursor_api_key = ""

                with patch("src.services.jira_discovery._get_jira_credentials", return_value=("https://jira", "token", "user@example.com")), \
                     patch("src.services.cve_analyzer.discover_from_jira", new_callable=AsyncMock) as mock_discover, \
                     patch("src.services.jira_discovery.discover_vulnerability_tickets_for_branch", new_callable=AsyncMock, return_value=[]):
                    mock_discover.return_value = MagicMock(cves_found=0)

                    branch = MagicMock()
                    branch.id = "br-1"
                    branch.name = "cert-manager-1.18"
                    mock_result = MagicMock()
                    mock_result.scalar_one_or_none.return_value = branch
                    mock_db.execute.return_value = mock_result

                    from src.services.cve_analyzer import analyze_all_branches
                    results = await analyze_all_branches(mock_db, skip_analysis=True)

                    assert len(results) == 1
                    mock_classify.assert_awaited_once_with(mock_db)
                    mock_estimate.assert_awaited_once_with(mock_db)

        asyncio.run(_test())
