"""Tests for the Jira poster service."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.services.jira_poster import (
    _build_comment_body,
    add_label_to_jira,
    check_already_posted,
    post_cve_summary_to_jira,
)


class TestBuildCommentBody:
    def test_builds_basic_comment(self):
        body = _build_comment_body(
            cve_id="CVE-2026-12345",
            severity="HIGH",
            cvss_score=7.5,
            branch_summaries=[],
            source="jira",
        )
        assert "CVE-2026-12345" in body
        assert "HIGH" in body
        assert "7.5" in body
        assert "jira" in body

    def test_includes_branch_table(self):
        body = _build_comment_body(
            cve_id="CVE-2026-99999",
            severity="CRITICAL",
            cvss_score=9.8,
            branch_summaries=[
                {
                    "branch_name": "cert-manager-1.20",
                    "risk_level": "CRITICAL",
                    "fix_type": "VERSION_BUMP",
                    "effort_tshirt": "S",
                    "confidence": "HIGH",
                },
            ],
            source="evidence",
        )
        assert "cert-manager-1.20" in body
        assert "VERSION_BUMP" in body
        assert "||Branch||" in body

    def test_handles_none_cvss(self):
        body = _build_comment_body(
            cve_id="CVE-2026-00001",
            severity="LOW",
            cvss_score=None,
            branch_summaries=[],
            source="govulncheck",
        )
        assert "CVSS" not in body


class TestCheckAlreadyPosted:
    def test_skip_when_own_label_present(self):
        async def _test():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "fields": {"labels": ["release-planner-posted"]}
            }

            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                should_skip, reason = await check_already_posted(
                    "CM-123", "https://jira", "user@test.com", "token",
                )
                assert should_skip is True
                assert "already posted" in reason

        asyncio.run(_test())

    def test_skip_when_analyze_cve_label_present(self):
        async def _test():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "fields": {"labels": ["ai-cve-analyzed"]}
            }

            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                should_skip, reason = await check_already_posted(
                    "CM-123", "https://jira", "user@test.com", "token",
                )
                assert should_skip is True
                assert "ai-cve-analyzed" in reason

        asyncio.run(_test())

    def test_no_skip_when_no_labels(self):
        async def _test():
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"fields": {"labels": []}}

            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                should_skip, _ = await check_already_posted(
                    "CM-123", "https://jira", "user@test.com", "token",
                )
                assert should_skip is False

        asyncio.run(_test())


class TestAddLabelToJira:
    def test_returns_true_on_success(self):
        async def _test():
            mock_resp = MagicMock()
            mock_resp.status_code = 204

            mock_client = AsyncMock()
            mock_client.put.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                result = await add_label_to_jira(
                    "CM-123", "test-label", "https://jira", "user@test.com", "token",
                )
                assert result is True

        asyncio.run(_test())

    def test_returns_false_on_failure(self):
        async def _test():
            mock_resp = MagicMock()
            mock_resp.status_code = 403

            mock_client = AsyncMock()
            mock_client.put.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                result = await add_label_to_jira(
                    "CM-123", "test-label", "https://jira", "user@test.com", "token",
                )
                assert result is False

        asyncio.run(_test())


class TestPostCveSummaryToJira:
    def test_skipped_when_already_posted(self):
        async def _test():
            with patch("src.services.jira_poster.get_releases_config") as mock_cfg:
                mock_jira = MagicMock()
                mock_jira.post_label = "release-planner-posted"
                mock_jira.skip_if_analyzed = True
                mock_cfg.return_value.jira = mock_jira

                with patch(
                    "src.services.jira_poster.check_already_posted",
                    new_callable=AsyncMock,
                    return_value=(True, "already posted"),
                ):
                    result = await post_cve_summary_to_jira(
                        jira_key="CM-123",
                        cve_id="CVE-2026-12345",
                        severity="HIGH",
                        cvss_score=7.5,
                        source="jira",
                        branch_summaries=[],
                        jira_url="https://jira",
                        email="user@test.com",
                        api_token="token",
                    )
                    assert result["status"] == "skipped"

        asyncio.run(_test())

    def test_success_posts_comment_and_label(self):
        async def _test():
            with patch("src.services.jira_poster.get_releases_config") as mock_cfg:
                mock_jira = MagicMock()
                mock_jira.post_label = "release-planner-posted"
                mock_jira.skip_if_analyzed = True
                mock_cfg.return_value.jira = mock_jira

                with patch(
                    "src.services.jira_poster.check_already_posted",
                    new_callable=AsyncMock,
                    return_value=(False, ""),
                ), patch(
                    "src.services.jira_poster.add_label_to_jira",
                    new_callable=AsyncMock,
                    return_value=True,
                ) as mock_label:
                    mock_resp = MagicMock()
                    mock_resp.status_code = 201

                    mock_client = AsyncMock()
                    mock_client.post.return_value = mock_resp
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=False)

                    with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                        result = await post_cve_summary_to_jira(
                            jira_key="CM-456",
                            cve_id="CVE-2026-99999",
                            severity="CRITICAL",
                            cvss_score=9.8,
                            source="evidence",
                            branch_summaries=[],
                            jira_url="https://jira",
                            email="user@test.com",
                            api_token="token",
                        )
                        assert result["status"] == "success"
                        mock_label.assert_awaited_once()

        asyncio.run(_test())

    def test_failure_returns_failed_status(self):
        """Posting failure must not raise — it returns a 'failed' result."""
        async def _test():
            with patch("src.services.jira_poster.get_releases_config") as mock_cfg:
                mock_jira = MagicMock()
                mock_jira.post_label = "release-planner-posted"
                mock_jira.skip_if_analyzed = False
                mock_cfg.return_value.jira = mock_jira

                mock_resp = MagicMock()
                mock_resp.status_code = 500
                mock_resp.text = "Internal Server Error"

                mock_client = AsyncMock()
                mock_client.post.return_value = mock_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)

                with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                    result = await post_cve_summary_to_jira(
                        jira_key="CM-789",
                        cve_id="CVE-2026-11111",
                        severity="MEDIUM",
                        cvss_score=5.0,
                        source="govulncheck",
                        branch_summaries=[],
                        jira_url="https://jira",
                        email="user@test.com",
                        api_token="token",
                    )
                    assert result["status"] == "failed"
                    assert "500" in result["reason"]

        asyncio.run(_test())

    def test_exception_returns_failed_status(self):
        """Network exception must not propagate — returns 'failed'."""
        async def _test():
            with patch("src.services.jira_poster.get_releases_config") as mock_cfg:
                mock_jira = MagicMock()
                mock_jira.post_label = "release-planner-posted"
                mock_jira.skip_if_analyzed = False
                mock_cfg.return_value.jira = mock_jira

                mock_client = AsyncMock()
                mock_client.post.side_effect = ConnectionError("network down")
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)

                with patch("src.services.jira_poster.httpx.AsyncClient", return_value=mock_client):
                    result = await post_cve_summary_to_jira(
                        jira_key="CM-000",
                        cve_id="CVE-2026-00000",
                        severity="LOW",
                        cvss_score=None,
                        source="jira",
                        branch_summaries=[],
                        jira_url="https://jira",
                        email="user@test.com",
                        api_token="token",
                    )
                    assert result["status"] == "failed"
                    assert "network down" in result["reason"]

        asyncio.run(_test())
