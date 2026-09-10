"""Tests for Jira MCP discovery service."""
from __future__ import annotations

import json

import pytest

from src.services.jira_discovery import (
    extract_cve_ids,
    extract_pr_links,
    extract_branch_refs,
    parse_ticket_from_search,
    parse_remote_links,
    parse_jira_search_result,
    build_jql_for_branch,
    build_govcloud_jql,
    build_critical_bugs_jql,
    JiraTicketContext,
)
from src.services.config_loader import JiraConfig


class TestExtractCVEIds:
    def test_single_cve(self):
        text = "Fix for CVE-2026-39821 in cert-manager"
        assert extract_cve_ids(text) == ["CVE-2026-39821"]

    def test_multiple_cves(self):
        text = "CVE-2026-39821 and CVE-2025-12345 found"
        result = extract_cve_ids(text)
        assert "CVE-2026-39821" in result
        assert "CVE-2025-12345" in result
        assert len(result) == 2

    def test_dedup(self):
        text = "CVE-2026-39821 affects multiple things CVE-2026-39821"
        assert extract_cve_ids(text) == ["CVE-2026-39821"]

    def test_empty(self):
        assert extract_cve_ids("") == []
        assert extract_cve_ids("no cves here") == []

    def test_none_safe(self):
        assert extract_cve_ids(None) == []

    def test_cve_in_url(self):
        text = "See https://nvd.nist.gov/vuln/detail/CVE-2026-39821"
        assert extract_cve_ids(text) == ["CVE-2026-39821"]


class TestExtractPRLinks:
    def test_github_pr(self):
        text = "Fixed in https://github.com/openshift/cert-manager-operator/pull/472"
        result = extract_pr_links(text)
        assert result == ["https://github.com/openshift/cert-manager-operator/pull/472"]

    def test_multiple_prs(self):
        text = """
        PR https://github.com/openshift/cert-manager-operator/pull/44
        and https://github.com/openshift/cert-manager-operator/pull/46
        """
        result = extract_pr_links(text)
        assert len(result) == 2

    def test_no_prs(self):
        assert extract_pr_links("no links here") == []
        assert extract_pr_links("") == []

    def test_non_pr_github_link(self):
        assert extract_pr_links("https://github.com/openshift/cert-manager-operator/issues/10") == []


class TestExtractBranchRefs:
    def test_branch_name(self):
        text = "rebase for cert-manager-1.18"
        result = extract_branch_refs(text)
        assert "cert-manager-1.18" in result

    def test_version_tag(self):
        text = "upgrade to v1.18.2"
        result = extract_branch_refs(text)
        assert "v1.18.2" in result

    def test_multiple(self):
        text = "cert-manager-1.18 and cert-manager-1.19"
        result = extract_branch_refs(text)
        assert len(result) == 2


class TestParseTicketFromSearch:
    def test_basic_parse(self):
        issue = {
            "key": "CM-1216",
            "fields": {
                "summary": "rebase and CVE fix for v1.18.2 CVE-2026-39821",
                "description": "This fixes CVE-2026-39821 and CVE-2025-22871",
                "status": {"name": "In Progress"},
                "priority": {"name": "Major"},
                "issuetype": {"name": "Story"},
                "labels": [],
            },
        }
        ticket = parse_ticket_from_search(issue)
        assert ticket.key == "CM-1216"
        assert "CVE-2026-39821" in ticket.cve_ids
        assert "CVE-2025-22871" in ticket.cve_ids
        assert ticket.status == "In Progress"
        assert ticket.issue_type == "Story"
        assert not ticket.is_govcloud

    def test_govcloud_detection_by_label(self):
        issue = {
            "key": "CM-1235",
            "fields": {
                "summary": "GovCloud August 2026 Vulnerability",
                "description": "",
                "status": {"name": "Open"},
                "priority": {"name": "High"},
                "issuetype": {"name": "Epic"},
                "labels": ["ROSA-GovCloud"],
            },
        }
        ticket = parse_ticket_from_search(issue)
        assert ticket.is_govcloud

    def test_govcloud_detection_by_summary(self):
        issue = {
            "key": "CM-1235",
            "fields": {
                "summary": "[GovCloud] August 2026 Vulnerability Notification",
                "description": "",
                "status": {"name": "Open"},
                "priority": {"name": "High"},
                "issuetype": {"name": "Epic"},
                "labels": [],
            },
        }
        ticket = parse_ticket_from_search(issue)
        assert ticket.is_govcloud

    def test_pr_extraction_from_description(self):
        issue = {
            "key": "CM-1222",
            "fields": {
                "summary": "rebase to latest upstream z-stream and fix CVES",
                "description": "PR: https://github.com/openshift/cert-manager-operator/pull/472",
                "status": {"name": "Done"},
                "priority": {"name": "Major"},
                "issuetype": {"name": "Story"},
                "labels": [],
            },
        }
        ticket = parse_ticket_from_search(issue)
        assert "https://github.com/openshift/cert-manager-operator/pull/472" in ticket.linked_prs


class TestParseRemoteLinks:
    def test_standard_remote_links(self):
        data = json.dumps({
            "remote_links": [
                {"object": {"url": "https://github.com/openshift/cert-manager-operator/pull/44", "title": "PR #44"}},
                {"object": {"url": "https://github.com/openshift/cert-manager-operator/pull/46", "title": "PR #46"}},
            ]
        })
        result = parse_remote_links(data)
        assert len(result) == 2
        assert "https://github.com/openshift/cert-manager-operator/pull/44" in result

    def test_no_remote_links(self):
        data = json.dumps({"remote_links": []})
        assert parse_remote_links(data) == []

    def test_non_github_links_filtered(self):
        data = json.dumps({
            "remote_links": [
                {"object": {"url": "https://example.com/something", "title": "Not a PR"}},
            ]
        })
        assert parse_remote_links(data) == []

    def test_invalid_json(self):
        assert parse_remote_links("not json") == []


class TestParseSearchResult:
    def test_dict_with_issues_key(self):
        data = json.dumps({"issues": [{"key": "CM-1"}, {"key": "CM-2"}], "total": 2})
        result = parse_jira_search_result(data)
        assert len(result) == 2

    def test_list_format(self):
        data = json.dumps([{"key": "CM-1"}])
        result = parse_jira_search_result(data)
        assert len(result) == 1

    def test_invalid_json(self):
        assert parse_jira_search_result("bad json") == []


class TestBuildJQL:
    def setup_method(self):
        self.config = JiraConfig(
            enabled=True,
            project_key="CM",
            rebase_search_pattern='(summary ~ "CVE" OR summary ~ "rebase") AND summary ~ "{version}"',
            govcloud_search='summary ~ "GovCloud" AND summary ~ "Vulnerability"',
            critical_bugs_search='priority in (Critical, Blocker) AND issuetype = Bug',
        )

    def test_branch_jql(self):
        jql = build_jql_for_branch(self.config, "cert-manager-1.18")
        assert "project = CM" in jql
        assert '"1.18"' in jql
        assert "statusCategory != Done" in jql

    def test_govcloud_jql(self):
        jql = build_govcloud_jql(self.config)
        assert "GovCloud" in jql
        assert "project = CM" in jql

    def test_critical_bugs_jql(self):
        jql = build_critical_bugs_jql(self.config)
        assert "Critical" in jql
        assert "Blocker" in jql
