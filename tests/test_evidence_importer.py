"""Tests for evidence importer parsing logic."""
from __future__ import annotations

from src.services.evidence_importer import (
    _detect_schema,
    _parse_analyze_cve_evidence,
    _parse_operator_evidence,
    _parse_operand_evidence,
)


OPERATOR_EVIDENCE = {
    "cve_id": "CVE-2026-39821",
    "go_vuln_id": "GO-2026-5026",
    "ghsa_id": "GHSA-w2q5-6q6x-x959",
    "cwe_id": "CWE-1289",
    "severity": {
        "rating": "CRITICAL",
        "cvss_score": 9.6,
        "source": "NVD / Go Vulnerability Database"
    },
    "affected_package": {
        "name": "golang.org/x/net/idna",
        "module": "golang.org/x/net",
        "vulnerable_versions": "< v0.55.0",
        "fixed_version": "v0.55.0",
    },
    "project_dependency": {
        "current_version": "v0.38.0",
        "dependency_type": "indirect",
        "symbol_reachable": True,
    },
    "risk_level": "MEDIUM",
    "confidence": "HIGH",
    "analysis_date": "2026-08-03",
}

ANALYZE_CVE_EVIDENCE = {
    "cve_id": "CVE-2014-7189",
    "go_advisory_id": "GO-2021-0154",
    "analysis_date": "2026-09-01",
    "risk_level": "LOW",
    "confidence": "HIGH",
    "verdict": "NOT_AFFECTED",
    "cve_profile": {
        "cve_id": "CVE-2014-7189",
        "severity": {
            "rating": "MEDIUM",
            "cvss_score": "4.3",
        },
        "affected_packages": [
            {
                "name": "std/crypto/tls",
                "module": "stdlib",
                "vulnerable_versions": "go1.1.0-0 through go1.3.1",
                "fixed_version": "go1.3.2",
            }
        ],
        "description": "TLS session resumption issue",
    },
}

OPERAND_EVIDENCE = {
    "skill": "codebase-impact-analysis",
    "status": "success",
    "risk_level": "HIGH",
    "cve_id": "CVE-2026-39821",
    "go_vuln_id": "GO-2026-5026",
    "methods_used": ["dependency_matching", "govulncheck"],
    "evidence": {
        "dependency": {
            "package_found": True,
            "module": "golang.org/x/net",
            "current_version": "v0.38.0",
            "dependency_type": "indirect",
        },
        "govulncheck": {
            "ran": True,
            "cve_found": True,
            "vulnerable_symbols_called": True,
        },
    },
    "confidence_assessment": {
        "level": "HIGH",
        "methods_count": 2,
        "gaps": [],
    },
}


class TestDetectSchema:
    def test_operator_schema(self):
        assert _detect_schema(OPERATOR_EVIDENCE) == "operator"

    def test_operand_schema(self):
        assert _detect_schema(OPERAND_EVIDENCE) == "operand"

    def test_analyze_cve_schema(self):
        assert _detect_schema(ANALYZE_CVE_EVIDENCE) == "analyze_cve"

    def test_empty_dict(self):
        assert _detect_schema({}) == "operator"


class TestParseAnalyzeCveEvidence:
    def test_nested_severity_and_verdict(self):
        cve_fields, bcve_fields = _parse_analyze_cve_evidence(ANALYZE_CVE_EVIDENCE)

        assert cve_fields["cve_id"] == "CVE-2014-7189"
        assert cve_fields["go_vuln_id"] == "GO-2021-0154"
        assert cve_fields["severity_rating"] == "MEDIUM"
        assert cve_fields["cvss_score"] == 4.3
        assert cve_fields["affected_module"] == "stdlib"
        assert cve_fields["affected_package"] == "std/crypto/tls"
        assert cve_fields["fixed_version"] == "go1.3.2"
        assert bcve_fields["risk_level"] == "LOW"
        assert bcve_fields["confidence"] == "HIGH"
        assert bcve_fields["jira_verdict"] == "NOT_AFFECTED"


class TestParseOperatorEvidence:
    def test_basic_parsing(self):
        cve_fields, bcve_fields = _parse_operator_evidence(OPERATOR_EVIDENCE)

        assert cve_fields["cve_id"] == "CVE-2026-39821"
        assert cve_fields["go_vuln_id"] == "GO-2026-5026"
        assert cve_fields["ghsa_id"] == "GHSA-w2q5-6q6x-x959"
        assert cve_fields["severity_rating"] == "CRITICAL"
        assert cve_fields["cvss_score"] == 9.6
        assert cve_fields["affected_module"] == "golang.org/x/net"
        assert cve_fields["affected_package"] == "golang.org/x/net/idna"
        assert cve_fields["fixed_version"] == "v0.55.0"

    def test_branch_cve_fields(self):
        _, bcve_fields = _parse_operator_evidence(OPERATOR_EVIDENCE)

        assert bcve_fields["risk_level"] == "MEDIUM"
        assert bcve_fields["confidence"] == "HIGH"
        assert bcve_fields["dependency_type"] == "indirect"
        assert bcve_fields["current_version"] == "v0.38.0"
        assert bcve_fields["symbol_reachable"] is True

    def test_moderate_maps_to_medium(self):
        data = {**OPERATOR_EVIDENCE, "severity": {"rating": "MODERATE"}}
        cve_fields, _ = _parse_operator_evidence(data)
        assert cve_fields["severity_rating"] == "MEDIUM"


class TestParseOperandEvidence:
    def test_basic_parsing(self):
        cve_fields, bcve_fields = _parse_operand_evidence(OPERAND_EVIDENCE)

        assert cve_fields["cve_id"] == "CVE-2026-39821"
        assert cve_fields["go_vuln_id"] == "GO-2026-5026"
        assert cve_fields["affected_module"] == "golang.org/x/net"

    def test_branch_cve_fields(self):
        _, bcve_fields = _parse_operand_evidence(OPERAND_EVIDENCE)

        assert bcve_fields["risk_level"] == "HIGH"
        assert bcve_fields["confidence"] == "HIGH"
        assert bcve_fields["dependency_type"] == "indirect"
        assert bcve_fields["current_version"] == "v0.38.0"
        assert bcve_fields["symbol_reachable"] is True
