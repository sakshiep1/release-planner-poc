"""Tests for fix type classification logic."""
from __future__ import annotations

import pytest

from src.models.fix import BranchCVE, FixType
from src.models.cve import CVEEntry
from src.services.fix_classifier import classify_single, normalize_risk_level, _parse_semver, _version_gap_size


class TestSemverParsing:
    def test_parse_with_v_prefix(self):
        assert _parse_semver("v0.38.0") == (0, 38, 0)

    def test_parse_without_prefix(self):
        assert _parse_semver("1.17.4") == (1, 17, 4)

    def test_parse_invalid(self):
        assert _parse_semver("invalid") is None

    def test_parse_empty(self):
        assert _parse_semver("") is None


class TestVersionGap:
    def test_patch_bump(self):
        assert _version_gap_size("v0.38.0", "v0.38.1") == "patch"

    def test_minor_bump(self):
        assert _version_gap_size("v0.38.0", "v0.55.0") == "minor"

    def test_major_bump(self):
        assert _version_gap_size("v0.38.0", "v1.0.0") == "major"

    def test_unknown_input(self):
        assert _version_gap_size("", "v0.55.0") == "unknown"


class TestClassifySingle:
    def _make_cve(self, fixed_version: str | None = "v0.55.0") -> CVEEntry:
        return CVEEntry(
            cve_id="CVE-2026-39821",
            severity_rating="CRITICAL",
            cvss_score=9.6,
            affected_module="golang.org/x/net",
            fixed_version=fixed_version,
        )

    def _make_bcve(
        self,
        risk_level: str = "MEDIUM",
        dep_type: str = "indirect",
        current: str = "v0.38.0",
        reachable: bool = True,
    ) -> BranchCVE:
        return BranchCVE(
            risk_level=risk_level,
            confidence="HIGH",
            dependency_type=dep_type,
            current_version=current,
            symbol_reachable=reachable,
        )

    def test_not_vulnerable_returns_na(self):
        bcve = self._make_bcve(risk_level="NOT_VULNERABLE")
        cve = self._make_cve()
        assert classify_single(bcve, cve) == FixType.NOT_APPLICABLE

    def test_low_risk_unreachable_returns_na(self):
        """CVE-2026-25681: LOW risk, symbol not reachable -> NOT_APPLICABLE."""
        bcve = self._make_bcve(risk_level="LOW", reachable=False)
        cve = self._make_cve()
        assert classify_single(bcve, cve) == FixType.NOT_APPLICABLE

    def test_no_fixed_version_returns_review(self):
        bcve = self._make_bcve()
        cve = self._make_cve(fixed_version=None)
        assert classify_single(bcve, cve) == FixType.NEEDS_REVIEW

    def test_indirect_reachable_minor_bump(self):
        """CVE-2026-39821: indirect dep, symbol reachable, v0.38.0 -> v0.55.0 (minor) -> TRIVIAL_BACKPORT."""
        bcve = self._make_bcve(dep_type="indirect", reachable=True, current="v0.38.0")
        cve = self._make_cve(fixed_version="v0.55.0")
        assert classify_single(bcve, cve) == FixType.TRIVIAL_BACKPORT

    def test_indirect_unreachable(self):
        """Indirect dep, not reachable -> VERSION_BUMP (just update go.mod)."""
        bcve = self._make_bcve(dep_type="indirect", reachable=False)
        cve = self._make_cve()
        assert classify_single(bcve, cve) == FixType.VERSION_BUMP

    def test_direct_patch_bump(self):
        bcve = self._make_bcve(dep_type="direct", current="v1.17.3")
        cve = self._make_cve(fixed_version="v1.17.4")
        assert classify_single(bcve, cve) == FixType.VERSION_BUMP

    def test_direct_major_bump(self):
        bcve = self._make_bcve(dep_type="direct", current="v0.38.0")
        cve = self._make_cve(fixed_version="v1.0.0")
        assert classify_single(bcve, cve) == FixType.NON_TRIVIAL_BACKPORT

    def test_indirect_reachable_major_bump(self):
        bcve = self._make_bcve(dep_type="indirect", reachable=True, current="v0.38.0")
        cve = self._make_cve(fixed_version="v1.0.0")
        assert classify_single(bcve, cve) == FixType.NON_TRIVIAL_BACKPORT

    def test_not_vulnerable_with_spaces(self):
        """Risk 'NOT VULNERABLE' (with space) should still classify as NOT_APPLICABLE."""
        bcve = self._make_bcve(risk_level="NOT VULNERABLE")
        cve = self._make_cve()
        assert classify_single(bcve, cve) == FixType.NOT_APPLICABLE


class TestNormalizeRiskLevel:
    def test_canonical(self):
        assert normalize_risk_level("NOT_VULNERABLE") == "NOT_VULNERABLE"

    def test_with_spaces(self):
        assert normalize_risk_level("NOT VULNERABLE") == "NOT_VULNERABLE"

    def test_with_dashes(self):
        assert normalize_risk_level("Not-Vulnerable") == "NOT_VULNERABLE"

    def test_none_returns_unknown(self):
        assert normalize_risk_level(None) == "UNKNOWN"

    def test_empty_returns_unknown(self):
        assert normalize_risk_level("") == "UNKNOWN"

    def test_passthrough(self):
        assert normalize_risk_level("MEDIUM") == "MEDIUM"

    def test_none_risk(self):
        assert normalize_risk_level("NONE") == "NONE"
