"""Tests for verdict taxonomy mapping (Mytreya's CM-1216 categories)."""
from __future__ import annotations

import json

import pytest

from src.models.cve import CVEEntry
from src.models.fix import BranchCVE, FixType
from src.services.fix_classifier import (
    map_to_verdict,
    VERDICT_FIXED,
    VERDICT_NOT_AFFECTED,
    VERDICT_REBUILD_ONLY,
    VERDICT_NOT_FIXED,
    VERDICT_FALSE_POSITIVE,
)


class TestVerdictMapping:
    """Test all verdict classification paths."""

    def _make_cve(
        self,
        fixed_version: str | None = "v0.55.0",
        linked_prs: str = "[]",
    ) -> CVEEntry:
        return CVEEntry(
            cve_id="CVE-2026-39821",
            severity_rating="CRITICAL",
            cvss_score=9.6,
            affected_module="golang.org/x/net",
            fixed_version=fixed_version,
            linked_prs=linked_prs,
        )

    def _make_bcve(
        self,
        fix_type: FixType = FixType.VERSION_BUMP,
        risk_level: str = "MEDIUM",
        reachable: bool = True,
    ) -> BranchCVE:
        return BranchCVE(
            risk_level=risk_level,
            confidence="HIGH",
            dependency_type="indirect",
            current_version="v0.38.0",
            symbol_reachable=reachable,
            fix_type=fix_type,
        )

    # ── NOT_APPLICABLE → NOT_AFFECTED or FALSE_POSITIVE ──

    def test_na_not_vulnerable_returns_not_affected(self):
        """NOT_APPLICABLE + NOT_VULNERABLE risk → NOT_AFFECTED."""
        bcve = self._make_bcve(fix_type=FixType.NOT_APPLICABLE, risk_level="NOT_VULNERABLE")
        cve = self._make_cve()
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_AFFECTED

    def test_na_none_risk_returns_not_affected(self):
        """NOT_APPLICABLE + NONE risk → NOT_AFFECTED."""
        bcve = self._make_bcve(fix_type=FixType.NOT_APPLICABLE, risk_level="NONE")
        cve = self._make_cve()
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_AFFECTED

    def test_na_unreachable_returns_not_affected(self):
        """NOT_APPLICABLE + symbol not reachable → NOT_AFFECTED."""
        bcve = self._make_bcve(fix_type=FixType.NOT_APPLICABLE, risk_level="LOW", reachable=False)
        cve = self._make_cve()
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_AFFECTED

    def test_na_otherwise_returns_false_positive(self):
        """NOT_APPLICABLE but reachable and not NONE/NOT_VULNERABLE → FALSE_POSITIVE."""
        bcve = self._make_bcve(fix_type=FixType.NOT_APPLICABLE, risk_level="LOW", reachable=True)
        cve = self._make_cve()
        assert map_to_verdict(bcve, cve) == VERDICT_FALSE_POSITIVE

    # ── VERSION_BUMP / TRIVIAL_BACKPORT → FIXED or NOT_FIXED ──

    def test_version_bump_with_prs_returns_fixed(self):
        """VERSION_BUMP with linked PRs → FIXED."""
        prs = json.dumps(["https://github.com/openshift/cert-manager-operator/pull/472"])
        bcve = self._make_bcve(fix_type=FixType.VERSION_BUMP)
        cve = self._make_cve(linked_prs=prs)
        assert map_to_verdict(bcve, cve) == VERDICT_FIXED

    def test_trivial_backport_with_prs_returns_fixed(self):
        """TRIVIAL_BACKPORT with linked PRs → FIXED."""
        prs = json.dumps(["https://github.com/openshift/cert-manager-operator/pull/44"])
        bcve = self._make_bcve(fix_type=FixType.TRIVIAL_BACKPORT)
        cve = self._make_cve(linked_prs=prs)
        assert map_to_verdict(bcve, cve) == VERDICT_FIXED

    def test_version_bump_without_prs_returns_not_fixed(self):
        """VERSION_BUMP without PRs → NOT_FIXED (work still needed)."""
        bcve = self._make_bcve(fix_type=FixType.VERSION_BUMP)
        cve = self._make_cve(linked_prs="[]")
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_FIXED

    def test_trivial_backport_without_prs_returns_not_fixed(self):
        bcve = self._make_bcve(fix_type=FixType.TRIVIAL_BACKPORT)
        cve = self._make_cve(linked_prs="[]")
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_FIXED

    # ── NEEDS_REVIEW → REBUILD_ONLY or NOT_FIXED ──

    def test_needs_review_no_fixed_version_returns_rebuild(self):
        """NEEDS_REVIEW + no fixed version → REBUILD_ONLY (likely stdlib)."""
        bcve = self._make_bcve(fix_type=FixType.NEEDS_REVIEW)
        cve = self._make_cve(fixed_version=None)
        assert map_to_verdict(bcve, cve) == VERDICT_REBUILD_ONLY

    def test_needs_review_with_fixed_version_returns_not_fixed(self):
        """NEEDS_REVIEW + has fixed version → NOT_FIXED."""
        bcve = self._make_bcve(fix_type=FixType.NEEDS_REVIEW)
        cve = self._make_cve(fixed_version="v1.0.0")
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_FIXED

    # ── NON_TRIVIAL_BACKPORT → FIXED or NOT_FIXED ──

    def test_non_trivial_with_prs_returns_fixed(self):
        """NON_TRIVIAL_BACKPORT with PRs → FIXED."""
        prs = json.dumps(["https://github.com/openshift/cert-manager-operator/pull/46"])
        bcve = self._make_bcve(fix_type=FixType.NON_TRIVIAL_BACKPORT)
        cve = self._make_cve(linked_prs=prs)
        assert map_to_verdict(bcve, cve) == VERDICT_FIXED

    def test_non_trivial_without_prs_returns_not_fixed(self):
        """NON_TRIVIAL_BACKPORT without PRs → NOT_FIXED."""
        bcve = self._make_bcve(fix_type=FixType.NON_TRIVIAL_BACKPORT)
        cve = self._make_cve(linked_prs="[]")
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_FIXED

    # ── Edge cases ──

    def test_empty_linked_prs_string(self):
        """Empty string linked_prs treated as no PRs."""
        bcve = self._make_bcve(fix_type=FixType.VERSION_BUMP)
        cve = self._make_cve(linked_prs="")
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_FIXED

    def test_invalid_json_linked_prs(self):
        """Invalid JSON in linked_prs treated as no PRs."""
        bcve = self._make_bcve(fix_type=FixType.VERSION_BUMP)
        cve = self._make_cve(linked_prs="not-json")
        assert map_to_verdict(bcve, cve) == VERDICT_NOT_FIXED

    def test_none_fix_type_returns_pending(self):
        """None fix_type → PENDING (not yet classified)."""
        bcve = self._make_bcve()
        bcve.fix_type = None
        cve = self._make_cve()
        assert map_to_verdict(bcve, cve) == "PENDING"


class TestVerdictMappingCompleteness:
    """Ensure all FixType enum values have a mapping path."""

    def test_all_fix_types_produce_valid_verdict(self):
        valid_verdicts = {VERDICT_FIXED, VERDICT_NOT_AFFECTED, VERDICT_REBUILD_ONLY, VERDICT_NOT_FIXED, VERDICT_FALSE_POSITIVE}
        cve = CVEEntry(
            cve_id="CVE-2026-00000",
            severity_rating="MEDIUM",
            fixed_version="v1.0.0",
            linked_prs="[]",
        )
        for ft in FixType:
            bcve = BranchCVE(
                risk_level="MEDIUM",
                dependency_type="direct",
                current_version="v0.9.0",
                symbol_reachable=True,
                fix_type=ft,
            )
            verdict = map_to_verdict(bcve, cve)
            assert verdict in valid_verdicts, f"FixType {ft} produced invalid verdict: {verdict}"
