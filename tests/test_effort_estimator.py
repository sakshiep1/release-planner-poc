"""Tests for effort estimation logic."""
from __future__ import annotations

import pytest

from src.models.fix import BranchCVE, FixType
from src.services.effort_estimator import estimate_single, aggregate_branch_effort, TSHIRT_MAP


class TestEstimateSingle:
    def test_version_bump(self):
        tshirt, hours = estimate_single(FixType.VERSION_BUMP)
        assert tshirt == "S"
        assert 2 <= hours <= 5

    def test_trivial_backport(self):
        tshirt, hours = estimate_single(FixType.TRIVIAL_BACKPORT)
        assert tshirt == "M"
        assert 5 <= hours <= 12

    def test_non_trivial_backport(self):
        tshirt, hours = estimate_single(FixType.NON_TRIVIAL_BACKPORT)
        assert tshirt == "L"
        assert 15 <= hours <= 30

    def test_needs_review(self):
        tshirt, hours = estimate_single(FixType.NEEDS_REVIEW)
        assert tshirt == "XL"
        assert hours > 20

    def test_not_applicable(self):
        tshirt, hours = estimate_single(FixType.NOT_APPLICABLE)
        assert tshirt == "-"
        assert hours == 0

    def test_critical_cvss_increases_effort(self):
        _, normal = estimate_single(FixType.TRIVIAL_BACKPORT, cvss_score=5.0)
        _, critical = estimate_single(FixType.TRIVIAL_BACKPORT, cvss_score=9.5)
        assert critical > normal


class TestAggregateBranchEffort:
    def _make_bcve(self, fix_type: FixType, hours: float, tshirt: str) -> BranchCVE:
        return BranchCVE(
            fix_type=fix_type,
            effort_hours=hours,
            effort_tshirt=tshirt,
        )

    def test_empty_list(self):
        result = aggregate_branch_effort([])
        assert result["total_hours"] == 0
        assert result["cve_count"] == 0

    def test_mixed_types(self):
        bcves = [
            self._make_bcve(FixType.VERSION_BUMP, 3.0, "S"),
            self._make_bcve(FixType.VERSION_BUMP, 3.0, "S"),
            self._make_bcve(FixType.TRIVIAL_BACKPORT, 8.0, "M"),
            self._make_bcve(FixType.NON_TRIVIAL_BACKPORT, 20.0, "L"),
        ]
        result = aggregate_branch_effort(bcves)
        assert result["cve_count"] == 4
        assert result["total_hours"] == 34.0
        assert result["breakdown"]["S"] == 2
        assert result["breakdown"]["M"] == 1
        assert result["breakdown"]["L"] == 1

    def test_overhead_multiplier_applied(self):
        bcves = [self._make_bcve(FixType.TRIVIAL_BACKPORT, 8.0, "M")]
        result = aggregate_branch_effort(bcves)
        assert result["total_with_overhead"] > result["total_hours"]
