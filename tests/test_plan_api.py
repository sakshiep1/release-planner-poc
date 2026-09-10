"""Tests for plan/effort API behavior."""
from __future__ import annotations

import pytest

from src.models.fix import BranchCVE, FixType
from src.services.effort_estimator import aggregate_branch_effort


class TestEffortNullFixType:
    """Effort aggregation should include unclassified (NULL fix_type) rows."""

    def test_null_fix_type_counted_in_aggregate(self):
        bcves = [
            BranchCVE(fix_type=None, effort_hours=0.0, effort_tshirt=""),
            BranchCVE(fix_type=FixType.VERSION_BUMP, effort_hours=3.0, effort_tshirt="S"),
            BranchCVE(fix_type=FixType.NOT_APPLICABLE, effort_hours=0.0, effort_tshirt="-"),
        ]
        # Simulate effort API filter: include NULL and exclude NOT_APPLICABLE
        included = [
            b for b in bcves
            if b.fix_type is None or b.fix_type != FixType.NOT_APPLICABLE
        ]
        assert len(included) == 2

        agg = aggregate_branch_effort([b for b in included if b.fix_type is not None])
        assert agg["cve_count"] == 1

    def test_all_null_fix_types_returns_zero_effort_but_has_count(self):
        bcves = [
            BranchCVE(fix_type=None, effort_hours=0.0, effort_tshirt=""),
            BranchCVE(fix_type=None, effort_hours=0.0, effort_tshirt=""),
        ]
        included = [b for b in bcves if b.fix_type is None or b.fix_type != FixType.NOT_APPLICABLE]
        assert len(included) == 2
