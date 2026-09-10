"""Tests for plan generator urgency logic."""
from __future__ import annotations

from src.services.plan_generator import _urgency_from_cvss


class TestUrgencyFromCVSS:
    def test_critical_score(self):
        assert _urgency_from_cvss(9.6) == "CRITICAL"

    def test_high_score(self):
        assert _urgency_from_cvss(7.5) == "HIGH"

    def test_medium_score(self):
        assert _urgency_from_cvss(5.8) == "ROUTINE"

    def test_low_score(self):
        assert _urgency_from_cvss(2.0) == "ROUTINE"

    def test_boundary_9(self):
        assert _urgency_from_cvss(9.0) == "CRITICAL"

    def test_boundary_7(self):
        assert _urgency_from_cvss(7.0) == "HIGH"

    def test_none_score(self):
        assert _urgency_from_cvss(None) == "ROUTINE"
