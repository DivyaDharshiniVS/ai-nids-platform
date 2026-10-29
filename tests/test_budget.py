"""
tests/test_budget.py - Automated Unit Tests for Budget Calculator Logic
Academic Project: Smart Tourism Planning and Local Guide Recommendation Platform
"""

import pytest
from recommender import calculate_budget

class TestBudgetCalculations:
    """Test suite for financial calculations, expense breakdown, and variance analysis."""

    def test_within_budget_calculation(self):
        """Standard budget should compute accurate totals, per-person rates, and positive variance."""
        result = calculate_budget(
            duration_days=3,
            travelers=2,
            allocated_budget=30000.0,
            base_daily_cost=2200.0,
            attraction_tickets_cost=1500.0,
            travel_pace="Moderate"
        )
        assert result["total_budget"] == 30000.0
        assert result["total_estimated_cost"] > 0
        assert result["cost_per_traveler"] == round(result["total_estimated_cost"] / 2)
        assert result["variance"] == 30000.0 - result["total_estimated_cost"]
        assert result["budget_status"] == "Within Budget"
        assert result["breakdown"]["Accommodation"] > 0
        assert result["breakdown"]["Food & Dining"] > 0
        assert result["breakdown"]["Local Transportation"] > 0

    def test_deficit_budget_calculation(self):
        """Underfunded budget should detect deficit and set status to Exceeded."""
        result = calculate_budget(
            duration_days=4,
            travelers=4,
            allocated_budget=5000.0,  # Far too low for 4 travelers over 4 days
            base_daily_cost=3000.0,
            attraction_tickets_cost=2000.0
        )
        assert result["variance"] < 0
        assert result["budget_status"] == "Significantly Exceeded"
        assert "Deficit" in result["status_message"]

    def test_zero_or_negative_validation(self):
        """Zero travelers or days should raise ValueError preventing division by zero."""
        with pytest.raises(ValueError):
            calculate_budget(duration_days=0, travelers=2, allocated_budget=20000)

        with pytest.raises(ValueError):
            calculate_budget(duration_days=3, travelers=0, allocated_budget=20000)

        with pytest.raises(ValueError):
            calculate_budget(duration_days=3, travelers=2, allocated_budget=-1000)

    def test_pace_multiplier_effect(self):
        """Fast-paced travel should incur higher transport and sightseeing costs than relaxed."""
        relaxed = calculate_budget(
            duration_days=3, travelers=2, allocated_budget=30000,
            base_daily_cost=2000, travel_pace="Relaxed"
        )
        fast = calculate_budget(
            duration_days=3, travelers=2, allocated_budget=30000,
            base_daily_cost=2000, travel_pace="Fast-paced"
        )
        assert fast["total_estimated_cost"] > relaxed["total_estimated_cost"]
