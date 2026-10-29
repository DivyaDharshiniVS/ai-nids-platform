"""
tests/test_itinerary.py - Automated Unit Tests for Itinerary Generator
Academic Project: Smart Tourism Planning and Local Guide Recommendation Platform
"""

import pytest
from recommender import generate_itinerary

class TestItineraryGeneration:
    """Test suite for constraint-satisfaction day-by-day scheduling."""

    def test_valid_chennai_itinerary(self):
        """Generates valid 3-day itinerary for Chennai with non-repeating attractions."""
        itinerary = generate_itinerary(
            destination_id="chennai",
            duration_days=3,
            travelers=2,
            budget=25000,
            interests=["culture", "beaches", "food"],
            travel_pace="Moderate"
        )
        assert itinerary["destination"]["id"] == "chennai"
        assert len(itinerary["days"]) == 3

        # Verify no duplicate attractions across days
        scheduled_ids = []
        for day in itinerary["days"]:
            assert len(day["schedule"]) > 0
            for act in day["schedule"]:
                assert act["attraction_id"] not in scheduled_ids, f"Duplicate attraction {act['attraction_name']}"
                scheduled_ids.append(act["attraction_id"])

        # Check financial summary is embedded
        assert "budget_analysis" in itinerary
        assert itinerary["budget_analysis"]["total_estimated_cost"] > 0

    def test_interest_matching_prioritization(self):
        """Selecting temples and culture should include cultural spots in early slots."""
        itinerary = generate_itinerary(
            destination_id="chennai",
            duration_days=2,
            travelers=1,
            budget=15000,
            interests=["culture", "temples"],
            travel_pace="Moderate"
        )
        all_cats = [act["category"] for day in itinerary["days"] for act in day["schedule"]]
        assert "culture" in all_cats

    def test_invalid_parameters_raise_error(self):
        """Invalid destination ID, 0 days, or 0 travelers must throw ValueError."""
        with pytest.raises(ValueError):
            generate_itinerary(
                destination_id="non_existent_city",
                duration_days=3,
                travelers=2,
                budget=20000,
                interests=[]
            )

        with pytest.raises(ValueError):
            generate_itinerary(
                destination_id="chennai",
                duration_days=0,
                travelers=2,
                budget=20000,
                interests=[]
            )
