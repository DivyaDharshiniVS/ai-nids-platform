"""
tests/test_recommendations.py - Automated Unit Tests for Recommendation Engine
Academic Project: Smart Tourism Planning and Local Guide Recommendation Platform
"""

import pytest
from recommender import (
    calculate_destination_match,
    recommend_destinations,
    calculate_guide_match,
    recommend_local_guides,
)
from sample_data import DESTINATIONS_DATA, GUIDES_DATA

class TestDestinationRecommendations:
    """Test suite for destination matching and ranking algorithms."""

    def test_cultural_destination_ranking(self):
        """Cultural query should prioritize heritage cities like Chennai/Varanasi/Madurai."""
        pref = {
            "interests": ["culture", "history", "temples"],
            "budget_per_person": 12000,
            "trip_duration": 3,
            "preferred_category": "Coastal & Heritage"
        }
        results = recommend_destinations(pref, top_k=5)
        assert len(results) > 0, "Should return matching destinations"
        top = results[0]
        assert top["compatibility_score"] >= 70.0
        assert "primary_reason" in top
        assert top["id"] in ["chennai", "mahabalipuram", "madurai", "varanasi", "jaipur"]

    def test_beach_and_adventure_ranking(self):
        """Beach/relaxation preference should dynamically rank Goa/Kanyakumari at the top."""
        pref = {
            "interests": ["beaches", "relaxation", "adventure"],
            "budget_per_person": 15000,
            "trip_duration": 4,
            "preferred_category": "Beach & Leisure"
        }
        results = recommend_destinations(pref, top_k=5)
        assert len(results) > 0
        top = results[0]
        assert top["id"] == "goa"
        assert top["compatibility_score"] >= 80.0

    def test_budget_constraint_penalty(self):
        """An unrealistically low budget should appropriately penalize high-cost destinations."""
        low_budget_pref = {
            "interests": ["beaches", "adventure"],
            "budget_per_person": 1500,  # Below Goa daily cost * 3 days
            "trip_duration": 3,
            "preferred_category": "All"
        }
        results = recommend_destinations(low_budget_pref)
        goa_rec = next((d for d in results if d["id"] == "goa"), None)
        assert goa_rec is not None
        assert goa_rec["component_scores"]["budget_score"] < 0.70

    def test_empty_interests_fallback(self):
        """System must handle empty interests safely without failing."""
        empty_pref = {
            "interests": [],
            "budget_per_person": 10000,
            "trip_duration": 2,
            "preferred_category": "All"
        }
        results = recommend_destinations(empty_pref)
        assert len(results) > 0
        for r in results:
            assert r["compatibility_score"] > 0


class TestGuideRecommendations:
    """Test suite for local guide matching and ranking algorithms."""

    def test_exact_city_and_language_match(self):
        """Guide in Chennai speaking Tamil should rank very high for Chennai trip."""
        query = {
            "destination_city": "Chennai",
            "language": "Tamil",
            "expertise": "Heritage & Architecture",
            "max_budget_per_day": 2500
        }
        matches = recommend_local_guides(query, min_rating=4.0)
        assert len(matches) > 0
        top_guide = matches[0]
        assert "Chennai" in top_guide["service_areas"]
        assert "Tamil" in top_guide["languages"]
        assert top_guide["compatibility_score"] >= 85.0

    def test_budget_cap_exclusion(self):
        """Guides charging more than the strict budget cap should be excluded."""
        strict_budget_query = {
            "destination_city": "All",
            "language": "All",
            "expertise": "All",
            "max_budget_per_day": 1500  # Low budget cap
        }
        matches = recommend_local_guides(strict_budget_query, min_rating=4.0)
        for g in matches:
            assert g["fee_per_day_inr"] <= 1500, f"Guide {g['name']} exceeded budget cap!"

    def test_no_matches_edge_case(self):
        """When an impossible combination is requested, return empty list gracefully."""
        impossible_query = {
            "destination_city": "NonExistentCity",
            "language": "Latin",
            "expertise": "Rocketry",
            "max_budget_per_day": 500
        }
        matches = recommend_local_guides(impossible_query, min_rating=4.9)
        assert matches == []
