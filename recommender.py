"""
recommender.py - Smart Tourism Recommendation & Planning Algorithms
Academic Project: SMART TOURISM PLANNING AND LOCAL GUIDE RECOMMENDATION PLATFORM

This module implements the mathematical and heuristic algorithms for:
1. Destination Compatibility Scoring (Weighted Multi-Criteria Matching)
2. Destination Recommendation & Ranking
3. Local Guide Compatibility Scoring (Multi-Factor Scoring)
4. Local Guide Recommendation & Ranking
5. Travel Budget Estimation & Variance Calculation
6. Dynamic Day-by-Day Itinerary Generation (Constraint-Satisfaction Scheduling)

All algorithms are fully deterministic, transparent, and explainable for faculty evaluation.
"""

from typing import List, Dict, Any, Optional
import math
from sample_data import (
    DESTINATIONS_DATA,
    ATTRACTIONS_DATA,
    GUIDES_DATA,
    get_destination_by_id,
    get_attractions_for_destination,
)


# ==============================================================================
# ALGORITHM 1: DESTINATION COMPATIBILITY SCORING
# ==============================================================================

def calculate_destination_match(destination: Dict[str, Any], user_preferences: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes a transparent multi-criteria compatibility score (0 - 100%)
    evaluating how well a destination satisfies the user's travel preferences.

    Mathematical Model:
    Score = (w_int * S_int + w_bud * S_bud + w_cat * S_cat + w_rat * S_rat + w_dur * S_dur) * 100

    Weights:
    - Interests Overlap (w_int) = 0.35
    - Budget Suitability (w_bud) = 0.25
    - Category Alignment (w_cat) = 0.15
    - Destination Rating (w_rat) = 0.15
    - Duration Alignment (w_dur) = 0.10
    Sum of weights = 1.00
    """
    dest_tags = set(tag.lower() for tag in destination.get("tags", []))
    user_interests = set(i.lower() for i in user_preferences.get("interests", []))

    # --- 1. Interests Overlap Score (S_int) ---
    # Combines Jaccard Similarity and Recall/Coverage
    if user_interests:
        intersection = user_interests.intersection(dest_tags)
        union = user_interests.union(dest_tags)
        jaccard = len(intersection) / len(union) if union else 0.0
        recall = len(intersection) / len(user_interests)
        # Weighted blend favoring recall: Did the destination have what the user asked for?
        s_int = 0.70 * recall + 0.30 * jaccard
        matched_tags = list(intersection)
    else:
        # Default baseline if user has no specific interests selected
        s_int = 0.80
        matched_tags = destination.get("tags", [])[:3]

    # --- 2. Budget Suitability Score (S_bud) ---
    # User budget per person vs estimated cost for the trip
    user_budget = float(user_preferences.get("budget_per_person", 10000.0))
    trip_duration = int(user_preferences.get("trip_duration", 3))
    est_trip_cost = float(destination.get("est_cost_per_day_per_person", 2200)) * trip_duration

    if user_budget <= 0:
        s_bud = 0.70
    elif est_trip_cost <= user_budget:
        # Destination is fully affordable
        ratio = est_trip_cost / user_budget
        if ratio >= 0.5:
            s_bud = 1.0  # Perfect fit within reasonable budget
        else:
            s_bud = 0.95 # Highly economical
    else:
        # Exceeds budget: apply linear decay penalty
        overrun_ratio = (est_trip_cost - user_budget) / user_budget
        s_bud = max(0.15, 1.0 - 1.5 * overrun_ratio)

    # --- 3. Category / Type Alignment (S_cat) ---
    pref_category = user_preferences.get("preferred_category", "All").strip().lower()
    dest_category = destination.get("category", "").lower()
    
    if pref_category in ["all", "", "any"]:
        s_cat = 1.0
    elif pref_category in dest_category or dest_category in pref_category:
        s_cat = 1.0
    else:
        # Partial match if any keyword matches
        pref_words = set(pref_category.replace("&", " ").split())
        dest_words = set(dest_category.replace("&", " ").split())
        if pref_words.intersection(dest_words):
            s_cat = 0.75
        else:
            s_cat = 0.35

    # --- 4. Rating Normalization (S_rat) ---
    rating = float(destination.get("rating", 4.0))
    s_rat = min(1.0, max(0.0, rating / 5.0))

    # --- 5. Duration Fit Score (S_dur) ---
    sugg_dur = int(destination.get("suggested_duration_days", 3))
    dur_diff = abs(sugg_dur - trip_duration)
    s_dur = max(0.40, 1.0 - (0.20 * dur_diff))

    # --- Composite Score Calculation ---
    w_int, w_bud, w_cat, w_rat, w_dur = 0.35, 0.25, 0.15, 0.15, 0.10
    composite_score = (
        (w_int * s_int) +
        (w_bud * s_bud) +
        (w_cat * s_cat) +
        (w_rat * s_rat) +
        (w_dur * s_dur)
    ) * 100.0

    # Round to 1 decimal place
    composite_score = round(min(99.5, max(15.0, composite_score)), 1)

    # --- Natural Language Match Explanation ---
    reasons = []
    if matched_tags:
        reasons.append(f"Matches your interest in {', '.join(t.capitalize() for t in matched_tags[:3])}")
    if est_trip_cost <= user_budget:
        reasons.append(f"Comfortably fits budget (~₹{int(est_trip_cost):,} for {trip_duration} days)")
    else:
        reasons.append(f"Slightly above target budget (Est. ₹{int(est_trip_cost):,})")
    
    if s_cat >= 0.75 and pref_category not in ["all", "", "any"]:
        reasons.append(f"Aligns with '{destination.get('category')}' style")
    
    reasons.append(f"Rated {rating}★ with {destination.get('reviews_count', 0):,} traveler reviews")

    return {
        "destination_id": destination["id"],
        "compatibility_score": composite_score,
        "score_breakdown": {
            "interests_score": round(s_int * 100, 1),
            "budget_score": round(s_bud * 100, 1),
            "category_score": round(s_cat * 100, 1),
            "rating_score": round(s_rat * 100, 1),
            "duration_score": round(s_dur * 100, 1)
        },
        "component_scores": {
            "interests_score": s_int,
            "budget_score": s_bud,
            "category_score": s_cat,
            "rating_score": s_rat,
            "duration_score": s_dur
        },
        "matched_tags": matched_tags,
        "estimated_trip_cost": int(est_trip_cost),
        "primary_reason": reasons[0] if reasons else "Well-rounded tourist destination",
        "detailed_reasons": reasons
    }


# ==============================================================================
# ALGORITHM 2: DESTINATION RECOMMENDATION & RANKING
# ==============================================================================

def recommend_destinations(
    user_preferences: Dict[str, Any],
    destinations: Optional[List[Dict[str, Any]]] = None,
    min_score: float = 0.0,
    top_k: int = 12
) -> List[Dict[str, Any]]:
    """
    Ranks all destinations according to user preferences using the multi-criteria
    scoring engine. Supports real-time filtering by state, search query, and category.
    """
    if destinations is None:
        destinations = DESTINATIONS_DATA

    search_query = user_preferences.get("search_query", "").strip().lower()
    selected_state = user_preferences.get("state_filter", "All").strip()

    ranked_results = []
    for dest in destinations:
        # Filter by state if specified
        if selected_state != "All" and dest.get("state") != selected_state:
            continue

        # Filter by text search query across name, state, category, and tags
        if search_query:
            query_match = (
                search_query in dest["name"].lower()
                or search_query in dest.get("state", "").lower()
                or search_query in dest.get("category", "").lower()
                or any(search_query in t.lower() for t in dest.get("tags", []))
            )
            if not query_match:
                continue

        # Calculate compatibility
        match_info = calculate_destination_match(dest, user_preferences)
        if match_info["compatibility_score"] >= min_score:
            combined = {**dest, **match_info}
            ranked_results.append(combined)

    # Sort descending by compatibility score
    ranked_results.sort(key=lambda x: x["compatibility_score"], reverse=True)
    return ranked_results[:top_k]


# ==============================================================================
# ALGORITHM 3: LOCAL GUIDE COMPATIBILITY SCORING
# ==============================================================================

def calculate_guide_match(guide: Dict[str, Any], user_preferences: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes a guide compatibility score (0 - 100%) based on:
    1. Geographic / Service Area Compatibility (w_city = 0.30)
    2. Spoken Language Alignment (w_lang = 0.25)
    3. Expertise Specialization Alignment (w_exp = 0.20)
    4. Verified Rating & Experience Weight (w_rat = 0.15)
    5. Daily Rate / Budget Suitability (w_bud = 0.10)
    """
    target_city = user_preferences.get("destination_city", "").strip().lower()
    pref_language = user_preferences.get("language", "All").strip()
    pref_expertise = user_preferences.get("expertise", "All").strip()
    max_budget_per_day = float(user_preferences.get("max_budget_per_day", 3000.0))

    # --- 1. Service Area Match (S_city) ---
    guide_areas = [a.lower() for a in guide.get("service_areas", [])]
    guide_city = guide.get("city", "").lower()

    if not target_city or target_city == "all":
        s_city = 0.85
    elif target_city in guide_city or any(target_city in area for area in guide_areas):
        s_city = 1.0  # Exact city operation
    else:
        # Not operating in target city
        s_city = 0.15

    # --- 2. Language Match (S_lang) ---
    guide_langs = [l.lower() for l in guide.get("languages", [])]
    if pref_language.lower() in ["all", "", "any"]:
        s_lang = 0.90
    elif pref_language.lower() in guide_langs:
        s_lang = 1.0
    else:
        s_lang = 0.20

    # --- 3. Expertise Match (S_exp) ---
    guide_primary_exp = guide.get("primary_expertise", "").lower()
    guide_all_exp = [e.lower() for e in guide.get("all_expertise", [])]
    
    if pref_expertise.lower() in ["all", "", "any"]:
        s_exp = 0.90
    elif pref_expertise.lower() in guide_primary_exp:
        s_exp = 1.0
    elif any(pref_expertise.lower() in e for e in guide_all_exp):
        s_exp = 0.80
    else:
        s_exp = 0.30

    # --- 4. Rating & Experience Score (S_rat) ---
    rating = float(guide.get("rating", 4.0))
    experience_yrs = int(guide.get("experience_years", 5))
    rating_norm = min(1.0, rating / 5.0)
    exp_norm = min(1.0, experience_yrs / 15.0)
    s_rat = 0.70 * rating_norm + 0.30 * exp_norm

    # --- 5. Budget Suitability (S_bud) ---
    fee = float(guide.get("fee_per_day_inr", 2000.0))
    if max_budget_per_day <= 0:
        s_bud = 0.80
    elif fee <= max_budget_per_day:
        s_bud = 1.0
    else:
        over = (fee - max_budget_per_day) / max_budget_per_day
        s_bud = max(0.10, 1.0 - 2.0 * over)

    # --- Composite Score ---
    w_city, w_lang, w_exp, w_rat, w_bud = 0.30, 0.25, 0.20, 0.15, 0.10
    composite_score = (
        (w_city * s_city) +
        (w_lang * s_lang) +
        (w_exp * s_exp) +
        (w_rat * s_rat) +
        (w_bud * s_bud)
    ) * 100.0

    composite_score = round(min(99.8, max(20.0, composite_score)), 1)

    # Match explanation rationale
    reasons = []
    if s_city >= 0.9:
        reasons.append(f"Operating locally in {guide.get('city')}")
    if s_lang >= 0.9 and pref_language not in ["All", "", "any"]:
        reasons.append(f"Fluent in requested language ({pref_language})")
    if s_exp >= 0.8 and pref_expertise not in ["All", "", "any"]:
        reasons.append(f"Specialist in {guide.get('primary_expertise')}")
    if fee <= max_budget_per_day:
        reasons.append(f"Affordable rate of ₹{int(fee):,}/day (Within ₹{int(max_budget_per_day):,} limit)")
    else:
        reasons.append(f"Fee: ₹{int(fee):,}/day")
    reasons.append(f"{experience_yrs}+ yrs experience ({guide.get('tours_completed', 0)} tours conducted)")

    return {
        "guide_id": guide["id"],
        "compatibility_score": composite_score,
        "score_breakdown": {
            "location_score": round(s_city * 100, 1),
            "language_score": round(s_lang * 100, 1),
            "expertise_score": round(s_exp * 100, 1),
            "rating_experience_score": round(s_rat * 100, 1),
            "budget_score": round(s_bud * 100, 1),
        },
        "match_reasons": reasons,
        "summary_reason": "; ".join(reasons[:2])
    }


# ==============================================================================
# ALGORITHM 4: LOCAL GUIDE RECOMMENDATION & RANKING
# ==============================================================================

def recommend_local_guides(
    user_preferences: Dict[str, Any],
    guides: Optional[List[Dict[str, Any]]] = None,
    min_rating: float = 0.0,
    top_k: int = 10
) -> List[Dict[str, Any]]:
    """
    Ranks local guides according to city, language, expertise, budget, and rating constraints.
    """
    if guides is None:
        guides = GUIDES_DATA

    target_city = user_preferences.get("destination_city", "").strip().lower()
    max_budget = float(user_preferences.get("max_budget_per_day", 0.0))

    scored_guides = []
    for g in guides:
        if float(g.get("rating", 0.0)) < min_rating:
            continue

        fee = float(g.get("fee_per_day_inr", 0.0))
        # Filter out if budget cap is set and fee exceeds budget
        if max_budget > 0 and fee > max_budget:
            continue

        # If user selected a specific city, guide MUST operate in that city
        if target_city and target_city != "all":
            guide_areas = [a.lower() for a in g.get("service_areas", [])]
            if target_city not in g.get("city", "").lower() and not any(target_city in a for a in guide_areas):
                continue

        match_info = calculate_guide_match(g, user_preferences)
        combined = {**g, **match_info}
        scored_guides.append(combined)

    scored_guides.sort(key=lambda x: x["compatibility_score"], reverse=True)
    return scored_guides[:top_k]


# ==============================================================================
# ALGORITHM 5: BUDGET ESTIMATION & VARIANCE ANALYSIS
# ==============================================================================

def calculate_budget(
    destination: Optional[Dict[str, Any]] = None,
    duration_days: int = 3,
    num_travelers: Optional[int] = None,
    travelers: Optional[int] = None,
    travel_pace: str = "Moderate",
    total_budget: Optional[float] = None,
    allocated_budget: Optional[float] = None,
    attraction_ticket_total: Optional[float] = None,
    attraction_tickets_cost: Optional[float] = None,
    base_daily_cost: Optional[float] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Generates an itemized budget calculation considering:
    - Accommodation (per room, assuming double occupancy)
    - Food & Beverages (per traveler per day)
    - Local Transport & Sightseeing Commute (per group per day)
    - Activity & Monument Entry Tickets (calculated from scheduled attractions)
    - Miscellaneous & Contingency Reserve (8% of subtotal)

    Compares estimated expenses with user budget and generates variance analysis.
    """
    actual_travelers = travelers if travelers is not None else (num_travelers if num_travelers is not None else 2)
    actual_budget = allocated_budget if allocated_budget is not None else (total_budget if total_budget is not None else 25000.0)
    actual_ticket_cost = attraction_tickets_cost if attraction_tickets_cost is not None else (attraction_ticket_total if attraction_ticket_total is not None else 0.0)

    if duration_days < 1:
        raise ValueError("Travel duration must be at least 1 day.")
    if actual_travelers < 1:
        raise ValueError("Number of travelers must be at least 1.")
    if actual_budget <= 0:
        raise ValueError("Trip budget must be greater than zero.")

    rooms_needed = max(1, math.ceil(actual_travelers / 2))
    
    # Base daily rates depend on destination cost tier and travel pace
    if destination is not None and isinstance(destination, dict) and "est_cost_per_day_per_person" in destination:
        base_dest_cost = float(destination.get("est_cost_per_day_per_person", 2200))
    elif base_daily_cost is not None:
        base_dest_cost = float(base_daily_cost)
    else:
        base_dest_cost = 2200.0

    # Pace multipliers
    pace_multipliers = {
        "Relaxed": 0.85,    # fewer activities, boutique/relaxed stays
        "Moderate": 1.00,   # balanced
        "Fast-paced": 1.15  # more taxis, rapid transit, high activity count
    }
    pace_mult = pace_multipliers.get(travel_pace, 1.0)

    # 1. Stay/Accommodation (per room per night)
    hotel_rate_per_night = (base_dest_cost * 0.90) * pace_mult
    total_accommodation = hotel_rate_per_night * rooms_needed * duration_days

    # 2. Food & Dining (per traveler per day: Breakfast, lunch, dinner, snacks)
    food_rate_per_person_day = (base_dest_cost * 0.40) * pace_mult
    total_food = food_rate_per_person_day * actual_travelers * duration_days

    # 3. Local Transit (auto-rickshaws, cabs, metro passes)
    transit_per_day = (base_dest_cost * 0.35) * pace_mult * (1 + (actual_travelers - 1) * 0.3)
    total_transit = transit_per_day * duration_days

    # 4. Activities & Entry Tickets
    total_tickets = actual_ticket_cost * actual_travelers

    # 5. Miscellaneous & Souvenirs buffer (8%)
    subtotal = total_accommodation + total_food + total_transit + total_tickets
    contingency = subtotal * 0.08
    total_estimated_cost = round(subtotal + contingency)

    # Budget Variance
    variance = round(actual_budget - total_estimated_cost)
    cost_per_traveler = round(total_estimated_cost / max(1, actual_travelers))

    if variance >= 0:
        budget_status = "Within Budget"
        status_color = "success"
        status_message = f"✅ Excellent! Estimated trip cost is ₹{abs(variance):,} UNDER your specified budget."
    elif abs(variance) <= (actual_budget * 0.15):
        budget_status = "Slightly Exceeded (Within 15%)"
        status_color = "warning"
        status_message = f"⚠️ Estimated cost exceeds budget slightly by ₹{abs(variance):,}. Easily manageable by choosing budget accommodation."
    else:
        budget_status = "Significantly Exceeded"
        status_color = "error"
        status_message = f"❌ Estimated expenses exceed budget by ₹{abs(variance):,}. Significant Deficit detected. Consider extending budget or reducing duration/travelers."

    return {
        "total_budget": round(actual_budget),
        "total_estimated_cost": total_estimated_cost,
        "variance": variance,
        "cost_per_traveler": cost_per_traveler,
        "budget_status": budget_status,
        "status_color": status_color,
        "status_message": status_message,
        "breakdown": {
            "Accommodation": round(total_accommodation),
            "Food & Dining": round(total_food),
            "Local Transportation": round(total_transit),
            "Sightseeing & Tickets": round(total_tickets),
            "Contingency Reserve (8%)": round(contingency)
        },
        "breakdown_percentages": {
            "Accommodation": round((total_accommodation / total_estimated_cost) * 100, 1),
            "Food & Dining": round((total_food / total_estimated_cost) * 100, 1),
            "Local Transportation": round((total_transit / total_estimated_cost) * 100, 1),
            "Sightseeing & Tickets": round((total_tickets / total_estimated_cost) * 100, 1),
            "Contingency Reserve (8%)": round((contingency / total_estimated_cost) * 100, 1),
        }
    }


# ==============================================================================
# ALGORITHM 6: DYNAMIC DAY-BY-DAY ITINERARY GENERATION
# ==============================================================================

def generate_itinerary(
    destination_id: str,
    duration_days: int,
    travelers: int,
    budget: float,
    interests: List[str],
    travel_pace: str = "Moderate"
) -> Dict[str, Any]:
    """
    Generates a personalized, time-slot scheduled day-by-day travel plan.
    Prioritizes attractions that match user interests and balances daily schedules.

    Validation rules:
    - Duration between 1 and 10 days
    - Travelers between 1 and 20
    - Budget > 0
    - Valid destination
    """
    # 1. Validation
    if duration_days < 1:
        raise ValueError("Travel duration must be at least 1 day.")
    if duration_days > 14:
        raise ValueError("Travel duration can be at most 14 days for this planner.")
    if travelers < 1:
        raise ValueError("Number of travelers must be at least 1.")
    if budget <= 0:
        raise ValueError("Trip budget must be greater than zero.")

    valid_dest_ids = [d["id"].lower() for d in DESTINATIONS_DATA] + [d["name"].lower() for d in DESTINATIONS_DATA]
    if destination_id.strip().lower() not in valid_dest_ids:
        raise ValueError(f"Destination with ID '{destination_id}' was not found in registered database.")

    destination = get_destination_by_id(destination_id)
    all_attractions = get_attractions_for_destination(destination_id)

    # 2. Prioritize attractions matching user interests
    user_interest_set = set(i.lower() for i in interests)

    def score_attraction(attr: Dict[str, Any]) -> float:
        attr_tags = set(t.lower() for t in attr.get("tags", []))
        overlap = len(attr_tags.intersection(user_interest_set))
        rating = attr.get("rating", 4.0)
        # Interest match gives huge boost (3.0 pts per matched tag), rating gives tie-breaker
        return (overlap * 3.0) + rating

    scored_attractions = sorted(all_attractions, key=score_attraction, reverse=True)

    # Slots per day according to pace
    slots_map = {
        "Relaxed": ["Morning", "Evening"],
        "Moderate": ["Morning", "Afternoon", "Evening"],
        "Fast-paced": ["Morning", "Afternoon", "Evening", "Night Experience"]
    }
    daily_slots = slots_map.get(travel_pace, ["Morning", "Afternoon", "Evening"])

    # 3. Schedule attractions across days
    itinerary_days = []
    used_attraction_ids = set()
    total_ticket_cost_per_person = 0.0

    # Categorize attractions by time-slot preference
    morning_pool = [a for a in scored_attractions if a.get("suggested_time_slot") == "Morning"]
    afternoon_pool = [a for a in scored_attractions if a.get("suggested_time_slot") == "Afternoon"]
    evening_pool = [a for a in scored_attractions if a.get("suggested_time_slot") == "Evening"]

    day_themes = [
        "Heritage & Cultural Immersion",
        "Coastal Breezes & Scenic Marvels",
        "Artisans, Architecture & Cuisine",
        "Spiritual Exploration & Hidden Gems",
        "Nature Retreat & Sunset Trails",
        "Local Markets & Modern Delights",
        "Culinary Discoveries & Leisure"
    ]

    for day_num in range(1, duration_days + 1):
        day_schedule = []
        day_ticket_cost = 0

        for slot in daily_slots:
            chosen = None

            # Pick from matching pool if available and not used
            if slot == "Morning":
                for cand in morning_pool:
                    if cand["id"] not in used_attraction_ids:
                        chosen = cand
                        break
            elif slot == "Afternoon":
                for cand in afternoon_pool:
                    if cand["id"] not in used_attraction_ids:
                        chosen = cand
                        break
            elif slot in ["Evening", "Night Experience"]:
                for cand in evening_pool:
                    if cand["id"] not in used_attraction_ids:
                        chosen = cand
                        break

            # Fallback to general pool if slot-specific pool exhausted
            if not chosen:
                for cand in scored_attractions:
                    if cand["id"] not in used_attraction_ids:
                        chosen = cand
                        break

            # If all attractions exhausted, reuse flagship attraction with a new leisure context
            if not chosen and scored_attractions:
                repeat_cand = scored_attractions[(day_num + len(day_schedule)) % len(scored_attractions)]
                chosen = {
                    **repeat_cand,
                    "name": f"{repeat_cand['name']} (Extended Exploration)",
                    "insider_tip": "Explore surrounding artisanal shops, local tea stalls, and photography angles."
                }

            if chosen:
                used_attraction_ids.add(chosen["id"])
                fee = chosen.get("entry_fee_inr", 0)
                day_ticket_cost += fee
                total_ticket_cost_per_person += fee

                day_schedule.append({
                    "slot": slot,
                    "attraction_id": chosen["id"],
                    "attraction_name": chosen["name"],
                    "category": chosen.get("category", "sightseeing"),
                    "duration_hours": chosen.get("duration_hours", 2.0),
                    "entry_fee_inr": fee,
                    "rating": chosen.get("rating", 4.5),
                    "description": chosen.get("description", ""),
                    "insider_tip": chosen.get("insider_tip", "Carry water and comfortable walking footwear.")
                })

        theme_title = day_themes[(day_num - 1) % len(day_themes)]
        itinerary_days.append({
            "day_number": day_num,
            "theme": f"Day {day_num}: {theme_title}",
            "schedule": day_schedule,
            "day_ticket_cost_per_person": day_ticket_cost
        })

    # 4. Compute comprehensive budget
    budget_details = calculate_budget(
        destination=destination,
        duration_days=duration_days,
        num_travelers=travelers,
        travel_pace=travel_pace,
        total_budget=budget,
        attraction_ticket_total=total_ticket_cost_per_person
    )

    return {
        "destination": destination,
        "duration_days": duration_days,
        "travelers": travelers,
        "travel_pace": travel_pace,
        "selected_interests": interests,
        "days": itinerary_days,
        "budget_analysis": budget_details,
        "total_attractions_planned": len(used_attraction_ids)
    }
