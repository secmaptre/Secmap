"""Regression tests for severity / actor / confidence scoring (lex.scoring)."""
from lex.scoring import (
    score_severity,
    score_confidence,
    extract_actors,
    quality_score,
    corroboration_key,
    same_event,
    CATEGORIES,
    KNOWN_ACTORS,
    ACTOR_TIER,
    SEVERITY_MAP,
)


class TestScoreSeverity:
    def test_base_from_map(self):
        assert score_severity("Demo/Kundgebung", "") == 2
        assert score_severity("Schmiererei", "") == 1
        assert score_severity("Brandanschlag", "") == 5

    def test_unknown_category_defaults_to_one(self):
        assert score_severity("Nonexistent", "") == 1

    def test_injury_escalates(self):
        # Sachbeschädigung base 3, +1 for "verletzt" = 4
        assert score_severity("Sachbeschädigung", "Eine Person wurde verletzt") == 4

    def test_fatality_escalates_more(self):
        # base 3 +2 for fatality, capped at 5
        assert score_severity("Sachbeschädigung", "Ein Mensch wurde getötet") == 5

    def test_incendiary_weapon_escalates(self):
        # Sabotage base 4, +1 for molotow = 5
        assert score_severity("Sabotage", "mit einem Molotow-Cocktail") == 5

    def test_high_damage_amount_escalates(self):
        # Besetzung base 3, +1 for >=100k euro
        assert score_severity("Besetzung", "Schaden von 250.000 Euro") == 4

    def test_capped_at_five(self):
        assert score_severity("Brandanschlag", "getötet molotow 2.000.000 Euro koordiniert") == 5


class TestScoreConfidence:
    def test_authority_is_five(self):
        assert score_confidence("verfassungsschutz.de") == 5
        assert score_confidence("https://justice.gov/press") == 5

    def test_mainstream_is_four(self):
        assert score_confidence("tagesschau.de") == 4

    def test_scene_source_is_two(self):
        assert score_confidence("barrikade.info") == 2

    def test_movement_outlet_is_one(self):
        assert score_confidence("perspektive-online.net") == 1

    def test_unknown_defaults_to_two(self):
        assert score_confidence("some-random-blog.xyz") == 2
        assert score_confidence("") == 2
        assert score_confidence(None) == 2


class TestExtractActors:
    def test_known_actor_matched(self):
        assert "Vulkangruppe" in extract_actors("Bekennerschreiben der Vulkangruppe")

    def test_hammerbande_maps_to_lina_e_network(self):
        # "hammerbande" is a pattern alias for the publicly-prosecuted Lina E. complex.
        assert "Lina E. Netzwerk" in extract_actors("Prozess gegen die Hammerbande")

    def test_multiple_actors(self):
        out = extract_actors("Vulkangruppe und Rote Flora")
        assert "Vulkangruppe" in out
        assert "Rote Flora" in out

    def test_no_actor_returns_empty(self):
        assert extract_actors("Ein gewöhnlicher Vorfall ohne Gruppe") == ""

    def test_empty_safe(self):
        assert extract_actors("") == ""
        assert extract_actors(None) == ""


class TestQualityScore:
    def test_unverified_floor(self):
        # No signals at all → unverified, score 0.
        r = quality_score()
        assert r["score"] == 0
        assert r["label"] == "unverified"

    def test_convicted_is_court_confirmed(self):
        # A conviction always reads as court-confirmed regardless of score band.
        r = quality_score(confidence=2, prosec_status="convicted",
                           case_ref="OLG Dresden 4 OJs 9/21")
        assert r["label"] == "court-confirmed"

    def test_authority_source_with_case_and_evidence_is_strong(self):
        r = quality_score(confidence=5, prosec_status="charged",
                          case_ref="Fulton County 23SC183872", has_evidence=True)
        # 40 + 20 + 25 + 15 = 100
        assert r["score"] == 100
        assert r["label"] in ("strong", "court-confirmed")

    def test_scene_source_single_uncorroborated_is_weak_or_unverified(self):
        # confidence 2 (scene), no case, no evidence, no corroboration → 16.
        r = quality_score(confidence=2)
        assert r["score"] == 16
        assert r["label"] == "unverified"

    def test_corroboration_raises_score(self):
        low = quality_score(confidence=2, corroboration=0)["score"]
        high = quality_score(confidence=2, corroboration=2)["score"]
        assert high > low
        assert high - low == 20

    def test_score_capped_at_100(self):
        r = quality_score(confidence=5, prosec_status="convicted",
                          case_ref="X", has_evidence=True, corroboration=2)
        assert r["score"] == 100

    def test_corroboration_clamped(self):
        # More than 2 extra sources should not exceed the 2-source bonus.
        a = quality_score(confidence=1, corroboration=2)["score"]
        b = quality_score(confidence=1, corroboration=9)["score"]
        assert a == b

    def test_components_present(self):
        r = quality_score(confidence=3, case_ref="ref")
        assert set(r["components"]) == {
            "source", "case_ref", "prosecution", "evidence", "corroboration"
        }


class TestCorroboration:
    def _evt(self, **kw):
        base = {"country": "DE", "category": "Brandanschlag",
                "location": "Leipzig", "date": "2024-05-01", "source": "a"}
        base.update(kw)
        return base

    def test_same_event_distinct_sources(self):
        a = self._evt(source="tagesschau.de")
        b = self._evt(source="spiegel.de", date="2024-05-02")
        assert same_event(a, b) is True

    def test_location_substring_match(self):
        # "Leipzig" vs "Leipzig-Connewitz" should count as the same place.
        a = self._evt(location="Leipzig")
        b = self._evt(location="Leipzig-Connewitz")
        assert same_event(a, b) is True

    def test_outside_date_window_no_match(self):
        a = self._evt(date="2024-05-01")
        b = self._evt(date="2024-05-20")
        assert same_event(a, b) is False

    def test_different_category_no_match(self):
        a = self._evt(category="Brandanschlag")
        b = self._evt(category="Sabotage")
        assert same_event(a, b) is False

    def test_different_country_no_match(self):
        a = self._evt(country="DE")
        b = self._evt(country="AT")
        assert same_event(a, b) is False

    def test_unparseable_date_no_match(self):
        a = self._evt(date="")
        b = self._evt(date="2024-05-01")
        assert same_event(a, b) is False

    def test_missing_location_no_match(self):
        a = self._evt(location="")
        b = self._evt(location="Leipzig")
        assert same_event(a, b) is False

    def test_corroboration_key_normalizes(self):
        assert corroboration_key("de", "Brandanschlag") == ("DE", "Brandanschlag")


class TestDataIntegrity:
    def test_actor_tier_covers_all_actors(self):
        assert len(ACTOR_TIER) == len(KNOWN_ACTORS)

    def test_tiers_are_valid(self):
        assert set(ACTOR_TIER.values()) <= {"act", "enable", "endorse"}

    def test_severity_map_keys_are_categories(self):
        # Every severity-mapped category is a known category.
        for cat in SEVERITY_MAP:
            assert cat in CATEGORIES
