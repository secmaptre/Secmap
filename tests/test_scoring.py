"""Regression tests for severity / actor / confidence scoring (lex.scoring)."""
from lex.scoring import (
    score_severity,
    score_confidence,
    extract_actors,
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


class TestDataIntegrity:
    def test_actor_tier_covers_all_actors(self):
        assert len(ACTOR_TIER) == len(KNOWN_ACTORS)

    def test_tiers_are_valid(self):
        assert set(ACTOR_TIER.values()) <= {"act", "enable", "endorse"}

    def test_severity_map_keys_are_categories(self):
        # Every severity-mapped category is a known category.
        for cat in SEVERITY_MAP:
            assert cat in CATEGORIES
