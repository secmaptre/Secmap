"""Tests for the data-grounded scene outlook (lex.forecast)."""
from lex.forecast import scene_outlook


class TestSceneOutlook:
    def test_up_trend_headline(self):
        o = scene_outlook({"trend_direction": "up", "slope": 2.4, "monthly_avg": 10,
                           "rising": [("Brandanschlag", 50)], "top_hotspot": "Leipzig",
                           "active_clusters": 2, "horizon_months": 3})
        assert "steigt" in o["headline"]
        assert any("Leipzig" in d for d in o["drivers"])
        assert any("Brandanschlag" in d for d in o["drivers"])
        assert any("Cluster" in d for d in o["drivers"])

    def test_down_trend_headline(self):
        o = scene_outlook({"trend_direction": "down", "slope": -1.5, "monthly_avg": 4})
        assert "zurück" in o["headline"]

    def test_stable_trend_headline(self):
        o = scene_outlook({"trend_direction": "stable", "slope": 0.0, "monthly_avg": 5})
        assert "stabil" in o["headline"]

    def test_caveat_always_present(self):
        for d in ("up", "down", "stable"):
            o = scene_outlook({"trend_direction": d})
            assert o["caveat"]
            assert "kein deterministischer" in o["caveat"].lower() or "Dunkelfeld" in o["caveat"]

    def test_confidence_levels(self):
        strong = scene_outlook({"trend_direction": "up", "slope": 3, "monthly_avg": 12,
                                "rising": [("Gewalt", 20), ("Sabotage", 10)],
                                "top_hotspot": "Berlin", "active_clusters": 1})
        assert strong["confidence"] == "mittel"
        weak = scene_outlook({"trend_direction": "stable"})
        assert weak["confidence"] == "niedrig"

    def test_empty_safe(self):
        o = scene_outlook({})
        assert o["headline"] and o["caveat"]
        assert o["confidence"] == "niedrig"

    def test_negative_rising_not_listed(self):
        # Only actual risers should appear as drivers.
        o = scene_outlook({"trend_direction": "stable", "rising": [("Demo/Kundgebung", -30)]})
        assert not any("Demo" in d for d in o["drivers"])
