"""Tests for paid-fetcher budget accounting (lex.budget)."""
from datetime import datetime

from lex.budget import month_key, over_budget


class TestMonthKey:
    def test_format(self):
        assert month_key(datetime(2026, 5, 9)) == "2026-05"
        assert month_key(datetime(2026, 12, 31)) == "2026-12"


class TestOverBudget:
    def test_under(self):
        assert over_budget(0, 500) is False
        assert over_budget(499, 500) is False

    def test_at_and_over(self):
        assert over_budget(500, 500) is True
        assert over_budget(501, 500) is True

    def test_zero_or_negative_cap_blocks(self):
        # A disabled cap must block (never spend).
        assert over_budget(0, 0) is True
        assert over_budget(0, -1) is True

    def test_bad_input_blocks(self):
        # Unparseable counters/caps fail safe (block the paid call).
        assert over_budget("x", 500) is True
        assert over_budget(0, "x") is True
