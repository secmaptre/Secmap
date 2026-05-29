"""Tests for the pure crawler HTTP helpers (lex.http_util)."""
from datetime import datetime, timezone

from lex.http_util import (
    build_conditional_headers,
    parse_retry_after,
    backoff_delay,
)


class TestConditionalHeaders:
    def test_etag_only(self):
        h = build_conditional_headers(etag='"abc123"')
        assert h == {"If-None-Match": '"abc123"'}

    def test_last_modified_only(self):
        h = build_conditional_headers(last_modified="Wed, 21 Oct 2026 07:28:00 GMT")
        assert h == {"If-Modified-Since": "Wed, 21 Oct 2026 07:28:00 GMT"}

    def test_both(self):
        h = build_conditional_headers(etag='"x"', last_modified="Wed, 21 Oct 2026 07:28:00 GMT")
        assert "If-None-Match" in h and "If-Modified-Since" in h

    def test_empty(self):
        assert build_conditional_headers() == {}
        assert build_conditional_headers("", "") == {}


class TestParseRetryAfter:
    def test_seconds(self):
        assert parse_retry_after("120") == 120

    def test_zero(self):
        assert parse_retry_after("0") == 0

    def test_http_date_future(self):
        now = datetime(2026, 10, 21, 7, 28, 0, tzinfo=timezone.utc)
        # 60 seconds in the future
        assert parse_retry_after("Wed, 21 Oct 2026 07:29:00 GMT", now=now) == 60

    def test_http_date_past_clamps_zero(self):
        now = datetime(2026, 10, 21, 7, 28, 0, tzinfo=timezone.utc)
        assert parse_retry_after("Wed, 21 Oct 2026 07:27:00 GMT", now=now) == 0

    def test_none_and_empty(self):
        assert parse_retry_after(None) is None
        assert parse_retry_after("") is None

    def test_garbage(self):
        assert parse_retry_after("soon") is None


class TestBackoffDelay:
    def test_exponential(self):
        assert backoff_delay(0) == 1
        assert backoff_delay(1) == 2
        assert backoff_delay(2) == 4

    def test_capped(self):
        assert backoff_delay(20, cap=60) == 60
