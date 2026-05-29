"""Pure HTTP helpers for crawler resilience & delta scraping (M2/M3).

Side-effect-free utilities so the crawler can:
  * skip unchanged feeds via HTTP conditional requests (ETag / Last-Modified)
  * back off correctly when a server sends Retry-After

Keeping the parsing pure makes the tricky bits (Retry-After in both seconds and
HTTP-date form) unit-testable without a network. See tests/test_http_util.py.
"""
from datetime import datetime, timezone


def build_conditional_headers(etag="", last_modified=""):
    """Return conditional-GET headers from stored validators.

    Sends If-None-Match (preferred) and/or If-Modified-Since so the server can
    answer 304 Not Modified when the feed is unchanged.
    """
    headers = {}
    if etag and etag.strip():
        headers["If-None-Match"] = etag.strip()
    if last_modified and last_modified.strip():
        headers["If-Modified-Since"] = last_modified.strip()
    return headers


def parse_retry_after(value, now=None):
    """Parse a Retry-After header into a non-negative seconds delay.

    Accepts the two RFC 7231 forms — a delta in seconds ("120") and an
    HTTP-date ("Wed, 21 Oct 2026 07:28:00 GMT"). Returns ``None`` if the value
    is missing or unparseable. Negative results (date in the past) clamp to 0.
    """
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    # Form 1: delta-seconds
    if v.isdigit():
        return int(v)
    # Form 2: HTTP-date
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S GMT"):
        try:
            dt = datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
            base = now or datetime.now(timezone.utc)
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
            return max(0, int((dt - base).total_seconds()))
        except ValueError:
            continue
    return None


def backoff_delay(attempt, base=2, cap=60):
    """Exponential backoff in seconds for retry ``attempt`` (0-based), capped."""
    return min(cap, base ** max(0, attempt))
