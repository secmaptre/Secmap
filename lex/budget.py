"""Paid-fetcher budget accounting (M2 cost safety).

Pure helpers for capping monthly spend on the paid scrape fallbacks
(Firecrawl / ScrapingBee / ScraperAPI). If the RSS layer breaks, the crawler
must not silently burn through a paid quota — these make the month bucket and
the cap check trivially testable; the counter itself lives in the DB metadata
table (see main.py). See tests/test_budget.py.
"""


def month_key(now=None):
    """Return the current budget bucket as 'YYYY-MM'."""
    from datetime import datetime
    n = now or datetime.now()
    return f"{n.year:04d}-{n.month:02d}"


def over_budget(used, cap):
    """True if ``used`` calls have reached/exceeded the monthly ``cap``.

    A non-positive cap means "disabled" → always over budget (block the call).
    """
    try:
        used = int(used or 0)
        cap = int(cap)
    except (TypeError, ValueError):
        return True
    if cap <= 0:
        return True
    return used >= cap
