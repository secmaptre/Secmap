"""Data-grounded scene outlook (predictions).

Turns the numeric trend signals the API already computes (slope, rising
categories, hotspots, active early-warning clusters) into a sober, structured
outlook — an *extrapolation of documented data*, never editorial prophecy. Every
outlook carries an explicit uncertainty caveat: under-reporting (Dunkelfeld) and
reporting fluctuations mean this is a trajectory, not a deterministic forecast.

Pure and side-effect-free so it is unit-testable (see tests/test_forecast.py).
"""


def scene_outlook(signals):
    """Build a structured outlook from trend signals.

    signals keys (all optional, safe defaults):
        trend_direction str  "up"|"down"|"stable"
        slope           float  incidents/month change (regression slope)
        monthly_avg     float  recent monthly incident average
        rising          list[(category, change_pct)]  strongest risers
        top_hotspot     str    location with most recent activity
        active_clusters int    active early-warning clusters
        horizon_months  int    projection horizon (default 3)

    Returns:
        {"headline", "drivers": [..], "caveat", "confidence"}
    """
    s = signals or {}
    direction = s.get("trend_direction", "stable")
    slope = float(s.get("slope") or 0.0)
    horizon = int(s.get("horizon_months") or 3)
    rising = s.get("rising") or []
    hotspot = s.get("top_hotspot") or ""
    clusters = int(s.get("active_clusters") or 0)
    monthly_avg = s.get("monthly_avg")

    if direction == "up":
        headline = (f"Die dokumentierte Vorfallsfrequenz steigt (≈ +{abs(slope):.1f}/Monat). "
                    f"Bei gleichbleibender Dynamik ist in den nächsten {horizon} Monaten mit "
                    f"weiterhin erhöhter Aktivität zu rechnen.")
    elif direction == "down":
        headline = (f"Die dokumentierte Vorfallsfrequenz geht zurück (≈ {slope:.1f}/Monat). "
                    f"Kurzfristig deutet die Datenlage auf nachlassende Aktivität — unter "
                    f"Vorbehalt von Meldeschwankungen.")
    else:
        headline = (f"Die dokumentierte Vorfallsfrequenz ist über die letzten Monate weitgehend "
                    f"stabil. Für die nächsten {horizon} Monate ist ohne neue Auslöser ein "
                    f"ähnliches Niveau zu erwarten.")

    drivers = []
    if monthly_avg is not None:
        drivers.append(f"Aktuelles Niveau: ≈ {round(float(monthly_avg))} dokumentierte Vorfälle/Monat.")
    for cat, pct in rising[:3]:
        if pct and pct > 0:
            drivers.append(f"Zunehmend: {cat} (+{int(pct)}% ggü. Vorquartal).")
    if hotspot:
        drivers.append(f"Räumlicher Schwerpunkt: {hotspot}.")
    if clusters > 0:
        drivers.append(f"{clusters} aktive Frühwarn-Cluster (≥3 gleichartige Vorfälle/Region).")

    caveat = ("Extrapolation aus dokumentierten, öffentlich belegten Vorfällen — kein "
              "deterministischer Vorhersagewert. Dunkelfeld, Meldeschwankungen und "
              "Verfahrensdynamik können das Bild verschieben.")

    # Confidence reflects how much signal underpins the outlook.
    n_signals = len(drivers)
    confidence = "mittel" if (n_signals >= 3 and monthly_avg and monthly_avg >= 2) else "niedrig"

    return {"headline": headline, "drivers": drivers, "caveat": caveat,
            "confidence": confidence}
