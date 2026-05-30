"""Severity / actor / source-confidence scoring.

Extracted verbatim from ``main.py`` (M1 modularization). Pure, stdlib-``re``-only
logic that turns a classified incident into the numeric and attribution signals
the rest of the pipeline (and the upcoming M4 verification/quality score) builds on:

  * :data:`CATEGORIES`        — canonical incident categories
  * :func:`score_severity`    — 1..5 severity from category + text signals
  * :data:`KNOWN_ACTORS`      — (display name, regex patterns, fedpol tier)
  * :data:`ACTOR_TIER`        — name -> tier map
  * :func:`extract_actors`    — comma-joined matched actor names
  * :data:`SOURCE_CONFIDENCE` — source substring -> confidence 1..5
  * :func:`score_confidence`  — confidence for a source string (default 2)

Attribution is intentionally conservative (Concept §C3 #2 — keine Vorverurteilung):
only "act" where the public record clearly connects a name to concrete violent
acts (claim letters or convictions). See ``tests/test_scoring.py``.
"""
import re

CATEGORIES = [
    "Brandanschlag","Sabotage","Gewalt","Schmiererei","Aufruf zu Gewalt",
    "Militante Aktion","Sachbeschädigung","Demo/Kundgebung","Besetzung",
    "Repression","Verhaftung","Sonstiges"
]

# ── SEVERITY SCORING ─────────────────────────────────────────────
SEVERITY_MAP = {
    "Brandanschlag": 5, "Gewalt": 5, "Militante Aktion": 5,
    "Aufruf zu Gewalt": 4, "Sabotage": 4,
    "Sachbeschädigung": 3, "Besetzung": 3, "Demo/Kundgebung": 2,
    "Verhaftung": 2, "Repression": 2,
    "Schmiererei": 1, "Sonstiges": 1,
}

def score_severity(category, text=""):
    """
    Schwere 1..5 — Basis aus SEVERITY_MAP, dann text-basiert hochgestuft.
    Mehrere Signale können stapeln (bis Cap 5). Reihenfolge nach Härte:
      Personen-Schaden > Brandwaffe/Sprengstoff > Sachschadens-Magnitude.
    """
    base = SEVERITY_MAP.get(category, 1)
    t = (text or "").lower()
    # Personenschaden = unmittelbarer Härte-Faktor
    if re.search(r"\b(schwer\s+verletzt|getötet|getoetet|\btot\b|tote\b|todesopfer|"
                 r"lebensgefahr|reanim(iert|ation)|krankenhaus(?!\w))",
                 t):
        base = min(base + 2, 5)
    elif re.search(r"\b(verletzt|verletzung|verletzte|geprellt|prellung|gebrochen|"
                   r"blutung)", t):
        base = min(base + 1, 5)
    # Brandwaffe / Sprengstoff / Werkzeugmilieu
    if re.search(r"\b(brandsatz|molotov|molotow|brand(?:flasche|beschleuniger)|"
                 r"sprengsatz|sprengstoff|usbv|brandsetzung)\b", t):
        base = min(base + 1, 5)
    # Sachschadens-Magnitude (€-Hinweise)
    m = re.search(r"(\d{1,3}(?:[.,]\d{3})+|\d{4,})\s*(?:€|euro|chf|franken)", t)
    if m:
        try:
            amt = int(re.sub(r"[.,]", "", m.group(1)))
            if   amt >= 1_000_000: base = min(base + 2, 5)
            elif amt >=   100_000: base = min(base + 1, 5)
        except Exception:
            pass
    # Mehrfach-Anschlag / koordinierte Aktion
    if re.search(r"(\bserien?anschl|\bkoordinier|\bmehrere\s+anschl|"
                 r"\bin\s+der\s+gleichen\s+nacht|\bsimultan|"
                 r"\b(?:fünf|sechs|sieben|acht|neun|zehn|\d{2,})\s+(?:fahrzeuge|"
                 r"autos|wagen|tesla|streifen|polizei))", t):
        base = min(base + 1, 5)
    return base

# ── ACTOR / GROUP TRACKING ────────────────────────────────────────
# Each entry: (display name, regex patterns, fedpol_tier).
# Tier mapping is intentionally conservative (Concept §C3 #2 — keine
# Vorverurteilung). Only attribute "act" where public record clearly
# connects the name to concrete violent acts (claim letters or convictions);
# "enable" for groups that organise support/propaganda for the milieu;
# "endorse" for scene/neighbourhood labels and movements that explicitly
# disavow violence themselves but are part of the broader endorsement layer.
KNOWN_ACTORS = [
    # ── DACH ───────────────────────────────────────────────────────
    ("Rote Flora",          [r"rote\s+flora"],                                "endorse"),
    ("Rigaer 94",           [r"rigaer\s*(?:94|straße|str\.)", r"liebig\s*34"], "endorse"),
    ("Ende Gelände",        [r"ende\s+gel[äa]nde"],                            "endorse"),
    ("Schwarzer Block",     [r"schwarzer\s+block", r"black\s+bloc"],           "act"),
    ("Rev. Zellen",         [r"revolutionäre\s+zellen", r"\brz\b"],            "act"),
    ("Letzte Generation",   [r"letzte\s+generation"],                          "endorse"),
    # "Antifa Ost" is the formal designation of the Lina-E./Hammerbande complex
    # (OLG Dresden conviction 5/2023) — all aliases for one publicly-prosecuted
    # network, kept as a single actor to avoid double-counting.
    ("Lina E. Netzwerk",    [r"\blina\s+e[\.\b]", r"hammerbande",
                              r"antifa[\s\-]?ost"],                              "act"),
    ("Rote Hilfe",          [r"rote\s+hilfe"],                                 "enable"),
    ("Antifa Leipzig",      [r"antifa\s+leipzig", r"connewitz"],               "endorse"),
    ("Autonome Gruppe",     [r"eine?\s+autonome\s+gruppe", r"autonome\s+zelle"], "act"),
    ("Junge Welt Umfeld",   [r"junge\s+welt\s+gruppe"],                        "enable"),
    ("Interventionist Left",[r"interventionistische\s+linke", r"\bil\b.*linke"], "endorse"),
    ("Vulkangruppe",        [r"vulkangruppe", r"vulkan\s+gruppe"],             "act"),
    # ── Schweiz ────────────────────────────────────────────────────
    ("Reitschule-Umfeld",   [r"reitschule(?:\s+bern)?\b"],                     "endorse"),
    ("Revolutionärer Aufbau",[r"revolutionäre?r?\s+aufbau"],                   "enable"),
    # ── USA / Nordamerika (per US 2026 CT-Strategy als Threat-Tier 1)
    ("Rose City Antifa",    [r"\brose\s+city\s+antifa\b", r"\brca\b\s+portland"], "endorse"),
    ("Portland Antifa",     [r"\bantifa\s+portland\b", r"\bpdx\s+antifa\b"],   "endorse"),
    ("Stop Cop City",       [r"\bstop\s+cop\s+city\b", r"\bdefend\s+the\s+atlanta\s+forest\b",
                              r"\bweelaunee\s+forest\b"],                       "act"),
    ("Crimethinc",          [r"\bcrimethinc\b"],                               "enable"),
    ("John Brown Gun Club", [r"\bjohn\s+brown\s+gun\s+club\b", r"\bjbgc\b"],   "endorse"),
    ("By Any Means Necessary", [r"\bby\s+any\s+means\s+necessary\b",
                                  r"\bbamn\b"],                                "endorse"),
    ("Smash Racial Capitalism",[r"\bsmash\s+racial\s+capital"],                "endorse"),
    # ── Griechenland (Exarchia-Komplex, in mehreren NDB/EU-INTCEN-Berichten)
    ("Exarchia-Strukturen", [r"\bexarch(ia|eia)\b", r"\bvouli\s+\d+\b"],       "endorse"),
    ("Conspiracy of Fire Cells",[r"\bconspiracy\s+of\s+fire\s+cells\b",
                                  r"\bsynomos[íi]a\s+pyr[íi]non\b"],            "act"),
    # ── Frankreich ─────────────────────────────────────────────────
    ("ZAD / Soulèvements",  [r"\bzad\b", r"\bzone\s+[àa]\s+d[ée]fendre\b",
                              r"\bsoul[èe]vements\s+de\s+la\s+terre\b"],       "endorse"),
    ("Action Antifasciste FR",[r"\baction\s+antifasciste\b.*\b(paris|france|lyon)",
                                r"\bafa\s+paris\b"],                            "endorse"),
    ("Black Bloc France",   [r"\bblack[\s-]?bloc\b.*\b(paris|france|toulouse|nantes)"], "act"),
    # ── Italien ────────────────────────────────────────────────────
    ("Centro Sociale",      [r"\bcentro\s+sociale\b", r"\bcsoa\b"],            "endorse"),
    ("NoTAV",               [r"\bnotav\b", r"\bno[\s-]?tav\b",
                              r"\bval\s+di\s+susa\b.*\b(protest|aktion)"],      "act"),
    ("Antifa Italia",       [r"\bantifa\s+(?:italia|bologna|roma|milano)\b"],  "endorse"),
    # ── Niederlande / Skandinavien / UK ────────────────────────────
    ("AFA Nederland",       [r"\bafa\s+nederland\b",
                              r"\bantifascistische\s+aktie\b.*(?:nl|nederland)"], "endorse"),
    ("AFA Stockholm",       [r"\bafa\s+stockholm\b",
                              r"\bantifascistisk\s+aktion\b"],                  "endorse"),
    ("Antifa Network UK",   [r"\bantifa\s+(?:uk|london|britain)\b",
                              r"\banti[\s-]?fascist\s+network\b"],              "endorse"),
    ("Class War",           [r"\bclass\s+war\b.*\b(uk|britain|london)\b"],     "enable"),
    # ── Spanien ────────────────────────────────────────────────────
    ("Acción Antifascista", [r"\bacci[óo]n\s+antifascista\b"],                 "endorse"),
    # ── Tag-X-Komitees (Lina-E.-Komplex) ──────────────────────────
    ("Tag-X-Komitee",       [r"\btag[\s-]?x[\s-]?komitee\b",
                              r"\btag\s+x\b"],                                  "enable"),
    # ── Internationale Erweiterung ────────────────────────────────
    ("Antifascistisk Aktion",[r"\bantifascistisk\s+aks?jon\b",
                                r"\bafa\s+(?:no|oslo|norge)\b"],                "endorse"),
    ("Anti-Cop-City Italia", [r"\banti[\s-]?cop[\s-]?city\b.*\b(italia|brescia|bologna)\b"], "endorse"),
    ("Vulkangruppe Bay Area",[r"\bvulkangruppe\s+bay\s+area\b"],               "act"),
    ("Defend the Atlanta Forest",
                            [r"\bdefend\s+the\s+atlanta\s+forest\b",
                              r"\bweelaunee\s+(?:forest|defenders)\b"],         "act"),
    ("Soulèvements de la Terre",
                            [r"\bsoul[èe]vements\s+de\s+la\s+terre\b",
                              r"\bsdt\b\s+(?:france|paris)\b"],                 "enable"),
    ("Carlos-Komitee",      [r"\bcarlos[\s-]?komitee\b"],                      "enable"),
    # ── Weitere internationale ────────────────────────────────────
    ("AFA Göteborg",        [r"\bafa\s+g[öo]teborg\b"],                       "endorse"),
    ("Antifa Network Bristol",[r"\bantifa\s+network\s+bristol\b",
                                r"\bafn\s+bristol\b"],                          "endorse"),
    ("Anti-RNC-Komitee",    [r"\banti[\s-]?rnc\b",
                              r"\brnc[\s-]?(welcoming|protest)"],               "enable"),
    ("Anti-DNC-Komitee",    [r"\banti[\s-]?dnc\b",
                              r"\bdnc[\s-]?(welcoming|protest)"],               "enable"),
    ("Cellule autonome FR", [r"\bcellule\s+autonome\b"],                       "act"),
    ("Anarchistische Zellen DE",
                            [r"\banarchistisch[er]?\s+zelle"],                  "act"),
    ("Welcoming Committee USA",
                            [r"\bwelcoming\s+committee\b"],                    "enable"),
    ("Eastmont-Front (Oakland)",
                            [r"\beastmont[\s-]?front\b"],                      "endorse"),
    ("Anti-Cybertruck",     [r"\banti[\s-]?cybertruck\b",
                              r"\bvulkangruppe\s+tesla\b"],                    "act"),
    ("Anti-Elon-Musk-Front", [r"\banti[\s-]?elon\b"],                          "endorse"),
    ("AntiCop Brescia",     [r"\banti[\s-]?cop\s+brescia\b"],                  "endorse"),
    ("Black Bloc Mailand",  [r"\bblack[\s-]?bloc\s+(milano|mailand)\b"],       "act"),
    ("AntiFa Frankfurt",    [r"\bantifa\s+frankfurt\b"],                       "endorse"),
    ("AntiFa Hamburg",      [r"\bantifa\s+hamburg\b"],                         "endorse"),
    ("Black Bloc Lyon",     [r"\bblack[\s-]?bloc\s+lyon\b"],                   "act"),
    # ── Weitere dokumentierte FR/DE-Strukturen (public record) ────────────
    # Bure: Widerstand gegen das Atommüll-Endlager Cigéo; mehrere Verfahren
    # nach Räumungen/Besetzungen (TGI Bar-le-Duc). endorse — Bewegung, nicht
    # einzelne Täter.
    ("Bure-Widerstand",     [r"\bcig[ée]o\b",
                              r"\bbure\b\s+(?:atomm[üu]ll|nuklear|besetzung|widerstand)"], "endorse"),
    # Tarnac: historischer FR-Komplex (SNCF-Sabotage 2008, Verfahren bis 2018).
    ("Tarnac-Komplex",      [r"\btarnac\b"],                                    "enable"),
    # Rebellyon-Umfeld (Lyon): Szene-Plattform/Aggregator, endorse-Layer.
    ("Rebellyon-Umfeld",    [r"\brebellyon\b"],                                 "endorse"),
]

ACTOR_TIER = {name: tier for name, _patterns, tier in KNOWN_ACTORS}

def extract_actors(text):
    found = []
    t = (text or "").lower()
    for entry in KNOWN_ACTORS:
        name, patterns = entry[0], entry[1]
        if any(re.search(p, t) for p in patterns):
            found.append(name)
    return ",".join(found)

# ── SOURCE CONFIDENCE SCORING ─────────────────────────────────────
SOURCE_CONFIDENCE = {
    "verfassungsschutz.de": 5,
    # Konfidenz 5 — Behörden-Primärquellen (Polizei-Press, Parlamente)
    "polizei-": 5, "presseportal.de": 5,
    "bundestag.de": 5, "bundestag-": 5,
    "bundesregierung.de": 5, "bundesregierung": 5,
    # US-Behörden-Primärquellen
    "justice.gov": 5, "us-attorney-press": 5,
    "fbi.gov": 5, "dhs.gov": 5, "dhs-cisa-alerts": 5,
    "nsa-press": 5, "usga-bureau-investigation": 5,
    "spd-blotter-seattle": 5, "portland-police": 5, "nypd-news": 5,
    "lapd-news": 5, "sfpd-news": 5, "philly-police": 5,
    "apd-atlanta": 5, "dpd-denver": 5, "mpd-minneapolis": 5,
    # Konfidenz 4 — öffentlich-rechtlich oder etablierte Leitmedien
    "tagesschau.de": 4, "zdf.de": 4, "deutschlandfunk.de": 4,
    "spiegel.de": 4, "zeit.de": 4, "sueddeutsche.de": 4, "faz.net": 4,
    "welt.de": 4,
    "srf.ch": 4, "orf.at": 4, "derstandard.at": 4, "nzz.ch": 4,
    "tagesanzeiger.ch": 4, "diepresse.com": 4,
    "lemonde.fr": 4, "liberation.fr": 4, "repubblica.it": 4, "corriere.it": 4,
    "elpais.com": 4, "euronews.com": 4,
    # US Mainstream-Outlets
    "nytimes-us": 4, "washingtonpost-politics": 4, "politico-politics": 4,
    "bbc-us-canada": 4, "axios-politics": 4, "usatoday-news": 4, "thehill": 4,
    "splcenter.org": 4, "gwu-extremism": 4,
    "apnews-politics": 4, "reuters-us": 4, "counterextremism.com": 4, "adl.org": 4,
    "npr-national": 4,
    # Konfidenz 3 — regionale öffentlich-rechtliche + Boulevard-Leit
    "tagesspiegel.de": 3, "mdr.de": 3, "rbb24.de": 3, "ndr.de": 3,
    "wdr.de": 3, "br.de": 3, "hr.de": 3, "swr.de": 3, "ntv.de": 3,
    "taz.de": 3, "blick.ch": 3, "20min.ch": 3, "belltower.news": 3,
    "bzbasel.ch": 3, "watson.ch": 3, "rts.ch": 3,
    "kurier.at": 3, "kleinezeitung.at": 3, "noen.at": 3, "krone.at": 3,
    "wien.orf.at": 3,
    "willamette-week-portland": 3, "ajc-atlanta": 3,
    # Konfidenz 2 — szenenahe Quellen, brauchen Cross-Check
    "barrikade.info": 2, "publish.barrikade.info": 2,
    "de.indymedia.org": 2, "nd-aktuell.de": 2,
    "jungle.world": 2, "gnews": 2, "labournet.de": 2, "woz.ch": 2,
    "jungewelt.de": 2, "rebellyon.info": 2,
    # Konfidenz 1 — Bewegungs-Outlets / Mailing-Listen-Archive
    "perspektive-online.net": 1, "radikal.news": 1, "klassegegenklasse.org": 1,
    "lists.riseup.net": 1,
    "Archiv": 3, "Manuell": 2,
}

def score_confidence(source):
    src = source or ""
    for k, v in SOURCE_CONFIDENCE.items():
        if k in src:
            return v
    return 2

# ── VERIFICATION / QUALITY SCORING (M4 — accountability ledger) ──────────
# The legitimate, durable effect of this tool comes from credible, verifiable,
# court-anchored documentation — not from targeting people. quality_score()
# turns the per-entry evidence signals into a single 0..100 credibility score
# plus a human label, so the UI can show a verification badge and analysts can
# rank by how well-substantiated a record is.
#
# Inputs (all optional, safe defaults):
#   confidence     int 1..5   — source-tier confidence (see score_confidence)
#   prosec_status  str        — {unknown,none,investigating,charged,trial,
#                                convicted,acquitted,dismissed}
#   case_ref       str        — public court/investigation reference (anchor)
#   has_evidence   bool       — a WARC snapshot of the source was archived
#   corroboration  int        — number of *additional* independent sources
#                                that documented the same incident (0 = single)
#
# The weighting deliberately rewards court-anchoring and corroboration most:
# those are exactly the signals that make a record hard to dismiss.
_PROSEC_POINTS = {
    "convicted": 35, "trial": 25, "charged": 25, "investigating": 15,
    # acquitted/dismissed are still *documented public process* — small anchor,
    # never negative: the event and its legal outcome are both on the record.
    "acquitted": 10, "dismissed": 10,
}

def quality_score(confidence=0, prosec_status="unknown", case_ref="",
                  has_evidence=False, corroboration=0):
    """Return a verification dict for one incident.

    Output:
        {"score": int 0..100, "label": str, "components": {...}}
    label ∈ {court-confirmed, strong, moderate, weak, unverified}

    Deterministic and side-effect-free so it can be unit-tested and reused by
    the API, the UI badge and any ranking. Higher = better substantiated.
    """
    conf = max(0, min(int(confidence or 0), 5))
    ps = (prosec_status or "unknown").strip().lower()
    corr = max(0, min(int(corroboration or 0), 2))

    components = {
        "source": conf * 8,                       # 0..40
        "case_ref": 20 if (case_ref or "").strip() else 0,
        "prosecution": _PROSEC_POINTS.get(ps, 0),  # 0..35
        "evidence": 15 if has_evidence else 0,
        "corroboration": corr * 10,                # 0..20
    }
    score = min(sum(components.values()), 100)

    if ps == "convicted":
        label = "court-confirmed"
    elif score >= 70:
        label = "strong"
    elif score >= 45:
        label = "moderate"
    elif score >= 25:
        label = "weak"
    else:
        label = "unverified"

    return {"score": score, "label": label, "components": components}


# ── FUNDING TRANSPARENCY SCORING (M5 — follow-the-money pillar) ───────────
# The funding pillar is about structural/financial transparency of *registered
# organisations* — the most defensible part of the project. Each funding record
# gets a transparency score so the UI can show how well-documented a money flow
# is, the same way incidents carry a verification badge.
#
# Inputs:
#   confidence    int 1..5  — documentation strength (5 = official primary doc)
#   verified      bool/int  — source_url points at a SPECIFIC primary document
#                             (grant list, activity report, parliamentary paper)
#   has_source    bool      — any source_url is present at all
#
# label ∈ {primärbelegt, belegt, teilbelegt, indikativ}

def funding_transparency(confidence=0, verified=False, has_source=False):
    """Return a transparency dict for one funding record.

    {"score": int 0..100, "label": str, "components": {...}}. Deterministic and
    side-effect-free (see tests/test_scoring.py). Higher = better documented.
    """
    conf = max(0, min(int(confidence or 0), 5))
    components = {
        "source": conf * 12,                       # 0..60
        "verified": 30 if verified else 0,         # specific primary document
        "has_source": 10 if has_source else 0,     # any citation at all
    }
    score = min(sum(components.values()), 100)

    if verified:
        label = "primärbelegt"
    elif score >= 60:
        label = "belegt"
    elif score >= 35:
        label = "teilbelegt"
    else:
        label = "indikativ"

    return {"score": score, "label": label, "components": components}

# Two independent sources reporting the same act is a strong credibility
# signal. These pure helpers decide whether two incident records describe the
# *same event*, so a DB pass can count distinct corroborating sources. Kept
# conservative: a false merge would wrongly inflate a record's credibility, so
# we require same country + same category + a location match + a tight date
# window. (Side-effect-free; see tests/test_scoring.py.)

def _norm_loc(location):
    return (location or "").strip().lower()

def corroboration_key(country, category):
    """Coarse bucket so only plausibly-related incidents are compared."""
    return ((country or "").strip().upper(), (category or "").strip())

def _days_between(date_a, date_b):
    """Whole-day distance between two YYYY-MM-DD strings, or None if unparseable."""
    from datetime import date
    def _p(s):
        try:
            y, m, d = (s or "")[:10].split("-")
            return date(int(y), int(m), int(d))
        except Exception:
            return None
    a, b = _p(date_a), _p(date_b)
    if a is None or b is None:
        return None
    return abs((a - b).days)

def same_event(a, b, day_window=3):
    """True if incident dicts ``a`` and ``b`` plausibly describe one event.

    Requires identical country + category, a location match (equal, or one
    name contained in the other — handles "Leipzig" vs "Leipzig-Connewitz"),
    and report dates within ``day_window`` days. Unparseable dates do not match.
    """
    if corroboration_key(a.get("country"), a.get("category")) != \
       corroboration_key(b.get("country"), b.get("category")):
        return False
    la, lb = _norm_loc(a.get("location")), _norm_loc(b.get("location"))
    if not la or not lb:
        return False
    if not (la == lb or la in lb or lb in la):
        return False
    dist = _days_between(a.get("date"), b.get("date"))
    return dist is not None and dist <= day_window

