"""Relevance & false-positive filtering — keeps the dataset clean.

Extracted verbatim from ``main.py`` (M1 modularization). This is the gate that
implements the project's "no random Zeitungsartikel" requirement: superficial
keyword hits that are NOT left-extremist political violence (autonomous *cars*,
foreign-policy items, ordinary police-blotter crime such as "Rentner verursacht
Brand", solidarity/culture events, right-wing-perpetrator stories) are rejected
before they ever reach the classifier or the database.

Public surface (unchanged names, re-imported by ``main.py``):
  * :data:`RSS_KEYWORDS`            — pre-fetch include keywords
  * :data:`BARRIKADE_RELEVANCE_KWS` — scene-source relevance keywords
  * :func:`is_false_positive`       — the reject gate

Depends only on the stdlib ``re`` module (see ``tests/test_filters.py``).
"""
import re

# ── RSS FEEDS ─────────────────────────────────────────────────────
RSS_KEYWORDS = [
    "linksextrem","linksradikal","antifa","anarchi","schwarzer block","black bloc",
    "brandanschlag","sabotage","molotow","farbbeutel","bekennerschreiben","militante",
    "besetzung","blockade","rigaer","rote flora","sachbeschädigung","in brand",
    "autonome gruppe","autonome szene","autonome aktion","autonome linke",
    "verfassungsschutz extremis","linksradikal verhaftung","linksextrem anschlag",
    "direkte aktion","barrikade","hausbesetzung","fahrzeugbrand","fahrzeuge in brand",
]

# ── FALSE-POSITIVE FILTER ─────────────────────────────────────────
# Reject articles that match RSS_KEYWORDS superficially but are NOT political extremism
_FP = [
    # Technology / autonomous vehicles
    # adjective ending widened ([snrm]?) so declined forms — "autonomen Fahren",
    # "autonomer LKW" — are caught too. Safe: anchored to tech/vehicle nouns,
    # so it never touches "autonome Gruppe/Szene".
    r'\bautonome[snrm]?\s+(fahren|fahrzeuge?|autos?\b|lkw|pkw|bus\b|roboter|drohnen?|flugzeug)',
    r'\bself.?driving\b', r'\bautopilot\b',
    r'\bautonome[snrm]?\s+(parken|laden|liefern)',
    r'\bautonome[srm]?\s+(mobilitäts?|verkehrs?|transport)',
    r'\belektroauto[s]?\b', r'\be-auto[s]?\b', r'\belektromobilit',
    r'\bdigitale\s+revolution\b',
    r'\bkünstliche\s+intelligenz\b',
    r'\bki-?\s*(modell|system|assistent|tool|chip)',
    r'\bmobilitäts?revolution\b', r'\benergie(wende|revolution)\b',
    r'\bkrypto|bitcoin|blockchain\b',
    r'\baktienmarkt|börsen?kurse?\b',
    r'\blandwirtschaft.*sabotag|sabotag.*landwirtschaft',
    r'\bautonomie\s+(schweiz|österreich|deutschland|region)',
    # Non-European conflicts / disasters (not relevant to DACH extremism)
    r'\bkongo\b', r'\bebola\b', r'\bafrika\b', r'\bnigeria\b', r'\bsomalia\b',
    r'\bsyrien\b', r'\bjemen\b', r'\biraq\b', r'\bafghanistan\b', r'\bukraine.*front\b',
    r'\bpalästina.*rakete|rakete.*palästina\b',
    r'\bdemokratische\s+republik\s+kongo\b',
    # Right-wing perpetrators attacking others (we track LEFT extremism only)
    r'\bneonazi.*angriff\b', r'\bnazi.*überfall\b', r'\bnazi.*attack\b',
    r'\brechtsextrem.*täter\b', r'\brechtsextrem.*angreifer\b',
    r'\bneonazi.*täter\b', r'\bfaschistisch.*motiv\b', r'\brechts.*täter\b',
    r'\bRechtsterror\b', r'\bPKK\b', r'\bIslamist\b', r'\bdschihadist\b',
    # Navigation/website content accidentally scraped
    r'\bTutorials\s+Videos\s+Archiv\b', r'\bdont\s+hate\s+the\s+media\b',
    r'\bDirekt\s+zum\s+Inhalt\b',
    # ── Plan §0 out-of-scope: solidarity / culture / repression-reports ──
    r'\bsolidaritätsaufruf\b', r'\bsolidaritätskundgebung\b',
    r'\bgedenken\b(?!.*anschlag)', r'\bmahnwache\b(?!.*anschlag)',
    r'\bprozessbeobachtung\b', r'\brepressionsbericht\b',
    r'\blesung\b', r'\bvokü\b', r'\btresen\b', r'\binfoveranstaltung\b',
    r'\bdiskussionsveranstaltung\b', r'\bkonzert\b', r'\bsoliparty\b',
    r'\bkneipenabend\b',
    # ── Non-DACH foreign-policy items that bypass the EU/perpetrator gate ──
    r'\b(gaza|israel|palästina|hamas)\b',
    r'\b(trump|biden|harris|usa\b|united\s+states)\b',
    r'\b(china|taiwan|tibet|xinjiang|hongkong)\b',
    r'\b(iran|saudi|yemen|libanon|hisbollah)\b',
    # ── Polizei-Press-FP: typische Nicht-Extremismus-Meldungen ────
    # Polizei-Pressestellen publizieren TÄGLICH Verkehrsunfälle,
    # Ladendiebstähle, Drogendelikte usw. Diese MUESSEN raus, sonst
    # frisst der Grok-Classifier eine 5stellige Token-Rechnung weg.
    r'\b(verkehrsunfall|verkehrskontrolle|geschwindigkeitskontrolle|alkohol\s*am\s+steuer)\b',
    r'\b(ladendiebstahl|taschendiebstahl|fahrraddiebstahl|wohnungseinbruch)\b',
    r'\b(drogenfund|btmg|cannabis|kokain|crystal\s*meth)\b(?!.*demo)',
    r'\bvermisst.*person\b', r'\bsenioren?\b.*\btrickbetrug\b',
    r'\bbrand\s+in\s+wohnung\b(?!.*polit)',
    r'\benkeltrick|schockanruf\b',
    r'\bsexual.*delikt\b(?!.*polit)',
    r'\bversicherungs?betrug|sozialleistungs?betrug\b',
    r'\bgemein(de|sames)?\s+spendenaufruf\b',
    r'\btierrettung|tierquäler', r'\bunwetter|hochwasser|sturm\b(?!.*demo)',
    # ── Bundestags-Drucksachen: vieles davon ist Lesung/Anhörung ────
    r'\b(lesung|abstimmung|anhörung|haushalts(beratung|debatte))\b(?!.*linksex)',
    r'\bgrundgesetz.*änderung\b(?!.*linksex)',
]

def is_false_positive(text):
    """Tightened per plan §0 — strict OSINT scope for DACH violent left."""
    t = text.lower()
    # Pure non-DACH foreign-policy hits should NOT veto an article that also
    # contains a DACH city + a real attack keyword (e.g. a Berlin Brandanschlag
    # framed as anti-Israel). Allow if a strong primary attack keyword is present.
    strong_attack = re.search(
        r'\b(brandanschlag|brandsatz|molotow|in\s+brand\s+gesetzt|sabotage\s+an|'
        r'bekennerschreiben|sprengstoff|militante\s+aktion)\b', t)
    for p in _FP:
        if re.search(p, t, re.IGNORECASE):
            # Exempt foreign-policy patterns only if a strong attack keyword + DACH city co-occur.
            if strong_attack and re.search(
                r'\b(berlin|hamburg|leipzig|münchen|köln|frankfurt|dresden|stuttgart|'
                r'wien|graz|linz|zürich|bern|basel|genf|lausanne)\b', t):
                continue
            return True
    return False

BARRIKADE_RELEVANCE_KWS = [
    "angriff","brand","sabotage","ausschreitungen","krawalle","randalen",
    "besetzung","verhaftung","razzia","molotow","bekennerschreiben",
    "autonome","antifa","schwarzer block","linksextrem","schäden","verletzt",
    "festnahmen","überfall","protest","demonstration","blockade","besetzt",
    # Actions against right-wing groups (barrikade.info coverage)
    "junge tat","identitär","neonazi","faschistisch"," nazi","rechtsextrem",
    "eingelackt","lackiert","lack ","besprüht","outing","dox","antifaschist",
    "aktion gegen","solidarität","hausdurchsuchung",
]
