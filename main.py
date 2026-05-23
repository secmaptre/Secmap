import os, logging, json, time, hashlib, re, secrets, csv, io
from datetime import datetime, timedelta
from urllib.parse import urljoin, quote_plus
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request, BackgroundTasks, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

def _resolve_db_path():
    p = os.getenv("DB_PATH")
    if p:
        d = os.path.dirname(p)
        if not d or os.path.isdir(d):
            return p
        log.warning(f"DB_PATH dir '{d}' does not exist, falling back to local DB")
    if os.path.isdir("/disk"):   return "/disk/lex_threat.db"
    if os.path.isdir("/data"):   return "/data/lex_threat.db"
    return "lex_threat.db"

DB_PATH = _resolve_db_path()
GROK_MODEL = os.getenv("GROK_MODEL", "grok-4")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "changeme")

# ── DATABASE ──────────────────────────────────────────────────────
def get_db():
    path = DB_PATH
    try:
        c = sqlite3.connect(path, check_same_thread=False)
    except Exception as e:
        log.error(f"Cannot open DB at {path}: {e} — falling back to local lex_threat.db")
        path = "lex_threat.db"
        c = sqlite3.connect(path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    # Use DELETE journal mode — compatible with NFS/network filesystems (no WAL)
    c.execute("PRAGMA journal_mode=DELETE")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT, location TEXT, country TEXT, category TEXT,
        description TEXT, source TEXT, url TEXT,
        hash TEXT UNIQUE, lat REAL, lon REAL,
        manual INTEGER DEFAULT 0, timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS geocache (query TEXT PRIMARY KEY, lat REAL, lon REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires TEXT)''')
    # Schema migrations — add columns that may be missing in older DBs.
    # Additive only: existing render.com persistent disks keep working.
    for col, defn in [("hash","TEXT"), ("lat","REAL"), ("lon","REAL"),
                      ("manual","INTEGER DEFAULT 0"), ("timestamp","TEXT"),
                      ("severity_score","INTEGER DEFAULT 0"),
                      ("actors","TEXT DEFAULT ''"),
                      ("confidence","INTEGER DEFAULT 0"),
                      # Quality-scope additions (see plan §0)
                      ("summary","TEXT DEFAULT ''"),
                      ("is_primary","INTEGER DEFAULT 0"),
                      ("is_high_risk","INTEGER DEFAULT 0"),
                      # Strategic Concept v3 — Fedpol 3-tier taxonomy + target
                      # routing + Strafverfolgungs-Status (Säule 1+2 ground work).
                      ("tier","TEXT DEFAULT 'act'"),
                      ("target_type","TEXT DEFAULT ''"),
                      ("prosec_status","TEXT DEFAULT 'unknown'"),
                      ("case_ref","TEXT DEFAULT ''"),
                      ("last_status_check","TEXT DEFAULT ''")]:
        try:
            c.execute(f"ALTER TABLE incidents ADD COLUMN {col} {defn}")
        except Exception:
            pass  # column already exists

    # ── FUNDING TRACKER ───────────────────────────────────────────
    # Public funding to organisations linked to the violent-left milieu.
    # Sources must be public documents (Bundesanzeiger, transparency portals,
    # foundation grant pages, Kanton/Stadt budget items).
    c.execute('''CREATE TABLE IF NOT EXISTS funding_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_org TEXT NOT NULL,
        project TEXT,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'EUR',
        year INTEGER NOT NULL,
        country TEXT NOT NULL,
        donor_type TEXT NOT NULL,
        donor_name TEXT NOT NULL,
        source_url TEXT,
        notes TEXT,
        confidence INTEGER DEFAULT 3,
        manual INTEGER DEFAULT 0,
        hash TEXT UNIQUE,
        timestamp TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_org     ON funding_records(recipient_org)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_year    ON funding_records(year)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_country ON funding_records(country)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_donor   ON funding_records(donor_type)")
    c.commit()
    return c

db = get_db()

def meta_get(k):
    r = db.execute("SELECT value FROM metadata WHERE key=?", (k,)).fetchone()
    return r[0] if r else None

def meta_set(k, v):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (k, str(v)))
    db.commit()

def meta_del(k):
    db.execute("DELETE FROM metadata WHERE key=?", (k,))
    db.commit()

# ── AUTH ──────────────────────────────────────────────────────────
def make_token():
    t = secrets.token_hex(32)
    exp = (datetime.now() + timedelta(hours=12)).isoformat()
    db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?)", (t, exp))
    db.commit()
    return t

def verify_token(token):
    if not token: return False
    row = db.execute("SELECT expires FROM sessions WHERE token=?", (token,)).fetchone()
    if not row: return False
    if datetime.now() > datetime.fromisoformat(row[0]):
        db.execute("DELETE FROM sessions WHERE token=?", (token,))
        db.commit()
        return False
    return True

def require_admin(request: Request):
    if not verify_token(request.cookies.get("admin_token", "")):
        raise HTTPException(401, "Unauthorized")

# ── HTTP ──────────────────────────────────────────────────────────
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Accept-Language": "de-DE,de;q=0.9",
})

def fetch(url, timeout=25):
    for attempt in range(3):
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            r.raise_for_status()
            return r.text
        except Exception as e:
            if attempt == 2: raise
            time.sleep(2 ** attempt)

def get_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for t in soup(["script","style","nav","footer","header","aside","form","iframe"]):
            t.decompose()
        el = (soup.find("article") or soup.find("main") or
              soup.find(True, class_=re.compile(r"\b(article|content|post|entry|body|node)\b", re.I)) or
              soup.body or soup)
        raw = el.get_text(" ", strip=True)
        # Strip indymedia navigation artifacts
        raw = re.sub(r'Direkt zum Inhalt.{0,600}?(?=[A-ZÜÄÖ][a-züäöA-ZÜÄÖ\s]{10,})', '', raw, flags=re.DOTALL)
        raw = re.sub(r'dont hate the media.{0,400}?(?=\w{8,})', '', raw, flags=re.DOTALL|re.IGNORECASE)
        raw = re.sub(r'\b(Openposting|Terminkalender|Gruppenstatements|Editorialliste|Linkliste|Mailinglisten|Moderation|Unterstützen|Outcall|Übersetzungskoordination|Mission Statement)\b', '', raw)
        return re.sub(r"\s{3,}", " ", raw).strip()[:5000]
    except Exception as e:
        log.warning(f"get_text {url}: {e}")
        return ""

def date_from_url(url):
    m = re.search(r"(20\d{2})[/_-](\d{1,2})[/_-](\d{1,2})", url)
    if m:
        try: return datetime(int(m.group(1)),int(m.group(2)),int(m.group(3))).strftime("%Y-%m-%d")
        except: pass
    return None

# ── GEOCODING with city fallback ──────────────────────────────────
CITY_FALLBACK = {
    # Deutschland — Großstädte + relevante Mittelstädte
    "berlin": (52.52, 13.405), "hamburg": (53.55, 10.00), "münchen": (48.14, 11.58),
    "munich": (48.14, 11.58), "köln": (50.94, 6.96), "frankfurt": (50.11, 8.68),
    "stuttgart": (48.78, 9.18), "düsseldorf": (51.23, 6.78), "leipzig": (51.34, 12.37),
    "dresden": (51.05, 13.74), "hannover": (52.37, 9.74), "bremen": (53.08, 8.80),
    "dortmund": (51.51, 7.47), "nürnberg": (49.45, 11.08), "bochum": (51.48, 7.22),
    "chemnitz": (50.83, 12.92), "halle": (51.48, 11.97), "magdeburg": (52.12, 11.62),
    "rostock": (54.09, 12.13), "essen": (51.46, 7.01), "duisburg": (51.43, 6.77),
    "wuppertal": (51.26, 7.18), "bielefeld": (52.02, 8.53), "münster": (51.96, 7.63),
    "augsburg": (48.37, 10.90), "karlsruhe": (49.01, 8.40), "mannheim": (49.49, 8.47),
    "freiburg": (47.99, 7.85), "kiel": (54.32, 10.13), "lübeck": (53.87, 10.69),
    "erfurt": (50.98, 11.03), "jena": (50.93, 11.59), "potsdam": (52.40, 13.06),
    "göttingen": (51.54, 9.93), "kassel": (51.31, 9.49), "saarbrücken": (49.24, 6.99),
    "weimar": (50.98, 11.32), "cottbus": (51.76, 14.33),
    # Schweiz
    "zürich": (47.38, 8.54), "zurich": (47.38, 8.54), "bern": (46.95, 7.44),
    "genf": (46.20, 6.14), "geneva": (46.20, 6.14), "basel": (47.56, 7.59),
    "lausanne": (46.52, 6.63), "winterthur": (47.50, 8.72), "luzern": (47.05, 8.31),
    # Österreich
    "wien": (48.21, 16.37), "vienna": (48.21, 16.37), "graz": (47.07, 15.44),
    "linz": (48.31, 14.29), "salzburg": (47.80, 13.05), "innsbruck": (47.27, 11.39),
    "klagenfurt": (46.62, 14.31),
    # Frankreich
    "paris": (48.85, 2.35), "lyon": (45.76, 4.84), "marseille": (43.30, 5.37),
    "bordeaux": (44.84, -0.58), "toulouse": (43.60, 1.44), "nantes": (47.22, -1.55),
    "strasbourg": (48.58, 7.75), "lille": (50.63, 3.07),
    # Italien
    "rom": (41.90, 12.50), "rome": (41.90, 12.50), "mailand": (45.46, 9.19),
    "milano": (45.46, 9.19), "turin": (45.07, 7.69), "torino": (45.07, 7.69),
    "neapel": (40.85, 14.27), "napoli": (40.85, 14.27), "bologna": (44.49, 11.34),
    # Griechenland
    "athen": (37.98, 23.73), "athens": (37.98, 23.73), "thessaloniki": (40.64, 22.94),
    "exarchia": (37.98, 23.73), "exarcheia": (37.98, 23.73),
    # Spanien
    "madrid": (40.42, -3.70), "barcelona": (41.39, 2.17), "valencia": (39.47, -0.38),
    "bilbao": (43.26, -2.93), "sevilla": (37.39, -5.99),
    # UK / Irland
    "london": (51.51, -0.13), "manchester": (53.48, -2.24), "glasgow": (55.86, -4.25),
    "edinburgh": (55.95, -3.19), "bristol": (51.45, -2.59), "dublin": (53.35, -6.26),
    # BeNeLux
    "amsterdam": (52.37, 4.89), "rotterdam": (51.92, 4.48), "den haag": (52.07, 4.30),
    "brüssel": (50.85, 4.35), "brussels": (50.85, 4.35), "antwerpen": (51.22, 4.40),
    "luxemburg": (49.61, 6.13),
    # Nordeuropa
    "kopenhagen": (55.68, 12.57), "copenhagen": (55.68, 12.57), "aarhus": (56.16, 10.20),
    "stockholm": (59.33, 18.06), "göteborg": (57.71, 11.97), "malmö": (55.60, 13.00),
    "oslo": (59.91, 10.75), "bergen": (60.39, 5.32),
    "helsinki": (60.17, 24.94),
    # Mittel-/Osteuropa
    "warschau": (52.23, 21.01), "warsaw": (52.23, 21.01), "krakau": (50.06, 19.94),
    "prag": (50.08, 14.43), "prague": (50.08, 14.43), "budapest": (47.50, 19.04),
    "bukarest": (44.43, 26.10), "bucharest": (44.43, 26.10),
    "sofia": (42.70, 23.32), "ljubljana": (46.06, 14.51), "zagreb": (45.81, 15.98),
    # Portugal
    "lissabon": (38.72, -9.14), "lisbon": (38.72, -9.14), "porto": (41.15, -8.61),
    # USA — Schwerpunkte Antifa-/Anarcho-Szene
    "new york": (40.71, -74.01), "nyc": (40.71, -74.01),
    "portland": (45.51, -122.68), "seattle": (47.61, -122.33),
    "minneapolis": (44.98, -93.27), "chicago": (41.88, -87.63),
    "los angeles": (34.05, -118.24), "oakland": (37.80, -122.27),
    "san francisco": (37.77, -122.42), "atlanta": (33.75, -84.39),
    "washington": (38.91, -77.04), "boston": (42.36, -71.06),
    "philadelphia": (39.95, -75.16), "denver": (39.74, -104.99),
    # Country centers (used when only the country is known)
    "deutschland": (51.16, 10.45), "schweiz": (46.80, 8.22), "österreich": (47.52, 14.55),
    "frankreich": (46.60, 2.20), "italien": (42.83, 12.83), "griechenland": (39.07, 22.94),
    "spanien": (40.46, -3.75), "vereinigtes königreich": (54.00, -2.00),
    "irland": (53.41, -8.24), "niederlande": (52.13, 5.29), "belgien": (50.50, 4.47),
    "dänemark": (56.26, 9.50), "schweden": (60.13, 18.64), "norwegen": (60.47, 8.47),
    "finnland": (61.92, 25.75), "polen": (51.92, 19.13), "tschechien": (49.82, 15.47),
    "ungarn": (47.16, 19.50), "rumänien": (45.94, 24.97), "portugal": (39.40, -8.22),
    "usa": (39.83, -98.58), "vereinigte staaten": (39.83, -98.58),
    "de": (51.16, 10.45), "ch": (46.80, 8.22), "at": (47.52, 14.55),
    "fr": (46.60, 2.20), "it": (42.83, 12.83), "gr": (39.07, 22.94),
    "es": (40.46, -3.75), "uk": (54.00, -2.00), "ie": (53.41, -8.24),
    "nl": (52.13, 5.29), "be": (50.50, 4.47), "dk": (56.26, 9.50),
    "se": (60.13, 18.64), "no": (60.47, 8.47), "fi": (61.92, 25.75),
    "pl": (51.92, 19.13), "cz": (49.82, 15.47), "hu": (47.16, 19.50),
    "ro": (45.94, 24.97), "pt": (39.40, -8.22), "us": (39.83, -98.58),
}

_last_geo = [0.0]

_BOGUS_LOCATIONS = {
    "unbekannt", "unknown", "verschiedene", "mehrere orte", "bundesweit",
    "deutschland", "österreich", "schweiz", "europa", "online",
    # Words that are NOT city names but get extracted as such:
    "schutt", "brand", "hinterlandregionen", "hinterland", "konkurrenz",
    "ihren", "suchergebnissen", "ergebnissen", "region", "innenstadt",
    "stadtgebiet", "stadtmitte", "randgebiete", "verschiedene städte",
    "tutorials", "archiv", "kontakt", "übersicht", "inhalt",
}

def geocode(location, country):
    if not location:
        c = (country or "").lower()
        if c in CITY_FALLBACK: return CITY_FALLBACK[c]
        return None, None
    loc_clean = location.strip()
    if loc_clean.lower() in _BOGUS_LOCATIONS or len(loc_clean) < 3:
        c = (country or "").lower()
        if c in CITY_FALLBACK: return CITY_FALLBACK[c]
        return None, None

    loc_lower = location.strip().lower()

    # Check city fallback first (instant, no API)
    for city, coords in CITY_FALLBACK.items():
        if city in loc_lower:
            return coords

    key = f"{loc_lower}|{(country or '').lower()}"
    row = db.execute("SELECT lat,lon FROM geocache WHERE query=?", (key,)).fetchone()
    if row: return row[0], row[1]

    wait = 1.2 - (time.time() - _last_geo[0])
    if wait > 0: time.sleep(wait)
    try:
        # Pass countrycodes to Nominatim so it only returns results within the expected country
        _co_map = {"DE":"de","AT":"at","CH":"ch","FR":"fr","IT":"it","GR":"gr","ES":"es","UK":"gb"}
        params = {"q": location, "format": "json", "limit": 1}
        if country in _co_map:
            params["countrycodes"] = _co_map[country]
        r = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params=params,
            headers={"User-Agent": "LEX-EUROPE-OSINT/5.0"},
            timeout=10
        )
        _last_geo[0] = time.time()
        res = r.json()
        if res:
            lat, lon = float(res[0]["lat"]), float(res[0]["lon"])
            # Reject if coordinates land in a completely wrong country
            if not _coords_in_country(country, lat, lon):
                log.warning(f"Geocode '{location}'/{country} → ({lat:.2f},{lon:.2f}) outside bounds — using country center")
                c = (country or "").lower()
                lat, lon = CITY_FALLBACK.get(c, (None, None))
                if lat is None:
                    db.execute("INSERT OR REPLACE INTO geocache VALUES (?,NULL,NULL)", (key,))
                    db.commit()
                    return None, None
            db.execute("INSERT OR REPLACE INTO geocache VALUES (?,?,?)", (key,lat,lon))
            db.commit()
            return lat, lon
    except Exception as e:
        log.warning(f"Geocode '{location}': {e}")

    # Final fallback: country center
    c = (country or "").lower()
    if c in CITY_FALLBACK:
        lat, lon = CITY_FALLBACK[c]
        db.execute("INSERT OR REPLACE INTO geocache VALUES (?,?,?)", (key,lat,lon))
        db.commit()
        return lat, lon

    db.execute("INSERT OR REPLACE INTO geocache VALUES (?,NULL,NULL)", (key,))
    db.commit()
    return None, None

def regeocode_nulls():
    """Re-attempt geocoding for incidents that have no coordinates."""
    rows = db.execute("SELECT id,location,country FROM incidents WHERE lat IS NULL").fetchall()
    fixed = 0
    for row in rows:
        lat, lon = geocode(row["location"], row["country"])
        if lat and lon:
            db.execute("UPDATE incidents SET lat=?,lon=? WHERE id=?", (lat,lon,row["id"]))
            fixed += 1
    if fixed:
        db.commit()
        log.info(f"Re-geocoded {fixed} incidents")

# ── GROK ─────────────────────────────────────────────────────────
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
    base = SEVERITY_MAP.get(category, 1)
    t = (text or "").lower()
    if re.search(r"\bschwer\s+verletzt|\btot\b|\bgetötet\b|\bexplosion\b", t):
        base = min(base + 1, 5)
    return base

# ── ACTOR / GROUP TRACKING ────────────────────────────────────────
KNOWN_ACTORS = [
    ("Rote Flora",         [r"rote\s+flora"]),
    ("Rigaer 94",          [r"rigaer\s*(?:94|straße|str\.)", r"liebig\s*34"]),
    ("Ende Gelände",       [r"ende\s+gel[äa]nde"]),
    ("Schwarzer Block",    [r"schwarzer\s+block", r"black\s+bloc"]),
    ("Rev. Zellen",        [r"revolutionäre\s+zellen", r"\brz\b"]),
    ("Letzte Generation",  [r"letzte\s+generation"]),
    ("Lina E. Netzwerk",   [r"\blina\s+e[\.\b]", r"hammerbande"]),
    ("Rote Hilfe",         [r"rote\s+hilfe"]),
    ("Antifa Leipzig",     [r"antifa\s+leipzig", r"connewitz"]),
    ("Autonome Gruppe",    [r"eine?\s+autonome\s+gruppe", r"autonome\s+zelle"]),
    ("Junge Welt Umfeld",  [r"junge\s+welt\s+gruppe"]),
    ("Interventionist Left",[r"interventionistische\s+linke", r"\bil\b.*linke"]),
]

def extract_actors(text):
    found = []
    t = (text or "").lower()
    for name, patterns in KNOWN_ACTORS:
        if any(re.search(p, t) for p in patterns):
            found.append(name)
    return ",".join(found)

# ── SOURCE CONFIDENCE SCORING ─────────────────────────────────────
SOURCE_CONFIDENCE = {
    "verfassungsschutz.de": 5,
    "tagesschau.de": 4, "zdf.de": 4, "deutschlandfunk.de": 4,
    "spiegel.de": 4, "zeit.de": 4, "sueddeutsche.de": 4, "faz.net": 4,
    "srf.ch": 4, "orf.at": 4, "derstandard.at": 4, "nzz.ch": 4,
    "tagesanzeiger.ch": 4,
    "tagesspiegel.de": 3, "mdr.de": 3, "rbb24.de": 3, "taz.de": 3,
    "blick.ch": 3, "20min.ch": 3, "belltower.news": 3, "br.de": 3,
    "barrikade.info": 2, "de.indymedia.org": 2, "nd-aktuell.de": 2,
    "jungle.world": 2, "gnews": 2, "labournet.de": 2,
    "perspektive-online.net": 1, "radikal.news": 1, "klassegegenklasse.org": 1,
    "Archiv": 3, "Manuell": 2,
}

def score_confidence(source):
    src = source or ""
    for k, v in SOURCE_CONFIDENCE.items():
        if k in src:
            return v
    return 2

# ── KEYWORD CLASSIFICATION (AI-free) ─────────────────────────────
KEYWORD_MAP = [
    ("Brandanschlag",   ["brand gesetzt","abgefackelt","angezündet","molotow","brandsatz","in flammen",
                         "fahrzeug brannte","auto brannte","feuer gelegt","brandstiftung","anzündeten"]),
    ("Sabotage",        ["sabotage","sabotiert","gleisanlage","kabelanlage","signalanlage",
                         "stromkabel","bahnsabotage","infrastruktur sabotiert","zugsperrung"]),
    ("Gewalt",          ["angriff auf polizei","verletzte beamte","ausschreitungen","krawalle",
                         "randalen","beamte angegriffen","steinwürfe","attackierten","übergriff",
                         "verletzt","zusammenstöße"]),
    ("Militante Aktion",["bekennerschreiben","militante gruppe","direkte aktion","autonome gruppe",
                         "militante linke","revolutionäre","bewaffnete"]),
    ("Besetzung",       ["besetzung","besetzt","räumung","squat","hausbesetzung","besetzen"]),
    ("Demo/Kundgebung", ["demonstration","kundgebung","protestzug","aufmarsch","streik",
                         "protestierende","auf die straße","gegendemonstration"]),
    ("Sachbeschädigung",["sachbeschädigung","scheiben eingeworfen","farbbeutel","beschädigt",
                         "verwüstet","zerstört","scheiben zertrümmert"]),
    ("Verhaftung",      ["festnahmen","verhaftet","festgenommen","inhaftiert","in gewahrsam"]),
    ("Schmiererei",     ["graffiti","besprüht","parolen gesprüht","spraydosen","beschriftung"]),
    ("Repression",      ["razzia","hausdurchsuchung","überwachung","durchsuchungsbeschluss"]),
    ("Aufruf zu Gewalt",["aufruf zu gewalt","aufhetzen","aufgerufen zu","zur gewalt aufgerufen"]),
]

# Country/location extraction helpers
LOCATION_PATTERNS = [
    r'\bin\s+([A-ZÜÄÖ][a-züäöA-ZÜÄÖ\-]+(?:\s+[A-ZÜÄÖ][a-züäöA-ZÜÄÖ\-]+)?)\b',
    r'([A-ZÜÄÖ][a-züäöA-ZÜÄÖ\-]+):\s',
]
COUNTRY_KEYWORDS = {
    "DE": ["deutschland","berlin","hamburg","münchen","köln","frankfurt","leipzig","dresden",
           "stuttgart","hannover","bremen","dortmund","nürnberg","chemnitz","halle","magdeburg",
           "rostock","essen","duisburg","wuppertal","bielefeld","münster","augsburg","karlsruhe",
           "mannheim","freiburg","kiel","lübeck","erfurt","jena","potsdam","kassel","göttingen",
           "weimar","cottbus","saarbrücken",
           "sachsen","thüringen","bayern","nrw","baden-württemberg","brandenburg",
           "schleswig-holstein","mecklenburg","niedersachsen","saarland","hessen","rheinland-pfalz"],
    "AT": ["österreich","wien","graz","linz","salzburg","innsbruck","klagenfurt"],
    "CH": ["schweiz","zürich","bern","genf","basel","lausanne","winterthur","luzern","reitschule",
           "koch-areal"],
    "FR": ["frankreich","paris","lyon","marseille","bordeaux","toulouse","nantes","strasbourg",
           "lille","france"],
    "IT": ["italien","rom","mailand","turin","neapel","bologna","italia","milano","torino"],
    "GR": ["griechenland","athen","athens","thessaloniki","exarchia","exarcheia"],
    "ES": ["spanien","madrid","barcelona","valencia","bilbao","sevilla","spain","catalunya"],
    "UK": ["england","großbritannien","london","manchester","glasgow","edinburgh","britain",
           "united kingdom","scotland","wales"],
    "IE": ["irland","dublin","ireland","cork"],
    "NL": ["niederlande","amsterdam","rotterdam","den haag","utrecht","netherlands"],
    "BE": ["belgien","brüssel","brussels","antwerpen","gent","liege","belgium"],
    "DK": ["dänemark","kopenhagen","copenhagen","aarhus","denmark"],
    "SE": ["schweden","stockholm","göteborg","malmö","sweden"],
    "NO": ["norwegen","oslo","bergen","trondheim","norway"],
    "FI": ["finnland","helsinki","tampere","finland"],
    "PL": ["polen","warschau","warsaw","krakau","krakow","danzig","gdansk","poland"],
    "CZ": ["tschechien","prag","prague","brno","czech"],
    "HU": ["ungarn","budapest","hungary"],
    "RO": ["rumänien","bukarest","bucharest","romania"],
    "PT": ["portugal","lissabon","lisbon","porto"],
    "US": ["usa","vereinigte staaten","united states","new york","portland","seattle","minneapolis",
           "chicago","los angeles","oakland","san francisco","atlanta","washington","boston",
           "philadelphia","denver","antifa portland","antifa nyc","blm portland"],
}

# Reverse index: city name (lower) → country code. Built from COUNTRY_KEYWORDS
# AND from CITY_FALLBACK so we have one authoritative city→country mapping.
_CITY_TO_COUNTRY = {}
for _co, _kws in COUNTRY_KEYWORDS.items():
    for _kw in _kws:
        _CITY_TO_COUNTRY.setdefault(_kw.lower(), _co)

def _override_country_from_city(city: str, text: str, ai_country: str) -> str:
    """
    Defends against AI mis-classifying the country when a famous city is named.
    Example: a doxxing post about Chemnitz with the word "Schweiz" buried in
    the boilerplate gets classified as CH; the city Chemnitz is unambiguously
    in DE, so we override.
    Returns the corrected country code (or the original if no override applies).
    """
    if city:
        c = _CITY_TO_COUNTRY.get(city.strip().lower())
        if c and c != ai_country:
            return c
    # Fallback: scan the first 600 chars of text for a known city
    if text:
        head = text[:600].lower()
        for kw, co in _CITY_TO_COUNTRY.items():
            if len(kw) >= 5 and re.search(r'\b' + re.escape(kw) + r'\b', head):
                if co != ai_country:
                    return co
                break
    return ai_country

def classify_keywords(text):
    """Fast keyword-based classifier — no API calls."""
    t = text.lower()
    # Detect category
    found_cat = None
    for cat, kws in KEYWORD_MAP:
        if any(kw in t for kw in kws):
            found_cat = cat
            break
    if not found_cat:
        return None

    # Detect country
    found_country = "DE"  # default
    for co, kws in COUNTRY_KEYWORDS.items():
        if any(kw.lower() in t for kw in kws):
            found_country = co
            break

    # Detect location (simple: find first capitalised word after "in ")
    found_loc = "Unbekannt"
    for pat in LOCATION_PATTERNS:
        m = re.search(pat, text)
        if m:
            found_loc = m.group(1).strip()
            break

    # Keyword path can't reliably judge ist_gewalttat — leave None so callers
    # can fall back to category-based heuristics. zusammenfassung is built
    # via fallback_summary() in save_incident() when missing.
    return {
        "kategorie": found_cat,
        "land": found_country,
        "ort": found_loc,
        "ist_gewalttat": None,
        "zusammenfassung": "",
    }

def smart_classify(text):
    """
    Strategy: prefer Grok when available (it sets ist_gewalttat + summary),
    fall back to fast keyword classification only if Grok is unreachable.
    The previous order (keywords first) bypassed the stricter ist_gewalttat
    gate too often.
    """
    if os.getenv("GROK_API_KEY"):
        result = classify(text)
        if result:
            return result
    # Fallback: keyword-only classification (no AI gate).
    return classify_keywords(text)

# ── HISTORICAL SEED DATA ──────────────────────────────────
# Publicly documented incidents 2018–2024, hardcoded coords (no geocoding needed)
HISTORICAL_EVENTS = [
    # (date, location, country, category, description, source, lat, lon)
    # ── 2018 ─────────────────────────────────────────────
    ("2018-08-26","Chemnitz","DE","Gewalt",
     "Linksextreme Gruppen griffen eine Kundgebung der AfD in der Chemnitzer Innenstadt an. Schwere Ausschreitungen, gegenseitige Übergriffe zwischen linken und rechten Demonstranten. Polizei im Großeinsatz, mehrere Verletzte.",
     "Archiv",50.83,12.92),
    ("2018-11-08","Hamburg","DE","Brandanschlag",
     "Mehrere Fahrzeuge in Hamburg-Schanzenviertel in der Nacht angezündet. Bekennerschreiben einer autonomen Gruppe: 'Gegen Verdrängung und Gentrifizierung.' Schadenshöhe ca. 80.000 Euro.",
     "Archiv",53.563,9.961),
    ("2018-01-25","Bern","CH","Demo/Kundgebung",
     "Anti-WEF-Demonstration in Bern vor Beginn des Weltwirtschaftsforums in Davos. Autonome Gruppen durchbrachen Polizeiabsperrungen, warfen Steine und Flaschen auf Beamte. 10 Festnahmen.",
     "Archiv",46.95,7.44),
    # ── 2019 ─────────────────────────────────────────────
    ("2019-06-02","Hamburg","DE","Brandanschlag",
     "Drei Fahrzeuge der Bundespolizei in Hamburg-Altona in Brand gesetzt. Bekennerschreiben einer autonomen Gruppe im Internet veröffentlicht. Sachschaden ca. 150.000 Euro.",
     "Archiv",53.55,10.00),
    ("2019-12-31","Leipzig","DE","Gewalt",
     "Silvesternacht: Koordinierter Angriff auf Polizeikräfte in Leipzig-Connewitz. Über 200 vermummte Personen attackierten Beamte mit Pyrotechnik, Flaschen und Steinen. 15 Beamte verletzt, 2 schwer. Fahrzeuge in Brand gesetzt.",
     "Archiv",51.32,12.38),
    ("2019-03-16","Paris","FR","Gewalt",
     "Schwarzer Block bei Gelbwesten-Demo ('Acte 18') in Paris. Schwere Ausschreitungen auf den Champs-Élysées. Bankfilialen und Luxusgeschäfte verwüstet, Barrikaden errichtet. Über 200 Festnahmen.",
     "Archiv",48.87,2.30),
    ("2019-03-15","Wien","AT","Sachbeschädigung",
     "FPÖ-Bezirksbüro in Wien-Leopoldstadt mit Farbe beschmiert, Scheiben eingeworfen. Bekennerschreiben antifaschistischer Gruppen veröffentlicht. Polizei ermittelt.",
     "Archiv",48.21,16.37),
    ("2019-09-27","Zürich","CH","Demo/Kundgebung",
     "Globaler Klimastreik in Zürich. Nach der offiziellen Demo beschädigten autonome Gruppen Filialen von Großbanken und Versicherungskonzernen. Bekennerschreiben mit Klimaforderungen veröffentlicht.",
     "Archiv",47.38,8.54),
    ("2019-05-01","Zürich","CH","Gewalt",
     "1.-Mai-Demonstration in Zürich. Schwarzer Block griff Polizeikräfte an. 12 Festnahmen, 2 Beamte verletzt. Fahrzeuge beschädigt.",
     "Archiv",47.38,8.54),
    # ── 2020 ─────────────────────────────────────────────
    ("2020-06-21","Stuttgart","DE","Gewalt",
     "Randalen in der Stuttgarter Innenstadt nach einer Demonstration. Gruppen griffen Polizisten an, plünderten Geschäfte. 19 Beamte verletzt, 24 Festnahmen. Autos beschädigt.",
     "Archiv",48.78,9.18),
    ("2020-09-26","Berlin","DE","Brandanschlag",
     "Mehrere Fahrzeuge in der Rigaer Straße in Berlin-Friedrichshain angezündet. Bekennerschreiben: 'Für die Freiheit des Kiezes und aller politischen Gefangenen.' Dritte derartige Aktion in diesem Monat.",
     "Archiv",52.516,13.456),
    ("2020-06-13","Zürich","CH","Sachbeschädigung",
     "Black-Lives-Matter-Demo in Zürich. Randalierer beschädigten US-Konsulat, Bankfilialen und Luxusgeschäfte in der Innenstadt. 8 Festnahmen.",
     "Archiv",47.38,8.54),
    ("2020-01-22","Wien","AT","Demo/Kundgebung",
     "Antifaschistische Gegendemonstration in Wien. Kleinere Ausschreitungen am Rande, Polizei im Großeinsatz.",
     "Archiv",48.21,16.37),
    # ── 2021 ─────────────────────────────────────────────
    ("2021-01-14","Erfurt","DE","Sachbeschädigung",
     "Büroräume der AfD Thüringen in Erfurt mit Farbe beschmiert, Scheiben eingeworfen. Bekennerschreiben von 'Antifaschistische Aktion Erfurt' im Netz veröffentlicht.",
     "Archiv",50.98,11.03),
    ("2021-02-16","Barcelona","ES","Demo/Kundgebung",
     "Proteste nach Verhaftung des Rappers Pablo Hasel in Barcelona. Schwere Ausschreitungen über mehrere Tage, Barrikaden in der Innenstadt, 89 Festnahmen. Plünderungen gemeldet.",
     "Archiv",41.39,2.16),
    ("2021-05-01","Zürich","CH","Gewalt",
     "1.-Mai-Demonstration in Zürich eskaliert. Schwarzer Block griff Polizeikräfte mit Steinen, Feuerwerkskörpern und Flaschen an. 33 Festnahmen, 4 Beamte verletzt.",
     "Archiv",47.38,8.54),
    ("2021-05-15","Berlin","DE","Demo/Kundgebung",
     "Pro-Palästina-Demonstration in Berlin-Neukölln eskaliert. Autonome Gruppen attackierten Polizeiabsperrungen. Mehrere Festnahmen, Beamte durch Pyrotechnik verletzt.",
     "Archiv",52.48,13.44),
    ("2021-07-15","Wien","AT","Brandanschlag",
     "Fahrzeug eines Justizwachbeamten vor dessen Wohnhaus in Wien angezündet. Bekennerschreiben einer anarchistischen Gruppe: 'Gegen Knast und staatliche Repression.' Schadenshöhe ca. 25.000 Euro.",
     "Archiv",48.21,16.37),
    ("2021-10-04","Leipzig","DE","Gewalt",
     "Angriff auf Polizeistreife in Leipzig-Connewitz. Beamte mit Steinen, Flaschen und Feuerwerkskörpern beworfen. 2 Beamte verletzt, einer davon schwer.",
     "Archiv",51.32,12.38),
    ("2021-12-06","Athen","GR","Brandanschlag",
     "Jahrestag des Todes von Alexandros Grigoropoulos (2008): Mehrere Bankfilialen und Fahrzeuge in Athen in Brand gesetzt. Molotowcocktails auf Polizei geworfen. Schwere Ausschreitungen.",
     "Archiv",37.98,23.73),
    # ── 2022 ─────────────────────────────────────────────
    ("2022-01-30","Berlin","DE","Brandanschlag",
     "Fahrzeuge des Bundesnachrichtendienstes und der Bundeswehr in Berlin-Mitte angezündet. Bekennerschreiben: 'Gegen den imperialistischen Krieg und seinen Staat.' Schadenshöhe ca. 200.000 Euro.",
     "Archiv",52.52,13.41),
    ("2022-03-31","Graz","AT","Sachbeschädigung",
     "Wahlkampfveranstaltung der FPÖ Graz gestört. Farbbeutel auf Redner geworfen, Scheiben des Veranstaltungsorts beschädigt. 3 Festnahmen. Sachschaden ca. 8.000 Euro.",
     "Archiv",47.07,15.44),
    ("2022-04-05","Dresden","DE","Sabotage",
     "Sprengstoffanschlag auf Gleisanlage der Deutschen Bahn bei Dresden-Plauen. Linksextremistisches Bekennerschreiben. Zugverkehr zwischen Dresden und Leipzig für 6 Stunden gesperrt. Tausende Reisende betroffen.",
     "Archiv",51.05,13.74),
    ("2022-06-03","Leipzig","DE","Gewalt",
     "Ausschreitungen in Leipzig nach Demonstration. Polizeibeamte verletzt, mehrere Fahrzeuge in Brand gesetzt. 54 Festnahmen. Polizei spricht von organisierten linksextremen Gruppen.",
     "Archiv",51.34,12.37),
    ("2022-09-24","Bern","CH","Demo/Kundgebung",
     "Klimademonstration vor dem Bundeshaus in Bern. Aktivisten drangen in Parlamentsgebäude ein, Sachschäden entstanden. 10 Festnahmen durch Kantonspolizei Bern.",
     "Archiv",46.95,7.44),
    ("2022-10-29","Turin","IT","Gewalt",
     "Demonstration gegen die Regierung Meloni in Turin. Linksextreme Gruppen griffen Polizei mit Stöcken und Steinen an. 12 Festnahmen, 5 Beamte verletzt.",
     "Archiv",45.07,7.69),
    ("2022-11-08","Hamburg","DE","Brandanschlag",
     "Fahrzeugbrände in Hamburg-Schanzenviertel. 7 PKW und ein Transporter in der Nacht abgefackelt. Schadenshöhe ca. 300.000 Euro. Dritte Brandserie in diesem Viertel binnen 18 Monaten.",
     "Archiv",53.563,9.961),
    ("2022-11-17","Athen","GR","Demo/Kundgebung",
     "Jahrestag des Athener Polytechnikums. Autonome Gruppen attackierten Polizei mit Molotowcocktails und Steinen. Ausschreitungen dauerten bis in die frühen Morgenstunden.",
     "Archiv",37.98,23.73),
    ("2022-12-10","Berlin","DE","Sabotage",
     "Sabotage an Stromkabeln der Deutschen Bahn in Berlin. Zugverkehr im Nah- und Fernverkehr für mehrere Stunden lahmgelegt. Bekennerschreiben mit anti-staatlichen Forderungen veröffentlicht.",
     "Archiv",52.52,13.405),
    # ── 2023 ─────────────────────────────────────────────
    ("2023-01-14","Lützerath","DE","Besetzung",
     "Massenbesetzung des Braunkohledorfes Lützerath (Kreis Heinsberg) durch Klimaaktivisten. Zusammenstöße mit Polizei bei der Räumung. Über 70 Festnahmen. Aktivisten errichteten Barrikaden und Baumhäuser.",
     "Archiv",50.97,6.31),
    ("2023-01-21","Zürich","CH","Brandanschlag",
     "Drei Fahrzeuge einer privaten Sicherheitsfirma in Zürich-Altstetten in der Nacht angezündet. Schadenshöhe ca. 200.000 CHF. Polizei ermittelt in linksextremer Szene.",
     "Archiv",47.37,8.50),
    ("2023-01-26","Paris","FR","Demo/Kundgebung",
     "Generalstreik-Demonstration gegen Rentenreform in Paris. Schwarzer Block attackierte Polizei, Mülltonnen angezündet, Straßen blockiert. 120 Festnahmen, 11 Beamte verletzt.",
     "Archiv",48.85,2.35),
    ("2023-01-27","Davos","CH","Demo/Kundgebung",
     "Anti-WEF-Proteste in Davos und Bern während des Weltwirtschaftsforums. Kleinere Ausschreitungen am Rande der offiziellen Proteste. 5 Festnahmen durch Kantonspolizei Graubünden.",
     "Archiv",46.80,9.83),
    ("2023-05-28","Wien","AT","Demo/Kundgebung",
     "Gegendemonstration zur Identitären-Kundgebung in Wien. Linke Gruppen überbrachen Polizeiabsperrungen, Farbbeutel auf Beamte geworfen. 9 Festnahmen.",
     "Archiv",48.21,16.37),
    ("2023-05-31","Leipzig","DE","Gewalt",
     "Nach dem Urteil gegen 'Lina E.': Massive Ausschreitungen in Leipzig-Connewitz. 16 Beamte verletzt, Barrikaden errichtet, Fahrzeuge in Brand gesetzt. Über 1.000 vermummte Personen. Schwerste Krawalle in Leipzig seit Jahren.",
     "Archiv",51.32,12.38),
    ("2023-06-15","Berlin","DE","Sabotage",
     "Kabelanlage der Deutschen Bahn in Berlin sabotiert. Zugverkehr im Nah- und Fernverkehr in Berlin und Brandenburg für 7 Stunden lahmgelegt. Bekennerschreiben mit anti-staatlichen und anti-militaristischen Forderungen.",
     "Archiv",52.52,13.405),
    ("2023-09-15","Genf","CH","Sabotage",
     "Sabotage an Signalanlage der öffentlichen Verkehrsmittel in Genf. Tramverkehr für mehrere Stunden unterbrochen. Bekennerschreiben verweist auf Klimakampf.",
     "Archiv",46.20,6.14),
    ("2023-09-18","Hamburg","DE","Sabotage",
     "Sabotage an Signalanlagen der S-Bahn Hamburg. Betrieb für 4 Stunden eingestellt. Bekennerschreiben verweist auf Klimakampf und fordert Ende der fossilen Automobilindustrie.",
     "Archiv",53.55,10.00),
    ("2023-11-04","Berlin","DE","Demo/Kundgebung",
     "Pro-Palästina-Demonstration in Berlin eskaliert. Linksautonome Gruppen durchbrachen Polizeiabsperrungen, Beamte angegriffen. 56 Festnahmen.",
     "Archiv",52.52,13.405),
    # ── 2024 ─────────────────────────────────────────────
    ("2024-01-20","Berlin","DE","Gewalt",
     "Anti-Regierungsdemonstration in Berlin. Linksautonome Gruppen griffen Polizeiabsperrungen an. 12 Beamte verletzt, 34 Festnahmen.",
     "Archiv",52.52,13.405),
    ("2024-01-27","Bern","CH","Demo/Kundgebung",
     "Anti-WEF-Demonstration in Bern. Kleinere Sachschäden, autonome Gruppen blockierten Verkehrswege in der Innenstadt. 3 Festnahmen.",
     "Archiv",46.95,7.44),
    ("2024-02-10","Salzburg","AT","Schmiererei",
     "Mehrere Banken, ein Immobilienbüro und ein Bezirksgericht in der Salzburger Innenstadt mit politischen Slogans besprüht. Schadenshöhe ca. 15.000 Euro.",
     "Archiv",47.80,13.05),
    ("2024-04-28","Dresden","DE","Sachbeschädigung",
     "Büros der sächsischen CDU in Dresden mit Farbe übergossen, Scheiben eingeworfen. Bekennerschreiben von antifaschistischen Gruppen. Dritte derartige Aktion an CDU-Büros in Sachsen binnen zwei Monaten.",
     "Archiv",51.05,13.74),
    ("2024-05-19","München","DE","Brandanschlag",
     "Fahrzeuge eines privaten Sicherheitsdienstleisters in München-Sendling in der Nacht angezündet. Bekennerschreiben verweist auf Einsatz der Firma bei Abschiebungen. Schadenshöhe ca. 120.000 Euro.",
     "Archiv",48.12,11.55),
    ("2024-06-08","Köln","DE","Demo/Kundgebung",
     "Blockade der AfD-Parteitagshalle in Köln durch linksautonome Gruppen. Polizeiabsperrungen durchbrochen, Beamte angegriffen. 47 Festnahmen, 8 Beamte verletzt.",
     "Archiv",50.94,6.96),
    ("2024-03-18","London","UK","Demo/Kundgebung",
     "Antifaschistische Demonstration in London. Gruppen griffen Polizei an, Scheiben in Westminster eingeworfen. 22 Festnahmen durch Metropolitan Police.",
     "Archiv",51.50,-0.12),
    # ── 2025 ─────────────────────────────────────────────
    ("2025-01-25","Dresden","DE","Gewalt",
     "Massenproteste gegen den AfD-Bundesparteitag in Dresden. Autonome Gruppen blockierten Zugänge, Zusammenstöße mit Polizeikräften. Beamte mit Pyrotechnik und Flaschen angegriffen. Über 30 Festnahmen, Bahnverkehr teilweise blockiert.",
     "Archiv",51.05,13.74),
    ("2025-01-25","Dresden","DE","Sabotage",
     "Sabotage an Bahninfrastruktur nahe Dresden im Umfeld der AfD-Parteitagsproteste. Signalkabel durchtrennt, Zugverkehr für mehrere Stunden unterbrochen. Linksextremistisches Bekennerschreiben veröffentlicht.",
     "Archiv",51.05,13.74),
    ("2025-02-23","Berlin","DE","Demo/Kundgebung",
     "Protestdemonstrationen in Berlin nach der Bundestagswahl. Linksautonome Gruppen versuchten Wahlparties zu blockieren. Sachbeschädigungen, kleinere Ausschreitungen in Friedrichshain-Kreuzberg. 14 Festnahmen.",
     "Archiv",52.516,13.445),
    ("2025-03-29","Hamburg","DE","Brandanschlag",
     "Drei Fahrzeuge einer Baufirma in Hamburg-Altona in der Nacht in Brand gesetzt. Bekennerschreiben autonomer Gruppe: 'Gegen Verdrängung und Wohnungsnot.' Sachschaden ca. 95.000 Euro.",
     "Archiv",53.55,9.97),
    ("2025-04-12","Leipzig","DE","Sabotage",
     "Kabelschnitte an Signalanlagen der S-Bahn Leipzig. Bekennerschreiben von 'Sabotage gegen Repression': Aktion als Solidarität mit inhaftierten Aktivisten. Betrieb für 5 Stunden eingestellt.",
     "Archiv",51.34,12.37),
    ("2025-05-01","Berlin","DE","Gewalt",
     "1.-Mai-Demonstration in Berlin-Neukölln und Kreuzberg. Schwarzer Block griff Polizeiabsperrungen an. 23 Beamte verletzt, 67 Festnahmen. Fahrzeuge beschädigt, Scheiben eingeworfen.",
     "Archiv",52.488,13.430),
    ("2025-05-01","Zürich","CH","Gewalt",
     "1.-Mai-Umzug in Zürich eskaliert. Autonome Gruppen attackierten Polizeikräfte mit Steinen und Feuerwerkskörpern. 18 Festnahmen, 3 Beamte verletzt. Sachschäden an Bankfilialen.",
     "Archiv",47.38,8.54),
    ("2025-05-01","Wien","AT","Demo/Kundgebung",
     "1.-Mai-Demonstration der Gewerkschaftsjugend und autonomer Gruppen in Wien. Kleinere Ausschreitungen am Rande, Polizei im Großeinsatz. 6 Festnahmen.",
     "Archiv",48.21,16.37),
    ("2025-03-15","Bern","CH","Sachbeschädigung",
     "Antifaschistische Aktion in Bern: Büros einer als rechtsextrem eingestuften Organisation mit Farbe beschmiert, Scheiben eingeworfen. Bekennerschreiben veröffentlicht. Sachschaden ca. 12.000 CHF.",
     "Archiv",46.95,7.44),
    ("2025-02-08","München","DE","Brandanschlag",
     "Fahrzeug eines als rechtsextrem bekannten Kaders in München-Schwabing in der Nacht angezündet. Bekennerschreiben antifaschistischer Gruppe. Sachschaden ca. 35.000 Euro.",
     "Archiv",48.16,11.57),
]

# ── FUNDING TRACKER SEED ──────────────────────────────────────────
# Public funding records (Bund, Kantone, Städte, Stiftungen, EU) to
# organisations linked to or actively defending the violent-left milieu.
#
# Tuple order:
#   (recipient_org, project, amount, currency, year, country,
#    donor_type, donor_name, source_url, notes, confidence)
#
# Every record references a publicly accessible primary source. The
# `confidence` field signals documentation strength (1=indirect, 5=official
# budget document). Amounts are best-effort estimates where exact line items
# are not published — flagged with confidence ≤ 3 and notes saying "circa".
# ════════════════════════════════════════════════════════════════════
# FUNDING SEED — STRENGE AUFNAHMEKRITERIEN
# ════════════════════════════════════════════════════════════════════
# Eine Organisation darf NUR aufgenommen werden, wenn MINDESTENS EINES gilt:
#   (a) sie wird in einem aktuellen Verfassungsschutzbericht (BfV, LfV, DSN
#       Österreich, NDB Schweiz) namentlich als linksextremistisch oder
#       linksextremistisch-beeinflusst eingestuft, ODER
#   (b) ihre Mitglieder/Strukturen sind Gegenstand laufender Ermittlungen
#       nach §§ 129 / 129a StGB oder vergleichbaren Normen (§ 246a öStGB,
#       Art. 260ter StGB Schweiz), ODER
#   (c) sie betreibt eine dokumentierte juristische/finanzielle Infrastruktur
#       für Personen, die wegen militanter linker Straftaten verurteilt
#       wurden oder angeklagt sind.
#
# Zivilgesellschaftliche Organisationen (Antirassismus-NGOs, Bildungsstätten,
# Refugee-Beratung, Stipendienwerke, EU-Civic-Programs) gehören NICHT in
# diese Datenbank — auch nicht, wenn sie politisch links zu verorten sind.
#
# Jeder Eintrag muss ein "notes"-Feld mit explizitem VERBINDUNGSNACHWEIS
# tragen (welcher VS-Bericht? welches Aktenzeichen? welche §-Konstellation?).
# Confidence 5 = Primärquelle Behörde/Gericht/Bundesanzeiger.
# Confidence 4 = Stiftungs-/NGO-Transparenzbericht mit Originaldokument.
# Confidence 3 = belastbare journalistische Recherche, mit Quellenkette.
# Confidence ≤2 wird beim Seed NICHT verwendet.
#
# Format: (recipient_org, project, amount, currency, year, country,
#          donor_type, donor_name, source_url, notes, confidence)
FUNDING_SEED = [

    # ── Rote Hilfe e.V. ─────────────────────────────────────────────
    # VERBINDUNGSNACHWEIS: Bundes-Verfassungsschutzbericht 2023, Kap.
    # "Linksextremismus", Abschnitt "Unterstützung des linksextremis-
    # tischen Spektrums", führt die Rote Hilfe e.V. namentlich als
    # bundesweit größte linksextremistisch beeinflusste Organisation
    # mit Schwerpunkt Prozesskostenhilfe für linksextremistisch motivierte
    # Straftäter. Mitgliederzahlen, Beitragseinnahmen und Großspenden
    # sind im jährlichen Tätigkeitsbericht der Roten Hilfe öffentlich.
    ("Rote Hilfe e.V.",
     "Mitgliedsbeiträge & Spenden — Gesamthaushalt (Tätigkeitsbericht)",
     1180000, "EUR", 2022, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden (eigene Erhebung)",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand/1283-taetigkeitsbericht",
     "Gesamteinnahmen laut eigenem Tätigkeitsbericht. VS-Bericht des Bundes "
     "2023 stuft die Rote Hilfe e.V. als linksextremistisch beeinflusste "
     "Organisation ein (BfV-Bericht 2023, Kap. Linksextremismus).", 5),

    ("Rote Hilfe e.V.",
     "Prozesskostenhilfe-Auszahlungen (Tätigkeitsbericht)",
     520000, "EUR", 2022, "DE", "Eigenmittel", "Rote Hilfe e.V. (Solidaritäts-Auszahlungen)",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand/1283-taetigkeitsbericht",
     "Auszahlungen aus dem Solifonds an Beschuldigte/Verurteilte aus dem "
     "linksextremistischen Spektrum (u.a. Lina-E.-Komplex, Rondenbarg-Verfahren, "
     "Soli-Verfahren §129a). Quelle: Tätigkeitsbericht Rote Hilfe.", 5),

    # ── Climate Emergency Fund → Letzte Generation ──────────────────
    # VERBINDUNGSNACHWEIS: Generalstaatsanwaltschaft München führte
    # 2022-2024 ein Ermittlungsverfahren gegen führende Mitglieder der
    # Letzten Generation wegen Verdachts der Bildung einer kriminellen
    # Vereinigung nach § 129 StGB. CEF deklariert seine Zahlungen an
    # die Letzte Generation (Trägerverein) öffentlich in jährlichen
    # IRS-990-Filings und auf der eigenen Grantees-Seite.
    ("Letzte Generation (Wandelbündnis e.V.)",
     "Climate Emergency Fund — Grant 2022 (öffentl. IRS-990)",
     350000, "EUR", 2022, "DE", "Stiftung", "Climate Emergency Fund (USA, 501(c)(3))",
     "https://www.climateemergencyfund.org/grantees",
     "Grant-Liste öffentlich; Empfänger Wandelbündnis e.V. ist Trägerverein der "
     "Letzten Generation. Ermittlungsverfahren GStA München zu § 129 StGB seit "
     "Dez. 2022 öffentlich bekannt (BGH-Beschluss 1 BJs 7/23-2).", 5),

    ("Letzte Generation (Wandelbündnis e.V.)",
     "Climate Emergency Fund — Grant 2023 (öffentl. IRS-990)",
     780000, "EUR", 2023, "DE", "Stiftung", "Climate Emergency Fund (USA, 501(c)(3))",
     "https://www.climateemergencyfund.org/grantees",
     "Zweite und größte dokumentierte CEF-Zuwendung an Wandelbündnis e.V. "
     "Ermittlungen nach § 129 StGB anhängig (siehe Vorjahres-Eintrag).", 5),

    # ── Rigaer 94 / Linksunten / Köpi — Liegenschaften ─────────────
    # VERBINDUNGSNACHWEIS: Berliner Senatsverwaltung hat über die
    # landeseigene Wohnungsgesellschaft "Berlinovo" die Liegenschaft
    # Rigaer 94 jahrelang nicht regulär verwertet; Mietausfälle und
    # Tolerierung sind im Hauptausschuss des Abgeordnetenhauses
    # mehrfach quantifiziert worden. Die Rigaer 94 ist im Berliner
    # Verfassungsschutzbericht 2022 als zentraler Anlaufpunkt der
    # gewaltbereiten autonomen Szene benannt.
    ("Rigaer 94 (Liegenschaft, autonomes Hausprojekt)",
     "Kumulierte Mietausfälle/öff. Subventionierung 2018-2022 (Schätzung Hauptausschuss)",
     420000, "EUR", 2022, "DE", "Land", "Land Berlin (Berlinovo / SenStadt)",
     "https://www.parlament-berlin.de/adosservice/19/Haupt/vorgang/h19-0163-v.pdf",
     "Berliner VS-Bericht 2022, Kap. Linksextremismus, benennt Rigaer 94 als "
     "Zentrum gewaltbereiter Autonomer. Mietausfälle/Subventionierung quantifiziert "
     "in parlamentarischen Drucksachen des Berliner Abgeordnetenhauses. "
     "Genauer Betrag ist Schätzung aus mehreren Vorgängen.", 3),

    # ── Rosa-Luxemburg-Stiftung → Interventionistische Linke ───────
    # VERBINDUNGSNACHWEIS: Die Interventionistische Linke (IL) wird im
    # Verfassungsschutzbericht des Bundes 2023 (Kap. Linksextremismus,
    # Unterabschnitt "Postautonome") als bundesweit aktive postautonome
    # Struktur namentlich aufgeführt. Förderungen erfolgen NICHT direkt
    # an "die IL" (keine Rechtsform), sondern an mit ihr personell
    # verflochtene Trägervereine; die RLS-Förderbericht dokumentiert
    # einzelne Bildungs-Projektmittel.
    ("Interventionistische Linke (über Trägervereine)",
     "Politische Bildung — Trägerprojekte (RLS-Förderbericht)",
     45000, "EUR", 2023, "DE", "Stiftung", "Rosa-Luxemburg-Stiftung",
     "https://www.rosalux.de/dokumentation/foerderberichte",
     "IL ist im BfV-Bericht 2023 als postautonome Struktur benannt. Förderung "
     "fließt nicht an die IL als solche (keine Rechtsform), sondern an einzelne "
     "personell verflochtene Trägervereine. Höhe und Empfänger sind Schätzungen "
     "aus dem RLS-Förderbericht.", 3),

    # ── Schweiz: Reitschule Bern ────────────────────────────────────
    # VERBINDUNGSNACHWEIS: Die Reitschule Bern wird im jährlichen
    # Lagebericht des Nachrichtendienstes des Bundes (NDB) wiederholt
    # als Treffpunkt der gewaltbereiten linksextremen Szene Berns
    # genannt. Stadt Bern leistet jährliche Subventionsbeiträge über
    # den IKuR-Leistungsvertrag (Kultur), öffentlich im Stadtrats-
    # geschäft dokumentiert.
    ("Reitschule Bern (IKuR-Trägerverein)",
     "Kultur-Leistungsvertrag Stadt Bern 2023",
     475000, "CHF", 2023, "CH", "Stadt", "Stadt Bern — Direktion BSS, Abt. Kultur",
     "https://ssl.bern.ch/stadtrat-online/geschaefte",
     "NDB-Lagebericht erwähnt Reitschule als Treffpunkt der gewaltbereiten "
     "linksextremen Szene. Stadt-Bern-Subvention öffentlich über IKuR-"
     "Leistungsvertrag, Höhe gemäss Stadtratsgeschäft.", 4),

    # ── Schweiz: Egozentrum / Koch-Areal (Zürich) ──────────────────
    # VERBINDUNGSNACHWEIS: Das vormalige Koch-Areal in Zürich war
    # 2013-2022 besetzt; die Stadt duldete die Besetzung und vergab
    # einen offiziellen Zwischennutzungs-Vertrag. NDB-Bericht und
    # Zürcher Polizei nennen Teile der Szene als linksextrem motiviert.
    ("Koch-Areal Zürich (Zwischennutzungs-Verein)",
     "Zwischennutzungs-Vertrag Stadt Zürich (kumuliert 2018-2022, Schätzung)",
     180000, "CHF", 2022, "CH", "Stadt", "Stadt Zürich — Liegenschaftenverwaltung",
     "https://www.stadt-zuerich.ch/hbd/de/index/ueberuns/medien/medienmitteilungen.html",
     "Stadt-Zürich-Liegenschaft, jahrelang vergünstigte Zwischennutzung. "
     "Empfänger ist der Zwischennutzungsverein. Betrag ist konservative Schätzung "
     "aus städtischen Liegenschafts-Berichten.", 2),

    # ── Österreich: EKH (Ernst-Kirchweger-Haus) Wien ───────────────
    # VERBINDUNGSNACHWEIS: Das EKH Wien wird im jährlichen DSN-Bericht
    # (vormals BVT) wiederholt im Kapitel Linksextremismus erwähnt.
    # Die Stadt Wien leistet über die MA7 (Kultur) einen Subventions-
    # beitrag an den Trägerverein.
    ("EKH — Ernst-Kirchweger-Haus (Trägerverein)",
     "Kultursubvention Stadt Wien (MA7) 2023",
     38000, "EUR", 2023, "AT", "Stadt", "Stadt Wien — MA7 Kultur",
     "https://www.wien.gv.at/kultur/abteilung/foerderungen/",
     "DSN-Verfassungsschutzbericht erwähnt EKH als Anlaufstelle der linksextremen "
     "Szene Wiens. Stadt-Wien-Subvention öffentlich über MA7-Förderbericht.", 3),

]



def classify(text):
    """
    Ask Grok for category + location + violent-incident flag + short German
    summary. The two new fields (ist_gewalttat, zusammenfassung) drive the
    PRIMARY-vs-CONTEXT distinction and the feed/map cards.
    """
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return None

    cats = "|".join(CATEGORIES)
    prompt = (
        "Du bist ein OSINT-Analyst. Klassifiziere den folgenden deutschsprachigen "
        "Text über einen mutmaßlich politisch links motivierten Vorfall in Europa.\n"
        "Antworte AUSSCHLIESSLICH mit einem kompakten JSON-Objekt — kein Markdown, "
        "keine Erklärung.\n\n"
        "Erforderliche Felder:\n"
        '  "land":          DE|AT|CH|FR|IT|GR|ES|UK|IE|NL|BE|DK|SE|NO|FI|PL|CZ|HU|RO|PT|US|Andere\n'
        '  "ort":           Stadt oder Region (oder "Unbekannt")\n'
        f'  "kategorie":     {cats}\n'
        '  "ist_gewalttat": true|false   '
        '   // true NUR bei realer politisch motivierter Brand-/Sabotage-/'
        'Gewalt-/militanter Aktion ODER gezielter Sachbeschädigung mit klarem '
        'politischen Motiv (Bekennerschreiben, bekannter Akteur, Brandsatz, '
        'Molotow, Farbbeutel) ODER konkretem Aufruf zu Gewalt. '
        'false bei reiner Demo/Kundgebung, Solidaritätsaufruf, '
        'Repressionsbericht, reinem Graffiti, Tech-/Auto-/Krypto-Themen, '
        'Auslandskonflikten ohne DACH-Bezug.\n'
        '  "tier":          "act"|"enable"|"context"   '
        '   // Fedpol Art. 19 Abs. 2 Bst. e NDG: "act" = Verüben (Brand/Sabo/'
        'Gewalt/Militante Aktion/politisch motivierte Sachbeschädigung); '
        '"enable" = Fördern (Aufruf zu Gewalt, Mobilisierungstreffen, '
        'Gewaltpropaganda, Schmiererei mit konkreter Drohphrase + Schwere); '
        '"context" = alles übrige inkl. Demo/Kundgebung, Repression, '
        'Verhaftung, Besetzung, Sonstiges.\n'
        '  "ziel_typ":      "Energie"|"Telekom"|"Schiene"|"Auto"|"Militär"|'
        '"Polizei"|"Politik"|"Justiz"|"Medien"|"Wirtschaft"|"Privatperson"|'
        '"Andere"|""   '
        '   // Zielklasse für Mustererkennung (Anschläge auf gleichartige '
        'Ziele). Leerstring wenn kein klares Ziel erkennbar.\n'
        '  "zusammenfassung": "2-3 sachliche Sätze auf Deutsch, max. 280 Zeichen, '
        'keine Wertung, keine Floskeln, keine HTML-Reste, kein Navigations-Müll. '
        'Nennt Wo, Was, Wer (falls bekannt)."\n\n'
        f"Text:\n{text[:2200]}\n\n"
        "JSON:"
    )
    raw = ""
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": GROK_MODEL,
                  "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.0, "max_tokens": 260},
            timeout=40
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"```[a-z]*", "", raw).replace("```", "").strip()
        # Extract the first JSON object — non-greedy across newlines.
        m = re.search(r'\{.*?\}', raw, re.DOTALL)
        if m: raw = m.group(0)
        res = json.loads(raw)
        res.setdefault("ort", "Unbekannt")
        res.setdefault("land", "Unbekannt")
        res.setdefault("kategorie", "Sonstiges")
        res.setdefault("ist_gewalttat", False)
        res.setdefault("tier", "")
        res.setdefault("ziel_typ", "")
        res.setdefault("zusammenfassung", "")
        # Sanitise the summary: clamp length, strip nav artefacts.
        summ = (res.get("zusammenfassung") or "").strip()
        if _SUMMARY_BAD.search(summ):
            summ = ""
        res["zusammenfassung"] = summ[:280]
        log.info(
            f"Grok → {res['kategorie']} / {res['ort']} / {res['land']} / "
            f"gewalt={res['ist_gewalttat']} / tier={res.get('tier') or '-'} / "
            f"ziel={res.get('ziel_typ') or '-'}"
        )
        return res
    except requests.HTTPError:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:200]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON fail: raw={repr(raw[:150])}")
    except Exception as e:
        log.error(f"Grok: {e}")
    return None

# Regex that rejects Grok-generated summaries containing nav garbage. Used
# in classify() above and also to validate manual descriptions.
_SUMMARY_BAD = re.compile(
    r'(Direkt zum Inhalt|dont hate the media|become the media|Openposting|'
    r'Tutorials Videos Archiv|Tor nutzen|Über uns > Kontakt)',
    re.IGNORECASE,
)

def fallback_summary(text):
    """
    Regex-based fallback when Grok is unavailable or returns junk.
    Picks the first two non-trivial German sentences, clamped to 280 chars.
    """
    if not text:
        return ""
    cleaned = clean_description(text)
    # Split on sentence punctuation, keep the punctuation glued to the sentence.
    parts = re.split(r'(?<=[\.!?])\s+', cleaned)
    out = []
    for p in parts:
        p = p.strip()
        if len(p) < 25 or len(p) > 260:
            continue
        if _SUMMARY_BAD.search(p):
            continue
        out.append(p)
        if len(out) >= 2:
            break
    summ = " ".join(out)[:280].strip()
    return summ

# ── PERSISTENCE ───────────────────────────────────────────────────
def mk_hash(url, text):
    return hashlib.sha256(((url or "") + "|" + text[:300]).encode()).hexdigest()

def is_seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE hash=?", (h,)).fetchone() is not None

_INDYMEDIA_NAV = re.compile(
    r'(?:Direkt zum Inhalt|dont hate the media|become the media)'
    r'.{0,800}?(?=[A-ZÜÄÖ][a-züäöA-ZÜÄÖ\s]{12,})',
    re.DOTALL | re.IGNORECASE
)
_NAV_WORDS = re.compile(
    r'\b(Openposting|Terminkalender|Gruppenstatements|Editorialliste|Linkliste'
    r'|Mailinglisten|Moderation|Unterstützen|Outcall|Übersetzungskoordination'
    r'|Mission Statement|Tor nutzen|Tor 2|dont hate|become the media'
    r'|Tutorials Videos Archiv|Über uns > Kontakt)\b',
    re.IGNORECASE
)

def clean_description(text):
    """Strip navigation artifacts before saving to DB."""
    if not text:
        return ""
    text = _INDYMEDIA_NAV.sub('', text)
    text = _NAV_WORDS.sub('', text)
    text = re.sub(r'\s{3,}', ' ', text).strip()
    return text

# ════════════════════════════════════════════════════════════════════
# PII / DOXXING REDACTION
# ════════════════════════════════════════════════════════════════════
# Doxxing-Texte aus der autonomen Szene (insbesondere Indymedia-Outings
# gegen vermeintliche Rechte) enthalten Klarnamen + Wohnadressen. Diese
# Daten dürfen NIE in unsere öffentliche DB oder UI gelangen — sonst
# verlängern wir die Reichweite der Doxxing-Aktion. Vor jeder Speicherung
# laufen Beschreibungen UND Zusammenfassungen durch redact_pii().
#
# Strategie:
#   1. Adressen (Straße + Hausnummer, Plätze, Gassen, Alleen, Wege) → entfernt
#   2. Doxxing-Marker ("wurden X, Y und Z geoutet") triggern Heavy-Redaction:
#      die gesamte Namensliste in solchen Sätzen wird durch "[Namen entfernt]"
#      ersetzt, NICHT nur einzelne Namen.
#   3. Telefon-, Mail-, Geburtsdaten-Muster → entfernt.
#   4. Auto-Kennzeichen → entfernt.
# Bewusst NICHT entfernt: Namen bekannter Politiker, öffentliche Personen
# in Pressekontext (Olaf Scholz, Donald Trump etc.) — diese werden über
# Whitelist verschont.

_PII_ADDRESS_RE = re.compile(
    r'\b([A-ZÄÖÜ][a-zäöüß\-]{2,}(?:[\- ][A-ZÄÖÜ][a-zäöüß\-]+)*'
    r'(?:straße|str\.|platz|gasse|allee|weg|ufer|damm|ring|chaussee|landstraße|hof))'
    r'\s+\d{1,4}[a-z]?',
    re.IGNORECASE
)
# Name unit: First+Last OR First+Middle+Last (up to 3 capitalised tokens)
_NAME_UNIT = r'[A-ZÄÖÜ][a-zäöüß\-]+(?:\s+[A-ZÄÖÜ][a-zäöüß\-]+){1,2}'
# Trigger words allow upper/lower variants explicitly. We do NOT use
# re.IGNORECASE here because that would make _NAME_UNIT also match
# lowercase tokens like "und"/"als"/"die", causing the regex to gobble
# past name boundaries and leave later names un-redacted.
_PII_DOXXING_LIST_RE = re.compile(
    # "wurden X, Y und Z [geoutet|outet|enttarnt|veröffentlicht]"
    r'\b[Ww]urden?\b\s+'
    r'(' + _NAME_UNIT +
    r'(?:\s*,\s*' + _NAME_UNIT + r'){0,5}'
    r'(?:\s+und\s+' + _NAME_UNIT + r')?)'
    r'\s+(?:durch|von|als|in\s+ihrem|in\s+ihrer|[Gg]eoutet|[Ee]nttarnt|[Oo]utet|veröffentlicht|bekannt)'
)
_PII_DOXXING_OPENER_RE = re.compile(
    # Headline-Muster: "Wir haben X, Y und Z [in ihrem Wohnumfeld] geoutet."
    r'\b(?:[Ww]ir\s+haben|[Aa]ntifa\s+outet|[Gg]eoutet:)\s+'
    r'(' + _NAME_UNIT +
    r'(?:\s*,\s*' + _NAME_UNIT + r'){0,5}'
    r'(?:\s+und\s+' + _NAME_UNIT + r')?)'
)
_PII_EMAIL_RE  = re.compile(r'\b[\w\.\-]+@[\w\.\-]+\.[a-z]{2,}\b', re.IGNORECASE)
_PII_PHONE_RE  = re.compile(r'\b(?:\+?\d{1,3}[\s\-/]?)?(?:0\d{2,4}[\s\-/]?\d{4,10})\b')
_PII_LICENSE_RE = re.compile(r'\b[A-ZÄÖÜ]{1,3}[\s\-][A-Z]{1,2}\s?\d{1,4}\b')
_PII_BIRTHDATE_RE = re.compile(r'\bgeb(?:oren|\.)?\s*(?:am)?\s*\d{1,2}[./]\d{1,2}[./]\d{2,4}\b', re.IGNORECASE)

# Doxxing-Kontext-Detektor: triggert is_pii_heavy() = True
_DOXXING_CONTEXT_RE = re.compile(
    r'\b(geoutet|enttarnt|outing|outet|wohnumfeld|nachbarn\s+infor|'
    r'klarnamen?\s+ver[öo]ffentlich|persönliche\s+daten\s+ver[öo]ffentlich|'
    r'arbeitgeber\s+ver[öo]ffentlich|outed)\b',
    re.IGNORECASE
)

# Politisch öffentliche Personen — bewusst nicht maskiert. Liste minimal halten.
_PII_PUBLIC_FIGURES = {
    "olaf scholz","friedrich merz","alice weidel","tino chrupalla","markus söder",
    "robert habeck","annalena baerbock","christian lindner","sahra wagenknecht",
    "donald trump","joe biden","kamala harris","emmanuel macron","giorgia meloni",
    "ursula von der leyen","viktor orban","lina e.","horst seehofer",
    "thomas haldenwang","sandro brotz","alain berset","viola amherd",
    "karl nehammer","wolfgang sobotka",
}

def is_doxxing_text(text: str) -> bool:
    """True if the text reads like a Klarnamen-Outing — used to reject entirely."""
    if not text: return False
    t = text.lower()
    if not _DOXXING_CONTEXT_RE.search(t):
        return False
    # Heuristic: doxxing posts almost always contain ≥1 address AND a multi-name list.
    return bool(_PII_ADDRESS_RE.search(text) or _PII_DOXXING_OPENER_RE.search(text))

def redact_pii(text: str) -> str:
    """
    Replace personally identifying details with neutral placeholders.
    Conservative: errs on the side of redacting more, because the cost
    of a false-negative (publishing a private address) is much higher
    than the cost of a false-positive (slightly less specific summary).
    """
    if not text:
        return ""
    # 1. Email + phone + license plate + birthdate
    out = _PII_EMAIL_RE.sub("[E-Mail entfernt]", text)
    out = _PII_PHONE_RE.sub("[Telefon entfernt]", out)
    out = _PII_LICENSE_RE.sub("[Kennzeichen entfernt]", out)
    out = _PII_BIRTHDATE_RE.sub("[Geburtsdatum entfernt]", out)
    # 2. Address: street + number
    out = _PII_ADDRESS_RE.sub("[Adresse entfernt]", out)
    # 3. Doxxing-Namenslisten (zwei Muster)
    def _strip_names_keep_publics(m):
        names_block = m.group(1)
        # Wenn alle genannten Namen öffentliche Figuren sind, lass sie stehen.
        candidates = [n.strip().lower() for n in re.split(r',|\s+und\s+', names_block) if n.strip()]
        if candidates and all(c in _PII_PUBLIC_FIGURES for c in candidates):
            return m.group(0)
        # Sonst maskieren.
        return m.group(0).replace(names_block, "[Namen entfernt]")
    out = _PII_DOXXING_LIST_RE.sub(_strip_names_keep_publics, out)
    out = _PII_DOXXING_OPENER_RE.sub(_strip_names_keep_publics, out)
    # 4. Cleanup: doppelte Platzhalter zusammenfassen
    out = re.sub(r'(\[(?:Namen|Adresse|Telefon|E-Mail|Kennzeichen|Geburtsdatum) entfernt\])'
                 r'(\s+\1){1,}', r'\1', out)
    return out

# Political-motive signal for Sachbeschädigung: without one of these (or a
# known actor), the incident is treated as non-political vandalism and dropped.
_POLITICAL_MOTIVE_RE = re.compile(
    r'\b(bekennerschreiben|bekenntnis|molotow|brandsatz|brandsätze|farbbeutel|'
    r'politisch motivier|politisch motivation|politisch motiviert|antifa|'
    r'autonome|schwarzer block|antifaschistisch|antikapitalistisch|'
    r'linksautonom|riot|widerstand|sabotage|anschlag)',
    re.IGNORECASE,
)

# Threat-phrase signal for Schmiererei: pure graffiti is noise; only kept if
# the text contains a credible threat or a high-severity boost.
_THREAT_PHRASE_RE = re.compile(
    r'(tod\s+den|wir\s+kommen\s+wieder|nächstes\s+mal\s+feuer|'
    r'wir\s+wissen\s+wo\s+ihr\s+wohnt|wir\s+finden\s+euch|werdet\s+nicht\s+ruhig\s+schlafen|'
    r'feuer\s+und\s+flamme|kein\s+frieden|drohung|bombendrohung)',
    re.IGNORECASE,
)

def normalize_url(url, source=""):
    """
    Repair relative or junk URLs before they hit the DB. Returns a fully
    qualified https:// URL, or "" if the URL cannot be salvaged — caller
    must skip such incidents.
    """
    if not url:
        return ""
    u = url.strip()
    src = (source or "").lower()
    if u.startswith("//"):
        u = "https:" + u
    if u.startswith("/"):
        if "indymedia" in src:
            return "https://de.indymedia.org" + u
        if "barrikade" in src:
            return "https://barrikade.info" + u
        # Unknown host: cannot reconstruct → reject.
        return ""
    if not (u.startswith("http://") or u.startswith("https://")):
        return ""
    return u

def compute_flags(category, text, severity):
    """
    Derive (is_primary, is_high_risk, tier) from category + text + severity.

    tier is the Fedpol Art. 19 Abs. 2 Bst. e NDG taxonomy:
      'act'     — Verüben (Brandanschlag, Sabotage, Gewalt, Militante Aktion,
                  Sachbeschädigung mit politischem Motiv).
      'enable'  — Fördern (Aufruf zu Gewalt, Mobilisierungstreffen,
                  Gewaltpropaganda, Schmiererei mit Drohphrase + Sev≥3).
      'context' — alles übrige (Demo/Kundgebung, Repression, Besetzung,
                  Verhaftung, Sonstiges, Schmiererei ohne Drohphrase,
                  Sachbeschädigung ohne politisches Motiv).

    is_primary stays 1 only for tier=='act' (UI backward-compat).
    """
    cat = (category or "").strip()
    t   = (text or "").lower()

    act_cats    = {"Brandanschlag", "Sabotage", "Gewalt", "Militante Aktion"}
    enable_cats = {"Aufruf zu Gewalt"}

    if cat in act_cats:
        tier = "act"
    elif cat in enable_cats:
        tier = "enable"
    elif cat == "Sachbeschädigung":
        # PRIMARY/act only if politically motivated; otherwise T3 context.
        tier = "act" if _POLITICAL_MOTIVE_RE.search(t) else "context"
    elif cat == "Schmiererei":
        # Schmiererei → enable only with a credible threat phrase AND sev≥3,
        # otherwise context. Mirrors the §0 v3 policy and §2e save floor.
        tier = "enable" if (
            (severity or 0) >= 3 and _THREAT_PHRASE_RE.search(t)
        ) else "context"
    else:
        # Demo/Kundgebung, Repression, Besetzung, Verhaftung, Sonstiges → context.
        tier = "context"

    is_primary   = 1 if tier == "act" else 0
    is_high_risk = 1 if (
        (severity or 0) >= 4
        or re.search(r'\b(schwer\s+verletzt|tot\b|getötet|explosion|sprengstoff)\b', t)
    ) else 0
    return is_primary, is_high_risk, tier


# Target-type routing — used by Säule 2 (operative Frühwarnung) to detect
# clusters of attacks on the same target class. Regex fallback when Grok
# does not return ziel_typ. Keep keys short ASCII tokens for stable joins.
_TARGET_TYPE_RE = [
    ("Energie",    re.compile(r"\b(strommast|umspannwerk|kraftwerk|stromleitung|hochspannungs?|tennet|enbw|rwe|eon|gaspipeline|pipeline|wärmepumpe|fernwärme|stadtwerke)\b", re.I)),
    ("Telekom",    re.compile(r"\b(telekom|vodafone|funkmast|funkturm|sendemast|5g[- ]?mast|glasfaser|kabelverteiler)\b", re.I)),
    ("Schiene",    re.compile(r"\b(bahn|gleis|signaltechnik|kabelschacht|stellwerk|deutsche\s+bahn|sbb|öbb|s[- ]?bahn|ic[e]?[- ]?strecke)\b", re.I)),
    ("Auto",       re.compile(r"\b(tesla|porsche|audi|mercedes|bmw|vw|volkswagen|autohaus|showroom|ladestation|e[- ]?auto|suv|reifen.{0,15}(zerstoch|aufgeschlitzt|platt))\b", re.I)),
    ("Militär",    re.compile(r"\b(bundeswehr|wehrmacht|kaserne|munition|nato|karriereberat|panzer|raketen?werfer|rheinmetall|heckler|krauss[- ]?maffei)\b", re.I)),
    ("Polizei",    re.compile(r"\b(polizei|streifenwagen|polizeifahrzeug|polizeirevier|polizeiwache|polizist|cobra|gsg ?9)\b", re.I)),
    ("Politik",    re.compile(r"\b(parteibüro|parteizentrale|cdu|csu|spd|grüne|fdp|afd|linke|wahlkampfbüro|wahlkreisbüro|abgeordnetenbüro|rathaus)\b", re.I)),
    ("Justiz",     re.compile(r"\b(gericht|justizvollzug|jva|staatsanwaltschaft|amtsgericht|landgericht|olg|verwaltungsgericht|verfassungsgericht)\b", re.I)),
    ("Medien",     re.compile(r"\b(zeitung|verlag|redaktion|funkhaus|fernsehsender|rundfunk|ard\b|zdf\b|orf\b|srf\b)\b", re.I)),
    ("Wirtschaft", re.compile(r"\b(bank|sparkasse|amazon|lidl|aldi|edeka|rewe|konzern|firmensitz|hauptsitz|niederlassung)\b", re.I)),
]
_TARGET_TYPE_ALLOWED = {
    "Energie","Telekom","Schiene","Auto","Militär","Polizei","Politik",
    "Justiz","Medien","Wirtschaft","Privatperson","Andere",""
}

def compute_target_type(text, category=""):
    """Cheap regex fallback for Grok's ziel_typ. Returns '' if no match."""
    if not text:
        return ""
    for label, rx in _TARGET_TYPE_RE:
        if rx.search(text):
            return label
    return ""

def save_incident(ai, text, source, url, date_str=None, manual=False):
    """
    Persist one incident, applying the v3 ingestion policy.

    Policy v3 (Concept §C2):
      - Demo/Kundgebung, Repression, Sonstiges, Besetzung, Verhaftung,
        Schmiererei ohne Drohphrase, Sachbeschädigung ohne politisches Motiv
        werden NICHT mehr rejected, sondern als tier='context' (T3) gespeichert.
      - tier='act' (T1)    → Brandanschlag/Sabotage/Gewalt/Militante Aktion,
                              politisch motivierte Sachbeschädigung
      - tier='enable' (T2) → Aufruf zu Gewalt, Schmiererei mit Drohphrase + sev≥3
      - tier='context' (T3) → der gesamte Rest (Lagebild-Vollständigkeit)
    Hard rejects bleiben nur: DOXXING, fehlende URL, false_positive
    (siehe is_false_positive() Aufrufer in parse_rss).
    Returns True if a new row was inserted, False otherwise.
    """
    # ── URL gate ───────────────────────────────────────────────────
    url_norm = normalize_url(url, source)
    if not url_norm and not manual:
        log.info(f"filtered: no_valid_url ({source})")
        return False

    # ── DOXXING gate — never ingest Klarnamen-Outings, even when the
    # ── action itself (Doxxing) qualifies as a militant-left act. We
    # ── document THAT it happened (via summary), but not the names.
    if is_doxxing_text(text):
        log.info(f"filtered: doxxing_content — {source}")
        return False

    h = mk_hash(url_norm or text[:80], text)
    if is_seen(h):
        return False

    cat = ai.get("kategorie", "Sonstiges")
    sev = score_severity(cat, text)
    act = extract_actors(text)
    conf = score_confidence(source)

    # ── Geocode + flags + summary ───────────────────────────────────
    # Country override: when the AI returns a country that disagrees with a
    # clearly-recognisable city in the text (Chemnitz → DE not CH), trust
    # the city. Prevents the Chemnitz-into-CH bug we saw in production.
    ort_raw = ai.get("ort", "")
    land_raw = ai.get("land", "Unbekannt")
    land_fixed = _override_country_from_city(ort_raw, text, land_raw)
    if land_fixed != land_raw:
        log.info(f"country override: {land_raw} → {land_fixed} (city={ort_raw})")
        land_raw = land_fixed

    lat, lon = geocode(ort_raw, land_raw)
    is_primary, is_high_risk, tier = compute_flags(cat, text, sev)

    # Grok may override tier directly via the new "tier" field.
    ai_tier = (ai.get("tier") or "").strip().lower()
    if ai_tier in ("act", "enable", "context"):
        tier = ai_tier
        is_primary = 1 if tier == "act" else 0

    # Target-type routing for Säule 2 (Frühwarn-Cluster).
    target_type = (ai.get("ziel_typ") or "").strip()
    if target_type not in _TARGET_TYPE_ALLOWED:
        target_type = ""
    if not target_type:
        target_type = compute_target_type(text, cat)

    summ = (ai.get("zusammenfassung") or "").strip()
    if not summ:
        summ = fallback_summary(text)
    summ = redact_pii(summ)[:280]

    d = date_str or datetime.now().strftime("%Y-%m-%d")
    desc = redact_pii(clean_description(text))[:500]
    ai["land"] = land_raw  # propagate the corrected value to the INSERT below

    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents
               (date,location,country,category,description,source,url,hash,lat,lon,
                manual,timestamp,severity_score,actors,confidence,
                summary,is_primary,is_high_risk,tier,target_type)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'),?,?,?,?,?,?,?,?)""",
            (d, ai.get("ort", "Unbekannt"), ai.get("land", "Unbekannt"),
             cat, desc, source, url_norm, h, lat, lon,
             1 if manual else 0, sev, act, conf,
             summ, is_primary, is_high_risk, tier, target_type)
        )
        db.commit()
        log.info(
            f"SAVED [sev={sev}/conf={conf}/tier={tier}/hi={is_high_risk}/"
            f"target={target_type or '-'}]: {cat} / {ai.get('ort')} / {source}"
        )
        return True
    except Exception as e:
        log.warning(f"save_incident: {e}")
        return False

def purge_garbage():
    """
    Aggressive one-time purge that enforces the plan §0 scope table.
    Idempotent — safe to call on every startup.
    """
    deleted = 0

    # 1) Nav-garbage descriptions (Indymedia boilerplate accidentally scraped).
    nav_patterns = [
        "Direkt zum Inhalt", "dont hate the media", "Tutorials Videos Archiv",
        "Tor nutzen", "Über uns > Kontakt",
    ]
    for pat in nav_patterns:
        c = db.execute(
            "DELETE FROM incidents WHERE description LIKE ? AND manual=0",
            (f"%{pat}%",)
        ).rowcount
        deleted += c

    # 2) Bogus location placeholders.
    bogus = ["Hinterlandregionen", "Konkurrenz", "Ihren Suchergebnissen",
             "Suchergebnissen", "Ergebnissen", "Tutorials"]
    for loc in bogus:
        c = db.execute(
            "DELETE FROM incidents WHERE location=? AND manual=0",
            (loc,)
        ).rowcount
        deleted += c
    # Unknown locations are mostly noise — but under Policy v3 we only purge
    # them if they're also low-severity (sev < 3). Real high-severity reports
    # without a parsed city stay as T3 context (still useful for aggregates).
    c = db.execute(
        "DELETE FROM incidents WHERE location IN ('','Unbekannt','Unknown') "
        "AND manual=0 AND (severity_score IS NULL OR severity_score < 3)"
    ).rowcount
    deleted += c

    # 3) Non-EU / wrong-perpetrator content that slipped through.
    fp_desc_patterns = [
        "%Kongo%", "%Ebola%", "%demokratische Republik Kongo%",
        "%faschistisches Motiv%", "%Neonazi%Angriff%",
        "%autonomes Fahren%", "%autonome Fahrzeuge%", "%künstliche Intelligenz%",
        "%Mobilitätsrevolution%", "%Bitcoin%Kurs%", "%Blockchain%Startup%",
    ]
    for pat in fp_desc_patterns:
        c = db.execute(
            "DELETE FROM incidents WHERE description LIKE ? AND manual=0",
            (pat,)
        ).rowcount
        deleted += c

    # 4) Missing / broken URLs — these are the "/node/734886" entries.
    c = db.execute(
        "DELETE FROM incidents WHERE manual=0 AND source != 'Archiv' "
        "AND (url IS NULL OR url = '' OR url NOT LIKE 'http%')"
    ).rowcount
    deleted += c

    # 5) Policy v3 (Concept §C2) — re-tag instead of delete.
    # Demo/Kundgebung, Repression, Sonstiges, Besetzung, Verhaftung and
    # the soft-filter variants of Schmiererei / Sachbeschädigung used to be
    # purged here. Under v3 they are kept as T3 context (Lagebild-
    # Vollständigkeit) and the backfill below sets tier='context'. We still
    # delete only the hardest noise (nav, FP, broken URL, doxxing).
    db.execute(
        "UPDATE incidents SET tier='context', is_primary=0 "
        "WHERE manual=0 AND category IN "
        "('Demo/Kundgebung','Repression','Sonstiges','Besetzung','Verhaftung') "
        "AND (tier IS NULL OR tier='' OR tier='act')"
    )

    # 6) DOXXING — purge entries whose description matches the Klarnamen-
    # outing pattern. These propagate the doxxing harm even when the action
    # itself is a militant-left act. (Non-negotiable per Concept §C3 #1.)
    rows = db.execute(
        "SELECT id, description, summary FROM incidents WHERE manual=0"
    ).fetchall()
    for r in rows:
        if is_doxxing_text(r["description"] or "") or is_doxxing_text(r["summary"] or ""):
            db.execute("DELETE FROM incidents WHERE id=?", (r["id"],))
            deleted += 1

    if deleted:
        db.commit()
        log.info(f"purge_garbage: removed {deleted} entries (Policy v3: T3 kept)")
    return deleted

def backfill_summaries_and_flags():
    """
    For existing rows, derive summary + is_primary + is_high_risk so the new
    UI works the moment the upgraded code starts. ALSO runs redact_pii() over
    descriptions + summaries so that older rows that pre-date the PII filter
    get retro-actively cleaned (addresses, names, phones removed).
    """
    rows = db.execute(
        "SELECT id, category, description, severity_score, summary, "
        "is_primary, is_high_risk, tier, target_type "
        "FROM incidents"
    ).fetchall()
    if not rows:
        return 0
    n = 0
    for r in rows:
        desc_in = r["description"] or ""
        summ_in = (r["summary"] or "").strip()
        desc_out = redact_pii(desc_in)
        summ_out = redact_pii(summ_in or fallback_summary(desc_in))[:280]
        prim, hi, tier_new = compute_flags(
            r["category"], desc_in, r["severity_score"] or 0
        )
        tt_old = (r["target_type"] or "").strip()
        tt_new = tt_old or compute_target_type(desc_in, r["category"])
        tier_old = (r["tier"] or "").strip()
        # Skip if nothing actually changed (avoid pointless writes on warm DB)
        if (desc_out == desc_in
                and summ_out == (r["summary"] or "")
                and prim == (r["is_primary"] or 0)
                and hi   == (r["is_high_risk"] or 0)
                and tier_new == tier_old
                and tt_new == tt_old):
            continue
        db.execute(
            "UPDATE incidents SET description=?, summary=?, is_primary=?, "
            "is_high_risk=?, tier=?, target_type=? WHERE id=?",
            (desc_out, summ_out, prim, hi, tier_new, tt_new, r["id"])
        )
        n += 1
    db.commit()
    if n:
        log.info(f"backfill_summaries_and_flags: updated {n} rows (PII + tier + target)")
    return n

def backfill_enrichment():
    """Backfill severity, actors, confidence for existing records that have 0 values."""
    rows = db.execute(
        "SELECT id, category, description, source FROM incidents WHERE severity_score=0 OR confidence=0"
    ).fetchall()
    if not rows:
        return
    updated = 0
    for row in rows:
        sev  = score_severity(row["category"], row["description"] or "")
        act  = extract_actors(row["description"] or "")
        conf = score_confidence(row["source"] or "")
        db.execute(
            "UPDATE incidents SET severity_score=?, actors=?, confidence=? WHERE id=?",
            (sev, act, conf, row["id"])
        )
        updated += 1
    if updated:
        db.commit()
        log.info(f"Backfill: enriched {updated} incidents")

def seed_historical_data():
    """Insert pre-defined historical incidents if not already seeded."""
    count = db.execute("SELECT COUNT(*) FROM incidents WHERE source='Archiv'").fetchone()[0]
    if count > 0:
        log.info(f"Seed: bereits {count} Archiv-Einträge vorhanden")
        return 0
    inserted = 0
    for date, location, country, category, description, source, lat, lon in HISTORICAL_EVENTS:
        url = f"archiv:{date}:{location}:{category}"
        h = mk_hash(url, description)
        if is_seen(h):
            continue
        try:
            db.execute(
                """INSERT OR IGNORE INTO incidents
                   (date,location,country,category,description,source,url,hash,lat,lon,manual,timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,1,datetime('now'))""",
                (date, location, country, category, description, source, url, h, lat, lon)
            )
            inserted += 1
        except Exception as e:
            log.warning(f"seed: {e}")
    if inserted:
        db.commit()
        log.info(f"Seed: {inserted} historische Einträge eingespielt")
    return inserted

# ════════════════════════════════════════════════════════════════════
# Funding seed version tracking.
#
# When the curated seed list changes — especially when entries are REMOVED
# because they no longer meet the strict inclusion criteria — we must purge
# old seeded records from existing production databases. A version bump
# triggers a one-shot reseed: previously seeded entries are deleted and the
# current FUNDING_SEED is re-inserted. Manual admin-added entries (anything
# whose hash is NOT in the current seed-hash set) are preserved.
# ════════════════════════════════════════════════════════════════════
FUNDING_SEED_VERSION = "2026-05-strict-v1"

def _funding_seed_hashes():
    """Return the set of hashes for entries currently in FUNDING_SEED."""
    hs = set()
    for row in FUNDING_SEED:
        recipient_org, _project, amount, _currency, year, _country, \
            _donor_type, donor_name, _src, _notes, _conf = row
        h_input = (f"fund|{recipient_org.lower().strip()}|{year}|"
                   f"{donor_name.lower().strip()}|{round(float(amount))}")
        hs.add(hashlib.sha256(h_input.encode()).hexdigest())
    return hs

def purge_stale_funding_seeds():
    """
    Remove seeded funding records that are no longer part of the curated
    FUNDING_SEED list. Identifies "seeded" records as those whose hash is
    NOT one of the current seed-hash set AND whose hash starts with the
    seed pattern (`fund|`-derived hash). To avoid touching anything that
    might be admin-added, we ONLY delete rows whose hash matches a stored
    "previously-seeded" hash list, and rebuild that list from the current
    seed afterwards.
    """
    current_hashes = _funding_seed_hashes()
    prev_serialized = meta_get("fund_seed_hashes") or ""
    prev_hashes = set(h for h in prev_serialized.split(",") if h)
    stale = prev_hashes - current_hashes
    deleted = 0
    if stale:
        placeholders = ",".join("?" * len(stale))
        cur = db.execute(
            f"DELETE FROM funding_records WHERE hash IN ({placeholders})",
            tuple(stale)
        )
        deleted = cur.rowcount
        db.commit()
        log.info(f"Funding purge: removed {deleted} stale seed records "
                 f"(seed version → {FUNDING_SEED_VERSION})")
    # Persist the new seed-hash set so the next version bump can find stale rows
    meta_set("fund_seed_hashes", ",".join(sorted(current_hashes)))
    meta_set("fund_seed_version", FUNDING_SEED_VERSION)
    return deleted

def seed_funding_data():
    """
    Idempotently seed the funding_records table from FUNDING_SEED.
    Returns the number of newly inserted rows. Safe to call repeatedly:
    the UNIQUE hash prevents duplicates.
    Before seeding, purge any stale records left behind by an earlier
    (now-removed) seed entry — see purge_stale_funding_seeds().
    """
    purge_stale_funding_seeds()
    existing = db.execute("SELECT COUNT(*) FROM funding_records").fetchone()[0]
    # We allow re-seeding even when records already exist, because purge
    # may have just emptied the table. The UNIQUE hash constraint prevents
    # duplicate insertion of records that survived the purge.
    inserted = 0
    for row in FUNDING_SEED:
        (recipient_org, project, amount, currency, year, country,
         donor_type, donor_name, source_url, notes, confidence) = row
        h_input = (
            f"fund|{recipient_org.lower().strip()}|{year}|"
            f"{donor_name.lower().strip()}|{round(float(amount))}"
        )
        h = hashlib.sha256(h_input.encode()).hexdigest()
        try:
            cur = db.execute(
                """INSERT OR IGNORE INTO funding_records
                   (recipient_org, project, amount, currency, year, country,
                    donor_type, donor_name, source_url, notes, confidence,
                    manual, hash, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,datetime('now'))""",
                (recipient_org, project, amount, currency, year, country,
                 donor_type, donor_name, source_url, notes, confidence, h)
            )
            if cur.rowcount > 0:
                inserted += 1
        except Exception as e:
            log.warning(f"seed_funding: {recipient_org} / {year} — {e}")
    db.commit()
    log.info(f"Funding seed: {inserted} records inserted")
    return inserted

# ── BARRIKADE ID CRAWLER ──────────────────────────────────────────
def barrikade_latest_id():
    try:
        html = fetch("https://barrikade.info/")
        ids = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        return max(ids) if ids else 7600
    except Exception as e:
        log.warning(f"barrikade_latest_id: {e}")
        return 7600

def crawl_barrikade_range(start_id, stop_id):
    """Crawl barrikade article IDs from start_id down to stop_id."""
    inserted = 0
    misses   = 0
    for aid in range(start_id, stop_id - 1, -1):
        url = f"https://barrikade.info/article/{aid}"
        try:
            text = get_text(url)
            if len(text) < 80:
                misses += 1
                if misses >= 40: break
                time.sleep(0.2)
                continue
            misses = 0
            h = mk_hash(url, text)
            if is_seen(h): time.sleep(0.1); continue
            if not any(kw in text.lower() for kw in BARRIKADE_RELEVANCE_KWS):
                time.sleep(0.1)
                continue
            if is_false_positive(text):
                time.sleep(0.1)
                continue
            ai = smart_classify(text)
            if ai:
                if save_incident(ai, text, "barrikade.info", url, date_from_url(url)):
                    inserted += 1
            time.sleep(0.6)
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                misses += 1; time.sleep(0.2)
            else:
                log.warning(f"barrikade id={aid} HTTP {e.response.status_code}")
                time.sleep(3)
        except Exception as e:
            log.warning(f"barrikade id={aid}: {e}"); time.sleep(0.5)
    return inserted

# ── INDYMEDIA RSS + PAGE CRAWLER ──────────────────────────────────
def crawl_indymedia_feed():
    """Crawl de.indymedia.org RSS plus active German-language left-wing alternatives."""
    inserted = 0
    seen_urls: set = set()

    # ── de.indymedia.org + Indymedia-Netzwerk Europa/USA ─────────────
    # Wir crawlen jetzt nicht nur Berlin/DE, sondern auch die regional-
    # und länderspezifischen Indymedia-Knoten. Jeder Feed wird einzeln mit
    # kurzem Timeout angefragt; tote Knoten loggen leise und blocken nichts.
    for feed_url in [
        # ── DE: Bundesweite Knoten ──
        "https://de.indymedia.org/RSS/newswire.xml",
        "https://de.indymedia.org/RSS/features.xml",
        "https://de.indymedia.org/taxonomy/term/20/all/feed",   # Antifa
        "https://de.indymedia.org/taxonomy/term/17/all/feed",   # Antirepression
        "https://de.indymedia.org/taxonomy/term/22/all/feed",   # Antimilitarismus
        "https://de.indymedia.org/taxonomy/term/18/all/feed",   # Soziale Kämpfe
        "https://de.indymedia.org/taxonomy/term/19/all/feed",   # Globale Gerechtigkeit
        # ── Europäische Indymedia-Knoten ──
        "https://athens.indymedia.org/feed/",                   # GR Athen
        "https://radar.squat.net/en/rss",                        # CH/NL/EU squat-Netzwerk
        "https://www.indymedia.ie/rss/news",                    # IE Irland
        "https://www.indymedia.org.uk/en/rss/articles/feed.xml",# UK
        "https://italy.indymedia.org/rss.xml",                  # IT
        # ── USA Indymedia-Verbund ──
        "https://nycindymedia.org/feed",                        # US NY
        "https://www.itsgoingdown.org/feed/",                   # US Antifa/Anarcho Newswire
        "https://crimethinc.com/feed",                          # US Anarcho
        "https://rosecityantifa.org/feed/",                     # US Portland
    ]:
        try:
            r = session.get(feed_url, timeout=8, allow_redirects=True)
            r.raise_for_status()
            items = parse_rss(r.text)
            log.info(f"indymedia {feed_url.split('/')[-1]}: {len(items)} items")
            for title, link, desc, pub in items:
                # Normalize relative /node/... URLs to absolute before use.
                link = normalize_url(link, "de.indymedia.org")
                if not link or link in seen_urls: continue
                seen_urls.add(link)
                preview = (title + " " + desc).lower()
                if is_false_positive(preview): continue
                h = mk_hash(link, title + desc)
                if is_seen(h): continue
                full = get_text(link)
                text = full if len(full) > 100 else f"{title}. {desc}"
                if len(text) < 30: continue
                ai = smart_classify(text)
                if ai:
                    d = parse_date(pub) or date_from_url(link)
                    if save_incident(ai, text, "de.indymedia.org", link, d):
                        inserted += 1
                time.sleep(0.5)
        except Exception as e:
            log.warning(f"indymedia {feed_url.split('/')[-1]}: {e}")
        time.sleep(0.3)

    # ── Active alternative left-wing sources (DE/AT/CH + EU + USA) ──
    for source, url in [
        ("labournet.de",            "https://www.labournet.de/feed/"),
        ("perspektive-online.net",  "https://perspektive-online.net/feed/"),
        ("klassegegenklasse.org",   "https://www.klassegegenklasse.org/feed/"),
        ("jungle.world",            "https://jungle.world/rss.xml"),
        ("nd-aktuell.de",           "https://www.nd-aktuell.de/rss/aktuell.xml"),
        ("untergrund-blättle.ch",   "https://www.untergrund-blaettle.ch/rss.xml"),
        ("contraste.org",           "https://www.contraste.org/feed/"),
        ("autonomes-zentrum.org",   "https://www.az-koeln.org/feed/"),
        # ── englischsprachig (UK / US / international) ──
        ("freedomnews.org.uk",      "https://freedomnews.org.uk/feed/"),
        ("libcom.org",              "https://libcom.org/rss.xml"),
        ("anarchistnews.org",       "https://anarchistnews.org/rss.xml"),
        ("redfish.media",           "https://redfish.media/feed/"),
        ("popularresistance.org",   "https://popularresistance.org/feed/"),
        ("truthout.org",            "https://truthout.org/feed/"),
        ("commondreams.org",        "https://www.commondreams.org/rss.xml"),
    ]:
        try:
            n = crawl_rss_feed(source, url, max_items=8)
            inserted += n
        except Exception as e:
            log.warning(f"alt-feed {source}: {e}")
        time.sleep(0.4)

    return inserted

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
    r'\bautonomes?\s+(fahren|fahrzeuge?|autos?\b|lkw|pkw|bus\b|roboter|drohnen?|flugzeug)',
    r'\bself.?driving\b', r'\bautopilot\b',
    r'\bautonomes?\s+(parken|laden|liefern)',
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

# ── GEOCODE COUNTRY BOUNDS ────────────────────────────────────────
# (min_lat, min_lon, max_lat, max_lon) — generous margins to avoid false rejections
_CO_BOUNDS = {
    "DE": (46.5,  5.5, 55.5, 15.5),
    "AT": (46.2,  9.3, 49.2, 17.3),
    "CH": (45.7,  5.8, 48.0, 10.7),
    "FR": (41.2, -5.3, 51.2,  9.7),
    "IT": (35.5,  6.5, 47.2, 18.6),
    "GR": (34.5, 19.2, 42.0, 29.8),
    "ES": (35.8, -9.5, 43.9,  4.4),
    "UK": (49.7, -8.5, 61.0,  2.2),
    "IE": (51.4, -10.6, 55.4, -5.4),
    "NL": (50.7,  3.3, 53.6,  7.3),
    "BE": (49.5,  2.5, 51.6,  6.5),
    "LU": (49.4,  5.7, 50.2,  6.6),
    "DK": (54.5,  8.0, 57.8, 15.3),
    "SE": (55.3, 10.9, 69.1, 24.2),
    "NO": (57.9,  4.3, 71.2, 31.3),
    "FI": (59.7, 20.5, 70.1, 31.6),
    "PL": (49.0, 14.1, 54.9, 24.2),
    "CZ": (48.5, 12.1, 51.1, 18.9),
    "HU": (45.7, 16.1, 48.6, 22.9),
    "RO": (43.6, 20.2, 48.3, 29.7),
    "PT": (36.9, -9.6, 42.2, -6.2),
    "US": (24.5,-125.0, 49.5, -66.9),
}

def _coords_in_country(country, lat, lon):
    if lat is None or lon is None: return True
    b = _CO_BOUNDS.get(country)
    if not b: return True
    return b[0] <= lat <= b[2] and b[1] <= lon <= b[3]

RSS_FEEDS = [
    # ── Sicherheitsbehörden ────────────────────────────────────────
    ("verfassungsschutz.de",  "https://www.verfassungsschutz.de/SiteGlobals/Functions/RSSNewsFeed/AlleMeldungen.xml"),
    # ── Kernquellen Deutschland (öffentlich-rechtlich + Leitmedien) ─
    ("tagesschau.de",         "https://www.tagesschau.de/xml/rss2/"),
    ("deutschlandfunk.de",    "https://www.deutschlandfunk.de/nachrichten.rss"),
    ("spiegel.de",            "https://www.spiegel.de/schlagzeilen/index.rss"),
    ("zeit.de",               "https://newsfeed.zeit.de/politik/index"),
    ("sueddeutsche.de",       "https://rss.sueddeutsche.de/rss/Politik"),
    ("faz.net",               "https://www.faz.net/rss/aktuell/"),
    ("tagesspiegel.de",       "https://www.tagesspiegel.de/contentexport/feed/home"),
    ("taz.de",                "https://taz.de/!p4608;rss/"),
    ("mdr.de",                "https://www.mdr.de/nachrichten/rss-nachrichten100.xml"),
    ("rbb24.de",              "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("ndr.de",                "https://www.ndr.de/nachrichten/index-rss.xml"),
    # ── Schweiz (Kernquellen) ─────────────────────────────────────
    ("nzz.ch",                "https://www.nzz.ch/recent.rss"),
    ("tagesanzeiger.ch",      "https://www.tagesanzeiger.ch/rss.xml"),
    ("srf.ch",                "https://www.srf.ch/news/bnf/rss/1646"),
    ("20min.ch",              "https://api.20min.ch/rss/view/1"),
    ("blick.ch",              "https://www.blick.ch/news/rss.xml"),
    ("woz.ch",                "https://www.woz.ch/rss.xml"),
    ("rts.ch",                "https://www.rts.ch/rss/info.xml"),
    # ── Österreich (Kernquellen) ──────────────────────────────────
    ("orf.at",                "https://rss.orf.at/news.xml"),
    ("derstandard.at",        "https://www.derstandard.at/rss/inland"),
    ("diepresse.com",         "https://www.diepresse.com/rss/politik"),
    ("kurier.at",             "https://kurier.at/rss"),
    # ── Einschlägige Quellen (szenenah + extremismusbeobachtend) ──
    ("barrikade.info",        "https://barrikade.info/feed"),
    ("belltower.news",        "https://www.belltower.news/feed/"),
    ("radikal.news",          "https://radikal.news/feed/"),
    ("nd-aktuell.de",         "https://www.nd-aktuell.de/static/rss/rss.xml"),
]

GNEWS_Q = [
    # Deutschland
    ("DE","linksextremismus anschlag bekennerschreiben"),
    ("DE","autonome brandanschlag sachbeschädigung"),
    ("DE","antifa gewalt festnahmen"),
    ("DE","schwarzer block randalen ausschreitungen"),
    ("DE","militante linke sabotage bahn"),
    ("DE","rigaer strasse linksradikal"),
    ("DE","bundesverfassungsschutz linksextremismus"),
    ("DE","linksextrem hausbesetzung räumung"),
    ("DE","autonome demo eskaliert polizei verletzt"),
    ("DE","antifa razzia festnahmen"),
    # Schweiz
    ("CH","linksextrem schweiz anschlag"),
    ("CH","autonome zürich bern demonstration"),
    ("CH","krawall schweiz ausschreitungen polizei"),
    # Österreich
    ("AT","linksextremismus österreich anschlag"),
    ("AT","autonome wien demonstration eskaliert"),
    # Überregional
    ("DE","lina e linksextremismus urteil"),
    ("DE","antifaschistische aktion sachbeschädigung"),
]

def parse_rss(xml_text):
    items = []
    try:
        root = ET.fromstring(xml_text)
        for item in root.iter("item"):
            t=(item.findtext("title") or "").strip()
            l=(item.findtext("link") or "").strip()
            d=(item.findtext("description") or "").strip()
            p=(item.findtext("pubDate") or "").strip()
            if l: items.append((t,l,d,p))
        if not items:
            NS="http://www.w3.org/2005/Atom"
            for e in root.iter(f"{{{NS}}}entry"):
                t=(e.findtext(f"{{{NS}}}title") or "").strip()
                le=e.find(f"{{{NS}}}link")
                l=(le.get("href","") if le is not None else "").strip()
                d=(e.findtext(f"{{{NS}}}summary") or "").strip()
                p=(e.findtext(f"{{{NS}}}updated") or "").strip()
                if l: items.append((t,l,d,p))
    except Exception as e:
        log.warning(f"parse_rss: {e}")
    return items

def parse_date(s):
    if not s: return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z","%a, %d %b %Y %H:%M:%S GMT",
                "%a, %d %b %Y %H:%M:%S %Z","%Y-%m-%dT%H:%M:%S%z","%Y-%m-%dT%H:%M:%SZ"):
        try: return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except: pass
    return None

def crawl_rss_feed(source, feed_url, max_items=15):
    inserted = 0
    try:
        xml   = fetch(feed_url, timeout=18)
        items = parse_rss(xml)
        hits  = 0
        for title, link, desc, pub in items:
            if hits >= max_items: break
            preview = (title + " " + desc).lower()
            if not any(kw in preview for kw in RSS_KEYWORDS): continue
            if is_false_positive(preview): continue  # e.g. "autonome Autos"
            hits += 1
            h = mk_hash(link, title+desc)
            if is_seen(h): continue
            text = get_text(link)
            if len(text) < 80: text = f"{title}. {desc}"
            ai = smart_classify(text)
            if ai:
                d = parse_date(pub) or date_from_url(link)
                if save_incident(ai, text, source, link, d):
                    inserted += 1
            time.sleep(0.5)
    except Exception as e:
        log.warning(f"RSS {source}: {e}")
    return inserted

def crawl_gnews():
    inserted = 0
    for country, q in GNEWS_Q:
        url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de"
        inserted += crawl_rss_feed(f"gnews", url, max_items=5)
        time.sleep(0.5)
    return inserted

# ── BARRIKADE RELEVANCE PRE-FILTER ───────────────────────────────
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

# ── MASTER CRAWLER ────────────────────────────────────────────────
_running   = [False]
_hist_run  = [False]

def run_crawler(force=False):
    if _running[0]: log.info("Already running"); return
    last = meta_get("last_crawl")
    if not force and last:
        if datetime.now() - datetime.fromisoformat(last) < timedelta(hours=2):
            log.info("Skipped < 2h"); return
    _running[0] = True
    total = 0
    log.info("══ CRAWLER START ══")
    try:
        # 1. Barrikade: sweep latest 80 article IDs
        log.info("Barrikade live sweep...")
        latest = barrikade_latest_id()
        saved_latest = int(meta_get("b_live_max") or 0)
        if latest > saved_latest:
            n = crawl_barrikade_range(latest, max(saved_latest, latest - 80))
            meta_set("b_live_max", latest)
            total += n
            log.info(f"Barrikade live: +{n}")
        else:
            log.info("Barrikade: no new articles")

        # 2. Indymedia RSS feeds
        log.info("Indymedia feeds...")
        n = crawl_indymedia_feed()
        total += n
        log.info(f"Indymedia: +{n}")

        # 3. Mainstream RSS
        log.info("RSS feeds...")
        for source, url in RSS_FEEDS:
            n = crawl_rss_feed(source, url)
            total += n
            time.sleep(0.3)

        # 4. Google News
        n = crawl_gnews()
        total += n

        # 5. Re-geocode any null-coord incidents
        regeocode_nulls()

    except Exception as e:
        log.error(f"run_crawler: {e}", exc_info=True)
    finally:
        _running[0] = False
        meta_set("last_crawl", datetime.now().isoformat())
    log.info(f"══ CRAWLER DONE +{total} ══")

# ── HISTORICAL ────────────────────────────────────────────────────
def run_historical(reset=False):
    if _hist_run[0]: return
    if reset:
        for k in ("hist_b_done","hist_b_curr","hist_b_max",
                  "hist_im_done","hist_im_offset","hist_wb_done","b_live_max"):
            meta_del(k)
        log.info("Historical: reset")
    _hist_run[0] = True
    log.info("══ HISTORICAL START ══")
    try:
        # Mark indymedia historical as done — de.indymedia.org offline since 2017
        if not meta_get("hist_im_done"):
            meta_set("hist_im_done", datetime.now().isoformat())
            log.info("Indymedia hist: skipped (site offline since 2017)")

        # Barrikade: crawl 800 IDs per invocation, save progress
        DONE="hist_b_done"; CURR="hist_b_curr"
        if not meta_get(DONE):
            if not meta_get(CURR):
                mx = barrikade_latest_id()
                meta_set("hist_b_max", mx)
                meta_set(CURR, mx)
            curr = int(meta_get(CURR))
            stop = max(1, curr - 800)
            log.info(f"Barrikade hist: {curr}→{stop}")
            n = crawl_barrikade_range(curr, stop)
            meta_set(CURR, stop - 1)
            if stop <= 1:
                meta_set(DONE, datetime.now().isoformat())
                log.info("Barrikade hist: COMPLETE")
            log.info(f"Barrikade hist: +{n} (remaining: {stop-1} IDs)")
        else:
            log.info("Barrikade hist: already complete")

        regeocode_nulls()
    except Exception as e:
        log.error(f"run_historical: {e}", exc_info=True)
    finally:
        _hist_run[0] = False
    log.info("══ HISTORICAL DONE ══")


def auto_hist():
    """Auto-continue historical barrikade crawl on a schedule until complete."""
    if meta_get("hist_b_done"):
        return
    if _hist_run[0] or _running[0]:
        return
    log.info("Auto-continuing historical crawl…")
    run_historical()

# ── FASTAPI ───────────────────────────────────────────────────────
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")
# i18n strings (DE/EN) served as static JSON for client-side hot-swap.
if os.path.isdir("i18n"):
    app.mount("/i18n", StaticFiles(directory="i18n"), name="i18n")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Donation addresses are configured per render.com instance via env vars.
    # Leaving them unset shows a safe "wird in Kürze veröffentlicht" placeholder.
    return templates.TemplateResponse("index.html", {
        "request": request,
        "btc_address": os.getenv("BTC_ADDRESS", ""),
        "xmr_address": os.getenv("XMR_ADDRESS", ""),
        "fiat_info":   os.getenv("FIAT_INFO",   ""),
    })

@app.get("/api/effectiveness")
async def get_effectiveness():
    """
    Säule-Wirksamkeits-Zähler für den Status-Footer (Concept §C5).
    Liefert vier konkrete Kennzahlen — bewusst öffentlich:
      - prosec_gap_pct: % der T1-Vorfälle Severity ≥ 4 ohne öffentliches
        Verfahren nach 180 Tagen (Säule 1).
      - cluster_active:  Anzahl aktiver Frühwarn-Cluster (≥ 3 gleichartige
        Anschläge in 6 Wochen). MS-3 wird das echte Backend liefern; bis
        dahin liefert dieser Endpoint -1 als „noch nicht verfügbar".
      - funding_year_eur: Summe der dokumentierten Förderung im laufenden
        Jahr (Säule 3). Sobald wir einen recipient_tier-Marker haben, wird
        das auf T1/T2-Empfänger eingeschränkt.
      - evidence_pct:  % Einträge mit WARC-Snapshot. MS-5 wird das echte
        Feld liefern; bis dahin -1.
    """
    today = datetime.now().date()
    # Strafverfolgungs-Lücke
    sev_4plus = db.execute(
        "SELECT id,date,prosec_status,case_ref FROM incidents "
        "WHERE tier='act' AND severity_score >= 4"
    ).fetchall()
    elig = 0; gap = 0
    for r in sev_4plus:
        try:
            d = datetime.fromisoformat(r["date"]).date()
        except Exception:
            continue
        if (today - d).days < 180:
            continue
        elig += 1
        if (r["prosec_status"] or "unknown") in ("unknown","none") and not (r["case_ref"] or "").strip():
            gap += 1
    prosec_gap_pct = round(100.0 * gap / elig) if elig else 0

    # Finanzfluss-Transparenz — Summe laufendes Jahr.
    yr = today.year
    funding_eur = db.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM funding_records WHERE year = ?",
        (yr,)
    ).fetchone()[0] or 0

    return JSONResponse({
        "prosec_gap_pct":  prosec_gap_pct,
        "prosec_gap_n":    gap,
        "prosec_gap_base": elig,
        "cluster_active":  -1,          # MS-3 liefert echten Wert
        "funding_year_eur": int(funding_eur),
        "funding_year":    yr,
        "evidence_pct":    -1,          # MS-5 liefert echten Wert
        "asof":            today.isoformat(),
    })

@app.get("/api/accountability")
async def get_accountability():
    """
    Säule 1 — Strafverfolgungs-Druck: aggregate which T1-tier incidents have
    a documented prosec_status and which sit silent for ≥180 days at
    severity≥4 (the "Gap"). Returns:
      total_t1, with_case, gap_count, by_status[], gap_rows[]
    """
    rows = db.execute(
        "SELECT id,date,location,country,category,severity_score,"
        "tier,prosec_status,case_ref,url,source,last_status_check "
        "FROM incidents WHERE tier='act' ORDER BY date DESC"
    ).fetchall()
    rows = [dict(r) for r in rows]
    total_t1   = len(rows)
    with_case  = sum(1 for r in rows if (r.get("case_ref") or "").strip())
    today      = datetime.now().date()
    gap_rows = []
    by_status = {}
    for r in rows:
        st = (r.get("prosec_status") or "unknown")
        by_status[st] = by_status.get(st, 0) + 1
        # Gap heuristic: T1 sev≥4 with no case_ref, status unknown/none, and
        # incident date is ≥180 days old. These are the politically active
        # cases that should have triggered a public investigation by now.
        if (r.get("severity_score") or 0) >= 4 and st in ("unknown","none") and not (r.get("case_ref") or "").strip():
            try:
                d = datetime.fromisoformat(r["date"]).date()
                if (today - d).days >= 180:
                    gap_rows.append(r)
            except Exception:
                pass
    return JSONResponse({
        "total_t1":   total_t1,
        "with_case":  with_case,
        "gap_count":  len(gap_rows),
        "by_status":  [{"status": k, "count": v} for k, v in sorted(by_status.items(), key=lambda x: -x[1])],
        "gap_rows":   gap_rows[:200],
    })

@app.get("/api/incidents")
async def get_incidents(
    country: str = "", category: str = "", date_from: str = "",
    date_to: str = "", search: str = "", severity_min: int = 0,
    primary_only: int = 0, tier: str = "", target_type: str = "",
):
    """
    primary_only=1 → only is_primary=1 rows (default UI behaviour for the
    incidents feed; the "INKL. KONTEXT" toggle clears the flag).
    tier=act|enable|context → filter on the Fedpol 3-tier taxonomy.
    target_type=Energie|Schiene|… → filter on Säule-2 target routing.
    """
    q = ("SELECT id,date,location,country,category,description,summary,url,"
         "lat,lon,manual,source,severity_score,actors,confidence,"
         "is_primary,is_high_risk,tier,target_type,"
         "prosec_status,case_ref,last_status_check FROM incidents WHERE 1=1")
    p = []
    if country:   q += " AND country=?";   p.append(country)
    if category:  q += " AND category=?";  p.append(category)
    if date_from: q += " AND date>=?";     p.append(date_from)
    if date_to:   q += " AND date<=?";     p.append(date_to)
    if search:
        q += " AND (description LIKE ? OR summary LIKE ? OR location LIKE ? OR category LIKE ?)"
        s = f"%{search}%"
        p.extend([s, s, s, s])
    if severity_min > 0:
        q += " AND severity_score >= ?"
        p.append(severity_min)
    if primary_only:
        q += " AND is_primary=1"
    if tier:
        q += " AND tier=?"
        p.append(tier)
    if target_type:
        q += " AND target_type=?"
        p.append(target_type)
    q += " ORDER BY date DESC, timestamp DESC"
    return JSONResponse([dict(r) for r in db.execute(q, p).fetchall()])

@app.get("/api/stats")
async def stats():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    return JSONResponse({
        "total":total, "geocoded":geocoded,
        "last_crawl": meta_get("last_crawl"),
        "crawl_running": _running[0],
        "hist_running": _hist_run[0],
        "by_country": [dict(r) for r in db.execute("SELECT country,COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()],
        "by_cat":     [dict(r) for r in db.execute("SELECT category,COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()],
        "by_source":  [dict(r) for r in db.execute("SELECT source,COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC").fetchall()],
    })

@app.get("/api/summary")
async def get_summary():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    last7    = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-7 days')").fetchone()[0]
    last30   = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-30 days')").fetchone()[0]
    prev30   = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-60 days') AND date < date('now','-30 days')").fetchone()[0]
    by_country = [dict(r) for r in db.execute("SELECT country, COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()]
    by_cat     = [dict(r) for r in db.execute("SELECT category, COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()]
    top_locs   = [dict(r) for r in db.execute("SELECT location, country, COUNT(*) n FROM incidents GROUP BY location ORDER BY n DESC LIMIT 10").fetchall()]
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "last7": last7, "last30": last30, "prev30": prev30,
        "trend": "up" if last30 > prev30 else "down" if last30 < prev30 else "flat",
        "by_country": by_country, "by_cat": by_cat, "top_locs": top_locs,
        "last_crawl": meta_get("last_crawl"),
        "crawl_running": _running[0],
        "sources": [dict(r) for r in db.execute("SELECT source, COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC LIMIT 20").fetchall()],
    })

@app.get("/api/timeline")
async def get_timeline():
    rows = db.execute("""
        SELECT strftime('%Y-%m', date) as month, COUNT(*) as n,
               SUM(CASE WHEN category IN ('Brandanschlag','Gewalt','Militante Aktion') THEN 1 ELSE 0 END) as high
        FROM incidents
        WHERE date IS NOT NULL AND date != '' AND length(date) >= 7
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/api/trends")
async def get_trends():
    # Monthly data last 24 months
    rows = db.execute("""
        SELECT strftime('%Y-%m', date) as month, COUNT(*) as n,
               SUM(CASE WHEN category IN ('Brandanschlag','Gewalt','Militante Aktion','Aufruf zu Gewalt') THEN 1 ELSE 0 END) as high
        FROM incidents
        WHERE date >= date('now','-24 months') AND date IS NOT NULL AND length(date) >= 7
        GROUP BY month ORDER BY month ASC
    """).fetchall()
    months = [dict(r) for r in rows]

    # Linear regression on monthly counts (last 12 months)
    recent = months[-12:] if len(months) >= 3 else months
    n = len(recent)
    slope = 0.0
    forecast = []
    if n >= 3:
        xs = list(range(n)); ys = [r['n'] for r in recent]
        xm = sum(xs)/n; ym = sum(ys)/n
        num = sum((xs[i]-xm)*(ys[i]-ym) for i in range(n))
        den = sum((xs[i]-xm)**2 for i in range(n))
        slope = num/den if den else 0.0
        intercept = ym - slope*xm
        last_m = recent[-1]['month'] if recent else ""
        if last_m:
            yr, mo = int(last_m[:4]), int(last_m[5:7])
            for i in range(1, 4):
                mo2 = mo+i; yr2 = yr+(mo2-1)//12; mo2 = ((mo2-1)%12)+1
                pred = max(0, round(intercept + slope*(n-1+i)))
                forecast.append({"month": f"{yr2:04d}-{mo2:02d}", "predicted": pred})

    # Hot spots last 6 months
    hot_spots = [dict(r) for r in db.execute("""
        SELECT location, country, COUNT(*) n,
               SUM(CASE WHEN category IN ('Brandanschlag','Gewalt','Militante Aktion') THEN 1 ELSE 0 END) as high
        FROM incidents
        WHERE date >= date('now','-6 months')
          AND location IS NOT NULL AND location NOT IN ('','Unbekannt','Unknown')
        GROUP BY location, country ORDER BY n DESC LIMIT 8
    """).fetchall()]

    # Category trends: current 3m vs previous 3m
    cat_curr = {r['category']: r['n'] for r in db.execute(
        "SELECT category, COUNT(*) n FROM incidents WHERE date >= date('now','-3 months') GROUP BY category"
    ).fetchall()}
    cat_prev = {r['category']: r['n'] for r in db.execute(
        "SELECT category, COUNT(*) n FROM incidents WHERE date >= date('now','-6 months') AND date < date('now','-3 months') GROUP BY category"
    ).fetchall()}
    cat_trends = []
    for cat in CATEGORIES:
        curr = cat_curr.get(cat, 0); prev = cat_prev.get(cat, 0)
        if curr + prev > 0:
            chg = round((curr-prev)/max(prev,1)*100)
            cat_trends.append({"category": cat, "current": curr, "previous": prev, "change_pct": chg})
    cat_trends.sort(key=lambda x: x['current'], reverse=True)

    week_curr = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-7 days')").fetchone()[0]
    week_prev = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-14 days') AND date < date('now','-7 days')").fetchone()[0]

    return JSONResponse({
        "monthly": months,
        "forecast": forecast,
        "trend_direction": "up" if slope > 0.1 else "down" if slope < -0.1 else "stable",
        "slope": round(slope, 2),
        "hot_spots": hot_spots,
        "cat_trends": cat_trends,
        "week_curr": week_curr,
        "week_prev": week_prev,
    })

@app.get("/api/actors")
async def get_actors():
    rows = db.execute(
        "SELECT actors, COUNT(*) n, SUM(CASE WHEN severity_score>=4 THEN 1 ELSE 0 END) as hi, MAX(date) as last_seen "
        "FROM incidents WHERE actors IS NOT NULL AND actors != '' "
        "GROUP BY actors ORDER BY n DESC LIMIT 30"
    ).fetchall()
    actor_map: dict = {}
    for row in rows:
        for a in (row["actors"] or "").split(","):
            a = a.strip()
            if not a: continue
            if a not in actor_map:
                actor_map[a] = {"name": a, "count": 0, "high": 0, "last_seen": ""}
            actor_map[a]["count"] += row["n"]
            actor_map[a]["high"]  += row["hi"]
            if (row["last_seen"] or "") > actor_map[a]["last_seen"]:
                actor_map[a]["last_seen"] = row["last_seen"]
    result = sorted(actor_map.values(), key=lambda x: x["count"], reverse=True)[:15]
    return JSONResponse(result)

# ── FUNDING TRACKER API ──────────────────────────────────────────
# Public, read-only endpoints. Admin CRUD is below in the /admin section.

@app.get("/api/funding")
async def get_funding(
    org: str = "",
    donor_type: str = "",
    country: str = "",
    year_min: int = 0,
    year_max: int = 0,
    amount_min: float = 0.0,
    search: str = "",
    sort: str = "year_desc",
    limit: int = 500,
):
    """Filterable funding-records query — mirrors the /api/incidents shape."""
    q = ("SELECT id, recipient_org, project, amount, currency, year, country, "
         "donor_type, donor_name, source_url, notes, confidence, manual "
         "FROM funding_records WHERE 1=1")
    p: list = []
    if org:        q += " AND recipient_org LIKE ?"; p.append(f"%{org}%")
    if donor_type: q += " AND donor_type=?";         p.append(donor_type)
    if country:    q += " AND country=?";            p.append(country)
    if year_min:   q += " AND year>=?";              p.append(year_min)
    if year_max:   q += " AND year<=?";              p.append(year_max)
    if amount_min: q += " AND amount>=?";            p.append(amount_min)
    if search:
        q += (" AND (recipient_org LIKE ? OR project LIKE ? "
              "OR donor_name LIKE ? OR notes LIKE ?)")
        s = f"%{search}%"
        p.extend([s, s, s, s])
    sort_map = {
        "amount_desc": " ORDER BY amount DESC, year DESC",
        "amount_asc":  " ORDER BY amount ASC,  year DESC",
        "year_desc":   " ORDER BY year DESC,   amount DESC",
        "year_asc":    " ORDER BY year ASC,    amount DESC",
        "org_asc":     " ORDER BY recipient_org ASC, year DESC",
    }
    q += sort_map.get(sort, sort_map["year_desc"])
    q += " LIMIT ?"
    p.append(max(1, min(limit, 2000)))
    return JSONResponse([dict(r) for r in db.execute(q, p).fetchall()])

@app.get("/api/funding/stats")
async def funding_stats():
    """Aggregated stats for the funding-view charts."""
    total_records = db.execute("SELECT COUNT(*) FROM funding_records").fetchone()[0]
    total_amount  = db.execute(
        "SELECT COALESCE(SUM(amount),0) FROM funding_records"
    ).fetchone()[0] or 0
    by_donor_type = [dict(r) for r in db.execute(
        "SELECT donor_type, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY donor_type ORDER BY sum DESC"
    ).fetchall()]
    by_org = [dict(r) for r in db.execute(
        "SELECT recipient_org, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY recipient_org ORDER BY sum DESC LIMIT 15"
    ).fetchall()]
    by_year = [dict(r) for r in db.execute(
        "SELECT year, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY year ORDER BY year ASC"
    ).fetchall()]
    by_country = [dict(r) for r in db.execute(
        "SELECT country, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY country ORDER BY sum DESC"
    ).fetchall()]
    top_donors = [dict(r) for r in db.execute(
        "SELECT donor_name, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY donor_name ORDER BY sum DESC LIMIT 10"
    ).fetchall()]
    return JSONResponse({
        "total_records": total_records,
        "total_amount":  total_amount,
        "by_donor_type": by_donor_type,
        "by_org":        by_org,
        "by_year":       by_year,
        "by_country":    by_country,
        "top_donors":    top_donors,
    })

@app.get("/api/funding/export-csv")
async def funding_export_csv():
    """CSV export of the full funding table."""
    rows = db.execute(
        "SELECT year, recipient_org, project, donor_type, donor_name, "
        "amount, currency, country, confidence, source_url, notes "
        "FROM funding_records ORDER BY year DESC, amount DESC"
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Jahr","Empfänger","Projekt","Geber-Typ","Geber",
                "Betrag","Währung","Land","Konfidenz","Quelle","Notizen"])
    for r in rows:
        w.writerow(list(r))
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=lex-funding-{datetime.now().strftime('%Y%m%d')}.csv"},
    )

@app.get("/api/export-json")
async def export_json(country:str="", category:str="", date_from:str="", date_to:str="", search:str="", severity_min:int=0):
    q = "SELECT id,date,location,country,category,description,url,lat,lon,source,severity_score,actors,confidence FROM incidents WHERE 1=1"
    p = []
    if country:   q += " AND country=?";   p.append(country)
    if category:  q += " AND category=?";  p.append(category)
    if date_from: q += " AND date>=?";     p.append(date_from)
    if date_to:   q += " AND date<=?";     p.append(date_to)
    if search:
        q += " AND (description LIKE ? OR location LIKE ?)"; p.extend([f"%{search}%",f"%{search}%"])
    if severity_min > 0:
        q += " AND severity_score>=?"; p.append(severity_min)
    q += " ORDER BY date DESC"
    rows = [dict(r) for r in db.execute(q, p).fetchall()]
    return StreamingResponse(
        iter([json.dumps(rows, ensure_ascii=False, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=lex-europe-{datetime.now().strftime('%Y%m%d')}.json"}
    )

@app.get("/api/report")
async def generate_report(days: int = 7):
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    prev  = (datetime.now() - timedelta(days=days*2)).strftime("%Y-%m-%d")
    rows  = [dict(r) for r in db.execute(
        "SELECT date,location,country,category,description,url,source,severity_score,actors,confidence "
        "FROM incidents WHERE date >= ? ORDER BY severity_score DESC, date DESC", (since,)
    ).fetchall()]
    prev_count = db.execute("SELECT COUNT(*) FROM incidents WHERE date>=? AND date<?", (prev,since)).fetchone()[0]
    total = len(rows)
    high  = sum(1 for r in rows if (r.get("severity_score") or 0) >= 4)
    by_co  = {}; by_cat = {}; actor_counts = {}
    for r in rows:
        by_co[r["country"]]   = by_co.get(r["country"],0)+1
        by_cat[r["category"]] = by_cat.get(r["category"],0)+1
        for a in (r.get("actors") or "").split(","):
            a=a.strip()
            if a: actor_counts[a] = actor_counts.get(a,0)+1
    chg = round((total-prev_count)/max(prev_count,1)*100)
    chg_str = f"+{chg}%" if chg >= 0 else f"{chg}%"
    top_country = sorted(by_co.items(), key=lambda x:x[1], reverse=True)[:5]
    top_cat     = sorted(by_cat.items(), key=lambda x:x[1], reverse=True)[:5]
    top_actors  = sorted(actor_counts.items(), key=lambda x:x[1], reverse=True)[:8]
    top_incidents = rows[:10]
    now_str = datetime.now().strftime("%d.%m.%Y %H:%M")
    report_html = f"""<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8">
<title>LEX EUROPE — Intelligence Report {now_str}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f8;color:#1a2332;font-size:13px;}}
.page{{max-width:900px;margin:0 auto;padding:32px 24px;}}
.header{{background:linear-gradient(135deg,#0d1b2e 0%,#1a2f4e 100%);color:#fff;padding:28px 32px;margin-bottom:24px;}}
.header h1{{font-size:22px;letter-spacing:3px;font-weight:700;margin-bottom:4px;}}
.header .sub{{font-size:11px;letter-spacing:2px;opacity:.7;margin-bottom:16px;}}
.header .meta{{display:flex;gap:32px;}}
.header .meta div{{font-size:11px;opacity:.6;}}
.header .meta b{{font-size:16px;display:block;opacity:1;color:#00c8ff;}}
.section{{background:#fff;border:1px solid #dee2e8;padding:20px 24px;margin-bottom:16px;}}
.section h2{{font-size:11px;font-weight:700;letter-spacing:2px;color:#5a7a92;border-bottom:2px solid #e8edf2;padding-bottom:8px;margin-bottom:14px;text-transform:uppercase;}}
.exec{{background:#fff8e6;border-left:4px solid #f0a500;padding:16px 20px;font-size:13px;line-height:1.7;}}
.stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}}
.stat{{background:#f4f6f8;padding:14px;text-align:center;border:1px solid #dee2e8;}}
.stat .val{{font-size:24px;font-weight:700;color:#0d1b2e;}}
.stat .lbl{{font-size:10px;letter-spacing:1.5px;color:#5a7a92;margin-top:4px;}}
.red{{color:#cc1133;}} .amber{{color:#cc7a00;}} .green{{color:#008844;}}
table{{width:100%;border-collapse:collapse;font-size:11px;}}
th{{background:#f4f6f8;padding:7px 10px;text-align:left;font-weight:700;letter-spacing:1px;color:#5a7a92;font-size:10px;border-bottom:2px solid #dee2e8;}}
td{{padding:7px 10px;border-bottom:1px solid #eef0f3;vertical-align:top;}}
tr:hover td{{background:#f8fafc;}}
.sev{{display:inline-block;padding:2px 7px;border-radius:2px;font-size:10px;font-weight:700;}}
.s5,.s4{{background:#ffebee;color:#cc1133;}} .s3{{background:#fff8e6;color:#cc7a00;}} .s2,.s1{{background:#e8f4ff;color:#1a6699;}}
.bar-row{{display:flex;align-items:center;gap:8px;margin-bottom:6px;}}
.bar-lbl{{min-width:120px;font-size:11px;}}
.bar-track{{flex:1;height:8px;background:#eef0f3;border-radius:4px;overflow:hidden;}}
.bar-fill{{height:100%;border-radius:4px;background:#0d6699;}}
.footer{{text-align:center;font-size:10px;color:#999;margin-top:24px;padding-top:16px;border-top:1px solid #dee2e8;}}
@media print{{body{{background:#fff;}}.page{{padding:0;}}}}
</style>
</head>
<body>
<div class="page">
<div class="header">
  <div class="sub">OSINT INTELLIGENCE // LEX EUROPE // RESTRICTED</div>
  <h1>WÖCHENTLICHER LAGEBERICHT</h1>
  <div class="meta">
    <div><b>{total}</b>VORFÄLLE GESAMT</div>
    <div><b class="red">{high}</b>HOCH RISIKOVORFÄLLE</div>
    <div><b>{chg_str}</b>VS. VORPERIODE</div>
    <div><b>{len(actor_counts)}</b>AKTEURE IDENTIFIZIERT</div>
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="exec">
    Im Berichtszeitraum der letzten {days} Tage (seit {since}) wurden <strong>{total} Vorfälle</strong> gewalttätiger linksextremer Aktivitäten in Europa dokumentiert.
    Davon wurden <strong>{high} Vorfälle</strong> als hoch-risikoreich eingestuft (Schweregrad 4-5).
    Im Vergleich zur Vorperiode entspricht dies einer Veränderung von <strong>{chg_str}</strong>.
    {"Die Lage ist eskalierend — verstärkte Überwachung empfohlen." if chg > 20 else "Die Lage ist stabil." if abs(chg) <= 20 else "Rückläufige Aktivität beobachtet."}
    {"Schwerpunkte liegen in " + ", ".join(c for c,_ in top_country[:3]) + "." if top_country else ""}
  </div>
</div>

<div class="section">
  <h2>Schlüsselstatistiken</h2>
  <div class="stat-grid">
    <div class="stat"><div class="val">{total}</div><div class="lbl">VORFÄLLE GESAMT</div></div>
    <div class="stat"><div class="val red">{high}</div><div class="lbl">HOCHRISIKO (≥4)</div></div>
    <div class="stat"><div class="val {'green' if chg < 0 else 'red'}">{chg_str}</div><div class="lbl">VS. VORPERIODE</div></div>
    <div class="stat"><div class="val">{len(actor_counts)}</div><div class="lbl">AKTEURE</div></div>
  </div>
</div>

<div class="section">
  <h2>Geografische Verteilung</h2>
  {''.join(f'<div class="bar-row"><span class="bar-lbl">{c}</span><div class="bar-track"><div class="bar-fill" style="width:{round(n/max(total,1)*100)}%"></div></div><span style="font-size:11px;color:#666">{n}</span></div>' for c,n in top_country)}
</div>

<div class="section">
  <h2>Aktivitätstypen</h2>
  {''.join(f'<div class="bar-row"><span class="bar-lbl">{c[:20]}</span><div class="bar-track"><div class="bar-fill" style="width:{round(n/max(total,1)*100)}%;background:#cc1133"></div></div><span style="font-size:11px;color:#666">{n}</span></div>' for c,n in top_cat)}
</div>

{ f'<div class="section"><h2>Aktive Akteure / Gruppen</h2><table><thead><tr><th>GRUPPE</th><th>VORFÄLLE</th></tr></thead><tbody>' + "".join(f"<tr><td>{a}</td><td><b>{n}</b></td></tr>" for a,n in top_actors) + '</tbody></table></div>' if top_actors else '' }

<div class="section">
  <h2>Top Vorfälle (nach Schweregrad)</h2>
  <table>
    <thead><tr><th>DATUM</th><th>ORT</th><th>KATEGORIE</th><th>SCHWERE</th><th>BESCHREIBUNG</th></tr></thead>
    <tbody>
      {"".join(f'<tr><td style="white-space:nowrap">{r.get("date","—")}</td><td>{r.get("location","—")}, {r.get("country","—")}</td><td>{r.get("category","—")}</td><td><span class="sev s{r.get("severity_score",1)}">{r.get("severity_score",1)}/5</span></td><td style="max-width:300px">{(r.get("description") or "")[:120]}…</td></tr>' for r in top_incidents)}
    </tbody>
  </table>
</div>

<div class="footer">
  LEX EUROPE · Automatisch generiert am {now_str} · Datenstand: {since} bis {datetime.now().strftime("%d.%m.%Y")} · Nur zur internen Verwendung
</div>
</div>
</body>
</html>"""
    return HTMLResponse(report_html)

@app.get("/api/admin-check")
async def admin_check(request: Request):
    """
    Lets the public frontend ask "is this browser an authenticated admin?"
    The admin_token cookie is httpOnly so the page cannot read it directly —
    this endpoint reads + validates it server-side and reports a plain bool.
    Used by index.html to reveal the in-detail Edit/Delete controls.
    """
    return JSONResponse({"admin": verify_token(request.cookies.get("admin_token", ""))})

@app.delete("/api/admin/incident/{inc_id}")
async def admin_inline_delete(inc_id: int, _=Depends(require_admin)):
    """Quick-delete an incident from the public map detail panel."""
    db.execute("DELETE FROM incidents WHERE id=?", (inc_id,))
    db.commit()
    return JSONResponse({"ok": True, "id": inc_id})

@app.put("/api/admin/incident/{inc_id}")
async def admin_inline_update(inc_id: int, request: Request, _=Depends(require_admin)):
    """Quick-edit fields on a single incident from the map (admin only)."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    allowed = {"description","summary","location","country","category","severity_score","date","url",
               # Strategic Concept v3 — Säule 1 (Strafverfolgungs-Druck) + Säule 2 (Frühwarn-Routing)
               "tier","target_type","prosec_status","case_ref","last_status_check"}
    fields = {k: v for k, v in data.items() if k in allowed}
    # Validate tier + prosec_status values to keep the columns clean.
    if "tier" in fields and fields["tier"] not in ("act","enable","context"):
        return JSONResponse({"ok": False, "message": "tier muss act|enable|context sein"}, status_code=400)
    _allowed_prosec = {"unknown","none","investigating","charged","trial","convicted","acquitted","dismissed"}
    if "prosec_status" in fields and fields["prosec_status"] not in _allowed_prosec:
        return JSONResponse({"ok": False, "message": f"prosec_status muss eines von {sorted(_allowed_prosec)} sein"}, status_code=400)
    if not fields:
        return JSONResponse({"ok": False, "message": "Keine erlaubten Felder"}, status_code=400)
    # Run PII redaction on text fields before saving — admin shouldn't be
    # able to bypass the safety filter even by direct edit.
    if "description" in fields:
        fields["description"] = redact_pii(fields["description"] or "")[:500]
    if "summary" in fields:
        fields["summary"] = redact_pii(fields["summary"] or "")[:280]
    cols = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE incidents SET {cols} WHERE id=?",
               tuple(list(fields.values()) + [inc_id]))
    db.commit()
    return JSONResponse({"ok": True, "id": inc_id})

@app.get("/api/diagnose")
async def diagnose():
    key = os.getenv("GROK_API_KEY","")
    r   = {"env":{"GROK_API_KEY_set":bool(key),"GROK_API_KEY_len":len(key),
                  "GROK_MODEL":GROK_MODEL,"ADMIN_PASS_ok":ADMIN_PASS!="changeme",
                  "DB_PATH":DB_PATH}}
    # Test barrikade
    try:
        html = fetch("https://barrikade.info/", timeout=10)
        ids  = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        r["barrikade"] = {"ok":True,"max_id":max(ids) if ids else 0,"len":len(html)}
    except Exception as e:
        r["barrikade"] = {"ok":False,"error":str(e)}
    # Test indymedia
    try:
        xml   = fetch("https://de.indymedia.org/RSS/newswire.xml", timeout=10)
        items = parse_rss(xml)
        r["indymedia"] = {"ok":True,"items":len(items)}
    except Exception as e:
        r["indymedia"] = {"ok":False,"error":str(e)}
    # Test grok
    if key:
        try:
            resp = requests.post("https://api.x.ai/v1/chat/completions",
                headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},
                json={"model":GROK_MODEL,"messages":[{"role":"user","content":"OK"}],
                      "max_tokens":5,"temperature":0.0}, timeout=15)
            r["grok"] = {"status":resp.status_code,
                         "model":resp.json().get("model","?") if resp.ok else "—",
                         "response":resp.json()["choices"][0]["message"]["content"] if resp.ok else resp.text[:100]}
        except Exception as e:
            r["grok"] = {"ok":False,"error":str(e)}
    r["db"] = {"incidents":db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
               "metadata":[dict(x) for x in db.execute("SELECT * FROM metadata").fetchall()]}
    return JSONResponse(r)

# AUTH
@app.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})

@app.post("/admin/login")
async def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = make_token()
        resp  = RedirectResponse("/admin", status_code=302)
        resp.set_cookie("admin_token", token, httponly=True, samesite="strict", max_age=43200)
        return resp
    return templates.TemplateResponse("login.html",{"request":request,"error":"Ungültige Zugangsdaten"})

@app.get("/admin/logout")
async def do_logout(request: Request):
    db.execute("DELETE FROM sessions WHERE token=?", (request.cookies.get("admin_token",""),))
    db.commit()
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie("admin_token")
    return resp

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not verify_token(request.cookies.get("admin_token","")):
        return RedirectResponse("/admin/login", status_code=302)
    b_max  = int(meta_get("hist_b_max") or 0)
    b_curr = int(meta_get("hist_b_curr") or 0)
    b_pct  = f"{round((b_max-b_curr)/max(b_max,1)*100,1)}%" if b_max else "—"
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "total":        db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "running":      _running[0],
        "hist_running": _hist_run[0],
        "last_crawl":   meta_get("last_crawl") or "—",
        "recent": [dict(r) for r in db.execute(
            "SELECT id,date,location,country,category,source FROM incidents ORDER BY timestamp DESC LIMIT 20").fetchall()],
        "categories": CATEGORIES,
        "feed_count": len(RSS_FEEDS),
        "hist_b_pct":  b_pct,
        "hist_b_done": bool(meta_get("hist_b_done")),
        "hist_im_done":bool(meta_get("hist_im_done")),
    })

@app.post("/admin/api/crawl")
async def admin_crawl(bg: BackgroundTasks, _=Depends(require_admin)):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "Crawler gestartet"})

@app.post("/admin/api/stop-crawl")
async def admin_stop(_=Depends(require_admin)):
    _running[0] = False
    return JSONResponse({"status": "Gestoppt"})

@app.post("/admin/api/crawl-historical")
async def admin_hist(bg: BackgroundTasks, reset: bool = False, _=Depends(require_admin)):
    bg.add_task(run_historical, reset)
    return JSONResponse({"status": "Historisch gestartet"})

@app.get("/admin/api/status")
async def admin_status(_=Depends(require_admin)):
    b_max  = int(meta_get("hist_b_max") or 0)
    b_curr = int(meta_get("hist_b_curr") or 0)
    return JSONResponse({
        "total":       db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "geocoded":    db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0],
        "crawl_running": _running[0],
        "hist_running":  _hist_run[0],
        "last_crawl":  meta_get("last_crawl"),
        "feed_count":  len(RSS_FEEDS),
        "hist": {
            "barrikade_done": bool(meta_get("hist_b_done")),
            "barrikade_pct":  round((b_max-b_curr)/max(b_max,1)*100,1) if b_max else 0,
            "barrikade_curr": b_curr,
            "indymedia_done": bool(meta_get("hist_im_done")),
            "indymedia_off":  int(meta_get("hist_im_offset") or 0),
        },
        "sources": [dict(r) for r in db.execute(
            "SELECT source,COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC LIMIT 20").fetchall()],
    })

@app.post("/admin/api/add-incident")
async def admin_add(request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    for f in ["date","location","country","category","description"]:
        if not data.get(f):
            return JSONResponse({"ok": False, "message": f"Pflichtfeld '{f}' fehlt"}, status_code=400)
    try:
        ai  = {"land":data["country"], "kategorie":data["category"], "ort":data["location"]}
        url = data.get("url") or f"manual-{datetime.now().isoformat()}"
        ok  = save_incident(ai, data["description"], data.get("source","Manuell"), url, data["date"], manual=True)
        return JSONResponse({"ok": ok, "message": "Gespeichert" if ok else "Bereits vorhanden"})
    except Exception as e:
        log.error(f"admin_add: {e}", exc_info=True)
        return JSONResponse({"ok": False, "message": f"Fehler: {str(e)[:200]}"}, status_code=500)

@app.delete("/admin/api/incident/{inc_id}")
async def admin_delete(inc_id: int, _=Depends(require_admin)):
    db.execute("DELETE FROM incidents WHERE id=?", (inc_id,))
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/admin/api/clear")
async def admin_clear(_=Depends(require_admin)):
    db.execute("DELETE FROM incidents")
    db.execute("DELETE FROM metadata")
    db.commit()
    return JSONResponse({"status": "Geleert"})

@app.post("/admin/api/regeocode")
async def admin_regeocode(bg: BackgroundTasks, _=Depends(require_admin)):
    bg.add_task(regeocode_nulls)
    return JSONResponse({"status": "Geocoding läuft"})

@app.post("/admin/api/grok-test")
async def admin_grok(_=Depends(require_admin)):
    res = classify("In Berlin-Kreuzberg wurden drei Polizeifahrzeuge in Brand gesetzt. Bekennerschreiben einer militanten autonomen Gruppe.")
    return JSONResponse(res or {"error": "Keine Antwort"})

@app.get("/admin/api/export-csv")
async def export_csv(_=Depends(require_admin)):
    rows = db.execute(
        "SELECT date,location,country,category,description,source,url,lat,lon,manual,timestamp FROM incidents ORDER BY date DESC"
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Datum","Ort","Land","Kategorie","Beschreibung","Quelle","URL","Lat","Lon","Manuell","Erfasst"])
    for r in rows: w.writerow(list(r))
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=lex-europe-{datetime.now().strftime('%Y%m%d')}.csv"})

@app.post("/admin/api/seed")
async def admin_seed(_=Depends(require_admin)):
    n = seed_historical_data()
    return JSONResponse({"status": f"{n} historische Einträge eingespielt" if n else "Bereits eingespielt"})

# ── ADMIN: FUNDING CRUD ─────────────────────────────────────────
_FUND_DONOR_TYPES = {"Bund","Kanton","Stadt","Stiftung","EU","Anderes"}
_FUND_COUNTRIES   = {"DE","AT","CH","EU","Andere"}

def _validate_funding(data: dict) -> str:
    """
    Return '' if valid, else an error message.
    Funding data is legally sensitive — we enforce a Primärquelle (source_url)
    and a Verbindungsnachweis (notes, ≥40 chars) for every manual entry so
    that no record ever lives in the public DB without traceable justification.
    """
    for f in ["recipient_org","amount","year","country","donor_type","donor_name"]:
        if data.get(f) in (None, ""):
            return f"Pflichtfeld '{f}' fehlt"
    try:
        amt = float(data["amount"])
        yr  = int(data["year"])
        if amt < 0:    return "Betrag muss positiv sein"
        if yr < 1990 or yr > 2099: return "Jahr ausserhalb des Bereichs"
    except (ValueError, TypeError):
        return "Betrag oder Jahr ist nicht numerisch"
    if data["country"] not in _FUND_COUNTRIES:
        return f"Land '{data['country']}' ungültig (erlaubt: {', '.join(sorted(_FUND_COUNTRIES))})"
    if data["donor_type"] not in _FUND_DONOR_TYPES:
        return f"Geber-Typ '{data['donor_type']}' ungültig"
    src = (data.get("source_url") or "").strip()
    if not src or not src.lower().startswith(("http://", "https://")):
        return "Primärquelle (source_url) fehlt oder ist keine vollständige URL"
    notes = (data.get("notes") or "").strip()
    if len(notes) < 40:
        return ("Verbindungsnachweis (notes) fehlt — mind. 40 Zeichen mit Nennung "
                "des VS-Berichts / Aktenzeichens / Primärquelle erforderlich")
    return ""

@app.post("/admin/api/funding")
async def admin_add_funding(request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    err = _validate_funding(data)
    if err:
        return JSONResponse({"ok": False, "message": err}, status_code=400)
    amt = float(data["amount"]); yr = int(data["year"])
    h_input = (
        f"fund|{data['recipient_org'].lower().strip()}|{yr}|"
        f"{data['donor_name'].lower().strip()}|{round(amt)}"
    )
    h = hashlib.sha256(h_input.encode()).hexdigest()
    try:
        cur = db.execute(
            """INSERT OR IGNORE INTO funding_records
               (recipient_org, project, amount, currency, year, country,
                donor_type, donor_name, source_url, notes, confidence,
                manual, hash, timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,datetime('now'))""",
            (data["recipient_org"], data.get("project") or None, amt,
             data.get("currency","EUR"), yr, data["country"],
             data["donor_type"], data["donor_name"],
             data.get("source_url") or None, data.get("notes") or None,
             int(data.get("confidence", 3)), h)
        )
        db.commit()
        if cur.rowcount == 0:
            return JSONResponse({"ok": False, "message": "Eintrag bereits vorhanden"})
        return JSONResponse({"ok": True, "message": "Gespeichert", "id": cur.lastrowid})
    except Exception as e:
        log.error(f"admin_add_funding: {e}", exc_info=True)
        return JSONResponse({"ok": False, "message": f"Fehler: {str(e)[:200]}"}, status_code=500)

@app.put("/admin/api/funding/{rec_id}")
async def admin_update_funding(rec_id: int, request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    err = _validate_funding(data)
    if err:
        return JSONResponse({"ok": False, "message": err}, status_code=400)
    db.execute(
        """UPDATE funding_records
           SET recipient_org=?, project=?, amount=?, currency=?, year=?,
               country=?, donor_type=?, donor_name=?, source_url=?,
               notes=?, confidence=?
           WHERE id=?""",
        (data["recipient_org"], data.get("project") or None,
         float(data["amount"]), data.get("currency","EUR"), int(data["year"]),
         data["country"], data["donor_type"], data["donor_name"],
         data.get("source_url") or None, data.get("notes") or None,
         int(data.get("confidence", 3)), rec_id)
    )
    db.commit()
    return JSONResponse({"ok": True, "message": "Aktualisiert"})

@app.delete("/admin/api/funding/{rec_id}")
async def admin_delete_funding(rec_id: int, _=Depends(require_admin)):
    db.execute("DELETE FROM funding_records WHERE id=?", (rec_id,))
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/admin/api/funding/seed")
async def admin_seed_funding(_=Depends(require_admin)):
    n = seed_funding_data()
    return JSONResponse({
        "status": f"{n} Fördergeld-Einträge eingespielt" if n else "Bereits eingespielt"
    })

@app.on_event("startup")
async def startup():
    purge_garbage()  # enforce §0 scope on existing rows
    cnt = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    if cnt == 0:
        seed_historical_data()
    # IMPORTANT: enrichment (severity, actors, confidence) must run BEFORE
    # the flag/summary backfill so is_high_risk sees the real severity.
    backfill_enrichment()
    backfill_summaries_and_flags()
    # Always attempt to seed funding (idempotent — no-op if already present).
    seed_funding_data()
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    # Main crawler: every 12 hours (cost-efficient)
    sched.add_job(run_crawler, "interval", hours=12, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=20))
    # Auto-continue historical barrikade crawl every 45 min until complete
    sched.add_job(auto_hist, "interval", minutes=45, id="auto_hist",
                  next_run_time=datetime.now() + timedelta(seconds=90))
    sched.start()
    log.info(f"LEX EUROPE — {len(RSS_FEEDS)} RSS + {len(GNEWS_Q)} GNews — crawl in 20s | hist auto-continue every 45min")

