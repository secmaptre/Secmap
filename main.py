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
        return re.sub(r"\s{3,}", " ", raw)[:5000]
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
    "berlin": (52.52, 13.405), "hamburg": (53.55, 10.00), "münchen": (48.14, 11.58),
    "munich": (48.14, 11.58), "köln": (50.94, 6.96), "frankfurt": (50.11, 8.68),
    "stuttgart": (48.78, 9.18), "düsseldorf": (51.23, 6.78), "leipzig": (51.34, 12.37),
    "dresden": (51.05, 13.74), "hannover": (52.37, 9.74), "bremen": (53.08, 8.80),
    "dortmund": (51.51, 7.47), "nürnberg": (49.45, 11.08), "bochum": (51.48, 7.22),
    "zürich": (47.38, 8.54), "zurich": (47.38, 8.54), "bern": (46.95, 7.44),
    "genf": (46.20, 6.14), "geneva": (46.20, 6.14), "basel": (47.56, 7.59),
    "wien": (48.21, 16.37), "vienna": (48.21, 16.37), "graz": (47.07, 15.44),
    "linz": (48.31, 14.29), "salzburg": (47.80, 13.05),
    "paris": (48.85, 2.35), "rom": (41.90, 12.50), "athen": (37.98, 23.73),
    "deutschland": (51.16, 10.45), "schweiz": (46.80, 8.22), "österreich": (47.52, 14.55),
    "de": (51.16, 10.45), "ch": (46.80, 8.22), "at": (47.52, 14.55),
}

_last_geo = [0.0]

def geocode(location, country):
    if not location or location.strip() in ("", "Unbekannt", "Unknown"):
        # Fallback to country center
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
        r = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": f"{location}, {country}", "format": "json", "limit": 1},
            headers={"User-Agent": "LEX-EUROPE-OSINT/5.0"},
            timeout=10
        )
        _last_geo[0] = time.time()
        res = r.json()
        if res:
            lat, lon = float(res[0]["lat"]), float(res[0]["lon"])
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
           "stuttgart","hannover","bremen","dortmund","nürnberg","sachsen","thüringen","Bayern",
           "NRW","Baden-Württemberg"],
    "AT": ["österreich","wien","graz","linz","salzburg","innsbruck"],
    "CH": ["schweiz","zürich","bern","genf","basel","lausanne","winterthur"],
    "FR": ["frankreich","paris","lyon","marseille","bordeaux"],
    "IT": ["italien","rom","mailand","turin","neapel"],
    "GR": ["griechenland","athen","thessaloniki"],
    "ES": ["spanien","madrid","barcelona","valencia"],
    "UK": ["england","großbritannien","london","manchester","glasgow"],
}

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

    return {"kategorie": found_cat, "land": found_country, "ort": found_loc}

def smart_classify(text):
    """Try keyword classification first, fall back to Grok only if no match."""
    result = classify_keywords(text)
    if result:
        return result
    return classify(text)

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
]

def classify(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return None

    cats = "|".join(CATEGORIES)
    prompt = (
        "Klassifiziere diesen Text über einen linksextremen Vorfall.\n"
        "Gib NUR ein JSON-Objekt zurück, kein Markdown, keine Erklärung.\n\n"
        f"Text: {text[:2000]}\n\n"
        f"Antwort: {{\"land\":\"DE|AT|CH|FR|IT|GR|ES|UK|Andere\","
        f"\"kategorie\":\"{cats}\","
        f"\"ort\":\"Stadt oder Region\"}}"
    )
    raw = ""
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": GROK_MODEL,
                  "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.0, "max_tokens": 100},
            timeout=35
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"```[a-z]*", "", raw).replace("```", "").strip()
        # Extract JSON object
        m = re.search(r'\{[^}]+\}', raw, re.DOTALL)
        if m: raw = m.group(0)
        res = json.loads(raw)
        res.setdefault("ort", "Unbekannt")
        res.setdefault("land", "Unbekannt")
        res.setdefault("kategorie", "Sonstiges")
        log.info(f"Grok → {res['kategorie']} / {res['ort']} / {res['land']}")
        return res
    except requests.HTTPError:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:200]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON fail: raw={repr(raw[:150])}")
    except Exception as e:
        log.error(f"Grok: {e}")
    return None

# ── PERSISTENCE ───────────────────────────────────────────────────
def mk_hash(url, text):
    return hashlib.sha256(((url or "") + "|" + text[:300]).encode()).hexdigest()

def is_seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE hash=?", (h,)).fetchone() is not None

def save_incident(ai, text, source, url, date_str=None, manual=False):
    h = mk_hash(url or text[:80], text)
    if is_seen(h): return False
    lat, lon = geocode(ai.get("ort",""), ai.get("land",""))
    d = date_str or datetime.now().strftime("%Y-%m-%d")
    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents
               (date,location,country,category,description,source,url,hash,lat,lon,manual,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
            (d, ai.get("ort","Unbekannt"), ai.get("land","Unbekannt"),
             ai.get("kategorie","Sonstiges"), text[:700],
             source, url or "", h, lat, lon, 1 if manual else 0)
        )
        db.commit()
        log.info(f"SAVED: {ai.get('kategorie')} / {ai.get('ort')} / {source}")
        return True
    except Exception as e:
        log.warning(f"save_incident: {e}")
        return False

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
    inserted = 0
    feeds = [
        "https://de.indymedia.org/RSS/newswire.xml",
        "https://de.indymedia.org/RSS/features.xml",
        "https://de.indymedia.org/taxonomy/term/20/all/feed",
        "https://de.indymedia.org/taxonomy/term/56/all/feed",
        "https://de.indymedia.org/taxonomy/term/671/all/feed",
        "https://de.indymedia.org/taxonomy/term/100/all/feed",
        "https://de.indymedia.org/taxonomy/term/130/all/feed",
    ]
    seen_urls = set()
    for feed_url in feeds:
        try:
            xml   = fetch(feed_url, timeout=15)
            items = parse_rss(xml)
            log.info(f"indymedia feed {feed_url.split('/')[-1]}: {len(items)} items")
            for title, link, desc, pub in items:
                if link in seen_urls: continue
                seen_urls.add(link)
                h = mk_hash(link, title + desc)
                if is_seen(h): continue
                # Get full article
                full = get_text(link)
                text = full if len(full) > 100 else f"{title}. {desc}"
                if len(text) < 30: continue
                ai = smart_classify(text)
                if ai:
                    d = parse_date(pub) or date_from_url(link)
                    save_incident(ai, text, "de.indymedia.org", link, d)
                    inserted += 1
                time.sleep(0.5)
        except Exception as e:
            log.warning(f"indymedia feed {feed_url}: {e}")
        time.sleep(0.3)
    return inserted

# ── RSS FEEDS ─────────────────────────────────────────────────────
RSS_KEYWORDS = [
    "linksextrem","linksradikal","autonom","antifa","anarchi","schwarzer block","black bloc",
    "brandanschlag","sabotage","molotow","farbbeutel","bekennerschreiben","militante",
    "besetzung","blockade","rigaer","rote flora","sachbeschädigung","in brand",
    "verfassungsschutz extremis","linksradikal verhaftung","linksextrem anschlag",
    "autonome gruppe","direkte aktion","barrikade",
]

RSS_FEEDS = [
    ("verfassungsschutz.de", "https://www.verfassungsschutz.de/SiteGlobals/Functions/RSSNewsFeed/AlleMeldungen.xml"),
    ("barrikade.info",    "https://barrikade.info/feed"),
    ("tagesschau.de",     "https://www.tagesschau.de/xml/rss2/"),
    ("deutschlandfunk.de","https://www.deutschlandfunk.de/nachrichten.rss"),
    ("deutschlandfunk.de","https://www.deutschlandfunk.de/inland.rss"),
    ("spiegel.de",        "https://www.spiegel.de/schlagzeilen/index.rss"),
    ("zeit.de",           "https://newsfeed.zeit.de/politik/index"),
    ("sueddeutsche.de",   "https://rss.sueddeutsche.de/rss/Politik"),
    ("faz.net",           "https://www.faz.net/rss/aktuell/"),
    ("tagesspiegel.de",   "https://www.tagesspiegel.de/contentexport/feed/home"),
    ("taz.de",            "https://taz.de/!p4608;rss/"),
    ("rbb24.de",          "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("ndr.de",            "https://www.ndr.de/nachrichten/index-rss.xml"),
    ("mdr.de",            "https://www.mdr.de/nachrichten/rss-nachrichten100.xml"),
    ("srf.ch",            "https://www.srf.ch/news/bnf/rss/1646"),
    ("nzz.ch",            "https://www.nzz.ch/recent.rss"),
    ("20min.ch",          "https://api.20min.ch/rss/view/1"),
    ("blick.ch",          "https://www.blick.ch/news/rss.xml"),
    ("orf.at",            "https://rss.orf.at/news.xml"),
    ("derstandard.at",    "https://www.derstandard.at/rss/inland"),
    ("diepresse.com",     "https://www.diepresse.com/rss/politik"),
    ("krone.at",          "https://www.krone.at/feed/news"),
]

GNEWS_Q = [
    ("DE","linksextremismus anschlag"),
    ("DE","autonome brandanschlag sachbeschädigung"),
    ("DE","antifa gewalt bekennerschreiben"),
    ("DE","schwarzer block randalen"),
    ("DE","militante linke sabotage"),
    ("CH","linksextrem schweiz anschlag"),
    ("CH","autonome zürich bern"),
    ("AT","linksextremismus österreich"),
    ("AT","autonome wien sabotage"),
    ("DE","rigaer strasse linksradikal"),
    ("DE","bundesverfassungsschutz linksextremismus"),
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
        # Barrikade: all IDs from max down to 1
        DONE="hist_b_done"; CURR="hist_b_curr"
        if not meta_get(DONE):
            if not meta_get(CURR):
                mx = barrikade_latest_id()
                meta_set("hist_b_max", mx)
                meta_set(CURR, mx)
            curr  = int(meta_get(CURR))
            stop  = max(1, curr - 300)
            log.info(f"Barrikade hist: {curr}→{stop}")
            n = crawl_barrikade_range(curr, stop)
            meta_set(CURR, stop - 1)
            if stop <= 1: meta_set(DONE, datetime.now().isoformat())
            log.info(f"Barrikade hist: +{n}")

        # Indymedia: offset pagination
        IDONE="hist_im_done"; IOFF="hist_im_offset"
        if not meta_get(IDONE):
            off = int(meta_get(IOFF) or 0)
            inserted = 0
            empty    = 0
            for o in range(off, off + 40*20, 20):
                links = []
                for base in [f"https://de.indymedia.org/?limit=20&offset={o}",
                             f"https://de.indymedia.org/index.html?limit=20&offset={o}"]:
                    try:
                        soup = BeautifulSoup(fetch(base), "html.parser")
                        for a in soup.find_all("a", href=True):
                            href = a["href"].strip()
                            if not href or any(x in href for x in ["#","mailto:",".css",".js","?"]): continue
                            full = urljoin("https://de.indymedia.org", href)
                            if "indymedia.org" not in full: continue
                            path = full.replace("https://de.indymedia.org","").strip("/")
                            if path and path not in ("impressum","about","contact","rss"): links.append(full)
                        if links: break
                    except: pass
                if not links:
                    empty += 1
                    if empty >= 6: meta_set(IDONE, datetime.now().isoformat()); break
                    time.sleep(1.5); continue
                empty = 0
                for url in list(dict.fromkeys(links))[:15]:
                    text = get_text(url)
                    if len(text) < 80: continue
                    h = mk_hash(url, text)
                    if is_seen(h): continue
                    ai = smart_classify(text)
                    if ai:
                        if save_incident(ai, text, "de.indymedia.org", url, date_from_url(url)):
                            inserted += 1
                    time.sleep(0.65)
                meta_set(IOFF, o + 20)
                time.sleep(1.0)
            log.info(f"Indymedia hist: +{inserted}")

        regeocode_nulls()
    except Exception as e:
        log.error(f"run_historical: {e}", exc_info=True)
    finally:
        _hist_run[0] = False
    log.info("══ HISTORICAL DONE ══")

# ── FASTAPI ───────────────────────────────────────────────────────
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents(country:str="", category:str="", date_from:str="", date_to:str="", search:str=""):
    q = "SELECT id,date,location,country,category,description,url,lat,lon,manual,source FROM incidents WHERE 1=1"
    p = []
    if country:   q += " AND country=?";   p.append(country)
    if category:  q += " AND category=?";  p.append(category)
    if date_from: q += " AND date>=?";     p.append(date_from)
    if date_to:   q += " AND date<=?";     p.append(date_to)
    if search:
        q += " AND (description LIKE ? OR location LIKE ? OR category LIKE ?)"
        p.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
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

@app.on_event("startup")
async def startup():
    if db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0:
        seed_historical_data()
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, "interval", hours=2, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=15))
    sched.start()
    log.info(f"LEX EUROPE v7 — {len(RSS_FEEDS)} RSS + {len(GNEWS_Q)} GNews — crawl in 15s")

