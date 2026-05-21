import os, logging, json, time, hashlib, re
from datetime import datetime, timedelta
from urllib.parse import urljoin, quote_plus
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DB_PATH = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
log.info(f"DB: {DB_PATH}")

# ─────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        date             TEXT,
        location         TEXT,
        country          TEXT,
        category         TEXT,
        description      TEXT,
        source           TEXT,
        url              TEXT,
        content_hash     TEXT UNIQUE,
        lat              REAL,
        lon              REAL,
        timestamp        TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY, value TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS geocache (
        query TEXT PRIMARY KEY, lat REAL, lon REAL
    )''')
    c.commit()
    return c

db = get_db()

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
}

# ─────────────────────────────────────────────────────────────────
# METADATA HELPERS
# ─────────────────────────────────────────────────────────────────
def meta_get(key):
    row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    return row[0] if row else None

def meta_set(key, val):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, str(val)))
    db.commit()

def meta_del(key):
    db.execute("DELETE FROM metadata WHERE key=?", (key,))
    db.commit()

# ─────────────────────────────────────────────────────────────────
# GEOCODING  (Nominatim, 1-per-1.2s, cached)
# ─────────────────────────────────────────────────────────────────
_last_geo = [0.0]

def geocode(location, country):
    if not location or location.strip() in ("", "Unbekannt", "Unknown"):
        return None, None
    key = f"{location.strip().lower()}|{country.strip().lower()}"
    row = db.execute("SELECT lat,lon FROM geocache WHERE query=?", (key,)).fetchone()
    if row:
        return row[0], row[1]
    wait = 1.2 - (time.time() - _last_geo[0])
    if wait > 0:
        time.sleep(wait)
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": f"{location}, {country}", "format": "json", "limit": 1},
            headers={"User-Agent": "LEX-EUROPE-OSINT/3.0"},
            timeout=10
        )
        _last_geo[0] = time.time()
        res = r.json()
        if res:
            lat, lon = float(res[0]["lat"]), float(res[0]["lon"])
            db.execute("INSERT OR REPLACE INTO geocache VALUES (?,?,?)", (key, lat, lon))
            db.commit()
            return lat, lon
    except Exception as e:
        log.warning(f"Geocode '{location}': {e}")
    db.execute("INSERT OR REPLACE INTO geocache VALUES (?,NULL,NULL)", (key,))
    db.commit()
    return None, None

# ─────────────────────────────────────────────────────────────────
# GROK CLASSIFICATION
#
# TWO MODES:
#   "loose"  → barrikade / indymedia: accept EVERYTHING that describes
#              any physical event, action, demo, arrest, attack, damage.
#              Reject only pure theory/essay texts with zero event content.
#
#   "strict" → mainstream RSS: only confirmed left-extremist violence.
# ─────────────────────────────────────────────────────────────────
CATEGORIES = ("Brandanschlag|Sabotage|Gewalt|Schmiererei|Aufruf zu Gewalt|"
              "Militante Aktion|Sachbeschädigung|Demo/Kundgebung|"
              "Besetzung|Repression|Verhaftung|Sonstiges|Unklassifiziert")

def classify(text, mode="loose"):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return None

    if mode == "loose":
        rule = (
            "AUFGABE: Entscheide ob dieser Text ein konkretes Ereignis beschreibt "
            "(Angriff, Demo, Besetzung, Verhaftung, Sabotage, Brandstiftung, "
            "Sachbeschädigung, Schmiererei, Aufruf zu Aktion, Repression, Blockade, "
            "Kundgebung oder ähnliches).\n"
            "relevant = true  → Text beschreibt ein KONKRETES EREIGNIS (auch kleine Aktionen, "
            "Graffiti, Demo-Berichte, Polizeieinsätze, Solidaritätsaktionen etc.)\n"
            "relevant = false → Reiner Theorietext / Analyse / Essay / Pressemitteilung "
            "ohne jedes konkrete Ereignis.\n"
            "IM ZWEIFEL: relevant = true."
        )
    else:
        rule = (
            "AUFGABE: Entscheide ob dieser Medienbericht eine konkrete linksextreme / "
            "linksradikale Gewalttat oder militante Aktion in Europa beschreibt.\n"
            "relevant = true  → Tat klar erkennbar, linksradikale Täter, DACH-Bezug.\n"
            "relevant = false → Kein konkreter Tatvorwurf oder nicht DACH."
        )

    prompt = (
        f"{rule}\n\n"
        f"TEXT:\n{text[:2000]}\n\n"
        "Antworte NUR mit kompaktem JSON ohne Markdown:\n"
        '{"land":"DE|AT|CH|FR|IT|GR|ES|UK|Andere",'
        f'"kategorie":"{CATEGORIES}",'
        '"ort":"Stadt oder Region (beste Schätzung wenn unklar)",'
        '"relevant":true}'
    )

    raw = ""
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={
                "model": "grok-4",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 200
            },
            timeout=35
        )
        r.raise_for_status()
        raw = (r.json()["choices"][0]["message"]["content"]
               .strip().replace("```json","").replace("```","").strip())
        res = json.loads(raw)
        # Ensure required keys
        res.setdefault("relevant", True)
        res.setdefault("ort", "Unbekannt")
        res.setdefault("land", "Unbekannt")
        res.setdefault("kategorie", "Sonstiges")
        log.info(f"Grok[{mode}]: {res}")
        return res
    except requests.HTTPError:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:300]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON fail: {e} — raw: {raw[:150]}")
    except Exception as e:
        log.error(f"Grok error: {e}")
    return None

# ─────────────────────────────────────────────────────────────────
# DB PERSISTENCE
# ─────────────────────────────────────────────────────────────────
def chash(url, text):
    return hashlib.sha256((url + "|" + text[:300]).encode()).hexdigest()

def seen(h):
    return db.execute(
        "SELECT 1 FROM incidents WHERE content_hash=?", (h,)
    ).fetchone() is not None

def save(ai, text, source, url, date_str=None):
    if not ai:
        return False
    h = chash(url, text)
    if seen(h):
        return False
    lat, lon = geocode(ai.get("ort", ""), ai.get("land", ""))
    d = date_str or datetime.now().strftime("%Y-%m-%d")
    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents
               (date,location,country,category,description,
                source,url,content_hash,lat,lon,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
            (d,
             ai.get("ort", "Unbekannt"),
             ai.get("land", "Unbekannt"),
             ai.get("kategorie", "Sonstiges"),
             text[:700],
             source, url, h, lat, lon)
        )
        db.commit()
        return True
    except Exception as e:
        log.warning(f"save: {e}")
        return False

# ─────────────────────────────────────────────────────────────────
# HTTP / PARSING HELPERS
# ─────────────────────────────────────────────────────────────────
def fetch(url, timeout=25):
    r = requests.get(url, timeout=timeout, headers=HEADERS)
    r.raise_for_status()
    return r.text

def get_text(url):
    """Fetch URL and extract main readable text."""
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script","style","nav","footer","header","aside","form","iframe"]):
            tag.decompose()
        # Try progressively broader selectors
        el = (
            soup.find("article") or
            soup.find("main") or
            soup.find(True, class_=re.compile(
                r"\b(article|content|post|entry|text|body|node|story)\b", re.I)) or
            soup.find(True, id=re.compile(
                r"\b(article|content|main|post|text|body)\b", re.I)) or
            soup.body or soup
        )
        raw = el.get_text(" ", strip=True)
        # Collapse whitespace
        raw = re.sub(r"[ \t]{2,}", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw[:4500]
    except Exception as e:
        log.warning(f"get_text {url}: {e}")
        return ""

def date_from_url(url):
    """Extract YYYY-MM-DD from a URL that contains a date pattern."""
    m = re.search(r"(20\d{2})[/_-](\d{1,2})[/_-](\d{1,2})", url)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)),
                            int(m.group(3))).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None

# ─────────────────────────────────────────────────────────────────
# BARRIKADE.INFO
#
# Articles are at /article/<integer_id>
# Estimated ID ranges (based on known articles 6493 and 7490):
#   ~7500 = early 2026
#   ~6500 = early 2025
#   ~5500 = early 2024
#   ~4500 = early 2023
# We crawl IDs 4000 → max to cover 2023–present.
# Each run processes BATCH_SIZE IDs, saves progress, resumes next run.
# ─────────────────────────────────────────────────────────────────
BARRIKADE_MIN_ID    = 4000   # safely covers all of 2023
BARRIKADE_BATCH     = 400    # IDs processed per crawl run

def barrikade_find_max_id():
    """Scrape barrikade front page and return the highest article ID found."""
    try:
        html = fetch("https://barrikade.info/")
        ids = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        if ids:
            mx = max(ids)
            log.info(f"barrikade max ID: {mx}")
            return mx
    except Exception as e:
        log.warning(f"barrikade_find_max_id: {e}")
    return 7600  # safe fallback

def scrape_barrikade():
    """
    Iterates barrikade article IDs.
    - On first call: starts from max ID found on front page.
    - Subsequent calls: resumes from last saved position going downward.
    - Stops when it reaches BARRIKADE_MIN_ID (covers back to 2023).
    - Marks complete when floor reached; can be reset via API.
    """
    DONE_KEY  = "b_done"
    CURR_KEY  = "b_curr_id"   # current ID (counts down)

    if meta_get(DONE_KEY):
        # Historical complete — just do a live sweep of latest 60 IDs
        log.info("barrikade: historical done, live sweep only")
        try:
            max_id = barrikade_find_max_id()
            saved_max = int(meta_get("b_max_id") or 0)
            if max_id <= saved_max:
                log.info("barrikade: no new articles")
                return 0
            meta_set("b_max_id", max_id)
            start = max_id
            stop  = max(saved_max, max_id - 60)
        except Exception as e:
            log.error(f"barrikade live sweep setup: {e}")
            return 0
    else:
        # Historical in progress
        if meta_get(CURR_KEY) is None:
            # Very first run: initialise
            max_id = barrikade_find_max_id()
            meta_set("b_max_id", max_id)
            meta_set(CURR_KEY, max_id)
            log.info(f"barrikade: first run, max_id={max_id}")
        start = int(meta_get(CURR_KEY))
        stop  = max(BARRIKADE_MIN_ID, start - BARRIKADE_BATCH)

    log.info(f"barrikade: scanning IDs {start} → {stop}")
    inserted    = 0
    consecutive_miss = 0

    for art_id in range(start, stop - 1, -1):
        url = f"https://barrikade.info/article/{art_id}"
        try:
            text = get_text(url)
            if len(text) < 60:
                consecutive_miss += 1
                # 50 consecutive empty = we've gone past the beginning
                if consecutive_miss >= 50:
                    log.info(f"barrikade: 50 consecutive misses at {art_id}, marking done")
                    meta_set(DONE_KEY, datetime.now().isoformat())
                    return inserted
                time.sleep(0.25)
                continue
            consecutive_miss = 0

            h = chash(url, text)
            if seen(h):
                time.sleep(0.15)
                continue

            # NO keyword pre-filter — every article goes to Grok
            ai = classify(text, mode="loose")
            if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
                if save(ai, text, "barrikade.info", url, date_from_url(url)):
                    inserted += 1
                    log.info(f"  barrikade +{inserted} id={art_id}: "
                             f"{ai['kategorie']} / {ai['ort']}")
            time.sleep(0.55)

        except requests.HTTPError as e:
            sc = e.response.status_code
            if sc == 404:
                consecutive_miss += 1
                time.sleep(0.2)
            else:
                log.warning(f"barrikade id={art_id} HTTP {sc}")
                time.sleep(2)
        except Exception as e:
            log.warning(f"barrikade id={art_id}: {e}")
            time.sleep(0.5)

    # Save progress
    meta_set(CURR_KEY, stop - 1)
    if stop <= BARRIKADE_MIN_ID:
        meta_set(DONE_KEY, datetime.now().isoformat())
        log.info("barrikade: historical COMPLETE (reached 2023 floor)")
    else:
        log.info(f"barrikade: batch done, next from {stop-1}")

    log.info(f"barrikade: +{inserted} this run")
    return inserted

# ─────────────────────────────────────────────────────────────────
# DE.INDYMEDIA.ORG
#
# Index pagination via ?limit=20&offset=N
# We iterate until we've found all articles back to 2023
# or until no more links appear.
# ─────────────────────────────────────────────────────────────────
INDYMEDIA_MAX_OFFSET = 3000   # ~3000 * 20 = 60 000 candidate links max
INDYMEDIA_BATCH      = 40     # offset steps per crawl run

def indymedia_links_at(offset):
    """Return article links from one indymedia index page."""
    urls = [
        f"https://de.indymedia.org/?limit=20&offset={offset}",
        f"https://de.indymedia.org/index.html?limit=20&offset={offset}",
    ]
    for idx_url in urls:
        try:
            html = fetch(idx_url)
            soup = BeautifulSoup(html, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or any(x in href for x in
                        ["#","mailto:","javascript:","?",".css",".js",".png",".jpg"]):
                    continue
                full = urljoin("https://de.indymedia.org", href)
                if "indymedia.org" not in full:
                    continue
                path = full.replace("https://de.indymedia.org","").strip("/")
                if path and path not in ("impressum","about","contact","rss"):
                    links.append(full)
            if links:
                return list(dict.fromkeys(links))
        except Exception as e:
            log.warning(f"indymedia offset={offset} ({idx_url}): {e}")
    return []

def scrape_indymedia():
    DONE_KEY  = "im_done"
    CURR_KEY  = "im_offset"

    if meta_get(DONE_KEY):
        # Historical done — just scrape front page for fresh articles
        log.info("indymedia: historical done, front page only")
        links = indymedia_links_at(0)
        inserted = 0
        for url in links[:25]:
            text = get_text(url)
            if len(text) < 60: continue
            h = chash(url, text)
            if seen(h): continue
            ai = classify(text, mode="loose")
            if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
                if save(ai, text, "de.indymedia.org", url, date_from_url(url)):
                    inserted += 1
                    log.info(f"  indymedia live +{inserted}: {ai['kategorie']} / {ai['ort']}")
            time.sleep(0.6)
        log.info(f"indymedia live: +{inserted}")
        return inserted

    start_offset = int(meta_get(CURR_KEY) or 0)
    end_offset   = start_offset + INDYMEDIA_BATCH * 20  # step=20 per page
    log.info(f"indymedia: offsets {start_offset} → {end_offset}")

    inserted       = 0
    empty_streak   = 0

    for offset in range(start_offset, end_offset, 20):
        links = indymedia_links_at(offset)
        if not links:
            empty_streak += 1
            log.info(f"indymedia: empty at offset={offset} (streak={empty_streak})")
            if empty_streak >= 6:
                log.info("indymedia: too many empty pages — marking done")
                meta_set(DONE_KEY, datetime.now().isoformat())
                return inserted
            time.sleep(1.5)
            continue
        empty_streak = 0

        for url in links[:18]:
            text = get_text(url)
            if len(text) < 60: continue
            h = chash(url, text)
            if seen(h): continue
            ai = classify(text, mode="loose")
            if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
                if save(ai, text, "de.indymedia.org", url, date_from_url(url)):
                    inserted += 1
                    log.info(f"  indymedia +{inserted} off={offset}: "
                             f"{ai['kategorie']} / {ai['ort']}")
            time.sleep(0.65)

        meta_set(CURR_KEY, offset + 20)
        time.sleep(1.0)

        if offset + 20 >= INDYMEDIA_MAX_OFFSET:
            meta_set(DONE_KEY, datetime.now().isoformat())
            log.info("indymedia: reached max offset — done")
            break

    log.info(f"indymedia: +{inserted} this run")
    return inserted

# ─────────────────────────────────────────────────────────────────
# RSS MAINSTREAM (21 German-language outlets)
# ─────────────────────────────────────────────────────────────────
RSS_FEEDS = [
    # Germany
    ("tagesschau.de",       "https://www.tagesschau.de/xml/rss2/"),
    ("spiegel.de",          "https://www.spiegel.de/schlagzeilen/index.rss"),
    ("zeit.de",             "https://newsfeed.zeit.de/politik/index"),
    ("sueddeutsche.de",     "https://rss.sueddeutsche.de/rss/Politik"),
    ("welt.de",             "https://www.welt.de/feeds/topnews.rss"),
    ("faz.net",             "https://www.faz.net/rss/aktuell/"),
    ("tagesspiegel.de",     "https://www.tagesspiegel.de/contentexport/feed/home"),
    ("berliner-zeitung.de", "https://www.berliner-zeitung.de/feed.xml"),
    ("rbb24.de",            "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("ndr.de",              "https://www.ndr.de/nachrichten/index-rss.xml"),
    ("mdr.de",              "https://www.mdr.de/nachrichten/rss-nachrichten100.xml"),
    ("focus.de",            "https://rss.focus.de/fol/News/news_schlagzeilen.xml"),
    # Switzerland
    ("srf.ch",              "https://www.srf.ch/news/bnf/rss/1646"),
    ("nzz.ch",              "https://www.nzz.ch/recent.rss"),
    ("20min.ch",            "https://api.20min.ch/rss/view/1"),
    ("watson.ch",           "https://www.watson.ch/api/feeds/rss/schweiz"),
    ("blick.ch",            "https://www.blick.ch/news/rss.xml"),
    # Austria
    ("orf.at",              "https://rss.orf.at/news.xml"),
    ("derstandard.at",      "https://www.derstandard.at/rss/inland"),
    ("krone.at",            "https://www.krone.at/feed/news"),
    ("diepresse.com",       "https://www.diepresse.com/rss/politik"),
]

GOOGLE_NEWS_QUERIES = [
    # DACH violence / extremism searches
    ("DE", "linksextremismus brandanschlag"),
    ("DE", "linksradikal anschlag deutschland"),
    ("DE", "autonome angriff sachbeschädigung"),
    ("DE", "antifa gewalt"),
    ("DE", "schwarzer block randalen"),
    ("DE", "rigaer strasse angriff berlin"),
    ("DE", "bekennerschreiben linksextrem"),
    ("DE", "militante linke aktion"),
    ("DE", "linksextrem sabotage"),
    ("CH", "linksextrem anschlag schweiz"),
    ("CH", "autonome zürich brandanschlag"),
    ("CH", "militante linke bern zürich"),
    ("CH", "linksradikal schweiz sabotage"),
    ("AT", "linksextremismus anschlag österreich"),
    ("AT", "autonome wien sabotage"),
    ("AT", "linksradikal angriff österreich"),
]

# Loose keyword pre-filter for RSS headlines (just needs one match
# to forward to Grok — keeps Grok calls focused)
RSS_SIGNAL_WORDS = {
    "linksextrem","linksradikal","autonom","antifa","black bloc","schwarzer block",
    "brandanschlag","sabotage","molotow","farbbeutel","militant","barrikade",
    "bekennerschreiben","besetzung","rigaer","anarchi","brandsatz","in brand",
    "sachbeschädigung","anschlag","attacke","angriff auf","randal","krawalle",
    "kundgebung","vermumm","vermummt",
}

def rss_parse(xml):
    items = []
    try:
        root = ET.fromstring(xml)
        for item in root.iter("item"):
            t = (item.findtext("title") or "").strip()
            l = (item.findtext("link") or "").strip()
            d = (item.findtext("description") or "").strip()
            p = (item.findtext("pubDate") or "").strip()
            if l:
                items.append((t, l, d, p))
        if not items:
            # Atom fallback
            NS = "http://www.w3.org/2005/Atom"
            for entry in root.iter(f"{{{NS}}}entry"):
                t = (entry.findtext(f"{{{NS}}}title") or "").strip()
                le = entry.find(f"{{{NS}}}link")
                l  = (le.get("href","") if le is not None else "").strip()
                d  = (entry.findtext(f"{{{NS}}}summary") or "").strip()
                p  = (entry.findtext(f"{{{NS}}}updated") or "").strip()
                if l:
                    items.append((t, l, d, p))
    except Exception as e:
        log.warning(f"rss_parse: {e}")
    return items

def rss_parse_date(s):
    if not s: return None
    for fmt in (
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None

def rss_headline_relevant(title, desc):
    combined = (title + " " + desc).lower()
    return any(kw in combined for kw in RSS_SIGNAL_WORDS)

def scrape_rss():
    log.info("RSS scrape ...")
    total = 0
    for name, feed_url in RSS_FEEDS:
        try:
            xml   = fetch(feed_url, timeout=15)
            items = rss_parse(xml)
            hits  = 0
            for title, link, desc, pub in items:
                if hits >= 10:
                    break
                if not rss_headline_relevant(title, desc):
                    continue
                hits += 1
                text = get_text(link)
                if len(text) < 150:
                    continue
                h = chash(link, text)
                if seen(h):
                    continue
                ai = classify(text, mode="strict")
                if (ai and ai.get("relevant") and
                        ai.get("kategorie") not in ("Unklassifiziert","Sonstiges")):
                    d = rss_parse_date(pub) or date_from_url(link)
                    if save(ai, text, name, link, d):
                        total += 1
                        log.info(f"  RSS {name} +1: {ai['kategorie']} / {ai['ort']}")
                time.sleep(0.5)
        except Exception as e:
            log.warning(f"RSS {name}: {e}")
        time.sleep(0.3)
    log.info(f"RSS total: +{total}")
    return total

def scrape_gnews():
    log.info("Google News scrape ...")
    total = 0
    for country, q in GOOGLE_NEWS_QUERIES:
        url = (f"https://news.google.com/rss/search"
               f"?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de")
        try:
            xml   = fetch(url, timeout=15)
            items = rss_parse(xml)
            hits  = 0
            for title, link, desc, pub in items:
                if hits >= 6:
                    break
                if not rss_headline_relevant(title, desc):
                    continue
                hits += 1
                text = get_text(link)
                if len(text) < 150:
                    continue
                h = chash(link, text)
                if seen(h):
                    continue
                ai = classify(text, mode="strict")
                if (ai and ai.get("relevant") and
                        ai.get("kategorie") not in ("Unklassifiziert","Sonstiges")):
                    src = link.split("/")[2] if "://" in link else "news"
                    d   = rss_parse_date(pub) or date_from_url(link)
                    if save(ai, text, src, link, d):
                        total += 1
                        log.info(f"  GNews [{country}] +1: {ai['kategorie']} / {ai['ort']}")
                time.sleep(0.8)
        except Exception as e:
            log.warning(f"GNews '{q}': {e}")
        time.sleep(0.4)
    log.info(f"GNews total: +{total}")
    return total

# ─────────────────────────────────────────────────────────────────
# MASTER CRAWLER
# ─────────────────────────────────────────────────────────────────
_running = [False]

def should_run():
    last = meta_get("last_crawl")
    if not last: return True
    return datetime.now() - datetime.fromisoformat(last) > timedelta(hours=6)

def run_crawler(force=False):
    if _running[0]:
        log.info("Crawler already active, skipping")
        return
    if not force and not should_run():
        log.info("Crawler: skipped (< 6h since last run)")
        return

    _running[0] = True
    log.info("══════════ CRAWLER START ══════════")
    try:
        scrape_barrikade()       # numeric ID iteration, 2023→present
        scrape_indymedia()       # offset pagination, 2023→present
        scrape_rss()             # 21 DACH mainstream outlets
        scrape_gnews()           # 16 DACH-targeted Google News queries
    except Exception as e:
        log.error(f"run_crawler: {e}", exc_info=True)
    finally:
        _running[0] = False
        meta_set("last_crawl", datetime.now().isoformat())
    log.info("══════════ CRAWLER DONE ══════════")

# ─────────────────────────────────────────────────────────────────
# FASTAPI
# ─────────────────────────────────────────────────────────────────
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute(
        "SELECT id,date,location,country,category,description,url,lat,lon "
        "FROM incidents ORDER BY date DESC, timestamp DESC"
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/api/stats")
async def get_stats():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    by_country = [dict(r) for r in db.execute(
        "SELECT country, COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC"
    ).fetchall()]
    by_cat = [dict(r) for r in db.execute(
        "SELECT category, COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC"
    ).fetchall()]
    by_source = [dict(r) for r in db.execute(
        "SELECT source, COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC"
    ).fetchall()]
    # Progress info
    b_done  = bool(meta_get("b_done"))
    b_curr  = meta_get("b_curr_id")
    b_max   = meta_get("b_max_id")
    im_done = bool(meta_get("im_done"))
    im_off  = meta_get("im_offset")
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "last_crawl": meta_get("last_crawl"),
        "crawl_running": _running[0],
        "barrikade": {
            "done": b_done,
            "current_id": int(b_curr or 0),
            "max_id": int(b_max or 0),
            "floor_id": BARRIKADE_MIN_ID,
        },
        "indymedia": {
            "done": im_done,
            "current_offset": int(im_off or 0),
        },
        "by_country": by_country,
        "by_cat":     by_cat,
        "by_source":  by_source,
    })

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "gestartet"})

@app.post("/api/reset-historical")
async def reset_historical(bg: BackgroundTasks):
    for k in ("b_done","b_curr_id","b_max_id","im_done","im_offset"):
        meta_del(k)
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "historisch zurückgesetzt — crawl läuft"})

@app.post("/api/clear")
async def clear_all():
    db.execute("DELETE FROM incidents")
    db.execute("DELETE FROM metadata")
    db.commit()
    return JSONResponse({"status": "cleared"})

@app.post("/api/grok-test")
async def grok_test():
    # Test both modes
    loose  = classify(
        "Heute Nacht wurden in Zürich zwei Fahrzeuge der Polizei in Brand gesetzt. "
        "Ein Bekennerschreiben einer autonomen Gruppe lag vor.", mode="loose")
    strict = classify(
        "Linksradikale Gruppe verübt Sabotageakt an Bahnstrecke bei Hamburg.", mode="strict")
    return JSONResponse({"loose": loose, "strict": strict})

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, "interval", hours=6, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=15))
    sched.start()
    log.info("LEX EUROPE v4 ready — first crawl in 15s")
