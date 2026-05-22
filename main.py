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

DB_PATH    = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
GROK_MODEL = os.getenv("GROK_MODEL", "grok-4")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "changeme")

# ── DATABASE ──────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
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
            # NO keyword filter — send everything to Grok
            ai = classify(text)
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
                ai = classify(text)
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
            ai = classify(text)
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
                    ai = classify(text)
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
async def get_incidents(country:str="", category:str="", date_from:str="", date_to:str=""):
    q = "SELECT id,date,location,country,category,description,url,lat,lon,manual,source FROM incidents WHERE 1=1"
    p = []
    if country:   q += " AND country=?";   p.append(country)
    if category:  q += " AND category=?";  p.append(category)
    if date_from: q += " AND date>=?";     p.append(date_from)
    if date_to:   q += " AND date<=?";     p.append(date_to)
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
        raise HTTPException(400, "Ungültiges JSON")
    for f in ["date","location","country","category","description"]:
        if not data.get(f):
            raise HTTPException(400, f"Pflichtfeld '{f}' fehlt")
    ai  = {"land":data["country"], "kategorie":data["category"], "ort":data["location"]}
    url = data.get("url") or f"manual-{datetime.now().isoformat()}"
    ok  = save_incident(ai, data["description"], data.get("source","Manuell"), url, data["date"], manual=True)
    return JSONResponse({"ok":ok, "message":"Gespeichert" if ok else "Bereits vorhanden"})

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

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, "interval", hours=2, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=15))
    sched.start()
    log.info(f"LEX EUROPE v6 — {len(RSS_FEEDS)} RSS + {len(GNEWS_Q)} GNews — crawl in 15s")

