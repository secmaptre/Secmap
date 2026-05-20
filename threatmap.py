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

# ==================== DATABASE ====================
DB_PATH = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
log.info(f"DB: {DB_PATH}")

def get_db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT, location TEXT, country TEXT, category TEXT,
        description TEXT, source TEXT, url TEXT,
        content_hash TEXT UNIQUE, lat REAL, lon REAL, timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS geocache (query TEXT PRIMARY KEY, lat REAL, lon REAL)''')
    c.commit()
    return c

db = get_db()

# ==================== HTTP HEADERS ====================
HEADERS_WEB = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
}

# ==================== GEOCODING ====================
_last_geo = [0.0]

def geocode(location, country):
    if not location or location in ("Unbekannt", "", None):
        return None, None
    key = f"{location}|{country}".lower()
    row = db.execute("SELECT lat, lon FROM geocache WHERE query=?", (key,)).fetchone()
    if row:
        return row[0], row[1]
    elapsed = time.time() - _last_geo[0]
    if elapsed < 1.2:
        time.sleep(1.2 - elapsed)
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": f"{location}, {country}", "format": "json", "limit": 1},
            headers={"User-Agent": "LEX-EUROPE-OSINT/2.0"},
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
        log.warning(f"Geocode fail '{location}': {e}")
    db.execute("INSERT OR REPLACE INTO geocache VALUES (?,NULL,NULL)", (key,))
    db.commit()
    return None, None

# ==================== GROK ====================
def classify(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt", "relevant": False}
    prompt = f"""Analysiere folgenden Medienbericht auf eine konkrete linksextreme/linksradikale Gewalttat oder militante Aktion in Europa.
Gib NUR gültiges JSON zurück, kein Markdown, keine Erklärung.

Text: {text[:1800]}

Format: {{"land":"DE|AT|CH|FR|IT|GR|ES|UK|Andere","kategorie":"Brandanschlag|Sabotage|Gewalt|Schmiererei|Aufruf zu Gewalt|Militante Aktion|Sachbeschädigung|Sonstiges|Unklassifiziert","ort":"Stadt oder Region","relevant":true/false}}

relevant=true NUR wenn:
- konkrete Tat/Aktion beschrieben (mit Ort, Zeit, Tathergang)
- Täter linksextrem/linksradikal/autonom/antifa zuzuordnen
- KEIN reiner Meinungsartikel/Kommentar/Hintergrundbericht ohne Tat"""
    raw = ""
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "grok-4", "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.0, "max_tokens": 250},
            timeout=30
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip().replace("```json","").replace("```","").strip()
        res = json.loads(raw)
        res.setdefault("relevant", True)
        log.info(f"Grok: {res}")
        return res
    except requests.HTTPError:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:200]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON fail: {e} — raw: {raw[:100]}")
    except Exception as e:
        log.error(f"Grok error: {e}")
    return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt", "relevant": False}

# ==================== COOLDOWN ====================
def should_crawl():
    row = db.execute("SELECT value FROM metadata WHERE key='last_crawl'").fetchone()
    if not row:
        return True
    return datetime.now() - datetime.fromisoformat(row[0]) > timedelta(hours=23)

def mark_crawled():
    db.execute("INSERT OR REPLACE INTO metadata VALUES ('last_crawl',?)", (datetime.now().isoformat(),))
    db.commit()

# ==================== KEYWORDS ====================
KEYWORDS = [
    "brandanschlag", "sabotage", "schmiererei", "graffiti", "molotow", "farbbeutel",
    "militant", "direkte aktion", "anschlag", "feuer gelegt", "blockade", "besetzung",
    "störaktion", "angriff", "attackier", "zerstör", "beschädig", "barrikade",
    "anti-repression", "linksextrem", "linksradikal", "autonome", "antifa", "schwarzer block",
    "bekennerschreiben", "brandsatz", "in brand gesetzt", "scheibe eingeworfen",
    "rigaer", "rote flora", "köpi", "anarchist", "extremlinks", "schwarzer block"
]

EXCLUDE_HINTS = [
    "rechtsextrem", "neonazi", "afd-anhänger", "rechtsradikal", "rechte szene",
    "islamist", "reichsbürger", "putin", "trump"
]

def chash(text, url):
    return hashlib.sha256((url + "|" + text[:500]).encode()).hexdigest()

def seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE content_hash=?", (h,)).fetchone() is not None

def save_incident(ai, text, source, url, date_str=None):
    h = chash(text, url)
    if seen(h):
        return False
    lat, lon = geocode(ai["ort"], ai["land"])
    d = date_str or datetime.now().strftime("%Y-%m-%d")
    db.execute(
        """INSERT OR IGNORE INTO incidents
           (date,location,country,category,description,source,url,content_hash,lat,lon,timestamp)
           VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
        (d, ai["ort"], ai["land"], ai["kategorie"], text[:500], source, url, h, lat, lon)
    )
    db.commit()
    return True

def kwmatch(text):
    t = text.lower()
    if not any(kw in t for kw in KEYWORDS):
        return False
    # Wenn fast nur rechte/andere Stichworte → skip
    left_hits = sum(1 for kw in ["linksextrem","linksradikal","autonome","antifa","militant","schwarzer block","anarchist"] if kw in t)
    right_hits = sum(1 for kw in EXCLUDE_HINTS if kw in t)
    if right_hits >= 2 and left_hits == 0:
        return False
    return True

def fetch_url(url, timeout=20):
    r = requests.get(url, timeout=timeout, headers=HEADERS_WEB)
    r.raise_for_status()
    return r.text

def get_article_text(url):
    try:
        html = fetch_url(url)
        soup = BeautifulSoup(html, 'html.parser')
        for t in soup(['script','style','nav','footer','header','aside','form','iframe']):
            t.decompose()
        el = (soup.find('article') or soup.find('main') or
              soup.find('div', class_=re.compile(r'(content|article|node|story|text|body)', re.I)))
        return (el or soup).get_text(" ", strip=True)[:4000]
    except Exception as e:
        log.warning(f"article_text fail {url}: {e}")
        return ""

def extract_date_from_url(url):
    """Extract YYYY-MM-DD or YYYY/MM/DD from URL."""
    m = re.search(r'(20\d{2})[/-](\d{1,2})[/-](\d{1,2})', url)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).strftime("%Y-%m-%d")
        except Exception:
            return None
    return None

# ==================== GENERIC SCRAPER (Indymedia/Barrikade) ====================
def scrape_source(name, base_url, max_check=15):
    log.info(f"Crawling {name} ...")
    inserted = 0
    try:
        html = fetch_url(base_url)
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if any(x in href for x in ['#','mailto:','javascript:']):
                continue
            full = urljoin(base_url, href)
            if base_url.split('/')[2] in full and full != base_url:
                links.append(full)
        links = list(dict.fromkeys(links))[:max_check * 3]
        checked = 0
        for url in links:
            if checked >= max_check:
                break
            text = get_article_text(url)
            if len(text) < 150 or not kwmatch(text):
                continue
            checked += 1
            log.info(f"{name} match: {url}")
            ai = classify(text)
            if ai.get("relevant") and ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                if save_incident(ai, text, name, url, extract_date_from_url(url)):
                    inserted += 1
            time.sleep(0.5)
    except Exception as e:
        log.error(f"{name} fail: {e}")
    log.info(f"{name}: +{inserted} incidents")
    return inserted

# ==================== RSS FEED SCRAPER ====================
RSS_FEEDS = [
    # Deutschland
    ("tagesschau.de", "https://www.tagesschau.de/inland/index~rss2.xml"),
    ("spiegel.de", "https://www.spiegel.de/politik/deutschland/index.rss"),
    ("welt.de", "https://www.welt.de/feeds/section/politik.rss"),
    ("zeit.de", "https://newsfeed.zeit.de/politik/index"),
    ("faz.net", "https://www.faz.net/rss/aktuell/politik/"),
    ("sueddeutsche.de", "https://rss.sueddeutsche.de/rss/Politik"),
    ("focus.de", "https://rss.focus.de/politik/"),
    ("rbb24.de", "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("ndr.de", "https://www.ndr.de/nachrichten/index-rss.xml"),
    # Schweiz
    ("srf.ch", "https://www.srf.ch/news/bnf/rss/1646"),
    ("nzz.ch", "https://www.nzz.ch/recent.rss"),
    ("watson.ch", "https://www.watson.ch/api/feeds/rss/schweiz"),
    ("20min.ch", "https://api.20min.ch/rss/view/1"),
    # Österreich
    ("orf.at", "https://rss.orf.at/news.xml"),
    ("derstandard.at", "https://www.derstandard.at/rss/inland"),
    ("krone.at", "https://www.krone.at/feed/news"),
]

def parse_rss(xml_text):
    """Return list of (title, link, description, pubDate)."""
    items = []
    try:
        root = ET.fromstring(xml_text)
        # RSS 2.0
        for item in root.iter('item'):
            title = (item.findtext('title') or "").strip()
            link = (item.findtext('link') or "").strip()
            desc = (item.findtext('description') or "").strip()
            pub = (item.findtext('pubDate') or "").strip()
            if link:
                items.append((title, link, desc, pub))
        # Atom fallback
        if not items:
            ns = {'a': 'http://www.w3.org/2005/Atom'}
            for entry in root.iter('{http://www.w3.org/2005/Atom}entry'):
                title = (entry.findtext('a:title', namespaces=ns) or "").strip()
                link_el = entry.find('a:link', namespaces=ns)
                link = link_el.get('href') if link_el is not None else ""
                desc = (entry.findtext('a:summary', namespaces=ns) or "").strip()
                pub = (entry.findtext('a:updated', namespaces=ns) or "").strip()
                if link:
                    items.append((title, link, desc, pub))
    except Exception as e:
        log.warning(f"RSS parse fail: {e}")
    return items

def parse_rss_date(s):
    """Try various RSS date formats → YYYY-MM-DD."""
    if not s:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S GMT",
                "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except Exception:
            continue
    return None

def scrape_rss_feeds(max_per_feed=8):
    log.info("RSS scrape ...")
    total_inserted = 0
    for source_name, feed_url in RSS_FEEDS:
        try:
            xml = fetch_url(feed_url, timeout=15)
            items = parse_rss(xml)
            log.info(f"RSS {source_name}: {len(items)} items")
            checked = 0
            for title, link, desc, pub in items:
                if checked >= max_per_feed:
                    break
                # Vorfilter auf Titel/Description (spart Article-Fetch)
                preview = (title + " " + desc).lower()
                if not any(kw in preview for kw in
                           ["link","autonom","antifa","brand","sabotag","militant","anschlag",
                            "extrem","barrikade","molotow","besetz","rigaer","schwarz"]):
                    continue
                checked += 1
                text = get_article_text(link)
                if len(text) < 200:
                    continue
                if not kwmatch(text):
                    continue
                log.info(f"RSS {source_name} match: {link}")
                ai = classify(text)
                if ai.get("relevant") and ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                    date_str = parse_rss_date(pub) or extract_date_from_url(link)
                    if save_incident(ai, text, source_name, link, date_str):
                        total_inserted += 1
                time.sleep(0.6)
        except Exception as e:
            log.warning(f"RSS {source_name} fail: {e}")
        time.sleep(0.4)
    log.info(f"RSS total: +{total_inserted}")
    return total_inserted

# ==================== GOOGLE NEWS RSS SEARCH ====================
GNEWS_QUERIES = [
    ("DE", "linksextremismus brandanschlag"),
    ("DE", "autonome anschlag deutschland"),
    ("DE", "antifa gewalt"),
    ("DE", "militante linke aktion"),
    ("CH", "linksextrem schweiz anschlag"),
    ("CH", "autonome zürich brandanschlag"),
    ("CH", "militante linke schweiz"),
    ("AT", "linksextremismus österreich"),
    ("AT", "autonome wien anschlag"),
    ("FR", "black bloc attaque France"),
    ("IT", "anarchici attentato italia"),
    ("GR", "anarchists attack greece"),
]

def scrape_google_news(max_per_query=6):
    log.info("Google News RSS scrape ...")
    inserted = 0
    for country, q in GNEWS_QUERIES:
        url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de"
        try:
            xml = fetch_url(url, timeout=15)
            items = parse_rss(xml)
            log.info(f"GNews '{q}' [{country}]: {len(items)} items")
            checked = 0
            for title, link, desc, pub in items:
                if checked >= max_per_query:
                    break
                preview = (title + " " + desc).lower()
                if not any(kw in preview for kw in
                           ["link","autonom","antifa","brand","sabotag","militant","anschlag",
                            "extrem","anarch","molotow","barrikade","black bloc"]):
                    continue
                checked += 1
                # Google News leitet weiter — Original-Link extrahieren
                real_link = link
                text = get_article_text(real_link)
                if len(text) < 200 or not kwmatch(text):
                    continue
                log.info(f"GNews match: {real_link}")
                ai = classify(text)
                if ai.get("relevant") and ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                    source_host = real_link.split('/')[2] if '://' in real_link else "google-news"
                    date_str = parse_rss_date(pub) or extract_date_from_url(real_link)
                    if save_incident(ai, text, source_host, real_link, date_str):
                        inserted += 1
                time.sleep(0.8)
        except Exception as e:
            log.warning(f"GNews '{q}' fail: {e}")
        time.sleep(0.5)
    log.info(f"Google News total: +{inserted}")
    return inserted

# ==================== TAGESANZEIGER 2026 ====================
TA_SEARCH_TERMS = [
    "linksextremismus schweiz",
    "militante linke schweiz",
    "brandanschlag schweiz",
    "sabotage linksradikal",
    "autonome anschlag",
    "linksextrem angriff",
]

def scrape_tagesanzeiger():
    log.info("Tagesanzeiger scrape ...")
    inserted = 0
    candidate_urls = set()
    for term in TA_SEARCH_TERMS:
        for search_url in [
            f"https://www.tagesanzeiger.ch/suche?q={quote_plus(term)}&sort=Datum",
        ]:
            try:
                html = fetch_url(search_url)
                soup = BeautifulSoup(html, 'html.parser')
                for a in soup.find_all('a', href=True):
                    full = urljoin("https://www.tagesanzeiger.ch", a['href'])
                    if 'tagesanzeiger.ch' in full and any(s in full for s in
                            ['/artikel/','/news/','/schweiz/','/politik/','/panorama/','/zuerich/']):
                        candidate_urls.add(full)
                time.sleep(1.5)
            except Exception as e:
                log.warning(f"TA search fail '{term}': {e}")
    log.info(f"TA: {len(candidate_urls)} URLs to process")
    for url in list(candidate_urls)[:40]:
        try:
            text = get_article_text(url)
            if len(text) < 200 or not kwmatch(text):
                continue
            ai = classify(text)
            if ai.get("relevant") and ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                if save_incident(ai, text, "tagesanzeiger.ch", url, extract_date_from_url(url)):
                    inserted += 1
                    log.info(f"TA saved: {url}")
            time.sleep(1.0)
        except Exception as e:
            log.warning(f"TA article fail {url}: {e}")
    log.info(f"Tagesanzeiger: +{inserted}")
    return inserted

# ==================== MASTER CRAWLER ====================
def run_crawler(force=False):
    if not force and not should_crawl():
        log.info("Crawler: skipped (< 23h)")
        return
    log.info("===== CRAWLER START =====")
    try:
        scrape_source("de.indymedia.org", "https://de.indymedia.org/")
    except Exception as e: log.error(f"indymedia: {e}")
    try:
        scrape_source("barrikade.info", "https://barrikade.info/")
    except Exception as e: log.error(f"barrikade: {e}")
    try:
        scrape_rss_feeds()
    except Exception as e: log.error(f"rss: {e}")
    try:
        scrape_google_news()
    except Exception as e: log.error(f"gnews: {e}")
    try:
        scrape_tagesanzeiger()
    except Exception as e: log.error(f"ta: {e}")
    mark_crawled()
    log.info("===== CRAWLER DONE =====")

# ==================== FASTAPI ====================
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute(
        "SELECT id,date,location,country,category,description,source,url,lat,lon,timestamp "
        "FROM incidents ORDER BY timestamp DESC"
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/api/stats")
async def get_stats():
    total = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    by_country = [dict(r) for r in db.execute(
        "SELECT country, COUNT(*) as n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()]
    by_cat = [dict(r) for r in db.execute(
        "SELECT category, COUNT(*) as n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()]
    by_source = [dict(r) for r in db.execute(
        "SELECT source, COUNT(*) as n FROM incidents GROUP BY source ORDER BY n DESC").fetchall()]
    last = db.execute("SELECT value FROM metadata WHERE key='last_crawl'").fetchone()
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "last_crawl": last[0] if last else None,
        "by_country": by_country, "by_cat": by_cat, "by_source": by_source,
    })

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "crawl gestartet"})

@app.post("/api/clear")
async def clear_db():
    db.execute("DELETE FROM incidents")
    db.execute("DELETE FROM metadata")
    db.commit()
    return JSONResponse({"status": "cleared"})

@app.post("/api/grok-test")
async def grok_test():
    res = classify("Unbekannte Täter haben in der Nacht einen Brandanschlag auf ein Polizeifahrzeug in Berlin-Kreuzberg verübt. Ein Bekennerschreiben einer militanten autonomen Gruppe wurde gefunden.")
    return JSONResponse(res)

@app.on_event("startup")
async def startup():
    scheduler = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    scheduler.add_job(run_crawler, 'interval', hours=1, id='crawler',
                      next_run_time=datetime.now() + timedelta(seconds=20))
    scheduler.start()
    log.info("LEX EUROPE API ready — crawler starts in 20s")
