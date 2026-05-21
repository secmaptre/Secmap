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

HEADERS_WEB = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
}

_last_geo = [0.0]

def geocode(location, country):
    if not location or location in ("Unbekannt", "", None):
        return None, None
    key = f"{location}|{country}".lower()
    row = db.execute("SELECT lat, lon FROM geocache WHERE query=?", (key,)).fetchone()
    if row:
        return row[0], row[1]
    elapsed = time.time() - _last_geo[0]
    if elapsed < 1.3:
        time.sleep(1.3 - elapsed)
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

def classify(text, strict=True):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt", "relevant": False}

    if strict:
        relevance_rule = "relevant=true NUR wenn konkrete linksextreme Tat beschrieben (Ort, Tathergang, Täter linksradikal/autonom/antifa). Kein reiner Kommentar."
    else:
        # For barrikade/indymedia we are lenient — they only publish relevant content anyway
        relevance_rule = "relevant=true wenn irgendeine linke/autonome/antifaschistische Aktion, Demo, Angriff, Sabotage oder militante Aktion beschrieben wird. Im Zweifel true."

    prompt = f"""Analysiere diesen Text. {relevance_rule}
Gib NUR JSON zurück, kein Markdown.

Text: {text[:1800]}

Format: {{"land":"DE|AT|CH|FR|IT|GR|ES|UK|Andere","kategorie":"Brandanschlag|Sabotage|Gewalt|Schmiererei|Aufruf zu Gewalt|Militante Aktion|Sachbeschädigung|Demo/Kundgebung|Besetzung|Sonstiges|Unklassifiziert","ort":"Stadt oder Region","relevant":true/false}}"""

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
        log.error(f"Grok JSON fail: {e} — raw: {raw[:150]}")
    except Exception as e:
        log.error(f"Grok error: {e}")
    return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt", "relevant": False}

def should_crawl():
    row = db.execute("SELECT value FROM metadata WHERE key='last_crawl'").fetchone()
    if not row:
        return True
    return datetime.now() - datetime.fromisoformat(row[0]) > timedelta(hours=23)

def mark_crawled():
    db.execute("INSERT OR REPLACE INTO metadata VALUES ('last_crawl',?)", (datetime.now().isoformat(),))
    db.commit()

def historical_done(key):
    row = db.execute("SELECT value FROM metadata WHERE key=?", (f"hist_{key}",)).fetchone()
    return row is not None

def mark_historical_done(key):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (f"hist_{key}", datetime.now().isoformat()))
    db.commit()

# Broad keywords for barrikade/indymedia
KEYWORDS_LOOSE = [
    "aktion", "angriff", "demo", "kundgebung", "besetzung", "blockade",
    "sabotage", "brand", "molotow", "farbbeutel", "schmiererei", "graffiti",
    "militant", "direkte aktion", "repression", "verhaftung", "anschlag",
    "solidarität", "autonome", "antifa", "schwarzer block", "anarchi",
    "linksradikal", "linksextrem", "bekennerschreiben", "in brand",
    "beschädigung", "störaktion", "barrikade", "rigaer", "rote flora"
]

# Strict keywords for mainstream media
KEYWORDS_STRICT = [
    "brandanschlag", "sabotage", "molotow", "farbbeutel", "linksextrem",
    "linksradikal", "autonome", "antifa", "schwarzer block", "bekennerschreiben",
    "militante", "direkte aktion", "in brand gesetzt", "anschlag", "linksradikal"
]

def kwmatch(text, loose=False):
    t = text.lower()
    kws = KEYWORDS_LOOSE if loose else KEYWORDS_STRICT
    return any(kw in t for kw in kws)

def chash(text, url):
    return hashlib.sha256((url + "|" + text[:400]).encode()).hexdigest()

def seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE content_hash=?", (h,)).fetchone() is not None

def save_incident(ai, text, source, url, date_str=None):
    h = chash(text, url)
    if seen(h):
        return False
    lat, lon = geocode(ai.get("ort",""), ai.get("land",""))
    d = date_str or datetime.now().strftime("%Y-%m-%d")
    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents
               (date,location,country,category,description,source,url,content_hash,lat,lon,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
            (d, ai.get("ort","Unbekannt"), ai.get("land","Unbekannt"),
             ai.get("kategorie","Sonstiges"), text[:600], source, url, h, lat, lon)
        )
        db.commit()
        return True
    except Exception as e:
        log.warning(f"save_incident fail: {e}")
        return False

def fetch_url(url, timeout=25):
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
              soup.find('div', class_=re.compile(r'(content|article|node|story|text|body|post)', re.I)) or
              soup.find('div', id=re.compile(r'(content|article|main|post)', re.I)))
        return (el or soup).get_text(" ", strip=True)[:4000]
    except Exception as e:
        log.warning(f"article_text fail {url}: {e}")
        return ""

def extract_date(url, html=""):
    m = re.search(r'(20\d{2})[/-](\d{1,2})[/-](\d{1,2})', url)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).strftime("%Y-%m-%d")
        except Exception:
            pass
    return None

# ==================== BARRIKADE HISTORICAL ====================
def scrape_barrikade_page(page_num):
    """Scrape one page of barrikade.info and return article links."""
    if page_num == 1:
        url = "https://barrikade.info/"
    else:
        url = f"https://barrikade.info/page/{page_num}/"
    try:
        html = fetch_url(url)
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        for a in soup.find_all('a', href=True):
            href = urljoin("https://barrikade.info", a['href'])
            if 'barrikade.info' in href and href != url and href != "https://barrikade.info/":
                path = href.replace("https://barrikade.info","")
                # Article paths are typically /YYYY/MM/slug or /category/slug
                if len(path.strip('/').split('/')) >= 1 and path.strip('/'):
                    links.append(href)
        return list(dict.fromkeys(links))
    except Exception as e:
        log.warning(f"barrikade page {page_num} fail: {e}")
        return []

def scrape_barrikade_historical(max_pages=60):
    """Pull all barrikade.info articles going back through 2025."""
    if historical_done("barrikade"):
        log.info("barrikade historical: already done")
        return 0
    log.info(f"barrikade historical crawl: up to {max_pages} pages ...")
    inserted = 0
    for page_num in range(1, max_pages + 1):
        links = scrape_barrikade_page(page_num)
        if not links:
            log.info(f"barrikade: no links on page {page_num}, stopping")
            break
        log.info(f"barrikade page {page_num}: {len(links)} links")
        for url in links[:20]:
            text = get_article_text(url)
            if len(text) < 100:
                continue
            if not kwmatch(text, loose=True):
                continue
            h = chash(text, url)
            if seen(h):
                continue
            ai = classify(text, strict=False)
            if ai.get("kategorie") not in ("Unklassifiziert",):
                if save_incident(ai, text, "barrikade.info", url, extract_date(url)):
                    inserted += 1
                    log.info(f"barrikade saved #{inserted}: {url}")
            time.sleep(0.8)
        time.sleep(1.0)
    mark_historical_done("barrikade")
    log.info(f"barrikade historical: +{inserted}")
    return inserted

# ==================== INDYMEDIA HISTORICAL ====================
def scrape_indymedia_page(offset=0):
    """Scrape indymedia with offset pagination."""
    urls_tried = [
        f"https://de.indymedia.org/?limit=20&offset={offset}",
        f"https://de.indymedia.org/index.html?limit=20&offset={offset}",
        f"https://de.indymedia.org/" if offset == 0 else None,
    ]
    for url in urls_tried:
        if url is None:
            continue
        try:
            html = fetch_url(url)
            soup = BeautifulSoup(html, 'html.parser')
            links = []
            for a in soup.find_all('a', href=True):
                href = urljoin("https://de.indymedia.org", a['href'])
                if 'indymedia.org' in href and href != url:
                    path = href.replace("https://de.indymedia.org","")
                    if path.startswith('/') and len(path) > 3:
                        links.append(href)
            if links:
                return list(dict.fromkeys(links))
        except Exception as e:
            log.warning(f"indymedia offset={offset} url={url} fail: {e}")
    return []

def scrape_indymedia_historical(max_offsets=30):
    if historical_done("indymedia"):
        log.info("indymedia historical: already done")
        return 0
    log.info(f"indymedia historical crawl ...")
    inserted = 0
    for step in range(0, max_offsets * 20, 20):
        links = scrape_indymedia_page(step)
        if not links:
            log.info(f"indymedia: no links at offset {step}, stopping")
            break
        log.info(f"indymedia offset={step}: {len(links)} links")
        for url in links[:15]:
            text = get_article_text(url)
            if len(text) < 100:
                continue
            if not kwmatch(text, loose=True):
                continue
            h = chash(text, url)
            if seen(h):
                continue
            ai = classify(text, strict=False)
            if ai.get("kategorie") not in ("Unklassifiziert",):
                if save_incident(ai, text, "de.indymedia.org", url, extract_date(url)):
                    inserted += 1
                    log.info(f"indymedia saved #{inserted}: {url}")
            time.sleep(0.8)
        time.sleep(1.2)
    mark_historical_done("indymedia")
    log.info(f"indymedia historical: +{inserted}")
    return inserted

# ==================== RSS MAINSTREAM MEDIA ====================
RSS_FEEDS = [
    ("tagesschau.de",    "https://www.tagesschau.de/xml/rss2/"),
    ("spiegel.de",       "https://www.spiegel.de/schlagzeilen/index.rss"),
    ("zeit.de",          "https://newsfeed.zeit.de/politik/index"),
    ("faz.net",          "https://www.faz.net/rss/aktuell/"),
    ("sueddeutsche.de",  "https://rss.sueddeutsche.de/rss/Politik"),
    ("welt.de",          "https://www.welt.de/feeds/topnews.rss"),
    ("mdr.de",           "https://www.mdr.de/nachrichten/rss-nachrichten100.xml"),
    ("rbb24.de",         "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("ndr.de",           "https://www.ndr.de/nachrichten/index-rss.xml"),
    ("srf.ch",           "https://www.srf.ch/news/bnf/rss/1646"),
    ("nzz.ch",           "https://www.nzz.ch/recent.rss"),
    ("20min.ch",         "https://api.20min.ch/rss/view/1"),
    ("watson.ch",        "https://www.watson.ch/api/feeds/rss/schweiz"),
    ("orf.at",           "https://rss.orf.at/news.xml"),
    ("derstandard.at",   "https://www.derstandard.at/rss/inland"),
    ("krone.at",         "https://www.krone.at/feed/news"),
    ("kleinezeitung.at", "https://www.kleinezeitung.at/storage/rss/rss.politik.xml"),
    ("tagesspiegel.de",  "https://www.tagesspiegel.de/contentexport/feed/themen/politik"),
    ("berliner-zeitung.de", "https://www.berliner-zeitung.de/feed.xml"),
    ("fr.de",            "https://www.fr.de/rssfeed.rdf"),
]

GNEWS_QUERIES = [
    ("DE", "linksextremismus brandanschlag"),
    ("DE", "autonome anschlag berlin"),
    ("DE", "antifa gewalt sachbeschädigung"),
    ("DE", "militante linke aktion"),
    ("DE", "rigaer strasse angriff"),
    ("DE", "schwarzer block randalen"),
    ("CH", "linksextrem schweiz anschlag"),
    ("CH", "autonome zürich brandanschlag"),
    ("CH", "militante linke bern"),
    ("AT", "linksextremismus österreich anschlag"),
    ("AT", "autonome wien sabotage"),
    ("FR", "black bloc attaque france"),
    ("IT", "anarchici attentato italia"),
    ("GR", "anarchists attack athens"),
]

def parse_rss(xml_text):
    items = []
    try:
        root = ET.fromstring(xml_text)
        for item in root.iter('item'):
            title = (item.findtext('title') or "").strip()
            link  = (item.findtext('link') or "").strip()
            desc  = (item.findtext('description') or "").strip()
            pub   = (item.findtext('pubDate') or "").strip()
            if link:
                items.append((title, link, desc, pub))
        if not items:
            ns = {'a': 'http://www.w3.org/2005/Atom'}
            for entry in root.iter('{http://www.w3.org/2005/Atom}entry'):
                title = (entry.findtext('a:title', namespaces=ns) or "").strip()
                link_el = entry.find('a:link', namespaces=ns)
                link  = link_el.get('href','') if link_el is not None else ""
                desc  = (entry.findtext('a:summary', namespaces=ns) or "").strip()
                pub   = (entry.findtext('a:updated', namespaces=ns) or "").strip()
                if link:
                    items.append((title, link, desc, pub))
    except Exception as e:
        log.warning(f"RSS parse fail: {e}")
    return items

def parse_rss_date(s):
    if not s:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S GMT",
                "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except Exception:
            continue
    return None

# Preview keywords for RSS pre-filter (before fetching full article)
RSS_PREVIEW_KW = [
    "link","autonom","antifa","brand","sabotag","militant","anschlag","extrem",
    "barrikade","molotow","besetz","schwarzer","rigaer","anarchi","linksrad",
    "black bloc","gewalt","angriff","kundgebung","demo"
]

def scrape_rss_feeds():
    log.info("RSS scrape ...")
    inserted = 0
    for source_name, feed_url in RSS_FEEDS:
        try:
            xml = fetch_url(feed_url, timeout=15)
            items = parse_rss(xml)
            log.info(f"RSS {source_name}: {len(items)} items")
            checked = 0
            for title, link, desc, pub in items:
                if checked >= 10:
                    break
                preview = (title + " " + desc).lower()
                if not any(kw in preview for kw in RSS_PREVIEW_KW):
                    continue
                checked += 1
                text = get_article_text(link)
                if len(text) < 200 or not kwmatch(text, loose=False):
                    continue
                log.info(f"RSS {source_name} match: {link}")
                ai = classify(text, strict=True)
                if ai.get("relevant") and ai.get("kategorie") not in ("Unklassifiziert","Sonstiges"):
                    date_str = parse_rss_date(pub) or extract_date(link)
                    if save_incident(ai, text, source_name, link, date_str):
                        inserted += 1
                time.sleep(0.6)
        except Exception as e:
            log.warning(f"RSS {source_name} fail: {e}")
        time.sleep(0.3)
    log.info(f"RSS total: +{inserted}")
    return inserted

def scrape_google_news():
    log.info("Google News scrape ...")
    inserted = 0
    for country, q in GNEWS_QUERIES:
        url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de"
        try:
            xml = fetch_url(url, timeout=15)
            items = parse_rss(xml)
            log.info(f"GNews '{q}': {len(items)} items")
            checked = 0
            for title, link, desc, pub in items:
                if checked >= 6:
                    break
                preview = (title + " " + desc).lower()
                if not any(kw in preview for kw in RSS_PREVIEW_KW):
                    continue
                checked += 1
                text = get_article_text(link)
                if len(text) < 200 or not kwmatch(text, loose=False):
                    continue
                log.info(f"GNews match: {link}")
                ai = classify(text, strict=True)
                if ai.get("relevant") and ai.get("kategorie") not in ("Unklassifiziert","Sonstiges"):
                    source_host = link.split('/')[2] if '://' in link else "google-news"
                    date_str = parse_rss_date(pub) or extract_date(link)
                    if save_incident(ai, text, source_host, link, date_str):
                        inserted += 1
                time.sleep(0.8)
        except Exception as e:
            log.warning(f"GNews '{q}' fail: {e}")
        time.sleep(0.5)
    log.info(f"GNews total: +{inserted}")
    return inserted

# ==================== MASTER CRAWLER ====================
def run_crawler(force=False):
    if not force and not should_crawl():
        log.info("Crawler: skipped (< 23h)")
        return
    log.info("===== CRAWLER START =====")
    # Historical first (only runs once per deployment)
    try:
        scrape_barrikade_historical(max_pages=60)
    except Exception as e:
        log.error(f"barrikade historical: {e}")
    try:
        scrape_indymedia_historical(max_offsets=30)
    except Exception as e:
        log.error(f"indymedia historical: {e}")
    # Regular ongoing sources
    try:
        scrape_rss_feeds()
    except Exception as e:
        log.error(f"rss: {e}")
    try:
        scrape_google_news()
    except Exception as e:
        log.error(f"gnews: {e}")
    mark_crawled()
    log.info("===== CRAWLER DONE =====")

# ==================== API ====================
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute(
        "SELECT id,date,location,country,category,description,url,lat,lon FROM incidents ORDER BY date DESC, timestamp DESC"
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/api/stats")
async def get_stats():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    by_country = [dict(r) for r in db.execute("SELECT country, COUNT(*) as n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()]
    by_cat     = [dict(r) for r in db.execute("SELECT category, COUNT(*) as n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()]
    by_source  = [dict(r) for r in db.execute("SELECT source, COUNT(*) as n FROM incidents GROUP BY source ORDER BY n DESC").fetchall()]
    last = db.execute("SELECT value FROM metadata WHERE key='last_crawl'").fetchone()
    hist_b = db.execute("SELECT value FROM metadata WHERE key='hist_barrikade'").fetchone()
    hist_i = db.execute("SELECT value FROM metadata WHERE key='hist_indymedia'").fetchone()
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "last_crawl": last[0] if last else None,
        "hist_barrikade": bool(hist_b),
        "hist_indymedia": bool(hist_i),
        "by_country": by_country, "by_cat": by_cat, "by_source": by_source,
    })

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "crawl gestartet"})

@app.post("/api/crawl-historical")
async def trigger_historical(bg: BackgroundTasks):
    # Reset historical flags so it runs again
    db.execute("DELETE FROM metadata WHERE key IN ('hist_barrikade','hist_indymedia')")
    db.commit()
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "historical crawl zurückgesetzt und gestartet"})

@app.post("/api/clear")
async def clear_db():
    db.execute("DELETE FROM incidents")
    db.execute("DELETE FROM metadata")
    db.commit()
    return JSONResponse({"status": "cleared"})

@app.post("/api/grok-test")
async def grok_test():
    res = classify("Unbekannte Täter haben in der Nacht einen Brandanschlag auf ein Polizeifahrzeug in Berlin-Kreuzberg verübt. Bekennerschreiben einer militanten autonomen Gruppe wurde gefunden.", strict=True)
    return JSONResponse(res)

@app.on_event("startup")
async def startup():
    scheduler = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    scheduler.add_job(run_crawler, 'interval', hours=1, id='crawler',
                      next_run_time=datetime.now() + timedelta(seconds=15))
    scheduler.start()
    log.info("LEX EUROPE ready — crawler starts in 15s")
