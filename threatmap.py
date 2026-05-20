import os, logging, json, time, hashlib
from datetime import datetime, timedelta
from urllib.parse import urljoin

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
HEADERS_WEB = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8"
}

def classify(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt", "relevant": False}
    prompt = f"""Analysiere folgenden Text auf linksextreme Gewalttat/Aktion in Europa.
Gib NUR gültiges JSON zurück, kein Markdown.

Text: {text[:1500]}

Format: {{"land":"DE|AT|CH|FR|IT|Andere","kategorie":"Brandanschlag|Sabotage|Gewalt|Schmiererei|Aufruf zu Gewalt|Militante Aktion|Sonstiges|Unklassifiziert","ort":"Stadt oder Region","relevant":true/false}}
relevant=true nur wenn konkrete Tat/Aktion beschrieben, nicht nur Meinungsartikel."""
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

# ==================== HELPERS ====================
KEYWORDS = [
    "brandanschlag", "sabotage", "schmiererei", "graffiti", "molotow", "farbbeutel",
    "militant", "direkte aktion", "anschlag", "feuer gelegt", "blockade", "besetzung",
    "störaktion", "angriff", "attackier", "zerstör", "beschädig", "barrikade",
    "anti-repression", "linksextrem", "linksradikal", "autonome", "antifa", "schwarzer block"
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
    return any(kw in text.lower() for kw in KEYWORDS)

def fetch_url(url, timeout=20):
    r = requests.get(url, timeout=timeout, headers=HEADERS_WEB)
    r.raise_for_status()
    return r.text

def get_article_text(url):
    try:
        html = fetch_url(url)
        soup = BeautifulSoup(html, 'html.parser')
        for t in soup(['script','style','nav','footer','header','aside']):
            t.decompose()
        el = (soup.find('article') or soup.find('main') or
              soup.find('div', class_='content') or soup.find('div', class_='node'))
        return (el or soup).get_text(" ", strip=True)[:3000]
    except Exception as e:
        log.warning(f"article_text fail {url}: {e}")
        return ""

# ==================== SCRAPERS ====================
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
                if save_incident(ai, text, name, url):
                    inserted += 1
            time.sleep(0.5)
    except Exception as e:
        log.error(f"{name} fail: {e}")
    log.info(f"{name}: +{inserted} incidents")
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

def scrape_tagesanzeiger_2026():
    """Pull Tagesanzeiger articles about left-wing violence from 2026."""
    log.info("Tagesanzeiger 2026 historical scrape ...")
    inserted = 0
    candidate_urls = set()

    for term in TA_SEARCH_TERMS:
        for search_url in [
            f"https://www.tagesanzeiger.ch/suche?q={term.replace(' ','+')}&sort=Datum",
            f"https://www.tagesanzeiger.ch/suche?q={term.replace(' ','+')}+2026&sort=Datum",
        ]:
            try:
                html = fetch_url(search_url)
                soup = BeautifulSoup(html, 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    full = urljoin("https://www.tagesanzeiger.ch", href)
                    # Accept article paths
                    if any(s in full for s in ['/artikel/','/news/','/schweiz/','/politik/','/panorama/']):
                        if 'tagesanzeiger.ch' in full:
                            candidate_urls.add(full)
                log.info(f"TA search '{term}': {len(candidate_urls)} total candidates so far")
                time.sleep(1.5)
            except Exception as e:
                log.warning(f"TA search fail '{term}': {e}")

    log.info(f"Tagesanzeiger: processing {len(candidate_urls)} URLs")
    for url in list(candidate_urls)[:40]:
        try:
            text = get_article_text(url)
            if len(text) < 200 or not kwmatch(text):
                continue

            # Try to extract date from URL (TA URLs often contain /YYYY-MM-DD/)
            date_str = None
            for part in url.split('/'):
                if len(part) == 10 and part.count('-') == 2:
                    try:
                        d = datetime.strptime(part, "%Y-%m-%d")
                        if d.year == 2026:
                            date_str = part
                            break
                    except Exception:
                        pass

            # Only keep 2026 articles (if date in URL is present and not 2026, skip)
            if date_str is None:
                # No date in URL — still include, let Grok decide
                pass

            ai = classify(text)
            if ai.get("relevant") and ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                if save_incident(ai, text, "tagesanzeiger.ch", url, date_str):
                    inserted += 1
                    log.info(f"TA saved: {url}")
            time.sleep(1.0)
        except Exception as e:
            log.warning(f"TA article fail {url}: {e}")

    log.info(f"Tagesanzeiger 2026: +{inserted} incidents")
    return inserted

# ==================== MASTER CRAWLER ====================
def run_crawler(force=False):
    if not force and not should_crawl():
        log.info("Crawler: skipped (< 23h)")
        return
    log.info("===== CRAWLER START =====")
    scrape_source("de.indymedia.org", "https://de.indymedia.org/")
    scrape_source("barrikade.info", "https://barrikade.info/")
    scrape_tagesanzeiger_2026()
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
        "total": total,
        "geocoded": geocoded,
        "last_crawl": last[0] if last else None,
        "by_country": by_country,
        "by_cat": by_cat,
        "by_source": by_source,
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
