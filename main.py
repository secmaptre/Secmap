import os, logging, json, time, hashlib, re, traceback
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

# ── GROK MODEL ──────────────────────────────────────────────────
# Set GROK_MODEL env var on Render to override, e.g. "grok-3"
GROK_MODEL = os.getenv("GROK_MODEL", "grok-4")
log.info(f"Grok model: {GROK_MODEL}")

# ── DATABASE ────────────────────────────────────────────────────
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

def meta_get(k):
    r = db.execute("SELECT value FROM metadata WHERE key=?", (k,)).fetchone()
    return r[0] if r else None

def meta_set(k, v):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (k, str(v)))
    db.commit()

def meta_del(k):
    db.execute("DELETE FROM metadata WHERE key=?", (k,))
    db.commit()

# ── HTTP SESSION ─────────────────────────────────────────────────
session = requests.Session()
session.headers.update({
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT":             "1",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
})

def fetch(url, timeout=25, allow_redirects=True):
    r = session.get(url, timeout=timeout, allow_redirects=allow_redirects)
    r.raise_for_status()
    return r.text

# ── TEXT EXTRACTION ──────────────────────────────────────────────
def get_text(url):
    try:
        html  = fetch(url)
        soup  = BeautifulSoup(html, "html.parser")
        for t in soup(["script","style","nav","footer","header","aside","form","iframe","noscript"]):
            t.decompose()
        el = (
            soup.find("article") or
            soup.find("main") or
            soup.find(True, class_=re.compile(r"\b(article|content|post|entry|text|body|node|story)\b", re.I)) or
            soup.find(True, id=re.compile(r"\b(article|content|main|post|text)\b", re.I)) or
            soup.body or soup
        )
        raw = el.get_text(" ", strip=True)
        raw = re.sub(r"[ \t]{3,}", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw[:5000]
    except Exception as e:
        log.warning(f"get_text {url}: {e}")
        return ""

def date_from_url(url):
    m = re.search(r"(20\d{2})[/_-](\d{1,2})[/_-](\d{1,2})", url)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None

# ── GEOCODING ────────────────────────────────────────────────────
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

# ── GROK ─────────────────────────────────────────────────────────
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
            "Entscheide ob dieser Text ein konkretes Ereignis beschreibt: "
            "Angriff, Demo, Besetzung, Verhaftung, Sabotage, Brandstiftung, "
            "Sachbeschädigung, Schmiererei, Blockade, Kundgebung, Repression o.ä.\n"
            "relevant=true wenn irgend ein konkretes Ereignis beschrieben wird.\n"
            "relevant=false NUR bei reinem Theorietext/Essay ohne jedes Ereignis."
        )
    else:
        rule = (
            "Entscheide ob dieser Bericht eine konkrete linksextreme Gewalttat "
            "oder militante Aktion in DACH beschreibt.\n"
            "relevant=true nur bei klarer Tat mit linksradikalen Tätern."
        )

    prompt = (
        f"{rule}\n\nTEXT:\n{text[:2000]}\n\n"
        "Antworte NUR mit JSON (kein Markdown):\n"
        '{"land":"DE|AT|CH|FR|IT|GR|ES|UK|Andere",'
        f'"kategorie":"{CATEGORIES}",'
        '"ort":"Stadt oder Region",'
        '"relevant":true}'
    )

    raw = ""
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": GROK_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 200
            },
            timeout=35
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw).strip()
        res = json.loads(raw)
        res.setdefault("relevant", True)
        res.setdefault("ort", "Unbekannt")
        res.setdefault("land", "Unbekannt")
        res.setdefault("kategorie", "Sonstiges")
        log.info(f"Grok[{mode}]: {res}")
        return res
    except requests.HTTPError as e:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:300]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON fail: {e} — raw={raw[:200]}")
    except Exception as e:
        log.error(f"Grok error: {e}")
    return None

# ── PERSISTENCE ──────────────────────────────────────────────────
def chash(url, text):
    return hashlib.sha256((url + "|" + text[:300]).encode()).hexdigest()

def seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE content_hash=?", (h,)).fetchone() is not None

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
               (date,location,country,category,description,source,url,content_hash,lat,lon,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
            (d, ai.get("ort","Unbekannt"), ai.get("land","Unbekannt"),
             ai.get("kategorie","Sonstiges"), text[:700], source, url, h, lat, lon)
        )
        db.commit()
        return True
    except Exception as e:
        log.warning(f"save: {e}")
        return False

# ── BARRIKADE ────────────────────────────────────────────────────
# IDs ~4000 = early 2023, ~7500 = early 2026
BARRIKADE_FLOOR = 4000
BARRIKADE_BATCH = 400

def barrikade_max_id():
    try:
        html = fetch("https://barrikade.info/")
        ids = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        if ids:
            mx = max(ids)
            log.info(f"barrikade max_id={mx}")
            return mx
    except Exception as e:
        log.warning(f"barrikade_max_id: {e}")
    return 7600

def scrape_barrikade():
    DONE = "b_done"
    CURR = "b_curr_id"

    # Always do a live sweep of latest 60 articles
    try:
        mx = barrikade_max_id()
    except:
        mx = 7600

    saved_mx = int(meta_get("b_max_id") or 0)
    if mx > saved_mx:
        meta_set("b_max_id", mx)

    # Live sweep: newest articles
    live_start = mx
    live_stop  = max(saved_mx, mx - 60)
    log.info(f"barrikade live sweep: {live_start}→{live_stop}")
    live_ins = 0
    for aid in range(live_start, live_stop - 1, -1):
        url  = f"https://barrikade.info/article/{aid}"
        text = get_text(url)
        if len(text) < 60:
            time.sleep(0.2)
            continue
        h = chash(url, text)
        if seen(h):
            time.sleep(0.15)
            continue
        ai = classify(text, "loose")
        if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
            if save(ai, text, "barrikade.info", url, date_from_url(url)):
                live_ins += 1
                log.info(f"  barrikade live +{live_ins} id={aid}: {ai['kategorie']}/{ai['ort']}")
        time.sleep(0.5)
    log.info(f"barrikade live: +{live_ins}")

    # Historical batch
    if meta_get(DONE):
        log.info("barrikade historical: complete")
        return

    if meta_get(CURR) is None:
        meta_set(CURR, mx)

    start = int(meta_get(CURR))
    stop  = max(BARRIKADE_FLOOR, start - BARRIKADE_BATCH)
    log.info(f"barrikade historical: {start}→{stop}")
    hist_ins = 0
    misses   = 0

    for aid in range(start, stop - 1, -1):
        url  = f"https://barrikade.info/article/{aid}"
        try:
            text = get_text(url)
            if len(text) < 60:
                misses += 1
                if misses >= 50:
                    log.info(f"barrikade: 50 misses at {aid}, marking done")
                    meta_set(DONE, datetime.now().isoformat())
                    return
                time.sleep(0.2)
                continue
            misses = 0
            h = chash(url, text)
            if seen(h):
                time.sleep(0.1)
                continue
            ai = classify(text, "loose")
            if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
                if save(ai, text, "barrikade.info", url, date_from_url(url)):
                    hist_ins += 1
                    log.info(f"  barrikade hist +{hist_ins} id={aid}: {ai['kategorie']}/{ai['ort']}")
            time.sleep(0.55)
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                misses += 1
                time.sleep(0.2)
            else:
                log.warning(f"barrikade id={aid} HTTP {e.response.status_code}")
                time.sleep(2)
        except Exception as e:
            log.warning(f"barrikade id={aid}: {e}")
            time.sleep(0.5)

    meta_set(CURR, stop - 1)
    if stop <= BARRIKADE_FLOOR:
        meta_set(DONE, datetime.now().isoformat())
        log.info("barrikade historical: COMPLETE")
    log.info(f"barrikade historical: +{hist_ins}")

# ── INDYMEDIA ────────────────────────────────────────────────────
INDYMEDIA_BATCH = 40

def indymedia_links(offset):
    for base in [
        f"https://de.indymedia.org/?limit=20&offset={offset}",
        f"https://de.indymedia.org/index.html?limit=20&offset={offset}",
    ]:
        try:
            html  = fetch(base)
            soup  = BeautifulSoup(html, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or any(x in href for x in ["#","mailto:","javascript:",".css",".js",".png",".jpg","?"]):
                    continue
                full = urljoin("https://de.indymedia.org", href)
                if "indymedia.org" not in full:
                    continue
                path = full.replace("https://de.indymedia.org","").strip("/")
                if path and path not in ("impressum","about","contact","rss","datenschutz"):
                    links.append(full)
            if links:
                return list(dict.fromkeys(links))
        except Exception as e:
            log.warning(f"indymedia offset={offset}: {e}")
    return []

def scrape_indymedia():
    DONE = "im_done"
    CURR = "im_offset"

    if meta_get(DONE):
        # Only scrape front page
        log.info("indymedia: historical done, live only")
        links = indymedia_links(0)
        ins = 0
        for url in links[:25]:
            text = get_text(url)
            if len(text) < 60: continue
            h = chash(url, text)
            if seen(h): continue
            ai = classify(text, "loose")
            if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
                if save(ai, text, "de.indymedia.org", url, date_from_url(url)):
                    ins += 1
                    log.info(f"  indymedia live +{ins}: {ai['kategorie']}/{ai['ort']}")
            time.sleep(0.6)
        log.info(f"indymedia live: +{ins}")
        return

    start_off = int(meta_get(CURR) or 0)
    end_off   = start_off + INDYMEDIA_BATCH * 20
    log.info(f"indymedia historical: offsets {start_off}→{end_off}")
    ins    = 0
    empty  = 0

    for off in range(start_off, end_off, 20):
        links = indymedia_links(off)
        if not links:
            empty += 1
            if empty >= 6:
                meta_set(DONE, datetime.now().isoformat())
                log.info("indymedia: done (too many empty pages)")
                return
            time.sleep(1.5)
            continue
        empty = 0
        for url in links[:18]:
            text = get_text(url)
            if len(text) < 60: continue
            h = chash(url, text)
            if seen(h): continue
            ai = classify(text, "loose")
            if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
                if save(ai, text, "de.indymedia.org", url, date_from_url(url)):
                    ins += 1
                    log.info(f"  indymedia +{ins} off={off}: {ai['kategorie']}/{ai['ort']}")
            time.sleep(0.65)
        meta_set(CURR, off + 20)
        time.sleep(1.0)

    log.info(f"indymedia historical: +{ins}")

# ── RSS + GOOGLE NEWS ────────────────────────────────────────────
RSS_FEEDS = [
    ("tagesschau.de",       "https://www.tagesschau.de/xml/rss2/"),
    ("spiegel.de",          "https://www.spiegel.de/schlagzeilen/index.rss"),
    ("zeit.de",             "https://newsfeed.zeit.de/politik/index"),
    ("sueddeutsche.de",     "https://rss.sueddeutsche.de/rss/Politik"),
    ("welt.de",             "https://www.welt.de/feeds/topnews.rss"),
    ("faz.net",             "https://www.faz.net/rss/aktuell/"),
    ("tagesspiegel.de",     "https://www.tagesspiegel.de/contentexport/feed/home"),
    ("rbb24.de",            "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("ndr.de",              "https://www.ndr.de/nachrichten/index-rss.xml"),
    ("mdr.de",              "https://www.mdr.de/nachrichten/rss-nachrichten100.xml"),
    ("srf.ch",              "https://www.srf.ch/news/bnf/rss/1646"),
    ("nzz.ch",              "https://www.nzz.ch/recent.rss"),
    ("20min.ch",            "https://api.20min.ch/rss/view/1"),
    ("blick.ch",            "https://www.blick.ch/news/rss.xml"),
    ("orf.at",              "https://rss.orf.at/news.xml"),
    ("derstandard.at",      "https://www.derstandard.at/rss/inland"),
    ("krone.at",            "https://www.krone.at/feed/news"),
    ("diepresse.com",       "https://www.diepresse.com/rss/politik"),
]

GNEWS_Q = [
    ("DE","linksextremismus brandanschlag"),
    ("DE","autonome angriff sachbeschädigung"),
    ("DE","antifa gewalt"),
    ("DE","schwarzer block randalen"),
    ("DE","bekennerschreiben linksextrem"),
    ("CH","linksextrem anschlag schweiz"),
    ("CH","autonome zürich bern brandanschlag"),
    ("AT","linksextremismus anschlag österreich"),
    ("AT","autonome wien sabotage"),
    ("DE","militante linke aktion"),
]

RSS_SIGNALS = {
    "linksextrem","linksradikal","autonom","antifa","black bloc","schwarzer block",
    "brandanschlag","sabotage","molotow","farbbeutel","militant","barrikade",
    "bekennerschreiben","besetzung","rigaer","anarchi","brandsatz","in brand",
    "sachbeschädigung","krawalle","randalen","vermummt",
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
            if l: items.append((t,l,d,p))
        if not items:
            NS = "http://www.w3.org/2005/Atom"
            for e in root.iter(f"{{{NS}}}entry"):
                t  = (e.findtext(f"{{{NS}}}title") or "").strip()
                le = e.find(f"{{{NS}}}link")
                l  = (le.get("href","") if le is not None else "").strip()
                d  = (e.findtext(f"{{{NS}}}summary") or "").strip()
                p  = (e.findtext(f"{{{NS}}}updated") or "").strip()
                if l: items.append((t,l,d,p))
    except Exception as e:
        log.warning(f"rss_parse: {e}")
    return items

def rss_date(s):
    if not s: return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z","%a, %d %b %Y %H:%M:%S GMT",
                "%a, %d %b %Y %H:%M:%S %Z","%Y-%m-%dT%H:%M:%S%z","%Y-%m-%dT%H:%M:%SZ"):
        try: return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except: pass
    return None

def headline_hit(title, desc):
    return any(kw in (title+" "+desc).lower() for kw in RSS_SIGNALS)

def scrape_rss():
    log.info("RSS scrape...")
    total = 0
    for name, url in RSS_FEEDS:
        try:
            xml   = fetch(url, timeout=15)
            items = rss_parse(xml)
            hits  = 0
            for title, link, desc, pub in items:
                if hits >= 10: break
                if not headline_hit(title, desc): continue
                hits += 1
                text = get_text(link)
                if len(text) < 150: continue
                h = chash(link, text)
                if seen(h): continue
                ai = classify(text, "strict")
                if ai and ai.get("relevant") and ai.get("kategorie") not in ("Unklassifiziert","Sonstiges"):
                    if save(ai, text, name, link, rss_date(pub) or date_from_url(link)):
                        total += 1
                        log.info(f"  RSS {name} +1: {ai['kategorie']}/{ai['ort']}")
                time.sleep(0.5)
        except Exception as e:
            log.warning(f"RSS {name}: {e}")
        time.sleep(0.3)
    log.info(f"RSS: +{total}")
    return total

def scrape_gnews():
    log.info("GNews scrape...")
    total = 0
    for country, q in GNEWS_Q:
        url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de"
        try:
            xml   = fetch(url, timeout=15)
            items = rss_parse(xml)
            hits  = 0
            for title, link, desc, pub in items:
                if hits >= 5: break
                if not headline_hit(title, desc): continue
                hits += 1
                text = get_text(link)
                if len(text) < 150: continue
                h = chash(link, text)
                if seen(h): continue
                ai = classify(text, "strict")
                if ai and ai.get("relevant") and ai.get("kategorie") not in ("Unklassifiziert","Sonstiges"):
                    src = link.split("/")[2] if "://" in link else "news"
                    if save(ai, text, src, link, rss_date(pub) or date_from_url(link)):
                        total += 1
                        log.info(f"  GNews +1: {ai['kategorie']}/{ai['ort']}")
                time.sleep(0.8)
        except Exception as e:
            log.warning(f"GNews '{q}': {e}")
        time.sleep(0.4)
    log.info(f"GNews: +{total}")
    return total

# ── MASTER CRAWLER ───────────────────────────────────────────────
_running = [False]

def should_run():
    last = meta_get("last_crawl")
    if not last: return True
    return datetime.now() - datetime.fromisoformat(last) > timedelta(hours=6)

def run_crawler(force=False):
    if _running[0]:
        log.info("Crawler already running")
        return
    if not force and not should_run():
        log.info("Crawler: skipped (<6h)")
        return
    _running[0] = True
    log.info("══════ CRAWLER START ══════")
    try:
        scrape_barrikade()
        scrape_indymedia()
        scrape_rss()
        scrape_gnews()
    except Exception as e:
        log.error(f"run_crawler: {e}\n{traceback.format_exc()}")
    finally:
        _running[0] = False
        meta_set("last_crawl", datetime.now().isoformat())
    log.info("══════ CRAWLER DONE ══════")

# ── FASTAPI ──────────────────────────────────────────────────────
app = FastAPI()
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
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "last_crawl":     meta_get("last_crawl"),
        "crawl_running":  _running[0],
        "barrikade": {
            "done":       bool(meta_get("b_done")),
            "current_id": int(meta_get("b_curr_id") or 0),
            "max_id":     int(meta_get("b_max_id") or 0),
            "floor_id":   BARRIKADE_FLOOR,
        },
        "indymedia": {
            "done":           bool(meta_get("im_done")),
            "current_offset": int(meta_get("im_offset") or 0),
        },
        "by_country": [dict(r) for r in db.execute(
            "SELECT country, COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()],
        "by_cat": [dict(r) for r in db.execute(
            "SELECT category, COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()],
        "by_source": [dict(r) for r in db.execute(
            "SELECT source, COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC").fetchall()],
    })

# ════════════════════════════════════════════════════════════
# /api/diagnose  — call this in browser to see EXACTLY what fails
# ════════════════════════════════════════════════════════════
@app.get("/api/diagnose")
async def diagnose():
    report = {}

    # 1. Env vars
    api_key = os.getenv("GROK_API_KEY","")
    report["env"] = {
        "GROK_API_KEY_set": bool(api_key),
        "GROK_API_KEY_len": len(api_key),
        "GROK_MODEL": GROK_MODEL,
        "DB_PATH": DB_PATH,
        "db_writable": os.access(os.path.dirname(DB_PATH) or ".", os.W_OK),
    }

    # 2. Barrikade fetch test
    for test_id in [7490, 6493]:
        url = f"https://barrikade.info/article/{test_id}"
        try:
            text = get_text(url)
            report[f"barrikade_{test_id}"] = {
                "ok": len(text) > 60,
                "length": len(text),
                "preview": text[:200],
            }
        except Exception as e:
            report[f"barrikade_{test_id}"] = {"ok": False, "error": str(e)}

    # 3. Barrikade homepage (find max ID)
    try:
        html = fetch("https://barrikade.info/")
        ids  = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        report["barrikade_index"] = {
            "ok": bool(ids),
            "max_id": max(ids) if ids else None,
            "id_count": len(ids),
        }
    except Exception as e:
        report["barrikade_index"] = {"ok": False, "error": str(e)}

    # 4. Indymedia fetch test
    try:
        links = indymedia_links(0)
        report["indymedia_index"] = {
            "ok": bool(links),
            "link_count": len(links),
            "sample": links[:3],
        }
    except Exception as e:
        report["indymedia_index"] = {"ok": False, "error": str(e)}

    # 5. Grok API test
    if api_key:
        try:
            r = requests.post(
                "https://api.x.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": GROK_MODEL,
                    "messages": [{"role": "user", "content": "Antworte nur mit: OK"}],
                    "max_tokens": 10,
                    "temperature": 0.0,
                },
                timeout=20
            )
            report["grok"] = {
                "ok": r.status_code == 200,
                "status_code": r.status_code,
                "response": r.json().get("choices",[{}])[0].get("message",{}).get("content","") if r.status_code == 200 else r.text[:300],
            }
        except Exception as e:
            report["grok"] = {"ok": False, "error": str(e)}
    else:
        report["grok"] = {"ok": False, "error": "GROK_API_KEY not set"}

    # 6. Full classify test
    try:
        res = classify(
            "In Zürich-Wiedikon wurden heute Nacht zwei Polizeifahrzeuge in Brand gesetzt. "
            "Ein Bekennerschreiben einer autonomen Gruppe wurde gefunden.",
            mode="loose"
        )
        report["classify_test"] = {"ok": bool(res), "result": res}
    except Exception as e:
        report["classify_test"] = {"ok": False, "error": str(e)}

    # 7. DB stats
    report["db"] = {
        "incidents": db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "geocache":  db.execute("SELECT COUNT(*) FROM geocache").fetchone()[0],
        "metadata":  [dict(r) for r in db.execute("SELECT * FROM metadata").fetchall()],
    }

    return JSONResponse(report)

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "gestartet"})

@app.post("/api/reset-historical")
async def reset_hist(bg: BackgroundTasks):
    for k in ("b_done","b_curr_id","b_max_id","im_done","im_offset"):
        meta_del(k)
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "reset + crawl gestartet"})

@app.post("/api/clear")
async def clear_all():
    db.execute("DELETE FROM incidents")
    db.execute("DELETE FROM metadata")
    db.commit()
    return JSONResponse({"status": "cleared"})

@app.post("/api/grok-test")
async def grok_test():
    res = classify(
        "Heute Nacht wurden in Zürich-Wiedikon zwei Polizeifahrzeuge in Brand gesetzt. "
        "Bekennerschreiben einer autonomen Gruppe.", mode="loose"
    )
    return JSONResponse(res or {"error": "no response"})

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, "interval", hours=6, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=15))
    sched.start()
    log.info(f"LEX EUROPE v4 ready — model={GROK_MODEL} — crawl in 15s")

