import os, logging, json, time, hashlib, re, secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin, quote_plus
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request, BackgroundTasks, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DB_PATH    = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
GROK_MODEL = os.getenv("GROK_MODEL", "grok-4")

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "changeme")
ADMIN_TOKEN_STORE: dict[str, datetime] = {}   # token → expiry

log.info(f"DB={DB_PATH}  model={GROK_MODEL}")

# ─────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        date         TEXT,
        location     TEXT,
        country      TEXT,
        category     TEXT,
        description  TEXT,
        source       TEXT,
        url          TEXT,
        hash         TEXT UNIQUE,
        lat          REAL,
        lon          REAL,
        manual       INTEGER DEFAULT 0,
        timestamp    TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS geocache  (query TEXT PRIMARY KEY, lat REAL, lon REAL)''')
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

# ─────────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────────
def make_token():
    return secrets.token_hex(32)

def verify_token(token: str) -> bool:
    if not token or token not in ADMIN_TOKEN_STORE:
        return False
    if datetime.now() > ADMIN_TOKEN_STORE[token]:
        del ADMIN_TOKEN_STORE[token]
        return False
    return True

def require_admin(request: Request):
    token = request.cookies.get("admin_token", "")
    if not verify_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token

# ─────────────────────────────────────────────────────────────────
# HTTP SESSION
# ─────────────────────────────────────────────────────────────────
session = requests.Session()
session.headers.update({
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
})

def fetch(url, timeout=25):
    r = session.get(url, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r.text

def get_article_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for t in soup(["script","style","nav","footer","header","aside","form","iframe","noscript"]):
            t.decompose()
        el = (
            soup.find("article") or
            soup.find("main") or
            soup.find(True, class_=re.compile(r"\b(article|content|post|entry|text|body|node|story)\b", re.I)) or
            soup.find(True, id=re.compile(r"\b(article|content|main|post)\b", re.I)) or
            soup.body or soup
        )
        raw = el.get_text(" ", strip=True)
        raw = re.sub(r"[ \t]{3,}", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw[:5000]
    except Exception as e:
        log.warning(f"get_article_text {url}: {e}")
        return ""

def date_from_url(url):
    m = re.search(r"(20\d{2})[/_-](\d{1,2})[/_-](\d{1,2})", url)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None

# ─────────────────────────────────────────────────────────────────
# GEOCODING
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
            headers={"User-Agent": "LEX-EUROPE-OSINT/4.0"},
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
# GROK — only classifies, never decides relevance
# Relevance is determined BEFORE calling Grok via keyword matching
# ─────────────────────────────────────────────────────────────────
CATEGORIES = [
    "Brandanschlag", "Sabotage", "Gewalt", "Schmiererei",
    "Aufruf zu Gewalt", "Militante Aktion", "Sachbeschädigung",
    "Demo/Kundgebung", "Besetzung", "Repression", "Verhaftung", "Sonstiges"
]

def classify(text: str) -> dict | None:
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return None

    cats = "|".join(CATEGORIES)
    prompt = (
        "Du bist ein Klassifikator für Sicherheitsvorfälle.\n"
        "Weise dem folgenden Text genau eine Kategorie zu, bestimme Land und Ort.\n"
        "Antworte NUR mit einem JSON-Objekt, ohne Markdown.\n\n"
        f"Text:\n{text[:2500]}\n\n"
        "Format:\n"
        f'{{"land":"DE|AT|CH|FR|IT|GR|ES|UK|Andere","kategorie":"{cats}","ort":"Stadt oder Region"}}'
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
                "max_tokens": 120
            },
            timeout=35
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw).strip()
        res = json.loads(raw)
        res.setdefault("ort", "Unbekannt")
        res.setdefault("land", "Unbekannt")
        res.setdefault("kategorie", "Sonstiges")
        log.info(f"Grok → {res}")
        return res
    except requests.HTTPError:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:300]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON: {e} raw={raw[:150]}")
    except Exception as e:
        log.error(f"Grok: {e}")
    return None

# ─────────────────────────────────────────────────────────────────
# PERSISTENCE
# ─────────────────────────────────────────────────────────────────
def mk_hash(url, text):
    return hashlib.sha256((url + "|" + text[:300]).encode()).hexdigest()

def is_seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE hash=?", (h,)).fetchone() is not None

def save_incident(ai: dict, text: str, source: str, url: str,
                  date_str: str = None, manual: bool = False) -> bool:
    h = mk_hash(url or text[:100], text)
    if is_seen(h):
        return False
    lat, lon = geocode(ai.get("ort", ""), ai.get("land", ""))
    d = date_str or datetime.now().strftime("%Y-%m-%d")
    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents
               (date,location,country,category,description,source,url,hash,lat,lon,manual,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
            (d, ai.get("ort","Unbekannt"), ai.get("land","Unbekannt"),
             ai.get("kategorie","Sonstiges"), text[:700],
             source, url, h, lat, lon, 1 if manual else 0)
        )
        db.commit()
        return True
    except Exception as e:
        log.warning(f"save_incident: {e}")
        return False

# ─────────────────────────────────────────────────────────────────
# KEYWORD FILTER  (replaces Grok as relevance gate)
# ─────────────────────────────────────────────────────────────────
KEYWORDS = [
    # Violence / attacks
    "brandanschlag","sabotage","molotow","farbbeutel","brandsatz","in brand gesetzt",
    "anschlag","sprengstoff","böller","pyrotechnik","feuer gelegt","anzünden",
    # Property damage
    "sachbeschädigung","scheibe eingeworfen","beschädigt","zerstört","verwüstet",
    "farbe geschmiert","graffiti","schmiererei","bekennerschreiben",
    # Political violence actors
    "linksextrem","linksradikal","autonom","autonome","antifa","anarchi",
    "schwarzer block","black bloc","militante","militant",
    # Actions / events
    "direkte aktion","blockade","besetzung","besetzt","hausbesetzung",
    "demo","kundgebung","störaktion","barrikade","rigaer",
    # Repression / legal
    "verhaftung","festnahme","razzia","durchsuchung","repression",
    # Infrastructure / targets
    "bahn sabotage","gleise","strommasten","kabel durchgeschnitten",
    "verfassungsschutz","extremismus","bundesverfassungsschutz",
    # DE/AT/CH specific
    "rote flora","köpi","liebig","wagenburg","infoladen",
]

def is_relevant(text: str, loose: bool = False) -> bool:
    """
    loose=True  → used for barrikade/indymedia — almost everything passes
    loose=False → used for mainstream RSS — stricter filter
    """
    t = text.lower()
    if loose:
        # For activist sources: block only obvious off-topic content
        off_topic = ["rezept", "wetter", "sport", "fussball", "bundesliga",
                     "börse", "aktien", "film", "musik", "mode", "reise"]
        if any(kw in t for kw in off_topic):
            return False
        return True  # accept everything else from activist sources
    return any(kw in t for kw in KEYWORDS)

# ─────────────────────────────────────────────────────────────────
# RSS PARSING
# ─────────────────────────────────────────────────────────────────
def parse_rss(xml_text: str) -> list[tuple]:
    """Returns list of (title, link, description, pubDate)."""
    items = []
    try:
        root = ET.fromstring(xml_text)
        # RSS 2.0
        for item in root.iter("item"):
            t = (item.findtext("title") or "").strip()
            l = (item.findtext("link") or "").strip()
            d = (item.findtext("description") or "").strip()
            p = (item.findtext("pubDate") or "").strip()
            if l:
                items.append((t, l, d, p))
        # Atom
        if not items:
            NS = "http://www.w3.org/2005/Atom"
            for e in root.iter(f"{{{NS}}}entry"):
                t  = (e.findtext(f"{{{NS}}}title") or "").strip()
                le = e.find(f"{{{NS}}}link")
                l  = (le.get("href","") if le is not None else "").strip()
                d  = (e.findtext(f"{{{NS}}}summary") or "").strip()
                p  = (e.findtext(f"{{{NS}}}updated") or "").strip()
                if l:
                    items.append((t, l, d, p))
    except Exception as e:
        log.warning(f"parse_rss: {e}")
    return items

def parse_date(s: str) -> str | None:
    if not s:
        return None
    for fmt in (
        "%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    return None

# ─────────────────────────────────────────────────────────────────
# RSS FEED LIST
# ─────────────────────────────────────────────────────────────────
RSS_FEEDS = [
    # ── INDYMEDIA ──────────────────────────────────────────────
    ("de.indymedia.org",   "https://de.indymedia.org/RSS/newswire.xml"),
    ("de.indymedia.org",   "https://de.indymedia.org/RSS/features.xml"),
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/20/all/feed"),   # Repression
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/56/all/feed"),   # Antifa
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/671/all/feed"),  # Militanz
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/100/all/feed"),  # Sabotage
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/130/all/feed"),  # Brandanschlag
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/200/all/feed"),  # Demo
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/250/all/feed"),  # Besetzung
    # ── VERFASSUNGSSCHUTZ ──────────────────────────────────────
    ("verfassungsschutz.de", "https://www.verfassungsschutz.de/SiteGlobals/Functions/RSSNewsFeed/AlleMeldungen.xml"),
    # ── ÖFFENTLICHE-RECHTLICHE DEUTSCHLAND ────────────────────
    ("tagesschau.de",      "https://www.tagesschau.de/xml/rss2/"),
    ("deutschlandfunk.de", "https://www.deutschlandfunk.de/nachrichten.rss"),
    ("deutschlandfunk.de", "https://www.deutschlandfunk.de/sicherheit.rss"),
    ("deutschlandfunk.de", "https://www.deutschlandfunk.de/inland.rss"),
    ("zdf.de",             "https://www.zdf.de/rss/zdf/nachrichten"),
    ("ndr.de",             "https://www.ndr.de/nachrichten/index-rss.xml"),
    ("mdr.de",             "https://www.mdr.de/nachrichten/rss-nachrichten100.xml"),
    ("rbb24.de",           "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("wdr.de",             "https://www1.wdr.de/nachrichten/index~rss2.xml"),
    ("br24.de",            "https://www.br.de/nachrichten/rss"),
    ("swr.de",             "https://www.swr.de/swraktuell/rss/feed.xml"),
    # ── PRINTMEDIEN DEUTSCHLAND ────────────────────────────────
    ("spiegel.de",         "https://www.spiegel.de/schlagzeilen/index.rss"),
    ("zeit.de",            "https://newsfeed.zeit.de/politik/index"),
    ("faz.net",            "https://www.faz.net/rss/aktuell/"),
    ("sueddeutsche.de",    "https://rss.sueddeutsche.de/rss/Politik"),
    ("welt.de",            "https://www.welt.de/feeds/topnews.rss"),
    ("tagesspiegel.de",    "https://www.tagesspiegel.de/contentexport/feed/home"),
    ("berliner-zeitung.de","https://www.berliner-zeitung.de/feed.xml"),
    ("taz.de",             "https://taz.de/!p4608;rss/"),
    ("junge-welt.de",      "https://www.jungewelt.de/rss.php"),
    # ── SCHWEIZ ────────────────────────────────────────────────
    ("srf.ch",             "https://www.srf.ch/news/bnf/rss/1646"),
    ("nzz.ch",             "https://www.nzz.ch/recent.rss"),
    ("20min.ch",           "https://api.20min.ch/rss/view/1"),
    ("watson.ch",          "https://www.watson.ch/api/feeds/rss/schweiz"),
    ("blick.ch",           "https://www.blick.ch/news/rss.xml"),
    ("barrikade.info",     "https://barrikade.info/feed"),
    # ── ÖSTERREICH ─────────────────────────────────────────────
    ("orf.at",             "https://rss.orf.at/news.xml"),
    ("derstandard.at",     "https://www.derstandard.at/rss/inland"),
    ("krone.at",           "https://www.krone.at/feed/news"),
    ("diepresse.com",      "https://www.diepresse.com/rss/politik"),
    ("kleinezeitung.at",   "https://www.kleinezeitung.at/storage/rss/rss.politik.xml"),
]

# Google News targeted queries for DACH left extremism
GNEWS_QUERIES = [
    ("DE", "linksextremismus anschlag infrastruktur"),
    ("DE", "linksradikal sabotage bahn"),
    ("DE", "autonome brandanschlag"),
    ("DE", "antifa gewalt sachbeschädigung"),
    ("DE", "bekennerschreiben linksextrem"),
    ("DE", "schwarzer block randalen"),
    ("DE", "militante linke aktion"),
    ("DE", "linksextrem verhaftung"),
    ("CH", "linksextrem anschlag schweiz"),
    ("CH", "autonome sabotage zürich bern"),
    ("AT", "linksextremismus österreich anschlag"),
    ("AT", "autonome wien sabotage"),
    ("DE", "bundesverfassungsschutz linksextremismus"),
    ("DE", "rigaer strasse angriff"),
]

ACTIVIST_SOURCES = {"de.indymedia.org", "barrikade.info"}

def run_feed(source_name: str, feed_url: str, max_articles: int = 12) -> int:
    is_activist = any(s in source_name for s in ACTIVIST_SOURCES)
    inserted = 0
    try:
        xml   = fetch(feed_url, timeout=18)
        items = parse_rss(xml)
        log.info(f"  {source_name}: {len(items)} items in feed")
        processed = 0
        for title, link, desc, pub in items:
            if processed >= max_articles:
                break
            preview = (title + " " + desc).lower()
            # Activist sources: much looser pre-filter
            if is_activist:
                if not is_relevant(preview, loose=True):
                    continue
            else:
                if not is_relevant(preview, loose=False):
                    continue
            processed += 1
            full_text = get_article_text(link)
            if len(full_text) < 80:
                full_text = title + ". " + desc
            if is_activist:
                if not is_relevant(full_text, loose=True):
                    continue
            else:
                if not is_relevant(full_text, loose=False):
                    continue
            h = mk_hash(link, full_text)
            if is_seen(h):
                continue
            # Classify with Grok
            ai = classify(full_text)
            if ai:
                # Activist sources: save everything
                # Mainstream: skip pure "Sonstiges"
                if is_activist or ai.get("kategorie") not in ("Sonstiges",):
                    d = parse_date(pub) or date_from_url(link)
                    if save_incident(ai, full_text, source_name, link, d):
                        inserted += 1
                        log.info(f"    ✓ {source_name}: {ai['kategorie']} / {ai['ort']}")
                else:
                    log.info(f"    – skipped Sonstiges: {source_name}")
            time.sleep(0.5)
    except Exception as e:
        log.warning(f"  feed {source_name} ({feed_url}): {e}")
    return inserted

def run_gnews() -> int:
    inserted = 0
    for country, q in GNEWS_QUERIES:
        url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de"
        inserted += run_feed(f"gnews/{q[:30]}", url, max_articles=6)
        time.sleep(0.4)
    return inserted

# ─────────────────────────────────────────────────────────────────
# MASTER CRAWLER
# ─────────────────────────────────────────────────────────────────
_running = [False]

def should_run() -> bool:
    last = meta_get("last_crawl")
    if not last:
        return True
    return datetime.now() - datetime.fromisoformat(last) > timedelta(hours=4)

def run_crawler(force: bool = False):
    if _running[0]:
        log.info("Crawler already running — skipped")
        return
    if not force and not should_run():
        log.info("Crawler: skipped (< 4h since last run)")
        return
    _running[0] = True
    total = 0
    log.info("══════ CRAWLER START ══════")
    try:
        for name, url in RSS_FEEDS:
            total += run_feed(name, url)
            time.sleep(0.3)
        total += run_gnews()
    except Exception as e:
        log.error(f"run_crawler: {e}", exc_info=True)
    finally:
        _running[0] = False
        meta_set("last_crawl", datetime.now().isoformat())
    log.info(f"══════ CRAWLER DONE — +{total} new ══════")

# ─────────────────────────────────────────────────────────────────
# FASTAPI APP
# ─────────────────────────────────────────────────────────────────
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

# ── PUBLIC ──────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute(
        "SELECT id,date,location,country,category,description,url,lat,lon,manual,source "
        "FROM incidents ORDER BY date DESC, timestamp DESC"
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/api/stats")
async def get_stats():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "last_crawl":    meta_get("last_crawl"),
        "crawl_running": _running[0],
        "by_country": [dict(r) for r in db.execute(
            "SELECT country, COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()],
        "by_cat": [dict(r) for r in db.execute(
            "SELECT category, COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()],
        "by_source": [dict(r) for r in db.execute(
            "SELECT source, COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC").fetchall()],
    })

# ── AUTH ────────────────────────────────────────────────────────
@app.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})

@app.post("/admin/login")
async def do_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = make_token()
        ADMIN_TOKEN_STORE[token] = datetime.now() + timedelta(hours=12)
        resp = RedirectResponse("/admin", status_code=302)
        resp.set_cookie("admin_token", token, httponly=True, samesite="strict", max_age=43200)
        return resp
    return templates.TemplateResponse("login.html", {"request": request, "error": "Ungültige Zugangsdaten"})

@app.get("/admin/logout")
async def do_logout(request: Request):
    token = request.cookies.get("admin_token","")
    if token in ADMIN_TOKEN_STORE:
        del ADMIN_TOKEN_STORE[token]
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie("admin_token")
    return resp

# ── ADMIN PANEL ──────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    token = request.cookies.get("admin_token","")
    if not verify_token(token):
        return RedirectResponse("/admin/login", status_code=302)
    total   = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    running = _running[0]
    last    = meta_get("last_crawl") or "—"
    recent  = [dict(r) for r in db.execute(
        "SELECT id,date,location,country,category,source FROM incidents ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()]
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "total": total, "running": running,
        "last_crawl": last, "recent": recent,
        "categories": CATEGORIES,
    })

# ── ADMIN API (protected) ────────────────────────────────────────
@app.post("/admin/api/crawl")
async def admin_crawl(bg: BackgroundTasks, _=Depends(require_admin)):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "Crawler gestartet"})

@app.post("/admin/api/stop-crawl")
async def admin_stop(_=Depends(require_admin)):
    _running[0] = False
    return JSONResponse({"status": "Crawl-Flag zurückgesetzt"})

@app.post("/admin/api/add-incident")
async def admin_add_incident(
    request: Request,
    _=Depends(require_admin)
):
    data = await request.json()
    required = ["date","location","country","category","description"]
    for f in required:
        if not data.get(f):
            raise HTTPException(400, f"Feld '{f}' fehlt")
    ai = {
        "land":      data["country"],
        "kategorie": data["category"],
        "ort":       data["location"],
    }
    text = data["description"]
    url  = data.get("url", f"manual-{datetime.now().isoformat()}")
    ok = save_incident(ai, text, data.get("source","Manuell"), url, data["date"], manual=True)
    return JSONResponse({"ok": ok, "message": "Gespeichert" if ok else "Bereits vorhanden"})

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
    return JSONResponse({"status": "Datenbank geleert"})

@app.post("/admin/api/grok-test")
async def admin_grok_test(_=Depends(require_admin)):
    res = classify(
        "Unbekannte Täter haben in der Nacht auf Samstag in Berlin-Kreuzberg "
        "mehrere Fahrzeuge der Bundespolizei in Brand gesetzt. "
        "Ein Bekennerschreiben einer militanten autonomen Gruppe wurde am Tatort hinterlassen."
    )
    return JSONResponse(res or {"error": "Keine Antwort"})

@app.get("/admin/api/status")
async def admin_status(_=Depends(require_admin)):
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    sources  = [dict(r) for r in db.execute(
        "SELECT source, COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC LIMIT 20"
    ).fetchall()]
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "crawl_running": _running[0],
        "last_crawl": meta_get("last_crawl"),
        "feed_count": len(RSS_FEEDS),
        "sources": sources,
    })

@app.get("/api/diagnose")
async def diagnose():
    report: dict = {}
    api_key = os.getenv("GROK_API_KEY","")
    report["env"] = {
        "GROK_API_KEY_set": bool(api_key),
        "GROK_API_KEY_len": len(api_key),
        "GROK_MODEL": GROK_MODEL,
        "DB_PATH": DB_PATH,
        "ADMIN_USER_set": bool(ADMIN_USER),
        "ADMIN_PASS_set": bool(ADMIN_PASS and ADMIN_PASS != "changeme"),
    }
    # Test a few feeds
    for name, url in RSS_FEEDS[:4]:
        try:
            xml   = fetch(url, timeout=10)
            items = parse_rss(xml)
            report[f"feed_{name}"] = {"ok": True, "items": len(items), "url": url}
        except Exception as e:
            report[f"feed_{name}"] = {"ok": False, "error": str(e), "url": url}
    # Grok
    if api_key:
        try:
            r = requests.post(
                "https://api.x.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": GROK_MODEL,
                      "messages": [{"role":"user","content":"Antworte nur: OK"}],
                      "max_tokens": 5, "temperature": 0.0},
                timeout=15
            )
            report["grok"] = {
                "ok": r.status_code == 200,
                "status": r.status_code,
                "response": r.json()["choices"][0]["message"]["content"] if r.status_code==200 else r.text[:200],
            }
        except Exception as e:
            report["grok"] = {"ok": False, "error": str(e)}
    report["db"] = {
        "incidents": db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
    }
    return JSONResponse(report)

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, "interval", hours=2, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=20))
    sched.start()
    log.info(f"LEX EUROPE v5 ready — {len(RSS_FEEDS)} RSS feeds + {len(GNEWS_QUERIES)} GNews queries — crawl in 20s")

# ═══════════════════════════════════════════════════════════════
# HISTORICAL CRAWL MODULE
# Runs separately from the regular RSS crawler.
# Triggered manually via /admin/api/crawl-historical
# ═══════════════════════════════════════════════════════════════

BARRIKADE_FLOOR_FULL = 1      # Go all the way back to article #1
BARRIKADE_BATCH_HIST = 300    # IDs per run (saves progress between runs)

def barrikade_max_id_current() -> int:
    try:
        html = fetch("https://barrikade.info/")
        ids  = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        return max(ids) if ids else 7600
    except Exception as e:
        log.warning(f"barrikade_max_id: {e}")
        return 7600

def historical_barrikade():
    """
    Iterate ALL barrikade.info article IDs from max down to 1.
    Saves progress in metadata so it resumes after restarts.
    """
    DONE_KEY = "hist_b_done"
    CURR_KEY = "hist_b_curr"

    if meta_get(DONE_KEY):
        log.info("barrikade historical: already complete")
        return 0

    if meta_get(CURR_KEY) is None:
        start = barrikade_max_id_current()
        meta_set("hist_b_max", start)
        meta_set(CURR_KEY, start)
        log.info(f"barrikade historical: initialised at max_id={start}")

    curr  = int(meta_get(CURR_KEY))
    stop  = max(BARRIKADE_FLOOR_FULL, curr - BARRIKADE_BATCH_HIST)
    total = int(meta_get("hist_b_max") or curr)
    pct   = round((total - curr) / max(total, 1) * 100, 1)

    log.info(f"barrikade historical: IDs {curr}→{stop}  ({pct}% done)")
    inserted = 0
    misses   = 0

    for aid in range(curr, stop - 1, -1):
        url  = f"https://barrikade.info/article/{aid}"
        try:
            text = get_article_text(url)
            if len(text) < 60:
                misses += 1
                if misses >= 60:
                    log.info(f"barrikade: 60 consecutive misses at {aid}, marking done")
                    meta_set(DONE_KEY, datetime.now().isoformat())
                    return inserted
                time.sleep(0.2)
                continue
            misses = 0
            h = mk_hash(url, text)
            if is_seen(h):
                time.sleep(0.1)
                continue
            if not is_relevant(text):
                time.sleep(0.3)
                continue
            ai = classify(text)
            if ai:
                if save_incident(ai, text, "barrikade.info", url, date_from_url(url)):
                    inserted += 1
                    log.info(f"  barrikade hist +{inserted} id={aid}: {ai['kategorie']}/{ai['ort']}")
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

    meta_set(CURR_KEY, stop - 1)
    if stop <= BARRIKADE_FLOOR_FULL:
        meta_set(DONE_KEY, datetime.now().isoformat())
        log.info("barrikade historical: COMPLETE — all articles processed")
    else:
        log.info(f"barrikade historical: batch done, resuming from {stop-1} next run")

    log.info(f"barrikade historical: +{inserted} this batch")
    return inserted


def historical_indymedia():
    """
    Iterate indymedia.org via offset pagination back through all years.
    """
    DONE_KEY = "hist_im_done"
    CURR_KEY = "hist_im_offset"

    if meta_get(DONE_KEY):
        log.info("indymedia historical: already complete")
        return 0

    start_off = int(meta_get(CURR_KEY) or 0)
    end_off   = start_off + 40 * 20   # 40 pages per batch
    log.info(f"indymedia historical: offsets {start_off}→{end_off}")
    inserted = 0
    empty    = 0

    for off in range(start_off, end_off, 20):
        links = []
        for base in [
            f"https://de.indymedia.org/?limit=20&offset={off}",
            f"https://de.indymedia.org/index.html?limit=20&offset={off}",
        ]:
            try:
                html  = fetch(base)
                soup  = BeautifulSoup(html, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if not href or any(x in href for x in ["#","mailto:","javascript:",".css",".js","?"]):
                        continue
                    full = urljoin("https://de.indymedia.org", href)
                    if "indymedia.org" not in full:
                        continue
                    path = full.replace("https://de.indymedia.org","").strip("/")
                    if path and path not in ("impressum","about","contact","rss","datenschutz"):
                        links.append(full)
                if links:
                    break
            except Exception as e:
                log.warning(f"indymedia off={off}: {e}")

        if not links:
            empty += 1
            if empty >= 8:
                meta_set(DONE_KEY, datetime.now().isoformat())
                log.info("indymedia historical: COMPLETE (8 empty pages)")
                return inserted
            time.sleep(1.5)
            continue
        empty = 0

        for url in list(dict.fromkeys(links))[:18]:
            text = get_article_text(url)
            if len(text) < 60:
                continue
            h = mk_hash(url, text)
            if is_seen(h):
                continue
            if not is_relevant(text):
                time.sleep(0.3)
                continue
            ai = classify(text)
            if ai:
                if save_incident(ai, text, "de.indymedia.org", url, date_from_url(url)):
                    inserted += 1
                    log.info(f"  indymedia hist +{inserted} off={off}: {ai['kategorie']}/{ai['ort']}")
            time.sleep(0.65)

        meta_set(CURR_KEY, off + 20)
        time.sleep(1.0)

    log.info(f"indymedia historical: +{inserted} this batch")
    return inserted


def historical_wayback(sources: list[str] = None):
    """
    Use the Wayback Machine CDX API to find archived snapshots of
    key sources and extract articles from them.
    Covers content going back to 2010+.
    """
    if sources is None:
        sources = [
            "barrikade.info",
            "de.indymedia.org",
            "linksunten.indymedia.org",   # archived, historically important
        ]

    DONE_KEY = "hist_wb_done"
    if meta_get(DONE_KEY):
        log.info("wayback historical: already complete")
        return 0

    inserted = 0
    CDX = "http://web.archive.org/cdx/search/cdx"

    for src in sources:
        log.info(f"Wayback CDX: querying {src} ...")
        try:
            # Get URLs of archived article pages, 2015–2023
            params = {
                "url":        f"{src}/*",
                "output":     "json",
                "fl":         "timestamp,original",
                "filter":     ["statuscode:200", "mimetype:text/html"],
                "from":       "20150101",
                "to":         "20231231",
                "limit":      500,
                "fastLatest": "true",
                "collapse":   "urlkey",   # deduplicate by URL
            }
            r = requests.get(CDX, params=params, timeout=30,
                             headers={"User-Agent": "LEX-EUROPE-OSINT/4.0"})
            r.raise_for_status()
            rows = r.json()
            if not rows or len(rows) < 2:
                log.info(f"Wayback {src}: no results")
                continue

            # First row is the header
            header = rows[0]
            ts_idx = header.index("timestamp")
            ur_idx = header.index("original")
            entries = rows[1:]
            log.info(f"Wayback {src}: {len(entries)} archived URLs")

            for row in entries:
                ts  = row[ts_idx]   # e.g. 20190815123045
                url = row[ur_idx]   # original URL

                # Only process article-like URLs
                if not any(x in url for x in ["/article/","/news/","/bericht/","/feature/"]):
                    if src == "barrikade.info" and "/article/" not in url:
                        continue
                    if src == "de.indymedia.org" and len(url.replace(f"http://{src}","").strip("/")) < 4:
                        continue

                h = mk_hash(url, url)  # lightweight seen-check on URL alone
                if is_seen(h):
                    continue

                # Reconstruct Wayback URL
                wb_url = f"https://web.archive.org/web/{ts}/{url}"
                try:
                    text = get_article_text(wb_url)
                    if len(text) < 80:
                        time.sleep(0.3)
                        continue
                    if not is_relevant(text):
                        time.sleep(0.3)
                        continue
                    # Parse date from timestamp
                    try:
                        d = datetime.strptime(ts[:8], "%Y%m%d").strftime("%Y-%m-%d")
                    except ValueError:
                        d = date_from_url(url)

                    ai = classify(text)
                    if ai:
                        if save_incident(ai, text, f"{src} (archiv)", url, d):
                            inserted += 1
                            log.info(f"  wayback +{inserted} {src}: {ai['kategorie']}/{ai['ort']} [{d}]")
                    time.sleep(1.2)   # Wayback rate limit: be polite
                except Exception as e:
                    log.warning(f"wayback article {wb_url}: {e}")
                    time.sleep(1.0)

        except Exception as e:
            log.error(f"Wayback CDX {src}: {e}")
        time.sleep(2.0)

    meta_set(DONE_KEY, datetime.now().isoformat())
    log.info(f"wayback historical: +{inserted} total")
    return inserted


_hist_running = [False]

def run_historical(reset: bool = False):
    """
    Full historical crawl — runs independently of the regular crawler.
    Each function saves its own progress and resumes on restart.
    """
    if _hist_running[0]:
        log.info("Historical crawler already running")
        return
    if reset:
        for k in ("hist_b_done","hist_b_curr","hist_b_max",
                  "hist_im_done","hist_im_offset","hist_wb_done"):
            meta_del(k)
        log.info("Historical progress reset")

    _hist_running[0] = True
    log.info("══════ HISTORICAL CRAWL START ══════")
    try:
        historical_barrikade()
        historical_indymedia()
        historical_wayback()
    except Exception as e:
        log.error(f"run_historical: {e}", exc_info=True)
    finally:
        _hist_running[0] = False
    log.info("══════ HISTORICAL CRAWL DONE ══════")


# ── NEW ADMIN ENDPOINTS ──────────────────────────────────────────

@app.post("/admin/api/crawl-historical")
async def start_historical(bg: BackgroundTasks, reset: bool = False, _=Depends(require_admin)):
    bg.add_task(run_historical, reset)
    return JSONResponse({"status": f"Historischer Crawl gestartet (reset={reset})"})

@app.get("/admin/api/hist-status")
async def hist_status(_=Depends(require_admin)):
    b_max  = int(meta_get("hist_b_max") or 0)
    b_curr = int(meta_get("hist_b_curr") or 0)
    b_pct  = round((b_max - b_curr) / max(b_max, 1) * 100, 1) if b_max else 0
    return JSONResponse({
        "running": _hist_running[0],
        "barrikade": {
            "done":    bool(meta_get("hist_b_done")),
            "current": b_curr,
            "max":     b_max,
            "pct":     b_pct,
        },
        "indymedia": {
            "done":   bool(meta_get("hist_im_done")),
            "offset": int(meta_get("hist_im_offset") or 0),
        },
        "wayback": {
            "done": bool(meta_get("hist_wb_done")),
        },
    })
