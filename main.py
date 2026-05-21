import os, logging, json, time, hashlib, re, secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin, quote_plus
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DB_PATH      = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
GROK_MODEL   = os.getenv("GROK_MODEL", "grok-4")
ADMIN_PW     = os.getenv("ADMIN_PASSWORD", "lexeurope2024")  # set on Render!
log.info(f"DB={DB_PATH}  model={GROK_MODEL}")

# ── ACTIVE ADMIN TOKENS (in-memory, expire 8h) ──────────────────
_tokens: dict[str, datetime] = {}

def issue_token() -> str:
    t = secrets.token_hex(32)
    _tokens[t] = datetime.now() + timedelta(hours=8)
    return t

def verify_token(t: str) -> bool:
    exp = _tokens.get(t)
    if exp and datetime.now() < exp:
        return True
    _tokens.pop(t, None)
    return False

security = HTTPBearer(auto_error=False)

def require_admin(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds or not verify_token(creds.credentials):
        raise HTTPException(status_code=401, detail="Nicht authorisiert")

# ── DATABASE ─────────────────────────────────────────────────────
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
        content_hash TEXT UNIQUE,
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
    db.execute("INSERT OR REPLACE INTO metadata VALUES(?,?)", (k, str(v)))
    db.commit()

# ── SESSION ──────────────────────────────────────────────────────
sess = requests.Session()
sess.headers.update({
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
    "DNT":             "1",
})

def fetch(url, timeout=20):
    r = sess.get(url, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r.text

def get_text(url):
    """Fetch URL → clean article text."""
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for t in soup(["script","style","nav","footer","header","aside","form","iframe","noscript"]):
            t.decompose()
        el = (
            soup.find("article") or
            soup.find("main") or
            soup.find(True, class_=re.compile(r"\b(article|content|post|entry|text|body|node|story|beitrag)\b", re.I)) or
            soup.body or soup
        )
        txt = el.get_text(" ", strip=True)
        return re.sub(r"\s{3,}", " ", txt)[:5000]
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
    if not location or location.strip() in ("","Unbekannt","Unknown","?"):
        return None, None
    key = f"{location.lower().strip()}|{country.lower().strip()}"
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
            headers={"User-Agent": "LEX-EUROPE/3.0"},
            timeout=10,
        )
        _last_geo[0] = time.time()
        res = r.json()
        if res:
            lat, lon = float(res[0]["lat"]), float(res[0]["lon"])
            db.execute("INSERT OR REPLACE INTO geocache VALUES(?,?,?)", (key,lat,lon))
            db.commit()
            return lat, lon
    except Exception as e:
        log.warning(f"Geocode '{location}': {e}")
    db.execute("INSERT OR REPLACE INTO geocache VALUES(?,NULL,NULL)", (key,))
    db.commit()
    return None, None

# ── GROK ─────────────────────────────────────────────────────────
CATS = ("Brandanschlag|Sabotage|Gewalt|Schmiererei|Aufruf zu Gewalt|"
        "Militante Aktion|Sachbeschädigung|Demo/Kundgebung|"
        "Besetzung|Repression|Verhaftung|Infrastrukturangriff|"
        "Sonstiges|Unklassifiziert")

def classify(text: str, mode: str = "strict") -> Optional[dict]:
    """
    mode='loose'  → barrikade / indymedia: accept any concrete event
    mode='strict' → mainstream: confirmed left-extremist act only
    """
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set")
        return None

    rule = {
        "loose": (
            "Du analysierst Texte von linken/antifaschistischen Medien (barrikade.info, indymedia).\n"
            "WICHTIG: Aktionen VON linken/antifaschistischen Gruppen GEGEN rechte Ziele "
            "(Nazis, Faschisten, Rechtsextreme, AFD, Junge Tat, Identitaere, etc.) "
            "sind IMMER relevant=true — als linke Militante Aktion / Sachbeschaedigung klassifizieren.\n"
            "Beispiele fuer relevant=true: Farbe an Nazihaus geworfen, Auto von Rechtsextremen beschaedigt, "
            "Antifa-Angriff auf rechte WG, Demo gegen Rechts, Besetzung, Verhaftung von Aktivisten, "
            "Repression gegen linke Gruppen, Sabotage, Brandstiftung, Graffiti/Schmiererei.\n"
            "relevant=false NUR: reiner Theorietext / politischer Essay ohne jedes konkrete Ereignis.\n"
            "Im Zweifel: relevant=true."
        ),
        "strict": (
            "Beschreibt der Text eine konkrete linksextreme/antifaschistische Gewalttat oder militante Aktion?\n"
            "WICHTIG: Angriffe von Linken/Antifa AUF rechte Personen/Objekte/Gruppen "
            "sind linke Aktionen — relevant=true.\n"
            "relevant=true: Tat klar beschrieben, linker/antifaschistischer Kontext erkennbar.\n"
            "relevant=false: reine Meinungen/Kommentare, kein konkreter Vorfall."
        ),
        "official": (
            "Offizielle Behoerdenmeldung.\n"
            "relevant=true wenn linksextreme Gewalt oder Aktivitaet beschrieben.\n"
            "relevant=false bei rechtsextremen, islamistischen oder anderen Themen."
        ),
    }.get(mode, "")

    prompt = (
        f"{rule}\n\n"
        f"TEXT:\n{text[:2200]}\n\n"
        "Antworte NUR mit kompaktem JSON (kein Markdown):\n"
        '{"land":"DE|AT|CH|FR|IT|GR|ES|UK|Andere",'
        f'"kategorie":"{CATS}",'
        '"ort":"Stadt oder Region",'
        '"relevant":true}'
    )

    raw = ""
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": GROK_MODEL, "messages": [{"role":"user","content":prompt}],
                  "temperature": 0.0, "max_tokens": 200},
            timeout=35,
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw).strip()
        res = json.loads(raw)
        for k, v in [("relevant",True),("ort","Unbekannt"),("land","Unbekannt"),("kategorie","Sonstiges")]:
            res.setdefault(k, v)
        log.info(f"Grok[{mode}]: {res}")
        return res
    except requests.HTTPError:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:300]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON fail: {e} raw={raw[:200]}")
    except Exception as e:
        log.error(f"Grok error: {e}")
    return None

# ── PERSISTENCE ──────────────────────────────────────────────────
def chash(url: str, text: str) -> str:
    return hashlib.sha256((url + "|" + text[:300]).encode()).hexdigest()

def seen(h: str) -> bool:
    return db.execute("SELECT 1 FROM incidents WHERE content_hash=?", (h,)).fetchone() is not None

def save_incident(ai: dict, text: str, source: str, url: str,
                  date_str: str = None, manual: int = 0) -> bool:
    h = chash(url, text)
    if seen(h):
        return False
    lat, lon = geocode(ai.get("ort",""), ai.get("land",""))
    d = date_str or datetime.now().strftime("%Y-%m-%d")
    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents
               (date,location,country,category,description,source,url,
                content_hash,lat,lon,manual,timestamp)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
            (d, ai.get("ort","Unbekannt"), ai.get("land","Unbekannt"),
             ai.get("kategorie","Sonstiges"), text[:800],
             source, url, h, lat, lon, manual),
        )
        db.commit()
        return True
    except Exception as e:
        log.warning(f"save: {e}")
        return False

# ── RSS PARSING ──────────────────────────────────────────────────
def rss_parse(xml_text: str) -> list:
    items = []
    try:
        root = ET.fromstring(xml_text)
        for item in root.iter("item"):
            t = (item.findtext("title") or "").strip()
            l = (item.findtext("link")  or "").strip()
            d = (item.findtext("description") or "").strip()
            p = (item.findtext("pubDate") or "").strip()
            if l:
                items.append((t, l, d, p))
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
        log.warning(f"rss_parse: {e}")
    return items

def rss_date(s: str) -> Optional[str]:
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

# ── RSS FEED REGISTRY ────────────────────────────────────────────
# Each entry: (source_name, feed_url, classify_mode)
# mode "loose"   → activist sites, include broad range of events
# mode "strict"  → mainstream media, only clear left-extremist acts
# mode "official"→ authorities, Verfassungsschutz / BKA / LKA

RSS_FEEDS = [

    # ── ACTIVIST (loose) ────────────────────────────────────────
    ("de.indymedia.org",   "https://de.indymedia.org/RSS/newswire.xml",              "loose"),
    ("de.indymedia.org",   "https://de.indymedia.org/RSS/features.xml",              "loose"),
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/20/all/feed",     "loose"),  # Repression
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/56/all/feed",     "loose"),  # Antifaschismus
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/671/all/feed",    "loose"),
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/6127/all/feed",   "loose"),
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/40/all/feed",     "loose"),  # Soziale Kämpfe
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/139/all/feed",    "loose"),  # Antimilitarismus
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/1/all/feed",      "loose"),  # Aktionen
    ("de.indymedia.org",   "https://de.indymedia.org/taxonomy/term/5/all/feed",      "loose"),  # Polizei
    ("barrikade.info",     "https://barrikade.info/spip.php?page=backend",           "loose"),
    ("barrikade.info",     "https://publish.barrikade.info/spip.php?page=backend",   "loose"),
    ("barrikade.info",     "https://barrikade.info/feed/atom/",                      "loose"),
    ("barrikade.info",     "https://barrikade.info/feed/",                           "loose"),

    # ── OFFICIAL / SECURITY (official) ──────────────────────────
    ("verfassungsschutz.de","https://www.verfassungsschutz.de/SiteGlobals/Functions/RSSNewsFeed/AlleMeldungen.xml","official"),
    ("bka.de",             "https://www.bka.de/SiteGlobals/Functions/RSSNewsFeed/DE/RSSNewsFeed_Pressemitteilungen.xml","official"),

    # ── GERMANY mainstream (strict) ─────────────────────────────
    ("tagesschau.de",      "https://www.tagesschau.de/xml/rss2/",                    "strict"),
    ("spiegel.de",         "https://www.spiegel.de/schlagzeilen/index.rss",          "strict"),
    ("zeit.de",            "https://newsfeed.zeit.de/politik/index",                 "strict"),
    ("sueddeutsche.de",    "https://rss.sueddeutsche.de/rss/Politik",                "strict"),
    ("welt.de",            "https://www.welt.de/feeds/topnews.rss",                  "strict"),
    ("faz.net",            "https://www.faz.net/rss/aktuell/",                       "strict"),
    ("tagesspiegel.de",    "https://www.tagesspiegel.de/contentexport/feed/home",    "strict"),
    ("deutschlandfunk.de", "https://www.deutschlandfunk.de/nachrichten-100.rss",     "strict"),
    ("deutschlandfunk.de", "https://www.deutschlandfunk.de/politik-und-gesellschaft.2290.de.rss", "strict"),
    ("focus.de",           "https://rss.focus.de/fol/News/news_schlagzeilen.xml",    "strict"),
    ("n-tv.de",            "https://www.n-tv.de/rss",                                "strict"),
    ("stern.de",           "https://www.stern.de/feed/standard/alle-nachrichten/",   "strict"),
    ("ntv.de",             "https://www.n-tv.de/rss/politik",                        "strict"),
    ("zdf.de",             "https://www.zdf.de/rss/zdf/nachrichten",                 "strict"),
    ("dw.com",             "https://rss.dw.com/rdf/rss-de-all",                      "strict"),
    ("rbb24.de",           "https://www.rbb24.de/index/rss.xml/index.xml",           "strict"),
    ("ndr.de",             "https://www.ndr.de/nachrichten/index-rss.xml",           "strict"),
    ("mdr.de",             "https://www.mdr.de/nachrichten/rss-nachrichten100.xml",  "strict"),
    ("br24.de",            "https://www.br.de/nachrichten/index.rss",                "strict"),
    ("wdr.de",             "https://www1.wdr.de/uebersicht100.feed",                 "strict"),
    ("swraktuell.de",      "https://www.swraktuell.de/aktuell/rss/swr_aktuell.xml",  "strict"),
    ("berliner-zeitung.de","https://www.berliner-zeitung.de/feed.xml",               "strict"),

    # ── SWITZERLAND (strict) ────────────────────────────────────
    ("srf.ch",             "https://www.srf.ch/news/bnf/rss/1646",                   "strict"),
    ("nzz.ch",             "https://www.nzz.ch/recent.rss",                          "strict"),
    ("20min.ch",           "https://api.20min.ch/rss/view/1",                        "strict"),
    ("blick.ch",           "https://www.blick.ch/news/rss.xml",                      "strict"),
    ("watson.ch",          "https://www.watson.ch/api/feeds/rss/schweiz",            "strict"),
    ("tagesanzeiger.ch",   "https://www.tagesanzeiger.ch/rss.html",                  "strict"),

    # ── AUSTRIA (strict) ────────────────────────────────────────
    ("orf.at",             "https://rss.orf.at/news.xml",                            "strict"),
    ("derstandard.at",     "https://www.derstandard.at/rss/inland",                  "strict"),
    ("krone.at",           "https://www.krone.at/feed/news",                         "strict"),
    ("diepresse.com",      "https://www.diepresse.com/rss/politik",                  "strict"),
    ("kurier.at",          "https://kurier.at/sitemap.xml",                          "strict"),
]

# Google News DACH search queries (RSS)
GNEWS = [
    ("DE", "linksextremismus brandanschlag"),
    ("DE", "linksradikal anschlag infrastruktur"),
    ("DE", "autonome sabotage angriff"),
    ("DE", "antifa gewalt sachbeschädigung"),
    ("DE", "schwarzer block randalen"),
    ("DE", "bekennerschreiben linksextrem"),
    ("DE", "militante linke aktion deutschland"),
    ("DE", "linksextrem infrastrukturangriff"),
    ("CH", "linksextrem anschlag schweiz"),
    ("CH", "autonome zürich bern sabotage"),
    ("CH", "linksradikal schweiz infrastruktur"),
    ("AT", "linksextremismus österreich anschlag"),
    ("AT", "autonome wien sabotage linksradikal"),
]

# Keyword pre-filter (loose: one hit = forward to Grok)
SIGNALS = {
    "linksextrem","linksradikal","autonom","antifa","black bloc","schwarzer block",
    "brandanschlag","sabotage","molotow","farbbeutel","militant","barrikade",
    "bekennerschreiben","besetzung","rigaer","anarchi","brandsatz","in brand",
    "sachbeschädigung","krawalle","randalen","vermummt","infrastrukturangriff",
    "zugstrecke gesperrt","bahnstrecke unterbrochen","sabotageakt",
    "anschlag auf","angegriffen","attackiert",
}

def headline_match(title: str, desc: str) -> bool:
    combined = (title + " " + desc).lower()
    return any(s in combined for s in SIGNALS)

# ── CRAWL ONE FEED ───────────────────────────────────────────────
def crawl_feed(name: str, url: str, mode: str, max_items: int = 15) -> int:
    inserted = 0
    try:
        xml   = fetch(url, timeout=18)
        items = rss_parse(xml)
        log.info(f"  {name} [{mode}]: {len(items)} items")
        checked = 0
        for title, link, desc, pub in items:
            if checked >= max_items:
                break
            # For loose/official: always check; for strict: require keyword
            if mode == "strict" and not headline_match(title, desc):
                continue
            checked += 1
            text = get_text(link)
            if len(text) < 100:
                continue
            h = chash(link, text)
            if seen(h):
                continue
            ai = classify(text, mode)
            if (ai and ai.get("relevant") and
                    ai.get("kategorie") not in ("Unklassifiziert",)):
                d = rss_date(pub) or date_from_url(link)
                if save_incident(ai, text, name, link, d):
                    inserted += 1
                    log.info(f"    +1 {ai['kategorie']} / {ai['ort']}")
            time.sleep(0.5)
    except Exception as e:
        log.warning(f"  feed {name} ({url}): {e}")
    return inserted

def crawl_gnews() -> int:
    inserted = 0
    for country, q in GNEWS:
        url = (f"https://news.google.com/rss/search"
               f"?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de")
        inserted += crawl_feed(f"google-news/{country}", url, "strict", max_items=6)
        time.sleep(0.4)
    return inserted

# ── MASTER CRAWLER ───────────────────────────────────────────────

# ── BARRIKADE ARTICLE-ID SCRAPER ─────────────────────────────────
# barrikade.info uses numeric IDs: /article/6493, /article/7490 etc.
# ID ~4000 ≈ start of 2023. We crawl newest → oldest in batches.

BARRIKADE_MIN_ID = 4000   # covers back to 2023
BARRIKADE_BATCH  = 300    # IDs per run

def barrikade_max_id() -> int:
    try:
        html = fetch("https://barrikade.info/", timeout=15)
        ids  = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        if ids:
            mx = max(ids)
            log.info(f"barrikade: max_id={mx}")
            return mx
    except Exception as e:
        log.warning(f"barrikade_max_id: {e}")
    return 7600

def crawl_barrikade_ids() -> int:
    DONE_K  = "b_done"
    CURR_K  = "b_curr"
    MAX_K   = "b_max"

    mx = barrikade_max_id()
    saved_mx = int(meta_get(MAX_K) or 0)
    if mx > saved_mx:
        meta_set(MAX_K, mx)

    # Always live-sweep latest 80 IDs for fresh content
    live_stop = max(saved_mx + 1, mx - 80)
    log.info(f"barrikade live sweep: {mx}→{live_stop}")
    inserted = 0
    for aid in range(mx, live_stop - 1, -1):
        url  = f"https://barrikade.info/article/{aid}"
        text = get_text(url)
        if len(text) < 80:
            time.sleep(0.2)
            continue
        h = chash(url, text)
        if seen(h):
            time.sleep(0.1)
            continue
        ai = classify(text, "loose")
        if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
            if save_incident(ai, text, "barrikade.info", url, date_from_url(url)):
                inserted += 1
                log.info(f"  barrikade live +{inserted} id={aid}: {ai['kategorie']}/{ai['ort']}")
        time.sleep(0.5)

    # Historical batch (2023 onwards)
    if not meta_get(DONE_K):
        start = int(meta_get(CURR_K) or mx)
        stop  = max(BARRIKADE_MIN_ID, start - BARRIKADE_BATCH)
        log.info(f"barrikade hist: {start}→{stop}")
        misses = 0
        for aid in range(start, stop - 1, -1):
            url  = f"https://barrikade.info/article/{aid}"
            try:
                text = get_text(url)
                if len(text) < 80:
                    misses += 1
                    if misses >= 40:
                        meta_set(DONE_K, datetime.now().isoformat())
                        break
                    time.sleep(0.2)
                    continue
                misses = 0
                h = chash(url, text)
                if seen(h):
                    time.sleep(0.1)
                    continue
                ai = classify(text, "loose")
                if ai and ai.get("relevant") and ai.get("kategorie") != "Unklassifiziert":
                    if save_incident(ai, text, "barrikade.info", url, date_from_url(url)):
                        inserted += 1
                        log.info(f"  barrikade hist +{inserted} id={aid}: {ai['kategorie']}/{ai['ort']}")
                time.sleep(0.55)
            except requests.HTTPError as e:
                if e.response.status_code == 404:
                    misses += 1
                    time.sleep(0.2)
                else:
                    time.sleep(2)
            except Exception as e:
                log.warning(f"barrikade id={aid}: {e}")
                time.sleep(0.5)

        meta_set(CURR_K, stop - 1)
        if stop <= BARRIKADE_MIN_ID:
            meta_set(DONE_K, datetime.now().isoformat())
            log.info("barrikade historical: COMPLETE")

    log.info(f"barrikade total: +{inserted}")
    return inserted

_running = [False]

def should_run() -> bool:
    last = meta_get("last_crawl")
    if not last:
        return True
    return datetime.now() - datetime.fromisoformat(last) > timedelta(hours=4)

def run_crawler(force: bool = False):
    if _running[0]:
        log.info("Crawler already running")
        return
    if not force and not should_run():
        log.info("Crawler: skipped (<4h)")
        return

    _running[0] = True
    total = 0
    log.info("══════ CRAWLER START ══════")
    try:
        total += crawl_barrikade_ids()
        for name, url, mode in RSS_FEEDS:
            total += crawl_feed(name, url, mode)
            time.sleep(0.3)
        total += crawl_gnews()
    except Exception as e:
        log.error(f"run_crawler: {e}")
    finally:
        _running[0] = False
        meta_set("last_crawl", datetime.now().isoformat())
    log.info(f"══════ CRAWLER DONE — +{total} new ══════")

# ── FASTAPI ──────────────────────────────────────────────────────
app       = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

# ── Public ───────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(req: Request):
    return templates.TemplateResponse("index.html", {"request": req})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute(
        "SELECT id,date,location,country,category,description,url,lat,lon,manual "
        "FROM incidents ORDER BY date DESC, timestamp DESC"
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/api/stats")
async def get_stats():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    manual   = db.execute("SELECT COUNT(*) FROM incidents WHERE manual=1").fetchone()[0]
    return JSONResponse({
        "total": total, "geocoded": geocoded, "manual": manual,
        "last_crawl":    meta_get("last_crawl"),
        "crawl_running": _running[0],
        "by_country": [dict(r) for r in db.execute(
            "SELECT country,COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()],
        "by_cat": [dict(r) for r in db.execute(
            "SELECT category,COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()],
        "by_source": [dict(r) for r in db.execute(
            "SELECT source,COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC").fetchall()],
    })

# ── Admin auth ───────────────────────────────────────────────────
class LoginRequest(BaseModel):
    password: str

@app.post("/api/admin/login")
async def admin_login(req: LoginRequest):
    if req.password != ADMIN_PW:
        raise HTTPException(status_code=401, detail="Falsches Passwort")
    return JSONResponse({"token": issue_token()})

@app.post("/api/admin/logout")
async def admin_logout(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds:
        _tokens.pop(creds.credentials, None)
    return JSONResponse({"ok": True})

# ── Protected admin endpoints ────────────────────────────────────
@app.post("/api/admin/crawl", dependencies=[Depends(require_admin)])
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "crawl gestartet"})

@app.post("/api/admin/clear", dependencies=[Depends(require_admin)])
async def clear_db():
    db.execute("DELETE FROM incidents")
    db.execute("DELETE FROM metadata")
    db.commit()
    return JSONResponse({"status": "cleared"})

@app.post("/api/admin/grok-test", dependencies=[Depends(require_admin)])
async def grok_test():
    res = classify(
        "Heute Nacht setzten Unbekannte in Berlin-Neukölln zwei Polizeifahrzeuge in Brand. "
        "Ein Bekennerschreiben einer militanten autonomen Gruppe wurde am Tatort gefunden.",
        mode="loose"
    )
    return JSONResponse(res or {"error": "no response"})

class ClassifyUrlRequest(BaseModel):
    url: str

@app.post("/api/admin/classify-url", dependencies=[Depends(require_admin)])
async def classify_url(req: ClassifyUrlRequest):
    """Fetch URL, classify, return result for manual review before saving."""
    text = get_text(req.url)
    if len(text) < 80:
        raise HTTPException(400, "Artikel konnte nicht geladen werden")
    ai = classify(text, mode="strict")
    if not ai:
        raise HTTPException(500, "Grok lieferte keine Antwort")
    return JSONResponse({
        "ai":      ai,
        "preview": text[:400],
        "url":     req.url,
    })

class ManualIncidentRequest(BaseModel):
    date:        str
    location:    str
    country:     str
    category:    str
    description: str
    url:         Optional[str] = ""
    source:      Optional[str] = "Manuell"

@app.post("/api/admin/incident", dependencies=[Depends(require_admin)])
async def create_manual_incident(req: ManualIncidentRequest):
    """Manually add an incident."""
    ai = {
        "land":      req.country,
        "ort":       req.location,
        "kategorie": req.category,
        "relevant":  True,
    }
    text = req.description
    url  = req.url or f"manual://{req.date}/{req.location}"
    ok   = save_incident(ai, text, req.source or "Manuell", url, req.date, manual=1)
    if not ok:
        return JSONResponse({"status": "duplicate or error"}, status_code=409)
    return JSONResponse({"status": "gespeichert"})

@app.delete("/api/admin/incident/{inc_id}", dependencies=[Depends(require_admin)])
async def delete_incident(inc_id: int):
    db.execute("DELETE FROM incidents WHERE id=?", (inc_id,))
    db.commit()
    return JSONResponse({"status": "gelöscht"})

@app.get("/api/diagnose")
async def diagnose():
    """Diagnostic endpoint — no auth required for debugging."""
    out = {}
    out["env"] = {
        "GROK_API_KEY_set": bool(os.getenv("GROK_API_KEY")),
        "GROK_API_KEY_len": len(os.getenv("GROK_API_KEY","") or ""),
        "GROK_MODEL": GROK_MODEL,
        "ADMIN_PASSWORD_set": bool(os.getenv("ADMIN_PASSWORD")),
        "DB_PATH": DB_PATH,
    }
    for test_url in ["https://barrikade.info/","https://de.indymedia.org/"]:
        try:
            html = fetch(test_url, timeout=10)
            out[test_url] = {"ok": True, "len": len(html)}
        except Exception as e:
            out[test_url] = {"ok": False, "error": str(e)}
    api_key = os.getenv("GROK_API_KEY","")
    if api_key:
        try:
            r = requests.post(
                "https://api.x.ai/v1/chat/completions",
                headers={"Authorization":f"Bearer {api_key}","Content-Type":"application/json"},
                json={"model":GROK_MODEL,"messages":[{"role":"user","content":"Antworte nur: OK"}],
                      "max_tokens":5,"temperature":0.0},
                timeout=20,
            )
            out["grok"] = {"status": r.status_code, "response": r.text[:200]}
        except Exception as e:
            out["grok"] = {"error": str(e)}
    out["db"] = {
        "incidents": db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "metadata":  [dict(r) for r in db.execute("SELECT * FROM metadata").fetchall()],
    }
    return JSONResponse(out)

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, "interval", hours=4, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=20))
    sched.start()
    log.info(f"LEX EUROPE ready — model={GROK_MODEL} — first crawl in 20s")
