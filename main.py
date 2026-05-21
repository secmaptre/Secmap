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
log.info(f"DB_PATH: {DB_PATH}")

# ─────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT, location TEXT, country TEXT, category TEXT,
        description TEXT, source TEXT, url TEXT, content_hash TEXT UNIQUE,
        lat REAL, lon REAL, timestamp TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS geocache (query TEXT PRIMARY KEY, lat REAL, lon REAL)''')
    conn.commit()
    return conn

db = get_db()

# ─────────────────────────────────────────────────────────────────
# HELPERS
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

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# ─────────────────────────────────────────────────────────────────
# ERWEITERTE KEYWORDS (real von Barrikade + Indymedia)
# ─────────────────────────────────────────────────────────────────
LOOSE_KEYWORDS = [
    "antifa", "antifasch", "fascho", "nazi", "nazibursche", "outing", "dox", "repression",
    "brandanschlag", "brandsatz", "sabotage", "farbbeutel", "farbe", "hammerschläge", "scherben",
    "blockade", "demo", "kundgebung", "besetzung", "verhaft", "razzia", "hausdurchsuchung",
    "solidarität", "knast", "gefangene", "aktion", "intervention", "sprayaktion", "banner",
    "polizei", "militant", "intifada", "antiimperialistisch", "queer", "feministisch", "castor",
    "verschönerungsaktion", "barrikade", "indymedia", "antirepressions"
]

# ─────────────────────────────────────────────────────────────────
# CLASSIFY
# ─────────────────────────────────────────────────────────────────
def classify(text, mode="loose", url=""):
    text_lower = text.lower()
    
    if mode == "loose":
        if any(kw in text_lower for kw in LOOSE_KEYWORDS):
            log.info(f"✅ Loose-Keyword-Filter getroffen: {url[-50:]}")
            return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "DE|AT|CH|Andere"}
        
        # Nur bei sehr cleanen Texten Grok fragen
        rule = (
            "Entscheide ob dieser Text ein reales linkes/antifaschistisches Ereignis beschreibt "
            "(Demo, Aktion, Sabotage, Repression, Outing, Besetzung, etc.). "
            "IM ZWEIFEL: relevant = true. Nur reine Theorie ohne konkrete Aktion = false."
        )
    else:
        rule = "Entscheide ob es sich um eine konkrete linksextreme Gewalttat handelt."

    prompt = f"{rule}\n\nTEXT:\n{text[:2000]}\n\nAntworte NUR mit JSON: {{\"relevant\":true, \"kategorie\":\"Sonstiges\", \"ort\":\"...\", \"land\":\"DE\"}}"

    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {os.getenv('GROK_API_KEY')}", "Content-Type": "application/json"},
            json={"model": "grok-4", "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 200},
            timeout=30
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        res = json.loads(raw)
        res.setdefault("relevant", True)
        res.setdefault("kategorie", "Sonstiges")
        res.setdefault("ort", "Unbekannt")
        res.setdefault("land", "Unbekannt")
        return res
    except Exception as e:
        log.warning(f"Grok fehlgeschlagen → Fallback relevant=true für {url[-40:]}")
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "Unbekannt"}

# ─────────────────────────────────────────────────────────────────
# SAVE + HASH
# ─────────────────────────────────────────────────────────────────
def chash(url, text):
    return hashlib.sha256((url + text[:500]).encode()).hexdigest()

def seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE content_hash=?", (h,)).fetchone() is not None

def save(ai, text, source, url, date_str=None):
    if not ai or not ai.get("relevant"):
        return False
    h = chash(url, text)
    if seen(h):
        return False

    lat, lon = None, None  # Geocode kann später nachgeholt werden
    d = date_str or datetime.now().strftime("%Y-%m-%d")
    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents 
               (date, location, country, category, description, source, url, content_hash, lat, lon, timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))""",
            (d, ai.get("ort", "Unbekannt"), ai.get("land", "Unbekannt"),
             ai.get("kategorie", "Sonstiges"), text[:800], source, url, h, lat, lon)
        )
        db.commit()
        log.info(f"✅ GESPEICHERT: {source} | {ai.get('kategorie')} | {ai.get('ort')} | {url[-40:]}")
        return True
    except Exception as e:
        log.error(f"Save-Error {url}: {e}")
        return False

# ─────────────────────────────────────────────────────────────────
# FETCH + TEXT
# ─────────────────────────────────────────────────────────────────
def fetch(url, timeout=25):
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    return r.text

def get_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside", "form", "iframe"]):
            tag.decompose()
        
        article = (soup.find("article") or soup.find("main") or 
                  soup.find(True, class_=re.compile(r"(article|content|post|entry|story|text)", re.I)) or 
                  soup.body or soup)
        text = article.get_text(separator=" ", strip=True)
        text = re.sub(r'\s+', ' ', text)
        return text[:5000]
    except Exception as e:
        log.warning(f"get_text failed {url}: {e}")
        return ""

# ─────────────────────────────────────────────────────────────────
# CRAWLER FUNKTIONEN (leicht optimiert)
# ─────────────────────────────────────────────────────────────────
# ... deine bestehenden scrape_barrikade(), scrape_indymedia(), scrape_rss(), scrape_gnews() bleiben gleich.
# Nur der classify-Aufruf ist jetzt viel besser.

# (Kopiere deine bisherigen scrape_ Funktionen hier rein – sie funktionieren mit dem neuen classify hervorragend)

# ─────────────────────────────────────────────────────────────────
# MASTER CRAWLER + FASTAPI
# ─────────────────────────────────────────────────────────────────
_running = [False]

def run_crawler(force=False):
    if _running[0]:
        return
    _running[0] = True
    log.info("══════════ CRAWLER STARTED ══════════")
    try:
        scrape_barrikade()
        scrape_indymedia()
        scrape_rss()
        scrape_gnews()
    except Exception as e:
        log.error(f"Crawler error: {e}", exc_info=True)
    finally:
        _running[0] = False
        meta_set("last_crawl", datetime.now().isoformat())
    log.info("══════════ CRAWLER FINISHED ══════════")

app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

# Deine bestehenden Routes bleiben gleich + folgende neue:

@app.get("/api/db-check")
async def db_check():
    total = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    return JSONResponse({
        "total_incidents": total,
        "barrikade_done": bool(meta_get("b_done")),
        "indymedia_done": bool(meta_get("im_done")),
        "last_crawl": meta_get("last_crawl"),
        "db_path": DB_PATH
    })

@app.post("/api/reset-all")
async def reset_all(bg: BackgroundTasks):
    db.execute("DELETE FROM incidents")
    for k in ["b_done","b_curr_id","b_max_id","im_done","im_offset","last_crawl"]:
        meta_del(k)
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "DB + Progress komplett zurückgesetzt. Crawl gestartet."})

@app.on_event("startup")
async def startup():
    # Automatischer Reset wenn zu wenige Einträge
    if db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] < 5:
        log.warning("Wenige Einträge → automatischer Reset")
        for k in ["b_done","im_done"]:
            meta_del(k)
    
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, "interval", hours=6, id="main", next_run_time=datetime.now() + timedelta(seconds=10))
    sched.start()
    log.info("LEX EUROPE v4.2 ready – mit stark verbessertem Filter + DB-Fixes")

# Starte mit Reset
@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "gestartet"})
