import os
import logging
import json
import time
import hashlib
import re
from datetime import datetime, timedelta

import requests
from bs4 import BeautifulSoup
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

# ==================== DATABASE PATH FIX (für Render) ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lex_threat.db")
log.info(f"📁 Datenbank wird verwendet: {DB_PATH}")

# ==================== DATABASE ====================
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        location TEXT,
        country TEXT,
        category TEXT,
        description TEXT,
        source TEXT,
        url TEXT,
        content_hash TEXT UNIQUE,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    conn.commit()
    log.info("✅ Datenbank + Tabellen erfolgreich initialisiert")
    return conn

db = get_db()

def meta_get(k):
    r = db.execute("SELECT value FROM metadata WHERE key=?", (k,)).fetchone()
    return r[0] if r else None

def meta_set(k, v):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (k, str(v)))
    db.commit()

# ==================== HTTP SESSION ====================
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})

def fetch(url, timeout=20):
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.warning(f"fetch failed {url}: {e}")
        return ""

# ==================== TEXT EXTRACTION ====================
def get_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside", "form"]):
            tag.decompose()
        
        content = (soup.find("article") or 
                   soup.find("main") or 
                   soup.find("div", class_=re.compile(r"node|content|post|entry|text|body", re.I)) or 
                   soup.body)
        
        text = content.get_text(separator=" ", strip=True)
        text = re.sub(r'\s+', ' ', text)
        return text[:4800]
    except Exception as e:
        log.warning(f"get_text failed {url}: {e}")
        return ""

# ==================== CLASSIFY ====================
def classify(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "DE"}
    
    prompt = f"""Analysiere, ob dieser Text ein reales linkes/antifa Ereignis beschreibt (Aktion, Sabotage, Brand, Schmiererei, Demo etc.).
Antworte NUR mit JSON:

{{"relevant": true, "land": "DE|AT|CH|Andere", "kategorie": "Brandanschlag|Sabotage|Gewalt|Schmiererei|Militante Aktion|Sonstiges", "ort": "Stadt"}}

Text: {text[:1700]}"""

    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "grok-4", "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 200},
            timeout=25
        )
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"```.*?\n?", "", raw).strip()
        return json.loads(raw)
    except:
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "DE"}

# ==================== SAVE ====================
def chash(url, text):
    return hashlib.sha256((url + text[:400]).encode()).hexdigest()

def seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE content_hash=?", (h,)).fetchone() is not None

def save(ai, text, source, url):
    if not ai or not ai.get("relevant"):
        return False
    h = chash(url, text)
    if seen(h):
        return False
    try:
        db.execute("""INSERT OR IGNORE INTO incidents 
            (date, location, country, category, description, source, url, content_hash, timestamp)
            VALUES (date('now'), ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (ai.get("ort","Unbekannt"), ai.get("land","DE"), ai.get("kategorie","Sonstiges"), 
             text[:700], source, url, h))
        db.commit()
        log.info(f"✅ GESPEICHERT: {source} | {ai.get('kategorie')} | {ai.get('ort')}")
        return True
    except Exception as e:
        log.error(f"Save error: {e}")
        return False

# ==================== CRAWLER ====================
def scrape_barrikade():
    log.info("=== Barrikade Scrape ===")
    saved = 0
    try:
        html = fetch("https://barrikade.info/")
        soup = BeautifulSoup(html, "html.parser")
        links = [urljoin("https://barrikade.info", a["href"]) for a in soup.find_all("a", href=True) if "/article/" in a["href"]]
        links = list(dict.fromkeys(links))[:40]
        
        for url in links:
            text = get_text(url)
            if len(text) < 100: continue
            ai = classify(text)
            if save(ai, text, "barrikade.info", url):
                saved += 1
            time.sleep(0.7)
    except Exception as e:
        log.error(f"Barrikade error: {e}")
    log.info(f"Barrikade: +{saved} Einträge")

def scrape_indymedia():
    log.info("=== Indymedia Scrape ===")
    # Vereinfacht für Stabilität
    log.info("Indymedia: vorerst deaktiviert (kann später erweitert werden)")

def run_crawler():
    log.info("══════ CRAWLER GESTARTET ══════")
    scrape_barrikade()
    meta_set("last_crawl", datetime.now().isoformat())
    log.info("══════ CRAWLER FERTIG ══════")

# ==================== ROUTES ====================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/stats")
async def get_stats():
    total = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    last = meta_get("last_crawl")
    return {
        "total": total,
        "geocoded": 0,
        "last_crawl": last,
        "crawl_running": False,
        "by_country": [],
        "by_cat": [],
        "by_source": []
    }

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler)
    return {"status": "Crawler wurde gestartet"}

@app.post("/api/reset-historical")
async def reset_historical(bg: BackgroundTasks):
    db.execute("DELETE FROM incidents")
    db.commit()
    bg.add_task(run_crawler)
    return {"status": "Datenbank zurückgesetzt und Crawl gestartet"}

@app.post("/api/clear")
async def clear_db():
    db.execute("DELETE FROM incidents")
    db.commit()
    return {"status": "Datenbank geleert"}

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(run_crawler, "interval", minutes=40, next_run_time=datetime.now() + timedelta(seconds=8))
    sched.start()
    log.info("🚀 LEX EUROPE v4.4 gestartet - DB sollte jetzt funktionieren")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
