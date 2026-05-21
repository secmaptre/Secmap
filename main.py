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

# ==================== PERSISTENT DB ====================
DB_PATH = "/data/lex_threat.db"
log.info(f"📁 DB Path: {DB_PATH}")

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT, location TEXT, country TEXT, category TEXT,
        description TEXT, source TEXT, url TEXT, content_hash TEXT UNIQUE,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    log.info("✅ DB initialisiert")
    return conn

db = get_db()

def meta_get(k):
    r = db.execute("SELECT value FROM metadata WHERE key=?", (k,)).fetchone()
    return r[0] if r else None

def meta_set(k, v):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (k, str(v)))
    db.commit()

# ==================== HELPERS ====================
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

def fetch(url):
    try:
        r = session.get(url, timeout=20)
        r.raise_for_status()
        return r.text
    except:
        return ""

def get_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for t in soup(["script","style","nav","footer","header","aside"]):
            t.decompose()
        content = soup.find("article") or soup.find("main") or soup.body
        text = content.get_text(separator=" ", strip=True)
        return re.sub(r'\s+', ' ', text)[:4500]
    except:
        return ""

def classify(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "DE"}
    
    prompt = f"""Analysiere ob dieser Text ein reales linkes Ereignis beschreibt. Antworte NUR JSON:
{{"relevant":true, "land":"DE|AT|CH", "kategorie":"Brandanschlag|Sabotage|Gewalt|Schmiererei|Militante Aktion|Sonstiges", "ort":"Stadt"}}
Text: {text[:1600]}"""
    
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "grok-4", "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 180},
            timeout=20
        )
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"```.*?\n?", "", raw).strip()
        return json.loads(raw)
    except:
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "DE"}

def save(ai, text, source, url):
    if not ai or not ai.get("relevant"): return False
    h = hashlib.sha256((url + text[:300]).encode()).hexdigest()
    if db.execute("SELECT 1 FROM incidents WHERE content_hash=?", (h,)).fetchone():
        return False
    try:
        db.execute("""INSERT OR IGNORE INTO incidents 
            (date,location,country,category,description,source,url,content_hash,timestamp)
            VALUES (date('now'),?,?,?,?,?,?,?,datetime('now'))""",
            (ai.get("ort","Unbekannt"), ai.get("land","DE"), ai.get("kategorie","Sonstiges"), text[:700], source, url, h))
        db.commit()
        return True
    except:
        return False

# ==================== CRAWLER ====================
def scrape_barrikade():
    log.info("Barrikade scrape...")
    try:
        html = fetch("https://barrikade.info/")
        soup = BeautifulSoup(html, "html.parser")
        links = [urljoin("https://barrikade.info", a["href"]) for a in soup.find_all("a", href=True) if "/article/" in a["href"]]
        links = list(dict.fromkeys(links))[:40]
        saved = 0
        for url in links:
            text = get_text(url)
            if len(text) < 100: continue
            ai = classify(text)
            if save(ai, text, "barrikade.info", url):
                saved += 1
            time.sleep(0.7)
        log.info(f"Barrikade +{saved}")
    except Exception as e:
        log.error(f"Barrikade error: {e}")

def run_crawler():
    log.info("Crawler gestartet")
    scrape_barrikade()
    meta_set("last_crawl", datetime.now().isoformat())

# ==================== ROUTES (wichtig!) ====================
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
    return {"total": total, "last_crawl": last, "by_country": [], "by_cat": [], "by_source": []}

@app.get("/api/diagnose")
async def diagnose():
    total = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    return {
        "status": "ok",
        "db_path": DB_PATH,
        "incidents": total,
        "last_crawl": meta_get("last_crawl"),
        "db_writable": os.access(os.path.dirname(DB_PATH) or ".", os.W_OK)
    }

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler)
    return {"status": "gestartet"}

@app.post("/api/reset-historical")
async def reset_historical(bg: BackgroundTasks):
    db.execute("DELETE FROM incidents")
    db.commit()
    bg.add_task(run_crawler)
    return {"status": "reset + crawl gestartet"}

@app.post("/api/clear")
async def clear_db():
    db.execute("DELETE FROM incidents")
    db.commit()
    return {"status": "cleared"}

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(run_crawler, "interval", minutes=30, next_run_time=datetime.now() + timedelta(seconds=10))
    sched.start()
    log.info("🚀 LEX EUROPE v4.5 gestartet")
