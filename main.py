import os
import logging
import json
import time
import hashlib
import re
import traceback
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

DB_PATH = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
GROK_MODEL = os.getenv("GROK_MODEL", "grok-4")

app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

# ==================== DATABASE ====================
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
    conn.commit()
    return conn

db = get_db()

def meta_get(k): 
    r = db.execute("SELECT value FROM metadata WHERE key=?", (k,)).fetchone()
    return r[0] if r else None

def meta_set(k, v):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (k, str(v)))
    db.commit()

# ==================== SESSION ====================
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "de-DE,de;q=0.9",
})

def fetch(url, timeout=20):
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.warning(f"fetch failed {url}: {e}")
        return ""

# ==================== TEXT EXTRACTION (verbessert) ====================
def get_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside", "form", "iframe"]):
            tag.decompose()
        
        # Barrikade-spezifisch
        content = (soup.find("article") or 
                   soup.find("div", class_=re.compile(r"node|content|post|entry", re.I)) or 
                   soup.find("div", id=re.compile(r"content|post", re.I)) or 
                   soup.body)
        
        text = content.get_text(separator=" ", strip=True)
        text = re.sub(r'\s+', ' ', text)
        return text[:4500]
    except Exception as e:
        log.warning(f"get_text {url}: {e}")
        return ""

# ==================== CLASSIFY ====================
def classify(text, mode="loose"):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "DE"}
    
    prompt = f"""
    Analysiere, ob dieser Text ein reales linksextremes Ereignis beschreibt (Demo, Aktion, Sabotage, Brand, Schmiererei, Verhaftung etc.).
    Antworte NUR mit JSON:

    {{"relevant": true/false, "land": "DE/AT/CH/Andere", "kategorie": "Brandanschlag/Sabotage/Gewalt/Schmiererei/Aufruf zu Gewalt/Militante Aktion/Sonstiges", "ort": "Stadt"}}
    
    Text: {text[:1800]}
    """
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": GROK_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 250},
            timeout=25
        )
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        res = json.loads(raw)
        res.setdefault("relevant", True)
        return res
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
             text[:650], source, url, h))
        db.commit()
        log.info(f"✅ SAVED {source} | {ai.get('kategorie')} | {ai.get('ort')}")
        return True
    except Exception as e:
        log.error(f"save error: {e}")
        return False

# ==================== BARRIKADE (neu & robuster) ====================
def scrape_barrikade():
    log.info("=== Barrikade scrape started ===")
    # Neue Artikel von der Startseite
    try:
        html = fetch("https://barrikade.info/")
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if "/article/" in href and len(href) > 20:
                full = urljoin("https://barrikade.info", href)
                if full not in links:
                    links.append(full)
        
        log.info(f"Barrikade found {len(links)} articles on frontpage")
        saved = 0
        for url in links[:30]:
            text = get_text(url)
            if len(text) < 100: 
                continue
            ai = classify(text, "loose")
            if save(ai, text, "barrikade.info", url):
                saved += 1
            time.sleep(0.7)
        log.info(f"Barrikade live: +{saved}")
    except Exception as e:
        log.error(f"Barrikade error: {e}")

# ==================== INDYMEDIA ====================
def scrape_indymedia():
    log.info("=== Indymedia scrape started ===")
    try:
        links = []
        for offset in [0, 20, 40]:
            url = f"https://de.indymedia.org/?limit=30&offset={offset}"
            html = fetch(url)
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                if "/openposting/" in a["href"] or a["href"].startswith("/node/"):
                    full = urljoin("https://de.indymedia.org", a["href"])
                    if full not in links:
                        links.append(full)
        
        saved = 0
        for url in links[:40]:
            text = get_text(url)
            if len(text) < 100: continue
            ai = classify(text, "loose")
            if save(ai, text, "de.indymedia.org", url):
                saved += 1
            time.sleep(0.6)
        log.info(f"Indymedia: +{saved}")
    except Exception as e:
        log.error(f"Indymedia error: {e}")

# ==================== MASTER CRAWLER ====================
def run_crawler(force=False):
    log.info("══════ CRAWLER START ══════")
    scrape_barrikade()
    scrape_indymedia()
    meta_set("last_crawl", datetime.now().isoformat())
    log.info("══════ CRAWLER DONE ══════")

# ==================== FASTAPI ROUTES ====================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/diagnose")
async def diagnose():
    return {"status": "alive", "last_crawl": meta_get("last_crawl"), "incidents": db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]}

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, True)
    return {"status": "Crawler wurde gestartet"}

@app.on_event("startup")
async def startup():
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(run_crawler, "interval", minutes=30, next_run_time=datetime.now() + timedelta(seconds=10))
    sched.start()
    log.info("LEX EUROPE gestartet")
