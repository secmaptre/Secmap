import os
import logging
import json
import time
import hashlib
import re
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

app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

DB_PATH = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"

# ==================== DATABASE ====================
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT, location TEXT, country TEXT, category TEXT,
        description TEXT, source TEXT, url TEXT, content_hash TEXT UNIQUE,
        timestamp TEXT
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
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

def fetch(url, timeout=20):
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.warning(f"fetch failed {url}: {e}")
        return ""

# ==================== VERBESSERTE TEXT EXTRACTION ====================
def get_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        
        # Barrikade-spezifischer Fix
        if "barrikade.info" in url:
            # Die wichtigsten Container auf Barrikade
            content = (
                soup.find("article") or
                soup.find("div", class_=re.compile(r"field-name-body|node-body|content|post-body", re.I)) or
                soup.find("div", id=re.compile(r"node|article|content", re.I)) or
                soup.find("div", class_=re.compile(r"node-full|article-full", re.I)) or
                soup.find("div", string=re.compile(r"Malergruppe|Antifa|besucht|Brand|Sabotage", re.I))  # Fallback
            )
        else:
            content = (
                soup.find("article") or
                soup.find("main") or
                soup.find("div", class_=re.compile(r"(article|content|post|entry|text|body|node)", re.I)) or
                soup.body
            )
        
        if content:
            text = content.get_text(separator=" ", strip=True)
            text = re.sub(r'\s+', ' ', text)
            return text[:4800]
        return ""
    except Exception as e:
        log.warning(f"get_text {url}: {e}")
        return ""

# ==================== CLASSIFY + SAVE (unverändert, aber stabil) ====================
def classify(text):
    # ... (deine aktuelle classify Funktion bleibt gleich)
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "CH"}
    
    prompt = f"""Analysiere kurz: Beschreibt dieser Text ein reales linkes/antifaschistisches Ereignis (Aktion, Sabotage, Brand, Schmiererei, Demo, Besetzung etc.)?
Antworte NUR mit JSON: {{"relevant":true, "land":"CH", "kategorie":"Militante Aktion", "ort":"Zürich"}}

Text: {text[:1600]}"""

    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "grok-4", "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 150},
            timeout=20
        )
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"```.*?\n?", "", raw).strip()
        return json.loads(raw)
    except:
        return {"relevant": True, "kategorie": "Sonstiges", "ort": "Unbekannt", "land": "CH"}

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
            (ai.get("ort","Unbekannt"), ai.get("land","CH"), ai.get("kategorie","Militante Aktion"), 
             text[:700], source, url, h))
        db.commit()
        log.info(f"✅ SAVED → {source} | {ai.get('kategorie')} | {ai.get('ort')}")
        return True
    except Exception as e:
        log.error(f"save error: {e}")
        return False

# ==================== BARRIKADE (jetzt fix für article/XXXX) ====================
def scrape_barrikade():
    log.info("=== Barrikade Scrape START ===")
    saved = 0
    # 1. Frontpage + neueste Artikel
    try:
        html = fetch("https://barrikade.info/")
        soup = BeautifulSoup(html, "html.parser")
        links = [urljoin("https://barrikade.info", a["href"]) for a in soup.find_all("a", href=True) 
                 if "/article/" in a["href"] and len(a["href"]) > 15]
        links = list(dict.fromkeys(links))[:40]
        
        for url in links:
            text = get_text(url)
            if len(text) < 120: 
                continue
            ai = classify(text)
            if save(ai, text, "barrikade.info", url):
                saved += 1
            time.sleep(0.8)
    except Exception as e:
        log.error(f"Barrikade frontpage error: {e}")

    log.info(f"Barrikade: +{saved} neue Einträge")
    return saved

# ==================== INDYMEDIA (bleibt gleich) ====================
def scrape_indymedia():
    log.info("=== Indymedia Scrape START ===")
    saved = 0
    for offset in [0, 20]:
        try:
            url = f"https://de.indymedia.org/?limit=30&offset={offset}"
            html = fetch(url)
            soup = BeautifulSoup(html, "html.parser")
            links = [urljoin("https://de.indymedia.org", a["href"]) for a in soup.find_all("a", href=True) 
                     if "/openposting/" in a["href"] or a["href"].startswith("/node/")]
            links = list(dict.fromkeys(links))[:30]
            
            for link in links:
                text = get_text(link)
                if len(text) < 100: continue
                ai = classify(text)
                if save(ai, text, "de.indymedia.org", link):
                    saved += 1
                time.sleep(0.6)
        except Exception as e:
            log.warning(f"Indymedia error: {e}")
    log.info(f"Indymedia: +{saved}")

# ==================== CRAWLER + ROUTES ====================
def run_crawler():
    log.info("══════ FULL CRAWL STARTED ══════")
    scrape_barrikade()
    scrape_indymedia()
    meta_set("last_crawl", datetime.now().isoformat())
    log.info("══════ CRAWL FINISHED ══════")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler)
    return {"status": "Crawler wurde gestartet"}

@app.on_event("startup")
async def startup():
    from apscheduler.schedulers.background import BackgroundScheduler
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(run_crawler, "interval", minutes=40, next_run_time=datetime.now() + timedelta(seconds=5))
    sched.start()
    log.info("LEX EUROPE v4.3 ready")
