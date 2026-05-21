import os
import logging
import json
import time
import hashlib
import re
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
from fastapi.staticfiles import StaticFiles

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ==================== CONFIG ====================
DB_PATH = "lex_threat.db"
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")

# Statische Dateien (Bilder)
app.mount("/static", StaticFiles(directory="static", html=False), name="static")

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

# ==================== ROOT ROUTE (wichtig gegen 404) ====================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# ==================== API ROUTES ====================
@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/stats")
async def get_stats():
    total = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    last = db.execute("SELECT value FROM metadata WHERE key='last_crawl'").fetchone()
    return {
        "total": total,
        "last_crawl": last[0] if last else None
    }

@app.post("/api/crawl")
async def trigger_crawl(bg: BackgroundTasks):
    bg.add_task(run_crawler, force=True)
    return {"status": "Crawler gestartet"}

# ==================== DEIN CRAWLER CODE (hier einfügen) ====================
# ... (füge hier deinen gesamten Crawler-Code ein: classify, scrape_ Funktionen, run_crawler etc.)

# ==================== STARTUP ====================
@app.on_event("startup")
async def startup_event():
    log.info("🚀 LEX EUROPE gestartet")
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    sched.add_job(run_crawler, 'interval', hours=6, next_run_time=datetime.now() + timedelta(seconds=30))
    sched.start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
