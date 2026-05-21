import os
import logging
import sqlite3
import requests
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import hashlib
import re
import time
import threading

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="LEX EUROPE")

DB_PATH = "lex_threat.db"

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
        timestamp TEXT
    )''')
    conn.commit()
    return conn

db = get_db()

# ==================== HTML (komplett inline - keine statics) ====================
HTML_CONTENT = """<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LEX EUROPE — Threat Map</title>
    <style>
        body { background:#0a0a0f; color:#ccc; font-family:Arial, sans-serif; margin:0; padding:0; }
        header { background:#1a0000; padding:15px; text-align:center; border-bottom:3px solid #e8001c; }
        .logo { font-size:42px; font-weight:bold; color:#e8001c; letter-spacing:4px; }
        .container { padding:20px; max-width:1400px; margin:auto; }
        h1 { color:#e8001c; }
        table { width:100%; border-collapse:collapse; margin-top:20px; }
        th, td { padding:10px; border:1px solid #333; text-align:left; }
        th { background:#1f1f2e; }
        .red { color:#ff4444; }
    </style>
</head>
<body>
    <header>
        <div class="logo">LEX EUROPE</div>
        <p>Threat Map • Gewalttätiger Linksextremismus • DACH / Europa</p>
    </header>
    
    <div class="container">
        <h1>Live Threat Map</h1>
        <p id="status">Crawler läuft im Hintergrund...</p>
        
        <table id="table">
            <thead>
                <tr>
                    <th>Datum</th>
                    <th>Ort</th>
                    <th>Land</th>
                    <th>Kategorie</th>
                    <th>Beschreibung</th>
                    <th>Quelle</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>

    <script>
        async function loadData() {
            try {
                const res = await fetch('/api/incidents');
                const data = await res.json();
                const tbody = document.querySelector('#table tbody');
                tbody.innerHTML = '';
                
                data.forEach(item => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${item.date || '-'}</td>
                        <td>${item.location || 'Unbekannt'}</td>
                        <td>${item.country || '-'}</td>
                        <td class="red">${item.category || 'Sonstiges'}</td>
                        <td>${item.description ? item.description.substring(0,120) + '...' : ''}</td>
                        <td><a href="${item.url}" target="_blank">Link</a></td>
                    `;
                    tbody.appendChild(row);
                });
            } catch(e) {
                console.error(e);
            }
        }
        setInterval(loadData, 15000);
        loadData();
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML_CONTENT

@app.get("/api/incidents")
async def get_incidents():
    rows = db.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall()
    return [dict(r) for r in rows]

# ==================== CRAWLER (Platzhalter - später füllen) ====================
def run_crawler():
    log.info("Crawler läuft...")
    # Hier später deine scrape-Funktionen einbauen
    time.sleep(10)  # nur zum Testen

@app.on_event("startup")
async def startup():
    threading.Thread(target=run_crawler, daemon=True).start()
    log.info("LEX EUROPE gestartet - Minimal Version")

print("✅ LEX EUROPE Minimal Server bereit")
