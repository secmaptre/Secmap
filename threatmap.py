import streamlit as st
import pandas as pd
import sqlite3
import requests
from bs4 import BeautifulSoup
import logging
import json
import os
import time
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urljoin

import folium
from streamlit_folium import st_folium
from apscheduler.schedulers.background import BackgroundScheduler

# ==================== LOGGING ====================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ==================== PAGE CONFIG ====================
st.set_page_config(page_title="LEX EUROPE", page_icon="eye-only.png", layout="wide")

# ==================== CONSTANTS ====================
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT, "Accept-Language": "de-DE,de;q=0.9,en;q=0.8"}

KEYWORDS = [
    "brandanschlag", "sabotage", "schmiererei", "graffiti", "molotow",
    "farbbeutel", "militant", "direkte aktion", "anschlag", "feuer gelegt",
    "blockade", "besetzung", "störaktion", "angriff", "attackier",
    "zerstör", "beschädig", "barrikade", "anti-repression"
]

# ==================== HEADER ====================
col1, col2 = st.columns([1, 4])
with col1:
    try:
        st.image("logo-main.png", width=210)
    except Exception:
        st.write("🛡️")
with col2:
    st.title("LEX EUROPE")
    st.markdown("**Threat Map • Gewalttätiger Linksextremismus in Europa**")
    st.caption("Fokus: DACH • Schweiz • Automatischer Crawler aktiv")

# ==================== DATABASE ====================
DB_PATH = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
log.info(f"Using database at: {DB_PATH}")

@st.cache_resource
def get_conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT, location TEXT, country TEXT, category TEXT,
        description TEXT, source TEXT, url TEXT, content_hash TEXT UNIQUE,
        lat REAL, lon REAL, timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS geocache (
        query TEXT PRIMARY KEY, lat REAL, lon REAL
    )''')
    c.commit()
    return c

conn = get_conn()

# ==================== GEOCODING (with cache + rate limit) ====================
_last_geocode_call = [0.0]

def geocode(location, country):
    if not location or location in ("Unbekannt", "", None):
        return None, None
    key = f"{location}|{country}".lower()
    row = conn.execute("SELECT lat, lon FROM geocache WHERE query = ?", (key,)).fetchone()
    if row:
        return row[0], row[1]

    # Rate limit: 1 req/sec for Nominatim
    elapsed = time.time() - _last_geocode_call[0]
    if elapsed < 1.1:
        time.sleep(1.1 - elapsed)

    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": f"{location}, {country}", "format": "json", "limit": 1},
            headers={"User-Agent": "LEX-EUROPE-OSINT/1.0"},
            timeout=10
        )
        _last_geocode_call[0] = time.time()
        results = r.json()
        if results:
            lat, lon = float(results[0]["lat"]), float(results[0]["lon"])
            conn.execute("INSERT OR REPLACE INTO geocache VALUES (?, ?, ?)", (key, lat, lon))
            conn.commit()
            return lat, lon
    except Exception as e:
        log.warning(f"Geocoding failed for '{location}': {e}")
    conn.execute("INSERT OR REPLACE INTO geocache VALUES (?, NULL, NULL)", (key,))
    conn.commit()
    return None, None

# ==================== GROK API ====================
def classify_with_ai(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt", "relevant": False}

    prompt = f"""Analysiere folgenden Text auf linksextreme Gewalttat/Aktion in Europa.
Gib NUR gültiges JSON zurück, keine Markdown-Codeblöcke.

Text: {text[:1500]}

Format:
{{"land": "DE|AT|CH|FR|IT|Andere", "kategorie": "...", "ort": "Stadt", "relevant": true/false}}

kategorie: Brandanschlag | Sabotage | Gewalt | Schmiererei | Aufruf zu Gewalt | Militante Aktion | Sonstiges | Unklassifiziert
relevant: true nur wenn konkrete Tat/Aktion beschrieben (nicht nur Meinung/News)"""

    raw = ""
    try:
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "grok-4", "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.0, "max_tokens": 250},
            timeout=30
        )
        response.raise_for_status()
        raw = response.json()["choices"][0]["message"]["content"].strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        result.setdefault("relevant", True)
        log.info(f"Grok: {result}")
        return result
    except requests.exceptions.HTTPError:
        log.error(f"Grok HTTP error: {response.text[:300]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON parse failed: {e} — raw: {raw[:200]}")
    except Exception as e:
        log.error(f"Grok error: {e}")
    return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt", "relevant": False}

# ==================== COOLDOWN ====================
def should_run_crawler():
    row = conn.execute("SELECT value FROM metadata WHERE key = 'last_crawl'").fetchone()
    if not row:
        return True
    return datetime.now() - datetime.fromisoformat(row[0]) > timedelta(hours=23)

def update_last_crawl():
    conn.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_crawl', ?)",
                 (datetime.now().isoformat(),))
    conn.commit()

# ==================== HELPERS ====================
def fetch(url, timeout=20):
    r = requests.get(url, timeout=timeout, headers=HEADERS)
    r.raise_for_status()
    return r.text

def content_hash(text, url):
    return hashlib.sha256((url + "|" + text[:500]).encode()).hexdigest()

def already_seen(h):
    return conn.execute("SELECT 1 FROM incidents WHERE content_hash = ?", (h,)).fetchone() is not None

def save_incident(ai, text, source, url):
    h = content_hash(text, url)
    if already_seen(h):
        return False
    lat, lon = geocode(ai["ort"], ai["land"])
    conn.execute(
        """INSERT OR IGNORE INTO incidents
           (date, location, country, category, description, source, url, content_hash, lat, lon, timestamp)
           VALUES (date('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
        (ai["ort"], ai["land"], ai["kategorie"], text[:500], source, url, h, lat, lon)
    )
    conn.commit()
    return True

def text_matches_keywords(text):
    t = text.lower()
    return any(kw in t for kw in KEYWORDS)

# ==================== SCRAPERS (article-level) ====================
def extract_article_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('#') or href.startswith('mailto:') or href.startswith('javascript:'):
            continue
        full = urljoin(base_url, href)
        # filter: same domain, looks like an article
        if base_url.split('/')[2] in full:
            links.add(full)
    return list(links)

def scrape_article(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, 'html.parser')
        # remove nav/footer
        for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
            tag.decompose()
        # Try common article containers
        article = (soup.find('article') or soup.find('main') or
                   soup.find('div', class_='node') or soup.find('div', class_='content'))
        text = (article.get_text(" ", strip=True) if article else soup.get_text(" ", strip=True))
        return text[:3000]
    except Exception as e:
        log.warning(f"article fetch failed {url}: {e}")
        return ""

def scrape_source(name, base_url, max_articles=15):
    log.info(f"Crawling {name} ...")
    inserted = 0
    try:
        html = fetch(base_url)
        links = extract_article_links(html, base_url)
        log.info(f"{name}: {len(links)} candidate links")

        # Filter to plausible article URLs (heuristic: depth >= 2 path segments)
        candidates = [l for l in links if len(l.replace(base_url, '').strip('/').split('/')) >= 1][:max_articles * 3]

        checked = 0
        for url in candidates:
            if checked >= max_articles:
                break
            text = scrape_article(url)
            if len(text) < 200:
                continue
            if not text_matches_keywords(text):
                continue
            checked += 1
            log.info(f"{name} match: {url}")
            ai = classify_with_ai(text)
            if ai.get("relevant") and ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                if save_incident(ai, text, name, url):
                    inserted += 1
            time.sleep(0.5)
        log.info(f"{name}: inserted {inserted} new incidents")
    except Exception as e:
        log.error(f"{name} scrape failed: {e}")
    return inserted

def run_crawler(force=False):
    if not force and not should_run_crawler():
        log.info("Crawler skipped — last run < 23h ago")
        return
    log.info("===== CRAWLER RUN START =====")
    scrape_source("de.indymedia.org", "https://de.indymedia.org/")
    scrape_source("barrikade.info", "https://barrikade.info/")
    update_last_crawl()
    log.info("===== CRAWLER RUN COMPLETE =====")

# ==================== SCHEDULER ====================
@st.cache_resource
def start_scheduler():
    scheduler = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    scheduler.add_job(run_crawler, 'interval', hours=1, id='crawler_job',
                      next_run_time=datetime.now() + timedelta(seconds=30))
    scheduler.start()
    log.info("APScheduler started")
    return scheduler

start_scheduler()

# ==================== TABS ====================
tab1, tab2, tab3 = st.tabs(["🗺️ Live Threat Map", "📋 Ereignis-Protokoll", "⚙️ Status & Debug"])

with tab1:
    st.subheader("Live Threat Map – Europa (DACH Fokus)")
    m = folium.Map(location=[49.0, 9.5], zoom_start=5.5, tiles="cartodb dark_matter")
    df = pd.read_sql("SELECT * FROM incidents ORDER BY timestamp DESC", conn)
    placed = 0
    for _, row in df.iterrows():
        lat, lon = row.get("lat"), row.get("lon")
        if not lat or not lon:
            continue
        color = "red" if row["category"] in ["Brandanschlag", "Sabotage", "Gewalt",
                                              "Militante Aktion", "Aufruf zu Gewalt"] else "orange"
        popup = (f"<b>{row['date']}</b><br><b>{row['location']}, {row['country']}</b><br>"
                 f"<b>{row['category']}</b><br>{row['description'][:200]}"
                 f"<br><a href='{row.get('url','')}' target='_blank'>Quelle</a>")
        folium.Marker(
            location=[lat, lon],
            popup=popup,
            icon=folium.Icon(color=color, icon="exclamation-triangle", prefix="fa")
        ).add_to(m)
        placed += 1
    st_folium(m, width=1450, height=740)
    if placed == 0 and not df.empty:
        st.info(f"{len(df)} Ereignisse ohne Koordinaten.")
    elif df.empty:
        st.info("Noch keine Ereignisse. Crawler läuft im Hintergrund.")

with tab2:
    st.subheader("Vollständiges Ereignis-Protokoll")
    df2 = pd.read_sql(
        "SELECT date, location, country, category, description, source, url FROM incidents ORDER BY timestamp DESC",
        conn)
    if df2.empty:
        st.info("Noch keine Ereignisse erfasst")
    else:
        st.dataframe(df2, use_container_width=True, hide_index=True)

with tab3:
    st.subheader("⚙️ Crawler Status & Debug")
    row = conn.execute("SELECT value FROM metadata WHERE key = 'last_crawl'").fetchone()
    if row:
        st.success(f"✅ Letzter Crawl: {row[0]}")
    else:
        st.warning("Noch kein Crawl durchgeführt")

    total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = conn.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    c1, c2, c3 = st.columns(3)
    c1.metric("Ereignisse", total)
    c2.metric("Geocodiert", geocoded)
    c3.metric("Datenbank", os.path.basename(DB_PATH))

    api_key = os.getenv("GROK_API_KEY")
    if api_key:
        st.success(f"✅ GROK_API_KEY gesetzt ({len(api_key)} Zeichen)")
    else:
        st.error("❌ GROK_API_KEY NICHT gesetzt!")

    st.divider()
    st.subheader("🔍 Debug")
    if st.button("🤖 Grok API testen"):
        with st.spinner("Teste Grok ..."):
            result = classify_with_ai("Unbekannte verübten in der Nacht einen Brandanschlag auf ein Polizeifahrzeug in Berlin-Kreuzberg. Bekennerschreiben einer militanten Gruppe.")
        st.json(result)

    st.divider()
    st.subheader("Manueller Crawl")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("🔄 Jetzt crawlen (force)"):
            with st.spinner("Crawle..."):
                run_crawler(force=True)
            st.success("Crawl abgeschlossen!")
            st.rerun()
    with c2:
        if st.button("🗑️ Datenbank leeren"):
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM metadata")
            conn.commit()
            st.warning("Datenbank geleert.")
            st.rerun()

st.caption("LEX EUROPE • OSINT • SEC")
