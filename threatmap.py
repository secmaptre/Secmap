import streamlit as st
import pandas as pd
import sqlite3
import requests
from bs4 import BeautifulSoup
import threading
import logging
import json
import os
from datetime import datetime, timedelta

import folium
from streamlit_folium import st_folium
from apscheduler.schedulers.background import BackgroundScheduler

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ==================== PAGE CONFIG ====================
st.set_page_config(page_title="LEX EUROPE", page_icon="eye-only.png", layout="wide")

# ==================== HEADER ====================
col1, col2 = st.columns([1, 4])
with col1:
    st.image("logo-main.png", width=210)
with col2:
    st.title("LEX EUROPE")
    st.markdown("**Threat Map • Gewalttätiger Linksextremismus in Europa**")
    st.caption("Fokus: DACH • Schweiz • Automatischer Crawler aktiv")

# ==================== DATABASE ====================
# Render paid tier: mount a persistent disk at /data in the Render dashboard
# Settings → Disks → Add Disk → Mount Path: /data
DB_PATH = "/data/lex_threat.db" if os.path.isdir("/data") else "lex_threat.db"
log.info(f"Using database at: {DB_PATH}")
conn = sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        location TEXT,
        country TEXT,
        category TEXT,
        description TEXT,
        source TEXT,
        lat REAL,
        lon REAL,
        timestamp TEXT,
        UNIQUE(description, source)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    conn.commit()

init_db()

# ==================== GEOCODING ====================
def geocode(location, country):
    """Resolve location name → lat/lon via Nominatim (free, no key needed)."""
    if not location or location in ("Unbekannt", ""):
        return None, None
    try:
        query = f"{location}, {country}"
        r = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": query, "format": "json", "limit": 1},
            headers={"User-Agent": "LEX-EUROPE-OSINT/1.0 (secmaptre@github)"},
            timeout=8
        )
        results = r.json()
        if results:
            return float(results[0]["lat"]), float(results[0]["lon"])
    except Exception as e:
        log.warning(f"Geocoding failed for '{location}, {country}': {e}")
    return None, None

# ==================== GROK API ====================
def classify_with_ai(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY is NOT set in Render environment variables!")
        return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt"}

    prompt = f"""Analysiere folgenden Text und gib NUR gültiges JSON zurück.
Kein Markdown, keine Erklärungen, nur das JSON-Objekt.

Text: {text}

Antworte ausschließlich mit diesem JSON-Format:
{{"land": "DE", "kategorie": "Brandanschlag", "ort": "Berlin"}}

Erlaubte Werte:
- land: DE | AT | CH | Andere
- kategorie: Brandanschlag | Sabotage | Gewalt | Schmiererei | Aufruf zu Gewalt | Militante Aktion | Sonstiges
- ort: Stadt oder Region als String"""

    try:
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "grok-4",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "max_tokens": 250
            },
            timeout=20
        )
        response.raise_for_status()
        raw = response.json()["choices"][0]["message"]["content"].strip()
        # Strip markdown fences Grok sometimes wraps around JSON
        raw = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        log.info(f"Grok classified: {result}")
        return result
    except requests.exceptions.HTTPError as e:
        log.error(f"Grok API HTTP error {response.status_code}: {response.text}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON parse failed: {e} — Raw response: {raw}")
    except Exception as e:
        log.error(f"Grok API unexpected error: {e}")

    return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt"}

# ==================== COOLDOWN ====================
def should_run_crawler():
    cursor = conn.execute("SELECT value FROM metadata WHERE key = 'last_crawl'")
    row = cursor.fetchone()
    if not row:
        return True
    last_crawl = datetime.fromisoformat(row[0])
    return datetime.now() - last_crawl > timedelta(hours=23)

def update_last_crawl():
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_crawl', ?)",
        (datetime.now().isoformat(),)
    )
    conn.commit()

# ==================== KEYWORDS ====================
KEYWORDS = [
    "brandanschlag", "sabotage", "schmiererei", "graffiti", "gewalt",
    "prügelei", "antifa", "militante aktion", "direkte aktion",
    "aufruf zu gewalt", "anschlag", "feuer", "molotow", "farbbeutel",
    "blockade", "besetzung", "störaktion"
]

# ==================== CRAWLERS ====================
def scrape_indymedia():
    log.info("Crawling de.indymedia.org ...")
    try:
        r = requests.get(
            "https://de.indymedia.org/",
            timeout=20,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36"
            }
        )
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')

        # Try multiple selectors — indymedia structure varies
        articles = (
            soup.find_all('div', class_='article') or
            soup.find_all('article') or
            soup.find_all('div', class_='post') or
            soup.find_all('div', class_='news-article') or
            soup.find_all('div', class_='view-row')
        )
        log.info(f"indymedia: found {len(articles)} candidate elements")

        count = 0
        for article in articles[:15]:
            title_tag = article.find('h2') or article.find('h3') or article.find('a')
            text = (title_tag.get_text(strip=True) if title_tag else "") + " " + article.get_text(strip=True)
            if any(kw in text.lower() for kw in KEYWORDS):
                log.info(f"indymedia keyword match: {text[:100]}")
                ai = classify_with_ai(text[:800])
                if ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                    lat, lon = geocode(ai["ort"], ai["land"])
                    conn.execute(
                        """INSERT OR IGNORE INTO incidents
                           (date, location, country, category, description, source, lat, lon, timestamp)
                           VALUES (date('now'), ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                        (ai["ort"], ai["land"], ai["kategorie"], text[:500], "de.indymedia.org", lat, lon)
                    )
                    conn.commit()
                    count += 1
        log.info(f"indymedia: inserted {count} new incidents")
    except Exception as e:
        log.error(f"indymedia scrape failed: {e}")

def scrape_barrikade():
    log.info("Crawling barrikade.info ...")
    try:
        r = requests.get(
            "https://barrikade.info/",
            timeout=20,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36"
            }
        )
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')

        # Try multiple selectors for barrikade.info
        articles = (
            soup.find_all('article') or
            soup.find_all('div', class_='node') or
            soup.find_all('div', class_='post') or
            soup.find_all('div', class_='entry') or
            soup.find_all('li', class_='article') or
            soup.find_all('div', class_='field-item')
        )
        log.info(f"barrikade: found {len(articles)} candidate elements")

        count = 0
        for article in articles[:12]:
            text = article.get_text(strip=True)
            if any(kw in text.lower() for kw in KEYWORDS):
                log.info(f"barrikade keyword match: {text[:100]}")
                ai = classify_with_ai(text[:800])
                if ai["kategorie"] not in ("Unklassifiziert", "Sonstiges"):
                    lat, lon = geocode(ai["ort"], ai["land"])
                    conn.execute(
                        """INSERT OR IGNORE INTO incidents
                           (date, location, country, category, description, source, lat, lon, timestamp)
                           VALUES (date('now'), ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                        (ai["ort"], ai["land"], ai["kategorie"], text[:500], "barrikade.info", lat, lon)
                    )
                    conn.commit()
                    count += 1
        log.info(f"barrikade: inserted {count} new incidents")
    except Exception as e:
        log.error(f"barrikade scrape failed: {e}")

def run_crawler():
    if should_run_crawler():
        log.info("===== CRAWLER RUN START =====")
        scrape_indymedia()
        scrape_barrikade()
        update_last_crawl()
        log.info("===== CRAWLER RUN COMPLETE =====")
    else:
        log.info("Crawler skipped — last run < 23h ago")

# ==================== SCHEDULER ====================
# APScheduler survives Streamlit reruns and Render worker restarts
# unlike a bare threading.Thread tied to session_state
if "scheduler_started" not in st.session_state:
    scheduler = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    # Check every hour whether the 23h cooldown has passed
    scheduler.add_job(run_crawler, 'interval', hours=1, id='crawler_job',
                      next_run_time=datetime.now())  # run immediately on first start
    scheduler.start()
    st.session_state.scheduler_started = True
    st.session_state.scheduler = scheduler
    log.info("APScheduler started — crawler will run now and then every hour")

# ==================== TABS ====================
tab1, tab2, tab3 = st.tabs(["🗺️ Live Threat Map", "📋 Ereignis-Protokoll", "⚙️ Status & Debug"])

with tab1:
    st.subheader("Live Threat Map – Europa (DACH Fokus)")
    m = folium.Map(location=[49.0, 9.5], zoom_start=5.5, tiles="cartodb dark_matter")
    df = pd.read_sql("SELECT * FROM incidents ORDER BY timestamp DESC", conn)

    placed = 0
    for _, row in df.iterrows():
        lat = row.get("lat")
        lon = row.get("lon")
        # Skip rows without valid coordinates rather than stacking them all at 48/8
        if not lat or not lon:
            continue
        color = "red" if row["category"] in [
            "Brandanschlag", "Sabotage", "Gewalt", "Militante Aktion", "Aufruf zu Gewalt"
        ] else "orange"
        folium.Marker(
            location=[lat, lon],
            popup=(
                f"<b>{row['date']}</b><br>"
                f"<b>{row['location']}, {row['country']}</b><br>"
                f"<b>{row['category']}</b><br>"
                f"{row['description'][:200]}"
            ),
            icon=folium.Icon(color=color, icon="exclamation-triangle", prefix="fa")
        ).add_to(m)
        placed += 1

    st_folium(m, width=1450, height=740)
    if placed == 0 and not df.empty:
        st.info(f"{len(df)} Ereignisse gespeichert, aber keine mit Koordinaten. Geocoding läuft beim nächsten Crawl.")

with tab2:
    st.subheader("Vollständiges Ereignis-Protokoll")
    df2 = pd.read_sql(
        "SELECT date, location, country, category, description, source FROM incidents ORDER BY timestamp DESC",
        conn
    )
    if df2.empty:
        st.image("empty-state.png", width=500)
        st.info("Noch keine Ereignisse erfasst")
    else:
        st.dataframe(df2, use_container_width=True, hide_index=True)

with tab3:
    st.subheader("⚙️ Crawler Status & Debug")

    # Last crawl time
    row = conn.execute("SELECT value FROM metadata WHERE key = 'last_crawl'").fetchone()
    if row:
        st.success(f"✅ Letzter Crawl: {row[0]}")
        last = datetime.fromisoformat(row[0])
        next_run = last + timedelta(hours=23)
        st.info(f"Nächster Crawl geplant: {next_run.strftime('%Y-%m-%d %H:%M')}")
    else:
        st.warning("⚠️ Noch kein Crawl durchgeführt — läuft gleich im Hintergrund")

    # Stats
    total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    col_a, col_b = st.columns(2)
    col_a.metric("Erfasste Ereignisse", total)
    col_b.metric("Datenbank", DB_PATH)

    # API key check
    st.subheader("API Key")
    api_key = os.getenv("GROK_API_KEY")
    if api_key:
        st.success(f"✅ GROK_API_KEY gesetzt ({len(api_key)} Zeichen)")
    else:
        st.error("❌ GROK_API_KEY NICHT gesetzt! → Render Dashboard → Environment → Add Variable")

    # Manual trigger
    st.subheader("Manueller Crawl")
    col1b, col2b = st.columns(2)
    with col1b:
        if st.button("🔄 Alle Quellen crawlen"):
            with st.spinner("Crawle alle Quellen..."):
                scrape_indymedia()
                scrape_barrikade()
                update_last_crawl()
            st.success("Crawl abgeschlossen!")
            st.rerun()
    with col2b:
        if st.button("🗑️ Datenbank leeren"):
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM metadata")
            conn.commit()
            st.warning("Datenbank geleert.")
            st.rerun()

st.caption("LEX EUROPE • OSINT • SEC")
