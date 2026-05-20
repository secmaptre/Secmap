import streamlit as st
import pandas as pd
import sqlite3
import requests
from bs4 import BeautifulSoup
import time
import threading
from datetime import datetime, timedelta
import os
import folium
from streamlit_folium import st_folium

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
conn = sqlite3.connect('lex_threat.db', check_same_thread=False)

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

# ==================== GROK API ====================
def classify_with_ai(text):
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        return {"land": "Unbekannt", "kategorie": "Unklassifiziert", "ort": "Unbekannt"}
    
    prompt = f"""
    Analysiere folgenden Text und gib NUR gültiges JSON zurück:
    {text}

    JSON Format:
    {{"land": "DE / AT / CH / Andere", "kategorie": "Brandanschlag / Sabotage / Gewalt / Schmiererei / Aufruf zu Gewalt / Militante Aktion / Sonstiges", "ort": "Stadt oder Region"}}
    """
    try:
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "grok-4", "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "max_tokens": 250},
            timeout=12
        )
        result = response.json()["choices"][0]["message"]["content"].strip()
        import json
        return json.loads(result)
    except:
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
    conn.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_crawl', ?)", 
                (datetime.now().isoformat(),))
    conn.commit()

# ==================== ECHTER CRAWLER ====================
KEYWORDS = ["brandanschlag", "sabotage", "schmiererei", "graffiti", "gewalt", "prügelei", "antifa", "militante aktion", "direkte aktion", "aufruf zu gewalt"]

def scrape_indymedia():
    try:
        r = requests.get("https://de.indymedia.org/", timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, 'html.parser')
        articles = soup.find_all('div', class_='article') or soup.find_all('article')
        for article in articles[:15]:
            title_tag = article.find('h2') or article.find('h3') or article.find('a')
            text = (title_tag.get_text(strip=True) if title_tag else "") + " " + article.get_text(strip=True)
            if any(kw in text.lower() for kw in KEYWORDS):
                ai = classify_with_ai(text[:800])
                if ai["kategorie"] != "Unklassifiziert":
                    conn.execute("""INSERT OR IGNORE INTO incidents 
                        (date, location, country, category, description, source, timestamp)
                        VALUES (date('now'), ?, ?, ?, ?, ?, datetime('now'))""",
                        (ai["ort"], ai["land"], ai["kategorie"], text[:500], "de.indymedia.org"))
                    conn.commit()
    except:
        pass

def scrape_barrikade():
    try:
        r = requests.get("https://barrikade.info/", timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, 'html.parser')
        articles = soup.find_all('div', class_='node') or soup.find_all('article')
        for article in articles[:12]:
            title = article.get_text(strip=True)
            if any(kw in title.lower() for kw in KEYWORDS):
                ai = classify_with_ai(title[:800])
                if ai["kategorie"] != "Unklassifiziert":
                    conn.execute("""INSERT OR IGNORE INTO incidents 
                        (date, location, country, category, description, source, timestamp)
                        VALUES (date('now'), ?, ?, ?, ?, ?, datetime('now'))""",
                        (ai["ort"], ai["land"], ai["kategorie"], title[:500], "barrikade.info"))
                    conn.commit()
    except:
        pass

def run_crawler():
    if should_run_crawler():
        scrape_indymedia()
        scrape_barrikade()
        update_last_crawl()

# ==================== BACKGROUND THREAD ====================
def auto_crawler():
    while True:
        run_crawler()
        time.sleep(3600)  # prüft jede Stunde, ob 23h vorbei sind

if "crawler_started" not in st.session_state:
    threading.Thread(target=auto_crawler, daemon=True).start()
    st.session_state.crawler_started = True

# ==================== TABS ====================
tab1, tab2 = st.tabs(["🗺️ Live Threat Map", "📋 Ereignis-Protokoll"])

with tab1:
    st.subheader("Live Threat Map – Europa (DACH Fokus)")
    m = folium.Map(location=[49.0, 9.5], zoom_start=5.5, tiles="cartodb dark_matter")
    df = pd.read_sql("SELECT * FROM incidents ORDER BY timestamp DESC", conn)
    
    for _, row in df.iterrows():
        color = "red" if row["category"] in ["Brandanschlag", "Sabotage", "Gewalt", "Militante Aktion", "Aufruf zu Gewalt"] else "orange"
        folium.Marker(
            location=[row.get("lat", 48.0), row.get("lon", 8.0)],
            popup=f"<b>{row['date']}</b><br><b>{row['location']}, {row['country']}</b><br><b>{row['category']}</b><br>{row['description']}",
            icon=folium.Icon(color=color, icon="exclamation-triangle", prefix="fa")
        ).add_to(m)
    
    st_folium(m, width=1450, height=740)

with tab2:
    st.subheader("Vollständiges Ereignis-Protokoll")
    df = pd.read_sql("SELECT date, location, country, category, description, source FROM incidents ORDER BY timestamp DESC", conn)
    if df.empty:
        st.image("empty-state.png", width=500)
        st.info("Noch keine Ereignisse erfasst")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

st.caption("LEX EUROPE • OSINT • SEC")
