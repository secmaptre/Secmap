import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sqlite3
import requests
from bs4 import BeautifulSoup
import folium
from streamlit_folium import st_folium
import time
import threading

st.set_page_config(page_title="LEX EUROPE", layout="wide")

st.title("🔴 LEX EUROPE")
st.markdown("**Linksextremismus Threat Map • Europa • DACH • Schweiz**")

conn = sqlite3.connect('lex_threat.db', check_same_thread=False)

def init_db():
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY,
        date TEXT,
        location TEXT,
        category TEXT,
        description TEXT,
        source TEXT,
        lat REAL,
        lon REAL,
        timestamp TEXT
    )''')
    conn.commit()

init_db()

# ==================== HOTSPOTS ====================
HOTSPOTS = {
    "zürich": (47.3769, 8.5417), "langstrasse": (47.3769, 8.5417),
    "basel": (47.5596, 7.5886), "bern": (46.9481, 7.4474),
    "berlin": (52.5200, 13.4050), "leipzig": (51.3397, 12.3731),
    "connewitz": (51.3397, 12.3731), "hamburg": (53.5511, 9.9937),
    "münchen": (48.1372, 11.5755), "frankfurt": (50.1109, 8.6821),
    "dresden": (51.0504, 13.7373), "köln": (50.9375, 6.9603),
}

def get_coordinates(text):
    if not text:
        return 47.5, 8.5
    text = text.lower()
    for city, coords in HOTSPOTS.items():
        if city in text:
            return coords
    return 47.5, 8.5

# ==================== CRAWLER FUNKTION ====================
def crawler_job():
    while True:
        try:
            urls = ["https://de.indymedia.org/", "https://barrikade.info/"]
            new_count = 0

            for url in urls:
                r = requests.get(url, timeout=20, headers={'User-Agent': 'Mozilla/5.0'})
                soup = BeautifulSoup(r.text, 'html.parser')
                articles = soup.find_all(['article', 'div', 'h2'], limit=40)

                for art in articles:
                    text = art.get_text(strip=True)
                    if len(text) < 40:
                        continue
                    lower = text.lower()

                    if any(word in lower for word in ["brandanschlag", "angezündet", "sabotage", "sabotiert", "farbbeutel", "angriff", "überfall", "zerstört", "direct action"]):
                        if any(w in lower for w in ["brand", "angezündet"]):
                            category = "Brandanschlag"
                        elif any(w in lower for w in ["sabot", "zerstört"]):
                            category = "Sabotage"
                        elif any(w in lower for w in ["angriff", "überfall", "gewalt"]):
                            category = "Gewalt"
                        else:
                            category = "Militante Aktion"

                        location = "Unbekannt"
                        for city in ["Zürich", "Berlin", "Leipzig", "Hamburg", "München", "Frankfurt", "Dresden", "Basel", "Bern"]:
                            if city.lower() in lower:
                                location = city
                                break

                        lat, lon = get_coordinates(location)

                        conn.execute('''INSERT OR IGNORE INTO incidents 
                            (date, location, category, description, source, lat, lon, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                            (datetime.now().date().isoformat(), location, category, text[:250], url, lat, lon, datetime.now().isoformat()))
                        new_count += 1

            conn.commit()
            print(f"[{datetime.now()}] Crawler: {new_count} neue Vorfälle gefunden")

        except Exception as e:
            print(f"Crawler Fehler: {e}")

        time.sleep(1800)  # alle 30 Minuten crawlen (für Test erstmal alle 5 Minuten möglich)

# Background Thread starten
if "crawler_started" not in st.session_state:
    st.session_state.crawler_started = True
    threading.Thread(target=crawler_job, daemon=True).start()
    st.success("Automatischer Crawler im Hintergrund gestartet")

# ==================== TABS ====================
tab1, tab2 = st.tabs(["🗺️ Live Map", "📋 Protokoll"])

with tab1:
    st.subheader("Europa Threat Map")
    m = folium.Map(location=[47.5, 8.5], zoom_start=6, tiles="cartodb dark_matter")
    
    df = pd.read_sql("SELECT * FROM incidents ORDER BY date DESC", conn)
    for _, row in df.iterrows():
        color = "red" if any(x in str(row['category']).lower() for x in ["brand", "gewalt", "sabotage", "angriff"]) else "orange"
        folium.Marker(
            location=[row.get('lat', 47.5), row.get('lon', 8.5)],
            popup=f"<b>{row['date']}</b><br>{row['location']}<br><b>{row['category']}</b><br>{row['description']}",
            icon=folium.Icon(color=color)
        ).add_to(m)
    
    st_folium(m, width=1450, height=780)

with tab2:
    st.subheader("Vollständiges Protokoll")
    df = pd.read_sql("SELECT date, location, category, description, source FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df, use_container_width=True)

st.caption("LEX EUROPE Threat Map • Automatischer Crawler läuft im Hintergrund (alle 30 Minuten)")
