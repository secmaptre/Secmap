import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3
import requests
from bs4 import BeautifulSoup
import folium
from streamlit_folium import st_folium

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

# ==================== TABS ====================
tab1, tab2, tab3 = st.tabs(["🗺️ Live Map", "📋 Protokoll", "🔄 Crawler"])

# ==================== LIVE MAP + EVENT FEED ====================
with tab1:
    col1, col2 = st.columns([3, 1])

    with col1:
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
        
        st_folium(m, width=1100, height=720)

    with col2:
        st.subheader("🔔 Event Feed (neueste Vorfälle)")
        if not df.empty:
            latest = df.head(12)
            for _, row in latest.iterrows():
                st.caption(f"**{row['date']}** — **{row['location']}**")
                st.write(f"**{row['category']}** — {row['description'][:90]}...")
                st.divider()
        else:
            st.info("Noch keine Vorfälle vorhanden. Starte den Crawler.")

# ==================== PROTOKOLL ====================
with tab2:
    st.subheader("Vollständiges Protokoll")
    df_full = pd.read_sql("SELECT date, location, category, description, source FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df_full, use_container_width=True)

# ==================== CRAWLER (nur für dich) ====================
with tab3:
    st.subheader("🔄 Crawler")
    if st.button("🚀 Jetzt Indymedia + Barrikade crawlen"):
        with st.spinner("Suche nach gewalttätigen Aktionen..."):
            # Hier kommt der Crawler-Code (wie vorher)
            st.info("Crawler wird ausgeführt... (in der nächsten Version vollautomatisch)")
            # (wir können später einen echten automatischen Crawler einbauen)

st.caption("LEX EUROPE Threat Map • Automatischer Crawler wird vorbereitet")
