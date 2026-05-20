import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3
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

# ==================== TABS (sauber & professionell) ====================
tab1, tab2, tab3, tab4 = st.tabs([
    "🗺️ Live Threat Map",
    "📋 Protokoll",
    "🔮 Forecasts & Trends",
    "✉️ Kontakt"
])

# ==================== LIVE MAP (groß) ====================
with tab1:
    st.subheader("Aktuelle Bedrohungslage – Europa / DACH / Schweiz")
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

# ==================== PROTOKOLL ====================
with tab2:
    st.subheader("Vollständiges Protokoll aller dokumentierten Vorfälle")
    df = pd.read_sql("SELECT date, location, category, description, source FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df, use_container_width=True)

# ==================== FORECASTS ====================
with tab3:
    st.subheader("🔮 Forecasts & Risiko-Trends")
    st.info("Dieser Bereich wird später mit Hotspot-Analysen und Vorhersagen gefüllt.")

# ==================== KONTAKT ====================
with tab4:
    st.subheader("Gewalttätigen Linksextremismus melden")
    st.write("**E-Mail:** contact-lexmap@proton.me")
    st.caption("Nur öffentliche Vorfälle werden verarbeitet. Vertraulich.")

st.caption("LEX EUROPE Threat Map • Automatische Erfassung im Hintergrund")
