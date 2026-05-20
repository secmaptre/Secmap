import streamlit as st
import pandas as pd
import sqlite3
import folium
from streamlit_folium import st_folium
from datetime import datetime

st.set_page_config(
    page_title="LEX EUROPE",
    page_icon="eye-only.png",          # Favicon
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ==================== HEADER ====================
col1, col2 = st.columns([1, 4])
with col1:
    st.image("logo-main.png", width=210)

with col2:
    st.title("LEX EUROPE")
    st.markdown("**Threat Map • Gewalttätiger Linksextremismus in Europa**")
    st.caption("Fokus: DACH • Schweiz • Echtzeit-Dokumentation")

# Datenbank
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
        timestamp TEXT
    )''')
    conn.commit()

init_db()

# ==================== TABS ====================
tab1, tab2 = st.tabs(["🗺️ Live Threat Map", "📋 Ereignis-Protokoll"])

# ==================== LIVE MAP ====================
with tab1:
    st.subheader("Live Threat Map – Europa (DACH Fokus)")
    
    m = folium.Map(
        location=[49.0, 9.5], 
        zoom_start=5.5, 
        tiles="cartodb dark_matter"
    )
    
    df = pd.read_sql("SELECT * FROM incidents ORDER BY date DESC", conn)
    
    for _, row in df.iterrows():
        color = "red" if row["category"] in ["Brandanschlag", "Sabotage", "Gewalt", "Militante Aktion", "Aufruf zu Gewalt"] else "orange"
        folium.Marker(
            location=[row.get("lat", 48.0), row.get("lon", 8.0)],
            popup=f"""
            <b>{row['date']}</b><br>
            <b>{row['location']}, {row['country']}</b><br>
            <b>{row['category']}</b><br>
            {row['description']}
            """,
            icon=folium.Icon(color=color, icon="exclamation-triangle", prefix="fa")
        ).add_to(m)
    
    st_folium(m, width=1450, height=740)

# ==================== PROTOKOLL ====================
with tab2:
    st.subheader("Vollständiges Ereignis-Protokoll")
    df = pd.read_sql("""
        SELECT date, location, country, category, description, source 
        FROM incidents 
        ORDER BY date DESC
    """, conn)
    
    if df.empty:
        st.image("empty-state.png", width=500)
        st.info("Noch keine Ereignisse erfasst. Der automatische Crawler läuft im Hintergrund.")
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)

# Footer
st.divider()
st.caption("LEX EUROPE Threat Map • Automatischer KI-Crawler aktiv • Nur öffentliche Quellen")
