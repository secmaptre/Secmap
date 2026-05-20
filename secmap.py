import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3
import folium
from streamlit_folium import st_folium

st.set_page_config(page_title="LEX EUROPE Threat Map", layout="wide")
st.title("🔴 LEX EUROPE - Linksextremismus Threat Map")
st.caption("Fokus: Europa • DACH • Schweiz • Nur öffentliche Quellen")

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
tab1, tab2, tab3, tab4 = st.tabs(["🗺️ Live Map", "📋 Protokoll", "🔮 Forecasts", "✉️ Kontakt"])

# ==================== LIVE MAP + EVENT FEED ====================
with tab1:
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Europa Threat Map")
        m = folium.Map(location=[47.5, 8.5], zoom_start=6, tiles="cartodb dark_matter")
        
        df = pd.read_sql("SELECT * FROM incidents ORDER BY date DESC", conn)
        for _, row in df.iterrows():
            color = "red" if "Brand" in row['category'] or "Gewalt" in row['category'] else "orange"
            folium.Marker(
                location=[row.get('lat', 47.5), row.get('lon', 8.5)],
                popup=f"<b>{row['date']}</b><br>{row['location']}<br><b>{row['category']}</b><br>{row['description']}",
                icon=folium.Icon(color=color, icon="exclamation-triangle")
            ).add_to(m)
        
        st_folium(m, width=1100, height=650)
    
    with col2:
        st.subheader("Event Feed (neueste Vorfälle)")
        if not df.empty:
            latest = df.head(10)
            for _, row in latest.iterrows():
                st.caption(f"**{row['date']}** — {row['location']}")
                st.write(f"**{row['category']}** | {row['description'][:80]}...")
                st.divider()
        else:
            st.info("Noch keine Vorfälle vorhanden.")

# ==================== PROTOKOLL ====================
with tab2:
    st.subheader("Vollständiges Protokoll")
    df_full = pd.read_sql("SELECT date, location, category, description, source FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df_full, use_container_width=True)

# ==================== FORECASTS ====================
with tab3:
    st.subheader("🔮 Forecasts & Trends")
    st.info("Hier kommen später Vorhersagen, Hotspot-Analysen und Risikobewertungen.")
    st.write("Aktuell noch in Entwicklung.")

# ==================== KONTAKT ====================
with tab4:
    st.subheader("✉️ Gewalttätiger Extremismus melden")
    st.markdown("### Kontakt")
    st.write("**Email:** contact-lexmap@proton.me")   # Du kannst das später ändern
    st.write("Meldungen werden vertraulich behandelt und nur öffentliche Vorfälle verarbeitet.")
    st.caption("Keine persönlichen Daten. Nur öffentliche Aktivitäten.")

st.caption("LEX EUROPE Threat Map • Läuft auf Streamlit Cloud")
