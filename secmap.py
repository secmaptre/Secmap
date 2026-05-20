import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3
import folium
from streamlit_folium import st_folium

st.set_page_config(page_title="LEX EUROPE Threat Map", layout="wide")
st.title("🔴 LEX EUROPE - Linksextremismus Threat Map")
st.caption("Öffentliche Vorfälle • Zürich & DACH • Nur öffentliche Quellen")

# Datenbank
conn = sqlite3.connect('lex_threat.db', check_same_thread=False)

def init_db():
    conn.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY,
        date TEXT,
        location TEXT,
        category TEXT,
        description TEXT,
        source TEXT,
        url TEXT,
        lat REAL,
        lon REAL,
        timestamp TEXT
    )''')
    conn.commit()

init_db()

# Tabs
tab1, tab2, tab3 = st.tabs(["🗺️ Live Threat Map", "📊 Archiv & Statistik", "📩 Neue Meldung"])

# ==================== LIVE MAP ====================
with tab1:
    st.subheader("Aktuelle Threat Map")
    m = folium.Map(location=[46.95, 8.38], zoom_start=7, tiles="cartodb dark_matter")
    
    df = pd.read_sql("SELECT * FROM incidents", conn)
    for _, row in df.iterrows():
        color = "red" if any(x in row['category'] for x in ["Brand", "Gewalt", "Sabotage"]) else "orange"
        folium.Marker(
            location=[row.get('lat', 46.95), row.get('lon', 8.38)],
            popup=f"<b>{row['date']}</b><br>{row['location']}<br><b>{row['category']}</b><br>{row['description']}",
            tooltip=row['location'],
            icon=folium.Icon(color=color, icon="exclamation-triangle", prefix="fa")
        ).add_to(m)
    
    st_folium(m, width=1300, height=700)

# ==================== ARCHIV ====================
with tab2:
    st.subheader("Alle dokumentierten Vorfälle")
    df = pd.read_sql("SELECT date, location, category, description, source FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df, use_container_width=True)
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Gesamt Vorfälle", len(df))
    with col2:
        st.metric("Diese Woche", len(df[df['date'].str.contains(str(datetime.now().year))]))  # grob

# ==================== MELDESTELLE ====================
with tab3:
    st.subheader("Anonyme Meldung eintragen")
    with st.form("meldung"):
        date = st.date_input("Datum", datetime.today())
        location = st.text_input("Ort (z.B. Langstrasse Zürich, Connewitz Leipzig)")
        category = st.selectbox("Art", [
            "Schmiererei/Graffiti", "Sticker", "Farbbeutel", "Sachbeschädigung",
            "Brandanschlag", "Sabotage", "Körperliche Gewalt", "Sonstiges"
        ])
        desc = st.text_area("Beschreibung (kurz, keine Namen von Personen)")
        source = st.text_input("Quelle (z.B. selbst gesehen, Indymedia)")
        
        if st.form_submit_button("Meldung speichern"):
            conn.execute('''INSERT INTO incidents 
                (date, location, category, description, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (str(date), location, category, desc, source, datetime.now().isoformat()))
            conn.commit()
            st.success("✅ Meldung gespeichert!")
            st.rerun()