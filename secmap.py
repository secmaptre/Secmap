import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3

st.set_page_config(page_title="LEX EUROPE", layout="wide")
st.title(" LEX EUROPE - Gewalttätiger Linksexrtemismus")
st.caption("Europa • Deutschland • Österreich • Schweiz ")

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

# ==================== SAUBERER EUROPA-GLOBUS ====================
st.subheader("🌍 Europa Threat Globe")

custom_globe = """
<div style="width:100%; height:720px; background:#000; position:relative;">
  <iframe src="https://three-globe.com/" width="100%" height="720" frameborder="0" style="filter: hue-rotate(200deg) saturate(1.5);"></iframe>
  <div style="position:absolute; top:20px; left:20px; color:white; font-size:18px; font-weight:bold; text-shadow: 0 0 10px red;">
    LEX EUROPE • DACH + Schweiz Fokus
  </div>
</div>
"""

st.components.v1.html(custom_globe, height=750)

# ==================== DEINE APP ====================
tab1, tab2 = st.tabs(["📊 Archiv", "📩 Neue Meldung"])

with tab1:
    df = pd.read_sql("SELECT date, location, category, description FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df, use_container_width=True)

with tab2:
    st.subheader("Neue Meldung eintragen")
    with st.form("meldung"):
        date = st.date_input("Datum", datetime.today())
        location = st.text_input("Ort (z.B. Langstrasse Zürich)")
        category = st.selectbox("Kategorie", [
            "Schmiererei/Graffiti", "Sticker", "Farbbeutel", "Sachbeschädigung", 
            "Brandanschlag", "Sabotage", "Gewalt", "Sonstiges"
        ])
        desc = st.text_area("Kurze Beschreibung")
        
        if st.form_submit_button("Speichern"):
            # Dummy-Koordinaten (später echte)
            lat = 47.37 + (len(df) * 0.03)
            lon = 8.54 + (len(df) * 0.03)
            conn.execute('INSERT INTO incidents (date, location, category, description, lat, lon, timestamp) VALUES (?,?,?,?,?,?,?)',
                        (str(date), location, category, desc, lat, lon, datetime.now().isoformat()))
            conn.commit()
            st.success("✅ Gespeichert!")

st.caption("Globus wird noch individuell angepasst")
