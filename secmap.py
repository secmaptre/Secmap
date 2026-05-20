import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3

st.set_page_config(page_title="LEX EUROPE Threat Map", layout="wide")
st.title("🔴 LEX EUROPE - Linksextremismus Threat Map")
st.caption("Fokus: Europa • DACH • Schweiz")

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

# ==================== ROTIERENDER GLOBUS ====================
st.subheader("🌍 Europa Threat Globe (DACH + Schweiz)")

# Einfachere, stabilere Version
globe_html = """
<iframe src="https://globalthreatmap.up.railway.app/" width="100%" height="750" frameborder="0" allowfullscreen></iframe>
<p style="text-align:center; color:#666; margin-top:10px;">
    <small>Demo-Globus (wird später durch eigenen ersetzt)</small>
</p>
"""

st.components.v1.html(globe_html, height=780)

# ==================== DEINE APP ====================
tab1, tab2 = st.tabs(["📊 Archiv", "📩 Neue Meldung"])

with tab1:
    df = pd.read_sql("SELECT date, location, category, description, source FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df, use_container_width=True)

with tab2:
    st.subheader("Neue Meldung")
    with st.form("meldung"):
        date = st.date_input("Datum", datetime.today())
        location = st.text_input("Ort (z.B. Langstrasse, Zürich)")
        category = st.selectbox("Kategorie", ["Schmiererei", "Farbbeutel", "Brandanschlag", "Sabotage", "Gewalt", "Sonstiges"])
        desc = st.text_area("Beschreibung")
        
        if st.form_submit_button("Speichern"):
            conn.execute('INSERT INTO incidents (date, location, category, description, timestamp) VALUES (?,?,?,?,?)',
                        (str(date), location, category, desc, datetime.now().isoformat()))
            conn.commit()
            st.success("Gespeichert!")

st.caption("Globus wird noch optimiert")
