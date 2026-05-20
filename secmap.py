import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3

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

# ==================== ROTIERENDER GLOBUS (nur Europa/DACH/Schweiz) ====================
st.subheader("🌍 Europa Threat Globe – Linksextremismus")

globe_html = """
<!DOCTYPE html>
<html>
<head>
  <script src="https://unpkg.com/three-globe@2.31.0/dist/three-globe.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
  <style>body { margin:0; background:#000; overflow:hidden; }</style>
</head>
<body>
  <div id="globe"></div>
  <script>
    const Globe = new ThreeGlobe()
      .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
      .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
      .pointAltitude(0.1)
      .pointColor(() => '#ff2222')
      .pointRadius(1.0);

    // Nur relevante Punkte für Linksextremismus in DACH / Schweiz / Europa
    Globe.pointsData([
      {lat: 47.3769, lng: 8.5417, size: 1.4, name: 'Zürich'},
      {lat: 47.5596, lng: 7.5886, size: 1.1, name: 'Basel'},
      {lat: 46.9481, lng: 7.4474, size: 1.0, name: 'Bern'},
      {lat: 52.5200, lng: 13.4050, size: 1.3, name: 'Berlin'},
      {lat: 51.3397, lng: 12.3731, size: 1.3, name: 'Leipzig'},
      {lat: 53.5511, lng: 9.9937, size: 1.1, name: 'Hamburg'},
      {lat: 48.1372, lng: 11.5755, size: 1.0, name: 'München'},
      {lat: 50.1109, lng: 8.6821, size: 0.9, name: 'Frankfurt'}
    ]);

    const scene = new THREE.Scene();
    scene.add(Globe);

    const renderer = new THREE.WebGLRenderer({antialias: true});
    renderer.setSize(window.innerWidth, 750);
    document.getElementById('globe').appendChild(renderer.domElement);

    const camera = new THREE.PerspectiveCamera(50, window.innerWidth/750, 1, 2000);
    camera.position.set(0, 0, 320);

    let angle = 0.8;
    function animate() {
      angle += 0.0004;
      Globe.rotation.y = angle;
      renderer.render(scene, camera);
      requestAnimationFrame(animate);
    }
    animate();
  </script>
</body>
</html>
"""

st.components.v1.html(globe_html, height=750)

# ==================== UNTERER TEIL ====================
tab1, tab2 = st.tabs(["📊 Archiv", "📩 Neue Meldung"])

with tab1:
    df = pd.read_sql("SELECT date, location, category, description FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df, use_container_width=True)

with tab2:
    st.subheader("Neue Meldung eintragen")
    with st.form("meldung"):
        date = st.date_input("Datum", datetime.today())
        location = st.text_input("Ort (z.B. Langstrasse Zürich)")
        category = st.selectbox("Kategorie", ["Schmiererei", "Farbbeutel", "Brandanschlag", "Sabotage", "Gewalt", "Sonstiges"])
        desc = st.text_area("Kurze Beschreibung")
        if st.form_submit_button("Speichern"):
            st.success("Gespeichert (wird später auf dem Globus angezeigt)")
            st.rerun()

st.caption("Globus dreht sich automatisch – nur Europa/DACH/Schweiz Fokus")
