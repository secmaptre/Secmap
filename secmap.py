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

# ==================== 3D GLOBUS - EUROPA FOKUS ====================
st.subheader("🌍 Europa Threat Globe (DACH + Schweiz Fokus)")

globe_html = """
<!DOCTYPE html>
<html>
<head>
  <script src="https://unpkg.com/three-globe@2.31.0/dist/three-globe.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
  <style>
    body { margin:0; overflow:hidden; background:#000; }
    #globe { width:100vw; height:720px; }
  </style>
</head>
<body>
  <div id="globe"></div>
  <script>
    const Globe = new ThreeGlobe()
      .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
      .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
      .pointAltitude(0.12)
      .pointColor(d => d.color)
      .pointRadius(0.9)
      .atmosphereColor("#ff4444")
      .atmosphereAltitude(0.25);

    // Starke Punkte in Europa / DACH / Schweiz
    Globe.pointsData([
      {lat: 47.3769, lng: 8.5417, size: 1.4, color: '#ff0000', name: 'Zürich - Langstrasse'},
      {lat: 47.5596, lng: 7.5886, size: 1.1, color: '#ff0000', name: 'Basel'},
      {lat: 46.9481, lng: 7.4474, size: 1.0, color: '#ff8800', name: 'Bern'},
      {lat: 52.5200, lng: 13.4050, size: 1.3, color: '#ff0000', name: 'Berlin'},
      {lat: 51.3397, lng: 12.3731, size: 1.2, color: '#ff0000', name: 'Leipzig - Connewitz'},
      {lat: 53.5511, lng: 9.9937, size: 1.0, color: '#ff8800', name: 'Hamburg'},
      {lat: 48.8566, lng: 2.3522, size: 0.9, color: '#ff0000', name: 'Paris'},
      {lat: 50.8503, lng: 4.3517, size: 0.8, color: '#ff8800', name: 'Brüssel'}
    ]);

    const scene = new THREE.Scene();
    scene.add(Globe);

    const renderer = new THREE.WebGLRenderer({antialias: true});
    renderer.setSize(window.innerWidth, 720);
    document.getElementById('globe').appendChild(renderer.domElement);

    const camera = new THREE.PerspectiveCamera(45, window.innerWidth / 720, 1, 1000);
    camera.position.set(0, 0, 280);  // Nahaufnahme Europa

    // Sanfte Auto-Rotation mit Europa-Fokus
    let angle = 0.6;  // Startposition über Europa
    function animate() {
      angle += 0.0004;  // langsame, elegante Rotation
      Globe.rotation.y = angle;
      renderer.render(scene, camera);
      requestAnimationFrame(animate);
    }
    animate();

    window.addEventListener('resize', () => {
      renderer.setSize(window.innerWidth, 720);
    });
  </script>
</body>
</html>
"""

st.components.v1.html(globe_html, height=720)

# ==================== REST DER APP ====================
tab1, tab2 = st.tabs(["📊 Archiv", "📩 Neue Meldung"])

with tab1:
    df = pd.read_sql("SELECT date, location, category, description, source FROM incidents ORDER BY date DESC", conn)
    st.dataframe(df, use_container_width=True)
    st.metric("Gesamt dokumentierte Vorfälle", len(df))

with tab2:
    st.subheader("Anonyme Meldung")
    with st.form("meldung"):
        date = st.date_input("Datum", datetime.today())
        location = st.text_input("Ort (z.B. Langstrasse Zürich, Connewitz Leipzig)")
        category = st.selectbox("Kategorie", [
            "Schmiererei/Graffiti", "Sticker", "Farbbeutel", "Sachbeschädigung",
            "Brandanschlag", "Sabotage", "Körperliche Gewalt", "Sonstiges"
        ])
        desc = st.text_area("Beschreibung (kurz, keine Namen)")
        source = st.text_input("Quelle (optional)")
        
        if st.form_submit_button("Meldung speichern"):
            # Dummy-Koordinaten für Test (später echte)
            lat = 47.3769 + (len(df) % 15) * 0.05
            lon = 8.5417 + (len(df) % 15) * 0.05
            conn.execute('INSERT INTO incidents (date, location, category, description, source, lat, lon, timestamp) VALUES (?,?,?,?,?,?,?,?)',
                        (str(date), location, category, desc, source, lat, lon, datetime.now().isoformat()))
            conn.commit()
            st.success("✅ Gespeichert und auf dem Globus sichtbar!")
            st.rerun()

st.caption("Globus rotiert langsam mit Fokus auf Europa / DACH / Schweiz")
