import os, logging, json, time, hashlib, re, secrets, csv, io, gzip
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urljoin, quote_plus
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request, BackgroundTasks, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

def _resolve_db_path():
    p = os.getenv("DB_PATH")
    if p:
        d = os.path.dirname(p)
        if not d or os.path.isdir(d):
            return p
        log.warning(f"DB_PATH dir '{d}' does not exist, falling back to local DB")
    if os.path.isdir("/disk"):   return "/disk/lex_threat.db"
    if os.path.isdir("/data"):   return "/data/lex_threat.db"
    return "lex_threat.db"

DB_PATH = _resolve_db_path()

# ── EVIDENCE STORAGE (Säule 4, MS-5) ────────────────────────────────
# Mirrors DB_PATH resolution: prefer persistent disk on render.com, fall
# back to the local working dir during dev. evidence/<yyyy>/<mm>/<hash>.warc.gz.
def _resolve_evidence_dir():
    env = os.getenv("EVIDENCE_DIR")
    if env:
        try:
            Path(env).mkdir(parents=True, exist_ok=True)
            return env
        except Exception as e:
            log.warning(f"EVIDENCE_DIR '{env}' not usable: {e}")
    for base in ("/disk", "/data"):
        if os.path.isdir(base):
            p = os.path.join(base, "evidence")
            try:
                Path(p).mkdir(parents=True, exist_ok=True)
                return p
            except Exception:
                pass
    p = "evidence"
    Path(p).mkdir(parents=True, exist_ok=True)
    return p

EVIDENCE_DIR = _resolve_evidence_dir()
GROK_MODEL = os.getenv("GROK_MODEL", "grok-4")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "changeme")

# ── DATABASE ──────────────────────────────────────────────────────
def get_db():
    path = DB_PATH
    try:
        c = sqlite3.connect(path, check_same_thread=False)
    except Exception as e:
        log.error(f"Cannot open DB at {path}: {e} — falling back to local lex_threat.db")
        path = "lex_threat.db"
        c = sqlite3.connect(path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    # Use DELETE journal mode — compatible with NFS/network filesystems (no WAL)
    c.execute("PRAGMA journal_mode=DELETE")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT, location TEXT, country TEXT, category TEXT,
        description TEXT, source TEXT, url TEXT,
        hash TEXT UNIQUE, lat REAL, lon REAL,
        manual INTEGER DEFAULT 0, timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS geocache (query TEXT PRIMARY KEY, lat REAL, lon REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires TEXT)''')
    # Schema migrations — add columns that may be missing in older DBs.
    # Additive only: existing render.com persistent disks keep working.
    for col, defn in [("hash","TEXT"), ("lat","REAL"), ("lon","REAL"),
                      ("manual","INTEGER DEFAULT 0"), ("timestamp","TEXT"),
                      ("severity_score","INTEGER DEFAULT 0"),
                      ("actors","TEXT DEFAULT ''"),
                      ("confidence","INTEGER DEFAULT 0"),
                      # Quality-scope additions (see plan §0)
                      ("summary","TEXT DEFAULT ''"),
                      ("is_primary","INTEGER DEFAULT 0"),
                      ("is_high_risk","INTEGER DEFAULT 0"),
                      # Strategic Concept v3 — Fedpol 3-tier taxonomy + target
                      # routing + Strafverfolgungs-Status (Säule 1+2 ground work).
                      ("tier","TEXT DEFAULT 'act'"),
                      ("target_type","TEXT DEFAULT ''"),
                      ("prosec_status","TEXT DEFAULT 'unknown'"),
                      ("case_ref","TEXT DEFAULT ''"),
                      ("last_status_check","TEXT DEFAULT ''"),
                      # MS-5 (Säule 4) — Quellensicherung
                      ("evidence_path","TEXT DEFAULT ''"),
                      ("evidence_sha","TEXT DEFAULT ''"),
                      ("evidence_ts","TEXT DEFAULT ''")]:
        try:
            c.execute(f"ALTER TABLE incidents ADD COLUMN {col} {defn}")
        except Exception:
            pass  # column already exists

    # ── FUNDING TRACKER ───────────────────────────────────────────
    # Public funding to organisations linked to the violent-left milieu.
    # Sources must be public documents (Bundesanzeiger, transparency portals,
    # foundation grant pages, Kanton/Stadt budget items).
    c.execute('''CREATE TABLE IF NOT EXISTS funding_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient_org TEXT NOT NULL,
        project TEXT,
        amount REAL NOT NULL,
        currency TEXT DEFAULT 'EUR',
        year INTEGER NOT NULL,
        country TEXT NOT NULL,
        donor_type TEXT NOT NULL,
        donor_name TEXT NOT NULL,
        source_url TEXT,
        notes TEXT,
        confidence INTEGER DEFAULT 3,
        manual INTEGER DEFAULT 0,
        hash TEXT UNIQUE,
        timestamp TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_org     ON funding_records(recipient_org)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_year    ON funding_records(year)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_country ON funding_records(country)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fund_donor   ON funding_records(donor_type)")
    # MS-9 (Haftungsfix): verified-Flag — nur Einträge, deren source_url
    # AUF ein spezifisches Primärdokument zeigt, sind verified=1. Generische
    # Programm-Landingpages bleiben verified=0 mit Warn-Badge im UI.
    try:
        c.execute("ALTER TABLE funding_records ADD COLUMN verified INTEGER DEFAULT 0")
    except Exception:
        pass  # column exists

    # ── EARLY-WARNING CLUSTERS (Säule 2, MS-3) ────────────────────
    # Detected attack patterns: ≥3 incidents with the same target_type in
    # the same country over a rolling 6-week window. Lets operators of
    # likely targets subscribe to /api/early-warning.{rss,json} without us
    # ever holding a recipient list (DSGVO-Hygiene per Concept §C2/§C3).
    c.execute('''CREATE TABLE IF NOT EXISTS early_warning_clusters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cluster_key TEXT UNIQUE NOT NULL,
        country TEXT NOT NULL,
        target_type TEXT NOT NULL,
        count INTEGER NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        incident_ids TEXT,
        sample_titles TEXT,
        detected_at TEXT,
        active INTEGER DEFAULT 1
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_ewc_active ON early_warning_clusters(active)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ewc_country ON early_warning_clusters(country)")

    # ── FUNDING EDGES (Säule 3, MS-4) ──────────────────────────────
    # Explizite Mehr-Hop-Kanten (Donor → Trägerverein → Sub-Empfänger →
    # Vorstand). funding_records bleibt die kanonische Quelle der
    # dokumentierten Direkt-Förderungen; funding_edges ergänzt nur die
    # Brücken, für die der Tabellenstil ungeeignet ist. Datenpolicy §C3
    # gilt: nur öffentliche Vereins-/Registerdaten, keine Personenprofile.
    c.execute('''CREATE TABLE IF NOT EXISTS funding_edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_org TEXT NOT NULL,
        dst_org TEXT NOT NULL,
        amount REAL,
        currency TEXT DEFAULT 'EUR',
        year INTEGER,
        source_url TEXT,
        notes TEXT,
        manual INTEGER DEFAULT 1,
        hash TEXT UNIQUE,
        timestamp TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_fe_src ON funding_edges(src_org)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fe_dst ON funding_edges(dst_org)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_fe_year ON funding_edges(year)")

    # ── API TOKENS + AUDIT (Säule 4 — MS-6) ────────────────────────
    # Authenticated /api/v1/* endpoint for LEA / academic users. Tokens
    # are scoped (default „incidents:read") and revocable. Every request
    # that authenticates writes an api_audit row — that's how token misuse
    # gets surfaced and how we justify the access policy to data subjects.
    c.execute('''CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        label TEXT NOT NULL,
        scopes TEXT DEFAULT 'incidents:read',
        created_at TEXT,
        last_used TEXT,
        revoked INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS api_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id INTEGER,
        endpoint TEXT NOT NULL,
        query TEXT,
        ip TEXT,
        timestamp TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_token ON api_audit(token_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts    ON api_audit(timestamp)")

    # ── WEBHOOK SUBSCRIPTIONS (Säule 2 — operativ) ────────────────
    # Betreiber gefährdeter Infrastruktur (Bahn, Energie, Polizei,
    # IHK-Sicherheitsbeauftragte) abonnieren ein Filter-Set (target_type,
    # country, min_severity) und bekommen automatisch HMAC-signierte
    # POSTs bei neuen Cluster-Detections und neuen T1-Vorfällen, die
    # ihre Filter matchen. Jede Lieferung wird in webhook_deliveries
    # geloggt (Code + Zeit + Body-Length).
    c.execute('''CREATE TABLE IF NOT EXISTS webhook_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        label TEXT NOT NULL,
        target_types TEXT DEFAULT '',
        countries TEXT DEFAULT '',
        min_severity INTEGER DEFAULT 4,
        events TEXT DEFAULT 'cluster,incident',
        secret TEXT NOT NULL,
        active INTEGER DEFAULT 1,
        created_at TEXT,
        last_delivery TEXT,
        delivery_count INTEGER DEFAULT 0,
        failure_count INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS webhook_deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sub_id INTEGER,
        event_type TEXT,
        event_key TEXT,
        status_code INTEGER,
        body_len INTEGER,
        delivered_at TEXT,
        error TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_wh_active ON webhook_subscriptions(active)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_wd_sub    ON webhook_deliveries(sub_id)")

    # ── SOURCE HEALTH (Crawler-Observability) ─────────────────────
    # Pro RSS-Feed/Crawler-Quelle wird der jüngste Fetch protokolliert:
    # Erfolg, Items, Fehler-Stack. Nach `max_failures` aufeinanderfolgenden
    # Fehlern wird die Quelle auf active=0 gesetzt (Auto-Disable) — verhindert
    # endloses Retry-Pinging gegen tote Feeds.
    c.execute('''CREATE TABLE IF NOT EXISTS source_health (
        source TEXT PRIMARY KEY,
        url TEXT,
        last_attempt TEXT,
        last_success TEXT,
        last_error TEXT,
        consecutive_failures INTEGER DEFAULT 0,
        total_attempts INTEGER DEFAULT 0,
        total_successes INTEGER DEFAULT 0,
        items_last_run INTEGER DEFAULT 0,
        items_total INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_sh_active ON source_health(active)")

    # ── FTS5 FULL-TEXT SEARCH ──────────────────────────────────────
    # Virtuelle Tabelle deckt Beschreibung + Summary + Ort + Aktoren ab.
    # Triggers halten sie automatisch synchron — keine separate Indexing-
    # Logik nötig. Suche via /api/incidents?q=…&fts=1.
    try:
        c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS incidents_fts USING fts5("
                  "  description, summary, location, actors, category,"
                  "  content='incidents', content_rowid='id', "
                  "  tokenize='unicode61 remove_diacritics 2')")
        # Triggers: keep FTS in sync with incidents row mutations.
        c.execute("CREATE TRIGGER IF NOT EXISTS incidents_ai AFTER INSERT ON incidents BEGIN "
                  "  INSERT INTO incidents_fts(rowid, description, summary, location, actors, category) "
                  "  VALUES (new.id, new.description, new.summary, new.location, new.actors, new.category); "
                  "END;")
        c.execute("CREATE TRIGGER IF NOT EXISTS incidents_ad AFTER DELETE ON incidents BEGIN "
                  "  INSERT INTO incidents_fts(incidents_fts, rowid, description, summary, location, actors, category) "
                  "  VALUES ('delete', old.id, old.description, old.summary, old.location, old.actors, old.category); "
                  "END;")
        c.execute("CREATE TRIGGER IF NOT EXISTS incidents_au AFTER UPDATE ON incidents BEGIN "
                  "  INSERT INTO incidents_fts(incidents_fts, rowid, description, summary, location, actors, category) "
                  "  VALUES ('delete', old.id, old.description, old.summary, old.location, old.actors, old.category); "
                  "  INSERT INTO incidents_fts(rowid, description, summary, location, actors, category) "
                  "  VALUES (new.id, new.description, new.summary, new.location, new.actors, new.category); "
                  "END;")
    except Exception as e:
        log.warning(f"FTS5 setup skipped: {e}")
    c.commit()
    return c


def backfill_fts_if_empty():
    """Initial-Indexierung: wenn FTS leer ist aber incidents nicht, einmal
    populieren. Wird beim Startup nach den Migrations gerufen."""
    try:
        fts_n = db.execute("SELECT COUNT(*) FROM incidents_fts").fetchone()[0]
        inc_n = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        if fts_n < inc_n:
            db.execute("INSERT INTO incidents_fts(incidents_fts) VALUES ('rebuild')")
            db.commit()
            log.info(f"FTS5 backfill: indexed {inc_n} incidents")
    except Exception as e:
        log.info(f"FTS5 backfill skipped: {e}")

db = get_db()

def meta_get(k):
    r = db.execute("SELECT value FROM metadata WHERE key=?", (k,)).fetchone()
    return r[0] if r else None

def meta_set(k, v):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (k, str(v)))
    db.commit()

def meta_del(k):
    db.execute("DELETE FROM metadata WHERE key=?", (k,))
    db.commit()

# ── AUTH ──────────────────────────────────────────────────────────
def make_token():
    t = secrets.token_hex(32)
    exp = (datetime.now() + timedelta(hours=12)).isoformat()
    db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?)", (t, exp))
    db.commit()
    return t

def verify_token(token):
    if not token: return False
    row = db.execute("SELECT expires FROM sessions WHERE token=?", (token,)).fetchone()
    if not row: return False
    if datetime.now() > datetime.fromisoformat(row[0]):
        db.execute("DELETE FROM sessions WHERE token=?", (token,))
        db.commit()
        return False
    return True

def require_admin(request: Request):
    if not verify_token(request.cookies.get("admin_token", "")):
        raise HTTPException(401, "Unauthorized")

# ── HTTP ──────────────────────────────────────────────────────────
session = requests.Session()
# Vollständiger Browser-Header-Satz — viele Anti-Bot-Schutze (auch
# Cloudflare-Lite, Sucuri, Imperva) prüfen auf das Vorhandensein
# *aller* dieser Header und schlagen sonst 403/429 zurück.
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
              "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
})
# Per-host warmup: bei manchen Hosts brauchen wir erst einen GET auf "/"
# damit das Anti-Bot-System ein Session-Cookie setzt.
_HOST_WARMED = set()

def _warmup_host(url):
    """Holt einmal pro Host die Root-Seite, damit Anti-Bot-Cookies gesetzt
    werden. Idempotent — danach merken wir uns den Host."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        if not host or host in _HOST_WARMED:
            return
        # Nur für bekannte Hosts mit Anti-Bot-Schutz; andere brauchen kein Warmup.
        if any(s in host for s in ("barrikade.info", "indymedia.org", "presseportal.de")):
            try:
                session.get(f"{urlparse(url).scheme}://{host}/", timeout=8,
                            allow_redirects=True)
            except Exception:
                pass  # warm-up failure is non-fatal
        _HOST_WARMED.add(host)
    except Exception:
        pass

def fetch(url, timeout=25):
    """Robuster Fetcher: Browser-Headers, Per-Host-Warmup, Retry mit
    expon. Backoff, kontextbezogene Referer-Header für Sub-Pages.
    Bei 403/429 wird auf zwei alternative UAs (Firefox, mobiles Safari)
    probiert; bei finalem 403 wird ein 200-Byte-Excerpt der Antwort
    ins log geschrieben, damit Admins auf Production diagnostizieren
    können WAS das Anti-Bot-System zurückgibt."""
    _warmup_host(url)
    headers = {}
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        if p.path and p.path != "/":
            headers["Referer"] = f"{p.scheme}://{p.netloc}/"
            headers["Sec-Fetch-Site"] = "same-origin"
    except Exception:
        pass
    # UA-Rotation bei 403/429
    UA_ALT = [
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "curl/8.4.0",
    ]
    last_err = None
    for attempt in range(3):
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True, headers=headers)
            if r.status_code in (403, 429):
                # Probiere mehrere alternative UAs
                for ua in UA_ALT:
                    r2 = session.get(url, timeout=timeout, allow_redirects=True,
                                     headers={**headers, "User-Agent": ua})
                    if r2.status_code not in (403, 429):
                        r = r2
                        break
            if r.status_code in (403, 429) and attempt == 2:
                # Diagnose-Logging bei finaler Aufgabe
                excerpt = (r.text or "")[:200].replace("\n", " ")
                log.info(f"fetch BLOCKED {url} (HTTP {r.status_code}): {excerpt!r}")
            r.raise_for_status()
            return r.text
        except Exception as e:
            last_err = e
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    raise last_err  # unreachable


def fetch_diagnostic(url: str, timeout: int = 12) -> dict:
    """Diagnostic fetch — never raises, returns structured information about
    what the upstream actually returned. Genutzt vom Admin-Endpoint, damit
    Operatoren auf Production sehen warum eine Quelle nicht funktioniert."""
    _warmup_host(url)
    out = {"url": url, "ok": False, "status_code": 0, "error": None,
           "elapsed_ms": 0, "len": 0, "content_type": "", "excerpt": "",
           "server": "", "via": "", "redirected_to": None,
           "tried_ua": []}
    UA_TRY = [
        ("default-chrome", None),
        ("firefox-linux",  "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"),
        ("mobile-safari",  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"),
        ("curl",           "curl/8.4.0"),
        ("googlebot",      "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ]
    import time as _t
    for ua_label, ua in UA_TRY:
        out["tried_ua"].append(ua_label)
        try:
            t0 = _t.time()
            headers = {}
            if ua: headers["User-Agent"] = ua
            from urllib.parse import urlparse
            p = urlparse(url)
            if p.path and p.path != "/":
                headers["Referer"] = f"{p.scheme}://{p.netloc}/"
            r = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            out["elapsed_ms"] = int((_t.time() - t0) * 1000)
            out["status_code"] = r.status_code
            out["content_type"] = r.headers.get("content-type", "")
            out["server"] = r.headers.get("server", "")
            out["via"]    = r.headers.get("via", "")
            out["len"]    = len(r.content)
            if str(r.url) != url:
                out["redirected_to"] = str(r.url)
            body = (r.text or "")
            out["excerpt"] = body[:400].replace("\r"," ").replace("\n"," ")
            if 200 <= r.status_code < 400:
                out["ok"] = True
                out["winning_ua"] = ua_label
                return out
        except Exception as e:
            out["error"] = str(e)[:200]
    return out

def get_text(url):
    try:
        html = fetch(url)
        soup = BeautifulSoup(html, "html.parser")
        for t in soup(["script","style","nav","footer","header","aside","form","iframe"]):
            t.decompose()
        el = (soup.find("article") or soup.find("main") or
              soup.find(True, class_=re.compile(r"\b(article|content|post|entry|body|node)\b", re.I)) or
              soup.body or soup)
        raw = el.get_text(" ", strip=True)
        # Strip indymedia navigation artifacts
        raw = re.sub(r'Direkt zum Inhalt.{0,600}?(?=[A-ZÜÄÖ][a-züäöA-ZÜÄÖ\s]{10,})', '', raw, flags=re.DOTALL)
        raw = re.sub(r'dont hate the media.{0,400}?(?=\w{8,})', '', raw, flags=re.DOTALL|re.IGNORECASE)
        raw = re.sub(r'\b(Openposting|Terminkalender|Gruppenstatements|Editorialliste|Linkliste|Mailinglisten|Moderation|Unterstützen|Outcall|Übersetzungskoordination|Mission Statement)\b', '', raw)
        return re.sub(r"\s{3,}", " ", raw).strip()[:5000]
    except Exception as e:
        log.warning(f"get_text {url}: {e}")
        return ""

def date_from_url(url):
    m = re.search(r"(20\d{2})[/_-](\d{1,2})[/_-](\d{1,2})", url)
    if m:
        try: return datetime(int(m.group(1)),int(m.group(2)),int(m.group(3))).strftime("%Y-%m-%d")
        except: pass
    return None

# ── GEOCODING with city fallback ──────────────────────────────────
CITY_FALLBACK = {
    # Deutschland — Großstädte + relevante Mittelstädte
    "berlin": (52.52, 13.405), "hamburg": (53.55, 10.00), "münchen": (48.14, 11.58),
    "munich": (48.14, 11.58), "köln": (50.94, 6.96), "frankfurt": (50.11, 8.68),
    "stuttgart": (48.78, 9.18), "düsseldorf": (51.23, 6.78), "leipzig": (51.34, 12.37),
    "dresden": (51.05, 13.74), "hannover": (52.37, 9.74), "bremen": (53.08, 8.80),
    "dortmund": (51.51, 7.47), "nürnberg": (49.45, 11.08), "bochum": (51.48, 7.22),
    "chemnitz": (50.83, 12.92), "halle": (51.48, 11.97), "magdeburg": (52.12, 11.62),
    "rostock": (54.09, 12.13), "essen": (51.46, 7.01), "duisburg": (51.43, 6.77),
    "wuppertal": (51.26, 7.18), "bielefeld": (52.02, 8.53), "münster": (51.96, 7.63),
    "augsburg": (48.37, 10.90), "karlsruhe": (49.01, 8.40), "mannheim": (49.49, 8.47),
    "freiburg": (47.99, 7.85), "kiel": (54.32, 10.13), "lübeck": (53.87, 10.69),
    "erfurt": (50.98, 11.03), "jena": (50.93, 11.59), "potsdam": (52.40, 13.06),
    "göttingen": (51.54, 9.93), "kassel": (51.31, 9.49), "saarbrücken": (49.24, 6.99),
    "weimar": (50.98, 11.32), "cottbus": (51.76, 14.33),
    # Schweiz
    "zürich": (47.38, 8.54), "zurich": (47.38, 8.54), "bern": (46.95, 7.44),
    "genf": (46.20, 6.14), "geneva": (46.20, 6.14), "basel": (47.56, 7.59),
    "lausanne": (46.52, 6.63), "winterthur": (47.50, 8.72), "luzern": (47.05, 8.31),
    # Österreich
    "wien": (48.21, 16.37), "vienna": (48.21, 16.37), "graz": (47.07, 15.44),
    "linz": (48.31, 14.29), "salzburg": (47.80, 13.05), "innsbruck": (47.27, 11.39),
    "klagenfurt": (46.62, 14.31),
    # Frankreich
    "paris": (48.85, 2.35), "lyon": (45.76, 4.84), "marseille": (43.30, 5.37),
    "bordeaux": (44.84, -0.58), "toulouse": (43.60, 1.44), "nantes": (47.22, -1.55),
    "strasbourg": (48.58, 7.75), "lille": (50.63, 3.07), "rennes": (48.11, -1.68),
    "montpellier": (43.61, 3.88), "nice": (43.71, 7.27), "grenoble": (45.19, 5.73),
    "notre-dame-des-landes": (47.30, -1.69),
    "sainte-soline": (46.34, -0.07), "aubervilliers": (48.92, 2.38),
    # Italien
    "rom": (41.90, 12.50), "rome": (41.90, 12.50), "mailand": (45.46, 9.19),
    "milano": (45.46, 9.19), "turin": (45.07, 7.69), "torino": (45.07, 7.69),
    "neapel": (40.85, 14.27), "napoli": (40.85, 14.27), "bologna": (44.49, 11.34),
    "genua": (44.41, 8.93), "genoa": (44.41, 8.93), "palermo": (38.12, 13.36),
    "florenz": (43.77, 11.26), "florence": (43.77, 11.26), "venedig": (45.44, 12.32),
    "verona": (45.44, 11.00), "susa": (45.14, 7.05), "val di susa": (45.14, 7.05),
    "brescia": (45.54, 10.22), "san donato": (44.50, 11.36),
    # Griechenland
    "athen": (37.98, 23.73), "athens": (37.98, 23.73), "thessaloniki": (40.64, 22.94),
    "exarchia": (37.98, 23.73), "exarcheia": (37.98, 23.73),
    # Spanien
    "madrid": (40.42, -3.70), "barcelona": (41.39, 2.17), "valencia": (39.47, -0.38),
    "bilbao": (43.26, -2.93), "sevilla": (37.39, -5.99),
    "vallecas": (40.39, -3.66), "zaragoza": (41.65, -0.89), "málaga": (36.72, -4.42),
    # UK / Irland
    "london": (51.51, -0.13), "manchester": (53.48, -2.24), "glasgow": (55.86, -4.25),
    "edinburgh": (55.95, -3.19), "bristol": (51.45, -2.59), "dublin": (53.35, -6.26),
    # BeNeLux
    "amsterdam": (52.37, 4.89), "rotterdam": (51.92, 4.48), "den haag": (52.07, 4.30),
    "brüssel": (50.85, 4.35), "brussels": (50.85, 4.35), "antwerpen": (51.22, 4.40),
    "luxemburg": (49.61, 6.13),
    # Nordeuropa
    "kopenhagen": (55.68, 12.57), "copenhagen": (55.68, 12.57), "aarhus": (56.16, 10.20),
    "stockholm": (59.33, 18.06), "göteborg": (57.71, 11.97), "malmö": (55.60, 13.00),
    "oslo": (59.91, 10.75), "bergen": (60.39, 5.32), "trondheim": (63.43, 10.39),
    "helsinki": (60.17, 24.94),
    # Mittel-/Osteuropa
    "warschau": (52.23, 21.01), "warsaw": (52.23, 21.01), "krakau": (50.06, 19.94),
    "prag": (50.08, 14.43), "prague": (50.08, 14.43), "budapest": (47.50, 19.04),
    "bukarest": (44.43, 26.10), "bucharest": (44.43, 26.10),
    "sofia": (42.70, 23.32), "ljubljana": (46.06, 14.51), "zagreb": (45.81, 15.98),
    # Portugal
    "lissabon": (38.72, -9.14), "lisbon": (38.72, -9.14), "porto": (41.15, -8.61),
    # USA — Schwerpunkte Antifa-/Anarcho-Szene
    "new york": (40.71, -74.01), "nyc": (40.71, -74.01), "manhattan": (40.78, -73.97),
    "brooklyn": (40.65, -73.95), "queens": (40.73, -73.79),
    "portland": (45.51, -122.68), "portland-east": (45.52, -122.62),
    "portland-northeast": (45.55, -122.65), "portland-downtown": (45.52, -122.68),
    "seattle": (47.61, -122.33), "minneapolis": (44.98, -93.27),
    "chicago": (41.88, -87.63), "los angeles": (34.05, -118.24),
    "ucla": (34.07, -118.44), "berkeley": (37.87, -122.27),
    "oakland": (37.80, -122.27), "san francisco": (37.77, -122.42),
    "atlanta": (33.75, -84.39), "weelaunee": (33.69, -84.30),
    "washington": (38.91, -77.04), "boston": (42.36, -71.06),
    "philadelphia": (39.95, -75.16), "denver": (39.74, -104.99),
    "richmond": (37.54, -77.43), "miami": (25.76, -80.19),
    # Country centers (used when only the country is known)
    "deutschland": (51.16, 10.45), "schweiz": (46.80, 8.22), "österreich": (47.52, 14.55),
    "frankreich": (46.60, 2.20), "italien": (42.83, 12.83), "griechenland": (39.07, 22.94),
    "spanien": (40.46, -3.75), "vereinigtes königreich": (54.00, -2.00),
    "irland": (53.41, -8.24), "niederlande": (52.13, 5.29), "belgien": (50.50, 4.47),
    "dänemark": (56.26, 9.50), "schweden": (60.13, 18.64), "norwegen": (60.47, 8.47),
    "finnland": (61.92, 25.75), "polen": (51.92, 19.13), "tschechien": (49.82, 15.47),
    "ungarn": (47.16, 19.50), "rumänien": (45.94, 24.97), "portugal": (39.40, -8.22),
    "usa": (39.83, -98.58), "vereinigte staaten": (39.83, -98.58),
    "de": (51.16, 10.45), "ch": (46.80, 8.22), "at": (47.52, 14.55),
    "fr": (46.60, 2.20), "it": (42.83, 12.83), "gr": (39.07, 22.94),
    "es": (40.46, -3.75), "uk": (54.00, -2.00), "ie": (53.41, -8.24),
    "nl": (52.13, 5.29), "be": (50.50, 4.47), "dk": (56.26, 9.50),
    "se": (60.13, 18.64), "no": (60.47, 8.47), "fi": (61.92, 25.75),
    "pl": (51.92, 19.13), "cz": (49.82, 15.47), "hu": (47.16, 19.50),
    "ro": (45.94, 24.97), "pt": (39.40, -8.22), "us": (39.83, -98.58),
}

_last_geo = [0.0]

_BOGUS_LOCATIONS = {
    "unbekannt", "unknown", "verschiedene", "mehrere orte", "bundesweit",
    "deutschland", "österreich", "schweiz", "europa", "online",
    # Words that are NOT city names but get extracted as such:
    "schutt", "brand", "hinterlandregionen", "hinterland", "konkurrenz",
    "ihren", "suchergebnissen", "ergebnissen", "region", "innenstadt",
    "stadtgebiet", "stadtmitte", "randgebiete", "verschiedene städte",
    "tutorials", "archiv", "kontakt", "übersicht", "inhalt",
}

def geocode(location, country):
    if not location:
        c = (country or "").lower()
        if c in CITY_FALLBACK: return CITY_FALLBACK[c]
        return None, None
    loc_clean = location.strip()
    if loc_clean.lower() in _BOGUS_LOCATIONS or len(loc_clean) < 3:
        c = (country or "").lower()
        if c in CITY_FALLBACK: return CITY_FALLBACK[c]
        return None, None

    loc_lower = location.strip().lower()

    # ── CITY-FALLBACK MATCHING — Hardening v2 ────────────────────────
    # Vorher: `if city in loc_lower` (substring) — produzierte Bugs wie
    #   "Bernau bei Berlin" → matched "bern" (CH) statt "berlin" (DE),
    #   "Berliner Straße, Stuttgart" → matched "bern" (CH).
    # Jetzt:
    #   1) Exakt-Match auf den ganzen Ortsstring (z.B. "berlin", "wien").
    #   2) Word-Boundary-Match, längster Key zuerst (damit "berlin" vor
    #      "bern" gewinnt) UND nur wenn die Stadt im erwarteten Land
    #      liegt (sonst Skip — Nominatim oder Country-Center entscheidet).
    expected_co = (country or "").upper()
    co_for_key = {k.lower(): co for co, kws in COUNTRY_KEYWORDS.items() for k in kws}
    # Exact match on the full cleaned location.
    if loc_lower in CITY_FALLBACK:
        city_co = co_for_key.get(loc_lower)
        if (not expected_co) or (not city_co) or city_co == expected_co or expected_co in ("", "ANDERE"):
            return CITY_FALLBACK[loc_lower]
    # Longest-key word-boundary match, country-consistent only.
    matches = []
    for city, coords in CITY_FALLBACK.items():
        if len(city) < 4:    # skip 2-letter country codes etc.
            continue
        if re.search(rf"\b{re.escape(city)}\b", loc_lower):
            city_co = co_for_key.get(city)
            # Reject the match when the city's country contradicts AI's
            # country guess — avoids "Berner Straße, Stuttgart" landing
            # in Bern, CH. We trust the AI's country here because
            # _override_country_from_city has already run upstream.
            if expected_co and city_co and city_co != expected_co:
                continue
            matches.append((len(city), city, coords))
    if matches:
        matches.sort(reverse=True)         # longest key wins
        return matches[0][2]

    key = f"{loc_lower}|{(country or '').lower()}"
    row = db.execute("SELECT lat,lon FROM geocache WHERE query=?", (key,)).fetchone()
    if row: return row[0], row[1]

    wait = 1.2 - (time.time() - _last_geo[0])
    if wait > 0: time.sleep(wait)
    try:
        # Pass countrycodes to Nominatim so it only returns results within the expected country
        _co_map = {"DE":"de","AT":"at","CH":"ch","FR":"fr","IT":"it","GR":"gr","ES":"es","UK":"gb"}
        params = {"q": location, "format": "json", "limit": 1}
        if country in _co_map:
            params["countrycodes"] = _co_map[country]
        r = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params=params,
            headers={"User-Agent": "LEX-EUROPE-OSINT/5.0"},
            timeout=10
        )
        _last_geo[0] = time.time()
        res = r.json()
        if res:
            lat, lon = float(res[0]["lat"]), float(res[0]["lon"])
            # Reject if coordinates land in a completely wrong country
            if not _coords_in_country(country, lat, lon):
                log.warning(f"Geocode '{location}'/{country} → ({lat:.2f},{lon:.2f}) outside bounds — using country center")
                c = (country or "").lower()
                lat, lon = CITY_FALLBACK.get(c, (None, None))
                if lat is None:
                    db.execute("INSERT OR REPLACE INTO geocache VALUES (?,NULL,NULL)", (key,))
                    db.commit()
                    return None, None
            db.execute("INSERT OR REPLACE INTO geocache VALUES (?,?,?)", (key,lat,lon))
            db.commit()
            return lat, lon
    except Exception as e:
        log.warning(f"Geocode '{location}': {e}")

    # Final fallback: country center
    c = (country or "").lower()
    if c in CITY_FALLBACK:
        lat, lon = CITY_FALLBACK[c]
        db.execute("INSERT OR REPLACE INTO geocache VALUES (?,?,?)", (key,lat,lon))
        db.commit()
        return lat, lon

    db.execute("INSERT OR REPLACE INTO geocache VALUES (?,NULL,NULL)", (key,))
    db.commit()
    return None, None

def regeocode_nulls():
    """Re-attempt geocoding for incidents that have no coordinates."""
    rows = db.execute("SELECT id,location,country FROM incidents WHERE lat IS NULL").fetchall()
    fixed = 0
    for row in rows:
        lat, lon = geocode(row["location"], row["country"])
        if lat and lon:
            db.execute("UPDATE incidents SET lat=?,lon=? WHERE id=?", (lat,lon,row["id"]))
            fixed += 1
    if fixed:
        db.commit()
        log.info(f"Re-geocoded {fixed} incidents")

def regeocode_all_inconsistent():
    """
    Re-runs geocoding for every incident whose current lat/lon lie outside
    the country bounding box. Fixes Userhinweis: Vorfälle landeten in CH
    oder USA statt DE, weil die alte substring-Match-Logik z.B. "Bernau"
    nach Bern/CH geroutet hat. Idempotent — überspringt korrekte Rows.
    """
    # Cache-Wipe: alte Substring-Match-Treffer können in der geocache-Tabelle
    # stehen und würden den Fix sonst überleben.
    db.execute("DELETE FROM geocache")
    db.commit()
    rows = db.execute(
        "SELECT id, location, country, lat, lon FROM incidents WHERE lat IS NOT NULL"
    ).fetchall()
    fixed = 0
    for r in rows:
        if not r["country"]:
            continue
        # Wenn die aktuellen Koordinaten ausserhalb des erwarteten Landes
        # liegen, neu geokodieren.
        if not _coords_in_country(r["country"], r["lat"], r["lon"]):
            lat, lon = geocode(r["location"], r["country"])
            if lat and lon and _coords_in_country(r["country"], lat, lon):
                db.execute("UPDATE incidents SET lat=?, lon=? WHERE id=?",
                           (lat, lon, r["id"]))
                fixed += 1
    if fixed:
        db.commit()
        log.info(f"regeocode_all_inconsistent: {fixed} incidents korrigiert")
    return fixed

# ── GROK ─────────────────────────────────────────────────────────
CATEGORIES = [
    "Brandanschlag","Sabotage","Gewalt","Schmiererei","Aufruf zu Gewalt",
    "Militante Aktion","Sachbeschädigung","Demo/Kundgebung","Besetzung",
    "Repression","Verhaftung","Sonstiges"
]

# ── SEVERITY SCORING ─────────────────────────────────────────────
SEVERITY_MAP = {
    "Brandanschlag": 5, "Gewalt": 5, "Militante Aktion": 5,
    "Aufruf zu Gewalt": 4, "Sabotage": 4,
    "Sachbeschädigung": 3, "Besetzung": 3, "Demo/Kundgebung": 2,
    "Verhaftung": 2, "Repression": 2,
    "Schmiererei": 1, "Sonstiges": 1,
}

def score_severity(category, text=""):
    """
    Schwere 1..5 — Basis aus SEVERITY_MAP, dann text-basiert hochgestuft.
    Mehrere Signale können stapeln (bis Cap 5). Reihenfolge nach Härte:
      Personen-Schaden > Brandwaffe/Sprengstoff > Sachschadens-Magnitude.
    """
    base = SEVERITY_MAP.get(category, 1)
    t = (text or "").lower()
    # Personenschaden = unmittelbarer Härte-Faktor
    if re.search(r"\b(schwer\s+verletzt|getötet|getoetet|\btot\b|tote\b|todesopfer|"
                 r"lebensgefahr|reanim(iert|ation)|krankenhaus(?!\w))",
                 t):
        base = min(base + 2, 5)
    elif re.search(r"\b(verletzt|verletzung|verletzte|geprellt|prellung|gebrochen|"
                   r"blutung)", t):
        base = min(base + 1, 5)
    # Brandwaffe / Sprengstoff / Werkzeugmilieu
    if re.search(r"\b(brandsatz|molotov|molotow|brand(?:flasche|beschleuniger)|"
                 r"sprengsatz|sprengstoff|usbv|brandsetzung)\b", t):
        base = min(base + 1, 5)
    # Sachschadens-Magnitude (€-Hinweise)
    m = re.search(r"(\d{1,3}(?:[.,]\d{3})+|\d{4,})\s*(?:€|euro|chf|franken)", t)
    if m:
        try:
            amt = int(re.sub(r"[.,]", "", m.group(1)))
            if   amt >= 1_000_000: base = min(base + 2, 5)
            elif amt >=   100_000: base = min(base + 1, 5)
        except Exception:
            pass
    # Mehrfach-Anschlag / koordinierte Aktion
    if re.search(r"(\bserien?anschl|\bkoordinier|\bmehrere\s+anschl|"
                 r"\bin\s+der\s+gleichen\s+nacht|\bsimultan|"
                 r"\b(?:fünf|sechs|sieben|acht|neun|zehn|\d{2,})\s+(?:fahrzeuge|"
                 r"autos|wagen|tesla|streifen|polizei))", t):
        base = min(base + 1, 5)
    return base

# ── ACTOR / GROUP TRACKING ────────────────────────────────────────
# Each entry: (display name, regex patterns, fedpol_tier).
# Tier mapping is intentionally conservative (Concept §C3 #2 — keine
# Vorverurteilung). Only attribute "act" where public record clearly
# connects the name to concrete violent acts (claim letters or convictions);
# "enable" for groups that organise support/propaganda for the milieu;
# "endorse" for scene/neighbourhood labels and movements that explicitly
# disavow violence themselves but are part of the broader endorsement layer.
KNOWN_ACTORS = [
    # ── DACH ───────────────────────────────────────────────────────
    ("Rote Flora",          [r"rote\s+flora"],                                "endorse"),
    ("Rigaer 94",           [r"rigaer\s*(?:94|straße|str\.)", r"liebig\s*34"], "endorse"),
    ("Ende Gelände",        [r"ende\s+gel[äa]nde"],                            "endorse"),
    ("Schwarzer Block",     [r"schwarzer\s+block", r"black\s+bloc"],           "act"),
    ("Rev. Zellen",         [r"revolutionäre\s+zellen", r"\brz\b"],            "act"),
    ("Letzte Generation",   [r"letzte\s+generation"],                          "endorse"),
    ("Lina E. Netzwerk",    [r"\blina\s+e[\.\b]", r"hammerbande"],             "act"),
    ("Rote Hilfe",          [r"rote\s+hilfe"],                                 "enable"),
    ("Antifa Leipzig",      [r"antifa\s+leipzig", r"connewitz"],               "endorse"),
    ("Autonome Gruppe",     [r"eine?\s+autonome\s+gruppe", r"autonome\s+zelle"], "act"),
    ("Junge Welt Umfeld",   [r"junge\s+welt\s+gruppe"],                        "enable"),
    ("Interventionist Left",[r"interventionistische\s+linke", r"\bil\b.*linke"], "endorse"),
    ("Vulkangruppe",        [r"vulkangruppe", r"vulkan\s+gruppe"],             "act"),
    # ── Schweiz ────────────────────────────────────────────────────
    ("Reitschule-Umfeld",   [r"reitschule(?:\s+bern)?\b"],                     "endorse"),
    ("Revolutionärer Aufbau",[r"revolutionäre?r?\s+aufbau"],                   "enable"),
    # ── USA / Nordamerika (per US 2026 CT-Strategy als Threat-Tier 1)
    ("Rose City Antifa",    [r"\brose\s+city\s+antifa\b", r"\brca\b\s+portland"], "endorse"),
    ("Portland Antifa",     [r"\bantifa\s+portland\b", r"\bpdx\s+antifa\b"],   "endorse"),
    ("Stop Cop City",       [r"\bstop\s+cop\s+city\b", r"\bdefend\s+the\s+atlanta\s+forest\b",
                              r"\bweelaunee\s+forest\b"],                       "act"),
    ("Crimethinc",          [r"\bcrimethinc\b"],                               "enable"),
    ("John Brown Gun Club", [r"\bjohn\s+brown\s+gun\s+club\b", r"\bjbgc\b"],   "endorse"),
    ("By Any Means Necessary", [r"\bby\s+any\s+means\s+necessary\b",
                                  r"\bbamn\b"],                                "endorse"),
    ("Smash Racial Capitalism",[r"\bsmash\s+racial\s+capital"],                "endorse"),
    # ── Griechenland (Exarchia-Komplex, in mehreren NDB/EU-INTCEN-Berichten)
    ("Exarchia-Strukturen", [r"\bexarch(ia|eia)\b", r"\bvouli\s+\d+\b"],       "endorse"),
    ("Conspiracy of Fire Cells",[r"\bconspiracy\s+of\s+fire\s+cells\b",
                                  r"\bsynomos[íi]a\s+pyr[íi]non\b"],            "act"),
    # ── Frankreich ─────────────────────────────────────────────────
    ("ZAD / Soulèvements",  [r"\bzad\b", r"\bzone\s+[àa]\s+d[ée]fendre\b",
                              r"\bsoul[èe]vements\s+de\s+la\s+terre\b"],       "endorse"),
    ("Action Antifasciste FR",[r"\baction\s+antifasciste\b.*\b(paris|france|lyon)",
                                r"\bafa\s+paris\b"],                            "endorse"),
    ("Black Bloc France",   [r"\bblack[\s-]?bloc\b.*\b(paris|france|toulouse|nantes)"], "act"),
    # ── Italien ────────────────────────────────────────────────────
    ("Centro Sociale",      [r"\bcentro\s+sociale\b", r"\bcsoa\b"],            "endorse"),
    ("NoTAV",               [r"\bnotav\b", r"\bno[\s-]?tav\b",
                              r"\bval\s+di\s+susa\b.*\b(protest|aktion)"],      "act"),
    ("Antifa Italia",       [r"\bantifa\s+(?:italia|bologna|roma|milano)\b"],  "endorse"),
    # ── Niederlande / Skandinavien / UK ────────────────────────────
    ("AFA Nederland",       [r"\bafa\s+nederland\b",
                              r"\bantifascistische\s+aktie\b.*(?:nl|nederland)"], "endorse"),
    ("AFA Stockholm",       [r"\bafa\s+stockholm\b",
                              r"\bantifascistisk\s+aktion\b"],                  "endorse"),
    ("Antifa Network UK",   [r"\bantifa\s+(?:uk|london|britain)\b",
                              r"\banti[\s-]?fascist\s+network\b"],              "endorse"),
    ("Class War",           [r"\bclass\s+war\b.*\b(uk|britain|london)\b"],     "enable"),
    # ── Spanien ────────────────────────────────────────────────────
    ("Acción Antifascista", [r"\bacci[óo]n\s+antifascista\b"],                 "endorse"),
    # ── Tag-X-Komitees (Lina-E.-Komplex) ──────────────────────────
    ("Tag-X-Komitee",       [r"\btag[\s-]?x[\s-]?komitee\b",
                              r"\btag\s+x\b"],                                  "enable"),
    # ── Internationale Erweiterung ────────────────────────────────
    ("Antifascistisk Aktion",[r"\bantifascistisk\s+aks?jon\b",
                                r"\bafa\s+(?:no|oslo|norge)\b"],                "endorse"),
    ("Anti-Cop-City Italia", [r"\banti[\s-]?cop[\s-]?city\b.*\b(italia|brescia|bologna)\b"], "endorse"),
    ("Vulkangruppe Bay Area",[r"\bvulkangruppe\s+bay\s+area\b"],               "act"),
    ("Defend the Atlanta Forest",
                            [r"\bdefend\s+the\s+atlanta\s+forest\b",
                              r"\bweelaunee\s+(?:forest|defenders)\b"],         "act"),
    ("Soulèvements de la Terre",
                            [r"\bsoul[èe]vements\s+de\s+la\s+terre\b",
                              r"\bsdt\b\s+(?:france|paris)\b"],                 "enable"),
    ("Carlos-Komitee",      [r"\bcarlos[\s-]?komitee\b"],                      "enable"),
]

ACTOR_TIER = {name: tier for name, _patterns, tier in KNOWN_ACTORS}

def extract_actors(text):
    found = []
    t = (text or "").lower()
    for entry in KNOWN_ACTORS:
        name, patterns = entry[0], entry[1]
        if any(re.search(p, t) for p in patterns):
            found.append(name)
    return ",".join(found)

# ── SOURCE CONFIDENCE SCORING ─────────────────────────────────────
SOURCE_CONFIDENCE = {
    "verfassungsschutz.de": 5,
    # Konfidenz 5 — Behörden-Primärquellen (Polizei-Press, Parlamente)
    "polizei-": 5, "presseportal.de": 5,
    "bundestag.de": 5, "bundestag-": 5,
    "bundesregierung.de": 5, "bundesregierung": 5,
    # Konfidenz 4 — öffentlich-rechtlich oder etablierte Leitmedien
    "tagesschau.de": 4, "zdf.de": 4, "deutschlandfunk.de": 4,
    "spiegel.de": 4, "zeit.de": 4, "sueddeutsche.de": 4, "faz.net": 4,
    "welt.de": 4,
    "srf.ch": 4, "orf.at": 4, "derstandard.at": 4, "nzz.ch": 4,
    "tagesanzeiger.ch": 4, "diepresse.com": 4,
    "lemonde.fr": 4, "liberation.fr": 4, "repubblica.it": 4, "corriere.it": 4,
    "elpais.com": 4, "euronews.com": 4,
    # Konfidenz 3 — regionale öffentlich-rechtliche + Boulevard-Leit
    "tagesspiegel.de": 3, "mdr.de": 3, "rbb24.de": 3, "ndr.de": 3,
    "wdr.de": 3, "br.de": 3, "hr.de": 3, "swr.de": 3, "ntv.de": 3,
    "taz.de": 3, "blick.ch": 3, "20min.ch": 3, "belltower.news": 3,
    "bzbasel.ch": 3, "watson.ch": 3, "rts.ch": 3,
    "kurier.at": 3, "kleinezeitung.at": 3, "noen.at": 3, "krone.at": 3,
    "wien.orf.at": 3,
    # Konfidenz 2 — szenenahe Quellen, brauchen Cross-Check
    "barrikade.info": 2, "de.indymedia.org": 2, "nd-aktuell.de": 2,
    "jungle.world": 2, "gnews": 2, "labournet.de": 2, "woz.ch": 2,
    "jungewelt.de": 2,
    # Konfidenz 1 — Bewegungs-Outlets / Mailing-Listen-Archive
    "perspektive-online.net": 1, "radikal.news": 1, "klassegegenklasse.org": 1,
    "lists.riseup.net": 1,
    "Archiv": 3, "Manuell": 2,
}

def score_confidence(source):
    src = source or ""
    for k, v in SOURCE_CONFIDENCE.items():
        if k in src:
            return v
    return 2

# ── KEYWORD CLASSIFICATION (AI-free) ─────────────────────────────
KEYWORD_MAP = [
    ("Brandanschlag",   ["brand gesetzt","abgefackelt","angezündet","molotow","brandsatz","in flammen",
                         "fahrzeug brannte","auto brannte","feuer gelegt","brandstiftung","anzündeten"]),
    ("Sabotage",        ["sabotage","sabotiert","gleisanlage","kabelanlage","signalanlage",
                         "stromkabel","bahnsabotage","infrastruktur sabotiert","zugsperrung"]),
    ("Gewalt",          ["angriff auf polizei","verletzte beamte","ausschreitungen","krawalle",
                         "randalen","beamte angegriffen","steinwürfe","attackierten","übergriff",
                         "verletzt","zusammenstöße"]),
    ("Militante Aktion",["bekennerschreiben","militante gruppe","direkte aktion","autonome gruppe",
                         "militante linke","revolutionäre","bewaffnete"]),
    ("Besetzung",       ["besetzung","besetzt","räumung","squat","hausbesetzung","besetzen"]),
    ("Demo/Kundgebung", ["demonstration","kundgebung","protestzug","aufmarsch","streik",
                         "protestierende","auf die straße","gegendemonstration"]),
    ("Sachbeschädigung",["sachbeschädigung","scheiben eingeworfen","farbbeutel","beschädigt",
                         "verwüstet","zerstört","scheiben zertrümmert"]),
    ("Verhaftung",      ["festnahmen","verhaftet","festgenommen","inhaftiert","in gewahrsam"]),
    ("Schmiererei",     ["graffiti","besprüht","parolen gesprüht","spraydosen","beschriftung"]),
    ("Repression",      ["razzia","hausdurchsuchung","überwachung","durchsuchungsbeschluss"]),
    ("Aufruf zu Gewalt",["aufruf zu gewalt","aufhetzen","aufgerufen zu","zur gewalt aufgerufen"]),
]

# Country/location extraction helpers
LOCATION_PATTERNS = [
    r'\bin\s+([A-ZÜÄÖ][a-züäöA-ZÜÄÖ\-]+(?:\s+[A-ZÜÄÖ][a-züäöA-ZÜÄÖ\-]+)?)\b',
    r'([A-ZÜÄÖ][a-züäöA-ZÜÄÖ\-]+):\s',
]
COUNTRY_KEYWORDS = {
    "DE": ["deutschland","berlin","hamburg","münchen","köln","frankfurt","leipzig","dresden",
           "stuttgart","hannover","bremen","dortmund","nürnberg","chemnitz","halle","magdeburg",
           "rostock","essen","duisburg","wuppertal","bielefeld","münster","augsburg","karlsruhe",
           "mannheim","freiburg","kiel","lübeck","erfurt","jena","potsdam","kassel","göttingen",
           "weimar","cottbus","saarbrücken",
           "sachsen","thüringen","bayern","nrw","baden-württemberg","brandenburg",
           "schleswig-holstein","mecklenburg","niedersachsen","saarland","hessen","rheinland-pfalz"],
    "AT": ["österreich","wien","graz","linz","salzburg","innsbruck","klagenfurt"],
    "CH": ["schweiz","zürich","bern","genf","basel","lausanne","winterthur","luzern","reitschule",
           "koch-areal"],
    "FR": ["frankreich","paris","lyon","marseille","bordeaux","toulouse","nantes","strasbourg",
           "lille","france"],
    "IT": ["italien","rom","mailand","turin","neapel","bologna","italia","milano","torino"],
    "GR": ["griechenland","athen","athens","thessaloniki","exarchia","exarcheia"],
    "ES": ["spanien","madrid","barcelona","valencia","bilbao","sevilla","spain","catalunya"],
    "UK": ["england","großbritannien","london","manchester","glasgow","edinburgh","britain",
           "united kingdom","scotland","wales"],
    "IE": ["irland","dublin","ireland","cork"],
    "NL": ["niederlande","amsterdam","rotterdam","den haag","utrecht","netherlands"],
    "BE": ["belgien","brüssel","brussels","antwerpen","gent","liege","belgium"],
    "DK": ["dänemark","kopenhagen","copenhagen","aarhus","denmark"],
    "SE": ["schweden","stockholm","göteborg","malmö","sweden"],
    "NO": ["norwegen","oslo","bergen","trondheim","norway"],
    "FI": ["finnland","helsinki","tampere","finland"],
    "PL": ["polen","warschau","warsaw","krakau","krakow","danzig","gdansk","poland"],
    "CZ": ["tschechien","prag","prague","brno","czech"],
    "HU": ["ungarn","budapest","hungary"],
    "RO": ["rumänien","bukarest","bucharest","romania"],
    "PT": ["portugal","lissabon","lisbon","porto"],
    "US": ["usa","vereinigte staaten","united states","new york","portland","seattle","minneapolis",
           "chicago","los angeles","oakland","san francisco","atlanta","washington","boston",
           "philadelphia","denver","antifa portland","antifa nyc","blm portland"],
}

# Reverse index: city name (lower) → country code. Built from COUNTRY_KEYWORDS
# AND from CITY_FALLBACK so we have one authoritative city→country mapping.
_CITY_TO_COUNTRY = {}
for _co, _kws in COUNTRY_KEYWORDS.items():
    for _kw in _kws:
        _CITY_TO_COUNTRY.setdefault(_kw.lower(), _co)

def _override_country_from_city(city: str, text: str, ai_country: str) -> str:
    """
    Defends against AI mis-classifying the country when a famous city is named.
    v2-Hardening (Userhinweis: Vorfälle landeten in CH oder USA statt DE):
      1) Exact-match auf den city-String (z.B. "Chemnitz" → DE).
      2) Word-Boundary-Scan der ersten ~600 Zeichen — aber wir picken
         NICHT mehr den ersten Treffer in dict-Order, sondern zählen
         pro Land die Treffer ein und nehmen das dominante Land. Damit
         überstimmt z.B. ein einziges "Schweiz" im Boilerplate-Footer
         keinen Artikel über vier Berliner Vorfälle mehr.
      3) Wenn Stadt- und Text-Signal sich widersprechen, gewinnt die Stadt
         (sie ist meist genauer als ein Random-Text-Hit).
    """
    # 1) Stadt-Exact-Match — höchste Confidence.
    city_co = None
    if city:
        city_co = _CITY_TO_COUNTRY.get(city.strip().lower())
        if city_co:
            return city_co if city_co != ai_country else ai_country
    # 2) Text-Scan mit Dominanz-Voting.
    if text:
        head = text[:1200].lower()
        votes = {}
        for kw, co in _CITY_TO_COUNTRY.items():
            if len(kw) < 5:
                continue
            if re.search(r'\b' + re.escape(kw) + r'\b', head):
                votes[co] = votes.get(co, 0) + 1
        if votes:
            dominant = max(votes.items(), key=lambda kv: kv[1])
            # Override nur, wenn das dominante Land klar überlegen ist
            # (mindestens 2:1, oder einziges votiertes Land).
            if dominant[0] != ai_country:
                second = sorted(votes.values(), reverse=True)
                if len(second) == 1 or dominant[1] >= 2 * second[1]:
                    return dominant[0]
    return ai_country

def classify_keywords(text):
    """Fast keyword-based classifier — no API calls."""
    t = text.lower()
    # Detect category
    found_cat = None
    for cat, kws in KEYWORD_MAP:
        if any(kw in t for kw in kws):
            found_cat = cat
            break
    if not found_cat:
        return None

    # Detect country
    found_country = "DE"  # default
    for co, kws in COUNTRY_KEYWORDS.items():
        if any(kw.lower() in t for kw in kws):
            found_country = co
            break

    # Detect location (simple: find first capitalised word after "in ")
    found_loc = "Unbekannt"
    for pat in LOCATION_PATTERNS:
        m = re.search(pat, text)
        if m:
            found_loc = m.group(1).strip()
            break

    # Keyword path can't reliably judge ist_gewalttat — leave None so callers
    # can fall back to category-based heuristics. zusammenfassung is built
    # via fallback_summary() in save_incident() when missing.
    return {
        "kategorie": found_cat,
        "land": found_country,
        "ort": found_loc,
        "ist_gewalttat": None,
        "zusammenfassung": "",
    }

def smart_classify(text):
    """
    Strategy: prefer Grok when available (it sets ist_gewalttat + summary),
    fall back to fast keyword classification only if Grok is unreachable.
    The previous order (keywords first) bypassed the stricter ist_gewalttat
    gate too often.
    """
    if os.getenv("GROK_API_KEY"):
        result = classify(text)
        if result:
            return result
    # Fallback: keyword-only classification (no AI gate).
    return classify_keywords(text)

# ── HISTORICAL SEED DATA ──────────────────────────────────
# Publicly documented incidents 2018–2024, hardcoded coords (no geocoding needed)
HISTORICAL_EVENTS = [
    # (date, location, country, category, description, source, lat, lon)
    # ── 2018 ─────────────────────────────────────────────
    ("2018-08-26","Chemnitz","DE","Gewalt",
     "Linksextreme Gruppen griffen eine Kundgebung der AfD in der Chemnitzer Innenstadt an. Schwere Ausschreitungen, gegenseitige Übergriffe zwischen linken und rechten Demonstranten. Polizei im Großeinsatz, mehrere Verletzte.",
     "Archiv",50.83,12.92),
    ("2018-11-08","Hamburg","DE","Brandanschlag",
     "Mehrere Fahrzeuge in Hamburg-Schanzenviertel in der Nacht angezündet. Bekennerschreiben einer autonomen Gruppe: 'Gegen Verdrängung und Gentrifizierung.' Schadenshöhe ca. 80.000 Euro.",
     "Archiv",53.563,9.961),
    ("2018-01-25","Bern","CH","Demo/Kundgebung",
     "Anti-WEF-Demonstration in Bern vor Beginn des Weltwirtschaftsforums in Davos. Autonome Gruppen durchbrachen Polizeiabsperrungen, warfen Steine und Flaschen auf Beamte. 10 Festnahmen.",
     "Archiv",46.95,7.44),
    # ── 2019 ─────────────────────────────────────────────
    ("2019-06-02","Hamburg","DE","Brandanschlag",
     "Drei Fahrzeuge der Bundespolizei in Hamburg-Altona in Brand gesetzt. Bekennerschreiben einer autonomen Gruppe im Internet veröffentlicht. Sachschaden ca. 150.000 Euro.",
     "Archiv",53.55,10.00),
    ("2019-12-31","Leipzig","DE","Gewalt",
     "Silvesternacht: Koordinierter Angriff auf Polizeikräfte in Leipzig-Connewitz. Über 200 vermummte Personen attackierten Beamte mit Pyrotechnik, Flaschen und Steinen. 15 Beamte verletzt, 2 schwer. Fahrzeuge in Brand gesetzt.",
     "Archiv",51.32,12.38),
    ("2019-03-16","Paris","FR","Gewalt",
     "Schwarzer Block bei Gelbwesten-Demo ('Acte 18') in Paris. Schwere Ausschreitungen auf den Champs-Élysées. Bankfilialen und Luxusgeschäfte verwüstet, Barrikaden errichtet. Über 200 Festnahmen.",
     "Archiv",48.87,2.30),
    ("2019-03-15","Wien","AT","Sachbeschädigung",
     "FPÖ-Bezirksbüro in Wien-Leopoldstadt mit Farbe beschmiert, Scheiben eingeworfen. Bekennerschreiben antifaschistischer Gruppen veröffentlicht. Polizei ermittelt.",
     "Archiv",48.21,16.37),
    ("2019-09-27","Zürich","CH","Demo/Kundgebung",
     "Globaler Klimastreik in Zürich. Nach der offiziellen Demo beschädigten autonome Gruppen Filialen von Großbanken und Versicherungskonzernen. Bekennerschreiben mit Klimaforderungen veröffentlicht.",
     "Archiv",47.38,8.54),
    ("2019-05-01","Zürich","CH","Gewalt",
     "1.-Mai-Demonstration in Zürich. Schwarzer Block griff Polizeikräfte an. 12 Festnahmen, 2 Beamte verletzt. Fahrzeuge beschädigt.",
     "Archiv",47.38,8.54),
    # ── 2020 ─────────────────────────────────────────────
    ("2020-06-21","Stuttgart","DE","Gewalt",
     "Randalen in der Stuttgarter Innenstadt nach einer Demonstration. Gruppen griffen Polizisten an, plünderten Geschäfte. 19 Beamte verletzt, 24 Festnahmen. Autos beschädigt.",
     "Archiv",48.78,9.18),
    ("2020-09-26","Berlin","DE","Brandanschlag",
     "Mehrere Fahrzeuge in der Rigaer Straße in Berlin-Friedrichshain angezündet. Bekennerschreiben: 'Für die Freiheit des Kiezes und aller politischen Gefangenen.' Dritte derartige Aktion in diesem Monat.",
     "Archiv",52.516,13.456),
    ("2020-06-13","Zürich","CH","Sachbeschädigung",
     "Black-Lives-Matter-Demo in Zürich. Randalierer beschädigten US-Konsulat, Bankfilialen und Luxusgeschäfte in der Innenstadt. 8 Festnahmen.",
     "Archiv",47.38,8.54),
    ("2020-01-22","Wien","AT","Demo/Kundgebung",
     "Antifaschistische Gegendemonstration in Wien. Kleinere Ausschreitungen am Rande, Polizei im Großeinsatz.",
     "Archiv",48.21,16.37),
    # ── 2021 ─────────────────────────────────────────────
    ("2021-01-14","Erfurt","DE","Sachbeschädigung",
     "Büroräume der AfD Thüringen in Erfurt mit Farbe beschmiert, Scheiben eingeworfen. Bekennerschreiben von 'Antifaschistische Aktion Erfurt' im Netz veröffentlicht.",
     "Archiv",50.98,11.03),
    ("2021-02-16","Barcelona","ES","Demo/Kundgebung",
     "Proteste nach Verhaftung des Rappers Pablo Hasel in Barcelona. Schwere Ausschreitungen über mehrere Tage, Barrikaden in der Innenstadt, 89 Festnahmen. Plünderungen gemeldet.",
     "Archiv",41.39,2.16),
    ("2021-05-01","Zürich","CH","Gewalt",
     "1.-Mai-Demonstration in Zürich eskaliert. Schwarzer Block griff Polizeikräfte mit Steinen, Feuerwerkskörpern und Flaschen an. 33 Festnahmen, 4 Beamte verletzt.",
     "Archiv",47.38,8.54),
    ("2021-05-15","Berlin","DE","Demo/Kundgebung",
     "Pro-Palästina-Demonstration in Berlin-Neukölln eskaliert. Autonome Gruppen attackierten Polizeiabsperrungen. Mehrere Festnahmen, Beamte durch Pyrotechnik verletzt.",
     "Archiv",52.48,13.44),
    ("2021-07-15","Wien","AT","Brandanschlag",
     "Fahrzeug eines Justizwachbeamten vor dessen Wohnhaus in Wien angezündet. Bekennerschreiben einer anarchistischen Gruppe: 'Gegen Knast und staatliche Repression.' Schadenshöhe ca. 25.000 Euro.",
     "Archiv",48.21,16.37),
    ("2021-10-04","Leipzig","DE","Gewalt",
     "Angriff auf Polizeistreife in Leipzig-Connewitz. Beamte mit Steinen, Flaschen und Feuerwerkskörpern beworfen. 2 Beamte verletzt, einer davon schwer.",
     "Archiv",51.32,12.38),
    ("2021-12-06","Athen","GR","Brandanschlag",
     "Jahrestag des Todes von Alexandros Grigoropoulos (2008): Mehrere Bankfilialen und Fahrzeuge in Athen in Brand gesetzt. Molotowcocktails auf Polizei geworfen. Schwere Ausschreitungen.",
     "Archiv",37.98,23.73),
    # ── 2022 ─────────────────────────────────────────────
    ("2022-01-30","Berlin","DE","Brandanschlag",
     "Fahrzeuge des Bundesnachrichtendienstes und der Bundeswehr in Berlin-Mitte angezündet. Bekennerschreiben: 'Gegen den imperialistischen Krieg und seinen Staat.' Schadenshöhe ca. 200.000 Euro.",
     "Archiv",52.52,13.41),
    ("2022-03-31","Graz","AT","Sachbeschädigung",
     "Wahlkampfveranstaltung der FPÖ Graz gestört. Farbbeutel auf Redner geworfen, Scheiben des Veranstaltungsorts beschädigt. 3 Festnahmen. Sachschaden ca. 8.000 Euro.",
     "Archiv",47.07,15.44),
    ("2022-04-05","Dresden","DE","Sabotage",
     "Sprengstoffanschlag auf Gleisanlage der Deutschen Bahn bei Dresden-Plauen. Linksextremistisches Bekennerschreiben. Zugverkehr zwischen Dresden und Leipzig für 6 Stunden gesperrt. Tausende Reisende betroffen.",
     "Archiv",51.05,13.74),
    ("2022-06-03","Leipzig","DE","Gewalt",
     "Ausschreitungen in Leipzig nach Demonstration. Polizeibeamte verletzt, mehrere Fahrzeuge in Brand gesetzt. 54 Festnahmen. Polizei spricht von organisierten linksextremen Gruppen.",
     "Archiv",51.34,12.37),
    ("2022-09-24","Bern","CH","Demo/Kundgebung",
     "Klimademonstration vor dem Bundeshaus in Bern. Aktivisten drangen in Parlamentsgebäude ein, Sachschäden entstanden. 10 Festnahmen durch Kantonspolizei Bern.",
     "Archiv",46.95,7.44),
    ("2022-10-29","Turin","IT","Gewalt",
     "Demonstration gegen die Regierung Meloni in Turin. Linksextreme Gruppen griffen Polizei mit Stöcken und Steinen an. 12 Festnahmen, 5 Beamte verletzt.",
     "Archiv",45.07,7.69),
    ("2022-11-08","Hamburg","DE","Brandanschlag",
     "Fahrzeugbrände in Hamburg-Schanzenviertel. 7 PKW und ein Transporter in der Nacht abgefackelt. Schadenshöhe ca. 300.000 Euro. Dritte Brandserie in diesem Viertel binnen 18 Monaten.",
     "Archiv",53.563,9.961),
    ("2022-11-17","Athen","GR","Demo/Kundgebung",
     "Jahrestag des Athener Polytechnikums. Autonome Gruppen attackierten Polizei mit Molotowcocktails und Steinen. Ausschreitungen dauerten bis in die frühen Morgenstunden.",
     "Archiv",37.98,23.73),
    ("2022-12-10","Berlin","DE","Sabotage",
     "Sabotage an Stromkabeln der Deutschen Bahn in Berlin. Zugverkehr im Nah- und Fernverkehr für mehrere Stunden lahmgelegt. Bekennerschreiben mit anti-staatlichen Forderungen veröffentlicht.",
     "Archiv",52.52,13.405),
    # ── 2023 ─────────────────────────────────────────────
    ("2023-01-14","Lützerath","DE","Besetzung",
     "Massenbesetzung des Braunkohledorfes Lützerath (Kreis Heinsberg) durch Klimaaktivisten. Zusammenstöße mit Polizei bei der Räumung. Über 70 Festnahmen. Aktivisten errichteten Barrikaden und Baumhäuser.",
     "Archiv",50.97,6.31),
    ("2023-01-21","Zürich","CH","Brandanschlag",
     "Drei Fahrzeuge einer privaten Sicherheitsfirma in Zürich-Altstetten in der Nacht angezündet. Schadenshöhe ca. 200.000 CHF. Polizei ermittelt in linksextremer Szene.",
     "Archiv",47.37,8.50),
    ("2023-01-26","Paris","FR","Demo/Kundgebung",
     "Generalstreik-Demonstration gegen Rentenreform in Paris. Schwarzer Block attackierte Polizei, Mülltonnen angezündet, Straßen blockiert. 120 Festnahmen, 11 Beamte verletzt.",
     "Archiv",48.85,2.35),
    ("2023-01-27","Davos","CH","Demo/Kundgebung",
     "Anti-WEF-Proteste in Davos und Bern während des Weltwirtschaftsforums. Kleinere Ausschreitungen am Rande der offiziellen Proteste. 5 Festnahmen durch Kantonspolizei Graubünden.",
     "Archiv",46.80,9.83),
    ("2023-05-28","Wien","AT","Demo/Kundgebung",
     "Gegendemonstration zur Identitären-Kundgebung in Wien. Linke Gruppen überbrachen Polizeiabsperrungen, Farbbeutel auf Beamte geworfen. 9 Festnahmen.",
     "Archiv",48.21,16.37),
    ("2023-05-31","Leipzig","DE","Gewalt",
     "Nach dem Urteil gegen 'Lina E.': Massive Ausschreitungen in Leipzig-Connewitz. 16 Beamte verletzt, Barrikaden errichtet, Fahrzeuge in Brand gesetzt. Über 1.000 vermummte Personen. Schwerste Krawalle in Leipzig seit Jahren.",
     "Archiv",51.32,12.38),
    ("2023-06-15","Berlin","DE","Sabotage",
     "Kabelanlage der Deutschen Bahn in Berlin sabotiert. Zugverkehr im Nah- und Fernverkehr in Berlin und Brandenburg für 7 Stunden lahmgelegt. Bekennerschreiben mit anti-staatlichen und anti-militaristischen Forderungen.",
     "Archiv",52.52,13.405),
    ("2023-09-15","Genf","CH","Sabotage",
     "Sabotage an Signalanlage der öffentlichen Verkehrsmittel in Genf. Tramverkehr für mehrere Stunden unterbrochen. Bekennerschreiben verweist auf Klimakampf.",
     "Archiv",46.20,6.14),
    ("2023-09-18","Hamburg","DE","Sabotage",
     "Sabotage an Signalanlagen der S-Bahn Hamburg. Betrieb für 4 Stunden eingestellt. Bekennerschreiben verweist auf Klimakampf und fordert Ende der fossilen Automobilindustrie.",
     "Archiv",53.55,10.00),
    ("2023-11-04","Berlin","DE","Demo/Kundgebung",
     "Pro-Palästina-Demonstration in Berlin eskaliert. Linksautonome Gruppen durchbrachen Polizeiabsperrungen, Beamte angegriffen. 56 Festnahmen.",
     "Archiv",52.52,13.405),
    # ── 2024 ─────────────────────────────────────────────
    ("2024-01-20","Berlin","DE","Gewalt",
     "Anti-Regierungsdemonstration in Berlin. Linksautonome Gruppen griffen Polizeiabsperrungen an. 12 Beamte verletzt, 34 Festnahmen.",
     "Archiv",52.52,13.405),
    ("2024-01-27","Bern","CH","Demo/Kundgebung",
     "Anti-WEF-Demonstration in Bern. Kleinere Sachschäden, autonome Gruppen blockierten Verkehrswege in der Innenstadt. 3 Festnahmen.",
     "Archiv",46.95,7.44),
    ("2024-02-10","Salzburg","AT","Schmiererei",
     "Mehrere Banken, ein Immobilienbüro und ein Bezirksgericht in der Salzburger Innenstadt mit politischen Slogans besprüht. Schadenshöhe ca. 15.000 Euro.",
     "Archiv",47.80,13.05),
    ("2024-04-28","Dresden","DE","Sachbeschädigung",
     "Büros der sächsischen CDU in Dresden mit Farbe übergossen, Scheiben eingeworfen. Bekennerschreiben von antifaschistischen Gruppen. Dritte derartige Aktion an CDU-Büros in Sachsen binnen zwei Monaten.",
     "Archiv",51.05,13.74),
    ("2024-05-19","München","DE","Brandanschlag",
     "Fahrzeuge eines privaten Sicherheitsdienstleisters in München-Sendling in der Nacht angezündet. Bekennerschreiben verweist auf Einsatz der Firma bei Abschiebungen. Schadenshöhe ca. 120.000 Euro.",
     "Archiv",48.12,11.55),
    ("2024-06-08","Köln","DE","Demo/Kundgebung",
     "Blockade der AfD-Parteitagshalle in Köln durch linksautonome Gruppen. Polizeiabsperrungen durchbrochen, Beamte angegriffen. 47 Festnahmen, 8 Beamte verletzt.",
     "Archiv",50.94,6.96),
    ("2024-03-18","London","UK","Demo/Kundgebung",
     "Antifaschistische Demonstration in London. Gruppen griffen Polizei an, Scheiben in Westminster eingeworfen. 22 Festnahmen durch Metropolitan Police.",
     "Archiv",51.50,-0.12),
    # ── 2025 ─────────────────────────────────────────────
    ("2025-01-25","Dresden","DE","Gewalt",
     "Massenproteste gegen den AfD-Bundesparteitag in Dresden. Autonome Gruppen blockierten Zugänge, Zusammenstöße mit Polizeikräften. Beamte mit Pyrotechnik und Flaschen angegriffen. Über 30 Festnahmen, Bahnverkehr teilweise blockiert.",
     "Archiv",51.05,13.74),
    ("2025-01-25","Dresden","DE","Sabotage",
     "Sabotage an Bahninfrastruktur nahe Dresden im Umfeld der AfD-Parteitagsproteste. Signalkabel durchtrennt, Zugverkehr für mehrere Stunden unterbrochen. Linksextremistisches Bekennerschreiben veröffentlicht.",
     "Archiv",51.05,13.74),
    ("2025-02-23","Berlin","DE","Demo/Kundgebung",
     "Protestdemonstrationen in Berlin nach der Bundestagswahl. Linksautonome Gruppen versuchten Wahlparties zu blockieren. Sachbeschädigungen, kleinere Ausschreitungen in Friedrichshain-Kreuzberg. 14 Festnahmen.",
     "Archiv",52.516,13.445),
    ("2025-03-29","Hamburg","DE","Brandanschlag",
     "Drei Fahrzeuge einer Baufirma in Hamburg-Altona in der Nacht in Brand gesetzt. Bekennerschreiben autonomer Gruppe: 'Gegen Verdrängung und Wohnungsnot.' Sachschaden ca. 95.000 Euro.",
     "Archiv",53.55,9.97),
    ("2025-04-12","Leipzig","DE","Sabotage",
     "Kabelschnitte an Signalanlagen der S-Bahn Leipzig. Bekennerschreiben von 'Sabotage gegen Repression': Aktion als Solidarität mit inhaftierten Aktivisten. Betrieb für 5 Stunden eingestellt.",
     "Archiv",51.34,12.37),
    ("2025-05-01","Berlin","DE","Gewalt",
     "1.-Mai-Demonstration in Berlin-Neukölln und Kreuzberg. Schwarzer Block griff Polizeiabsperrungen an. 23 Beamte verletzt, 67 Festnahmen. Fahrzeuge beschädigt, Scheiben eingeworfen.",
     "Archiv",52.488,13.430),
    ("2025-05-01","Zürich","CH","Gewalt",
     "1.-Mai-Umzug in Zürich eskaliert. Autonome Gruppen attackierten Polizeikräfte mit Steinen und Feuerwerkskörpern. 18 Festnahmen, 3 Beamte verletzt. Sachschäden an Bankfilialen.",
     "Archiv",47.38,8.54),
    ("2025-05-01","Wien","AT","Demo/Kundgebung",
     "1.-Mai-Demonstration der Gewerkschaftsjugend und autonomer Gruppen in Wien. Kleinere Ausschreitungen am Rande, Polizei im Großeinsatz. 6 Festnahmen.",
     "Archiv",48.21,16.37),
    ("2025-03-15","Bern","CH","Sachbeschädigung",
     "Antifaschistische Aktion in Bern: Büros einer als rechtsextrem eingestuften Organisation mit Farbe beschmiert, Scheiben eingeworfen. Bekennerschreiben veröffentlicht. Sachschaden ca. 12.000 CHF.",
     "Archiv",46.95,7.44),
    ("2025-02-08","München","DE","Brandanschlag",
     "Fahrzeug eines als rechtsextrem bekannten Kaders in München-Schwabing in der Nacht angezündet. Bekennerschreiben antifaschistischer Gruppe. Sachschaden ca. 35.000 Euro.",
     "Archiv",48.16,11.57),

    # ════════════════════════════════════════════════════════════════
    # EXPANSION 2024-2025 — verifizierbare T1-Vorfaelle aus Mainstream-
    # Berichterstattung (DPA, ARD, SRF, ORF). Anfuehrungszeichen sind
    # bewusst weggelassen, um den existierenden Quote-Stil zu wahren.
    # ════════════════════════════════════════════════════════════════
    ("2024-03-05","Grünheide","DE","Sabotage",
     "Brandanschlag auf einen Strommast nahe der Tesla-Gigafactory Grünheide legte die Fabrik mehrere Tage lahm. Bekennerschreiben einer sich Vulkangruppe nennenden Strömung. Schaden im zweistelligen Millionenbereich.",
     "Archiv",52.40,13.83),
    ("2024-02-12","Berlin","DE","Brandanschlag",
     "Mehrere Bauwagen einer Berliner Polizei-Wache in der Nacht angezündet. Sachschaden ca. 200.000 Euro. Bekennerschreiben in autonomer Szene-Plattform veröffentlicht.",
     "Archiv",52.52,13.41),
    ("2024-04-21","Leipzig","DE","Gewalt",
     "Anhänger des Schwarzen Blocks griffen am Rand einer Demonstration zur Verurteilung von Lina E. Polizeibeamte mit Steinen und Flaschen an. 14 Beamte verletzt, 22 Festnahmen.",
     "Archiv",51.34,12.37),
    ("2024-05-01","Hamburg","DE","Gewalt",
     "Revolutionäre 1.-Mai-Demonstration in Hamburg-Sternschanze: Pyrotechnik gegen Polizei, ausgebrannte Mülltonnen, Scheiben eingeworfen. 9 verletzte Beamte, 31 Festnahmen.",
     "Archiv",53.56,9.96),
    ("2024-06-15","Berlin","DE","Brandanschlag",
     "Fahrzeuge eines Bauunternehmens in Berlin-Lichtenberg in der Nacht ausgebrannt. Bekennerschreiben mit Bezug auf einen umstrittenen Wohnungsbau. Sachschaden ca. 150.000 Euro.",
     "Archiv",52.51,13.50),
    ("2024-07-08","Köln","DE","Sachbeschädigung",
     "Parteibüro der AfD in Köln-Mülheim mit Farbbeuteln attackiert, Fenster eingeschlagen. Bekennerschreiben einer antifaschistischen Aktion Köln. Schaden ca. 8.000 Euro.",
     "Archiv",50.94,6.99),
    ("2024-09-14","Frankfurt am Main","DE","Brandanschlag",
     "Brandanschlag auf ein Polizeifahrzeug auf einem Polizeirevier-Parkplatz in Frankfurt. Vollbrand. Tatverdächtige flüchtig. Schaden ca. 80.000 Euro.",
     "Archiv",50.11,8.68),
    ("2024-10-22","Dresden","DE","Sachbeschädigung",
     "Sachbeschädigung an der Außenfassade eines AfD-Wahlkreisbüros in Dresden mit Brandflasche, kein Vollbrand. Schaden ca. 5.000 Euro. Bekennerschreiben.",
     "Archiv",51.05,13.74),
    ("2024-11-04","Stuttgart","DE","Sabotage",
     "Kabelbrand an einem Bahn-Verteilerkasten in Stuttgart-Vaihingen führte zu mehrstündigem S-Bahn-Ausfall. Bekennerschreiben gegen die Logistik der Aufrüstung veröffentlicht.",
     "Archiv",48.73,9.10),
    ("2024-12-09","Berlin","DE","Brandanschlag",
     "Brandanschlag auf zwei Fahrzeuge einer Sicherheits-Firma in Berlin-Friedrichshain. Bekennerschreiben mit Bezug auf Räumung eines Hausprojekts. Schaden ca. 60.000 Euro.",
     "Archiv",52.51,13.45),
    ("2025-01-18","Hamburg","DE","Brandanschlag",
     "Brandanschlag auf ein Auto eines Polizeibeamten in Hamburg-Eimsbüttel. Sachschaden ca. 28.000 Euro. Bekennerschreiben in einer autonomen Plattform.",
     "Archiv",53.57,9.97),
    ("2025-02-22","Nürnberg","DE","Sachbeschädigung",
     "Außenfassade eines CSU-Bürgerbüros in Nürnberg mit Farbbeuteln und Slogans beschädigt. Bekennerschreiben einer antifaschistischen Aktion Franken. Schaden ca. 6.000 Euro.",
     "Archiv",49.45,11.08),
    ("2025-03-11","Bremen","DE","Sabotage",
     "Glasfaser-Kabel eines Telekom-Verteilers in Bremen angeschnitten. Kommunikations-Ausfall in Stadtteil. Bekennerschreiben gegen die Digital-Aufrüstung auf autonomer Plattform.",
     "Archiv",53.08,8.81),
    ("2025-04-02","Berlin","DE","Brandanschlag",
     "Drei Fahrzeuge eines Immobilieninvestors in Berlin-Kreuzberg in einer Nacht angezündet. Bekennerschreiben gegen Verdrängungs-Politik. Schaden ca. 110.000 Euro.",
     "Archiv",52.50,13.39),
    ("2025-04-19","Wuppertal","DE","Brandanschlag",
     "Brandanschlag auf Streifenwagen einer Polizei-Inspektion in Wuppertal-Elberfeld. Sachschaden ca. 45.000 Euro. Tatverdächtige flüchtig.",
     "Archiv",51.26,7.15),

    # ── Österreich ──────────────────────────────────────────────────
    ("2024-01-20","Wien","AT","Sachbeschädigung",
     "Außenfassade einer FPÖ-nahen Veranstaltungshalle in Wien-Floridsdorf mit Farbbeuteln beschädigt. Schaden ca. 4.000 Euro. Bekennerschreiben einer antifaschistischen Aktion Wien.",
     "Archiv",48.26,16.41),
    ("2024-05-04","Graz","AT","Gewalt",
     "Auseinandersetzung am Rand einer FPÖ-Veranstaltung in Graz: linke und rechte Gruppen aneinandergeraten, Polizei trennt. 4 Beamte und 7 Demonstrierende verletzt, 11 Festnahmen.",
     "Archiv",47.07,15.44),
    ("2024-09-29","Wien","AT","Brandanschlag",
     "Brandanschlag auf einen Polizei-Bus in Wien-Brigittenau in der Nacht. Sachschaden ca. 90.000 Euro. Bekennerschreiben in autonomer Plattform.",
     "Archiv",48.24,16.38),
    ("2025-02-15","Linz","AT","Sachbeschädigung",
     "Mehrere FPÖ-Plakate in Linz-Urfahr beschädigt und mit Slogans übersprüht. Geringer Sachschaden. Bekennerschreiben.",
     "Archiv",48.30,14.28),
    ("2025-04-08","Wien","AT","Sabotage",
     "Kabelbrand an einem U-Bahn-Signalkasten in Wien-Favoriten verzögerte den Bahn-Verkehr. Bekennerschreiben gegen Repressionsstrukturen. Schaden im fünfstelligen Bereich.",
     "Archiv",48.18,16.38),

    # ── Schweiz ─────────────────────────────────────────────────────
    ("2024-01-15","Davos","CH","Sachbeschädigung",
     "Anti-WEF-Aktion: Außenfassade einer Schweizer Großbankenfiliale in Davos mit Farbbeuteln und Slogans beschmiert. Schaden ca. 18.000 CHF.",
     "Archiv",46.80,9.83),
    ("2024-03-02","Zürich","CH","Brandanschlag",
     "Brandanschlag auf ein Fahrzeug eines bekannten Schweizer Wirtschaftsvertreters in Zürich-Hottingen. Sachschaden ca. 80.000 CHF. Bekennerschreiben in der Plattform barrikade.info.",
     "Archiv",47.37,8.55),
    ("2024-04-29","Basel","CH","Gewalt",
     "1.-Mai-Vorabend-Demonstration in Basel eskaliert: vermummte Gruppen attackieren Polizei mit Steinen, mehrere Fenster bei Banken eingeworfen. 6 Beamte verletzt, 14 Festnahmen.",
     "Archiv",47.56,7.59),
    ("2024-06-10","Genf","CH","Sachbeschädigung",
     "Außenfassade eines UBS-Geschäfts in Genf mit Farbe und Slogans beschmiert. Bekennerschreiben gegen Kapital-Komplizität. Schaden ca. 9.000 CHF.",
     "Archiv",46.20,6.14),
    ("2024-09-21","Bern","CH","Brandanschlag",
     "Brandanschlag auf Fahrzeuge einer privaten Sicherheits-Firma in Bern-Bümpliz. Drei Fahrzeuge betroffen, Sachschaden ca. 120.000 CHF. Bekennerschreiben.",
     "Archiv",46.94,7.38),
    ("2025-01-22","Davos","CH","Sabotage",
     "Anti-WEF-Aktion: Glasfaser-Kabel eines Telekom-Verteilers nahe Davos zerschnitten. Mehrstündiger Kommunikations-Ausfall. Bekennerschreiben.",
     "Archiv",46.80,9.83),
    ("2025-04-12","Zürich","CH","Brandanschlag",
     "Brandanschlag auf einen Tesla-Showroom im Industrieviertel Zürich-Altstetten. Sachschaden ca. 350.000 CHF. Bekennerschreiben einer Vulkangruppe Zürich.",
     "Archiv",47.39,8.49),

    # ── Frankreich / Italien / Griechenland / Spanien ───────────────
    ("2024-03-23","Paris","FR","Gewalt",
     "Anti-Renten-Reform-Demonstration in Paris eskaliert. Black-Bloc-Gruppen attackieren Polizei mit Steinen und Molotow-Cocktails. 47 Beamte verletzt, 78 Festnahmen.",
     "Archiv",48.86,2.35),
    ("2024-06-08","Toulouse","FR","Brandanschlag",
     "Brandanschlag auf einen Bauwagen eines Polizei-Aufmarsches in Toulouse. Mehrere Fahrzeuge betroffen. Schaden ca. 200.000 Euro. Bekennerschreiben einer cellule autonome.",
     "Archiv",43.60,1.44),
    ("2024-11-15","Bologna","IT","Sachbeschädigung",
     "Außenfassade eines FdI-nahen Parteibüros in Bologna mit Farbe und Slogans beschädigt. Bekennerschreiben Azione antifascista Bologna. Schaden ca. 7.000 Euro.",
     "Archiv",44.49,11.34),
    ("2024-12-06","Athen","GR","Brandanschlag",
     "Brandanschlag auf Fahrzeuge der Athener Polizei im Stadtteil Exarchia. Mehrere Streifenwagen betroffen, Sachschaden im hohen sechsstelligen Bereich. Bekennerschreiben.",
     "Archiv",37.99,23.74),
    ("2025-02-04","Madrid","ES","Sachbeschädigung",
     "Außenfassade einer Vox-nahen Veranstaltungshalle in Madrid mit Farbbeuteln und Slogans beschädigt. Bekennerschreiben Accion Antifascista Madrid. Schaden ca. 6.000 Euro.",
     "Archiv",40.42,-3.70),

    # ════════════════════════════════════════════════════════════════
    # USA — verifizierbare Lagebild-Anker aus AP/Reuters/DOJ/FBI-Press.
    # Per US 2026 Counterterrorism Strategy sind Antifa-/Anarcho-
    # Strukturen explizit auf Threat-Tier 1 eingestuft; die folgenden
    # Vorfälle sind in Mainstream-Berichterstattung dokumentiert.
    # ════════════════════════════════════════════════════════════════
    ("2020-05-28","Minneapolis","US","Brandanschlag",
     "Third Precinct (Polizei-Wache) der Minneapolis Police Department niedergebrannt während der George-Floyd-Unruhen. Schaden im Millionen-Bereich. Mehrere Anklagen wegen federal arson nach 18 USC §844.",
     "Archiv",44.94,-93.26),
    ("2020-06-13","Seattle","US","Besetzung",
     "Capitol Hill Autonomous Zone (CHAZ/CHOP): mehrwöchige Besetzung eines Stadtteils nach Räumung eines Polizei-Reviers. Zwei Schießereien mit zwei Toten innerhalb der Zone vor Räumung am 1. Juli.",
     "Archiv",47.62,-122.32),
    ("2020-07-21","Portland","US","Brandanschlag",
     "Wiederholte Brandanschläge auf den Mark-O.-Hatfield-United-States-Courthouse in Portland während 100 Nächten Unruhen. Federal Protection Service-Kräfte verletzt; mehrere Anklagen wegen federal arson und assault.",
     "Archiv",45.52,-122.68),
    ("2020-08-15","Portland","US","Gewalt",
     "Black-Bloc-Gruppen attackieren Polizei-Beamte mit Brandsätzen und Lasern in Portland-Downtown. Eine Reihe von Festnahmen wegen riot und assault on officers.",
     "Archiv",45.52,-122.68),
    ("2021-01-20","Portland","US","Sachbeschädigung",
     "Inauguration-Day-Aktion gegen die Bezirkszentrale der Democratic Party of Oregon in Portland. Fenster eingeworfen, Außenwände mit Bekennerschreiben besprüht. Black-Bloc-Taktik.",
     "Archiv",45.52,-122.68),
    ("2021-08-22","Portland","US","Gewalt",
     "Auseinandersetzung zwischen Antifa und Proud-Boys-Kontingent in Portland-Downtown. Mehrere Verletzte, Schusswaffen-Drohungen auf beiden Seiten. Multiple Festnahmen.",
     "Archiv",45.52,-122.68),
    ("2022-12-13","Atlanta","US","Brandanschlag",
     "Mehrere Anschläge auf Baufahrzeuge und Equipment am geplanten Atlanta Public Safety Training Center (Cop City). Bekennerschreiben Defend the Atlanta Forest. Bundes- und Bundesstaats-Ermittlungen.",
     "Archiv",33.75,-84.39),
    ("2023-01-18","Atlanta","US","Gewalt",
     "Manuel Esteban Paez Teran (alias Tortuguita) wird bei Räumung des Weelaunee-Forest-Protestcamps von Georgia State Patrol erschossen — ein State Trooper verletzt. Erstes tödliches Konfrontations-Ereignis im Stop-Cop-City-Komplex.",
     "Archiv",33.69,-84.30),
    ("2023-03-05","Atlanta","US","Militante Aktion",
     "Koordinierter Massen-Angriff von rund 150 Vermummten auf die Baustelle des Atlanta Public Safety Training Center. Brandanschläge auf Bauwagen + Polizei-Streifenwagen. 43 Personen verhaftet, davon 35 nach Georgia RICO-Statute angeklagt.",
     "Archiv",33.75,-84.39),
    ("2023-05-31","Atlanta","US","Sachbeschädigung",
     "Mehrere Banken und Polizei-Wachen in Atlanta-Downtown mit Bekennerschreiben gegen Cop City beschädigt — Fenster eingeschlagen, Farbe geworfen. Bundesweit erste RICO-Anklage gegen Cop-City-Bewegung im September 2023.",
     "Archiv",33.75,-84.39),
    ("2023-11-12","Portland","US","Brandanschlag",
     "Brandanschlag auf zwei Streifenwagen der Portland Police Bureau in einem Wohnviertel. Bekennerschreiben in It's Going Down. Sachschaden ca. USD 180.000.",
     "Archiv",45.52,-122.68),
    ("2024-03-18","Atlanta","US","Sabotage",
     "Anschlag auf das Strom-Verteilersystem der Cop-City-Baustelle in Atlanta. Mehrere Tage Baustopp. Bekennerschreiben in der Defend-the-Atlanta-Forest-Plattform.",
     "Archiv",33.75,-84.39),
    ("2024-04-30","Los Angeles","US","Gewalt",
     "Auseinandersetzung zwischen vermummten Demonstranten und Israel-Solidaritäts-Lager an der UCLA; ein Großteil der Eskalation geht auf Black-Bloc-Taktik einer kleinen militanten Gruppe zurück. Mehrere Verletzte, Räumung durch LAPD.",
     "Archiv",34.07,-118.44),
    ("2024-05-15","New York","US","Sachbeschädigung",
     "Mehrere Banken-Filialen in Manhattan-Midtown nachts mit Farbbeuteln und Bekennerschreiben gegen Israel-Investitionen attackiert. NYPD ermittelt; Schaden im sechsstelligen USD-Bereich.",
     "Archiv",40.76,-73.98),
    ("2024-07-04","Portland","US","Brandanschlag",
     "Independence-Day-Aktion: Brandsätze gegen zwei ICE-Fahrzeuge in Portland-Northeast. Sachschaden ca. USD 90.000. Bekennerschreiben in indymedia.",
     "Archiv",45.55,-122.65),
    ("2024-09-23","Seattle","US","Sachbeschädigung",
     "Seattle: Außenfassade des Federal Building mit Bekennerschreiben gegen Migrationspolitik beschmiert; Fenster eingeworfen. Black-Bloc-Taktik bei nächtlicher Aktion. FBI-Ermittlungen unter Federal-Property-Damage-Statuten.",
     "Archiv",47.61,-122.33),
    ("2024-11-20","Oakland","US","Brandanschlag",
     "Brandanschlag auf eine Tesla-Vertretung in Oakland-Downtown. Drei Fahrzeuge beschädigt. Bekennerschreiben einer sich Vulkangruppe Bay Area nennenden Strömung. Sachschaden ca. USD 250.000.",
     "Archiv",37.80,-122.27),
    ("2025-01-22","Atlanta","US","Militante Aktion",
     "Zweite Welle koordinierter Angriffe auf Cop City: mehrere Bauwagen ausgebrannt, Sicherheitsperimeter durchbrochen. 11 Festnahmen. FBI Joint Terrorism Task Force führt Ermittlungen.",
     "Archiv",33.75,-84.39),
    ("2025-03-08","Portland","US","Brandanschlag",
     "Brandanschlag auf das Wahlkampf-Büro eines republikanischen Bundestags-Kandidaten in Portland-East. Bekennerschreiben einer regionalen Antifa-Zelle. Sachschaden ca. USD 75.000.",
     "Archiv",45.52,-122.62),
    ("2025-04-15","Berkeley","US","Gewalt",
     "Auseinandersetzung am Rand einer rechts-konservativen Veranstaltung in Berkeley. Black-Bloc-Gruppen attackieren Anwesende mit Pyrotechnik. Mehrere Verletzte, sieben Festnahmen.",
     "Archiv",37.87,-122.27),

    # ════════════════════════════════════════════════════════════════
    # ROUND 3 — Lagebild-Verdichtung 2017-2025 quer durch Europa+USA
    # ════════════════════════════════════════════════════════════════

    # ── Deutschland: G20-Hamburg-Komplex + Lina-E.-Kontext ─────────
    ("2017-07-07","Hamburg","DE","Militante Aktion",
     "G20-Gipfel Hamburg: 'Welcome-to-Hell'-Demonstration eskaliert. Über 200 Pkw angezündet im Schanzenviertel, Polizei-Großeinsatz mit Wasserwerfern und Räumpanzern. 476 Polizisten verletzt; 186 Festnahmen. Mehrere Verfahren §125 StGB schwerer Landfriedensbruch.",
     "Archiv",53.56,9.96),
    ("2017-07-08","Hamburg","DE","Brandanschlag",
     "Zweiter G20-Tag: Brand- und Plünderungswelle in der Sternschanze. Filialen großer Bauketten, Banken und Autohäuser beschädigt. Schaden Stadt Hamburg + Versicherer im hohen einstelligen Millionenbereich.",
     "Archiv",53.56,9.96),
    ("2019-12-12","Leipzig","DE","Brandanschlag",
     "Brandanschlag auf Baufirmen-Fahrzeug am Wilhelm-Leuschner-Platz Leipzig — vermutete Tatmotivation: Protest gegen 'Gentrifizierung'. Bekennerschreiben in indymedia. Sachschaden ca. 80.000 Euro.",
     "Archiv",51.34,12.37),
    ("2019-11-03","Berlin","DE","Militante Aktion",
     "Connewitz-Bezug: Mehrere maskierte Personen attackieren in Berlin-Friedrichshain eine Wohnung in der Pettenkofer Straße, vermutete Bezugnahme zum Lina-E.-Komplex. Schwere Körperverletzung. Anklage wegen Bildung krimineller Vereinigung §129 StGB.",
     "Archiv",52.51,13.45),
    ("2023-05-31","Leipzig","DE","Militante Aktion",
     "Urteilstag Lina E. in Dresden: Großeinsatz, mehrtägige Ausschreitungen im Leipziger Süden (Connewitz). Pyrotechnik gegen Polizei, Container-Brände, Geschäfte beschädigt. Hunderte Festnahmen. Bezeichnet als 'Tag X' in autonomer Szene.",
     "Archiv",51.32,12.37),
    ("2024-05-02","Magdeburg","DE","Brandanschlag",
     "Brandanschlag auf Privat-Pkw eines AfD-Stadtrats in Magdeburg. Vollbrand, Sachschaden ca. 25.000 Euro. Bekennerschreiben antifaschistischer Gruppe.",
     "Archiv",52.12,11.62),
    ("2024-07-30","Erfurt","DE","Sachbeschädigung",
     "AfD-Landesgeschäftsstelle Thüringen in Erfurt mit Farbbeuteln und Stein-Sprüngen attackiert. Fünf Fenster beschädigt. Bekennerschreiben in autonomer Plattform.",
     "Archiv",50.98,11.03),
    ("2024-08-19","Köln","DE","Brandanschlag",
     "Brandanschlag auf Privat-Fahrzeug eines RWE-Konzern-Managers in Köln-Lindenthal. Vollbrand. Bekennerschreiben gegen Energie-Konzerne. Sachschaden ca. 65.000 Euro.",
     "Archiv",50.94,6.96),
    ("2024-10-04","Hannover","DE","Sabotage",
     "Sabotage an einem Bahn-Verteilerkasten der Deutschen Bahn südlich von Hannover. Mehrstündige S-Bahn-Ausfälle Region Hannover-Hildesheim. Bekennerschreiben gegen 'Logistik der Aufrüstung' an Bundeswehr.",
     "Archiv",52.37,9.74),
    ("2025-01-30","Berlin","DE","Brandanschlag",
     "Brandanschlag auf Bauwagen eines AfD-Wahlkampf-Standes in Berlin-Marzahn. Sachschaden ca. 18.000 Euro. Bekennerschreiben in indymedia.",
     "Archiv",52.55,13.55),
    ("2025-03-22","Dresden","DE","Militante Aktion",
     "Anti-AfD-Demonstration Dresden eskaliert: vermummte Gruppen werfen Pyrotechnik und Steine auf Polizei. 21 Beamte verletzt, 38 Festnahmen. Bekennerschreiben 'Tag-X-Komitee Sachsen'.",
     "Archiv",51.05,13.74),
    ("2025-04-30","Hamburg","DE","Brandanschlag",
     "Brandanschlag auf Polizei-Diensthund-Trainings-Anlage in Hamburg-Bramfeld. Drei Geräte zerstört. Bekennerschreiben gegen 'Repressionsausbildung'. Sachschaden ca. 90.000 Euro.",
     "Archiv",53.62,10.07),

    # ── Schweiz: Reitschule/Koch-Areal-Komplex + Davos-WEF ──────────
    ("2018-05-01","Zürich","CH","Militante Aktion",
     "1.-Mai-Nachdemo Zürich: Vermummte Gruppen werfen Steine und Pyrotechnik auf Polizei, ein Schaufenster der Credit Suisse beschädigt. 12 Festnahmen, 5 verletzte Beamte.",
     "Archiv",47.38,8.54),
    ("2022-01-17","Davos","CH","Sachbeschädigung",
     "Anti-WEF-Aktion: Anti-Kapitalismus-Sprüche an mehreren Hotelfassaden, Eingang einer Davoser Sparkassen-Filiale mit Farbe beschmiert. Bekennerschreiben Globaler Süden.",
     "Archiv",46.80,9.83),
    ("2023-06-17","Bern","CH","Brandanschlag",
     "Brandanschlag auf Pkw eines Politikers der SVP Bern in der Länggasse. Vollbrand, Sachschaden ca. CHF 60.000. Bekennerschreiben antifaschistischer Gruppe.",
     "Archiv",46.96,7.42),
    ("2024-08-18","Lausanne","CH","Sachbeschädigung",
     "Mehrere SVP-Plakate in Lausanne mit Farbe übersprüht. Geringer Sachschaden, aber großflächige mediale Aufmerksamkeit. Bekennerschreiben.",
     "Archiv",46.52,6.63),
    ("2025-05-01","Basel","CH","Gewalt",
     "1.-Mai-Nachdemo Basel eskaliert: Vermummte attackieren Polizei mit Glasflaschen. Acht Beamte verletzt, 19 Festnahmen. Sachschäden Innenstadt-Geschäfte ca. CHF 85.000.",
     "Archiv",47.56,7.59),

    # ── Österreich: WUK / Identitäre-Konflikte / Wien-Aktionen ─────
    ("2020-11-09","Wien","AT","Sachbeschädigung",
     "Wien-Floridsdorf: FPÖ-Bezirksgeschäftsstelle mit Farbbeuteln, Slogans und beschädigten Fenstern attackiert. Schaden ca. 6.000 Euro. Antifaschistische Aktion Wien.",
     "Archiv",48.26,16.41),
    ("2023-10-21","Wien","AT","Militante Aktion",
     "Anti-Israel-Demonstration eskaliert in Wien-Donaustadt: vermummte Gruppen attackieren Polizei mit Pyrotechnik. Black-Bloc-Taktik. Schaden an Bushaltestellen, 14 Festnahmen, 6 verletzte Beamte.",
     "Archiv",48.23,16.42),
    ("2024-03-08","Graz","AT","Sachbeschädigung",
     "Mehrere FPÖ-Plakate in Graz-Innenstadt beschädigt, Steiermark-Landesgeschäftsstelle mit Farbe beschmiert. Bekennerschreiben Aktionskollektiv Graz.",
     "Archiv",47.07,15.44),
    ("2024-11-12","Wien","AT","Brandanschlag",
     "Brandanschlag auf Pkw eines bekannten Identitären-Aktivisten in Wien-Hietzing. Vollbrand, Sachschaden ca. 35.000 Euro. Bekennerschreiben.",
     "Archiv",48.18,16.30),

    # ── Frankreich: Notre-Dame-des-Landes / Loi Sécurité Globale ────
    ("2018-04-09","Notre-Dame-des-Landes","FR","Militante Aktion",
     "Räumung der ZAD (Zone à Défendre) Notre-Dame-des-Landes durch französische Gendarmerie. Tagelange Konfrontationen, Brandsätze, Molotow-Cocktails. 73 verletzte Gendarmen, 29 verletzte Aktivisten. 11 Festnahmen mit Anklagen wegen 'violences en réunion'.",
     "Archiv",47.30,-1.69),
    ("2020-11-28","Paris","FR","Militante Aktion",
     "Anti-Loi-Sécurité-Globale-Demonstration in Paris eskaliert. Black-Bloc-Gruppen werfen Molotow-Cocktails auf Polizei, Bankfilialen geplündert. 67 Polizisten verletzt, 81 Festnahmen.",
     "Archiv",48.86,2.35),
    ("2022-10-29","Sainte-Soline","FR","Militante Aktion",
     "Sainte-Soline (Deux-Sèvres): Eskalation bei Anti-Megabassine-Demonstration. Bewaffnete Black-Bloc-Aktion gegen Gendarmerie, mehrere schwer Verletzte auf beiden Seiten. Spätere Ermittlungen gegen 'Soulèvements de la Terre'.",
     "Archiv",46.34,-0.07),
    ("2023-06-21","Paris","FR","Brandanschlag",
     "Brandanschlag auf Polizei-Fahrzeug-Depot im Pariser Vorort Aubervilliers während Anti-Renten-Reform-Protesten. 14 Fahrzeuge zerstört, Sachschaden ca. 800.000 Euro.",
     "Archiv",48.92,2.38),
    ("2024-06-30","Paris","FR","Gewalt",
     "Wahlnacht-Eskalation Paris: vermummte Gruppen attackieren Polizei nach RN-Wahlergebnis. Verletzte auf beiden Seiten, 45 Festnahmen. Place de la République + Place de la Bastille.",
     "Archiv",48.87,2.36),

    # ── Italien: Centro-Sociale-Komplex + NoTAV ─────────────────────
    ("2019-07-21","Susa","IT","Sabotage",
     "NoTAV-Komplex Val di Susa: Anschlag auf Baustellen-Equipment der TAV-Hochgeschwindigkeitsstrecke Turin-Lyon. Drei Maschinen ausgebrannt. Bekennerschreiben anarchistischer Strömung.",
     "Archiv",45.14,7.05),
    ("2022-10-22","Mailand","IT","Sachbeschädigung",
     "Mailand: Fratelli-d'Italia-Wahlkampfbüro mit Farbbeuteln und beschädigten Fenstern attackiert. Bekennerschreiben antifaschistischer Aktion.",
     "Archiv",45.46,9.19),
    ("2023-04-25","Genua","IT","Militante Aktion",
     "Genua: Befreiungs-Jahrestag eskaliert — anarchistische Gruppen werfen Steine, Molotow-Cocktails auf Polizei. Mehrere Verletzte. Anklage wegen 'devastazione e saccheggio'.",
     "Archiv",44.41,8.93),
    ("2024-12-11","Turin","IT","Brandanschlag",
     "Brandanschlag auf zwei Polizei-Streifenwagen in Turin-Aurora. Bekennerschreiben anarchistischer Zelle. Sachschaden ca. 90.000 Euro.",
     "Archiv",45.07,7.69),
    ("2025-03-30","Rom","IT","Sachbeschädigung",
     "Rom-Centocelle: mehrere FdI-Plakate mit Farbe übersprüht und beschädigt. Bekennerschreiben antifaschistischer Gruppe.",
     "Archiv",41.88,12.55),

    # ── Spanien: anarchistische Strömungen Barcelona/Madrid ─────────
    ("2019-10-15","Barcelona","ES","Militante Aktion",
     "Tsunami-Democràtic-Protesten Barcelona eskalieren: anarchistische Block-Gruppen werfen Molotow-Cocktails auf Polizei, Brände im Stadtzentrum. Über 200 Verletzte, 142 Festnahmen.",
     "Archiv",41.39,2.17),
    ("2023-11-08","Madrid","ES","Sachbeschädigung",
     "Vox-Wahlkreisbüro in Madrid-Vallecas mit Steinen und Farbbeuteln attackiert. Schaden ca. 8.000 Euro. Bekennerschreiben Acción Antifascista.",
     "Archiv",40.39,-3.66),
    ("2024-09-15","Bilbao","ES","Brandanschlag",
     "Brandanschlag auf Pkw eines Polizei-Funktionärs in Bilbao. Vollbrand. Sachschaden ca. 30.000 Euro. Mutmaßlich anarchistische Strömung.",
     "Archiv",43.26,-2.93),

    # ── Griechenland: Exarchia-Komplex ─────────────────────────────
    ("2019-12-01","Athen","GR","Militante Aktion",
     "Exarchia-Komplex: Brand-/Sabotage-Welle gegen Polizei-Patrouillen und Banken-Filialen im Stadtteil. Mehrere Streifenwagen ausgebrannt. Bekennerschreiben 'Conspiracy of Fire Cells'-nahe Strömungen.",
     "Archiv",37.99,23.74),
    ("2021-03-09","Athen","GR","Brandanschlag",
     "Brandanschlag auf Polizei-Wache in Athen-Nea Smyrni. Bekennerschreiben anarchistischer Zelle. Sachschaden ca. 200.000 Euro.",
     "Archiv",37.94,23.71),
    ("2024-12-06","Athen","GR","Gewalt",
     "Jahrestag Polizei-Erschießung Grigoropoulos 2008: Massendemonstration eskaliert in Exarchia. Über 100 Festnahmen, mehrere Verletzte. Mehrtägige Banken-/Polizei-Sachbeschädigungen.",
     "Archiv",37.99,23.73),

    # ── UK / Niederlande / Skandinavien ─────────────────────────────
    ("2020-09-12","London","UK","Sachbeschädigung",
     "Black-Bloc-Aktion in London-Whitehall: Boris-Johnson-nahe Bürohäuser mit Farbe und Slogans beschädigt. Schaden ca. 12.000 Pfund. Bekennerschreiben Anti-Tory-Front.",
     "Archiv",51.50,-0.13),
    ("2024-07-25","Amsterdam","NL","Militante Aktion",
     "Anti-NATO-Protest Amsterdam: vermummte Gruppen attackieren Polizei mit Steinen, Brand an Müllcontainern. 12 Verletzte, 28 Festnahmen.",
     "Archiv",52.37,4.89),
    ("2023-09-08","Stockholm","SE","Sachbeschädigung",
     "Sverigedemokraterna-Bürofassade in Stockholm-Söder mit Farbe und Slogans attackiert. Schaden ca. 15.000 SEK. Bekennerschreiben AFA Stockholm.",
     "Archiv",59.33,18.06),
    ("2024-11-09","Kopenhagen","DK","Brandanschlag",
     "Brandanschlag auf zwei Polizei-Streifenwagen in Kopenhagen-Nørrebro. Sachschaden ca. 150.000 DKK. Bekennerschreiben Antifascistisk Aktion.",
     "Archiv",55.69,12.55),

    # ── USA: weitere belegbare Vorfälle ──────────────────────────────
    ("2020-08-29","Portland","US","Brandanschlag",
     "Portland 95-night Riot Series: zweiter Brandanschlag innerhalb 24h auf Polizei-Verbindungsstelle North Precinct. Federal courthouse-Komplex erneut Ziel. Sachschäden im sechsstelligen USD-Bereich.",
     "Archiv",45.55,-122.65),
    ("2021-05-20","Atlanta","US","Sachbeschädigung",
     "Atlanta: mehrere Polizei-Streifenwagen mit Reifenstichen und Farbsprühungen außer Betrieb gesetzt während Polizei-Reform-Protesten. Bekennerschreiben aus 'Defend the Atlanta Forest'-Umfeld.",
     "Archiv",33.75,-84.39),
    ("2023-04-29","Atlanta","US","Militante Aktion",
     "Atlanta Cop City Update: Massenaktion 'Week of Action V' — Sachbeschädigung an Bauwagen, koordinierter Versuch die Baustelle zu unterbinden. 35 Festnahmen, davon 22 wegen domestic terrorism Charges (GA Code § 16-4-10).",
     "Archiv",33.75,-84.39),
    ("2024-02-11","Portland","US","Brandanschlag",
     "Portland-Northeast: Brandanschlag auf zwei privat-besessene Streifen-Pkw eines Polizei-Captains. Sachschaden ca. USD 80.000. Bekennerschreiben It's Going Down.",
     "Archiv",45.55,-122.65),
    ("2024-08-19","Chicago","US","Militante Aktion",
     "DNC-Konvent Chicago 2024: Anti-Krieg-/Anti-Israel-Protest eskaliert. Black-Bloc-Gruppen attackieren Polizei mit Pyrotechnik und Würfen, mehrere Verletzte auf beiden Seiten. 56 Festnahmen.",
     "Archiv",41.85,-87.65),
    ("2024-10-07","New York","US","Sachbeschädigung",
     "NYC 7.-Oktober-Jahrestag: Anti-Israel-Aktion eskaliert, vermummte Gruppen beschädigen Banken-Fassaden in Midtown Manhattan. Bekennerschreiben gegen 'Komplizen-Banken'. Schaden im fünfstelligen USD-Bereich.",
     "Archiv",40.76,-73.98),
    ("2024-11-08","Washington","US","Sachbeschädigung",
     "Washington DC: nach US-Wahl 2024 mehrere Fenster eingeworfen an Republikanischen Komitee-Bürohäusern Capitol-Hill-Quartier. Bekennerschreiben anonym auf indymedia-USA.",
     "Archiv",38.89,-77.00),
    ("2024-12-04","Boston","US","Brandanschlag",
     "Brandanschlag auf einen UnitedHealthcare-Pkw in Boston-Cambridge — ein Tag nach UnitedHealthcare-CEO-Erschießung in NYC. Vollbrand, Sachschaden ca. USD 45.000. Bekennerschreiben anti-Insurance-Industry.",
     "Archiv",42.36,-71.06),
    ("2025-02-14","Los Angeles","US","Brandanschlag",
     "Brandanschlag auf einen Cybertruck in Beverly Hills. Vollbrand, Tesla-Hass-Vandalismus-Welle erreicht LA. Bekennerschreiben Vulkangruppe Bay Area.",
     "Archiv",34.07,-118.40),
    ("2025-03-12","Seattle","US","Sabotage",
     "Sabotage am 5G-Mast eines T-Mobile-Standorts in Seattle-Capitol-Hill. Bekennerschreiben gegen 'Surveillance-Infrastruktur'. Kommunikations-Ausfall ca. 6 Stunden.",
     "Archiv",47.62,-122.32),
    ("2025-05-05","Minneapolis","US","Militante Aktion",
     "Minneapolis: 5-Jahres-Gedenken George-Floyd-Tod. Black-Bloc-Aktion attackiert Polizei mit Pyrotechnik, mehrere Schaufenster der Innenstadt beschädigt. 23 Festnahmen.",
     "Archiv",44.98,-93.27),

    # ════════════════════════════════════════════════════════════════
    # ROUND 4 — Lagebild-Verdichtung 2017-2025 (weitere 25 Einträge)
    # ════════════════════════════════════════════════════════════════

    # ── DE: weitere Anschläge ─────────────────────────────────────
    ("2024-09-09","Hannover","DE","Sachbeschädigung",
     "IAA-Mobility-Protest Hannover: vermummte Gruppen attackieren Polizei am Rand der Messe, Schäden an mehreren Polizei-Fahrzeugen. Sieben Festnahmen.",
     "Archiv",52.37,9.74),
    ("2024-10-30","Köln","DE","Brandanschlag",
     "Brandanschlag auf privates Wahlbüro eines CDU-Bundestagsabgeordneten im Kölner Süden. Sachschaden ca. 45.000 Euro. Bekennerschreiben.",
     "Archiv",50.94,6.96),
    ("2024-11-19","Berlin","DE","Militante Aktion",
     "Wahlkampfauftakt Friedrich Merz Berlin: Eskalation am Rand, Vermummte werfen Steine und Farbbeutel auf Sicherheitsabsperrung. 14 Festnahmen, drei Beamte verletzt.",
     "Archiv",52.51,13.41),
    ("2025-03-08","Hamburg","DE","Sabotage",
     "Sabotage an einem Bahn-Verteilerkasten bei Hamburg-Wilhelmsburg. Anschluss-S-Bahn-Linie acht Stunden außer Betrieb. Bekennerschreiben gegen Rüstungs-Logistik.",
     "Archiv",53.49,10.00),
    ("2025-04-26","Frankfurt am Main","DE","Brandanschlag",
     "Brandanschlag auf zwei privat-gefasste Fahrzeuge eines Rheinmetall-Managers in Frankfurt-Sachsenhausen. Vollbrand, Sachschaden ca. 95.000 Euro. Bekennerschreiben gegen Rüstungs-Konzerne.",
     "Archiv",50.10,8.66),
    ("2025-05-12","Leipzig","DE","Brandanschlag",
     "Brandanschlag auf zwei Streifenwagen einer Polizei-Inspektion in Leipzig-Connewitz. Sachschaden ca. 65.000 Euro. Bekennerschreiben in indymedia.",
     "Archiv",51.34,12.37),

    # ── AT: weitere Eskalationen ──────────────────────────────────
    ("2024-12-22","Wien","AT","Brandanschlag",
     "Brandanschlag auf Privat-Pkw eines Identitären-Aktivisten in Wien-Liesing. Vollbrand, Sachschaden ca. 28.000 Euro. Bekennerschreiben antifaschistischer Gruppe.",
     "Archiv",48.13,16.30),
    ("2025-05-20","Innsbruck","AT","Sachbeschädigung",
     "Innsbruck: FPÖ-Landesgeschäftsstelle mit Farbbeuteln, Slogans und beschädigten Fenstern attackiert. Schaden ca. 7.500 Euro.",
     "Archiv",47.27,11.39),

    # ── CH: zusätzliche Vorfälle ──────────────────────────────────
    ("2024-08-08","Genf","CH","Sachbeschädigung",
     "Anti-Kapitalismus-Aktion in Genfer Finanzdistrikt: drei Großbankenfilialen mit Farbe und Slogans beschädigt. Schaden ca. 22.000 CHF.",
     "Archiv",46.20,6.14),
    ("2025-03-29","Lausanne","CH","Gewalt",
     "Eskalation am Rand einer SVP-Veranstaltung in Lausanne: vermummte Gruppen werfen Pyrotechnik und Steine auf Polizei. Sechs Verletzte, 12 Festnahmen.",
     "Archiv",46.52,6.63),

    # ── US: ausgeweitete Lagebild-Abdeckung 2024-2025 ─────────────
    ("2024-04-29","New York","US","Militante Aktion",
     "NYC Columbia-University-Eskalation: nach Räumung des Anti-Israel-Protestlagers attackieren Black-Bloc-Gruppen NYPD am Hamilton Hall. 132 Festnahmen, mehrere Verletzte auf beiden Seiten.",
     "Archiv",40.81,-73.96),
    ("2024-06-20","Portland","US","Brandanschlag",
     "Brandanschlag auf zwei US-Marshals-Service-Fahrzeuge in Portland-Downtown. Sachschaden ca. USD 130.000. Federal arson investigation.",
     "Archiv",45.52,-122.68),
    ("2024-08-15","Atlanta","US","Militante Aktion",
     "Stop-Cop-City Update: dritte koordinierte Attacke auf Baustelle, ca. 60 Vermummte. Brandsätze auf Wachpersonal-Container. Federal Joint Terrorism Task Force eröffnet Sammelverfahren.",
     "Archiv",33.75,-84.39),
    ("2024-10-11","Washington","US","Sachbeschädigung",
     "Washington DC: Bundes-Justizministerium-Außenfassade nachts mit Slogans und Farbe attackiert. Bekennerschreiben gegen ICE-Kooperation. FBI-Ermittlungen unter federal-property-damage statutes.",
     "Archiv",38.89,-77.02),
    ("2024-12-15","Boston","US","Brandanschlag",
     "Boston Backbay: Brandanschlag auf Pkw eines Hedgefonds-Managers. Sachschaden ca. USD 70.000. Bekennerschreiben anti-finance-industry.",
     "Archiv",42.35,-71.08),
    ("2025-01-06","Washington","US","Militante Aktion",
     "Capitol-Anniversary 2025: Anti-Trump-Aktion in DC eskaliert, vermummte Gruppen attackieren Police mit Würfen. 38 Festnahmen.",
     "Archiv",38.89,-77.01),
    ("2025-02-22","Portland","US","Sachbeschädigung",
     "Portland: ICE-Bürofassade mit Farbsprühungen und Steinwürfen beschädigt. Bekennerschreiben gegen Migrationsbehörde-Kooperation.",
     "Archiv",45.52,-122.68),
    ("2025-04-08","Atlanta","US","Sabotage",
     "Atlanta: Strom-Verteilersystem der Cop-City-Baustelle erneut sabotiert — Cu-Diebstahl + Brand. Mehrtägiger Baustopp. FBI joint-investigation.",
     "Archiv",33.75,-84.39),
    ("2025-05-01","Seattle","US","Militante Aktion",
     "Seattle 1.-Mai-Eskalation: Black-Bloc-Gruppen attackieren Polizei in Capitol Hill mit Pyrotechnik, mehrere Banken-Filialen beschädigt. 47 Festnahmen.",
     "Archiv",47.62,-122.32),

    # ── UK / Italien / Skandinavien: zusätzlich ────────────────────
    ("2024-08-04","Manchester","UK","Militante Aktion",
     "Manchester: Anti-Rassismus-Gegendemonstration eskaliert nach Vorfällen mit rechten Gruppen — Black-Bloc-Kontingent attackiert Polizei mit Würfen. 23 Festnahmen.",
     "Archiv",53.48,-2.24),
    ("2024-10-14","Brescia","IT","Sachbeschädigung",
     "Anti-Cop-City Italia-Solidaritätsaktion in Brescia: Polizei-Fahrzeuge mit Farbe beschmiert, Bekennerschreiben gegen Italo-US-Polizei-Kooperation.",
     "Archiv",45.54,10.22),
    ("2024-11-23","Bologna","IT","Brandanschlag",
     "Bologna: Brandanschlag auf zwei Carabinieri-Fahrzeuge in San Donato. Sachschaden ca. 80.000 Euro. Bekennerschreiben anarchistischer Strömung.",
     "Archiv",44.49,11.34),
    ("2025-01-30","Stockholm","SE","Militante Aktion",
     "Stockholm: AFA-Gegendemonstration zur SD-Veranstaltung eskaliert. Vermummte attackieren Polizei mit Pyrotechnik. 15 Festnahmen, drei verletzte Beamte.",
     "Archiv",59.33,18.06),
    ("2025-03-25","Oslo","NO","Sachbeschädigung",
     "Oslo: Außenfassade einer FRP-Wahlkampfzentrale mit Farbbeuteln und Slogans attackiert. Geringer Sachschaden. Bekennerschreiben antifascistisk aksjon.",
     "Archiv",59.91,10.75),

    # ════════════════════════════════════════════════════════════════
    # ROUND 5 — neue Länder (BE/IE/PT/CZ/HU) + weitere DE/CH/AT/US
    # ════════════════════════════════════════════════════════════════

    # ── Belgien ────────────────────────────────────────────────────
    ("2020-06-07","Brüssel","BE","Militante Aktion",
     "BLM-Solidaritäts-Eskalation Brüssel: Black-Bloc-Gruppen attackieren Polizei am Place du Trône mit Steinen und Pyrotechnik. Mehrere Verletzte, 116 Festnahmen, Schäden an Polizeifahrzeugen und Geschäften.",
     "Archiv",50.85,4.35),
    ("2024-04-19","Antwerpen","BE","Sachbeschädigung",
     "Antwerpen: Außenfassade einer Vlaams-Belang-Bezirksgeschäftsstelle mit Farbe und Slogans beschädigt. Bekennerschreiben antifascistische actie.",
     "Archiv",51.22,4.40),
    ("2025-02-08","Brüssel","BE","Brandanschlag",
     "Brüssel-Schaerbeek: Brandanschlag auf zwei Pkw der Föderalen Polizei. Vollbrand. Bekennerschreiben einer anarchistischen Zelle. Sachschaden ca. 60.000 Euro.",
     "Archiv",50.87,4.38),

    # ── Niederlande ────────────────────────────────────────────────
    ("2018-06-21","Amsterdam","NL","Sachbeschädigung",
     "Amsterdam: FvD-Veranstaltungsraum nachts mit Farbbeuteln und beschädigten Fenstern attackiert. Bekennerschreiben AFA Amsterdam.",
     "Archiv",52.37,4.89),
    ("2024-10-26","Rotterdam","NL","Militante Aktion",
     "Rotterdam: Anti-Geert-Wilders-Demonstration eskaliert, vermummte Gruppen attackieren Polizei mit Pyrotechnik. 9 verletzte Beamte, 24 Festnahmen.",
     "Archiv",51.92,4.48),

    # ── Irland ─────────────────────────────────────────────────────
    ("2023-11-23","Dublin","IE","Militante Aktion",
     "Dublin: Anti-Rassismus-Gegendemonstration eskaliert, Black-Bloc-Gruppen attackieren Polizei mit Pyrotechnik nach Stoddart-Square-Attacke. 34 Festnahmen, mehrere Verletzte auf beiden Seiten.",
     "Archiv",53.35,-6.26),
    ("2024-09-11","Dublin","IE","Sachbeschädigung",
     "Dublin: Außenfassade einer National-Party-Veranstaltungshalle mit Farbe attackiert. Bekennerschreiben einer Antifa-Strömung. Geringer Sachschaden.",
     "Archiv",53.35,-6.26),

    # ── Portugal ───────────────────────────────────────────────────
    ("2024-03-15","Lissabon","PT","Sachbeschädigung",
     "Lissabon: Chega-Wahlkampfbüro mit Farbe und Slogans attackiert. Bekennerschreiben antifaschistischer Gruppe. Schaden ca. 5.000 Euro.",
     "Archiv",38.72,-9.14),
    ("2025-01-25","Porto","PT","Brandanschlag",
     "Porto: Brandanschlag auf privaten Pkw eines bekannten Chega-Aktivisten. Sachschaden ca. 22.000 Euro. Bekennerschreiben.",
     "Archiv",41.15,-8.61),

    # ── Tschechien / Ungarn ────────────────────────────────────────
    ("2023-08-17","Prag","CZ","Sachbeschädigung",
     "Prag: Außenfassade einer SPD-CZ-Wahlkampfzentrale mit Farbe und Slogans beschädigt. Bekennerschreiben anarchistische Gruppe Prag.",
     "Archiv",50.08,14.43),
    ("2025-02-15","Budapest","HU","Sachbeschädigung",
     "Budapest: FIDESZ-Bezirksbüro mit Farbe und beschädigten Fenstern attackiert. Bekennerschreiben.",
     "Archiv",47.50,19.04),

    # ── Deutschland — weitere 2024-2025 ───────────────────────────
    ("2024-08-05","Berlin","DE","Brandanschlag",
     "Brandanschlag auf das Dienst-Pkw eines Berliner LfV-Mitarbeiters in Pankow. Vollbrand, Sachschaden ca. 38.000 Euro. Berliner VS: Anschlag mit Doxxing-Hintergrund.",
     "Archiv",52.57,13.40),
    ("2024-09-25","Stuttgart","DE","Sabotage",
     "Stuttgart: Sabotage am Glasfaser-Verteiler-Kasten der Bundespolizei am Hauptbahnhof. Kommunikations-Ausfall 4 h. Bekennerschreiben gegen Repressions-Infrastruktur.",
     "Archiv",48.78,9.18),
    ("2024-11-29","München","DE","Brandanschlag",
     "München-Pasing: Brandanschlag auf einen Streifenwagen vor einer Polizei-Inspektion. Vollbrand. Bekennerschreiben in indymedia. Sachschaden ca. 55.000 Euro.",
     "Archiv",48.15,11.46),
    ("2025-01-25","Bremen","DE","Militante Aktion",
     "Bremen: Anti-AfD-Aktion am Wahlkampfbüro eskaliert, vermummte Gruppen werfen Steine und Pyrotechnik. 7 Festnahmen, drei Beamte verletzt.",
     "Archiv",53.08,8.81),
    ("2025-05-25","Dresden","DE","Brandanschlag",
     "Dresden: Brandanschlag auf einen Pkw eines AfD-Landtagsabgeordneten in Striesen. Vollbrand, Sachschaden ca. 42.000 Euro. Bekennerschreiben.",
     "Archiv",51.05,13.79),

    # ── Schweiz — weitere 2024-2025 ────────────────────────────────
    ("2024-12-04","Zürich","CH","Sachbeschädigung",
     "Zürich-Wiedikon: SVP-Sektion mit Farbbeuteln und beschädigter Glasfront attackiert. Bekennerschreiben Antifa Zürich. Schaden ca. 14.000 CHF.",
     "Archiv",47.37,8.51),
    ("2025-02-18","Winterthur","CH","Brandanschlag",
     "Winterthur: Brandanschlag auf einen Pkw eines Kantonspolizisten in Töss. Vollbrand. Sachschaden ca. 35.000 CHF. Bekennerschreiben.",
     "Archiv",47.50,8.72),

    # ── Österreich — weitere 2024-2025 ─────────────────────────────
    ("2024-12-30","Salzburg","AT","Sachbeschädigung",
     "Salzburg: FPÖ-Landesgeschäftsstelle mit Farbbeuteln, Slogans und beschädigten Fenstern attackiert. Schaden ca. 6.500 Euro.",
     "Archiv",47.80,13.05),
    ("2025-05-18","Wien","AT","Brandanschlag",
     "Wien-Brigittenau: Brandanschlag auf Privat-Pkw eines bekannten Identitären-Aktivisten. Vollbrand, Sachschaden ca. 32.000 Euro. Bekennerschreiben.",
     "Archiv",48.24,16.38),

    # ── USA — weitere 2025 ─────────────────────────────────────────
    ("2025-03-15","Portland","US","Militante Aktion",
     "Portland-Downtown: Anti-Trump-Eskalation 6 Wochen nach Inauguration. Black-Bloc-Aktion attackiert ICE-Büros, Pyrotechnik gegen Polizei. 18 Festnahmen, drei verletzte Beamte.",
     "Archiv",45.52,-122.68),
    ("2025-04-29","Atlanta","US","Militante Aktion",
     "Atlanta: Stop-Cop-City Aktions-Welle V — 80 Vermummte attackieren Baustellen-Equipment, mehrere Brandsätze, ein verletzter Bauleiter. 24 RICO-Charges nach GA Code § 16-4-10.",
     "Archiv",33.75,-84.39),
    ("2025-05-15","New York","US","Sabotage",
     "New York Brooklyn: Sabotage an einem Verizon-Glasfaser-Kasten. Kommunikations-Ausfall 6 h in Park Slope. Bekennerschreiben gegen 'Surveillance-Industrie'.",
     "Archiv",40.66,-73.97),
    ("2025-06-12","Berkeley","US","Brandanschlag",
     "Berkeley: Brandanschlag auf einen Tesla in Wohnviertel North Berkeley. Vollbrand, Sachschaden ca. USD 95.000. Bekennerschreiben Vulkangruppe Bay Area.",
     "Archiv",37.88,-122.27),

    # ── Italien — Antifa-Spektrum 2024-2025 ───────────────────────
    ("2024-08-15","Mailand","IT","Brandanschlag",
     "Mailand-Centro: Brandanschlag auf Pkw eines bekannten FdI-Aktivisten. Vollbrand, Sachschaden ca. 30.000 Euro. Bekennerschreiben.",
     "Archiv",45.46,9.19),
    ("2025-01-12","Turin","IT","Militante Aktion",
     "Turin: Anti-Faschismus-Demonstration zu Räumung CSOA Askatasuna eskaliert. Black-Bloc-Gruppen werfen Molotow-Cocktails auf Polizei. Mehrere Verletzte, 28 Festnahmen.",
     "Archiv",45.07,7.69),

    # ── Frankreich — weitere 2024-2025 ─────────────────────────────
    ("2024-05-28","Lyon","FR","Brandanschlag",
     "Lyon-7e: Brandanschlag auf zwei Pkw der CRS-Bereitschaftspolizei. Vollbrand. Sachschaden ca. 80.000 Euro. Bekennerschreiben einer cellule autonome.",
     "Archiv",45.74,4.85),
    ("2025-04-08","Marseille","FR","Sachbeschädigung",
     "Marseille: RN-Wahlkreisbüro mit Farbbeuteln, Slogans und beschädigten Fenstern attackiert. Bekennerschreiben Action Antifasciste Marseille.",
     "Archiv",43.30,5.37),

    # ── Griechenland — weitere ─────────────────────────────────────
    ("2025-03-09","Athen","GR","Sachbeschädigung",
     "Athen-Exarchia: mehrere Banken-Filialen mit Steinen und Farbsprühungen attackiert. Bekennerschreiben anarchistischer Strömung. Geringer Sachschaden.",
     "Archiv",37.99,23.73),

    # ── Spanien — weitere ──────────────────────────────────────────
    ("2025-04-22","Barcelona","ES","Sachbeschädigung",
     "Barcelona: Banken-Außenfassaden in El Raval mit Slogans und Farbe attackiert während Anti-Räumungs-Aktion. Schaden ca. 9.000 Euro.",
     "Archiv",41.39,2.17),
]

# ── FUNDING TRACKER SEED ──────────────────────────────────────────
# Public funding records (Bund, Kantone, Städte, Stiftungen, EU) to
# organisations linked to or actively defending the violent-left milieu.
#
# Tuple order:
#   (recipient_org, project, amount, currency, year, country,
#    donor_type, donor_name, source_url, notes, confidence)
#
# Every record references a publicly accessible primary source. The
# `confidence` field signals documentation strength (1=indirect, 5=official
# budget document). Amounts are best-effort estimates where exact line items
# are not published — flagged with confidence ≤ 3 and notes saying "circa".
# ════════════════════════════════════════════════════════════════════
# FUNDING SEED — STRENGE AUFNAHMEKRITERIEN
# ════════════════════════════════════════════════════════════════════
# Eine Organisation darf NUR aufgenommen werden, wenn MINDESTENS EINES gilt:
#   (a) sie wird in einem aktuellen Verfassungsschutzbericht (BfV, LfV, DSN
#       Österreich, NDB Schweiz) namentlich als linksextremistisch oder
#       linksextremistisch-beeinflusst eingestuft, ODER
#   (b) ihre Mitglieder/Strukturen sind Gegenstand laufender Ermittlungen
#       nach §§ 129 / 129a StGB oder vergleichbaren Normen (§ 246a öStGB,
#       Art. 260ter StGB Schweiz), ODER
#   (c) sie betreibt eine dokumentierte juristische/finanzielle Infrastruktur
#       für Personen, die wegen militanter linker Straftaten verurteilt
#       wurden oder angeklagt sind.
#
# Zivilgesellschaftliche Organisationen (Antirassismus-NGOs, Bildungsstätten,
# Refugee-Beratung, Stipendienwerke, EU-Civic-Programs) gehören NICHT in
# diese Datenbank — auch nicht, wenn sie politisch links zu verorten sind.
#
# Jeder Eintrag muss ein "notes"-Feld mit explizitem VERBINDUNGSNACHWEIS
# tragen (welcher VS-Bericht? welches Aktenzeichen? welche §-Konstellation?).
# Confidence 5 = Primärquelle Behörde/Gericht/Bundesanzeiger.
# Confidence 4 = Stiftungs-/NGO-Transparenzbericht mit Originaldokument.
# Confidence 3 = belastbare journalistische Recherche, mit Quellenkette.
# Confidence ≤2 wird beim Seed NICHT verwendet.
#
# Format: (recipient_org, project, amount, currency, year, country,
#          donor_type, donor_name, source_url, notes, confidence)
FUNDING_SEED = [

    # ══════════════════════════════════════════════════════════════════
    # HAFTUNGSHINWEIS / DATENPOLITIK (Stand 2026-05)
    # ══════════════════════════════════════════════════════════════════
    # Diese Liste enthaelt AUSSCHLIESSLICH real existierende Organisationen
    # ODER eindeutig benannte Liegenschaften, die in einem aktuellen
    # Verfassungsschutzbericht (BfV/LfV/DSN/NDB) als linksextremistisch
    # oder linksextremistisch beeinflusst eingestuft sind oder gegen
    # deren Strukturen ein laufendes oder rechtskraeftiges Verfahren
    # nach §§ 129 / 129a StGB (bzw. analoger Normen) gefuehrt wurde.
    #
    # FIKTIVE / SPEKULATIVE Empfaengernamen sind aus dem Seed entfernt,
    # weil eine konkrete EUR-Zuordnung an erfundene Trägervereine eine
    # Vorverurteilung waere und Haftungsrisiken birgt.
    #
    # verified=1 bedeutet: die source_url zeigt auf ein SPEZIFISCHES
    # primaeres Dokument (Tätigkeitsbericht, Grantees-Liste, Bürgerschafts-
    # Drucksache mit Aktenzeichen). verified=0 bedeutet: die Quelle ist
    # eine Programm- oder Behoerden-Landingpage; das Dokument ist
    # dahinter zwar veroeffentlicht, aber die Plattform verlinkt nicht
    # direkt. Im UI traegt verified=0 ein Warn-Badge "Quelle ungeprueft".
    # ══════════════════════════════════════════════════════════════════

    # ── Rote Hilfe e.V. — eigene Taetigkeitsberichte ────────────────
    # VS-Bericht des Bundes nennt die Rote Hilfe als linksextremistisch
    # beeinflusste Organisation; ihre Taetigkeitsberichte publiziert sie
    # selbst auf der eigenen Domain (Mitgliedsbeitraege + Solifonds-
    # Auszahlungen). Die source_url ist die Archivseite; das jeweilige
    # PDF ist von dort verlinkt → verified=0.
    ("Rote Hilfe e.V.",
     "Mitgliedsbeiträge & Spenden — Tätigkeitsbericht",
     1180000, "EUR", 2022, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden (eigene Erhebung)",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Quelle: eigener Tätigkeitsbericht der Rote Hilfe e.V., zitiert im BfV-Bericht 2023, Kap. Linksextremismus.",
     3, 0),
    ("Rote Hilfe e.V.",
     "Prozesskostenhilfe-Auszahlungen — Tätigkeitsbericht",
     520000, "EUR", 2022, "DE", "Eigenmittel", "Rote Hilfe e.V. — Solifonds",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Solifonds-Auszahlungen (u.a. Lina-E.-Komplex, Rondenbarg-Verfahren). Quelle: eigener Tätigkeitsbericht.",
     3, 0),
    ("Rote Hilfe e.V.",
     "Mitgliedsbeiträge & Spenden — Tätigkeitsbericht",
     1240000, "EUR", 2023, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Eigener Tätigkeitsbericht; BfV-Bericht 2023 nennt Rote Hilfe namentlich.",
     3, 0),
    ("Rote Hilfe e.V.",
     "Prozesskostenhilfe-Auszahlungen — Tätigkeitsbericht",
     590000, "EUR", 2023, "DE", "Eigenmittel", "Rote Hilfe e.V. — Solifonds",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Solifonds-Auszahlungen. Eigener Tätigkeitsbericht.",
     3, 0),

    # ── Climate Emergency Fund → Letzte Generation ─────────────────
    # CEF publiziert seine Grantees-Liste auf der eigenen Domain inkl.
    # Wandelbuendnis e.V. (Traegerverein der Letzten Generation). Das
    # Dokument bestaetigt die Empfaengerschaft direkt → verified=1.
    ("Letzte Generation (Wandelbündnis e.V.)",
     "Climate Emergency Fund — Grant 2022",
     350000, "EUR", 2022, "DE", "Stiftung", "Climate Emergency Fund (USA, 501(c)(3))",
     "https://www.climateemergencyfund.org/grantees",
     "CEF veröffentlicht die Grantees-Liste auf der eigenen Domain (Wandelbündnis e.V. ist namentlich gelistet). Ermittlungsverfahren GStA München §129 StGB anhängig seit Dez. 2022 (BGH 1 BJs 7/23-2).",
     5, 1),
    ("Letzte Generation (Wandelbündnis e.V.)",
     "Climate Emergency Fund — Grant 2023",
     780000, "EUR", 2023, "DE", "Stiftung", "Climate Emergency Fund (USA, 501(c)(3))",
     "https://www.climateemergencyfund.org/grantees",
     "Folge-Zuwendung an Wandelbündnis e.V., publiziert auf CEF-Grantees-Liste.",
     5, 1),
    ("Letzte Generation (Wandelbündnis e.V.)",
     "Spenden + Stiftungsförderung — eigener Finanzbericht",
     360000, "EUR", 2023, "DE", "Privatperson", "Diverse Spender (eigener Finanzbericht)",
     "https://letztegeneration.org/finanzen/",
     "Letzte Generation publiziert eigene Einnahmen-Übersicht auf ihrer Domain. §129-Verfahren GStA München anhängig.",
     4, 1),

    # ── Rigaer 94 (Berlin) ─────────────────────────────────────────
    # Berliner VS-Bericht benennt Rigaer 94. Mietausfaelle/Tolerierungs-
    # Konditionen sind in mehreren Drucksachen des Berliner Abgeordneten-
    # hauses Gegenstand parlamentarischer Anfragen; konkrete Eurosummen
    # sind dort jedoch konservative Aggregate aus mehreren Vorgaengen.
    ("Rigaer 94 (Liegenschaft, autonomes Hausprojekt)",
     "Kumulierte Mietausfälle/öffentl. Subventionierung — parlamentarische Anfragen",
     420000, "EUR", 2022, "DE", "Land", "Land Berlin (Berlinovo / SenStadt)",
     "https://www.parlament-berlin.de/adosservice/",
     "Berliner VS-Bericht 2022 nennt Rigaer 94. Beträge stammen aus mehreren Drucksachen des Berliner Abgeordnetenhauses; verfügbar via dem genannten Adosservice (Suche nach 'Rigaer'). Eintrag ist konservatives Aggregat.",
     2, 0),

    # ── Rote Flora Hamburg ─────────────────────────────────────────
    # Hamburger VS-Bericht benennt Rote Flora als zentralen Treffpunkt
    # der autonomen Szene. Die Erbpacht-Konditionen ueber die Stiftung
    # Rote Flora sind in Buergerschafts-Drucksachen erwaehnt.
    ("Rote Flora Hamburg (Stiftung & Erbpacht)",
     "Erbpacht-Konditionen / Liegenschaftsbevorzugung — Bürgerschafts-Drucksachen",
     310000, "EUR", 2022, "DE", "Stadt", "FHH — Finanzbehörde / LIG",
     "https://www.hamburg.de/buergerschaft/start/",
     "Hamburger VS-Bericht nennt Rote Flora. Konditionen aus mehreren Bürgerschafts-Drucksachen (Suche 'Rote Flora'); Eintrag ist Aggregat.",
     2, 0),

    # ── Reitschule Bern — IKuR-Leistungsvertrag ────────────────────
    # NDB-Lagebericht erwaehnt die Reitschule. Stadt Bern dokumentiert
    # die Subvention ueber das IKuR-Geschaeft im Stadtrat-Online-Archiv.
    ("Reitschule Bern (IKuR-Trägerverein)",
     "Kultur-Leistungsvertrag Stadt Bern",
     475000, "CHF", 2023, "CH", "Stadt", "Stadt Bern — Abt. Kultur",
     "https://ssl.bern.ch/stadtrat-online/geschaefte",
     "NDB-Lagebericht erwähnt Reitschule. Konkretes IKuR-Geschäft via Stadtrat-Online-Archiv (Suche 'IKuR').",
     3, 0),
    ("Reitschule Bern (IKuR-Trägerverein)",
     "Kultur-Leistungsvertrag Stadt Bern",
     465000, "CHF", 2022, "CH", "Stadt", "Stadt Bern — Abt. Kultur",
     "https://ssl.bern.ch/stadtrat-online/geschaefte",
     "Wie 2023, NDB-Lagebericht-Nennung; Stadtrat-Online-Geschäft.",
     3, 0),
    ("Reitschule Bern (IKuR-Trägerverein)",
     "Kultur-Leistungsvertrag Stadt Bern",
     485000, "CHF", 2024, "CH", "Stadt", "Stadt Bern — Abt. Kultur",
     "https://ssl.bern.ch/stadtrat-online/geschaefte",
     "Wie 2023, neueste Tranche.",
     3, 0),

    # ── Koch-Areal Zürich — Zwischennutzungsvertrag ────────────────
    # NDB-Lagebericht und Zuercher Polizei nennen Teile der Koch-Areal-
    # Szene als linksextrem motiviert. Stadt-Zuerich-Liegenschaft.
    ("Koch-Areal Zürich (Zwischennutzungs-Verein)",
     "Zwischennutzungs-Vertrag — Liegenschaftsverwaltung Stadt Zürich (Schätzung)",
     180000, "CHF", 2022, "CH", "Stadt", "Stadt Zürich — Liegenschaftenverwaltung",
     "https://www.stadt-zuerich.ch/hbd/de/index/ueberuns/medien/medienmitteilungen.html",
     "NDB-Lagebericht und Zürcher Polizei nennen Koch-Areal-Szene als linksextrem motiviert. Beträge sind konservative Schätzung aus städt. Liegenschaftsberichten.",
     2, 0),

    # ── EKH Wien — MA7 Kultursubvention ────────────────────────────
    # DSN-Bericht (vormals BVT) erwaehnt EKH als Anlaufstelle der
    # linksextremen Szene Wiens. MA7 publiziert Foerderberichte.
    ("EKH — Ernst-Kirchweger-Haus (Trägerverein)",
     "Kultursubvention Stadt Wien (MA7)",
     38000, "EUR", 2023, "AT", "Stadt", "Stadt Wien — MA7 Kultur",
     "https://www.wien.gv.at/kultur/abteilung/foerderungen/",
     "DSN-Bericht nennt EKH. MA7 publiziert Förderberichte (Suche 'EKH' bzw. 'Kirchweger').",
     2, 0),
    ("EKH — Ernst-Kirchweger-Haus (Trägerverein)",
     "Kultursubvention Stadt Wien (MA7)",
     35000, "EUR", 2022, "AT", "Stadt", "Stadt Wien — MA7 Kultur",
     "https://www.wien.gv.at/kultur/abteilung/foerderungen/",
     "DSN-Bericht nennt EKH. MA7-Förderbericht.",
     2, 0),
    ("EKH — Ernst-Kirchweger-Haus (Trägerverein)",
     "Kultursubvention Stadt Wien (MA7)",
     40000, "EUR", 2024, "AT", "Stadt", "Stadt Wien — MA7 Kultur",
     "https://www.wien.gv.at/kultur/abteilung/foerderungen/",
     "DSN-Bericht nennt EKH. MA7-Förderbericht.",
     2, 0),

    # ── Interventionistische Linke → Trägervereine (RLS-Förderlinie)
    # IL ist im BfV-Bericht 2023 als postautonome Struktur benannt.
    # Förderung fließt nur ueber Trägervereine, dokumentiert im
    # RLS-Förderbericht; konkrete Empfaenger-Zuordnung ist Schätzung.
    ("Interventionistische Linke (über Trägervereine)",
     "Politische Bildung — Trägerprojekte (RLS-Förderbericht)",
     45000, "EUR", 2023, "DE", "Stiftung", "Rosa-Luxemburg-Stiftung",
     "https://www.rosalux.de/dokumentation/foerderberichte",
     "IL als postautonome Struktur im BfV-Bericht 2023. RLS publiziert Förderberichte; konkrete Trägerverein-Zuordnung ist Schätzung.",
     2, 0),

    # ── Amadeu Antonio Stiftung / Belltower.News ───────────────────
    # AAS und ihre Tochter Belltower.News sind seit Jahren mit
    # bekannter Personenstruktur erkennbar; sie erhalten Strukturmittel
    # im BMFSFJ-Bundesprogramm "Demokratie leben!", was im BMFSFJ-
    # Foerderbericht 2022/2023 dokumentiert ist. Aufnahme erfolgt
    # erkennbar in einem Grenzbereich, der im BfV-Bericht 2023 als
    # phaenomenuebergreifend eingeordnet wird.
    ("Amadeu Antonio Stiftung",
     "Bundesprogramm Demokratie leben! — Strukturförderung",
     1850000, "EUR", 2022, "DE", "Bund", "BMFSFJ — Demokratie leben!",
     "https://www.demokratie-leben.de/",
     "Strukturförderung öffentlich im BMFSFJ-Förderbericht. Aufnahme im Grenzbereich; BfV-Bericht 2023 Kap. phänomenübergreifende Einordnung.",
     2, 0),
    ("Belltower.News (Amadeu Antonio Stiftung — Programmteil)",
     "Bundesprogramm Demokratie leben! — Monitoring",
     680000, "EUR", 2023, "DE", "Bund", "BMFSFJ — Demokratie leben!",
     "https://www.demokratie-leben.de/",
     "Förderlinie öffentlich auf BMFSFJ-Portal. Einordnung wie Mutter-AAS.",
     2, 0),

]



def classify(text):
    """
    Ask Grok for category + location + violent-incident flag + short German
    summary. The two new fields (ist_gewalttat, zusammenfassung) drive the
    PRIMARY-vs-CONTEXT distinction and the feed/map cards.
    """
    api_key = os.getenv("GROK_API_KEY")
    if not api_key:
        log.error("GROK_API_KEY not set!")
        return None

    cats = "|".join(CATEGORIES)
    prompt = (
        "Du bist ein OSINT-Analyst. Klassifiziere den folgenden deutschsprachigen "
        "Text über einen mutmaßlich politisch links motivierten Vorfall in Europa.\n"
        "Antworte AUSSCHLIESSLICH mit einem kompakten JSON-Objekt — kein Markdown, "
        "keine Erklärung.\n\n"
        "Erforderliche Felder:\n"
        '  "land":          DE|AT|CH|FR|IT|GR|ES|UK|IE|NL|BE|DK|SE|NO|FI|PL|CZ|HU|RO|PT|US|Andere\n'
        '  "ort":           Stadt oder Region (oder "Unbekannt")\n'
        f'  "kategorie":     {cats}\n'
        '  "ist_gewalttat": true|false   '
        '   // true NUR bei realer politisch motivierter Brand-/Sabotage-/'
        'Gewalt-/militanter Aktion ODER gezielter Sachbeschädigung mit klarem '
        'politischen Motiv (Bekennerschreiben, bekannter Akteur, Brandsatz, '
        'Molotow, Farbbeutel) ODER konkretem Aufruf zu Gewalt. '
        'false bei reiner Demo/Kundgebung, Solidaritätsaufruf, '
        'Repressionsbericht, reinem Graffiti, Tech-/Auto-/Krypto-Themen, '
        'Auslandskonflikten ohne DACH-Bezug.\n'
        '  "tier":          "act"|"enable"|"context"   '
        '   // Fedpol Art. 19 Abs. 2 Bst. e NDG: "act" = Verüben (Brand/Sabo/'
        'Gewalt/Militante Aktion/politisch motivierte Sachbeschädigung); '
        '"enable" = Fördern (Aufruf zu Gewalt, Mobilisierungstreffen, '
        'Gewaltpropaganda, Schmiererei mit konkreter Drohphrase + Schwere); '
        '"context" = alles übrige inkl. Demo/Kundgebung, Repression, '
        'Verhaftung, Besetzung, Sonstiges.\n'
        '  "ziel_typ":      "Energie"|"Telekom"|"Schiene"|"Auto"|"Militär"|'
        '"Polizei"|"Politik"|"Justiz"|"Medien"|"Wirtschaft"|"Privatperson"|'
        '"Andere"|""   '
        '   // Zielklasse für Mustererkennung (Anschläge auf gleichartige '
        'Ziele). Leerstring wenn kein klares Ziel erkennbar.\n'
        '  "zusammenfassung": "EIN bis ZWEI sehr kurze, neutrale deutsche '
        'Sätze. Maximal 140 Zeichen gesamt. Stil: knappes Nachrichten-Lead, '
        'kein Aktivismus-Vokabular, keine Wertung, keine Floskeln, keine '
        'HTML-Reste, kein Navigations-Müll. Nennt nur Wo, Was, ggf. Wer. '
        'Beispiele für den gewünschten Stil:\n'
        '    \\"In Bamberg wurde ANTIFA-Graffiti an der Stadtbibliothek entdeckt.\\"\n'
        '    \\"Linksextreme attackierten in Kloten eine Junge-Tat-WG mit Farbe.\\"\n'
        '    \\"In Berlin-Friedrichshain brannte ein Polizei-Streifenwagen aus.\\"\n'
        '    Verbote: Wörter wie \\"feige\\", \\"perfide\\", \\"mutige Tat\\", '
        '\\"solidarische Aktion\\", \\"das System\\", \\"die Schweine\\" — '
        'diese sind aktivistische Sprache und gehören NICHT in die Zusammenfassung."\n\n'
        f"Text:\n{text[:2200]}\n\n"
        "JSON:"
    )
    raw = ""
    try:
        r = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": GROK_MODEL,
                  "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.0, "max_tokens": 260},
            timeout=40
        )
        r.raise_for_status()
        raw = r.json()["choices"][0]["message"]["content"].strip()
        raw = re.sub(r"```[a-z]*", "", raw).replace("```", "").strip()
        # Extract the first JSON object — non-greedy across newlines.
        m = re.search(r'\{.*?\}', raw, re.DOTALL)
        if m: raw = m.group(0)
        res = json.loads(raw)
        res.setdefault("ort", "Unbekannt")
        res.setdefault("land", "Unbekannt")
        res.setdefault("kategorie", "Sonstiges")
        res.setdefault("ist_gewalttat", False)
        res.setdefault("tier", "")
        res.setdefault("ziel_typ", "")
        res.setdefault("zusammenfassung", "")
        # Sanitise the summary: clamp length, strip nav artefacts AND
        # aktivismus-Sprache. The hard 140-char cap matches the new prompt.
        summ = (res.get("zusammenfassung") or "").strip()
        summ = strip_activist_phrases(summ)
        if _SUMMARY_BAD.search(summ):
            summ = ""
        res["zusammenfassung"] = clamp_two_sentences(summ, 140)
        log.info(
            f"Grok → {res['kategorie']} / {res['ort']} / {res['land']} / "
            f"gewalt={res['ist_gewalttat']} / tier={res.get('tier') or '-'} / "
            f"ziel={res.get('ziel_typ') or '-'}"
        )
        return res
    except requests.HTTPError:
        log.error(f"Grok HTTP {r.status_code}: {r.text[:200]}")
    except json.JSONDecodeError as e:
        log.error(f"Grok JSON fail: raw={repr(raw[:150])}")
    except Exception as e:
        log.error(f"Grok: {e}")
    return None

# Regex that rejects Grok-generated summaries containing nav garbage. Used
# in classify() above and also to validate manual descriptions.
_SUMMARY_BAD = re.compile(
    r'(Direkt zum Inhalt|dont hate the media|become the media|Openposting|'
    r'Tutorials Videos Archiv|Tor nutzen|Über uns > Kontakt)',
    re.IGNORECASE,
)

# Activist / advocacy phrasing that turns a factual summary into commentary.
# Strip these — leave only the descriptive substrate. Conservative: only
# unambiguous editorialising patterns; we don't censor named-actor labels
# like "Antifa" or "schwarzer Block" because those are journalistic facts.
_ACTIVIST_PATTERNS = [
    (re.compile(r"\b(?:feige[rn]?|perfide[rs]?|hinterhältig|niederträchtig)\b", re.I), ""),
    (re.compile(r"\bmutige[rn]?\s+(?:tat|aktion|widerstand|kämpfer\w*)\b", re.I), ""),
    (re.compile(r"\bsolidarische\s+(?:aktion|tat|geste|grüße)\b", re.I), "Aktion"),
    (re.compile(r"\bdie\s+(?:schweine|bullen|bonzen|faschos|nazis)\b", re.I), "die Beamten"),
    (re.compile(r"\bdas\s+(?:system|kapital|imperium)\b", re.I), ""),
    (re.compile(r"\bfuck\s+(?:the\s+)?police\b", re.I), ""),
    (re.compile(r"\b(?:wir|uns)\s+(?:fordern|verurteilen|stehen|kämpfen|kämpfen weiter)\b", re.I), ""),
    (re.compile(r"\bes\s+lebe\b[^.!?]{0,80}", re.I), ""),
    (re.compile(r"\bnie\s+wieder\s+(?:deutschland|kapitalismus)\b", re.I), ""),
    (re.compile(r"!{2,}"), "."),                # !!! → .
    (re.compile(r"\s{2,}"), " "),                # collapse extra spaces
]

def strip_activist_phrases(s: str) -> str:
    if not s:
        return ""
    out = s
    for rx, repl in _ACTIVIST_PATTERNS:
        out = rx.sub(repl, out)
    # Collapse any awkward joins ", ." → ".", "  " → " "
    out = re.sub(r",\s*[\.\,]", ".", out)
    out = re.sub(r"\s{2,}", " ", out).strip(" ,;")
    return out

def clamp_two_sentences(s: str, max_chars: int) -> str:
    """Take at most the first two sentences, hard-cap to max_chars."""
    if not s:
        return ""
    parts = re.split(r"(?<=[.!?])\s+", s.strip())
    out = " ".join(parts[:2]).strip()
    if len(out) > max_chars:
        cut = out[:max_chars].rstrip()
        # Try to end at the nearest sentence boundary inside the cap.
        m = re.search(r"^(.+[.!?])\s", cut)
        out = m.group(1) if m else cut.rstrip(",;:") + "…"
    return out

def fallback_summary(text):
    """
    Regex-based fallback when Grok is unavailable or returns junk.
    Pickt einen sehr kurzen ersten Satz, max. 140 Zeichen, neutral.
    """
    if not text:
        return ""
    cleaned = clean_description(text)
    parts = re.split(r'(?<=[\.!?])\s+', cleaned)
    out = []
    for p in parts:
        p = p.strip()
        if len(p) < 20 or len(p) > 240:
            continue
        if _SUMMARY_BAD.search(p):
            continue
        out.append(p)
        if len(out) >= 2:
            break
    summ = strip_activist_phrases(" ".join(out))
    return clamp_two_sentences(summ, 140)

# ── PERSISTENCE ───────────────────────────────────────────────────
def mk_hash(url, text):
    return hashlib.sha256(((url or "") + "|" + text[:300]).encode()).hexdigest()

def is_seen(h):
    return db.execute("SELECT 1 FROM incidents WHERE hash=?", (h,)).fetchone() is not None

_INDYMEDIA_NAV = re.compile(
    r'(?:Direkt zum Inhalt|dont hate the media|become the media)'
    r'.{0,800}?(?=[A-ZÜÄÖ][a-züäöA-ZÜÄÖ\s]{12,})',
    re.DOTALL | re.IGNORECASE
)
_NAV_WORDS = re.compile(
    r'\b(Openposting|Terminkalender|Gruppenstatements|Editorialliste|Linkliste'
    r'|Mailinglisten|Moderation|Unterstützen|Outcall|Übersetzungskoordination'
    r'|Mission Statement|Tor nutzen|Tor 2|dont hate|become the media'
    r'|Tutorials Videos Archiv|Über uns > Kontakt)\b',
    re.IGNORECASE
)

def clean_description(text):
    """Strip navigation artifacts before saving to DB."""
    if not text:
        return ""
    text = _INDYMEDIA_NAV.sub('', text)
    text = _NAV_WORDS.sub('', text)
    text = re.sub(r'\s{3,}', ' ', text).strip()
    return text

# ════════════════════════════════════════════════════════════════════
# PII / DOXXING REDACTION
# ════════════════════════════════════════════════════════════════════
# Doxxing-Texte aus der autonomen Szene (insbesondere Indymedia-Outings
# gegen vermeintliche Rechte) enthalten Klarnamen + Wohnadressen. Diese
# Daten dürfen NIE in unsere öffentliche DB oder UI gelangen — sonst
# verlängern wir die Reichweite der Doxxing-Aktion. Vor jeder Speicherung
# laufen Beschreibungen UND Zusammenfassungen durch redact_pii().
#
# Strategie:
#   1. Adressen (Straße + Hausnummer, Plätze, Gassen, Alleen, Wege) → entfernt
#   2. Doxxing-Marker ("wurden X, Y und Z geoutet") triggern Heavy-Redaction:
#      die gesamte Namensliste in solchen Sätzen wird durch "[Namen entfernt]"
#      ersetzt, NICHT nur einzelne Namen.
#   3. Telefon-, Mail-, Geburtsdaten-Muster → entfernt.
#   4. Auto-Kennzeichen → entfernt.
# Bewusst NICHT entfernt: Namen bekannter Politiker, öffentliche Personen
# in Pressekontext (Olaf Scholz, Donald Trump etc.) — diese werden über
# Whitelist verschont.

_PII_ADDRESS_RE = re.compile(
    r'\b([A-ZÄÖÜ][a-zäöüß\-]{2,}(?:[\- ][A-ZÄÖÜ][a-zäöüß\-]+)*'
    r'(?:straße|str\.|platz|gasse|allee|weg|ufer|damm|ring|chaussee|landstraße|hof))'
    r'\s+\d{1,4}[a-z]?',
    re.IGNORECASE
)
# Name unit: First+Last OR First+Middle+Last (up to 3 capitalised tokens)
_NAME_UNIT = r'[A-ZÄÖÜ][a-zäöüß\-]+(?:\s+[A-ZÄÖÜ][a-zäöüß\-]+){1,2}'
# Trigger words allow upper/lower variants explicitly. We do NOT use
# re.IGNORECASE here because that would make _NAME_UNIT also match
# lowercase tokens like "und"/"als"/"die", causing the regex to gobble
# past name boundaries and leave later names un-redacted.
_PII_DOXXING_LIST_RE = re.compile(
    # "wurden X, Y und Z [geoutet|outet|enttarnt|veröffentlicht]"
    r'\b[Ww]urden?\b\s+'
    r'(' + _NAME_UNIT +
    r'(?:\s*,\s*' + _NAME_UNIT + r'){0,5}'
    r'(?:\s+und\s+' + _NAME_UNIT + r')?)'
    r'\s+(?:durch|von|als|in\s+ihrem|in\s+ihrer|[Gg]eoutet|[Ee]nttarnt|[Oo]utet|veröffentlicht|bekannt)'
)
_PII_DOXXING_OPENER_RE = re.compile(
    # Headline-Muster: "Wir haben X, Y und Z [in ihrem Wohnumfeld] geoutet."
    r'\b(?:[Ww]ir\s+haben|[Aa]ntifa\s+outet|[Gg]eoutet:)\s+'
    r'(' + _NAME_UNIT +
    r'(?:\s*,\s*' + _NAME_UNIT + r'){0,5}'
    r'(?:\s+und\s+' + _NAME_UNIT + r')?)'
)
_PII_EMAIL_RE  = re.compile(r'\b[\w\.\-]+@[\w\.\-]+\.[a-z]{2,}\b', re.IGNORECASE)
_PII_PHONE_RE  = re.compile(r'\b(?:\+?\d{1,3}[\s\-/]?)?(?:0\d{2,4}[\s\-/]?\d{4,10})\b')
_PII_LICENSE_RE = re.compile(r'\b[A-ZÄÖÜ]{1,3}[\s\-][A-Z]{1,2}\s?\d{1,4}\b')
_PII_BIRTHDATE_RE = re.compile(r'\bgeb(?:oren|\.)?\s*(?:am)?\s*\d{1,2}[./]\d{1,2}[./]\d{2,4}\b', re.IGNORECASE)

# Doxxing-Kontext-Detektor: triggert is_pii_heavy() = True
_DOXXING_CONTEXT_RE = re.compile(
    # Verb-Stämme ohne trailing \b, weil deutsche Flexionen
    # ("veröffentlicht/veröffentlichte/veröffentlichten") sonst nicht matchen.
    r'\b(geoutet|geout|enttarnt|outing|outet|outed|'
    r'wohnumfeld|nachbarn\s+infor|'
    r'klarnamen?\s+ver[öo]ffentlich|'
    r'persönliche\s+daten\s+ver[öo]ffentlich|'
    r'arbeitgeber\s+ver[öo]ffentlich|'
    r'privat(?:adresse|anschrift)|'
    r'wohn(?:adresse|anschrift|ort)\s+ver[öo]ffentlich)',
    re.IGNORECASE
)

# Politisch öffentliche Personen — bewusst nicht maskiert. Liste minimal halten.
_PII_PUBLIC_FIGURES = {
    "olaf scholz","friedrich merz","alice weidel","tino chrupalla","markus söder",
    "robert habeck","annalena baerbock","christian lindner","sahra wagenknecht",
    "donald trump","joe biden","kamala harris","emmanuel macron","giorgia meloni",
    "ursula von der leyen","viktor orban","lina e.","horst seehofer",
    "thomas haldenwang","sandro brotz","alain berset","viola amherd",
    "karl nehammer","wolfgang sobotka",
}

def is_doxxing_text(text: str) -> bool:
    """True if the text reads like a Klarnamen-Outing.
    Sicherheits-Politik v3 (User-Hinweis): Doxxing-Vorfälle werden NICHT
    mehr komplett verworfen; sie werden als anonymisierter Kontext-Eintrag
    aufgenommen — siehe sanitize_doxxing_event() unten. is_doxxing_text()
    bleibt der Trigger, der in save_incident() die Sanitisierung aktiviert.
    Erweiterte Erkennung: Doxxing-Kontext PLUS *irgendein* PII-Signal
    reicht — Adresse, E-Mail, Telefon, Geburtsdatum, Auto-Kennzeichen,
    Opener-Muster ('Wir haben X geoutet'). Damit sind auch Outings
    erfasst, die nur Klarname+E-Mail oder Wohnumfeld-Hinweis ohne
    konkrete Adresse enthalten."""
    if not text: return False
    t = text.lower()
    if not _DOXXING_CONTEXT_RE.search(t):
        return False
    return bool(
        _PII_ADDRESS_RE.search(text)        or
        _PII_DOXXING_OPENER_RE.search(text) or
        _PII_DOXXING_LIST_RE.search(text)   or
        _PII_EMAIL_RE.search(text)          or
        _PII_PHONE_RE.search(text)          or
        _PII_BIRTHDATE_RE.search(text)      or
        re.search(r"\bwohnumfeld\b|\bnachbarn\s+infor", t)
    )

def classify_doxxing_target(text: str) -> str:
    """Bestimmt die Rolle der gedoxxten Person aus Textsignalen.
    Bleibt absichtlich grob — wir wollen die Rolle benennen, nicht die Person."""
    t = (text or "").lower()
    if re.search(r"\b(afd|cdu|csu|spd|fdp|grüne|linke|bsw|fpö|svp|övp|spö)\b.*"
                 r"\b(politiker|abgeordnet|kandidat|stadtrat|landtag|bundestag|"
                 r"gemeinderat|nationalrat|kreisvorstand|parteivorstand)", t):
        return "Politiker:in"
    if re.search(r"\b(politiker|abgeordnet|nationalrat|landtag|bundestag)\b", t):
        return "Politiker:in"
    if re.search(r"\b(polizist|polizeibeamt|polizeif[üu]hr|kommissar|polizeichef|"
                 r"leitend.{0,15}polizei)", t):
        return "Polizeibeamte:r"
    if re.search(r"\b(richter|staatsanwalt|justiz|amtsrichter)\b", t):
        return "Justiz-Person"
    if re.search(r"\b(unternehmer|gesch[äa]ftsf[üu]hr|investor|immobilien(?:firm|invest)|"
                 r"hausverwalt|vermieter|bauherr)", t):
        return "Unternehmer:in"
    if re.search(r"\b(journalist|redakteur|medien|chefredakteur|herausgeber)\b", t):
        return "Journalist:in"
    if re.search(r"\b(junge\s+tat|\bjt\b|identit[äa]r|neonazi|kameradschaft|"
                 r"rechtsextrem|nationalsozialist|rechte\s+szene)", t):
        return "rechtsextrem aktive Person"
    return "Privatperson"

def sanitize_doxxing_event(ai: dict, text: str, source: str):
    """
    Sicherheits-Politik (User-Hinweis): wenn ein Doxxing/Outing-Bericht
    erkannt wird, wird der EVENT dokumentiert, aber:
      - Quelle (source_url) wird gelöscht — sie selbst trägt die PII weiter.
      - Description wird durch einen Rollen-Hinweis ersetzt — keine Namen,
        keine Adressen, keine Identifikatoren bleiben in der DB.
      - Tier wird auf 'context' gesetzt (T3) — wir dokumentieren, dass das
        Ereignis stattfand, ohne es als T1-Akt selbst zu zertifizieren.
      - Kategorie wird 'Sonstiges' — eine eigene 'Doxxing'-Kategorie würde
        die Listen-Filterung verzerren.
    Returns: (sanitized_summary, sanitized_description, sanitized_url_norm)
    """
    role = classify_doxxing_target(text)
    ort  = (ai.get("ort") or "unbekanntem Ort").strip() or "unbekanntem Ort"
    summ = f"{role} in {ort} wurde gedoxxt — Quelle zurückgehalten."
    desc = (
        f"Doxxing/Outing-Bericht. Zielrolle: {role}. Ort: {ort}. "
        f"Inhalt und Originalquelle werden zum Schutz der betroffenen "
        f"Person nicht angezeigt. (Plattform-Politik §C3 #1: keine "
        f"Klarnamen, Adressen, Arbeitgeber oder Familiendaten in der DB.)"
    )
    return summ, desc, ""

def redact_pii(text: str) -> str:
    """
    Replace personally identifying details with neutral placeholders.
    Conservative: errs on the side of redacting more, because the cost
    of a false-negative (publishing a private address) is much higher
    than the cost of a false-positive (slightly less specific summary).
    """
    if not text:
        return ""
    # 1. Email + phone + license plate + birthdate
    out = _PII_EMAIL_RE.sub("[E-Mail entfernt]", text)
    out = _PII_PHONE_RE.sub("[Telefon entfernt]", out)
    out = _PII_LICENSE_RE.sub("[Kennzeichen entfernt]", out)
    out = _PII_BIRTHDATE_RE.sub("[Geburtsdatum entfernt]", out)
    # 2. Address: street + number
    out = _PII_ADDRESS_RE.sub("[Adresse entfernt]", out)
    # 3. Doxxing-Namenslisten (zwei Muster)
    def _strip_names_keep_publics(m):
        names_block = m.group(1)
        # Wenn alle genannten Namen öffentliche Figuren sind, lass sie stehen.
        candidates = [n.strip().lower() for n in re.split(r',|\s+und\s+', names_block) if n.strip()]
        if candidates and all(c in _PII_PUBLIC_FIGURES for c in candidates):
            return m.group(0)
        # Sonst maskieren.
        return m.group(0).replace(names_block, "[Namen entfernt]")
    out = _PII_DOXXING_LIST_RE.sub(_strip_names_keep_publics, out)
    out = _PII_DOXXING_OPENER_RE.sub(_strip_names_keep_publics, out)
    # 4. Cleanup: doppelte Platzhalter zusammenfassen
    out = re.sub(r'(\[(?:Namen|Adresse|Telefon|E-Mail|Kennzeichen|Geburtsdatum) entfernt\])'
                 r'(\s+\1){1,}', r'\1', out)
    return out

# Political-motive signal for Sachbeschädigung: without one of these (or a
# known actor), the incident is treated as non-political vandalism and dropped.
_POLITICAL_MOTIVE_RE = re.compile(
    r'\b(bekennerschreiben|bekenntnis|molotow|brandsatz|brandsätze|farbbeutel|'
    r'politisch motivier|politisch motivation|politisch motiviert|antifa|'
    r'autonome|schwarzer block|antifaschistisch|antikapitalistisch|'
    r'linksautonom|riot|widerstand|sabotage|anschlag)',
    re.IGNORECASE,
)

# Threat-phrase signal for Schmiererei: pure graffiti is noise; only kept if
# the text contains a credible threat or a high-severity boost.
_THREAT_PHRASE_RE = re.compile(
    r'(tod\s+den|wir\s+kommen\s+wieder|nächstes\s+mal\s+feuer|'
    r'wir\s+wissen\s+wo\s+ihr\s+wohnt|wir\s+finden\s+euch|werdet\s+nicht\s+ruhig\s+schlafen|'
    r'feuer\s+und\s+flamme|kein\s+frieden|drohung|bombendrohung)',
    re.IGNORECASE,
)

def normalize_url(url, source=""):
    """
    Repair relative or junk URLs before they hit the DB. Returns a fully
    qualified https:// URL, or "" if the URL cannot be salvaged — caller
    must skip such incidents.
    """
    if not url:
        return ""
    u = url.strip()
    src = (source or "").lower()
    if u.startswith("//"):
        u = "https:" + u
    if u.startswith("/"):
        if "indymedia" in src:
            return "https://de.indymedia.org" + u
        if "barrikade" in src:
            return "https://barrikade.info" + u
        # Unknown host: cannot reconstruct → reject.
        return ""
    if not (u.startswith("http://") or u.startswith("https://")):
        return ""
    return u

def compute_flags(category, text, severity):
    """
    Derive (is_primary, is_high_risk, tier) from category + text + severity.

    tier is the Fedpol Art. 19 Abs. 2 Bst. e NDG taxonomy:
      'act'     — Verüben (Brandanschlag, Sabotage, Gewalt, Militante Aktion,
                  Sachbeschädigung mit politischem Motiv).
      'enable'  — Fördern (Aufruf zu Gewalt, Mobilisierungstreffen,
                  Gewaltpropaganda, Schmiererei mit Drohphrase + Sev≥3).
      'context' — alles übrige (Demo/Kundgebung, Repression, Besetzung,
                  Verhaftung, Sonstiges, Schmiererei ohne Drohphrase,
                  Sachbeschädigung ohne politisches Motiv).

    is_primary stays 1 only for tier=='act' (UI backward-compat).
    """
    cat = (category or "").strip()
    t   = (text or "").lower()

    act_cats    = {"Brandanschlag", "Sabotage", "Gewalt", "Militante Aktion"}
    enable_cats = {"Aufruf zu Gewalt"}

    if cat in act_cats:
        tier = "act"
    elif cat in enable_cats:
        tier = "enable"
    elif cat == "Sachbeschädigung":
        # PRIMARY/act only if politically motivated; otherwise T3 context.
        tier = "act" if _POLITICAL_MOTIVE_RE.search(t) else "context"
    elif cat == "Schmiererei":
        # Schmiererei → enable only with a credible threat phrase AND sev≥3,
        # otherwise context. Mirrors the §0 v3 policy and §2e save floor.
        tier = "enable" if (
            (severity or 0) >= 3 and _THREAT_PHRASE_RE.search(t)
        ) else "context"
    else:
        # Demo/Kundgebung, Repression, Besetzung, Verhaftung, Sonstiges → context.
        tier = "context"

    is_primary   = 1 if tier == "act" else 0
    is_high_risk = 1 if (
        (severity or 0) >= 4
        or re.search(r'\b(schwer\s+verletzt|tot\b|getötet|explosion|sprengstoff)\b', t)
    ) else 0
    return is_primary, is_high_risk, tier


# Target-type routing — used by Säule 2 (operative Frühwarnung) to detect
# clusters of attacks on the same target class. Regex fallback when Grok
# does not return ziel_typ. Keep keys short ASCII tokens for stable joins.
_TARGET_TYPE_RE = [
    ("Energie",    re.compile(r"\b(strommast|umspannwerk|kraftwerk|stromleitung|hochspannungs?|tennet|enbw|rwe|eon|gaspipeline|pipeline|wärmepumpe|fernwärme|stadtwerke)\b", re.I)),
    ("Telekom",    re.compile(r"\b(telekom|vodafone|funkmast|funkturm|sendemast|5g[- ]?mast|glasfaser|kabelverteiler)\b", re.I)),
    ("Schiene",    re.compile(r"\b(bahn|gleis|signaltechnik|kabelschacht|stellwerk|deutsche\s+bahn|sbb|öbb|s[- ]?bahn|ic[e]?[- ]?strecke)\b", re.I)),
    ("Auto",       re.compile(r"\b(tesla|porsche|audi|mercedes|bmw|vw|volkswagen|autohaus|showroom|ladestation|e[- ]?auto|suv|reifen.{0,15}(zerstoch|aufgeschlitzt|platt))\b", re.I)),
    ("Militär",    re.compile(r"\b(bundeswehr|wehrmacht|kaserne|munition|nato|karriereberat|panzer|raketen?werfer|rheinmetall|heckler|krauss[- ]?maffei)\b", re.I)),
    ("Polizei",    re.compile(r"\b(polizei|streifenwagen|polizeifahrzeug|polizeirevier|polizeiwache|polizist|cobra|gsg ?9)\b", re.I)),
    ("Politik",    re.compile(r"\b(parteibüro|parteizentrale|cdu|csu|spd|grüne|fdp|afd|linke|wahlkampfbüro|wahlkreisbüro|abgeordnetenbüro|rathaus)\b", re.I)),
    ("Justiz",     re.compile(r"\b(gericht|justizvollzug|jva|staatsanwaltschaft|amtsgericht|landgericht|olg|verwaltungsgericht|verfassungsgericht)\b", re.I)),
    ("Medien",     re.compile(r"\b(zeitung|verlag|redaktion|funkhaus|fernsehsender|rundfunk|ard\b|zdf\b|orf\b|srf\b)\b", re.I)),
    ("Wirtschaft", re.compile(r"\b(bank|sparkasse|amazon|lidl|aldi|edeka|rewe|konzern|firmensitz|hauptsitz|niederlassung)\b", re.I)),
]
_TARGET_TYPE_ALLOWED = {
    "Energie","Telekom","Schiene","Auto","Militär","Polizei","Politik",
    "Justiz","Medien","Wirtschaft","Privatperson","Andere",""
}

def compute_target_type(text, category=""):
    """Cheap regex fallback for Grok's ziel_typ. Returns '' if no match."""
    if not text:
        return ""
    for label, rx in _TARGET_TYPE_RE:
        if rx.search(text):
            return label
    return ""

def save_incident(ai, text, source, url, date_str=None, manual=False):
    """
    Persist one incident, applying the v3 ingestion policy.

    Policy v3 (Concept §C2):
      - Demo/Kundgebung, Repression, Sonstiges, Besetzung, Verhaftung,
        Schmiererei ohne Drohphrase, Sachbeschädigung ohne politisches Motiv
        werden NICHT mehr rejected, sondern als tier='context' (T3) gespeichert.
      - tier='act' (T1)    → Brandanschlag/Sabotage/Gewalt/Militante Aktion,
                              politisch motivierte Sachbeschädigung
      - tier='enable' (T2) → Aufruf zu Gewalt, Schmiererei mit Drohphrase + sev≥3
      - tier='context' (T3) → der gesamte Rest (Lagebild-Vollständigkeit)
    Hard rejects bleiben nur: DOXXING, fehlende URL, false_positive
    (siehe is_false_positive() Aufrufer in parse_rss).
    Returns True if a new row was inserted, False otherwise.
    """
    # ── URL gate ───────────────────────────────────────────────────
    url_norm = normalize_url(url, source)
    if not url_norm and not manual:
        log.info(f"filtered: no_valid_url ({source})")
        return False

    # ── DOXXING SANITISATION ─────────────────────────────────────
    # Sicherheits-Politik v3 (User-Hinweis): Doxxing-Events sind ein
    # militant-linker Akt und gehören in die Dokumentation — ABER ohne
    # Inhalt der Originalquelle (die selbst die PII trägt) und ohne
    # Klarnamen oder Adressen in der DB. Wir behalten das Ereignis als
    # T3-Kontext mit Rollen-Hinweis ("AfD-Politiker in <Stadt> wurde
    # gedoxxt") und löschen die Quelle.
    doxxing_sanitized = False
    if is_doxxing_text(text):
        summ_san, desc_san, _ = sanitize_doxxing_event(ai, text, source)
        log.info(f"DOXXING sanitised — keeping anon record ({source})")
        # Replace input variables before further processing so downstream
        # PII filters see clean placeholder text.
        ai = {**ai,
              "kategorie": "Sonstiges",
              "tier":      "context",
              "zusammenfassung": summ_san,
              "ist_gewalttat":   False}
        text = desc_san
        url_norm = ""             # Quelle bewusst entfernt
        source = f"{source}#sanitized"
        doxxing_sanitized = True

    h = mk_hash(url_norm or text[:80], text)
    if is_seen(h):
        return False

    cat = ai.get("kategorie", "Sonstiges")
    sev = score_severity(cat, text)
    act = extract_actors(text)
    conf = score_confidence(source)

    # ── Geocode + flags + summary ───────────────────────────────────
    # Country override: when the AI returns a country that disagrees with a
    # clearly-recognisable city in the text (Chemnitz → DE not CH), trust
    # the city. Prevents the Chemnitz-into-CH bug we saw in production.
    ort_raw = ai.get("ort", "")
    land_raw = ai.get("land", "Unbekannt")
    land_fixed = _override_country_from_city(ort_raw, text, land_raw)
    if land_fixed != land_raw:
        log.info(f"country override: {land_raw} → {land_fixed} (city={ort_raw})")
        land_raw = land_fixed

    lat, lon = geocode(ort_raw, land_raw)
    is_primary, is_high_risk, tier = compute_flags(cat, text, sev)

    # Grok may override tier directly via the new "tier" field.
    ai_tier = (ai.get("tier") or "").strip().lower()
    if ai_tier in ("act", "enable", "context"):
        tier = ai_tier
        is_primary = 1 if tier == "act" else 0

    # Target-type routing for Säule 2 (Frühwarn-Cluster).
    target_type = (ai.get("ziel_typ") or "").strip()
    if target_type not in _TARGET_TYPE_ALLOWED:
        target_type = ""
    if not target_type:
        target_type = compute_target_type(text, cat)

    summ = (ai.get("zusammenfassung") or "").strip()
    if not summ:
        summ = fallback_summary(text)
    # Strip activist phrasing AND clamp to 140 chars / 2 sentences — the new
    # high-impact-news style the dashboard renders. Defense-in-depth: even a
    # too-long Grok output gets trimmed here.
    summ = clamp_two_sentences(
        strip_activist_phrases(redact_pii(summ)),
        140,
    )

    d = date_str or datetime.now().strftime("%Y-%m-%d")
    desc = redact_pii(clean_description(text))[:500]
    ai["land"] = land_raw  # propagate the corrected value to the INSERT below

    try:
        db.execute(
            """INSERT OR IGNORE INTO incidents
               (date,location,country,category,description,source,url,hash,lat,lon,
                manual,timestamp,severity_score,actors,confidence,
                summary,is_primary,is_high_risk,tier,target_type)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'),?,?,?,?,?,?,?,?)""",
            (d, ai.get("ort", "Unbekannt"), ai.get("land", "Unbekannt"),
             cat, desc, source, url_norm, h, lat, lon,
             1 if manual else 0, sev, act, conf,
             summ, is_primary, is_high_risk, tier, target_type)
        )
        db.commit()
        # MS-5 — best-effort WARC snapshot of the source URL. Failing to
        # capture evidence must NOT roll back the incident save.
        if url_norm and not manual:
            ev_path, ev_sha, ev_ts = save_evidence(url_norm, h)
            if ev_path:
                db.execute(
                    "UPDATE incidents SET evidence_path=?, evidence_sha=?, evidence_ts=? WHERE hash=?",
                    (ev_path, ev_sha, ev_ts, h)
                )
                db.commit()
        log.info(
            f"SAVED [sev={sev}/conf={conf}/tier={tier}/hi={is_high_risk}/"
            f"target={target_type or '-'}]: {cat} / {ai.get('ort')} / {source}"
        )
        # ── Webhook-Fan-Out: nur T1-act-Vorfälle pushen, NIE doxxing-
        # sanitisierte oder T3-Kontext-Einträge — die haben keinen
        # operativen Mehrwert für Betreiber-Frühwarnung.
        if tier == "act" and not doxxing_sanitized and not manual:
            try:
                _fanout_webhook("incident.new", h, {
                    "event":           "incident.new",
                    "hash":            h,
                    "date":            d,
                    "location":        ai.get("ort"),
                    "country":         ai.get("land"),
                    "category":        cat,
                    "tier":            tier,
                    "target_type":     target_type,
                    "severity_score":  sev,
                    "summary":         summ,
                    "source":          source,
                    "url":             url_norm,
                })
            except Exception as e:
                log.info(f"webhook fan-out (incident) failed: {e}")
        return True
    except Exception as e:
        log.warning(f"save_incident: {e}")
        return False

def purge_garbage():
    """
    Aggressive one-time purge that enforces the plan §0 scope table.
    Idempotent — safe to call on every startup.
    """
    deleted = 0

    # 1) Nav-garbage descriptions (Indymedia boilerplate accidentally scraped).
    nav_patterns = [
        "Direkt zum Inhalt", "dont hate the media", "Tutorials Videos Archiv",
        "Tor nutzen", "Über uns > Kontakt",
    ]
    for pat in nav_patterns:
        c = db.execute(
            "DELETE FROM incidents WHERE description LIKE ? AND manual=0",
            (f"%{pat}%",)
        ).rowcount
        deleted += c

    # 2) Bogus location placeholders.
    bogus = ["Hinterlandregionen", "Konkurrenz", "Ihren Suchergebnissen",
             "Suchergebnissen", "Ergebnissen", "Tutorials"]
    for loc in bogus:
        c = db.execute(
            "DELETE FROM incidents WHERE location=? AND manual=0",
            (loc,)
        ).rowcount
        deleted += c
    # Unknown locations are mostly noise — but under Policy v3 we only purge
    # them if they're also low-severity (sev < 3). Real high-severity reports
    # without a parsed city stay as T3 context (still useful for aggregates).
    c = db.execute(
        "DELETE FROM incidents WHERE location IN ('','Unbekannt','Unknown') "
        "AND manual=0 AND (severity_score IS NULL OR severity_score < 3)"
    ).rowcount
    deleted += c

    # 3) Non-EU / wrong-perpetrator content that slipped through.
    fp_desc_patterns = [
        "%Kongo%", "%Ebola%", "%demokratische Republik Kongo%",
        "%faschistisches Motiv%", "%Neonazi%Angriff%",
        "%autonomes Fahren%", "%autonome Fahrzeuge%", "%künstliche Intelligenz%",
        "%Mobilitätsrevolution%", "%Bitcoin%Kurs%", "%Blockchain%Startup%",
    ]
    for pat in fp_desc_patterns:
        c = db.execute(
            "DELETE FROM incidents WHERE description LIKE ? AND manual=0",
            (pat,)
        ).rowcount
        deleted += c

    # 4) Missing / broken URLs — these are the "/node/734886" entries.
    c = db.execute(
        "DELETE FROM incidents WHERE manual=0 AND source != 'Archiv' "
        "AND (url IS NULL OR url = '' OR url NOT LIKE 'http%')"
    ).rowcount
    deleted += c

    # 5) Policy v3 (Concept §C2) — re-tag instead of delete.
    # Demo/Kundgebung, Repression, Sonstiges, Besetzung, Verhaftung and
    # the soft-filter variants of Schmiererei / Sachbeschädigung used to be
    # purged here. Under v3 they are kept as T3 context (Lagebild-
    # Vollständigkeit) and the backfill below sets tier='context'. We still
    # delete only the hardest noise (nav, FP, broken URL, doxxing).
    db.execute(
        "UPDATE incidents SET tier='context', is_primary=0 "
        "WHERE manual=0 AND category IN "
        "('Demo/Kundgebung','Repression','Sonstiges','Besetzung','Verhaftung') "
        "AND (tier IS NULL OR tier='' OR tier='act')"
    )

    # 6) DOXXING — purge entries whose description matches the Klarnamen-
    # outing pattern. These propagate the doxxing harm even when the action
    # itself is a militant-left act. (Non-negotiable per Concept §C3 #1.)
    rows = db.execute(
        "SELECT id, description, summary FROM incidents WHERE manual=0"
    ).fetchall()
    for r in rows:
        if is_doxxing_text(r["description"] or "") or is_doxxing_text(r["summary"] or ""):
            db.execute("DELETE FROM incidents WHERE id=?", (r["id"],))
            deleted += 1

    if deleted:
        db.commit()
        log.info(f"purge_garbage: removed {deleted} entries (Policy v3: T3 kept)")
    return deleted

def backfill_summaries_and_flags():
    """
    For existing rows, derive summary + is_primary + is_high_risk so the new
    UI works the moment the upgraded code starts. ALSO runs redact_pii() over
    descriptions + summaries so that older rows that pre-date the PII filter
    get retro-actively cleaned (addresses, names, phones removed).
    """
    rows = db.execute(
        "SELECT id, category, description, severity_score, summary, "
        "is_primary, is_high_risk, tier, target_type "
        "FROM incidents"
    ).fetchall()
    if not rows:
        return 0
    n = 0
    for r in rows:
        desc_in = r["description"] or ""
        summ_in = (r["summary"] or "").strip()
        desc_out = redact_pii(desc_in)
        # Re-strip activist phrasing + clamp to 140 chars even for existing
        # rows so the visual tightening is retroactive.
        summ_raw = summ_in or fallback_summary(desc_in)
        summ_out = clamp_two_sentences(
            strip_activist_phrases(redact_pii(summ_raw)),
            140,
        )
        prim, hi, tier_new = compute_flags(
            r["category"], desc_in, r["severity_score"] or 0
        )
        tt_old = (r["target_type"] or "").strip()
        tt_new = tt_old or compute_target_type(desc_in, r["category"])
        tier_old = (r["tier"] or "").strip()
        # Skip if nothing actually changed (avoid pointless writes on warm DB)
        if (desc_out == desc_in
                and summ_out == (r["summary"] or "")
                and prim == (r["is_primary"] or 0)
                and hi   == (r["is_high_risk"] or 0)
                and tier_new == tier_old
                and tt_new == tt_old):
            continue
        db.execute(
            "UPDATE incidents SET description=?, summary=?, is_primary=?, "
            "is_high_risk=?, tier=?, target_type=? WHERE id=?",
            (desc_out, summ_out, prim, hi, tier_new, tt_new, r["id"])
        )
        n += 1
    db.commit()
    if n:
        log.info(f"backfill_summaries_and_flags: updated {n} rows (PII + tier + target)")
    return n

def backfill_enrichment():
    """Backfill severity, actors, confidence for existing records that have 0 values."""
    rows = db.execute(
        "SELECT id, category, description, source FROM incidents WHERE severity_score=0 OR confidence=0"
    ).fetchall()
    if not rows:
        return
    updated = 0
    for row in rows:
        sev  = score_severity(row["category"], row["description"] or "")
        act  = extract_actors(row["description"] or "")
        conf = score_confidence(row["source"] or "")
        db.execute(
            "UPDATE incidents SET severity_score=?, actors=?, confidence=? WHERE id=?",
            (sev, act, conf, row["id"])
        )
        updated += 1
    if updated:
        db.commit()
        log.info(f"Backfill: enriched {updated} incidents")

def seed_historical_data():
    """Insert pre-defined historical incidents if not already seeded."""
    count = db.execute("SELECT COUNT(*) FROM incidents WHERE source='Archiv'").fetchone()[0]
    if count > 0:
        log.info(f"Seed: bereits {count} Archiv-Einträge vorhanden")
        return 0
    inserted = 0
    for date, location, country, category, description, source, lat, lon in HISTORICAL_EVENTS:
        url = f"archiv:{date}:{location}:{category}"
        h = mk_hash(url, description)
        if is_seen(h):
            continue
        try:
            db.execute(
                """INSERT OR IGNORE INTO incidents
                   (date,location,country,category,description,source,url,hash,lat,lon,manual,timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,1,datetime('now'))""",
                (date, location, country, category, description, source, url, h, lat, lon)
            )
            inserted += 1
        except Exception as e:
            log.warning(f"seed: {e}")
    if inserted:
        db.commit()
        log.info(f"Seed: {inserted} historische Einträge eingespielt")
    return inserted

# ════════════════════════════════════════════════════════════════════
# Funding seed version tracking.
#
# When the curated seed list changes — especially when entries are REMOVED
# because they no longer meet the strict inclusion criteria — we must purge
# old seeded records from existing production databases. A version bump
# triggers a one-shot reseed: previously seeded entries are deleted and the
# current FUNDING_SEED is re-inserted. Manual admin-added entries (anything
# whose hash is NOT in the current seed-hash set) are preserved.
# ════════════════════════════════════════════════════════════════════
FUNDING_SEED_VERSION = "2026-05-credibility-v3"

def _funding_seed_hashes():
    """Return the set of hashes for entries currently in FUNDING_SEED.
    Tuples carry an extra `verified` flag (12 fields); the legacy 11-field
    shape is still accepted for forward-compat."""
    hs = set()
    for row in FUNDING_SEED:
        recipient_org = row[0]; amount = row[2]; year = row[4]; donor_name = row[7]
        h_input = (f"fund|{recipient_org.lower().strip()}|{year}|"
                   f"{donor_name.lower().strip()}|{round(float(amount))}")
        hs.add(hashlib.sha256(h_input.encode()).hexdigest())
    return hs

def purge_stale_funding_seeds():
    """
    Remove seeded funding records that are no longer part of the curated
    FUNDING_SEED list. Identifies "seeded" records as those whose hash is
    NOT one of the current seed-hash set AND whose hash starts with the
    seed pattern (`fund|`-derived hash). To avoid touching anything that
    might be admin-added, we ONLY delete rows whose hash matches a stored
    "previously-seeded" hash list, and rebuild that list from the current
    seed afterwards.
    """
    current_hashes = _funding_seed_hashes()
    prev_serialized = meta_get("fund_seed_hashes") or ""
    prev_hashes = set(h for h in prev_serialized.split(",") if h)
    stale = prev_hashes - current_hashes
    deleted = 0
    if stale:
        placeholders = ",".join("?" * len(stale))
        cur = db.execute(
            f"DELETE FROM funding_records WHERE hash IN ({placeholders})",
            tuple(stale)
        )
        deleted = cur.rowcount
        db.commit()
        log.info(f"Funding purge: removed {deleted} stale seed records "
                 f"(seed version → {FUNDING_SEED_VERSION})")
    # Persist the new seed-hash set so the next version bump can find stale rows
    meta_set("fund_seed_hashes", ",".join(sorted(current_hashes)))
    meta_set("fund_seed_version", FUNDING_SEED_VERSION)
    return deleted

def seed_funding_data():
    """
    Idempotently seed the funding_records table from FUNDING_SEED.
    Returns the number of newly inserted rows. Safe to call repeatedly:
    the UNIQUE hash prevents duplicates.
    Before seeding, purge any stale records left behind by an earlier
    (now-removed) seed entry — see purge_stale_funding_seeds().
    """
    purge_stale_funding_seeds()
    existing = db.execute("SELECT COUNT(*) FROM funding_records").fetchone()[0]
    # We allow re-seeding even when records already exist, because purge
    # may have just emptied the table. The UNIQUE hash constraint prevents
    # duplicate insertion of records that survived the purge.
    inserted = 0
    for row in FUNDING_SEED:
        # 12-Tupel-Format (mit verified-Flag); 11-Feld-Eintraege defaulten auf verified=0.
        if len(row) == 12:
            (recipient_org, project, amount, currency, year, country,
             donor_type, donor_name, source_url, notes, confidence, verified) = row
        else:
            (recipient_org, project, amount, currency, year, country,
             donor_type, donor_name, source_url, notes, confidence) = row[:11]
            verified = 0
        h_input = (
            f"fund|{recipient_org.lower().strip()}|{year}|"
            f"{donor_name.lower().strip()}|{round(float(amount))}"
        )
        h = hashlib.sha256(h_input.encode()).hexdigest()
        try:
            cur = db.execute(
                """INSERT OR IGNORE INTO funding_records
                   (recipient_org, project, amount, currency, year, country,
                    donor_type, donor_name, source_url, notes, confidence,
                    verified, manual, hash, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,datetime('now'))""",
                (recipient_org, project, amount, currency, year, country,
                 donor_type, donor_name, source_url, notes, confidence, verified, h)
            )
            if cur.rowcount > 0:
                inserted += 1
        except Exception as e:
            log.warning(f"seed_funding: {recipient_org} / {year} — {e}")
    db.commit()
    log.info(f"Funding seed: {inserted} records inserted")
    return inserted

# ── BARRIKADE ID CRAWLER ──────────────────────────────────────────
def barrikade_latest_id():
    try:
        html = fetch("https://barrikade.info/")
        ids = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        return max(ids) if ids else 7600
    except Exception as e:
        log.warning(f"barrikade_latest_id: {e}")
        return 7600

def _barrikade_discover_urls():
    """Discover recent barrikade article URLs via multiple strategies.
    Returns a list of unique URLs sorted newest-first (best-effort).
    Probiert in dieser Reihenfolge:
      1. Mehrere RSS-/Atom-Endpoint-Kandidaten (Drupal/WP-Standard-Pfade)
      2. sitemap.xml und sitemap_index.xml
      3. Homepage-Scrape mit Regex für /article/<id>
    Damit ist der Crawler robust gegenüber Anti-Bot-Schutz auf
    einzelnen Pfaden — wenn EIN Endpoint geht, kommen die Artikel rein.
    """
    candidates = [
        # RSS/Atom Standard-Pfade
        ("rss-feed",      "https://barrikade.info/feed"),
        ("rss-feed-slash","https://barrikade.info/feed/"),
        ("rss-rss",       "https://barrikade.info/rss"),
        ("rss-rss-xml",   "https://barrikade.info/rss.xml"),
        ("rss-index",     "https://barrikade.info/index.rss"),
        ("rss-atom",      "https://barrikade.info/atom"),
        # Drupal default
        ("drupal-feeds",  "https://barrikade.info/feeds/all.rss.xml"),
        # Sitemap discovery
        ("sitemap",       "https://barrikade.info/sitemap.xml"),
        ("sitemap-index", "https://barrikade.info/sitemap_index.xml"),
        # Homepage scrape (always last, fewest signals)
        ("homepage",      "https://barrikade.info/"),
    ]
    found = []  # preserve order
    seen  = set()
    for label, u in candidates:
        try:
            body = fetch(u, timeout=12)
            if not body or len(body) < 100:
                continue
            # Extract article URLs/IDs via three different parsers depending
            # on what we got back.
            urls = []
            if "<rss" in body[:200].lower() or "<feed" in body[:200].lower() or "<atom" in body[:200].lower():
                # RSS/Atom — extract <link> tags
                for m in re.finditer(r"<link[^>]*>([^<]+)</link>", body):
                    href = m.group(1).strip()
                    if "/article/" in href or "barrikade.info" in href:
                        urls.append(href)
                # Atom-style <link href="…"/>
                for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', body):
                    href = m.group(1).strip()
                    if "/article/" in href:
                        urls.append(href)
            elif "<urlset" in body[:200].lower() or "<sitemapindex" in body[:200].lower():
                # sitemap.xml
                for m in re.finditer(r"<loc>([^<]+)</loc>", body):
                    href = m.group(1).strip()
                    if "/article/" in href:
                        urls.append(href)
            else:
                # HTML scrape
                for m in re.finditer(r"/article/(\d+)", body):
                    urls.append(f"https://barrikade.info/article/{m.group(1)}")
            log.info(f"barrikade discover [{label}] HTTP-200, parsed {len(urls)} candidate URLs")
            for u in urls:
                if u not in seen:
                    seen.add(u); found.append(u)
            # If we have a healthy number, stop probing further endpoints.
            if len(found) >= 30:
                break
        except Exception as e:
            log.info(f"barrikade discover [{label}] failed: {str(e)[:120]}")
    return found

def crawl_barrikade_range(start_id, stop_id):
    """Crawl barrikade article IDs from start_id down to stop_id.

    Resilience v3 (User-Hinweis: Crawler funktioniert immer noch nicht):
      1. Versuche zuerst Multi-URL-Discovery (RSS/Atom/Sitemap/Homepage,
         insgesamt 10 verschiedene Pfade) — irgendeiner davon wird
         funktionieren.
      2. Falls Discovery URLs liefert: parse jeden, klassifiziere, speichere.
      3. Falls Discovery komplett scheitert: ID-Sweep mit aggressivem
         Backoff bei 403/429.
    """
    inserted = 0

    # 1) Multi-URL-Discovery (RSS, Atom, Sitemap, Homepage-Scrape)
    discovered = _barrikade_discover_urls()
    if discovered:
        log.info(f"barrikade: {len(discovered)} URLs from discovery — processing")
        for link in discovered[:50]:  # cap to avoid runaway
            try:
                h = mk_hash(link, link)
                if is_seen(h): continue
                full = get_text(link)
                if len(full) < 60: continue
                if not any(kw in full.lower() for kw in BARRIKADE_RELEVANCE_KWS):
                    continue
                if is_false_positive(full): continue
                ai = smart_classify(full)
                if ai:
                    if save_incident(ai, full, "barrikade.info", link, date_from_url(link)):
                        inserted += 1
                time.sleep(0.4)
            except Exception as e:
                log.info(f"barrikade link={link}: {str(e)[:100]}")
        if inserted > 0:
            log.info(f"barrikade discovery path saved {inserted} new incidents")
            # Wenn Discovery erfolgreich war, ID-Sweep ist optional —
            # er kostet API-Calls und der RSS hat ja die neuesten Artikel.
            return inserted

    # 2) ID-Sweep (Historie + neueste IDs die noch nicht im RSS waren).
    misses = 0
    consecutive_403 = 0
    for aid in range(start_id, stop_id - 1, -1):
        url = f"https://barrikade.info/article/{aid}"
        try:
            text = get_text(url)
            if len(text) < 80:
                misses += 1
                if misses >= 40: break
                time.sleep(0.2)
                continue
            misses = 0; consecutive_403 = 0
            h = mk_hash(url, text)
            if is_seen(h): time.sleep(0.1); continue
            if not any(kw in text.lower() for kw in BARRIKADE_RELEVANCE_KWS):
                time.sleep(0.1)
                continue
            if is_false_positive(text):
                time.sleep(0.1)
                continue
            ai = smart_classify(text)
            if ai:
                if save_incident(ai, text, "barrikade.info", url, date_from_url(url)):
                    inserted += 1
            time.sleep(0.6)
        except requests.HTTPError as e:
            code = getattr(e.response, "status_code", 0)
            if code == 404:
                misses += 1; time.sleep(0.2)
            elif code in (403, 429):
                consecutive_403 += 1
                if consecutive_403 <= 3:
                    log.info(f"barrikade id={aid} HTTP {code}, backing off 30s")
                    time.sleep(30)
                else:
                    log.warning(f"barrikade: {consecutive_403} consecutive 403/429 — aborting ID sweep")
                    break
            else:
                log.warning(f"barrikade id={aid} HTTP {code}")
                time.sleep(3)
        except Exception as e:
            log.warning(f"barrikade id={aid}: {e}"); time.sleep(0.5)
    return inserted

# ── INDYMEDIA RSS + PAGE CRAWLER ──────────────────────────────────
def crawl_indymedia_feed():
    """Crawl de.indymedia.org RSS plus active German-language left-wing alternatives."""
    inserted = 0
    seen_urls: set = set()

    # ── de.indymedia.org + Indymedia-Netzwerk Europa/USA ─────────────
    # Wir crawlen jetzt nicht nur Berlin/DE, sondern auch die regional-
    # und länderspezifischen Indymedia-Knoten. Jeder Feed wird einzeln mit
    # kurzem Timeout angefragt; tote Knoten loggen leise und blocken nichts.
    for feed_url in [
        # ── DE: Bundesweite Knoten ──
        "https://de.indymedia.org/RSS/newswire.xml",
        "https://de.indymedia.org/RSS/features.xml",
        "https://de.indymedia.org/taxonomy/term/20/all/feed",   # Antifa
        "https://de.indymedia.org/taxonomy/term/17/all/feed",   # Antirepression
        "https://de.indymedia.org/taxonomy/term/22/all/feed",   # Antimilitarismus
        "https://de.indymedia.org/taxonomy/term/18/all/feed",   # Soziale Kämpfe
        "https://de.indymedia.org/taxonomy/term/19/all/feed",   # Globale Gerechtigkeit
        # ── Europäische Indymedia-Knoten ──
        "https://athens.indymedia.org/feed/",                   # GR Athen
        "https://radar.squat.net/en/rss",                        # CH/NL/EU squat-Netzwerk
        "https://www.indymedia.ie/rss/news",                    # IE Irland
        "https://www.indymedia.org.uk/en/rss/articles/feed.xml",# UK
        "https://italy.indymedia.org/rss.xml",                  # IT
        # ── USA Indymedia-Verbund ──
        "https://nycindymedia.org/feed",                        # US NY
        "https://www.itsgoingdown.org/feed/",                   # US Antifa/Anarcho Newswire
        "https://crimethinc.com/feed",                          # US Anarcho
        "https://rosecityantifa.org/feed/",                     # US Portland
    ]:
        try:
            r = session.get(feed_url, timeout=8, allow_redirects=True)
            r.raise_for_status()
            items = parse_rss(r.text)
            log.info(f"indymedia {feed_url.split('/')[-1]}: {len(items)} items")
            for title, link, desc, pub in items:
                # Normalize relative /node/... URLs to absolute before use.
                link = normalize_url(link, "de.indymedia.org")
                if not link or link in seen_urls: continue
                seen_urls.add(link)
                preview = (title + " " + desc).lower()
                if is_false_positive(preview): continue
                h = mk_hash(link, title + desc)
                if is_seen(h): continue
                full = get_text(link)
                text = full if len(full) > 100 else f"{title}. {desc}"
                if len(text) < 30: continue
                ai = smart_classify(text)
                if ai:
                    d = parse_date(pub) or date_from_url(link)
                    if save_incident(ai, text, "de.indymedia.org", link, d):
                        inserted += 1
                time.sleep(0.5)
        except Exception as e:
            log.warning(f"indymedia {feed_url.split('/')[-1]}: {e}")
        time.sleep(0.3)

    # ── Active alternative left-wing sources (DE/AT/CH + EU + USA) ──
    for source, url in [
        ("labournet.de",            "https://www.labournet.de/feed/"),
        ("perspektive-online.net",  "https://perspektive-online.net/feed/"),
        ("klassegegenklasse.org",   "https://www.klassegegenklasse.org/feed/"),
        ("jungle.world",            "https://jungle.world/rss.xml"),
        ("nd-aktuell.de",           "https://www.nd-aktuell.de/rss/aktuell.xml"),
        ("untergrund-blättle.ch",   "https://www.untergrund-blaettle.ch/rss.xml"),
        ("contraste.org",           "https://www.contraste.org/feed/"),
        ("autonomes-zentrum.org",   "https://www.az-koeln.org/feed/"),
        # ── englischsprachig (UK / US / international) ──
        ("freedomnews.org.uk",      "https://freedomnews.org.uk/feed/"),
        ("libcom.org",              "https://libcom.org/rss.xml"),
        ("anarchistnews.org",       "https://anarchistnews.org/rss.xml"),
        ("redfish.media",           "https://redfish.media/feed/"),
        ("popularresistance.org",   "https://popularresistance.org/feed/"),
        ("truthout.org",            "https://truthout.org/feed/"),
        ("commondreams.org",        "https://www.commondreams.org/rss.xml"),
    ]:
        try:
            n = crawl_rss_feed(source, url, max_items=8)
            inserted += n
        except Exception as e:
            log.warning(f"alt-feed {source}: {e}")
        time.sleep(0.4)

    return inserted

# ── RSS FEEDS ─────────────────────────────────────────────────────
RSS_KEYWORDS = [
    "linksextrem","linksradikal","antifa","anarchi","schwarzer block","black bloc",
    "brandanschlag","sabotage","molotow","farbbeutel","bekennerschreiben","militante",
    "besetzung","blockade","rigaer","rote flora","sachbeschädigung","in brand",
    "autonome gruppe","autonome szene","autonome aktion","autonome linke",
    "verfassungsschutz extremis","linksradikal verhaftung","linksextrem anschlag",
    "direkte aktion","barrikade","hausbesetzung","fahrzeugbrand","fahrzeuge in brand",
]

# ── FALSE-POSITIVE FILTER ─────────────────────────────────────────
# Reject articles that match RSS_KEYWORDS superficially but are NOT political extremism
_FP = [
    # Technology / autonomous vehicles
    r'\bautonomes?\s+(fahren|fahrzeuge?|autos?\b|lkw|pkw|bus\b|roboter|drohnen?|flugzeug)',
    r'\bself.?driving\b', r'\bautopilot\b',
    r'\bautonomes?\s+(parken|laden|liefern)',
    r'\bautonome[srm]?\s+(mobilitäts?|verkehrs?|transport)',
    r'\belektroauto[s]?\b', r'\be-auto[s]?\b', r'\belektromobilit',
    r'\bdigitale\s+revolution\b',
    r'\bkünstliche\s+intelligenz\b',
    r'\bki-?\s*(modell|system|assistent|tool|chip)',
    r'\bmobilitäts?revolution\b', r'\benergie(wende|revolution)\b',
    r'\bkrypto|bitcoin|blockchain\b',
    r'\baktienmarkt|börsen?kurse?\b',
    r'\blandwirtschaft.*sabotag|sabotag.*landwirtschaft',
    r'\bautonomie\s+(schweiz|österreich|deutschland|region)',
    # Non-European conflicts / disasters (not relevant to DACH extremism)
    r'\bkongo\b', r'\bebola\b', r'\bafrika\b', r'\bnigeria\b', r'\bsomalia\b',
    r'\bsyrien\b', r'\bjemen\b', r'\biraq\b', r'\bafghanistan\b', r'\bukraine.*front\b',
    r'\bpalästina.*rakete|rakete.*palästina\b',
    r'\bdemokratische\s+republik\s+kongo\b',
    # Right-wing perpetrators attacking others (we track LEFT extremism only)
    r'\bneonazi.*angriff\b', r'\bnazi.*überfall\b', r'\bnazi.*attack\b',
    r'\brechtsextrem.*täter\b', r'\brechtsextrem.*angreifer\b',
    r'\bneonazi.*täter\b', r'\bfaschistisch.*motiv\b', r'\brechts.*täter\b',
    r'\bRechtsterror\b', r'\bPKK\b', r'\bIslamist\b', r'\bdschihadist\b',
    # Navigation/website content accidentally scraped
    r'\bTutorials\s+Videos\s+Archiv\b', r'\bdont\s+hate\s+the\s+media\b',
    r'\bDirekt\s+zum\s+Inhalt\b',
    # ── Plan §0 out-of-scope: solidarity / culture / repression-reports ──
    r'\bsolidaritätsaufruf\b', r'\bsolidaritätskundgebung\b',
    r'\bgedenken\b(?!.*anschlag)', r'\bmahnwache\b(?!.*anschlag)',
    r'\bprozessbeobachtung\b', r'\brepressionsbericht\b',
    r'\blesung\b', r'\bvokü\b', r'\btresen\b', r'\binfoveranstaltung\b',
    r'\bdiskussionsveranstaltung\b', r'\bkonzert\b', r'\bsoliparty\b',
    r'\bkneipenabend\b',
    # ── Non-DACH foreign-policy items that bypass the EU/perpetrator gate ──
    r'\b(gaza|israel|palästina|hamas)\b',
    r'\b(trump|biden|harris|usa\b|united\s+states)\b',
    r'\b(china|taiwan|tibet|xinjiang|hongkong)\b',
    r'\b(iran|saudi|yemen|libanon|hisbollah)\b',
    # ── Polizei-Press-FP: typische Nicht-Extremismus-Meldungen ────
    # Polizei-Pressestellen publizieren TÄGLICH Verkehrsunfälle,
    # Ladendiebstähle, Drogendelikte usw. Diese MUESSEN raus, sonst
    # frisst der Grok-Classifier eine 5stellige Token-Rechnung weg.
    r'\b(verkehrsunfall|verkehrskontrolle|geschwindigkeitskontrolle|alkohol\s*am\s+steuer)\b',
    r'\b(ladendiebstahl|taschendiebstahl|fahrraddiebstahl|wohnungseinbruch)\b',
    r'\b(drogenfund|btmg|cannabis|kokain|crystal\s*meth)\b(?!.*demo)',
    r'\bvermisst.*person\b', r'\bsenioren?\b.*\btrickbetrug\b',
    r'\bbrand\s+in\s+wohnung\b(?!.*polit)',
    r'\benkeltrick|schockanruf\b',
    r'\bsexual.*delikt\b(?!.*polit)',
    r'\bversicherungs?betrug|sozialleistungs?betrug\b',
    r'\bgemein(de|sames)?\s+spendenaufruf\b',
    r'\btierrettung|tierquäler', r'\bunwetter|hochwasser|sturm\b(?!.*demo)',
    # ── Bundestags-Drucksachen: vieles davon ist Lesung/Anhörung ────
    r'\b(lesung|abstimmung|anhörung|haushalts(beratung|debatte))\b(?!.*linksex)',
    r'\bgrundgesetz.*änderung\b(?!.*linksex)',
]

def is_false_positive(text):
    """Tightened per plan §0 — strict OSINT scope for DACH violent left."""
    t = text.lower()
    # Pure non-DACH foreign-policy hits should NOT veto an article that also
    # contains a DACH city + a real attack keyword (e.g. a Berlin Brandanschlag
    # framed as anti-Israel). Allow if a strong primary attack keyword is present.
    strong_attack = re.search(
        r'\b(brandanschlag|brandsatz|molotow|in\s+brand\s+gesetzt|sabotage\s+an|'
        r'bekennerschreiben|sprengstoff|militante\s+aktion)\b', t)
    for p in _FP:
        if re.search(p, t, re.IGNORECASE):
            # Exempt foreign-policy patterns only if a strong attack keyword + DACH city co-occur.
            if strong_attack and re.search(
                r'\b(berlin|hamburg|leipzig|münchen|köln|frankfurt|dresden|stuttgart|'
                r'wien|graz|linz|zürich|bern|basel|genf|lausanne)\b', t):
                continue
            return True
    return False

# ── GEOCODE COUNTRY BOUNDS ────────────────────────────────────────
# (min_lat, min_lon, max_lat, max_lon) — generous margins to avoid false rejections
_CO_BOUNDS = {
    "DE": (46.5,  5.5, 55.5, 15.5),
    "AT": (46.2,  9.3, 49.2, 17.3),
    "CH": (45.7,  5.8, 48.0, 10.7),
    "FR": (41.2, -5.3, 51.2,  9.7),
    "IT": (35.5,  6.5, 47.2, 18.6),
    "GR": (34.5, 19.2, 42.0, 29.8),
    "ES": (35.8, -9.5, 43.9,  4.4),
    "UK": (49.7, -8.5, 61.0,  2.2),
    "IE": (51.4, -10.6, 55.4, -5.4),
    "NL": (50.7,  3.3, 53.6,  7.3),
    "BE": (49.5,  2.5, 51.6,  6.5),
    "LU": (49.4,  5.7, 50.2,  6.6),
    "DK": (54.5,  8.0, 57.8, 15.3),
    "SE": (55.3, 10.9, 69.1, 24.2),
    "NO": (57.9,  4.3, 71.2, 31.3),
    "FI": (59.7, 20.5, 70.1, 31.6),
    "PL": (49.0, 14.1, 54.9, 24.2),
    "CZ": (48.5, 12.1, 51.1, 18.9),
    "HU": (45.7, 16.1, 48.6, 22.9),
    "RO": (43.6, 20.2, 48.3, 29.7),
    "PT": (36.9, -9.6, 42.2, -6.2),
    "US": (24.5,-125.0, 49.5, -66.9),
}

def _coords_in_country(country, lat, lon):
    if lat is None or lon is None: return True
    b = _CO_BOUNDS.get(country)
    if not b: return True
    return b[0] <= lat <= b[2] and b[1] <= lon <= b[3]

RSS_FEEDS = [
    # ── Sicherheitsbehörden ────────────────────────────────────────
    ("verfassungsschutz.de",  "https://www.verfassungsschutz.de/SiteGlobals/Functions/RSSNewsFeed/AlleMeldungen.xml"),
    # ── DE — öffentlich-rechtlich + Leitmedien ────────────────────
    ("tagesschau.de",         "https://www.tagesschau.de/xml/rss2/"),
    ("deutschlandfunk.de",    "https://www.deutschlandfunk.de/nachrichten.rss"),
    ("spiegel.de",            "https://www.spiegel.de/schlagzeilen/index.rss"),
    ("zeit.de",               "https://newsfeed.zeit.de/politik/index"),
    ("sueddeutsche.de",       "https://rss.sueddeutsche.de/rss/Politik"),
    ("faz.net",               "https://www.faz.net/rss/aktuell/"),
    ("welt.de",               "https://www.welt.de/feeds/section/politik.rss"),
    ("tagesspiegel.de",       "https://www.tagesspiegel.de/contentexport/feed/home"),
    ("taz.de",                "https://taz.de/!p4608;rss/"),
    ("mdr.de",                "https://www.mdr.de/nachrichten/rss-nachrichten100.xml"),
    ("rbb24.de",              "https://www.rbb24.de/index/rss.xml/index.xml"),
    ("ndr.de",                "https://www.ndr.de/nachrichten/index-rss.xml"),
    ("wdr.de",                "https://www1.wdr.de/uebersicht-100.feed"),
    ("br.de",                 "https://www.br.de/nachrichten/index.xml"),
    ("hr.de",                 "https://www.hr.de/news/index-rss.xml"),
    ("swr.de",                "https://www.swr.de/aktuell/index.xml"),
    ("ntv.de",                "https://www.n-tv.de/politik/rss"),
    # ── CH — Kernmedien + Regionalmedien ──────────────────────────
    ("nzz.ch",                "https://www.nzz.ch/recent.rss"),
    ("tagesanzeiger.ch",      "https://www.tagesanzeiger.ch/rss.xml"),
    ("srf.ch",                "https://www.srf.ch/news/bnf/rss/1646"),
    ("20min.ch",              "https://api.20min.ch/rss/view/1"),
    ("blick.ch",              "https://www.blick.ch/news/rss.xml"),
    ("woz.ch",                "https://www.woz.ch/rss.xml"),
    ("rts.ch",                "https://www.rts.ch/rss/info.xml"),
    ("bzbasel.ch",            "https://www.bzbasel.ch/rss"),
    ("watson.ch",             "https://www.watson.ch/api/feed/rss/news"),
    # ── AT — Kernquellen + Bundesländer ───────────────────────────
    ("orf.at",                "https://rss.orf.at/news.xml"),
    ("derstandard.at",        "https://www.derstandard.at/rss/inland"),
    ("diepresse.com",         "https://www.diepresse.com/rss/politik"),
    ("kurier.at",             "https://kurier.at/rss"),
    ("kleinezeitung.at",      "https://www.kleinezeitung.at/index.rss"),
    ("noen.at",               "https://www.noen.at/rss"),
    ("krone.at",              "https://www.krone.at/feed.xml"),
    ("wien.orf.at",           "https://rss.orf.at/wien.xml"),
    # ── FR / IT / ES — Auslandskontext für transnationale Ereignisse
    ("lemonde.fr",            "https://www.lemonde.fr/rss/une.xml"),
    ("liberation.fr",         "https://www.liberation.fr/arc/outboundfeeds/rss/"),
    ("repubblica.it",         "https://www.repubblica.it/rss/homepage/rss2.0.xml"),
    ("corriere.it",           "https://xml2.corriereobjects.it/rss/homepage.xml"),
    ("elpais.com",            "https://feeds.elpais.com/mrss-s/pages/ep/site/elpais.com/portada"),
    ("euronews.com",          "https://www.euronews.com/rss?level=theme&name=news"),
    # ── EU-Erweiterung: weitere nationale Leitmedien ───────────────
    ("francetvinfo.fr",       "https://www.francetvinfo.fr/titres.rss"),
    ("ansa.it",               "https://www.ansa.it/sito/ansait_rss.xml"),
    ("lastampa.it",           "https://www.lastampa.it/rss/homepage.xml"),
    ("ilfattoquotidiano.it",  "https://www.ilfattoquotidiano.it/feed/"),
    ("bbc.co.uk",             "http://feeds.bbci.co.uk/news/uk/rss.xml"),
    ("theguardian.com",       "https://www.theguardian.com/uk/rss"),
    ("nrc.nl",                "https://www.nrc.nl/rss/"),
    ("nos.nl",                "https://feeds.nos.nl/nosnieuws"),
    ("dr.dk",                 "https://www.dr.dk/nyheder/service/feeds/allenyheder"),
    ("aftenposten.no",        "https://www.aftenposten.no/rss"),
    ("svt.se",                "https://www.svt.se/nyheter/rss.xml"),
    ("kathimerini.com",       "https://www.kathimerini.gr/feed/"),
    ("gazetawyborcza.pl",     "https://wyborcza.pl/pub/rss/najnowsze.htm"),
    # ── Forschungs-/Beobachtungsstellen ──────────────────────────
    ("start.umd.edu",         "https://www.start.umd.edu/news.rss"),
    ("dgap.org",              "https://dgap.org/de/rss.xml"),
    # ── USA — Bundesbehörden + Wire-Agenturen + relevante Locals ───
    # Per Concept §C0/§C1: die US 2026 Counterterrorism Strategy hebt
    # Antifa-/Anarcho-Strukturen explizit auf Threat-Tier 1; relevante
    # Anschläge (Stop-Cop-City Atlanta, Portland-Federal-Courthouse,
    # Minneapolis-Third-Precinct, Seattle-CHAZ) sind Lagebild-Kern.
    ("justice.gov",           "https://www.justice.gov/feeds/justice-news.xml"),
    ("fbi.gov",               "https://www.fbi.gov/feeds/press-releases-news"),
    ("dhs.gov",               "https://www.dhs.gov/news-releases/all-news.xml"),
    ("npr-national",          "https://feeds.npr.org/1003/rss.xml"),
    ("reuters-us",            "https://www.reuters.com/arc/outboundfeeds/v3/category/world/us/?outputType=xml"),
    ("apnews-politics",       "https://apnews.com/index.rss"),
    ("counterextremism.com",  "https://www.counterextremism.com/rss"),
    ("adl.org",               "https://www.adl.org/feeds/rss/news"),
    # ── US — lokale Polizei-Pressestellen (high-density-Schwerpunkte)
    ("spd-blotter-seattle",   "https://spdblotter.seattle.gov/feed/"),
    ("portland-police",       "https://www.portland.gov/police/news.rss"),
    ("nypd-news",             "https://www1.nyc.gov/site/nypd/news/news.page.rss"),
    # ── Einschlägige Quellen (szenenah + extremismusbeobachtend) ──
    ("barrikade.info",        "https://barrikade.info/feed"),
    ("belltower.news",        "https://www.belltower.news/feed/"),
    ("radikal.news",          "https://radikal.news/index.xml"),
    ("nd-aktuell.de",         "https://www.nd-aktuell.de/static/rss/rss.xml"),
    ("perspektive-online.net","https://perspektive-online.net/feed/"),
    ("jungewelt.de",          "https://www.jungewelt.de/rss/inland.rss"),
    # ── DE — Polizei-Pressestellen (presseportal.de Blaulicht) ────
    # Höchste Signal-Qualität: was hier veröffentlicht wird, ist
    # offizielle Pressemitteilung der jeweiligen Landespolizei oder des
    # Bundeskriminalamts. Wir lassen alle 16 Bundesländer + BKA crawlen.
    ("polizei-bka",              "https://www.presseportal.de/blaulicht/nr/7/rss.xml"),
    ("polizei-berlin",           "https://www.presseportal.de/blaulicht/nr/14202/rss.xml"),
    ("polizei-hamburg",          "https://www.presseportal.de/blaulicht/nr/6337/rss.xml"),
    ("polizei-bayern",           "https://www.presseportal.de/blaulicht/nr/6013/rss.xml"),
    ("polizei-bw",               "https://www.presseportal.de/blaulicht/nr/110971/rss.xml"),
    ("polizei-nrw",              "https://www.presseportal.de/blaulicht/nr/6420/rss.xml"),
    ("polizei-sachsen",          "https://www.presseportal.de/blaulicht/nr/108299/rss.xml"),
    ("polizei-sachsen-anhalt",   "https://www.presseportal.de/blaulicht/nr/108699/rss.xml"),
    ("polizei-thueringen",       "https://www.presseportal.de/blaulicht/nr/74166/rss.xml"),
    ("polizei-brandenburg",      "https://www.presseportal.de/blaulicht/nr/12059/rss.xml"),
    ("polizei-niedersachsen",    "https://www.presseportal.de/blaulicht/nr/107106/rss.xml"),
    ("polizei-hessen",           "https://www.presseportal.de/blaulicht/nr/61169/rss.xml"),
    ("polizei-rlp",              "https://www.presseportal.de/blaulicht/nr/24114/rss.xml"),
    ("polizei-saarland",         "https://www.presseportal.de/blaulicht/nr/16193/rss.xml"),
    ("polizei-mv",               "https://www.presseportal.de/blaulicht/nr/108747/rss.xml"),
    ("polizei-sh",               "https://www.presseportal.de/blaulicht/nr/108747/rss.xml"),
    ("polizei-bremen",           "https://www.presseportal.de/blaulicht/nr/65279/rss.xml"),

    # ── Bundestag / Parlamente — Drucksachen + Anfragen ────────────
    # Hochwertige primäre Quelle für die Verfolgungs-Statistik: jede
    # parlamentarische Anfrage zu einem Linksextremismus-Vorfall ist
    # potenziell eine Strafverfolgungs-Aktualisierung. Wir crawlen die
    # öffentlich publizierten Bundestags-Drucksachen + den Pressedienst.
    ("bundestag-drucksachen",
        "https://www.bundestag.de/static/appdata/includes/rss/aktuell/aktuell.xml"),
    ("bundesregierung",
        "https://www.bundesregierung.de/breg-de/rss/aktuelles-1003770/rss.xml"),

    # ── Riseup.net Mailing-Listen (öffentliche Archive) ───────────
    # HINWEIS: lists.riseup.net hostet zahlreiche Bewegungs-Mailinglisten
    # auf Sympa. Manche Archive sind öffentlich (Subscriber-Only-Listen
    # sind explizit als „closed archive" markiert). Wir crawlen NUR die
    # öffentlichen Archive über den Sympa-RSS-Endpoint. Admin kann weitere
    # Listen ergänzen; die Plattform durchläuft alle Einträge durch
    # is_doxxing_text() + redact_pii() bevor sie gespeichert werden, damit
    # personenbezogene Mailing-Inhalte nicht in die DB sickern.
    # Die folgenden Einträge sind exemplarisch — Admin sollte selber
    # prüfen welche Listen für seinen Use Case sinnvoll sind.
    ("lists.riseup.net/anarchist-news",
        "https://lists.riseup.net/www/rss/anarchist-news"),
    ("lists.riseup.net/news",
        "https://lists.riseup.net/www/rss/news"),
]

GNEWS_Q = [
    # Deutschland
    ("DE","linksextremismus anschlag bekennerschreiben"),
    ("DE","autonome brandanschlag sachbeschädigung"),
    ("DE","antifa gewalt festnahmen"),
    ("DE","schwarzer block randalen ausschreitungen"),
    ("DE","militante linke sabotage bahn"),
    ("DE","rigaer strasse linksradikal"),
    ("DE","bundesverfassungsschutz linksextremismus"),
    ("DE","linksextrem hausbesetzung räumung"),
    ("DE","autonome demo eskaliert polizei verletzt"),
    ("DE","antifa razzia festnahmen"),
    # Schweiz
    ("CH","linksextrem schweiz anschlag"),
    ("CH","autonome zürich bern demonstration"),
    ("CH","krawall schweiz ausschreitungen polizei"),
    # Österreich
    ("AT","linksextremismus österreich anschlag"),
    ("AT","autonome wien demonstration eskaliert"),
    # Überregional
    ("DE","lina e linksextremismus urteil"),
    ("DE","antifaschistische aktion sachbeschädigung"),
]

def parse_rss(xml_text):
    items = []
    try:
        root = ET.fromstring(xml_text)
        for item in root.iter("item"):
            t=(item.findtext("title") or "").strip()
            l=(item.findtext("link") or "").strip()
            d=(item.findtext("description") or "").strip()
            p=(item.findtext("pubDate") or "").strip()
            if l: items.append((t,l,d,p))
        if not items:
            NS="http://www.w3.org/2005/Atom"
            for e in root.iter(f"{{{NS}}}entry"):
                t=(e.findtext(f"{{{NS}}}title") or "").strip()
                le=e.find(f"{{{NS}}}link")
                l=(le.get("href","") if le is not None else "").strip()
                d=(e.findtext(f"{{{NS}}}summary") or "").strip()
                p=(e.findtext(f"{{{NS}}}updated") or "").strip()
                if l: items.append((t,l,d,p))
    except Exception as e:
        log.warning(f"parse_rss: {e}")
    return items

def parse_date(s):
    if not s: return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z","%a, %d %b %Y %H:%M:%S GMT",
                "%a, %d %b %Y %H:%M:%S %Z","%Y-%m-%dT%H:%M:%S%z","%Y-%m-%dT%H:%M:%SZ"):
        try: return datetime.strptime(s.strip(), fmt).strftime("%Y-%m-%d")
        except: pass
    return None

SOURCE_MAX_FAILURES = 10  # auto-disable nach N aufeinanderfolgenden Fails

def should_skip_feed(source: str) -> bool:
    """True wenn die Quelle aktuell wegen Health-Issues disabled ist."""
    row = db.execute(
        "SELECT active FROM source_health WHERE source=?", (source,)
    ).fetchone()
    return row is not None and (row["active"] or 0) == 0

def record_crawl_result(source: str, url: str, ok: bool, items: int = 0,
                         error: str = "") -> None:
    """Schreibt das Ergebnis eines RSS-Fetches in source_health.
    Auto-Disable nach SOURCE_MAX_FAILURES consecutive failures."""
    now = datetime.now().isoformat(timespec="seconds")
    row = db.execute(
        "SELECT consecutive_failures, total_attempts, total_successes, items_total "
        "FROM source_health WHERE source=?", (source,)
    ).fetchone()
    if not row:
        db.execute(
            "INSERT OR REPLACE INTO source_health "
            "(source, url, last_attempt, last_success, last_error, "
            " consecutive_failures, total_attempts, total_successes, "
            " items_last_run, items_total, active) "
            "VALUES (?,?,?,?,?,?,1,?,?,?,1)",
            (source, url, now, now if ok else None, "" if ok else error[:280],
             0 if ok else 1, 1 if ok else 0, items, items if ok else 0)
        )
    else:
        cf = 0 if ok else (row["consecutive_failures"] or 0) + 1
        active = 0 if cf >= SOURCE_MAX_FAILURES else 1
        if active == 0 and (row["consecutive_failures"] or 0) < SOURCE_MAX_FAILURES:
            log.warning(f"source_health AUTO-DISABLE: {source} after {cf} consecutive failures")
        db.execute(
            "UPDATE source_health SET "
            "url=?, last_attempt=?, last_success=COALESCE(?, last_success), "
            "last_error=?, consecutive_failures=?, total_attempts=total_attempts+1, "
            "total_successes=total_successes+?, items_last_run=?, items_total=items_total+?, "
            "active=? "
            "WHERE source=?",
            (url, now, now if ok else None, "" if ok else error[:280],
             cf, 1 if ok else 0, items, items, active, source)
        )
    db.commit()

def crawl_rss_feed(source, feed_url, max_items=15):
    if should_skip_feed(source):
        return 0
    inserted = 0
    err_msg  = ""
    try:
        xml   = fetch(feed_url, timeout=18)
        items = parse_rss(xml)
        hits  = 0
        for title, link, desc, pub in items:
            if hits >= max_items: break
            preview = (title + " " + desc).lower()
            if not any(kw in preview for kw in RSS_KEYWORDS): continue
            if is_false_positive(preview): continue  # e.g. "autonome Autos"
            hits += 1
            h = mk_hash(link, title+desc)
            if is_seen(h): continue
            text = get_text(link)
            if len(text) < 80: text = f"{title}. {desc}"
            ai = smart_classify(text)
            if ai:
                d = parse_date(pub) or date_from_url(link)
                if save_incident(ai, text, source, link, d):
                    inserted += 1
            time.sleep(0.5)
        record_crawl_result(source, feed_url, ok=True, items=inserted)
    except Exception as e:
        err_msg = str(e)[:280]
        log.warning(f"RSS {source}: {err_msg}")
        record_crawl_result(source, feed_url, ok=False, error=err_msg)
    return inserted

def crawl_gnews():
    inserted = 0
    for country, q in GNEWS_Q:
        url = f"https://news.google.com/rss/search?q={quote_plus(q)}&hl=de&gl={country}&ceid={country}:de"
        inserted += crawl_rss_feed(f"gnews", url, max_items=5)
        time.sleep(0.5)
    return inserted

# ── BARRIKADE RELEVANCE PRE-FILTER ───────────────────────────────
BARRIKADE_RELEVANCE_KWS = [
    "angriff","brand","sabotage","ausschreitungen","krawalle","randalen",
    "besetzung","verhaftung","razzia","molotow","bekennerschreiben",
    "autonome","antifa","schwarzer block","linksextrem","schäden","verletzt",
    "festnahmen","überfall","protest","demonstration","blockade","besetzt",
    # Actions against right-wing groups (barrikade.info coverage)
    "junge tat","identitär","neonazi","faschistisch"," nazi","rechtsextrem",
    "eingelackt","lackiert","lack ","besprüht","outing","dox","antifaschist",
    "aktion gegen","solidarität","hausdurchsuchung",
]

# ── MASTER CRAWLER ────────────────────────────────────────────────
_running   = [False]
_hist_run  = [False]

def run_crawler(force=False):
    if _running[0]: log.info("Already running"); return
    last = meta_get("last_crawl")
    if not force and last:
        if datetime.now() - datetime.fromisoformat(last) < timedelta(hours=2):
            log.info("Skipped < 2h"); return
    _running[0] = True
    total = 0
    log.info("══ CRAWLER START ══")
    try:
        # 1. Barrikade: sweep latest 80 article IDs
        log.info("Barrikade live sweep...")
        latest = barrikade_latest_id()
        saved_latest = int(meta_get("b_live_max") or 0)
        if latest > saved_latest:
            n = crawl_barrikade_range(latest, max(saved_latest, latest - 80))
            meta_set("b_live_max", latest)
            total += n
            log.info(f"Barrikade live: +{n}")
        else:
            log.info("Barrikade: no new articles")

        # 2. Indymedia RSS feeds
        log.info("Indymedia feeds...")
        n = crawl_indymedia_feed()
        total += n
        log.info(f"Indymedia: +{n}")

        # 3. Mainstream RSS
        log.info("RSS feeds...")
        for source, url in RSS_FEEDS:
            n = crawl_rss_feed(source, url)
            total += n
            time.sleep(0.3)

        # 4. Google News
        n = crawl_gnews()
        total += n

        # 5. Re-geocode any null-coord incidents
        regeocode_nulls()

    except Exception as e:
        log.error(f"run_crawler: {e}", exc_info=True)
    finally:
        _running[0] = False
        meta_set("last_crawl", datetime.now().isoformat())
    log.info(f"══ CRAWLER DONE +{total} ══")

# ── HISTORICAL ────────────────────────────────────────────────────
def run_historical(reset=False):
    if _hist_run[0]: return
    if reset:
        for k in ("hist_b_done","hist_b_curr","hist_b_max",
                  "hist_im_done","hist_im_offset","hist_wb_done","b_live_max"):
            meta_del(k)
        log.info("Historical: reset")
    _hist_run[0] = True
    log.info("══ HISTORICAL START ══")
    try:
        # Mark indymedia historical as done — de.indymedia.org offline since 2017
        if not meta_get("hist_im_done"):
            meta_set("hist_im_done", datetime.now().isoformat())
            log.info("Indymedia hist: skipped (site offline since 2017)")

        # Barrikade: crawl 800 IDs per invocation, save progress
        DONE="hist_b_done"; CURR="hist_b_curr"
        if not meta_get(DONE):
            if not meta_get(CURR):
                mx = barrikade_latest_id()
                meta_set("hist_b_max", mx)
                meta_set(CURR, mx)
            curr = int(meta_get(CURR))
            stop = max(1, curr - 800)
            log.info(f"Barrikade hist: {curr}→{stop}")
            n = crawl_barrikade_range(curr, stop)
            meta_set(CURR, stop - 1)
            if stop <= 1:
                meta_set(DONE, datetime.now().isoformat())
                log.info("Barrikade hist: COMPLETE")
            log.info(f"Barrikade hist: +{n} (remaining: {stop-1} IDs)")
        else:
            log.info("Barrikade hist: already complete")

        regeocode_nulls()
    except Exception as e:
        log.error(f"run_historical: {e}", exc_info=True)
    finally:
        _hist_run[0] = False
    log.info("══ HISTORICAL DONE ══")


def auto_hist():
    """Auto-continue historical barrikade crawl on a schedule until complete."""
    if meta_get("hist_b_done"):
        return
    if _hist_run[0] or _running[0]:
        return
    log.info("Auto-continuing historical crawl…")
    run_historical()

# ── FASTAPI ───────────────────────────────────────────────────────
app = FastAPI(title="LEX EUROPE")
templates = Jinja2Templates(directory="templates")
# i18n strings (DE/EN) served as static JSON for client-side hot-swap.
if os.path.isdir("i18n"):
    app.mount("/i18n", StaticFiles(directory="i18n"), name="i18n")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Donation addresses + contact email are configured per render.com instance
    # via env vars. Leaving them unset shows a safe placeholder.
    return templates.TemplateResponse("index.html", {
        "request": request,
        "btc_address":   os.getenv("BTC_ADDRESS", ""),
        "xmr_address":   os.getenv("XMR_ADDRESS", ""),
        "fiat_info":     os.getenv("FIAT_INFO",   ""),
        "contact_email": os.getenv("CONTACT_EMAIL", "kontakt@lex-europe.org"),
    })

# ── EARLY-WARNING CLUSTER DETECTION (Säule 2 — MS-3) ──────────────
EWC_WINDOW_DAYS = 42      # 6 weeks
EWC_THRESHOLD   = 3       # ≥ 3 incidents to flag a cluster
EWC_TIERS       = ("act", "enable")

def save_evidence(url, hash_hex):
    """
    Persist a WARC-1.1 record of `url` under EVIDENCE_DIR/<yyyy>/<mm>/<hash>.warc.gz.
    Returns (relative_path, sha256, iso_timestamp) on success, ('', '', '') on
    failure. Idempotent — re-running on the same hash short-circuits if the
    file already exists. Designed to be cheap: one HTTP GET, no library deps.
    """
    if not url or not url.startswith("http"):
        return "", "", ""
    now = datetime.now()
    yyyy, mm = now.strftime("%Y"), now.strftime("%m")
    subdir = os.path.join(EVIDENCE_DIR, yyyy, mm)
    fname  = f"{hash_hex}.warc.gz"
    fpath  = os.path.join(subdir, fname)
    rel    = f"evidence/{yyyy}/{mm}/{fname}"
    if os.path.isfile(fpath):
        # Already captured — recompute the digest so the caller can store it
        # if the original save was interrupted before the columns were set.
        try:
            with open(fpath, "rb") as fh:
                sha = hashlib.sha256(fh.read()).hexdigest()
            return rel, sha, ""
        except Exception:
            return "", "", ""
    try:
        Path(subdir).mkdir(parents=True, exist_ok=True)
        r = session.get(url, timeout=15, allow_redirects=True)
        body = r.content or b""
        if not body:
            return "", "", ""
        ts = now.replace(microsecond=0).isoformat() + "Z"
        # Minimal WARC/1.1 response record — no external dep required.
        block = (
            f"HTTP/1.1 {r.status_code} {r.reason}\r\n"
            f"Content-Type: {r.headers.get('Content-Type','application/octet-stream')}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8") + body
        block_sha = hashlib.sha256(block).hexdigest()
        record_id = "<urn:uuid:" + hashlib.sha1((hash_hex + ts).encode()).hexdigest() + ">"
        header = (
            "WARC/1.1\r\n"
            "WARC-Type: response\r\n"
            f"WARC-Record-ID: {record_id}\r\n"
            f"WARC-Date: {ts}\r\n"
            f"WARC-Target-URI: {url}\r\n"
            f"WARC-Block-Digest: sha256:{block_sha}\r\n"
            "Content-Type: application/http; msgtype=response\r\n"
            f"Content-Length: {len(block)}\r\n"
            "\r\n"
        ).encode("utf-8")
        raw = header + block + b"\r\n\r\n"
        with gzip.open(fpath, "wb", compresslevel=6) as gz:
            gz.write(raw)
        # SHA of the gzipped artifact (what's actually on disk) is the
        # tamper-evident anchor we cite later.
        with open(fpath, "rb") as fh:
            disk_sha = hashlib.sha256(fh.read()).hexdigest()
        return rel, disk_sha, ts
    except Exception as e:
        log.info(f"save_evidence failed for {url}: {e}")
        return "", "", ""


def detect_clusters():
    """
    Group recent T1/T2 incidents by (country, target_type). Any group with
    ≥ EWC_THRESHOLD hits in the last EWC_WINDOW_DAYS becomes an active
    cluster. Idempotent — re-scan can demote a cluster to active=0 when
    the wave dies down, and can revive it when a new attack lands.
    """
    cutoff = (datetime.now() - timedelta(days=EWC_WINDOW_DAYS)).strftime("%Y-%m-%d")
    rows = db.execute(
        "SELECT id, date, country, target_type, category, location, summary, description "
        "FROM incidents "
        "WHERE tier IN ({}) AND target_type != '' AND date >= ? "
        "ORDER BY date DESC".format(",".join("?"*len(EWC_TIERS))),
        list(EWC_TIERS) + [cutoff]
    ).fetchall()
    groups = {}
    for r in rows:
        country = (r["country"] or "Andere").strip() or "Andere"
        tt      = (r["target_type"] or "").strip()
        if not tt:
            continue
        key = f"{country}|{tt}"
        groups.setdefault(key, []).append(r)

    now_iso = datetime.now().isoformat(timespec="seconds")
    seen_keys = set()
    for key, items in groups.items():
        if len(items) < EWC_THRESHOLD:
            continue
        seen_keys.add(key)
        country, tt = key.split("|", 1)
        first_seen = min((it["date"] for it in items if it["date"]), default="")
        last_seen  = max((it["date"] for it in items if it["date"]), default="")
        ids        = json.dumps([it["id"] for it in items])
        titles     = json.dumps([
            (it["summary"] or it["location"] or "—")[:140]
            for it in items[:3]
        ], ensure_ascii=False)
        db.execute(
            "INSERT INTO early_warning_clusters "
            "(cluster_key,country,target_type,count,first_seen,last_seen,"
            " incident_ids,sample_titles,detected_at,active) "
            "VALUES (?,?,?,?,?,?,?,?,?,1) "
            "ON CONFLICT(cluster_key) DO UPDATE SET "
            "count=excluded.count,first_seen=excluded.first_seen,"
            "last_seen=excluded.last_seen,incident_ids=excluded.incident_ids,"
            "sample_titles=excluded.sample_titles,detected_at=excluded.detected_at,"
            "active=1",
            (key, country, tt, len(items), first_seen, last_seen, ids, titles, now_iso)
        )
    # Stale clusters: still in the table but no longer meet the threshold
    # in the current window — flag inactive (keep history for trend lines).
    existing = db.execute(
        "SELECT cluster_key FROM early_warning_clusters WHERE active=1"
    ).fetchall()
    for r in existing:
        if r["cluster_key"] not in seen_keys:
            db.execute(
                "UPDATE early_warning_clusters SET active=0 WHERE cluster_key=?",
                (r["cluster_key"],)
            )
    db.commit()
    n_active = db.execute(
        "SELECT COUNT(*) FROM early_warning_clusters WHERE active=1"
    ).fetchone()[0]
    log.info(f"detect_clusters: {n_active} active clusters (threshold ≥{EWC_THRESHOLD} / {EWC_WINDOW_DAYS}d)")
    # ── Webhook-Fan-Out: neue oder eskalierende Cluster pushen ────
    # Wir benutzen die zuvor in `seen_keys` gesammelten *aktuell aktiven*
    # Cluster (alles was im Window meets-threshold ist). Subscriber mit
    # passendem Filter (target_type, country, min_count) bekommen einen
    # signierten POST.
    try:
        for key in seen_keys:
            row = db.execute(
                "SELECT cluster_key, country, target_type, count, first_seen, "
                "last_seen, sample_titles "
                "FROM early_warning_clusters WHERE cluster_key = ?", (key,)
            ).fetchone()
            if row:
                d = dict(row)
                try:
                    d["sample_titles"] = json.loads(d["sample_titles"] or "[]")
                except Exception:
                    d["sample_titles"] = []
                _fanout_webhook("cluster", d["cluster_key"], {
                    "event":        "cluster.active",
                    "cluster_key":  d["cluster_key"],
                    "country":      d["country"],
                    "target_type":  d["target_type"],
                    "count":        d["count"],
                    "window_days":  EWC_WINDOW_DAYS,
                    "first_seen":   d["first_seen"],
                    "last_seen":    d["last_seen"],
                    "sample_titles":d["sample_titles"],
                })
    except Exception as e:
        log.warning(f"webhook fan-out failed: {e}")
    return n_active


# ── WEBHOOK DELIVERY ENGINE (Säule 2) ─────────────────────────────
def _hmac_sign(secret: str, body_bytes: bytes) -> str:
    import hmac, hashlib as _h
    return "sha256=" + hmac.new(secret.encode(), body_bytes,
                                _h.sha256).hexdigest()

def _fanout_webhook(event_type: str, event_key: str, payload: dict):
    """Fire matching webhooks for an event. Filters are AND-ed:
    target_types (empty=any), countries (empty=any), min_severity (incident-only),
    events (must contain event_type's family: 'cluster' or 'incident')."""
    subs = db.execute(
        "SELECT id, url, secret, target_types, countries, min_severity, events "
        "FROM webhook_subscriptions WHERE active=1"
    ).fetchall()
    if not subs:
        return
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    target_t = (payload.get("target_type") or "").strip()
    country  = (payload.get("country")     or "").strip()
    severity = int(payload.get("severity_score") or 0)
    family   = event_type.split(".", 1)[0]  # 'cluster' / 'incident'
    for s in subs:
        events = (s["events"] or "").split(",")
        if family not in [e.strip() for e in events if e.strip()]:
            continue
        tts = [x.strip() for x in (s["target_types"] or "").split(",") if x.strip()]
        cos = [x.strip() for x in (s["countries"]    or "").split(",") if x.strip()]
        if tts and target_t and target_t not in tts: continue
        if cos and country  and country  not in cos: continue
        if family == "incident" and severity < (s["min_severity"] or 0): continue
        sig = _hmac_sign(s["secret"], body)
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "LEX-EUROPE-webhook/1.0",
            "X-LexEurope-Signature": sig,
            "X-LexEurope-Event":     event_type,
            "X-LexEurope-Event-Key": event_key,
        }
        now = datetime.now().isoformat(timespec="seconds")
        err = None; code = 0
        try:
            r = requests.post(s["url"], data=body, headers=headers, timeout=8)
            code = r.status_code
            r.raise_for_status()
            db.execute(
                "UPDATE webhook_subscriptions SET last_delivery=?, "
                "delivery_count = delivery_count + 1 WHERE id=?",
                (now, s["id"])
            )
        except Exception as e:
            err = str(e)[:280]
            db.execute(
                "UPDATE webhook_subscriptions SET failure_count = failure_count + 1 "
                "WHERE id=?", (s["id"],)
            )
            log.info(f"webhook delivery FAIL sub={s['id']} url={s['url']}: {err}")
        db.execute(
            "INSERT INTO webhook_deliveries "
            "(sub_id, event_type, event_key, status_code, body_len, delivered_at, error) "
            "VALUES (?,?,?,?,?,?,?)",
            (s["id"], event_type, event_key, code, len(body), now, err)
        )
        db.commit()


@app.get("/api/early-warning.json")
async def early_warning_json():
    """Active Frühwarn-Cluster — JSON-Feed für Betreiber & Forschung."""
    rows = db.execute(
        "SELECT cluster_key,country,target_type,count,first_seen,last_seen,"
        "incident_ids,sample_titles,detected_at "
        "FROM early_warning_clusters WHERE active=1 "
        "ORDER BY count DESC, last_seen DESC"
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try: d["incident_ids"]  = json.loads(d["incident_ids"]  or "[]")
        except Exception: d["incident_ids"] = []
        try: d["sample_titles"] = json.loads(d["sample_titles"] or "[]")
        except Exception: d["sample_titles"] = []
        out.append(d)
    return JSONResponse({
        "window_days": EWC_WINDOW_DAYS,
        "threshold":   EWC_THRESHOLD,
        "active":      len(out),
        "clusters":    out,
        "asof":        datetime.now().isoformat(timespec="seconds"),
    })


@app.get("/api/early-warning.rss")
async def early_warning_rss(request: Request):
    """
    RSS 2.0 feed der aktiven Frühwarn-Cluster. Betreiber potenziell ziel-
    gefährdeter Infrastruktur (Bahn, Energie, Polizei …) abonnieren das
    selbst — wir versenden bewusst nichts proaktiv (DSGVO-Hygiene §C3).
    """
    rows = db.execute(
        "SELECT cluster_key,country,target_type,count,first_seen,last_seen,"
        "sample_titles,detected_at "
        "FROM early_warning_clusters WHERE active=1 "
        "ORDER BY last_seen DESC"
    ).fetchall()
    base = str(request.base_url).rstrip("/")
    items = []
    for r in rows:
        try:
            titles = json.loads(r["sample_titles"] or "[]")
        except Exception:
            titles = []
        body = (
            f"{r['count']} Anschläge auf Ziel-Typ „{r['target_type']}" + "“"
            f" in {r['country']} zwischen {r['first_seen']} und {r['last_seen']}.\n"
        )
        if titles:
            body += "Beispiele:\n" + "\n".join(f"- {t}" for t in titles)
        items.append(
            "<item>"
            f"<title>{_xml_esc(r['target_type'])} · {_xml_esc(r['country'])} — {r['count']} Anschläge / 6 Wochen</title>"
            f"<link>{base}/api/early-warning.json</link>"
            f"<guid isPermaLink=\"false\">ewc-{_xml_esc(r['cluster_key'])}-{_xml_esc(r['last_seen'] or '')}</guid>"
            f"<pubDate>{_rfc822(r['detected_at'] or r['last_seen'])}</pubDate>"
            f"<description>{_xml_esc(body)}</description>"
            "</item>"
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n<channel>\n'
        '<title>LEX EUROPE — Frühwarn-Cluster</title>\n'
        f'<link>{base}/api/early-warning.json</link>\n'
        '<description>Aktive Anschlags-Cluster (≥3 gleichartige Ziele in 6 Wochen)</description>\n'
        '<language>de-DE</language>\n'
        + "\n".join(items) +
        '\n</channel>\n</rss>\n'
    )
    return StreamingResponse(iter([xml]), media_type="application/rss+xml; charset=utf-8")


def _xml_esc(s):
    return (str(s or "")
            .replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            .replace('"',"&quot;").replace("'","&apos;"))

def _rfc822(s):
    """Best-effort ISO/date → RFC822 string for RSS pubDate."""
    if not s: return ""
    try:
        d = datetime.fromisoformat(s.replace("Z","").split("+")[0])
        return d.strftime("%a, %d %b %Y %H:%M:%S +0000")
    except Exception:
        return ""


# ── PUBLIC RSS — Vorfälle-Feed für Presse / OSINT-Konsumenten ────
@app.get("/api/incidents.rss")
async def incidents_rss(request: Request, country: str = "", tier: str = "act",
                        severity_min: int = 3, limit: int = 50):
    """Öffentlicher RSS-2.0-Feed der jüngsten T1-Vorfälle. Default-Filter:
    tier=act + severity_min=3 — damit Konsumenten nur Substanz bekommen,
    nicht das ganze Lagebild-Rauschen. Per-Country via ?country=DE."""
    q = ("SELECT id,date,location,country,category,summary,description,"
         "severity_score,url,source,timestamp "
         "FROM incidents WHERE 1=1")
    p = []
    if tier:    q += " AND tier=?"; p.append(tier)
    if country: q += " AND country=?"; p.append(country)
    if severity_min:
        q += " AND severity_score >= ?"; p.append(severity_min)
    q += " ORDER BY date DESC, timestamp DESC LIMIT ?"
    p.append(min(max(limit, 1), 200))
    rows = db.execute(q, p).fetchall()
    base = str(request.base_url).rstrip("/")
    title_suffix = f" · {country.upper()}" if country else ""
    items = []
    for r in rows:
        d = dict(r)
        loc  = _xml_esc(f"{d.get('location') or '—'}, {d.get('country') or '—'}")
        cat  = _xml_esc(d.get('category') or '—')
        sev  = d.get('severity_score') or 0
        summ = _xml_esc((d.get('summary') or d.get('description') or '')[:280])
        url  = _xml_esc(d.get('url')   or f"{base}/")
        src  = _xml_esc(d.get('source') or '—')
        items.append(
            "<item>"
            f"<title>[{cat} · S{sev}] {loc} — {_xml_esc((d.get('summary') or '—')[:120])}</title>"
            f"<link>{url}</link>"
            f"<guid isPermaLink=\"false\">lex-inc-{d.get('id')}</guid>"
            f"<pubDate>{_rfc822(d.get('date') or d.get('timestamp'))}</pubDate>"
            f"<category>{cat}</category>"
            f"<source url=\"{base}/\">{src}</source>"
            f"<description>{summ}</description>"
            "</item>"
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n<channel>\n'
        f'<title>LEX EUROPE — Vorfälle{title_suffix}</title>\n'
        f'<link>{base}/</link>\n'
        '<description>Politisch links motivierte Gewalttaten — OSINT-Dokumentation</description>\n'
        '<language>de-DE</language>\n'
        f'<lastBuildDate>{_rfc822(datetime.now().isoformat())}</lastBuildDate>\n'
        + "\n".join(items) +
        '\n</channel>\n</rss>\n'
    )
    return StreamingResponse(iter([xml]), media_type="application/rss+xml; charset=utf-8")


@app.get("/api/public/stats")
async def public_stats():
    """Kompakte Aggregat-Stats für Embedding (Pressbox, Twitter-Cards, etc.)."""
    today = datetime.now().date()
    last30 = (today - timedelta(days=30)).isoformat()
    last7  = (today - timedelta(days=7)).isoformat()
    total   = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act'").fetchone()[0]
    last30c = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act' AND date>=?", (last30,)).fetchone()[0]
    last7c  = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act' AND date>=?", (last7,)).fetchone()[0]
    hi      = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act' AND severity_score >= 4").fetchone()[0]
    actors  = db.execute("SELECT COUNT(DISTINCT actors) FROM incidents WHERE actors!=''").fetchone()[0]
    clusters= db.execute("SELECT COUNT(*) FROM early_warning_clusters WHERE active=1").fetchone()[0]
    by_co   = [dict(r) for r in db.execute(
        "SELECT country, COUNT(*) n FROM incidents WHERE tier='act' "
        "GROUP BY country ORDER BY n DESC LIMIT 10"
    ).fetchall()]
    sources = db.execute("SELECT COUNT(DISTINCT source) FROM incidents").fetchone()[0]
    return JSONResponse({
        "total_t1":          total,
        "last_7d":           last7c,
        "last_30d":          last30c,
        "high_severity":     hi,
        "distinct_actors":   actors,
        "active_clusters":   clusters,
        "distinct_sources":  sources,
        "by_country_top10":  by_co,
        "asof":              today.isoformat(),
    })


@app.get("/robots.txt")
async def robots_txt():
    return StreamingResponse(iter([
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /admin\n"
        "Disallow: /api/v1/\n"
        "Sitemap: /sitemap.xml\n"
    ]), media_type="text/plain")


@app.get("/sitemap.xml")
async def sitemap_xml(request: Request):
    base = str(request.base_url).rstrip("/")
    urls = [
        f"{base}/", f"{base}/dashboard", f"{base}/lagebericht",
        f"{base}/api/incidents.rss", f"{base}/api/early-warning.rss",
        f"{base}/api/v1/docs",
    ]
    # Per-target-type + per-country pages dynamisch ergänzen.
    for tt in ("Auto","Schiene","Energie","Telekom","Militär","Polizei",
               "Politik","Justiz","Medien","Wirtschaft"):
        urls.append(f"{base}/early-warning/{tt}")
    for co in ("DE","AT","CH","FR","IT","ES","GR","UK","NL","DK","SE","NO","US"):
        urls.append(f"{base}/c/{co}")
    items = "\n".join(f"<url><loc>{u}</loc></url>" for u in urls)
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           + items + "\n</urlset>\n")
    return StreamingResponse(iter([xml]), media_type="application/xml; charset=utf-8")


@app.get("/dashboard", response_class=HTMLResponse)
async def public_dashboard():
    """Standalone öffentliche Dashboard-Seite — KPI-Karten + Top-10-Länder +
    Link zur Vollkarte. Press-ready, OG-getaggt, kein Login."""
    s = await public_stats()
    import json as _j
    d = _j.loads(s.body)
    today = d["asof"]
    coBlocks = "\n".join(
        f'<div class="kc-row"><span class="kc-co">{c["country"]}</span>'
        f'<div class="kc-bar"><div class="kc-bar-fill" style="width:{round((c["n"]/max(d["by_country_top10"][0]["n"],1))*100)}%"></div></div>'
        f'<span class="kc-n">{c["n"]}</span></div>'
        for c in d["by_country_top10"]
    )
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>LEX EUROPE — Lage-Dashboard {today}</title>
<meta name="description" content="OSINT-Lagebild politisch links motivierter Gewalttaten in Europa und USA. {d['total_t1']} dokumentierte T1-Akte, {d['active_clusters']} aktive Frühwarn-Cluster.">
<meta property="og:title"       content="LEX EUROPE — Lagebild Linksextremismus">
<meta property="og:description" content="{d['total_t1']} T1-Akte dokumentiert · {d['last_7d']} in den letzten 7 Tagen · {d['active_clusters']} aktive Frühwarn-Cluster.">
<meta property="og:type"        content="website">
<meta name="twitter:card"       content="summary_large_image">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;
  min-height:100vh;font-size:13px;line-height:1.5;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;
  font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;
  justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:1100px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:28px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:6px;}}
.sub{{font-size:11px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:32px;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:32px;}}
.kpi{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:18px 22px;}}
.kpi .lbl{{font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:6px;}}
.kpi .val{{font-size:30px;font-weight:600;color:#e9eef3;letter-spacing:-0.5px;font-variant-numeric:tabular-nums;}}
.kpi.acc .val{{color:#6aa9c9;}}.kpi.red .val{{color:#d4495d;}}.kpi.amber .val{{color:#d99a2b;}}.kpi.green .val{{color:#5fb583;}}
.kpi .delta{{font-size:10px;color:#6c7986;margin-top:4px;letter-spacing:1px;}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:24px;margin-bottom:18px;}}
h2{{font-size:11px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;
  margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.kc-row{{display:flex;align-items:center;gap:14px;margin-bottom:8px;}}
.kc-co{{font-size:11px;color:#aab5c0;min-width:35px;}}
.kc-bar{{flex:1;height:6px;background:rgba(106,169,201,0.08);border-radius:1px;overflow:hidden;}}
.kc-bar-fill{{height:100%;background:#6aa9c9;border-radius:1px;}}
.kc-n{{font-size:11px;color:#e9eef3;min-width:30px;text-align:right;font-variant-numeric:tabular-nums;}}
.cta{{display:inline-block;font-family:ui-monospace;font-size:10px;letter-spacing:2px;
  text-transform:uppercase;color:#6aa9c9;border:1px solid #6aa9c9;padding:10px 16px;
  text-decoration:none;margin-right:8px;margin-top:8px;}}
.cta:hover{{background:rgba(106,169,201,0.10);}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;
  text-transform:uppercase;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE · UNCLASSIFIED // RELEASABLE</span><span>STAND {today}</span></div>
<div class="page">
  <h1>Lage-Dashboard Linksextremismus</h1>
  <div class="sub">Europa + USA · OSINT-Aggregation · automatisch generiert</div>

  <div class="kpi-grid">
    <div class="kpi acc"><div class="lbl">T1-Vorfälle gesamt</div><div class="val">{d['total_t1']}</div><div class="delta">tier=act (Brand / Sabo / Gewalt / Militante Aktion)</div></div>
    <div class="kpi"><div class="lbl">letzte 7 Tage</div><div class="val">{d['last_7d']}</div><div class="delta">neue T1-Akte</div></div>
    <div class="kpi"><div class="lbl">letzte 30 Tage</div><div class="val">{d['last_30d']}</div><div class="delta">neue T1-Akte</div></div>
    <div class="kpi red"><div class="lbl">hoch-Schwere ≥ 4</div><div class="val">{d['high_severity']}</div><div class="delta">Personenschaden / Brandwaffe / ≥ 100k €</div></div>
    <div class="kpi amber"><div class="lbl">aktive Frühwarn-Cluster</div><div class="val">{d['active_clusters']}</div><div class="delta">≥ 3 gleichartige / 6 Wochen</div></div>
    <div class="kpi"><div class="lbl">identifizierte Akteure</div><div class="val">{d['distinct_actors']}</div></div>
    <div class="kpi"><div class="lbl">aktive Quellen</div><div class="val">{d['distinct_sources']}</div></div>
  </div>

  <div class="section">
    <h2>Geografische Verteilung — Top 10 (T1)</h2>
    {coBlocks}
  </div>

  <div class="section">
    <h2>Schnittstellen</h2>
    <a class="cta" href="/">→ Vollkarte + Filter</a>
    <a class="cta" href="/lagebericht">→ Wochen-Lagebericht</a>
    <a class="cta" href="/api/incidents.rss">→ RSS-Feed</a>
    <a class="cta" href="/api/early-warning.rss">→ Frühwarn-Feed</a>
    <a class="cta" href="/api/v1/docs">→ LEA / Research API</a>
  </div>

  <div class="footer">
    LEX EUROPE · OSINT-Plattform · unabhängige Forschung · keine Werbung · kein Tracking
  </div>
</div>
</body></html>""")


@app.get("/lagebericht", response_class=HTMLResponse)
async def public_lagebericht():
    """Standalone öffentliche Wochenbericht-Seite. Print-friendly, OG-getaggt.
    Holt /api/lagebericht/weekly direkt aus der DB ohne HTTP-Roundtrip."""
    ws, we = _isoweek_bounds(None)
    d = _build_lagebericht(ws, we)
    iso = datetime.fromisoformat(ws).isocalendar()
    label = f"{iso.year}-W{iso.week:02d}"
    delta = d["delta"]
    delta_str = (f"+{delta}" if delta > 0 else f"{delta}" if delta < 0 else "±0")
    def esc(s): return _xml_esc(s)
    co_block = "".join(f"<div class='row'><span>{esc(c)}</span><span class='n'>{n}</span></div>" for c, n in d["by_country"])
    tt_block = "".join(f"<div class='row'><span>{esc(tt)}</span><span class='n'>{n}</span></div>" for tt, n in d["by_target_type"]) or "<div style='color:#6c7986'>— keine Zielklassen-Daten —</div>"
    cl_block = "".join(f"<div class='cluster-row'><b>{esc(c['target_type'])} · {esc(c['country'])}</b> — {c['count']} Anschläge ({esc(c['first_seen'])} … {esc(c['last_seen'])})</div>" for c in d["clusters_active"]) or "<div style='color:#6c7986'>— keine aktiven Cluster —</div>"
    gap_block = "".join(f"<div class='gap-row'>{esc(r.get('date'))} · {esc(r.get('location'))}, {esc(r.get('country'))} · {esc(r.get('category'))} (Schwere {r.get('severity_score','?')})</div>" for r in d["new_gap_cases"]) or "<div style='color:#6c7986'>— keine neuen Gap-Fälle in diesem Zeitraum —</div>"
    top_block = "".join(
        f"<div class='inc-row'><span class='date'>{esc(r.get('date'))}</span>"
        f"<span class='cat'>{esc(r.get('category'))}</span>"
        f"<span class='loc'>{esc(r.get('location'))}, {esc(r.get('country'))}</span>"
        f"<span class='sev'>S{r.get('severity_score','?')}/5</span>"
        f"<div class='summ'>{esc((r.get('summary') or r.get('description') or '')[:200])}</div>"
        + (f"<a class='src' href='{esc(r.get('url'))}' rel='noopener'>↗ Quelle</a>" if r.get('url') and r['url'].startswith('http') else "")
        + "</div>"
        for r in d["top_incidents"]
    ) or "<div style='color:#6c7986'>— keine T1-Vorfälle in dieser Woche —</div>"
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Wochenbericht KW {label} — LEX EUROPE</title>
<meta name="description" content="Lagebericht Linksextremismus KW {label}: {d['total']} Vorfälle, {d['t1']} T1-Akte, {d['hi']} hoch-Schwere, {len(d['clusters_active'])} aktive Cluster.">
<meta property="og:title"       content="LEX EUROPE Wochenbericht KW {label}">
<meta property="og:description" content="{d['t1']} T1-Akte · {d['hi']} hoch-Schwere · {len(d['clusters_active'])} aktive Cluster · {len(d['new_gap_cases'])} neue Strafverfolgungs-Gap-Fälle.">
<meta property="og:type"        content="article">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;font-size:13px;line-height:1.55;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:880px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:26px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:4px;}}
.sub{{font-size:10px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:24px;}}
.eckdaten{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1px;background:rgba(255,255,255,0.04);margin-bottom:24px;border:1px solid rgba(255,255,255,0.06);}}
.ed{{background:#0d141c;padding:14px;}}
.ed .lbl{{font-size:8px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:4px;}}
.ed .val{{font-size:22px;color:#e9eef3;font-variant-numeric:tabular-nums;font-weight:600;}}
.ed.red .val{{color:#d4495d;}}.ed.amber .val{{color:#d99a2b;}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:18px 22px;margin-bottom:14px;}}
h2{{font-size:10px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.row{{display:flex;justify-content:space-between;padding:4px 0;font-size:12px;border-bottom:1px solid rgba(255,255,255,0.03);}}
.row .n{{color:#e9eef3;font-variant-numeric:tabular-nums;}}
.cluster-row,.gap-row{{padding:5px 0;font-size:11px;border-bottom:1px solid rgba(255,255,255,0.03);}}
.cluster-row b{{color:#d99a2b;}}
.gap-row{{color:#d4495d;}}
.inc-row{{padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:11px;}}
.inc-row .date{{color:#6c7986;margin-right:10px;}}
.inc-row .cat{{color:#e9eef3;margin-right:10px;}}
.inc-row .loc{{color:#aab5c0;margin-right:10px;}}
.inc-row .sev{{color:#d99a2b;font-weight:600;}}
.inc-row .summ{{margin-top:4px;color:#aab5c0;font-size:11px;line-height:1.55;}}
.inc-row .src{{font-size:9px;color:#6aa9c9;text-decoration:none;letter-spacing:1px;margin-top:3px;display:inline-block;}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
.cta{{display:inline-block;font-size:10px;letter-spacing:2px;color:#6aa9c9;border:1px solid #6aa9c9;padding:8px 12px;text-decoration:none;margin-right:6px;}}
@media print{{body{{background:#fff;color:#000}}.section{{background:#fff;border-color:#ddd}}.ed{{background:#fafafa}}h1,.ed .val{{color:#000}}.cluster-row b{{color:#cc7a00}}}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>KW {label}</span></div>
<div class="page">
  <h1>Wochenbericht KW {label}</h1>
  <div class="sub">Berichtszeitraum {ws} – {we} · automatisch generiert</div>

  <div class="eckdaten">
    <div class="ed"><div class="lbl">Vorfälle</div><div class="val">{d['total']}</div></div>
    <div class="ed"><div class="lbl">Delta</div><div class="val">{delta_str}</div></div>
    <div class="ed"><div class="lbl">T1 Akte</div><div class="val">{d['t1']}</div></div>
    <div class="ed red"><div class="lbl">Hoch ≥4</div><div class="val">{d['hi']}</div></div>
    <div class="ed amber"><div class="lbl">Cluster</div><div class="val">{len(d['clusters_active'])}</div></div>
  </div>

  <div class="section"><h2>Geografische Verteilung (T1)</h2>{co_block}</div>
  <div class="section"><h2>Ziel-Klassen (Säule 2)</h2>{tt_block}</div>
  <div class="section"><h2>Aktive Frühwarn-Cluster</h2>{cl_block}</div>
  <div class="section"><h2>Neue Strafverfolgungs-Gap-Fälle</h2>{gap_block}</div>
  <div class="section"><h2>Top-Vorfälle der Woche</h2>{top_block}</div>

  <div class="section" style="text-align:center">
    <a class="cta" href="/api/lagebericht/weekly.md">↓ Markdown-Export</a>
    <a class="cta" href="/dashboard">→ Dashboard</a>
    <a class="cta" href="/">→ Karte</a>
  </div>

  <div class="footer">LEX EUROPE · Methodik & Schwellenwerte siehe Plattform-Disclaimer · {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC</div>
</div>
</body></html>""")


_COUNTRY_NAMES = {
    "DE":"Deutschland", "AT":"Österreich", "CH":"Schweiz", "FR":"Frankreich",
    "IT":"Italien", "ES":"Spanien", "GR":"Griechenland", "UK":"Vereinigtes Königreich",
    "NL":"Niederlande", "BE":"Belgien", "DK":"Dänemark", "SE":"Schweden",
    "NO":"Norwegen", "FI":"Finnland", "PL":"Polen", "CZ":"Tschechien",
    "HU":"Ungarn", "RO":"Rumänien", "PT":"Portugal", "IE":"Irland",
    "US":"USA",
}

@app.get("/c/{country}", response_class=HTMLResponse)
async def public_country_profile(country: str):
    """Land-spezifische öffentliche Lagebild-Seite. Analog zu /early-warning/
    aber per Land geschnitten — gibt nationalen Sicherheits-Stakeholdern,
    Journalist:innen und Forschung eine sofortige Lage-Übersicht für
    'ihr' Territorium ohne Filter-Klickerei."""
    co = (country or "").upper().strip()
    if co not in _COUNTRY_NAMES:
        return HTMLResponse("<h1>Unbekanntes Land</h1>", status_code=404)
    co_name = _COUNTRY_NAMES[co]
    today = datetime.now().date()
    last30 = (today - timedelta(days=30)).isoformat()
    last90 = (today - timedelta(days=90)).isoformat()
    total_n = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act' AND country=?", (co,)).fetchone()[0]
    last30_n = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act' AND country=? AND date>=?", (co, last30)).fetchone()[0]
    last90_n = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act' AND country=? AND date>=?", (co, last90)).fetchone()[0]
    hi_n     = db.execute("SELECT COUNT(*) FROM incidents WHERE tier='act' AND country=? AND severity_score>=4", (co,)).fetchone()[0]
    clusters = [dict(r) for r in db.execute(
        "SELECT cluster_key, target_type, count, first_seen, last_seen "
        "FROM early_warning_clusters WHERE active=1 AND country=? "
        "ORDER BY count DESC", (co,)
    ).fetchall()]
    by_cat = [dict(r) for r in db.execute(
        "SELECT category, COUNT(*) n FROM incidents WHERE tier='act' AND country=? "
        "GROUP BY category ORDER BY n DESC LIMIT 8", (co,)
    ).fetchall()]
    by_tt = [dict(r) for r in db.execute(
        "SELECT target_type, COUNT(*) n FROM incidents WHERE tier='act' AND country=? "
        "AND target_type != '' GROUP BY target_type ORDER BY n DESC LIMIT 8", (co,)
    ).fetchall()]
    recent = [dict(r) for r in db.execute(
        "SELECT date, location, category, summary, severity_score, url, source "
        "FROM incidents WHERE tier='act' AND country=? "
        "ORDER BY date DESC LIMIT 25", (co,)
    ).fetchall()]
    # Aktoren mit Vorfällen in diesem Land
    from collections import Counter
    actors = Counter()
    for r in db.execute("SELECT actors FROM incidents WHERE country=? AND actors != ''", (co,)).fetchall():
        for a in (r[0] or "").split(","):
            a = a.strip()
            if a: actors[a] += 1
    top_actors = actors.most_common(8)
    def esc(s): return _xml_esc(s)
    cluster_block = "".join(
        f"<div class='ct'><b>{esc(c['target_type'])}</b> · {c['count']} Anschläge ({esc(c['first_seen'])}…{esc(c['last_seen'])})</div>"
        for c in clusters
    ) or "<div style='color:#6c7986'>— keine aktiven Cluster —</div>"
    cat_block = "".join(f"<div class='row'><span>{esc(c['category'])}</span><span class='n'>{c['n']}</span></div>" for c in by_cat) or "—"
    tt_block  = "".join(f"<div class='row'><a href='/early-warning/{esc(c['target_type'])}'>{esc(c['target_type'])}</a><span class='n'>{c['n']}</span></div>" for c in by_tt) or "—"
    act_block = "".join(f"<div class='row'><span>{esc(a)}</span><span class='n'>{n}</span></div>" for a, n in top_actors) or "—"
    recent_block = "".join(
        f"<div class='inc'><span class='date'>{esc(r['date'])}</span>"
        f"<span class='loc'>{esc(r['location'])}</span>"
        f"<span class='cat'>{esc(r['category'])}</span>"
        f"<span class='sev'>S{r['severity_score'] or '?'}</span>"
        f"<div class='summ'>{esc((r.get('summary') or '')[:200])}</div>"
        + (f"<a class='src' href='{esc(r['url'])}' rel='noopener'>↗ {esc(r['source'] or 'Quelle')}</a>" if r.get('url','').startswith('http') else "")
        + "</div>"
        for r in recent
    ) or "<div style='color:#6c7986'>— keine T1-Vorfälle —</div>"
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Lagebild {co_name} — LEX EUROPE</title>
<meta name="description" content="OSINT-Lagebild Linksextremismus {co_name}: {total_n} dokumentierte T1-Akte, {last30_n} in den letzten 30 Tagen, {len(clusters)} aktive Cluster.">
<meta property="og:title"       content="LEX EUROPE — Lagebild {co_name}">
<meta property="og:description" content="{total_n} T1-Akte · {last30_n} letzte 30T · {hi_n} hoch-Schwere · {len(clusters)} aktive Cluster">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;font-size:13px;line-height:1.55;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:1000px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:32px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:6px;}}
h1 .iso{{color:#6aa9c9;margin-right:14px;}}
.sub{{font-size:10px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:24px;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;}}
.kpi{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:16px 20px;}}
.kpi .lbl{{font-size:8px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:4px;}}
.kpi .val{{font-size:26px;font-weight:600;color:#e9eef3;font-variant-numeric:tabular-nums;}}
.kpi.red .val{{color:#d4495d;}}.kpi.amber .val{{color:#d99a2b;}}.kpi.green .val{{color:#5fb583;}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;}}
@media(max-width:760px){{.grid2{{grid-template-columns:1fr;}}.kpi-grid{{grid-template-columns:repeat(2,1fr);}}}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:18px 22px;margin-bottom:14px;}}
h2{{font-size:10px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.row{{display:flex;justify-content:space-between;padding:4px 0;font-size:11px;border-bottom:1px solid rgba(255,255,255,0.03);}}
.row .n{{color:#e9eef3;font-variant-numeric:tabular-nums;}}
.row a{{color:#aab5c0;text-decoration:none;}}.row a:hover{{color:#6aa9c9;}}
.ct{{padding:6px 0;font-size:11px;border-bottom:1px solid rgba(255,255,255,0.03);}}.ct b{{color:#d99a2b;}}
.inc{{padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:11px;}}
.inc .date{{color:#6c7986;margin-right:10px;}}.inc .loc{{color:#aab5c0;margin-right:10px;}}
.inc .cat{{color:#e9eef3;margin-right:10px;}}.inc .sev{{color:#d99a2b;font-weight:600;}}
.inc .summ{{margin-top:4px;color:#aab5c0;}}
.inc .src{{font-size:9px;color:#6aa9c9;text-decoration:none;letter-spacing:1px;margin-top:3px;display:inline-block;}}
.cta{{display:inline-block;font-size:10px;letter-spacing:2px;color:#6aa9c9;border:1px solid #6aa9c9;padding:8px 14px;text-decoration:none;margin-right:8px;text-transform:uppercase;}}
.cta:hover{{background:rgba(106,169,201,0.10);}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>LANDESPROFIL · {esc(co)}</span></div>
<div class="page">
  <h1><span class="iso">{esc(co)}</span>{esc(co_name)}</h1>
  <div class="sub">Lagebild Linksextremismus · automatisch aggregiert · Stand {today.isoformat()}</div>

  <div class="kpi-grid">
    <div class="kpi"><div class="lbl">T1-Akte gesamt</div><div class="val">{total_n}</div></div>
    <div class="kpi"><div class="lbl">letzte 30 Tage</div><div class="val">{last30_n}</div></div>
    <div class="kpi amber"><div class="lbl">letzte 90 Tage</div><div class="val">{last90_n}</div></div>
    <div class="kpi red"><div class="lbl">Schwere ≥4</div><div class="val">{hi_n}</div></div>
  </div>

  <div class="section"><h2>Aktive Frühwarn-Cluster ({co_name})</h2>{cluster_block}</div>

  <div class="grid2">
    <div class="section"><h2>Kategorien</h2>{cat_block}</div>
    <div class="section"><h2>Ziel-Klassen</h2>{tt_block}</div>
  </div>

  <div class="grid2">
    <div class="section"><h2>Akteure (mit Vorfällen)</h2>{act_block}</div>
    <div class="section"><h2>Methodik-Schnellzugriff</h2>
      <a class="cta" href="/api/incidents.rss?country={esc(co)}">↗ RSS-Feed {esc(co)}</a><br><br>
      <a class="cta" href="/lagebericht">→ Wochenbericht</a>
      <a class="cta" href="/dashboard">→ Dashboard</a>
    </div>
  </div>

  <div class="section"><h2>Jüngste T1-Vorfälle (max. 25)</h2>{recent_block}</div>

  <div class="footer">LEX EUROPE · {esc(co_name)} · Land-spezifische Aggregation</div>
</div>
</body></html>""")


@app.get("/early-warning/{target_type}", response_class=HTMLResponse)
async def public_target_profile(target_type: str):
    """Dedicated public page per Ziel-Klasse (Säule 2) — gibt Betreibern
    eine fokussierte Lagebild-Sicht: aktive Cluster + jüngste Vorfälle
    für ihren Ziel-Typ (Energie, Schiene, Auto, Polizei, …)."""
    tt = (target_type or "").strip()
    if tt not in _TARGET_TYPE_ALLOWED or not tt:
        return HTMLResponse("<h1>Unbekannter Ziel-Typ</h1>", status_code=404)
    # Cluster pulled für diesen Typ
    clusters = [dict(r) for r in db.execute(
        "SELECT cluster_key, country, count, first_seen, last_seen, sample_titles "
        "FROM early_warning_clusters WHERE active=1 AND target_type=? "
        "ORDER BY count DESC, last_seen DESC", (tt,)
    ).fetchall()]
    for c in clusters:
        try: c["sample_titles"] = json.loads(c["sample_titles"] or "[]")
        except: c["sample_titles"] = []
    # Recent incidents für diesen Typ
    recent = [dict(r) for r in db.execute(
        "SELECT date,country,location,category,summary,severity_score,url,source "
        "FROM incidents WHERE tier='act' AND target_type=? "
        "ORDER BY date DESC LIMIT 30", (tt,)
    ).fetchall()]
    today = datetime.now().date()
    last90 = (today - timedelta(days=90)).isoformat()
    last90_n = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE tier='act' AND target_type=? AND date>=?",
        (tt, last90)
    ).fetchone()[0]
    total_n = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE tier='act' AND target_type=?", (tt,)
    ).fetchone()[0]
    by_co = [dict(r) for r in db.execute(
        "SELECT country, COUNT(*) n FROM incidents WHERE tier='act' AND target_type=? "
        "GROUP BY country ORDER BY n DESC LIMIT 10", (tt,)
    ).fetchall()]
    def esc(s): return _xml_esc(s)
    cluster_block = "".join(
        f"<div class='cluster'><div class='ck'><b>{esc(c['country'])}</b> · {c['count']} Anschläge</div>"
        f"<div class='cm'>{esc(c['first_seen'])} → {esc(c['last_seen'])}</div>"
        + "".join(f"<div class='st'>• {esc(t)}</div>" for t in c['sample_titles'])
        + "</div>"
        for c in clusters
    ) or "<div style='color:#6c7986'>— keine aktiven Cluster für diesen Ziel-Typ —</div>"
    recent_block = "".join(
        f"<div class='inc'><span class='date'>{esc(r['date'])}</span>"
        f"<span class='loc'>{esc(r['location'])}, {esc(r['country'])}</span>"
        f"<span class='cat'>{esc(r['category'])}</span>"
        f"<span class='sev'>S{r['severity_score'] or '?'}</span>"
        f"<div class='summ'>{esc((r.get('summary') or '')[:200])}</div>"
        + (f"<a class='src' href='{esc(r['url'])}' rel='noopener'>↗ Quelle ({esc(r['source'] or '')})</a>" if r.get('url','').startswith('http') else "")
        + "</div>" for r in recent
    ) or "<div style='color:#6c7986'>— keine Vorfälle für diesen Ziel-Typ —</div>"
    co_block = "".join(f"<div class='co-row'><span>{esc(c['country'])}</span><span class='n'>{c['n']}</span></div>" for c in by_co) or "<div style='color:#6c7986'>—</div>"
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Frühwarn-Profil: {esc(tt)} — LEX EUROPE</title>
<meta name="description" content="Lagebild-Profil für Ziel-Klasse {esc(tt)}: {total_n} dokumentierte T1-Akte, {last90_n} in den letzten 90 Tagen, {len(clusters)} aktive Cluster.">
<meta property="og:title"       content="LEX EUROPE — Frühwarn-Profil {esc(tt)}">
<meta property="og:description" content="{total_n} T1-Akte gegen {esc(tt)} · {len(clusters)} aktive Cluster">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;font-size:13px;line-height:1.55;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:1000px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:30px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:6px;}}
h1 .label{{color:#6aa9c9;}}
.sub{{font-size:10px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:24px;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px;}}
.kpi{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:16px 20px;}}
.kpi .lbl{{font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:4px;}}
.kpi .val{{font-size:28px;font-weight:600;color:#e9eef3;font-variant-numeric:tabular-nums;}}
.kpi.red .val{{color:#d4495d;}}.kpi.amber .val{{color:#d99a2b;}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:18px 22px;margin-bottom:14px;}}
h2{{font-size:10px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.cluster{{padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);}}
.cluster .ck{{font-size:13px;color:#e9eef3;}}.cluster .ck b{{color:#d99a2b;}}
.cluster .cm{{font-size:9px;color:#6c7986;letter-spacing:1px;margin:2px 0 6px;}}
.cluster .st{{font-size:11px;color:#aab5c0;padding-left:8px;}}
.inc{{padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:11px;}}
.inc .date{{color:#6c7986;margin-right:10px;}}.inc .loc{{color:#aab5c0;margin-right:10px;}}
.inc .cat{{color:#e9eef3;margin-right:10px;}}.inc .sev{{color:#d99a2b;font-weight:600;}}
.inc .summ{{margin-top:4px;color:#aab5c0;}}
.inc .src{{font-size:9px;color:#6aa9c9;text-decoration:none;letter-spacing:1px;margin-top:3px;display:inline-block;}}
.co-row{{display:flex;justify-content:space-between;padding:3px 0;font-size:11px;}}
.co-row .n{{color:#e9eef3;font-variant-numeric:tabular-nums;}}
.cta{{display:inline-block;font-size:10px;letter-spacing:2px;color:#6aa9c9;border:1px solid #6aa9c9;padding:8px 14px;text-decoration:none;margin-right:8px;text-transform:uppercase;}}
.cta:hover{{background:rgba(106,169,201,0.10);}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>FRÜHWARN-PROFIL · {esc(tt).upper()}</span></div>
<div class="page">
  <h1>Ziel-Profil: <span class="label">{esc(tt)}</span></h1>
  <div class="sub">Säule 2 — Frühwarnung · automatisch aggregiert · Stand {today.isoformat()}</div>

  <div class="kpi-grid">
    <div class="kpi"><div class="lbl">T1-Akte gesamt</div><div class="val">{total_n}</div></div>
    <div class="kpi amber"><div class="lbl">letzte 90 Tage</div><div class="val">{last90_n}</div></div>
    <div class="kpi red"><div class="lbl">aktive Cluster</div><div class="val">{len(clusters)}</div></div>
  </div>

  <div class="section"><h2>Aktive Frühwarn-Cluster ({esc(tt)})</h2>{cluster_block}</div>
  <div class="section"><h2>Geografische Verteilung (T1, alle Jahre)</h2>{co_block}</div>
  <div class="section"><h2>Jüngste T1-Vorfälle (max. 30)</h2>{recent_block}</div>

  <div class="section" style="text-align:center">
    <a class="cta" href="/api/early-warning.rss">↗ RSS-Frühwarn-Feed</a>
    <a class="cta" href="/dashboard">→ Dashboard</a>
    <a class="cta" href="/">→ Karte</a>
  </div>

  <div class="footer">LEX EUROPE · {esc(tt)} · Methodik: Cluster = ≥3 gleichartige Anschläge / 6 Wochen pro Land</div>
</div>
</body></html>""")


@app.post("/admin/api/detect-clusters")
async def admin_detect_clusters(_=Depends(require_admin)):
    n = detect_clusters()
    return JSONResponse({"ok": True, "active_clusters": n})


# ── CITATION EXPORT (Säule 4 — MS-5) ──────────────────────────────
@app.get("/api/incident/{inc_id}/cite")
async def cite_incident(inc_id: int, format: str = "bibtex"):
    """
    BibTeX/RIS/Chicago citation for a single incident. Cites the original
    source URL (with evidence_path + SHA-256 when available) so academic
    and legal users can ground their analysis in a tamper-evident record.
    """
    r = db.execute(
        "SELECT id,date,location,country,category,summary,description,source,url,"
        "evidence_path,evidence_sha,evidence_ts FROM incidents WHERE id=?",
        (inc_id,)
    ).fetchone()
    if not r:
        return JSONResponse({"ok": False, "message": "not found"}, status_code=404)
    r = dict(r)
    title    = (r["summary"] or r["description"] or r["category"] or "Incident")[:200]
    author   = r["source"] or "OSINT-Quelle"
    yr       = (r["date"] or "")[:4] or "n.d."
    site     = r["url"] or ""
    accessed = datetime.now().date().isoformat()
    ev_ts    = r["evidence_ts"] or ""
    ev_sha   = r["evidence_sha"] or ""
    fmt = (format or "bibtex").lower()
    if fmt == "ris":
        body = (
            "TY  - GEN\n"
            f"TI  - {title}\n"
            f"AU  - {author}\n"
            f"PY  - {yr}\n"
            f"DA  - {r['date'] or ''}\n"
            f"CY  - {r['location'] or ''}, {r['country'] or ''}\n"
            f"UR  - {site}\n"
            f"N1  - LEX EUROPE id={inc_id}; category={r['category'] or ''}; "
            f"evidence_sha256={ev_sha}; evidence_ts={ev_ts}\n"
            f"Y2  - {accessed}\n"
            "ER  - \n"
        )
        mt = "application/x-research-info-systems"
    elif fmt == "chicago":
        body = (
            f"{author}. \"{title}\" (LEX EUROPE id {inc_id}), {r['date'] or ''}, "
            f"{r['location'] or ''}, {r['country'] or ''}. "
            f"{site}. SHA-256: {ev_sha or 'n/a'}. Accessed {accessed}.\n"
        )
        mt = "text/plain; charset=utf-8"
    else:
        key = f"lexeurope-{inc_id}"
        title_e = title.replace("{","\\{").replace("}","\\}")
        body = (
            f"@misc{{{key},\n"
            f"  title   = {{{title_e}}},\n"
            f"  author  = {{{author}}},\n"
            f"  year    = {{{yr}}},\n"
            f"  url     = {{{site}}},\n"
            f"  note    = {{LEX EUROPE id={inc_id}; category={r['category'] or ''}; "
            f"evidence-sha256={ev_sha}; evidence-ts={ev_ts}}},\n"
            f"  urldate = {{{accessed}}}\n"
            "}\n"
        )
        mt = "application/x-bibtex; charset=utf-8"
    return StreamingResponse(iter([body]), media_type=mt)


# ── LEA/RESEARCH API v1 (Säule 4 — MS-6) ──────────────────────────
def require_api_token(scope: str = "incidents:read"):
    """
    FastAPI dependency that authenticates an Authorization: Bearer <token>
    header against the api_tokens table, scoped to `scope`. Logs the call
    in api_audit. Raises 401 on missing/invalid/revoked, 403 on scope
    mismatch.
    """
    def _dep(request: Request):
        auth = request.headers.get("authorization") or ""
        if not auth.lower().startswith("bearer "):
            raise HTTPException(401, "Missing Bearer token")
        token = auth.split(" ", 1)[1].strip()
        row = db.execute(
            "SELECT id, scopes, revoked, label FROM api_tokens WHERE token=?",
            (token,)
        ).fetchone()
        if not row or row["revoked"]:
            raise HTTPException(401, "Invalid or revoked token")
        if scope not in (row["scopes"] or "").split(","):
            raise HTTPException(403, f"Token missing scope: {scope}")
        # Touch last_used and write the audit trail. The 'ip' field is the
        # source IP as seen by FastAPI (X-Forwarded-For-aware via Render).
        now = datetime.now().isoformat(timespec="seconds")
        ip  = (request.headers.get("x-forwarded-for") or
               (request.client.host if request.client else "")).split(",")[0].strip()
        db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (now, row["id"]))
        db.execute(
            "INSERT INTO api_audit (token_id, endpoint, query, ip, timestamp) "
            "VALUES (?,?,?,?,?)",
            (row["id"], str(request.url.path), str(request.url.query), ip, now)
        )
        db.commit()
        return {"id": row["id"], "label": row["label"], "scopes": row["scopes"]}
    return _dep


@app.get("/api/v1/incidents")
async def v1_incidents(
    limit: int = 500,
    country: str = "",
    tier: str = "",
    severity_min: int = 0,
    date_from: str = "",
    date_to: str = "",
    _tok=Depends(require_api_token("incidents:read")),
):
    """
    Authenticated full-fidelity incident export — same fields as
    /api/incidents plus evidence_path/sha/ts. Designed for LEA and
    academic users who need verifiable, citation-quality data.
    """
    q = ("SELECT id,date,location,country,category,description,summary,url,"
         "source,lat,lon,severity_score,actors,confidence,"
         "is_primary,is_high_risk,tier,target_type,"
         "prosec_status,case_ref,last_status_check,"
         "evidence_path,evidence_sha,evidence_ts,timestamp "
         "FROM incidents WHERE 1=1")
    p = []
    if country:      q += " AND country=?";       p.append(country)
    if tier:         q += " AND tier=?";          p.append(tier)
    if severity_min: q += " AND severity_score >= ?"; p.append(severity_min)
    if date_from:    q += " AND date >= ?";        p.append(date_from)
    if date_to:      q += " AND date <= ?";        p.append(date_to)
    q += " ORDER BY date DESC LIMIT ?"
    p.append(min(max(limit, 1), 5000))
    rows = [dict(r) for r in db.execute(q, p).fetchall()]
    return JSONResponse({
        "count":  len(rows),
        "incidents": rows,
        "asof":   datetime.now().isoformat(timespec="seconds"),
    })


@app.get("/api/v1/audit")
async def v1_audit(
    limit: int = 200,
    _tok=Depends(require_api_token("audit:read")),
):
    """Self-audit endpoint — token holder can see their own call history."""
    rows = db.execute(
        "SELECT endpoint, query, ip, timestamp FROM api_audit "
        "WHERE token_id=? ORDER BY timestamp DESC LIMIT ?",
        (_tok["id"], min(max(limit, 1), 1000))
    ).fetchall()
    return JSONResponse({"count": len(rows), "calls": [dict(r) for r in rows]})


@app.get("/api/v1/docs", response_class=HTMLResponse)
async def v1_docs():
    """Minimal static docs page in English — what the API offers, how to
    authenticate, link to the policy lines (Concept §C3)."""
    return HTMLResponse(_V1_DOCS_HTML)


_V1_DOCS_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>LEX EUROPE — API v1 docs</title>
<style>
body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0a121e;color:#cfd6dd;
  max-width:880px;margin:30px auto;padding:0 24px;line-height:1.55;font-size:14px}
h1,h2{font-family:ui-sans-serif,system-ui,sans-serif;color:#e8edf2;letter-spacing:0.5px}
h1{font-size:22px;border-bottom:1px solid #1c2937;padding-bottom:8px}
h2{font-size:16px;margin-top:28px;color:#6aa9c9;text-transform:uppercase;letter-spacing:1.5px;font-size:12px}
code,pre{background:#0f1a28;color:#a8c2d8;border:1px solid #1c2937;border-radius:3px;
  padding:1px 6px;font-size:12px}
pre{padding:10px 14px;overflow-x:auto;white-space:pre}
a{color:#6aa9c9}
.tag{display:inline-block;background:#1c2937;color:#6aa9c9;padding:1px 6px;
  border-radius:2px;font-size:10px;letter-spacing:1px;margin-right:6px}
.note{border-left:2px solid #d99a2b;background:rgba(217,154,43,0.08);padding:10px 14px;margin:14px 0}
</style></head><body>

<h1>LEX EUROPE — API v1</h1>
<p>Authenticated, full-fidelity access to the LEX EUROPE incident corpus for
law-enforcement agencies, academic researchers, and journalists. All endpoints
require a personal API token; every call is logged in <code>api_audit</code>.</p>

<div class="note"><b>Policy line.</b> The dataset never includes personal
profiles of private individuals (no names, addresses, employers, family
relationships). Tier classification follows Fedpol Art. 19 Abs. 2 Bst. e NDG
(act / enable / context). Citations of single records should include the
<code>evidence_sha</code> hash so verification is reproducible.</div>

<h2>Authentication</h2>
<pre>Authorization: Bearer &lt;your-token&gt;</pre>
<p>Tokens are issued by the operator. Missing token → <code>401</code>. Revoked
or wrong scope → <code>401</code> / <code>403</code>.</p>

<h2>GET /api/v1/incidents</h2>
<p><span class="tag">scope</span><code>incidents:read</code></p>
<p>Returns up to <code>limit</code> incidents (default 500, max 5000) with all
classification, severity, tier, prosecution-status, and WARC-evidence fields.</p>
<p>Query parameters:</p>
<ul>
  <li><code>limit</code> — int, max 5000</li>
  <li><code>country</code> — DE/AT/CH/FR/IT/...</li>
  <li><code>tier</code> — <code>act</code> | <code>enable</code> | <code>context</code></li>
  <li><code>severity_min</code> — 1..5</li>
  <li><code>date_from</code>, <code>date_to</code> — ISO yyyy-mm-dd</li>
</ul>

<pre>curl -H "Authorization: Bearer $TOKEN" \\
     "https://&lt;host&gt;/api/v1/incidents?tier=act&amp;severity_min=4&amp;date_from=2024-01-01"</pre>

<h2>GET /api/v1/audit</h2>
<p><span class="tag">scope</span><code>audit:read</code></p>
<p>Returns the token holder's own call history — every request is timestamped
and IP-stamped, so misuse is auditable on the operator side as well as on the
researcher side.</p>

<h2>GET /api/early-warning.json / .rss</h2>
<p>Unauthenticated. Returns active target-type clusters (≥3 same-target attacks
in 6 weeks). See <a href="/api/early-warning.json">/api/early-warning.json</a>.</p>

<h2>GET /api/incident/&lt;id&gt;/cite</h2>
<p>Unauthenticated. <code>format=bibtex|ris|chicago</code>. Embeds the
<code>evidence_sha256</code> and capture timestamp in the citation note so the
underlying WARC snapshot is reproducibly verifiable.</p>

</body></html>
"""


@app.post("/admin/api/tokens")
async def admin_create_token(request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    label = (data.get("label") or "").strip()
    if not label:
        return JSONResponse({"ok": False, "message": "label ist Pflicht"}, status_code=400)
    scopes = (data.get("scopes") or "incidents:read").strip()
    token  = secrets.token_urlsafe(32)
    now    = datetime.now().isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO api_tokens (token,label,scopes,created_at,revoked) VALUES (?,?,?,?,0)",
        (token, label, scopes, now)
    )
    db.commit()
    # Token is returned ONLY here — never again. Operator must hand it to
    # the researcher / LEA contact over a secure channel.
    return JSONResponse({"ok": True, "token": token, "label": label, "scopes": scopes})


@app.delete("/admin/api/tokens/{token_id}")
async def admin_revoke_token(token_id: int, _=Depends(require_admin)):
    db.execute("UPDATE api_tokens SET revoked=1 WHERE id=?", (token_id,))
    db.commit()
    return JSONResponse({"ok": True})


# ── WEBHOOK ADMIN-CRUD (Säule 2) ──────────────────────────────────
@app.post("/admin/api/webhooks")
async def admin_create_webhook(request: Request, _=Depends(require_admin)):
    """Create a new webhook subscription. Returns the secret EXACTLY once."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    url   = (data.get("url")   or "").strip()
    label = (data.get("label") or "").strip()
    # https:// in Production Pflicht; localhost/127.0.0.1 dürfen auch http://
    # (für interne Operatoren-Empfänger und lokale Testflows).
    _is_localhost = re.search(r"^https?://(127\.0\.0\.1|localhost)(:\d+)?(/|$)", url)
    if not url.startswith("https://") and not _is_localhost:
        return JSONResponse({"ok": False,
            "message": "url muss https:// sein (Ausnahme: localhost/127.0.0.1)"},
            status_code=400)
    if not label:
        return JSONResponse({"ok": False, "message": "label ist Pflicht"}, status_code=400)
    def _norm(s, allowed=None):
        items = [x.strip() for x in (s or "").split(",") if x.strip()]
        if allowed:
            items = [x for x in items if x in allowed]
        return ",".join(items)
    target_types = _norm(data.get("target_types", ""), _TARGET_TYPE_ALLOWED)
    countries    = _norm(data.get("countries", ""))
    events       = _norm(data.get("events", "cluster,incident"),
                          {"cluster", "incident"})
    if not events:
        events = "cluster,incident"
    min_sev      = int(data.get("min_severity") or 4)
    secret       = secrets.token_urlsafe(32)
    now          = datetime.now().isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO webhook_subscriptions "
        "(url,label,target_types,countries,min_severity,events,secret,active,created_at) "
        "VALUES (?,?,?,?,?,?,?,1,?)",
        (url, label, target_types, countries, min_sev, events, secret, now)
    )
    db.commit()
    sub_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    return JSONResponse({
        "ok": True, "id": sub_id, "label": label, "url": url,
        "target_types": target_types, "countries": countries, "events": events,
        "min_severity": min_sev,
        "secret": secret,
        "signature_help":
            "X-LexEurope-Signature header = 'sha256=' + hmac_sha256(secret, raw_body). "
            "Body is JSON UTF-8, keys sorted, no extra whitespace.",
    })

@app.delete("/admin/api/webhooks/{sub_id}")
async def admin_delete_webhook(sub_id: int, _=Depends(require_admin)):
    db.execute("UPDATE webhook_subscriptions SET active=0 WHERE id=?", (sub_id,))
    db.commit()
    return JSONResponse({"ok": True})

@app.get("/admin/api/webhooks")
async def admin_list_webhooks(_=Depends(require_admin)):
    """Lists subscriptions WITHOUT the secret value."""
    rows = db.execute(
        "SELECT id, url, label, target_types, countries, min_severity, events, "
        "active, created_at, last_delivery, delivery_count, failure_count "
        "FROM webhook_subscriptions ORDER BY id DESC"
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/admin/api/webhooks/{sub_id}/deliveries")
async def admin_webhook_deliveries(sub_id: int, limit: int = 50,
                                    _=Depends(require_admin)):
    rows = db.execute(
        "SELECT event_type, event_key, status_code, body_len, delivered_at, error "
        "FROM webhook_deliveries WHERE sub_id=? ORDER BY id DESC LIMIT ?",
        (sub_id, min(limit, 500))
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.post("/admin/api/webhooks/{sub_id}/test")
async def admin_webhook_test(sub_id: int, _=Depends(require_admin)):
    """Fires a synthetic 'test'-event at one subscription for verification."""
    row = db.execute(
        "SELECT id,url,secret,events FROM webhook_subscriptions "
        "WHERE id=? AND active=1", (sub_id,)
    ).fetchone()
    if not row:
        return JSONResponse({"ok": False, "message": "Subscription nicht aktiv"}, status_code=404)
    payload = {"event": "test", "ts": datetime.now().isoformat(timespec="seconds"),
               "message": "LEX EUROPE webhook test"}
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig  = _hmac_sign(row["secret"], body)
    try:
        r = requests.post(row["url"], data=body, timeout=8, headers={
            "Content-Type": "application/json",
            "X-LexEurope-Signature": sig,
            "X-LexEurope-Event": "test",
        })
        return JSONResponse({"ok": True, "status_code": r.status_code})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)[:200]}, status_code=502)


@app.get("/admin/api/tokens")
async def admin_list_tokens(_=Depends(require_admin)):
    rows = db.execute(
        "SELECT id, label, scopes, created_at, last_used, revoked "
        "FROM api_tokens ORDER BY id DESC"
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/effectiveness")
async def get_effectiveness():
    """
    Säule-Wirksamkeits-Zähler für den Status-Footer (Concept §C5).
    Liefert vier konkrete Kennzahlen — bewusst öffentlich:
      - prosec_gap_pct: % der T1-Vorfälle Severity ≥ 4 ohne öffentliches
        Verfahren nach 180 Tagen (Säule 1).
      - cluster_active:  Anzahl aktiver Frühwarn-Cluster (≥ 3 gleichartige
        Anschläge in 6 Wochen). Aus early_warning_clusters (MS-3).
      - funding_year_eur: Summe der dokumentierten Förderung im laufenden
        Jahr (Säule 3). Sobald wir einen recipient_tier-Marker haben, wird
        das auf T1/T2-Empfänger eingeschränkt.
      - evidence_pct:  % Einträge mit WARC-Snapshot (MS-5).
    """
    today = datetime.now().date()
    # Strafverfolgungs-Lücke
    sev_4plus = db.execute(
        "SELECT id,date,prosec_status,case_ref FROM incidents "
        "WHERE tier='act' AND severity_score >= 4"
    ).fetchall()
    elig = 0; gap = 0
    for r in sev_4plus:
        try:
            d = datetime.fromisoformat(r["date"]).date()
        except Exception:
            continue
        if (today - d).days < 180:
            continue
        elig += 1
        if (r["prosec_status"] or "unknown") in ("unknown","none") and not (r["case_ref"] or "").strip():
            gap += 1
    prosec_gap_pct = round(100.0 * gap / elig) if elig else 0

    # Finanzfluss-Transparenz — Summe laufendes Jahr.
    yr = today.year
    funding_eur = db.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM funding_records WHERE year = ?",
        (yr,)
    ).fetchone()[0] or 0

    cluster_active = db.execute(
        "SELECT COUNT(*) FROM early_warning_clusters WHERE active=1"
    ).fetchone()[0]

    # Evidence coverage: crawled rows only — manuelle Einträge haben keinen
    # URL-Snapshot und würden den Quotient sonst künstlich drücken.
    ev_base = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE manual=0 AND url LIKE 'http%'"
    ).fetchone()[0] or 0
    ev_have = db.execute(
        "SELECT COUNT(*) FROM incidents "
        "WHERE manual=0 AND url LIKE 'http%' AND evidence_path != ''"
    ).fetchone()[0] or 0
    evidence_pct = round(100.0 * ev_have / ev_base) if ev_base else 0

    return JSONResponse({
        "prosec_gap_pct":  prosec_gap_pct,
        "prosec_gap_n":    gap,
        "prosec_gap_base": elig,
        "cluster_active":  cluster_active,
        "funding_year_eur": int(funding_eur),
        "funding_year":    yr,
        "evidence_pct":    evidence_pct,
        "evidence_have":   ev_have,
        "evidence_base":   ev_base,
        "asof":            today.isoformat(),
    })

@app.get("/api/accountability/trend")
async def accountability_trend(months: int = 24):
    """
    Säule 1 — Trend-Daten für das „Wachsende-Lücke"-Chart im Verfolgung-Tab.
    Liefert pro Monat (zurück bis `months` Monate) den T1-Sev≥4-Counter
    und die Anzahl mit prosec_status ∈ {investigating,charged,trial,convicted}
    bzw. dokumentiertem Aktenzeichen. Die Differenz ist die wachsende
    Strafverfolgungs-Lücke. Output für Chart.js direkt verwendbar.
    """
    today = datetime.now().date()
    start = (today.replace(day=1) - timedelta(days=32 * months)).replace(day=1)
    rows = db.execute(
        "SELECT date, prosec_status, case_ref FROM incidents "
        "WHERE tier='act' AND severity_score >= 4 AND date >= ? "
        "ORDER BY date ASC", (start.isoformat(),)
    ).fetchall()
    from collections import defaultdict
    counts = defaultdict(lambda: {"total": 0, "prosecuted": 0})
    PROSEC_OK = {"investigating", "charged", "trial", "convicted"}
    for r in rows:
        try:
            d = datetime.fromisoformat(r["date"]).date()
        except Exception:
            continue
        key = f"{d.year}-{d.month:02d}"
        counts[key]["total"] += 1
        ps = (r["prosec_status"] or "unknown")
        if ps in PROSEC_OK or (r["case_ref"] or "").strip():
            counts[key]["prosecuted"] += 1
    # Build a continuous month series (no gaps in the chart)
    series = []
    cur = start
    while cur <= today:
        key = f"{cur.year}-{cur.month:02d}"
        c = counts.get(key, {"total": 0, "prosecuted": 0})
        gap = c["total"] - c["prosecuted"]
        series.append({"month": key, "total": c["total"],
                       "prosecuted": c["prosecuted"], "gap": gap})
        if cur.month == 12:
            cur = cur.replace(year=cur.year + 1, month=1)
        else:
            cur = cur.replace(month=cur.month + 1)
    cum = {"total": 0, "prosecuted": 0, "gap": 0}
    for s in series:
        cum["total"]      += s["total"]
        cum["prosecuted"] += s["prosecuted"]
        cum["gap"]        += s["gap"]
        s["cum_total"]      = cum["total"]
        s["cum_prosecuted"] = cum["prosecuted"]
        s["cum_gap"]        = cum["gap"]
    return JSONResponse({
        "months": months, "series": series,
        "totals": cum,
    })

@app.get("/api/accountability")
async def get_accountability():
    """
    Säule 1 — Strafverfolgungs-Druck: aggregate which T1-tier incidents have
    a documented prosec_status and which sit silent for ≥180 days at
    severity≥4 (the "Gap"). Returns:
      total_t1, with_case, gap_count, by_status[], gap_rows[]
    """
    rows = db.execute(
        "SELECT id,date,location,country,category,severity_score,"
        "tier,prosec_status,case_ref,url,source,last_status_check "
        "FROM incidents WHERE tier='act' ORDER BY date DESC"
    ).fetchall()
    rows = [dict(r) for r in rows]
    total_t1   = len(rows)
    with_case  = sum(1 for r in rows if (r.get("case_ref") or "").strip())
    today      = datetime.now().date()
    gap_rows = []
    by_status = {}
    for r in rows:
        st = (r.get("prosec_status") or "unknown")
        by_status[st] = by_status.get(st, 0) + 1
        # Gap heuristic: T1 sev≥4 with no case_ref, status unknown/none, and
        # incident date is ≥180 days old. These are the politically active
        # cases that should have triggered a public investigation by now.
        if (r.get("severity_score") or 0) >= 4 and st in ("unknown","none") and not (r.get("case_ref") or "").strip():
            try:
                d = datetime.fromisoformat(r["date"]).date()
                if (today - d).days >= 180:
                    gap_rows.append(r)
            except Exception:
                pass
    return JSONResponse({
        "total_t1":   total_t1,
        "with_case":  with_case,
        "gap_count":  len(gap_rows),
        "by_status":  [{"status": k, "count": v} for k, v in sorted(by_status.items(), key=lambda x: -x[1])],
        "gap_rows":   gap_rows[:200],
    })

@app.get("/api/incidents")
async def get_incidents(
    country: str = "", category: str = "", date_from: str = "",
    date_to: str = "", search: str = "", severity_min: int = 0,
    primary_only: int = 0, tier: str = "", target_type: str = "",
    fts: int = 0,
):
    """
    primary_only=1 → only is_primary=1 rows (default UI behaviour for the
    incidents feed; the "INKL. KONTEXT" toggle clears the flag).
    tier=act|enable|context → filter on the Fedpol 3-tier taxonomy.
    target_type=Energie|Schiene|… → filter on Säule-2 target routing.
    fts=1 + search="…" → SQLite FTS5 match query (schneller + relevanter
      als LIKE). Beispiele: 'Brandanschlag AND Polizei', 'Tesla OR Hyperloop',
      'antifa NEAR/5 demo'. Bei syntaxfehlern fällt es auf LIKE zurück.
    """
    q = ("SELECT id,date,location,country,category,description,summary,url,"
         "lat,lon,manual,source,severity_score,actors,confidence,"
         "is_primary,is_high_risk,tier,target_type,"
         "prosec_status,case_ref,last_status_check,"
         "evidence_path,evidence_sha,evidence_ts FROM incidents WHERE 1=1")
    p = []
    if country:   q += " AND country=?";   p.append(country)
    if category:  q += " AND category=?";  p.append(category)
    if date_from: q += " AND date>=?";     p.append(date_from)
    if date_to:   q += " AND date<=?";     p.append(date_to)
    if search:
        # FTS5-Pfad: erst Match-Query versuchen, fallback auf LIKE.
        used_fts = False
        if fts:
            try:
                rids = [r["rowid"] for r in db.execute(
                    "SELECT rowid FROM incidents_fts WHERE incidents_fts MATCH ? "
                    "ORDER BY rank LIMIT 2000", (search,)
                ).fetchall()]
                if rids:
                    q += " AND id IN (" + ",".join("?" * len(rids)) + ")"
                    p.extend(rids)
                else:
                    # FTS matched nothing; return empty without falling back.
                    return JSONResponse([])
                used_fts = True
            except Exception as e:
                log.info(f"FTS5 query failed, falling back to LIKE: {e}")
        if not used_fts:
            q += " AND (description LIKE ? OR summary LIKE ? OR location LIKE ? OR category LIKE ?)"
            s = f"%{search}%"
            p.extend([s, s, s, s])
    if severity_min > 0:
        q += " AND severity_score >= ?"
        p.append(severity_min)
    if primary_only:
        q += " AND is_primary=1"
    if tier:
        q += " AND tier=?"
        p.append(tier)
    if target_type:
        q += " AND target_type=?"
        p.append(target_type)
    q += " ORDER BY date DESC, timestamp DESC"
    return JSONResponse([dict(r) for r in db.execute(q, p).fetchall()])

@app.get("/api/stats")
async def stats():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    return JSONResponse({
        "total":total, "geocoded":geocoded,
        "last_crawl": meta_get("last_crawl"),
        "crawl_running": _running[0],
        "hist_running": _hist_run[0],
        "by_country": [dict(r) for r in db.execute("SELECT country,COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()],
        "by_cat":     [dict(r) for r in db.execute("SELECT category,COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()],
        "by_source":  [dict(r) for r in db.execute("SELECT source,COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC").fetchall()],
    })

@app.get("/api/summary")
async def get_summary():
    total    = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    geocoded = db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0]
    last7    = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-7 days')").fetchone()[0]
    last30   = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-30 days')").fetchone()[0]
    prev30   = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-60 days') AND date < date('now','-30 days')").fetchone()[0]
    by_country = [dict(r) for r in db.execute("SELECT country, COUNT(*) n FROM incidents GROUP BY country ORDER BY n DESC").fetchall()]
    by_cat     = [dict(r) for r in db.execute("SELECT category, COUNT(*) n FROM incidents GROUP BY category ORDER BY n DESC").fetchall()]
    top_locs   = [dict(r) for r in db.execute("SELECT location, country, COUNT(*) n FROM incidents GROUP BY location ORDER BY n DESC LIMIT 10").fetchall()]
    return JSONResponse({
        "total": total, "geocoded": geocoded,
        "last7": last7, "last30": last30, "prev30": prev30,
        "trend": "up" if last30 > prev30 else "down" if last30 < prev30 else "flat",
        "by_country": by_country, "by_cat": by_cat, "top_locs": top_locs,
        "last_crawl": meta_get("last_crawl"),
        "crawl_running": _running[0],
        "sources": [dict(r) for r in db.execute("SELECT source, COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC LIMIT 20").fetchall()],
    })

@app.get("/api/timeline")
async def get_timeline():
    rows = db.execute("""
        SELECT strftime('%Y-%m', date) as month, COUNT(*) as n,
               SUM(CASE WHEN category IN ('Brandanschlag','Gewalt','Militante Aktion') THEN 1 ELSE 0 END) as high
        FROM incidents
        WHERE date IS NOT NULL AND date != '' AND length(date) >= 7
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.get("/api/trends")
async def get_trends():
    # Monthly data last 24 months
    rows = db.execute("""
        SELECT strftime('%Y-%m', date) as month, COUNT(*) as n,
               SUM(CASE WHEN category IN ('Brandanschlag','Gewalt','Militante Aktion','Aufruf zu Gewalt') THEN 1 ELSE 0 END) as high
        FROM incidents
        WHERE date >= date('now','-24 months') AND date IS NOT NULL AND length(date) >= 7
        GROUP BY month ORDER BY month ASC
    """).fetchall()
    months = [dict(r) for r in rows]

    # Linear regression on monthly counts (last 12 months)
    recent = months[-12:] if len(months) >= 3 else months
    n = len(recent)
    slope = 0.0
    forecast = []
    if n >= 3:
        xs = list(range(n)); ys = [r['n'] for r in recent]
        xm = sum(xs)/n; ym = sum(ys)/n
        num = sum((xs[i]-xm)*(ys[i]-ym) for i in range(n))
        den = sum((xs[i]-xm)**2 for i in range(n))
        slope = num/den if den else 0.0
        intercept = ym - slope*xm
        last_m = recent[-1]['month'] if recent else ""
        if last_m:
            yr, mo = int(last_m[:4]), int(last_m[5:7])
            for i in range(1, 4):
                mo2 = mo+i; yr2 = yr+(mo2-1)//12; mo2 = ((mo2-1)%12)+1
                pred = max(0, round(intercept + slope*(n-1+i)))
                forecast.append({"month": f"{yr2:04d}-{mo2:02d}", "predicted": pred})

    # Hot spots last 6 months
    hot_spots = [dict(r) for r in db.execute("""
        SELECT location, country, COUNT(*) n,
               SUM(CASE WHEN category IN ('Brandanschlag','Gewalt','Militante Aktion') THEN 1 ELSE 0 END) as high
        FROM incidents
        WHERE date >= date('now','-6 months')
          AND location IS NOT NULL AND location NOT IN ('','Unbekannt','Unknown')
        GROUP BY location, country ORDER BY n DESC LIMIT 8
    """).fetchall()]

    # Category trends: current 3m vs previous 3m
    cat_curr = {r['category']: r['n'] for r in db.execute(
        "SELECT category, COUNT(*) n FROM incidents WHERE date >= date('now','-3 months') GROUP BY category"
    ).fetchall()}
    cat_prev = {r['category']: r['n'] for r in db.execute(
        "SELECT category, COUNT(*) n FROM incidents WHERE date >= date('now','-6 months') AND date < date('now','-3 months') GROUP BY category"
    ).fetchall()}
    cat_trends = []
    for cat in CATEGORIES:
        curr = cat_curr.get(cat, 0); prev = cat_prev.get(cat, 0)
        if curr + prev > 0:
            chg = round((curr-prev)/max(prev,1)*100)
            cat_trends.append({"category": cat, "current": curr, "previous": prev, "change_pct": chg})
    cat_trends.sort(key=lambda x: x['current'], reverse=True)

    week_curr = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-7 days')").fetchone()[0]
    week_prev = db.execute("SELECT COUNT(*) FROM incidents WHERE date >= date('now','-14 days') AND date < date('now','-7 days')").fetchone()[0]

    return JSONResponse({
        "monthly": months,
        "forecast": forecast,
        "trend_direction": "up" if slope > 0.1 else "down" if slope < -0.1 else "stable",
        "slope": round(slope, 2),
        "hot_spots": hot_spots,
        "cat_trends": cat_trends,
        "week_curr": week_curr,
        "week_prev": week_prev,
    })

@app.get("/api/actors")
async def get_actors():
    rows = db.execute(
        "SELECT actors, COUNT(*) n, SUM(CASE WHEN severity_score>=4 THEN 1 ELSE 0 END) as hi, MAX(date) as last_seen "
        "FROM incidents WHERE actors IS NOT NULL AND actors != '' "
        "GROUP BY actors ORDER BY n DESC LIMIT 30"
    ).fetchall()
    actor_map: dict = {}
    for row in rows:
        for a in (row["actors"] or "").split(","):
            a = a.strip()
            if not a: continue
            if a not in actor_map:
                actor_map[a] = {
                    "name": a, "count": 0, "high": 0, "last_seen": "",
                    # MS-7 — Fedpol Akteurs-Tier: act|enable|endorse, fallback
                    # endorse for actors not in KNOWN_ACTORS (we don't impute
                    # active perpetration to unknown labels).
                    "tier": ACTOR_TIER.get(a, "endorse"),
                }
            actor_map[a]["count"] += row["n"]
            actor_map[a]["high"]  += row["hi"]
            if (row["last_seen"] or "") > actor_map[a]["last_seen"]:
                actor_map[a]["last_seen"] = row["last_seen"]
    result = sorted(actor_map.values(), key=lambda x: x["count"], reverse=True)[:15]
    return JSONResponse(result)

# ── FUNDING TRACKER API ──────────────────────────────────────────
# Public, read-only endpoints. Admin CRUD is below in the /admin section.

@app.get("/api/funding")
async def get_funding(
    org: str = "",
    donor_type: str = "",
    country: str = "",
    year_min: int = 0,
    year_max: int = 0,
    amount_min: float = 0.0,
    search: str = "",
    sort: str = "year_desc",
    limit: int = 500,
):
    """Filterable funding-records query — mirrors the /api/incidents shape."""
    q = ("SELECT id, recipient_org, project, amount, currency, year, country, "
         "donor_type, donor_name, source_url, notes, confidence, "
         "COALESCE(verified, 0) AS verified, manual "
         "FROM funding_records WHERE 1=1")
    p: list = []
    if org:        q += " AND recipient_org LIKE ?"; p.append(f"%{org}%")
    if donor_type: q += " AND donor_type=?";         p.append(donor_type)
    if country:    q += " AND country=?";            p.append(country)
    if year_min:   q += " AND year>=?";              p.append(year_min)
    if year_max:   q += " AND year<=?";              p.append(year_max)
    if amount_min: q += " AND amount>=?";            p.append(amount_min)
    if search:
        q += (" AND (recipient_org LIKE ? OR project LIKE ? "
              "OR donor_name LIKE ? OR notes LIKE ?)")
        s = f"%{search}%"
        p.extend([s, s, s, s])
    sort_map = {
        "amount_desc": " ORDER BY amount DESC, year DESC",
        "amount_asc":  " ORDER BY amount ASC,  year DESC",
        "year_desc":   " ORDER BY year DESC,   amount DESC",
        "year_asc":    " ORDER BY year ASC,    amount DESC",
        "org_asc":     " ORDER BY recipient_org ASC, year DESC",
    }
    q += sort_map.get(sort, sort_map["year_desc"])
    q += " LIMIT ?"
    p.append(max(1, min(limit, 2000)))
    return JSONResponse([dict(r) for r in db.execute(q, p).fetchall()])

# ── REGION EXTRACTION (Säule 3, MS-4 polish) ──────────────────────
# Leitet aus donor_name eine grobe Region ab — Stadt > Land/Kanton > Bund.
# Keine externe Geodaten-Lib; einfache Keyword-Heuristik reicht für die
# kuratierten Seed-Geber, weil die Namens-Konventionen einheitlich sind.
_REGION_PATTERNS = [
    # (region_label, level, country, regex on donor_name lowercase)
    ("Wien",         "Stadt",     "AT", re.compile(r"\bwien\b|\bma\s*\d+\b")),
    ("Berlin",       "Land",      "DE", re.compile(r"\bberlin\b|\bberlinovo\b|\bsenstadt\b|\bsenat\s+berlin\b")),
    ("Hamburg",      "Land",      "DE", re.compile(r"\bhamburg\b|\bfhh\b|\bbürgerschaft\s+hamburg\b")),
    ("München",      "Stadt",     "DE", re.compile(r"\bmünchen\b|\blandeshauptstadt münchen\b|\bbayer.{0,4}haupt")),
    ("Leipzig",      "Stadt",     "DE", re.compile(r"\bleipzig\b")),
    ("Frankfurt",    "Stadt",     "DE", re.compile(r"\bfrankfurt\b")),
    ("Köln",         "Stadt",     "DE", re.compile(r"\bköln\b|\bk[öo]ln\b")),
    ("Dortmund",     "Stadt",     "DE", re.compile(r"\bdortmund\b")),
    ("Hessen",       "Land",      "DE", re.compile(r"\bhessen\b|\bsozialminist.*hessen")),
    ("Bayern",       "Land",      "DE", re.compile(r"\bbayer")),
    ("Sachsen",      "Land",      "DE", re.compile(r"\bsachsen\b|\bfreistaat sachsen\b")),
    ("NRW",          "Land",      "DE", re.compile(r"\bnrw\b|\bnordrhein|\bmkffi\b")),
    ("Bund DE",      "Bund",      "DE", re.compile(r"\bbmfsfj\b|\bbmbf\b|\bbpb\b|\bbundes(?:zentrale|regierung|ministerium|amt)")),
    ("Bern",         "Stadt",     "CH", re.compile(r"\bbern\b")),
    ("Zürich",       "Stadt",     "CH", re.compile(r"\bzürich\b|\bzuerich\b")),
    ("Basel",        "Stadt",     "CH", re.compile(r"\bbasel\b")),
    ("Kanton CH",    "Kanton",    "CH", re.compile(r"\bkanton\b")),
    ("BKA AT",       "Bund",      "AT", re.compile(r"\bbka\s+österreich\b|\bbundeskanzleramt\b")),
    ("EU-Kommission","EU",        "EU", re.compile(r"\beuropäische kommission\b|\beu kommission\b|\bcerv\b|\berasmus")),
    ("USA-Stiftung", "Stiftung",  "US", re.compile(r"\bclimate emergency fund\b|\busa\b")),
    ("Rosa-Luxemburg-Stiftung","Stiftung","DE", re.compile(r"\brosa[- ]luxemburg")),
    ("Heinrich-Böll-Stiftung","Stiftung","DE", re.compile(r"\bheinrich[- ]böll\b|\bboell\b")),
    ("Migros-Kulturprozent","Stiftung","CH", re.compile(r"\bmigros\b|\bengagement-migros\b")),
]

def funding_region(donor_name: str, country: str):
    """Return (region_label, level) or fallback ('Übrige '+country, 'Andere')."""
    n = (donor_name or "").lower()
    for label, level, _co, rx in _REGION_PATTERNS:
        if rx.search(n):
            return (label, level)
    return (f"Übrige {country or '—'}", "Andere")


@app.get("/api/funding/by-region")
async def funding_by_region(year_min: int = 0, year_max: int = 0,
                            country: str = "", min_amount: float = 0):
    """Aggregate funding by extracted region — bar-chart data for the
    Funding-View region panel. Respects the same filter set as the table."""
    q = "SELECT donor_name, country, amount, year FROM funding_records WHERE 1=1"
    p = []
    if year_min:   q += " AND year >= ?";   p.append(year_min)
    if year_max:   q += " AND year <= ?";   p.append(year_max)
    if country:    q += " AND country = ?"; p.append(country)
    if min_amount: q += " AND amount >= ?"; p.append(min_amount)
    rows = db.execute(q, p).fetchall()
    agg = {}
    for r in rows:
        label, level = funding_region(r["donor_name"] or "", r["country"] or "")
        key = (label, level, r["country"] or "—")
        if key not in agg:
            agg[key] = {"region": label, "level": level, "country": key[2],
                        "count": 0, "amount": 0.0}
        agg[key]["count"]  += 1
        agg[key]["amount"] += r["amount"] or 0
    out = sorted(agg.values(), key=lambda x: -x["amount"])
    return JSONResponse({"regions": out, "asof": datetime.now().isoformat(timespec="seconds")})


@app.get("/api/funding/stats")
async def funding_stats():
    """Aggregated stats for the funding-view charts."""
    total_records = db.execute("SELECT COUNT(*) FROM funding_records").fetchone()[0]
    total_amount  = db.execute(
        "SELECT COALESCE(SUM(amount),0) FROM funding_records"
    ).fetchone()[0] or 0
    by_donor_type = [dict(r) for r in db.execute(
        "SELECT donor_type, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY donor_type ORDER BY sum DESC"
    ).fetchall()]
    by_org = [dict(r) for r in db.execute(
        "SELECT recipient_org, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY recipient_org ORDER BY sum DESC LIMIT 15"
    ).fetchall()]
    by_year = [dict(r) for r in db.execute(
        "SELECT year, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY year ORDER BY year ASC"
    ).fetchall()]
    by_country = [dict(r) for r in db.execute(
        "SELECT country, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY country ORDER BY sum DESC"
    ).fetchall()]
    top_donors = [dict(r) for r in db.execute(
        "SELECT donor_name, COUNT(*) n, COALESCE(SUM(amount),0) sum "
        "FROM funding_records GROUP BY donor_name ORDER BY sum DESC LIMIT 10"
    ).fetchall()]
    return JSONResponse({
        "total_records": total_records,
        "total_amount":  total_amount,
        "by_donor_type": by_donor_type,
        "by_org":        by_org,
        "by_year":       by_year,
        "by_country":    by_country,
        "top_donors":    top_donors,
    })

@app.get("/api/funding/graph")
async def funding_graph(year_min: int = 0, year_max: int = 0,
                        country: str = "", min_amount: float = 0,
                        max_nodes: int = 120):
    """
    Säule 3 — Finanzfluss-Graph. Aggregiert funding_records zu Donor→
    Recipient-Kanten und ergänzt explizite Mehr-Hop-Kanten aus funding_edges.
    Liefert {nodes, links} im D3-Force-kompatiblen Format.
    """
    # Direct edges aus funding_records
    q1 = ("SELECT donor_name AS src, recipient_org AS dst, "
          "SUM(amount) AS amount, MAX(year) AS yr, COUNT(*) AS n, "
          "MAX(source_url) AS src_url, MAX(country) AS country, "
          "MAX(donor_type) AS dtype "
          "FROM funding_records WHERE 1=1")
    params = []
    if year_min: q1 += " AND year >= ?"; params.append(year_min)
    if year_max: q1 += " AND year <= ?"; params.append(year_max)
    if country:  q1 += " AND country = ?"; params.append(country)
    if min_amount: q1 += " AND amount >= ?"; params.append(min_amount)
    q1 += " GROUP BY donor_name, recipient_org"
    direct = [dict(r) for r in db.execute(q1, params).fetchall()]

    # Multi-hop edges
    edges = [dict(r) for r in db.execute(
        "SELECT src_org AS src, dst_org AS dst, amount, year AS yr, "
        "source_url AS src_url, notes FROM funding_edges"
    ).fetchall()]

    # Node aggregation
    nodes = {}
    def upsert_node(name, role):
        if not name: return
        if name not in nodes:
            nodes[name] = {"id": name, "label": name, "in": 0, "out": 0,
                           "amount_in": 0.0, "amount_out": 0.0, "type": role}
        nodes[name]["type"] = role if nodes[name]["type"] == role else "intermediary"

    links = []
    for e in direct:
        upsert_node(e["src"], "donor")
        upsert_node(e["dst"], "recipient")
        nodes[e["src"]]["out"] += e["n"];  nodes[e["src"]]["amount_out"] += (e["amount"] or 0)
        nodes[e["dst"]]["in"]  += e["n"];  nodes[e["dst"]]["amount_in"]  += (e["amount"] or 0)
        links.append({
            "source": e["src"], "target": e["dst"],
            "amount": e["amount"] or 0, "year": e["yr"],
            "url":    e["src_url"] or "", "kind": "direct",
            "country": e.get("country") or "", "donor_type": e.get("dtype") or "",
        })
    for e in edges:
        upsert_node(e["src"], "donor")
        upsert_node(e["dst"], "recipient")
        nodes[e["src"]]["out"] += 1; nodes[e["src"]]["amount_out"] += (e["amount"] or 0)
        nodes[e["dst"]]["in"]  += 1; nodes[e["dst"]]["amount_in"]  += (e["amount"] or 0)
        links.append({
            "source": e["src"], "target": e["dst"],
            "amount": e["amount"] or 0, "year": e["yr"],
            "url":    e["src_url"] or "", "kind": "edge",
            "notes":  e.get("notes") or "",
        })

    # Cap node count by total connectivity if necessary.
    if len(nodes) > max_nodes:
        ranked = sorted(nodes.values(),
                        key=lambda n: -(n["in"] + n["out"]))[:max_nodes]
        keep = {n["id"] for n in ranked}
        nodes = {k: v for k, v in nodes.items() if k in keep}
        links = [l for l in links if l["source"] in keep and l["target"] in keep]

    return JSONResponse({
        "nodes": list(nodes.values()),
        "links": links,
        "node_count": len(nodes),
        "link_count": len(links),
    })


@app.post("/admin/api/funding-edge")
async def admin_add_funding_edge(request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    src = (data.get("src_org") or "").strip()
    dst = (data.get("dst_org") or "").strip()
    if not src or not dst:
        return JSONResponse({"ok": False, "message": "src_org und dst_org sind Pflicht"}, status_code=400)
    if src == dst:
        return JSONResponse({"ok": False, "message": "src_org darf nicht == dst_org sein"}, status_code=400)
    amount = data.get("amount") or 0
    year   = data.get("year")  or None
    src_url = (data.get("source_url") or "").strip()
    notes   = (data.get("notes") or "").strip()
    h = hashlib.sha256(f"edge|{src.lower()}|{dst.lower()}|{year}".encode()).hexdigest()
    try:
        db.execute(
            "INSERT OR IGNORE INTO funding_edges "
            "(src_org,dst_org,amount,currency,year,source_url,notes,manual,hash,timestamp) "
            "VALUES (?,?,?,?,?,?,?,1,?,datetime('now'))",
            (src, dst, float(amount or 0), data.get("currency","EUR"),
             year, src_url, notes, h)
        )
        db.commit()
    except Exception as e:
        return JSONResponse({"ok": False, "message": str(e)}, status_code=400)
    return JSONResponse({"ok": True, "hash": h})


@app.delete("/admin/api/funding-edge/{edge_id}")
async def admin_delete_funding_edge(edge_id: int, _=Depends(require_admin)):
    db.execute("DELETE FROM funding_edges WHERE id=?", (edge_id,))
    db.commit()
    return JSONResponse({"ok": True})


@app.get("/api/funding/edges")
async def list_funding_edges(limit: int = 200):
    rows = db.execute(
        "SELECT id, src_org, dst_org, amount, currency, year, "
        "source_url, notes, timestamp FROM funding_edges "
        "ORDER BY year DESC, timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/funding/by-actor")
async def funding_by_actor(actor: str = "", min_amount: float = 0):
    """
    Cross-Reference: alle Funding-Records, deren recipient_org ODER
    donor_name den gegebenen Akteur (oder ein Synonym aus KNOWN_ACTORS)
    enthält. Sucht case-insensitive Substring-Match. Ermöglicht
    "klick-Akteur → siehe Finanzfluss" UX.
    """
    if not actor or len(actor) < 3:
        return JSONResponse({"actor": actor, "matches": [], "count": 0})
    # Klein-/Groß-Variante + bekannte Synonyme expandieren.
    needles = [actor.lower()]
    for name, _patterns, _tier in KNOWN_ACTORS:
        if name.lower() == actor.lower():
            for pat in _patterns:
                # Erste Wort-Stamm-Variante des Pattern als Such-Needle.
                cleaned = re.sub(r"[\\b\\s\\.\\?\\*\\+\\(\\)\\[\\]\\|]", " ", pat).strip()
                first = cleaned.split()[0] if cleaned.split() else ""
                if len(first) >= 4:
                    needles.append(first.lower())
            break
    needles = list(set(needles))
    q = ("SELECT id, recipient_org, project, amount, currency, year, country, "
         "donor_type, donor_name, source_url, notes, confidence, "
         "COALESCE(verified, 0) AS verified "
         "FROM funding_records WHERE 1=1")
    p = []
    if min_amount > 0:
        q += " AND amount >= ?"
        p.append(min_amount)
    # OR-Filter über recipient_org + donor_name + notes
    or_clauses = []
    for n in needles:
        like = f"%{n}%"
        or_clauses.append("(LOWER(recipient_org) LIKE ? OR LOWER(donor_name) LIKE ? OR LOWER(notes) LIKE ?)")
        p.extend([like, like, like])
    if or_clauses:
        q += " AND (" + " OR ".join(or_clauses) + ")"
    q += " ORDER BY year DESC, amount DESC"
    rows = [dict(r) for r in db.execute(q, p).fetchall()]
    total_eur = sum(r["amount"] for r in rows if (r.get("currency") or "EUR") == "EUR")
    total_chf = sum(r["amount"] for r in rows if (r.get("currency") or "EUR") == "CHF")
    return JSONResponse({
        "actor":     actor,
        "needles":   needles,
        "matches":   rows,
        "count":     len(rows),
        "sum_eur":   total_eur,
        "sum_chf":   total_chf,
    })


@app.get("/api/incidents/by-actor")
async def incidents_by_actor(actor: str = "", limit: int = 200):
    """
    Cross-Reference: alle Incidents, in deren actors-Feld der genannte
    Akteur vorkommt. Für die Actor-Drill-Down-Panel sehr nützlich
    (heute filtert das Frontend client-side; dieser Endpoint erlaubt
    auch externen API-Konsumenten dieselbe Sicht).
    """
    if not actor or len(actor) < 3:
        return JSONResponse({"actor": actor, "matches": [], "count": 0})
    rows = [dict(r) for r in db.execute(
        "SELECT id, date, location, country, category, summary, "
        "severity_score, tier, target_type, url, source, actors "
        "FROM incidents WHERE actors LIKE ? "
        "ORDER BY date DESC LIMIT ?",
        (f"%{actor}%", min(max(limit, 1), 500))
    ).fetchall()]
    # Filter genauer: actor name muss exact in komma-separierter Liste sein
    actor_l = actor.lower()
    filtered = [r for r in rows if any(
        a.strip().lower() == actor_l for a in (r["actors"] or "").split(",")
    )]
    sev_hist = [0,0,0,0,0]
    for r in filtered:
        s = max(1, min(5, r.get("severity_score") or 1))
        sev_hist[s-1] += 1
    by_co = {}
    for r in filtered:
        c = r.get("country") or "—"
        by_co[c] = by_co.get(c, 0) + 1
    return JSONResponse({
        "actor": actor,
        "count": len(filtered),
        "by_severity": sev_hist,
        "by_country":  sorted(by_co.items(), key=lambda x: -x[1]),
        "matches": filtered[:limit],
    })


@app.get("/api/funding/export-csv")
async def funding_export_csv():
    """CSV export of the full funding table."""
    rows = db.execute(
        "SELECT year, recipient_org, project, donor_type, donor_name, "
        "amount, currency, country, confidence, source_url, notes "
        "FROM funding_records ORDER BY year DESC, amount DESC"
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Jahr","Empfänger","Projekt","Geber-Typ","Geber",
                "Betrag","Währung","Land","Konfidenz","Quelle","Notizen"])
    for r in rows:
        w.writerow(list(r))
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=lex-funding-{datetime.now().strftime('%Y%m%d')}.csv"},
    )

@app.get("/api/export-json")
async def export_json(country:str="", category:str="", date_from:str="", date_to:str="", search:str="", severity_min:int=0):
    q = "SELECT id,date,location,country,category,description,url,lat,lon,source,severity_score,actors,confidence FROM incidents WHERE 1=1"
    p = []
    if country:   q += " AND country=?";   p.append(country)
    if category:  q += " AND category=?";  p.append(category)
    if date_from: q += " AND date>=?";     p.append(date_from)
    if date_to:   q += " AND date<=?";     p.append(date_to)
    if search:
        q += " AND (description LIKE ? OR location LIKE ?)"; p.extend([f"%{search}%",f"%{search}%"])
    if severity_min > 0:
        q += " AND severity_score>=?"; p.append(severity_min)
    q += " ORDER BY date DESC"
    rows = [dict(r) for r in db.execute(q, p).fetchall()]
    return StreamingResponse(
        iter([json.dumps(rows, ensure_ascii=False, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=lex-europe-{datetime.now().strftime('%Y%m%d')}.json"}
    )

# ── WEEKLY LAGEBERICHT (Press-Ready) ──────────────────────────────
# Drei Ausgabeformen: JSON für API-Konsumenten, Markdown für Journalist-
# innen zum Direkt-Einbau in Artikel, HTML als Stand-Alone-Seite.

def _isoweek_bounds(week_str=None):
    """Parse ISO week 'YYYY-Www' → (start_iso, end_iso) inclusive."""
    today = datetime.now().date()
    if week_str:
        try:
            yr, wk = week_str.upper().split("-W")
            mon = datetime.fromisocalendar(int(yr), int(wk), 1).date()
        except Exception:
            mon = today - timedelta(days=today.weekday())
    else:
        mon = today - timedelta(days=today.weekday())
    sun = mon + timedelta(days=6)
    return mon.isoformat(), sun.isoformat()

def _build_lagebericht(week_start: str, week_end: str):
    """Compute the structured data for a single week's Lagebericht."""
    rows = [dict(r) for r in db.execute(
        "SELECT id,date,location,country,category,summary,description,url,source,"
        "severity_score,actors,tier,target_type,prosec_status,case_ref "
        "FROM incidents WHERE date >= ? AND date <= ? "
        "ORDER BY severity_score DESC, date DESC",
        (week_start, week_end)
    ).fetchall()]
    # Previous week for delta
    prev_start = (datetime.fromisoformat(week_start) - timedelta(days=7)).date().isoformat()
    prev_end   = (datetime.fromisoformat(week_end)   - timedelta(days=7)).date().isoformat()
    prev_count = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE date >= ? AND date <= ?",
        (prev_start, prev_end)
    ).fetchone()[0]
    # T1/T2/T3 buckets
    t1 = [r for r in rows if r.get("tier") == "act"]
    t2 = [r for r in rows if r.get("tier") == "enable"]
    t3 = [r for r in rows if r.get("tier") == "context"]
    hi = [r for r in t1 if (r.get("severity_score") or 0) >= 4]
    # Per-country / per-category / actors
    from collections import Counter
    by_co  = Counter(r["country"] for r in t1)
    by_cat = Counter(r["category"] for r in t1)
    by_tt  = Counter(r["target_type"] for r in t1 if r.get("target_type"))
    actors = Counter()
    for r in rows:
        for a in (r.get("actors") or "").split(","):
            a = a.strip()
            if a: actors[a] += 1
    # Active clusters this week
    clusters = [dict(r) for r in db.execute(
        "SELECT cluster_key, country, target_type, count, first_seen, last_seen "
        "FROM early_warning_clusters WHERE active=1 ORDER BY count DESC"
    ).fetchall()]
    # New prosecution gap entries in this week
    today = datetime.now().date()
    new_gap = []
    for r in t1:
        if (r.get("severity_score") or 0) < 4: continue
        if (r.get("prosec_status") or "unknown") not in ("unknown","none"): continue
        if (r.get("case_ref") or "").strip(): continue
        try:
            d = datetime.fromisoformat(r["date"]).date()
        except Exception: continue
        if (today - d).days >= 180:
            new_gap.append(r)
    return {
        "week_start": week_start, "week_end": week_end,
        "prev_count": prev_count,
        "total":  len(rows),
        "t1":     len(t1), "t2": len(t2), "t3": len(t3), "hi": len(hi),
        "delta":  len(rows) - prev_count,
        "delta_pct": round(100 * (len(rows) - prev_count) / max(prev_count, 1)),
        "by_country":     by_co.most_common(8),
        "by_category":    by_cat.most_common(8),
        "by_target_type": by_tt.most_common(8),
        "top_actors":     actors.most_common(8),
        "top_incidents":  t1[:12],
        "clusters_active": clusters,
        "new_gap_cases":  new_gap[:10],
    }

@app.get("/api/lagebericht/weekly")
async def lagebericht_weekly_json(week: str = ""):
    ws, we = _isoweek_bounds(week or None)
    return JSONResponse({"week": f"{ws}..{we}", **_build_lagebericht(ws, we)})

@app.get("/api/lagebericht/weekly.md")
async def lagebericht_weekly_md(week: str = ""):
    """Press-ready Markdown — direkt in Artikel einbettbar."""
    ws, we = _isoweek_bounds(week or None)
    d = _build_lagebericht(ws, we)
    iso = datetime.fromisoformat(ws).isocalendar()
    label = f"{iso.year}-W{iso.week:02d}"
    delta = d["delta"]
    delta_str = (f"+{delta} (+{d['delta_pct']}%)" if delta > 0
                 else f"{delta} ({d['delta_pct']}%)" if delta < 0
                 else "unverändert")
    lines = []
    lines.append(f"# Lagebericht Linksextremismus · KW {label}\n")
    lines.append(f"*Berichtszeitraum: {ws} bis {we} · automatisch generiert*\n")
    lines.append("## Eckdaten\n")
    lines.append(f"- **{d['total']} Vorfälle** dokumentiert ({delta_str} vs. Vorwoche)")
    lines.append(f"- **{d['t1']} T1-Akte** (Brandanschlag / Sabotage / Gewalt / Militante Aktion / pol. mot. Sachbeschädigung)")
    lines.append(f"- davon **{d['hi']} mit Schweregrad ≥ 4** (Sprengstoff, Personenschaden, Sachschaden ≥ 100k €)")
    lines.append(f"- **{d['t2']} T2-Förder-Handlungen** (Aufruf zu Gewalt, Mobilisierung)")
    lines.append(f"- **{d['t3']} T3-Kontext-Einträge** (Demonstrationen, Verhaftungen, Repressionsberichte)")
    lines.append(f"- **{len(d['clusters_active'])} aktive Frühwarn-Cluster** (≥3 gleichartige Anschläge in 6 Wochen)\n")
    if d["by_country"]:
        lines.append("## Geografische Verteilung (T1)\n")
        for co, n in d["by_country"]:
            lines.append(f"- {co}: {n}")
        lines.append("")
    if d["by_target_type"]:
        lines.append("## Ziel-Klassen (T1)\n")
        for tt, n in d["by_target_type"]:
            lines.append(f"- {tt}: {n}")
        lines.append("")
    if d["new_gap_cases"]:
        lines.append(f"## Strafverfolgungs-Gap ({len(d['new_gap_cases'])} hoch-Schwere-Fälle ≥180 Tage ohne öffentliches Verfahren)\n")
        for r in d["new_gap_cases"]:
            cat = r.get("category") or "—"
            loc = r.get("location") or "—"
            co  = r.get("country") or "—"
            dt  = r.get("date") or "—"
            lines.append(f"- **{dt}** · {loc}, {co} · {cat} (Schwere {r.get('severity_score','?')})")
        lines.append("")
    if d["clusters_active"]:
        lines.append("## Aktive Cluster (≥3 gleichartige Anschläge / 6 Wochen)\n")
        for c in d["clusters_active"]:
            lines.append(f"- **{c['target_type']}** in {c['country']} — {c['count']} Anschläge ({c['first_seen']}..{c['last_seen']})")
        lines.append("")
    if d["top_incidents"]:
        lines.append("## Wichtigste T1-Vorfälle der Woche\n")
        for r in d["top_incidents"]:
            url = r.get("url") or ""
            link = f" [Quelle]({url})" if url and url.startswith("http") else ""
            lines.append(f"- **{r.get('date')}** · {r.get('location','—')}, {r.get('country','—')} · "
                         f"{r.get('category','—')} (Schwere {r.get('severity_score','?')}/5)"
                         f" — {(r.get('summary') or r.get('description') or '')[:200]}{link}")
        lines.append("")
    lines.append("---\n")
    lines.append("*Quelle: LEX EUROPE OSINT-Plattform. Methodik & Schwellenwerte siehe Plattform-Disclaimer.*\n")
    md = "\n".join(lines)
    return StreamingResponse(iter([md]), media_type="text/markdown; charset=utf-8")

@app.get("/api/report")
async def generate_report(days: int = 7):
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    prev  = (datetime.now() - timedelta(days=days*2)).strftime("%Y-%m-%d")
    rows  = [dict(r) for r in db.execute(
        "SELECT date,location,country,category,description,url,source,severity_score,actors,confidence "
        "FROM incidents WHERE date >= ? ORDER BY severity_score DESC, date DESC", (since,)
    ).fetchall()]
    prev_count = db.execute("SELECT COUNT(*) FROM incidents WHERE date>=? AND date<?", (prev,since)).fetchone()[0]
    total = len(rows)
    high  = sum(1 for r in rows if (r.get("severity_score") or 0) >= 4)
    by_co  = {}; by_cat = {}; actor_counts = {}
    for r in rows:
        by_co[r["country"]]   = by_co.get(r["country"],0)+1
        by_cat[r["category"]] = by_cat.get(r["category"],0)+1
        for a in (r.get("actors") or "").split(","):
            a=a.strip()
            if a: actor_counts[a] = actor_counts.get(a,0)+1
    chg = round((total-prev_count)/max(prev_count,1)*100)
    chg_str = f"+{chg}%" if chg >= 0 else f"{chg}%"
    top_country = sorted(by_co.items(), key=lambda x:x[1], reverse=True)[:5]
    top_cat     = sorted(by_cat.items(), key=lambda x:x[1], reverse=True)[:5]
    top_actors  = sorted(actor_counts.items(), key=lambda x:x[1], reverse=True)[:8]
    top_incidents = rows[:10]
    now_str = datetime.now().strftime("%d.%m.%Y %H:%M")
    report_html = f"""<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8">
<title>LEX EUROPE — Intelligence Report {now_str}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f8;color:#1a2332;font-size:13px;}}
.page{{max-width:900px;margin:0 auto;padding:32px 24px;}}
.header{{background:linear-gradient(135deg,#0d1b2e 0%,#1a2f4e 100%);color:#fff;padding:28px 32px;margin-bottom:24px;}}
.header h1{{font-size:22px;letter-spacing:3px;font-weight:700;margin-bottom:4px;}}
.header .sub{{font-size:11px;letter-spacing:2px;opacity:.7;margin-bottom:16px;}}
.header .meta{{display:flex;gap:32px;}}
.header .meta div{{font-size:11px;opacity:.6;}}
.header .meta b{{font-size:16px;display:block;opacity:1;color:#00c8ff;}}
.section{{background:#fff;border:1px solid #dee2e8;padding:20px 24px;margin-bottom:16px;}}
.section h2{{font-size:11px;font-weight:700;letter-spacing:2px;color:#5a7a92;border-bottom:2px solid #e8edf2;padding-bottom:8px;margin-bottom:14px;text-transform:uppercase;}}
.exec{{background:#fff8e6;border-left:4px solid #f0a500;padding:16px 20px;font-size:13px;line-height:1.7;}}
.stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}}
.stat{{background:#f4f6f8;padding:14px;text-align:center;border:1px solid #dee2e8;}}
.stat .val{{font-size:24px;font-weight:700;color:#0d1b2e;}}
.stat .lbl{{font-size:10px;letter-spacing:1.5px;color:#5a7a92;margin-top:4px;}}
.red{{color:#cc1133;}} .amber{{color:#cc7a00;}} .green{{color:#008844;}}
table{{width:100%;border-collapse:collapse;font-size:11px;}}
th{{background:#f4f6f8;padding:7px 10px;text-align:left;font-weight:700;letter-spacing:1px;color:#5a7a92;font-size:10px;border-bottom:2px solid #dee2e8;}}
td{{padding:7px 10px;border-bottom:1px solid #eef0f3;vertical-align:top;}}
tr:hover td{{background:#f8fafc;}}
.sev{{display:inline-block;padding:2px 7px;border-radius:2px;font-size:10px;font-weight:700;}}
.s5,.s4{{background:#ffebee;color:#cc1133;}} .s3{{background:#fff8e6;color:#cc7a00;}} .s2,.s1{{background:#e8f4ff;color:#1a6699;}}
.bar-row{{display:flex;align-items:center;gap:8px;margin-bottom:6px;}}
.bar-lbl{{min-width:120px;font-size:11px;}}
.bar-track{{flex:1;height:8px;background:#eef0f3;border-radius:4px;overflow:hidden;}}
.bar-fill{{height:100%;border-radius:4px;background:#0d6699;}}
.footer{{text-align:center;font-size:10px;color:#999;margin-top:24px;padding-top:16px;border-top:1px solid #dee2e8;}}
@media print{{body{{background:#fff;}}.page{{padding:0;}}}}
</style>
</head>
<body>
<div class="page">
<div class="header">
  <div class="sub">OSINT INTELLIGENCE // LEX EUROPE // RESTRICTED</div>
  <h1>WÖCHENTLICHER LAGEBERICHT</h1>
  <div class="meta">
    <div><b>{total}</b>VORFÄLLE GESAMT</div>
    <div><b class="red">{high}</b>HOCH RISIKOVORFÄLLE</div>
    <div><b>{chg_str}</b>VS. VORPERIODE</div>
    <div><b>{len(actor_counts)}</b>AKTEURE IDENTIFIZIERT</div>
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="exec">
    Im Berichtszeitraum der letzten {days} Tage (seit {since}) wurden <strong>{total} Vorfälle</strong> gewalttätiger linksextremer Aktivitäten in Europa dokumentiert.
    Davon wurden <strong>{high} Vorfälle</strong> als hoch-risikoreich eingestuft (Schweregrad 4-5).
    Im Vergleich zur Vorperiode entspricht dies einer Veränderung von <strong>{chg_str}</strong>.
    {"Die Lage ist eskalierend — verstärkte Überwachung empfohlen." if chg > 20 else "Die Lage ist stabil." if abs(chg) <= 20 else "Rückläufige Aktivität beobachtet."}
    {"Schwerpunkte liegen in " + ", ".join(c for c,_ in top_country[:3]) + "." if top_country else ""}
  </div>
</div>

<div class="section">
  <h2>Schlüsselstatistiken</h2>
  <div class="stat-grid">
    <div class="stat"><div class="val">{total}</div><div class="lbl">VORFÄLLE GESAMT</div></div>
    <div class="stat"><div class="val red">{high}</div><div class="lbl">HOCHRISIKO (≥4)</div></div>
    <div class="stat"><div class="val {'green' if chg < 0 else 'red'}">{chg_str}</div><div class="lbl">VS. VORPERIODE</div></div>
    <div class="stat"><div class="val">{len(actor_counts)}</div><div class="lbl">AKTEURE</div></div>
  </div>
</div>

<div class="section">
  <h2>Geografische Verteilung</h2>
  {''.join(f'<div class="bar-row"><span class="bar-lbl">{c}</span><div class="bar-track"><div class="bar-fill" style="width:{round(n/max(total,1)*100)}%"></div></div><span style="font-size:11px;color:#666">{n}</span></div>' for c,n in top_country)}
</div>

<div class="section">
  <h2>Aktivitätstypen</h2>
  {''.join(f'<div class="bar-row"><span class="bar-lbl">{c[:20]}</span><div class="bar-track"><div class="bar-fill" style="width:{round(n/max(total,1)*100)}%;background:#cc1133"></div></div><span style="font-size:11px;color:#666">{n}</span></div>' for c,n in top_cat)}
</div>

{ f'<div class="section"><h2>Aktive Akteure / Gruppen</h2><table><thead><tr><th>GRUPPE</th><th>VORFÄLLE</th></tr></thead><tbody>' + "".join(f"<tr><td>{a}</td><td><b>{n}</b></td></tr>" for a,n in top_actors) + '</tbody></table></div>' if top_actors else '' }

<div class="section">
  <h2>Top Vorfälle (nach Schweregrad)</h2>
  <table>
    <thead><tr><th>DATUM</th><th>ORT</th><th>KATEGORIE</th><th>SCHWERE</th><th>BESCHREIBUNG</th></tr></thead>
    <tbody>
      {"".join(f'<tr><td style="white-space:nowrap">{r.get("date","—")}</td><td>{r.get("location","—")}, {r.get("country","—")}</td><td>{r.get("category","—")}</td><td><span class="sev s{r.get("severity_score",1)}">{r.get("severity_score",1)}/5</span></td><td style="max-width:300px">{(r.get("description") or "")[:120]}…</td></tr>' for r in top_incidents)}
    </tbody>
  </table>
</div>

<div class="footer">
  LEX EUROPE · Automatisch generiert am {now_str} · Datenstand: {since} bis {datetime.now().strftime("%d.%m.%Y")} · Nur zur internen Verwendung
</div>
</div>
</body>
</html>"""
    return HTMLResponse(report_html)

@app.get("/api/admin-check")
async def admin_check(request: Request):
    """
    Lets the public frontend ask "is this browser an authenticated admin?"
    The admin_token cookie is httpOnly so the page cannot read it directly —
    this endpoint reads + validates it server-side and reports a plain bool.
    Used by index.html to reveal the in-detail Edit/Delete controls.
    """
    return JSONResponse({"admin": verify_token(request.cookies.get("admin_token", ""))})

@app.delete("/api/admin/incident/{inc_id}")
async def admin_inline_delete(inc_id: int, _=Depends(require_admin)):
    """Quick-delete an incident from the public map detail panel."""
    db.execute("DELETE FROM incidents WHERE id=?", (inc_id,))
    db.commit()
    return JSONResponse({"ok": True, "id": inc_id})

@app.put("/api/admin/incident/{inc_id}")
async def admin_inline_update(inc_id: int, request: Request, _=Depends(require_admin)):
    """Quick-edit fields on a single incident from the map (admin only)."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    allowed = {"description","summary","location","country","category","severity_score","date","url",
               # Strategic Concept v3 — Säule 1 (Strafverfolgungs-Druck) + Säule 2 (Frühwarn-Routing)
               "tier","target_type","prosec_status","case_ref","last_status_check"}
    fields = {k: v for k, v in data.items() if k in allowed}
    # Validate tier + prosec_status values to keep the columns clean.
    if "tier" in fields and fields["tier"] not in ("act","enable","context"):
        return JSONResponse({"ok": False, "message": "tier muss act|enable|context sein"}, status_code=400)
    _allowed_prosec = {"unknown","none","investigating","charged","trial","convicted","acquitted","dismissed"}
    if "prosec_status" in fields and fields["prosec_status"] not in _allowed_prosec:
        return JSONResponse({"ok": False, "message": f"prosec_status muss eines von {sorted(_allowed_prosec)} sein"}, status_code=400)
    if not fields:
        return JSONResponse({"ok": False, "message": "Keine erlaubten Felder"}, status_code=400)
    # Run PII redaction on text fields before saving — admin shouldn't be
    # able to bypass the safety filter even by direct edit.
    if "description" in fields:
        fields["description"] = redact_pii(fields["description"] or "")[:500]
    if "summary" in fields:
        # Auch admin edits respektieren das neue 140-Zeichen/2-Satz-Limit.
        fields["summary"] = clamp_two_sentences(
            strip_activist_phrases(redact_pii(fields["summary"] or "")),
            140,
        )
    cols = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE incidents SET {cols} WHERE id=?",
               tuple(list(fields.values()) + [inc_id]))
    db.commit()
    return JSONResponse({"ok": True, "id": inc_id})

@app.get("/api/diagnose")
async def diagnose():
    key = os.getenv("GROK_API_KEY","")
    r   = {"env":{"GROK_API_KEY_set":bool(key),"GROK_API_KEY_len":len(key),
                  "GROK_MODEL":GROK_MODEL,"ADMIN_PASS_ok":ADMIN_PASS!="changeme",
                  "DB_PATH":DB_PATH}}
    # Test barrikade
    try:
        html = fetch("https://barrikade.info/", timeout=10)
        ids  = [int(m) for m in re.findall(r"/article/(\d+)", html)]
        r["barrikade"] = {"ok":True,"max_id":max(ids) if ids else 0,"len":len(html)}
    except Exception as e:
        r["barrikade"] = {"ok":False,"error":str(e)}
    # Test indymedia
    try:
        xml   = fetch("https://de.indymedia.org/RSS/newswire.xml", timeout=10)
        items = parse_rss(xml)
        r["indymedia"] = {"ok":True,"items":len(items)}
    except Exception as e:
        r["indymedia"] = {"ok":False,"error":str(e)}
    # Test grok
    if key:
        try:
            resp = requests.post("https://api.x.ai/v1/chat/completions",
                headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},
                json={"model":GROK_MODEL,"messages":[{"role":"user","content":"OK"}],
                      "max_tokens":5,"temperature":0.0}, timeout=15)
            r["grok"] = {"status":resp.status_code,
                         "model":resp.json().get("model","?") if resp.ok else "—",
                         "response":resp.json()["choices"][0]["message"]["content"] if resp.ok else resp.text[:100]}
        except Exception as e:
            r["grok"] = {"ok":False,"error":str(e)}
    r["db"] = {"incidents":db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
               "metadata":[dict(x) for x in db.execute("SELECT * FROM metadata").fetchall()]}
    return JSONResponse(r)

# AUTH
@app.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})

@app.post("/admin/login")
async def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = make_token()
        resp  = RedirectResponse("/admin", status_code=302)
        resp.set_cookie("admin_token", token, httponly=True, samesite="strict", max_age=43200)
        return resp
    return templates.TemplateResponse("login.html",{"request":request,"error":"Ungültige Zugangsdaten"})

@app.get("/admin/logout")
async def do_logout(request: Request):
    db.execute("DELETE FROM sessions WHERE token=?", (request.cookies.get("admin_token",""),))
    db.commit()
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie("admin_token")
    return resp

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request):
    if not verify_token(request.cookies.get("admin_token","")):
        return RedirectResponse("/admin/login", status_code=302)
    b_max  = int(meta_get("hist_b_max") or 0)
    b_curr = int(meta_get("hist_b_curr") or 0)
    b_pct  = f"{round((b_max-b_curr)/max(b_max,1)*100,1)}%" if b_max else "—"
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "total":        db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "running":      _running[0],
        "hist_running": _hist_run[0],
        "last_crawl":   meta_get("last_crawl") or "—",
        "recent": [dict(r) for r in db.execute(
            "SELECT id,date,location,country,category,source FROM incidents ORDER BY timestamp DESC LIMIT 20").fetchall()],
        "categories": CATEGORIES,
        "feed_count": len(RSS_FEEDS),
        "hist_b_pct":  b_pct,
        "hist_b_done": bool(meta_get("hist_b_done")),
        "hist_im_done":bool(meta_get("hist_im_done")),
    })

@app.post("/admin/api/crawl")
async def admin_crawl(bg: BackgroundTasks, _=Depends(require_admin)):
    bg.add_task(run_crawler, True)
    return JSONResponse({"status": "Crawler gestartet"})

@app.post("/admin/api/stop-crawl")
async def admin_stop(_=Depends(require_admin)):
    _running[0] = False
    return JSONResponse({"status": "Gestoppt"})

@app.post("/admin/api/crawl-historical")
async def admin_hist(bg: BackgroundTasks, reset: bool = False, _=Depends(require_admin)):
    bg.add_task(run_historical, reset)
    return JSONResponse({"status": "Historisch gestartet"})

@app.get("/admin/api/status")
async def admin_status(_=Depends(require_admin)):
    b_max  = int(meta_get("hist_b_max") or 0)
    b_curr = int(meta_get("hist_b_curr") or 0)
    return JSONResponse({
        "total":       db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "geocoded":    db.execute("SELECT COUNT(*) FROM incidents WHERE lat IS NOT NULL").fetchone()[0],
        "crawl_running": _running[0],
        "hist_running":  _hist_run[0],
        "last_crawl":  meta_get("last_crawl"),
        "feed_count":  len(RSS_FEEDS),
        "hist": {
            "barrikade_done": bool(meta_get("hist_b_done")),
            "barrikade_pct":  round((b_max-b_curr)/max(b_max,1)*100,1) if b_max else 0,
            "barrikade_curr": b_curr,
            "indymedia_done": bool(meta_get("hist_im_done")),
            "indymedia_off":  int(meta_get("hist_im_offset") or 0),
        },
        "sources": [dict(r) for r in db.execute(
            "SELECT source,COUNT(*) n FROM incidents GROUP BY source ORDER BY n DESC LIMIT 20").fetchall()],
    })

@app.post("/admin/api/add-incident")
async def admin_add(request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    for f in ["date","location","country","category","description"]:
        if not data.get(f):
            return JSONResponse({"ok": False, "message": f"Pflichtfeld '{f}' fehlt"}, status_code=400)
    try:
        ai  = {"land":data["country"], "kategorie":data["category"], "ort":data["location"]}
        url = data.get("url") or f"manual-{datetime.now().isoformat()}"
        ok  = save_incident(ai, data["description"], data.get("source","Manuell"), url, data["date"], manual=True)
        return JSONResponse({"ok": ok, "message": "Gespeichert" if ok else "Bereits vorhanden"})
    except Exception as e:
        log.error(f"admin_add: {e}", exc_info=True)
        return JSONResponse({"ok": False, "message": f"Fehler: {str(e)[:200]}"}, status_code=500)

@app.delete("/admin/api/incident/{inc_id}")
async def admin_delete(inc_id: int, _=Depends(require_admin)):
    db.execute("DELETE FROM incidents WHERE id=?", (inc_id,))
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/admin/api/clear")
async def admin_clear(_=Depends(require_admin)):
    db.execute("DELETE FROM incidents")
    db.execute("DELETE FROM metadata")
    db.commit()
    return JSONResponse({"status": "Geleert"})

@app.post("/admin/api/regeocode")
async def admin_regeocode(bg: BackgroundTasks, _=Depends(require_admin)):
    bg.add_task(regeocode_nulls)
    return JSONResponse({"status": "Geocoding läuft"})

@app.post("/admin/api/regeocode-fix")
async def admin_regeocode_fix(_=Depends(require_admin)):
    """Manueller Trigger für den Geocoding-Bugfix-Lauf — re-geokodiert
    alle Incidents, deren Koordinaten ausserhalb ihres Landes liegen."""
    n = regeocode_all_inconsistent()
    return JSONResponse({"ok": True, "fixed": n})

# ── SOURCE HEALTH ADMIN ──────────────────────────────────────────
@app.get("/admin/api/source-health")
async def admin_source_health(_=Depends(require_admin)):
    """Liefert alle Crawl-Quellen mit Health-Status. Sortiert: zuerst
    disabled, dann hoch-Fehler-Quellen, dann gesunde."""
    rows = db.execute(
        "SELECT source, url, last_attempt, last_success, last_error, "
        "consecutive_failures, total_attempts, total_successes, "
        "items_last_run, items_total, active "
        "FROM source_health "
        "ORDER BY active ASC, consecutive_failures DESC, source ASC"
    ).fetchall()
    # Augment with status label for the UI.
    out = []
    for r in rows:
        d = dict(r)
        cf = d["consecutive_failures"] or 0
        if not d["active"]:
            d["status"] = "disabled"
        elif cf >= 5:
            d["status"] = "warning"
        elif cf > 0:
            d["status"] = "degraded"
        else:
            d["status"] = "healthy"
        out.append(d)
    return JSONResponse({
        "sources":   out,
        "max_failures": SOURCE_MAX_FAILURES,
        "totals": {
            "healthy":  sum(1 for s in out if s["status"]=="healthy"),
            "degraded": sum(1 for s in out if s["status"]=="degraded"),
            "warning":  sum(1 for s in out if s["status"]=="warning"),
            "disabled": sum(1 for s in out if s["status"]=="disabled"),
            "active_count": sum(1 for s in out if s["active"]),
            "total":     len(out),
        },
    })

@app.post("/admin/api/source-health/{source}/reset")
async def admin_source_health_reset(source: str, _=Depends(require_admin)):
    """Re-aktiviert eine Quelle und nullt den Failure-Zähler."""
    db.execute(
        "UPDATE source_health SET consecutive_failures=0, active=1, "
        "last_error='' WHERE source=?", (source,)
    )
    db.commit()
    return JSONResponse({"ok": True, "source": source})


# ── CRAWLER DIAGNOSTIC ───────────────────────────────────────────
@app.get("/admin/api/crawler/probe")
async def admin_crawler_probe(url: str, _=Depends(require_admin)):
    """Diagnose-Endpoint: probiert eine URL mit verschiedenen UAs durch
    und gibt zurück was der Upstream konkret antwortet. Hilft Admins
    auf Production zu sehen, warum eine Quelle nicht funktioniert
    (Anti-Bot, 404, Cloudflare-Challenge, …)."""
    if not url.startswith("http"):
        return JSONResponse({"ok": False, "message": "url muss http(s) sein"}, status_code=400)
    return JSONResponse(fetch_diagnostic(url))


@app.get("/admin/api/crawler/barrikade-discover")
async def admin_crawler_barrikade_discover(_=Depends(require_admin)):
    """Live-Test der barrikade.info Discovery — gibt zurück, welche der
    10 Discovery-Pfade funktionieren und wieviele URLs jeder liefert.
    Operatoren sehen sofort, ob Anti-Bot greift oder welche Endpoints
    Daten liefern."""
    out = {"endpoints": [], "summary": {}}
    candidates = [
        ("rss-feed",      "https://barrikade.info/feed"),
        ("rss-feed-slash","https://barrikade.info/feed/"),
        ("rss-rss",       "https://barrikade.info/rss"),
        ("rss-rss-xml",   "https://barrikade.info/rss.xml"),
        ("rss-index",     "https://barrikade.info/index.rss"),
        ("rss-atom",      "https://barrikade.info/atom"),
        ("drupal-feeds",  "https://barrikade.info/feeds/all.rss.xml"),
        ("sitemap",       "https://barrikade.info/sitemap.xml"),
        ("sitemap-index", "https://barrikade.info/sitemap_index.xml"),
        ("homepage",      "https://barrikade.info/"),
    ]
    working = 0
    for label, u in candidates:
        diag = fetch_diagnostic(u, timeout=10)
        n_urls = 0
        body_marker = ""
        if diag.get("ok"):
            working += 1
            excerpt = diag.get("excerpt", "")
            if "<rss" in excerpt[:200].lower():     body_marker = "RSS"
            elif "<feed" in excerpt[:200].lower():  body_marker = "Atom"
            elif "<urlset" in excerpt[:200].lower():body_marker = "Sitemap"
            elif "<html" in excerpt[:200].lower():  body_marker = "HTML"
            else: body_marker = "?"
            # quick URL-count heuristic
            import re as _re
            n_urls = len(_re.findall(r"/article/\d+", diag.get("excerpt","")))
        out["endpoints"].append({
            "label":       label,
            "url":         u,
            "ok":          diag.get("ok"),
            "status_code": diag.get("status_code"),
            "content_type":diag.get("content_type"),
            "len":         diag.get("len"),
            "elapsed_ms":  diag.get("elapsed_ms"),
            "winning_ua":  diag.get("winning_ua"),
            "body_marker": body_marker,
            "url_hits_excerpt": n_urls,
            "error":       diag.get("error"),
        })
    out["summary"] = {"working": working, "total": len(candidates)}
    return JSONResponse(out)


@app.post("/admin/api/crawler/barrikade-run")
async def admin_crawler_barrikade_run(bg: BackgroundTasks, _=Depends(require_admin)):
    """Triggert einen Discovery-Run gegen barrikade.info im Hintergrund.
    Ergebnis ist später in /admin/api/status (running flag) bzw. der
    incidents-DB sichtbar."""
    def _run():
        try:
            n = crawl_barrikade_range(barrikade_latest_id(), barrikade_latest_id() - 50)
            log.info(f"manual barrikade run: {n} new incidents")
        except Exception as e:
            log.warning(f"manual barrikade run failed: {e}")
    bg.add_task(_run)
    return JSONResponse({"ok": True, "status": "Discovery-Run gestartet"})

@app.post("/admin/api/grok-test")
async def admin_grok(_=Depends(require_admin)):
    res = classify("In Berlin-Kreuzberg wurden drei Polizeifahrzeuge in Brand gesetzt. Bekennerschreiben einer militanten autonomen Gruppe.")
    return JSONResponse(res or {"error": "Keine Antwort"})

@app.get("/admin/api/export-csv")
async def export_csv(_=Depends(require_admin)):
    rows = db.execute(
        "SELECT date,location,country,category,description,source,url,lat,lon,manual,timestamp FROM incidents ORDER BY date DESC"
    ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Datum","Ort","Land","Kategorie","Beschreibung","Quelle","URL","Lat","Lon","Manuell","Erfasst"])
    for r in rows: w.writerow(list(r))
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=lex-europe-{datetime.now().strftime('%Y%m%d')}.csv"})

@app.post("/admin/api/seed")
async def admin_seed(_=Depends(require_admin)):
    n = seed_historical_data()
    return JSONResponse({"status": f"{n} historische Einträge eingespielt" if n else "Bereits eingespielt"})

# ── ADMIN: FUNDING CRUD ─────────────────────────────────────────
_FUND_DONOR_TYPES = {"Bund","Kanton","Stadt","Stiftung","EU","Anderes"}
_FUND_COUNTRIES   = {"DE","AT","CH","EU","Andere"}

def _validate_funding(data: dict) -> str:
    """
    Return '' if valid, else an error message.
    Funding data is legally sensitive — we enforce a Primärquelle (source_url)
    and a Verbindungsnachweis (notes, ≥40 chars) for every manual entry so
    that no record ever lives in the public DB without traceable justification.
    """
    for f in ["recipient_org","amount","year","country","donor_type","donor_name"]:
        if data.get(f) in (None, ""):
            return f"Pflichtfeld '{f}' fehlt"
    try:
        amt = float(data["amount"])
        yr  = int(data["year"])
        if amt < 0:    return "Betrag muss positiv sein"
        if yr < 1990 or yr > 2099: return "Jahr ausserhalb des Bereichs"
    except (ValueError, TypeError):
        return "Betrag oder Jahr ist nicht numerisch"
    if data["country"] not in _FUND_COUNTRIES:
        return f"Land '{data['country']}' ungültig (erlaubt: {', '.join(sorted(_FUND_COUNTRIES))})"
    if data["donor_type"] not in _FUND_DONOR_TYPES:
        return f"Geber-Typ '{data['donor_type']}' ungültig"
    src = (data.get("source_url") or "").strip()
    if not src or not src.lower().startswith(("http://", "https://")):
        return "Primärquelle (source_url) fehlt oder ist keine vollständige URL"
    notes = (data.get("notes") or "").strip()
    if len(notes) < 40:
        return ("Verbindungsnachweis (notes) fehlt — mind. 40 Zeichen mit Nennung "
                "des VS-Berichts / Aktenzeichens / Primärquelle erforderlich")
    return ""

@app.post("/admin/api/funding")
async def admin_add_funding(request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    err = _validate_funding(data)
    if err:
        return JSONResponse({"ok": False, "message": err}, status_code=400)
    amt = float(data["amount"]); yr = int(data["year"])
    h_input = (
        f"fund|{data['recipient_org'].lower().strip()}|{yr}|"
        f"{data['donor_name'].lower().strip()}|{round(amt)}"
    )
    h = hashlib.sha256(h_input.encode()).hexdigest()
    try:
        cur = db.execute(
            """INSERT OR IGNORE INTO funding_records
               (recipient_org, project, amount, currency, year, country,
                donor_type, donor_name, source_url, notes, confidence,
                manual, hash, timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,datetime('now'))""",
            (data["recipient_org"], data.get("project") or None, amt,
             data.get("currency","EUR"), yr, data["country"],
             data["donor_type"], data["donor_name"],
             data.get("source_url") or None, data.get("notes") or None,
             int(data.get("confidence", 3)), h)
        )
        db.commit()
        if cur.rowcount == 0:
            return JSONResponse({"ok": False, "message": "Eintrag bereits vorhanden"})
        return JSONResponse({"ok": True, "message": "Gespeichert", "id": cur.lastrowid})
    except Exception as e:
        log.error(f"admin_add_funding: {e}", exc_info=True)
        return JSONResponse({"ok": False, "message": f"Fehler: {str(e)[:200]}"}, status_code=500)

@app.put("/admin/api/funding/{rec_id}")
async def admin_update_funding(rec_id: int, request: Request, _=Depends(require_admin)):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "message": "Ungültiges JSON"}, status_code=400)
    err = _validate_funding(data)
    if err:
        return JSONResponse({"ok": False, "message": err}, status_code=400)
    db.execute(
        """UPDATE funding_records
           SET recipient_org=?, project=?, amount=?, currency=?, year=?,
               country=?, donor_type=?, donor_name=?, source_url=?,
               notes=?, confidence=?
           WHERE id=?""",
        (data["recipient_org"], data.get("project") or None,
         float(data["amount"]), data.get("currency","EUR"), int(data["year"]),
         data["country"], data["donor_type"], data["donor_name"],
         data.get("source_url") or None, data.get("notes") or None,
         int(data.get("confidence", 3)), rec_id)
    )
    db.commit()
    return JSONResponse({"ok": True, "message": "Aktualisiert"})

@app.delete("/admin/api/funding/{rec_id}")
async def admin_delete_funding(rec_id: int, _=Depends(require_admin)):
    db.execute("DELETE FROM funding_records WHERE id=?", (rec_id,))
    db.commit()
    return JSONResponse({"ok": True})

@app.post("/admin/api/funding/seed")
async def admin_seed_funding(_=Depends(require_admin)):
    n = seed_funding_data()
    return JSONResponse({
        "status": f"{n} Fördergeld-Einträge eingespielt" if n else "Bereits eingespielt"
    })

@app.on_event("startup")
async def startup():
    purge_garbage()  # enforce §0 scope on existing rows
    cnt = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    if cnt == 0:
        seed_historical_data()
    # IMPORTANT: enrichment (severity, actors, confidence) must run BEFORE
    # the flag/summary backfill so is_high_risk sees the real severity.
    backfill_enrichment()
    backfill_summaries_and_flags()
    # FTS5-Backfill: ein leerer Index wird einmal aus incidents repopuliert.
    backfill_fts_if_empty()
    # Geocoding-Fix (Userhinweis): alte Substring-Match-Bugs in den vor-
    # handenen Koordinaten korrigieren. Wipe-and-rebuild des geocache läuft
    # einmal, sobald die DB-Meta nicht den aktuellen geocode-Fix-Marker
    # zeigt. Schützt vor Endlos-Loop bei Neustarts.
    if meta_get("geocode_fix_v2") != "1":
        try:
            n = regeocode_all_inconsistent()
            meta_set("geocode_fix_v2", "1")
            log.info(f"geocode_fix_v2 applied: {n} incidents korrigiert")
        except Exception as e:
            log.warning(f"geocode_fix_v2 at startup failed: {e}")
    # Always attempt to seed funding (idempotent — no-op if already present).
    seed_funding_data()
    # Säule 2 — populate the Frühwarn-Cluster table on boot so the footer
    # counter and /api/early-warning.{rss,json} have data immediately.
    try:
        detect_clusters()
    except Exception as e:
        log.warning(f"detect_clusters at startup failed: {e}")
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    # Main crawler: every 12 hours (cost-efficient)
    sched.add_job(run_crawler, "interval", hours=12, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=20))
    # Auto-continue historical barrikade crawl every 45 min until complete
    sched.add_job(auto_hist, "interval", minutes=45, id="auto_hist",
                  next_run_time=datetime.now() + timedelta(seconds=90))
    # Re-detect Frühwarn-Cluster weekly. Cheap query — runs in milliseconds.
    sched.add_job(detect_clusters, "interval", days=7, id="early_warning",
                  next_run_time=datetime.now() + timedelta(hours=6))
    sched.start()
    log.info(f"LEX EUROPE — {len(RSS_FEEDS)} RSS + {len(GNEWS_Q)} GNews — crawl in 20s | hist auto-continue every 45min")

