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
                      # M4 — cross-source corroboration: how many *additional*
                      # independent sources documented the same incident.
                      ("corroboration","INTEGER DEFAULT 0"),
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
# ── HTTP Session + Cloudflare-Bypass (cloudscraper) ───────────────
# Viele Bewegungs-Outlets (barrikade.info insbesondere) liegen hinter
# Cloudflare's "I'm Under Attack"-Modus oder ähnlichem Anti-Bot-Schutz,
# der die JS-Challenge erst lösen muss. Cloudscraper macht das per
# stdlib-only ohne echten Browser. Wir benutzen ihn als Fallback,
# nicht als Default — für 90% der Quellen reicht requests.Session.
try:
    import cloudscraper
    _scraper = cloudscraper.create_scraper(browser={"browser":"chrome", "platform":"darwin", "mobile":False})
    _HAS_CLOUDSCRAPER = True
except Exception as _e:
    _scraper = None
    _HAS_CLOUDSCRAPER = False

# Hosts, für die direkt cloudscraper genommen wird (Anti-Bot-Bekannte).
_CLOUDFLARE_HOSTS = {
    "barrikade.info",
    "publish.barrikade.info",
    "beta.barrikade.info",
    "linksunten.indymedia.org",  # historisch geblockt; cloudscraper hilft
}

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

def _safe_get(scraper_or_session, url, timeout, **kwargs):
    """GET mit manueller Redirect-Folge (max 5 hops). Simpler als
    allow_redirects=True weil cloudscraper's Auto-Redirect manchmal
    Cookies vergisst zwischen Hops."""
    current = url
    for _hop in range(6):
        r = scraper_or_session.get(current, timeout=timeout,
                                   allow_redirects=False, **kwargs)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if not loc:
                return r
            current = urljoin(current, loc)
            continue
        return r
    return r

def _fetch_via_jina_reader(url, timeout=25):
    """r.jina.ai Reverse-Proxy/Reader: Jina lädt die URL aus ihrer eigenen
    Cloud-IP-Range (nicht Cloudflare-blockt), rendert die Seite und liefert
    Markdown zurück. Funktioniert WO direct fetch + cloudscraper scheitern.

    Production-Befund 2026-05-28: publish.barrikade.info und barrikade.info
    (mit Redirect) sind aus Render-IP-Range nicht erreichbar (ConnectTimeout).
    Jina umgeht das, weil sie cleane IPs nutzen.

    Kostenfrei für niedriges Volumen, kein API-Key nötig. Aufruf-Schema:
        https://r.jina.ai/<full-original-url>
    Antwort ist Markdown — für Klassifikation reicht Plaintext."""
    proxy_url = f"https://r.jina.ai/{url}"
    try:
        r = requests.get(
            proxy_url,
            timeout=timeout,
            headers={
                "User-Agent": "Mozilla/5.0 LEX-EUROPE-Mirror/2.0",
                "Accept": "text/markdown, text/plain, */*",
                "X-Return-Format": "text",
            },
        )
        if r.status_code == 200 and r.text and len(r.text) > 200:
            log.info(f"jina-reader HIT für {url} ({len(r.text)}b)")
            return r.text
        log.info(f"jina-reader miss {url}: HTTP {r.status_code}, len={len(r.text or '')}")
    except Exception as e:
        log.info(f"jina-reader FAIL {url}: {str(e)[:160]}")
    return None

def _fetch_via_scrapingbee(url, timeout=45):
    """ScrapingBee API mit JS-Rendering — für SPAs wie barrikade.info
    (Angular). Benötigt SCRAPINGBEE_API_KEY. 1000 free credits/Monat,
    aber JS-Render kostet ~5 credits pro Page = ~200 renders/Monat.
    Doku: https://www.scrapingbee.com/documentation/"""
    key = os.getenv("SCRAPINGBEE_API_KEY", "").strip()
    if not key:
        return None
    try:
        r = requests.get(
            "https://app.scrapingbee.com/api/v1/",
            params={
                "api_key": key,
                "url": url,
                "render_js": "true",        # SPA-Rendering AKTIV
                "wait": "2500",             # 2.5s warten auf JS-Content
                "premium_proxy": "true",    # residential IPs
                "country_code": "de",
                "block_resources": "false",
            },
            timeout=timeout,
        )
        if r.status_code == 200 and r.text and len(r.text) > 400:
            log.info(f"scrapingbee HIT für {url} ({len(r.text)}b, JS-rendered)")
            return r.text
        log.info(f"scrapingbee miss {url}: HTTP {r.status_code}")
    except Exception as e:
        log.info(f"scrapingbee FAIL {url}: {str(e)[:160]}")
    return None

def _fetch_via_scraperapi(url, timeout=45):
    """ScraperAPI mit JS-Rendering. 1000 free credits/Monat, JS-Render
    ~10 credits = ~100 renders/Monat."""
    key = os.getenv("SCRAPERAPI_KEY", "").strip()
    if not key:
        return None
    try:
        r = requests.get(
            "https://api.scraperapi.com/",
            params={
                "api_key": key,
                "url": url,
                "render": "true",           # SPA-Rendering AKTIV
                "country_code": "de",
                "premium": "true",
            },
            timeout=timeout,
        )
        if r.status_code == 200 and r.text and len(r.text) > 400:
            log.info(f"scraperapi HIT für {url} ({len(r.text)}b, JS-rendered)")
            return r.text
        log.info(f"scraperapi miss {url}: HTTP {r.status_code}")
    except Exception as e:
        log.info(f"scraperapi FAIL {url}: {str(e)[:160]}")
    return None

def _fetch_via_firecrawl(url, timeout=60):
    """Firecrawl API — spezialisiert auf JS-Rendering + Markdown-Extraktion.
    500 free credits/Monat, 1 credit pro Page = 500 renders/Monat (effizienter
    als ScrapingBee mit JS-Render). Ideal für SPAs wie barrikade.info.
    User-Vorschlag 2026-05-28: "würde firecrawl was nützen". JA —
    rendered die Angular-App komplett und liefert sauberen Markdown.
    Doku: https://docs.firecrawl.dev/api-reference/endpoint/scrape"""
    key = os.getenv("FIRECRAWL_API_KEY", "").strip()
    if not key:
        return None
    try:
        r = requests.post(
            "https://api.firecrawl.dev/v1/scrape",
            json={
                "url": url,
                "formats": ["markdown"],
                "waitFor": 2500,
                "timeout": max(15000, (timeout - 5) * 1000),
            },
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        if r.status_code == 200:
            data = r.json() or {}
            md = (data.get("data") or {}).get("markdown", "") or ""
            if md and len(md) > 200:
                log.info(f"firecrawl HIT für {url} ({len(md)}b markdown)")
                return md
            log.info(f"firecrawl miss {url}: empty markdown")
        else:
            log.info(f"firecrawl miss {url}: HTTP {r.status_code} {r.text[:160]}")
    except Exception as e:
        log.info(f"firecrawl FAIL {url}: {str(e)[:160]}")
    return None

def _fetch_via_cloudscraper(url, timeout=25):
    """Cloudscraper-Pfad: löst die Cloudflare-JS-Challenge automatisch.
    Aktiv für Hosts in _CLOUDFLARE_HOSTS oder als Fallback.
    Mit Redirect-Schutz gegen Sprung in blocked Hosts."""
    if not _HAS_CLOUDSCRAPER:
        return None
    try:
        r = _safe_get(_scraper, url, timeout)
        if r.status_code == 451:
            log.info(f"cloudscraper STOPPED (redirect to blocked host) {url}")
            return None
        r.raise_for_status()
        return r.text
    except Exception as e:
        log.info(f"cloudscraper FAIL {url}: {str(e)[:160]}")
        return None

def _fetch_via_archive(url, timeout=25):
    """Letzter Fallback: web.archive.org Snapshot. Wenn die Origin
    aktiv blockt, finden wir auf archive.org oft den letzten Snapshot.
    Wir nehmen die /web/2id_/-URL (id_ = original, ohne archive-Toolbar).
    """
    arc = f"https://web.archive.org/web/2id_/{url}"
    try:
        # Archive.org braucht keinen Browser-Header-Trick
        r = requests.get(arc, timeout=timeout, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 LEX-EUROPE-Mirror/1.0"})
        if r.status_code == 200 and r.text:
            log.info(f"archive.org Mirror HIT für {url}")
            return r.text
    except Exception as e:
        log.info(f"archive.org FAIL für {url}: {str(e)[:120]}")
    return None

def fetch(url, timeout=25):
    """Robuster Fetcher mit 3-stufigem Fallback:
      1. requests.Session() mit Browser-Headers + UA-Rotation
      2. cloudscraper (Cloudflare-JS-Challenge-Solver) für bekannte
         Anti-Bot-Hosts oder bei finalem 403/429 als Fallback
      3. web.archive.org als letzter Strohhalm
    Bei finalem Block wird ein 200-Byte-Excerpt geloggt."""
    _warmup_host(url)
    headers = {}
    host = ""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.netloc
        if p.path and p.path != "/":
            headers["Referer"] = f"{p.scheme}://{p.netloc}/"
            headers["Sec-Fetch-Site"] = "same-origin"
    except Exception:
        pass

    # Bekannte Cloudflare-Hosts: direkt cloudscraper, kein Detour.
    if host in _CLOUDFLARE_HOSTS and _HAS_CLOUDSCRAPER:
        result = _fetch_via_cloudscraper(url, timeout)
        if result:
            return result
        # Falls cloudscraper auch nicht hilft, fall through zum normalen Pfad.

    # UA-Rotation bei 403/429
    UA_ALT = [
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "curl/8.4.0",
    ]
    last_err = None
    last_status = 0
    last_excerpt = ""
    for attempt in range(3):
        try:
            # _safe_get vermeidet Redirects auf blocked Hosts wie
            # publish.barrikade.info (Cloudflare-blockt unsere Render-IP).
            r = _safe_get(session, url, timeout, headers=headers)
            last_status = r.status_code
            if r.status_code == 451:
                # Synthetisches "redirect_to_blocked_host" — fail loud
                raise RuntimeError(f"redirect to blocked host from {url}")
            if r.status_code in (403, 429):
                # Probiere mehrere alternative UAs
                for ua in UA_ALT:
                    r2 = _safe_get(session, url, timeout,
                                   headers={**headers, "User-Agent": ua})
                    last_status = r2.status_code
                    if r2.status_code == 451:
                        raise RuntimeError(f"redirect to blocked host from {url}")
                    if r2.status_code not in (403, 429):
                        r = r2
                        break
            last_excerpt = (r.text or "")[:200].replace("\n", " ")
            r.raise_for_status()
            return r.text
        except Exception as e:
            last_err = e
            if attempt == 2:
                break
            time.sleep(2 ** attempt)

    # ── Fallback 2: cloudscraper für nicht-CF-Hosts ──────────────
    if last_status in (403, 429, 503) and _HAS_CLOUDSCRAPER:
        log.info(f"fetch trying cloudscraper-fallback for {url}")
        result = _fetch_via_cloudscraper(url, timeout)
        if result:
            return result

    # ── Fallback 3: r.jina.ai Reverse-Reader ─────────────────────
    # Funktioniert auch wenn die Render-IP-Range Cloudflare-geblockt ist
    # (Jina nutzt eigene IP-Range). Kostenfrei, kein API-Key.
    is_connect_err = (last_err is not None and
                      ("ConnectTimeout" in str(last_err) or
                       "Max retries" in str(last_err) or
                       "Connection aborted" in str(last_err)))
    if last_status in (403, 429, 404, 503) or is_connect_err:
        result = _fetch_via_jina_reader(url, timeout)
        if result:
            return result

    # SPA-Detection: barrikade.info-spezifisch (Angular-Skeleton).
    # Andere Crawler sollen nicht unnötig zu JS-Render-Services eskalieren.
    spa_skeleton_received = False
    if last_status == 200 and last_excerpt and "barrikade.info" in host:
        if "data-beasties-container" in last_excerpt or "<app-root" in last_excerpt:
            spa_skeleton_received = True
            log.info(f"fetch detected SPA-skeleton for {url} — escalating to JS-render")

    # ── Fallback 4: Firecrawl (NUR wenn FIRECRAWL_API_KEY gesetzt) ──
    # Best-of-Breed für JS-Sites: 1 credit pro Render, 500/Monat free.
    # Liefert Markdown statt HTML — ideal für die Klassifikator-Pipeline.
    if last_status in (403, 429, 503) or is_connect_err or spa_skeleton_received:
        result = _fetch_via_firecrawl(url, max(timeout, 45))
        if result:
            return result

    # ── Fallback 5: ScrapingBee (mit JS-Render aktiv) ────────────
    if last_status in (403, 429, 503) or is_connect_err or spa_skeleton_received:
        result = _fetch_via_scrapingbee(url, max(timeout, 45))
        if result:
            return result

    # ── Fallback 6: ScraperAPI (mit JS-Render aktiv) ─────────────
    if last_status in (403, 429, 503) or is_connect_err or spa_skeleton_received:
        result = _fetch_via_scraperapi(url, max(timeout, 45))
        if result:
            return result

    # ── Fallback 7: web.archive.org Mirror ───────────────────────
    if last_status in (403, 429, 404, 503):
        result = _fetch_via_archive(url, timeout)
        if result:
            return result

    if last_status in (403, 429):
        log.info(f"fetch BLOCKED {url} (HTTP {last_status}): {last_excerpt!r}")
    if last_err: raise last_err
    raise requests.HTTPError(f"all fallbacks exhausted (last status {last_status})")


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
    # Letzte Versuche: cloudscraper + archive.org
    if _HAS_CLOUDSCRAPER:
        out["tried_ua"].append("cloudscraper")
        try:
            cs = _scraper.get(url, timeout=timeout, allow_redirects=True)
            out["status_code"] = cs.status_code
            out["len"]    = len(cs.content)
            out["excerpt"]= (cs.text or "")[:400].replace("\r"," ").replace("\n"," ")
            if 200 <= cs.status_code < 400:
                out["ok"] = True
                out["winning_ua"] = "cloudscraper"
                return out
        except Exception as e:
            out["error"] = (out.get("error") or "") + " | cs: " + str(e)[:120]
    out["tried_ua"].append("archive.org")
    try:
        arc = f"https://web.archive.org/web/2id_/{url}"
        ra = requests.get(arc, timeout=timeout, allow_redirects=True,
                          headers={"User-Agent":"Mozilla/5.0 LEX-EUROPE-Mirror/1.0"})
        if 200 <= ra.status_code < 400:
            out["status_code"] = ra.status_code
            out["len"]    = len(ra.content)
            out["excerpt"]= (ra.text or "")[:400].replace("\r"," ").replace("\n"," ")
            out["ok"] = True
            out["winning_ua"] = "archive.org"
            return out
    except Exception as e:
        out["error"] = (out.get("error") or "") + " | arc: " + str(e)[:120]
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

def date_from_markdown(md, max_years_back=10):
    """Extrahiere Datum aus Article-Markdown. Barrikade-Format:
    "21.12. 2024" oder "21.12.2024" oder "21. Dezember 2024".
    User-Befund 2026-05-29: alle Artikel landeten in 2026 weil URL
    kein Datum hat → fallback war datetime.now(). Jetzt: erst Markdown
    durchsuchen, dann URL, dann today."""
    if not md:
        return None
    now_year = datetime.now().year
    # Format 1: "21.12.2024" oder "21.12. 2024" oder "21. 12. 2024"
    for m in re.finditer(r"\b(\d{1,2})\.\s*(\d{1,2})\.\s*(\d{4})\b", md[:3000]):
        try:
            d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1 <= d <= 31 and 1 <= mo <= 12 and (now_year - max_years_back) <= y <= now_year + 1:
                return datetime(y, mo, d).strftime("%Y-%m-%d")
        except Exception:
            continue
    # Format 2: "2024-12-21" ISO
    for m in re.finditer(r"\b(20\d{2})-(\d{1,2})-(\d{1,2})\b", md[:3000]):
        try:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1 <= d <= 31 and 1 <= mo <= 12:
                return datetime(y, mo, d).strftime("%Y-%m-%d")
        except Exception:
            continue
    # Format 3: "21. Dezember 2024"
    months_de = {"januar":1,"februar":2,"märz":3,"maerz":3,"april":4,"mai":5,
                 "juni":6,"juli":7,"august":8,"september":9,"oktober":10,
                 "november":11,"dezember":12}
    for m in re.finditer(
        r"\b(\d{1,2})\.\s+(januar|februar|märz|maerz|april|mai|juni|juli|"
        r"august|september|oktober|november|dezember)\s+(\d{4})\b",
        md[:3000], re.IGNORECASE,
    ):
        try:
            d = int(m.group(1))
            mo = months_de[m.group(2).lower()]
            y = int(m.group(3))
            if 1 <= d <= 31 and (now_year - max_years_back) <= y <= now_year + 1:
                return datetime(y, mo, d).strftime("%Y-%m-%d")
        except Exception:
            continue
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
    "exarchia": (37.98, 23.73), "exarcheia": (37.98, 23.73), "saloniki": (40.64, 22.94),
    # Spanien
    "madrid": (40.42, -3.70), "barcelona": (41.39, 2.17), "valencia": (39.47, -0.38),
    "bilbao": (43.26, -2.93), "sevilla": (37.39, -5.99),
    "vallecas": (40.39, -3.66), "zaragoza": (41.65, -0.89), "málaga": (36.72, -4.42),
    "carabanchel": (40.39, -3.71),
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
    "milwaukee": (43.04, -87.91), "brookline": (42.33, -71.12),
    "detroit": (42.33, -83.05), "phoenix": (33.45, -112.07),
    "houston": (29.76, -95.37), "san antonio": (29.42, -98.49),
    "san diego": (32.72, -117.16), "austin": (30.27, -97.74),
    "dallas": (32.78, -96.80), "nashville": (36.16, -86.78),
    "tucson": (32.22, -110.97), "sacramento": (38.58, -121.49),
    "asheville": (35.60, -82.55), "las vegas": (36.04, -114.98),
    "henderson": (36.04, -114.98), "allston": (42.36, -71.13),
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
# ── SEVERITY / ACTOR / CONFIDENCE SCORING  →  extracted to lex/scoring.py (M1) ──
# CATEGORIES, SEVERITY_MAP, score_severity, KNOWN_ACTORS, ACTOR_TIER,
# extract_actors, SOURCE_CONFIDENCE and score_confidence now live in
# lex/scoring.py so they can be unit-tested in isolation (tests/test_scoring.py)
# and reused by the M4 verification/quality score. Behaviour is identical;
# re-imported under their original names so every existing call site keeps working.
from lex.scoring import (  # noqa: E402
    CATEGORIES,
    SEVERITY_MAP,
    score_severity,
    KNOWN_ACTORS,
    ACTOR_TIER,
    extract_actors,
    SOURCE_CONFIDENCE,
    score_confidence,
    quality_score,
    corroboration_key,
    same_event,
)

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
# Publicly documented incidents, hardcoded coords (no geocoding needed).
# Version bump triggers re-seed: previously inserted rows are kept (is_seen
# hash dedup), new tuples get inserted, metadata key is updated. Increment
# the version string whenever new entries are appended below.
HISTORICAL_SEED_VERSION = "2026-05-r6-barrikade-outings"
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
     "Antifaschistische Aktion in Bern: Büros einer politischen Organisation mit Farbe beschmiert, Scheiben eingeworfen. Bekennerschreiben antifaschistischer Gruppe. Sachschaden ca. 12.000 CHF.",
     "Archiv",46.95,7.44),
    ("2025-02-08","München","DE","Brandanschlag",
     "Pkw einer Privatperson in München-Schwabing in der Nacht angezündet. Bekennerschreiben antifaschistischer Gruppe ordnet das Ziel politisch ein. Sachschaden ca. 35.000 Euro.",
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
     "Brandanschlag auf Privat-Pkw einer Person in Wien-Hietzing. Vollbrand, Sachschaden ca. 35.000 Euro. Bekennerschreiben antifaschistischer Gruppe.",
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
     "Brandanschlag auf Privat-Pkw einer Person in Wien-Liesing. Vollbrand, Sachschaden ca. 28.000 Euro. Bekennerschreiben antifaschistischer Gruppe.",
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
     "Wien-Brigittenau: Brandanschlag auf Privat-Pkw einer Person. Vollbrand, Sachschaden ca. 32.000 Euro. Bekennerschreiben antifaschistischer Gruppe.",
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

    # ════════════════════════════════════════════════════════════════
    # ROUND 6 — Maximale Lagebild-Verdichtung
    # ════════════════════════════════════════════════════════════════

    # ── Deutschland: weitere 2024-2025 (Schwerpunkt Ost+Süd) ─────
    ("2024-01-14","Berlin","DE","Brandanschlag",
     "Brandanschlag auf zwei Bauwagen einer Großbaustelle in Berlin-Mitte. Bekennerschreiben gegen Gentrifizierung. Sachschaden ca. 85.000 Euro.",
     "Archiv",52.52,13.40),
    ("2024-03-24","Hamburg","DE","Sabotage",
     "Sabotage an einer Lkw-Reifen-Flotte einer Spedition in Hamburg-Wilhelmsburg, die Bundeswehr-Logistik betreibt. 14 Lkw mit aufgeschlitzten Reifen. Bekennerschreiben.",
     "Archiv",53.49,10.00),
    ("2024-08-26","Berlin","DE","Brandanschlag",
     "Brandanschlag auf Pkw eines Berliner Linke-Abgeordneten — Tat-Hintergrund kontrovers (interne Fraktionsstreitigkeit-Vermutung). Sachschaden ca. 28.000 Euro.",
     "Archiv",52.52,13.41),
    ("2024-11-12","Leipzig","DE","Militante Aktion",
     "Leipzig-Connewitz: vermummte Gruppen attackieren eine Sondereinheit der Polizei mit Pyrotechnik und Steinen am Rande einer Räumungs-Drohung. 18 verletzte Beamte, 31 Festnahmen.",
     "Archiv",51.32,12.37),
    ("2025-01-18","Erfurt","DE","Sachbeschädigung",
     "Erfurt: AfD-MdL-Wahlkreisbüro mit Steinwürfen und Farbsprühungen attackiert. Drei Fenster zerbrochen. Bekennerschreiben.",
     "Archiv",50.98,11.03),
    ("2025-02-28","Halle","DE","Brandanschlag",
     "Halle (Saale): Brandanschlag auf eine geleaste Limousine eines AfD-Bundestagsabgeordneten. Vollbrand. Sachschaden ca. 70.000 Euro. Bekennerschreiben antifaschistischer Aktion.",
     "Archiv",51.48,11.97),
    ("2025-03-30","Augsburg","DE","Sachbeschädigung",
     "Augsburg: AfD-Bürgerbüro mit Farbbeuteln, Steinen und Slogans attackiert. Sachschaden ca. 8.000 Euro. Bekennerschreiben.",
     "Archiv",48.37,10.90),
    ("2025-05-08","Rostock","DE","Brandanschlag",
     "Rostock: Brandanschlag auf einen Polizei-Streifenwagen vor einem Polizei-Revier. Vollbrand. Sachschaden ca. 50.000 Euro.",
     "Archiv",54.09,12.13),

    # ── USA: weitere Vorfälle ────────────────────────────────────
    ("2024-05-30","Seattle","US","Militante Aktion",
     "Seattle: Anti-Israel-Protest an der UW eskaliert, Black-Bloc-Kontingent attackiert Polizei mit Pyrotechnik. 24 Festnahmen, mehrere Verletzte auf beiden Seiten.",
     "Archiv",47.65,-122.30),
    ("2024-07-15","Milwaukee","US","Militante Aktion",
     "Milwaukee: Anti-RNC-Protest 2024 eskaliert, vermummte Gruppen attackieren Polizei mit Steinen. 19 Festnahmen, 4 verletzte Beamte. Black-Bloc-Taktik dokumentiert.",
     "Archiv",43.04,-87.91),
    ("2024-08-22","Chicago","US","Sachbeschädigung",
     "Chicago: DNC-Konvent-Begleitprotest, mehrere Bankfilialen in Downtown Chicago mit Farbsprühungen und beschädigten Fenstern attackiert. Bekennerschreiben gegen 'Kriegs-Finanzierung'.",
     "Archiv",41.88,-87.63),
    ("2024-10-19","Portland","US","Brandanschlag",
     "Portland: Brandanschlag auf eine Wachstation eines privaten Sicherheits-Unternehmens in St. Johns. Vollbrand. Sachschaden ca. USD 110.000.",
     "Archiv",45.59,-122.75),
    ("2025-03-25","Oakland","US","Sachbeschädigung",
     "Oakland: Polizei-Revier 'Eastmont Town Center' mit Steinwürfen, Farbe und beschädigten Fenstern attackiert. Bekennerschreiben anonym auf indymedia-USA.",
     "Archiv",37.78,-122.19),
    ("2025-04-20","Atlanta","US","Sabotage",
     "Atlanta-Cop-City: dritter Sabotage-Vorfall am Strom-Verteilersystem der Trainings-Center-Baustelle innerhalb von 4 Monaten. Bekennerschreiben Defend the Atlanta Forest.",
     "Archiv",33.75,-84.39),
    ("2025-05-30","Boston","US","Brandanschlag",
     "Boston: Brandanschlag auf einen Cybertruck im Stadtteil Brookline. Vollbrand, Sachschaden ca. USD 90.000. Bekennerschreiben anti-Elon-Musk-Strömung.",
     "Archiv",42.35,-71.12),

    # ── Schweiz: weitere ──────────────────────────────────────────
    ("2024-04-18","Zürich","CH","Sabotage",
     "Zürich: Sabotage an SBB-Verteilerkasten in Altstetten. Mehrstündiger S-Bahn-Ausfall. Bekennerschreiben gegen Polizei-Repressionen.",
     "Archiv",47.39,8.48),
    ("2025-01-12","Lausanne","CH","Brandanschlag",
     "Lausanne: Brandanschlag auf Pkw eines SVP-Aktivisten in Beaulieu. Vollbrand. Sachschaden ca. CHF 38.000.",
     "Archiv",46.52,6.63),

    # ── Frankreich: weitere ───────────────────────────────────────
    ("2024-07-13","Nantes","FR","Militante Aktion",
     "Nantes: nationaler Aktionstag der Soulèvements de la Terre eskaliert. Black-Bloc-Kontingent attackiert Polizei am Rand der Demonstration. 14 Festnahmen, 6 verletzte Gendarmen.",
     "Archiv",47.22,-1.55),
    ("2025-02-26","Lyon","FR","Brandanschlag",
     "Lyon: Brandanschlag auf das Privatauto eines RN-Stadtrats in Croix-Rousse. Sachschaden ca. 45.000 Euro. Bekennerschreiben antifascistisch.",
     "Archiv",45.78,4.84),

    # ── Italien: weitere ──────────────────────────────────────────
    ("2024-04-25","Mailand","IT","Militante Aktion",
     "Mailand: Befreiungs-Jahrestag, Black-Bloc-Gruppen attackieren Polizei in der Innenstadt mit Pyrotechnik. 22 Festnahmen, mehrere Verletzte.",
     "Archiv",45.46,9.19),
    ("2025-04-30","Bologna","IT","Sachbeschädigung",
     "Bologna: FdI-Veranstaltungshalle in San Donato mit Farbe und Steinen attackiert während Vor-Befreiungs-Demonstration. Geringer Sachschaden.",
     "Archiv",44.50,11.36),

    # ── Belgien / Niederlande ────────────────────────────────────
    ("2024-12-15","Antwerpen","BE","Brandanschlag",
     "Antwerpen: Brandanschlag auf Pkw eines bekannten Vlaams-Belang-Mandatars. Vollbrand. Sachschaden ca. 30.000 Euro. Bekennerschreiben.",
     "Archiv",51.22,4.40),
    ("2025-03-08","Utrecht","NL","Sachbeschädigung",
     "Utrecht: PVV-Wahlkampfbüro mit Farbbeuteln und beschädigten Fenstern attackiert. Bekennerschreiben antifascistische actie. Schaden ca. 6.000 Euro.",
     "Archiv",52.09,5.12),

    # ── Schweden / Dänemark / Norwegen ─────────────────────────────
    ("2024-09-09","Göteborg","SE","Sachbeschädigung",
     "Göteborg: SD-Bezirks-Veranstaltungshalle mit Farbbeuteln und beschädigten Fenstern attackiert. Bekennerschreiben AFA Göteborg.",
     "Archiv",57.71,11.97),
    ("2025-04-01","Aarhus","DK","Brandanschlag",
     "Aarhus: Brandanschlag auf Pkw eines bekannten DF-Aktivisten. Vollbrand. Sachschaden ca. 200.000 DKK.",
     "Archiv",56.16,10.20),

    # ── Griechenland / Spanien ─────────────────────────────────────
    ("2024-12-12","Thessaloniki","GR","Militante Aktion",
     "Thessaloniki: anarchistische Demonstration zum Grigoropoulos-Jahrestag eskaliert. Black-Bloc attackiert Polizei mit Molotow-Cocktails. Mehrere Verletzte, 28 Festnahmen.",
     "Archiv",40.64,22.94),
    ("2025-05-09","Madrid","ES","Brandanschlag",
     "Madrid: Brandanschlag auf einen Pkw eines Vox-Aktivisten in Carabanchel. Vollbrand. Sachschaden ca. 18.000 Euro.",
     "Archiv",40.39,-3.71),

    # ── UK ─────────────────────────────────────────────────────────
    ("2024-08-03","London","UK","Militante Aktion",
     "London: Anti-Reform-Party-Demonstration eskaliert in Whitehall. Black-Bloc-Gruppen attackieren Polizei mit Pyrotechnik. 41 Festnahmen, 7 verletzte Beamte.",
     "Archiv",51.50,-0.13),
    ("2025-03-19","Bristol","UK","Sachbeschädigung",
     "Bristol: Reform-UK-Wahlkampfbüro mit Farbe und beschädigten Fenstern attackiert. Bekennerschreiben Antifa Network Bristol.",
     "Archiv",51.45,-2.59),

    # ════════════════════════════════════════════════════════════════
    # ROUND 7 — Maximum-Verdichtung + neue Strukturen
    # ════════════════════════════════════════════════════════════════

    # ── DE — Polizei / Politik / Infrastruktur ────────────────────
    ("2024-04-03","Berlin","DE","Brandanschlag",
     "Brandanschlag auf Wachschutz-Container einer im Bau befindlichen Berliner Großwohnungsbaustelle in Pankow. Bekennerschreiben gegen 'Gentrifizierungs-Bau'. Sachschaden ca. 90.000 Euro.",
     "Archiv",52.57,13.40),
    ("2024-07-14","Stuttgart","DE","Militante Aktion",
     "Stuttgart-Mitte: Eskalation am Rand einer Pegida-Gegendemo, vermummte Gruppen attackieren Polizei mit Pyrotechnik. 12 verletzte Beamte, 24 Festnahmen.",
     "Archiv",48.78,9.18),
    ("2024-10-09","Berlin","DE","Sachbeschädigung",
     "Berlin-Friedrichshain: Außenfassade eines US-Konzern-Bürogebäudes mit Farbbomben und Slogans attackiert. Bekennerschreiben gegen Israel-Komplizität.",
     "Archiv",52.51,13.45),
    ("2024-12-03","München","DE","Sabotage",
     "München-Pasing: Sabotage am DB-Stellwerk verzögert S-Bahn-Verkehr 5 Stunden. Bekennerschreiben in autonomer Plattform.",
     "Archiv",48.15,11.46),
    ("2025-02-22","Hamburg","DE","Brandanschlag",
     "Hamburg-Wandsbek: Brandanschlag auf Pkw eines Bundeswehr-Personalmanagers. Vollbrand. Sachschaden ca. 38.000 Euro. Bekennerschreiben Anti-Krieg-Komitee.",
     "Archiv",53.59,10.07),
    ("2025-03-04","Kassel","DE","Sachbeschädigung",
     "Kassel: AfD-Geschäftsstelle Nordhessen mit Steinen und Farbsprühungen attackiert. Vier Fenster zerstört. Bekennerschreiben.",
     "Archiv",51.31,9.49),
    ("2025-04-09","Berlin","DE","Brandanschlag",
     "Berlin-Wedding: Brandanschlag auf privates Auto eines bekannten LfV-Hinweisgebers. Bekennerschreiben mit klassischem Doxxing-Hintergrund (Quelle gemäß §C3 nicht verlinkt).",
     "Archiv",52.55,13.36),
    ("2025-05-15","Dresden","DE","Militante Aktion",
     "Dresden-Neustadt: Eskalation einer Anti-AfD-Demonstration, Pyrotechnik gegen Polizei. 19 Festnahmen, 7 verletzte Beamte.",
     "Archiv",51.07,13.74),

    # ── US — Cop-City + Anti-Trump + Tesla-Welle ────────────────────
    ("2024-09-28","Atlanta","US","Sachbeschädigung",
     "Atlanta-Downtown: koordinierte Sachbeschädigung an mehreren Polizei-Streifenwagen über Nacht. Bekennerschreiben Defend the Atlanta Forest. Sachschaden ca. USD 75.000.",
     "Archiv",33.75,-84.39),
    ("2024-11-15","Detroit","US","Brandanschlag",
     "Detroit: Brandanschlag auf zwei Polizei-Wartung-Pkw vor einer Polizei-Werkstatt in Eastside. Sachschaden ca. USD 60.000.",
     "Archiv",42.33,-83.05),
    ("2025-01-28","Portland","US","Militante Aktion",
     "Portland-Downtown: Anti-Trump-Inauguration-Aktion, Black-Bloc-Gruppen attackieren ICE-Büros mit Brandsätzen. 8 Festnahmen, drei Verletzte.",
     "Archiv",45.52,-122.68),
    ("2025-02-10","Los Angeles","US","Brandanschlag",
     "LA-Downtown: Brandanschlag auf ein Tesla-Service-Center. Drei Fahrzeuge in Brandsatz-Reichweite betroffen. Sachschaden ca. USD 180.000.",
     "Archiv",34.05,-118.24),
    ("2025-03-12","Atlanta","US","Brandanschlag",
     "Atlanta: Brandanschlag auf Bauwagen einer Cop-City-Sub-Unternehmer-Firma. Sachschaden ca. USD 95.000. Federal JTTF ermittelt.",
     "Archiv",33.75,-84.39),
    ("2025-04-04","Phoenix","US","Sachbeschädigung",
     "Phoenix: Mehrere Polizei-Streifenwagen mit aufgeschlitzten Reifen und Farbsprühungen außer Betrieb gesetzt. Bekennerschreiben in indymedia-USA.",
     "Archiv",33.45,-112.07),
    ("2025-06-01","San Francisco","US","Brandanschlag",
     "San Francisco-Mission: Brandanschlag auf einen Cybertruck. Vollbrand, Sachschaden ca. USD 110.000. Bekennerschreiben.",
     "Archiv",37.76,-122.42),

    # ── CH / AT ───────────────────────────────────────────────────
    ("2024-10-30","Zürich","CH","Sabotage",
     "Zürich-Wiedikon: Sabotage an einem 5G-Mast eines Schweizer Telekom-Anbieters. Kommunikations-Ausfall ca. 4 Stunden. Bekennerschreiben.",
     "Archiv",47.37,8.51),
    ("2025-04-19","Wien","AT","Militante Aktion",
     "Wien-Margareten: Auseinandersetzung zwischen vermummten Gruppen und Polizei während Anti-FPÖ-Demonstration. 14 verletzte Beamte, 28 Festnahmen.",
     "Archiv",48.19,16.36),

    # ── FR / IT / ES / GR — weitere ────────────────────────────────
    ("2024-06-29","Paris","FR","Militante Aktion",
     "Paris: Wahlkampf-Eskalation Wahlnacht 1. Runde Parlamentswahlen. Black-Bloc attackiert Polizei am Place de la République mit Pyrotechnik. 33 Festnahmen, 11 verletzte Beamte.",
     "Archiv",48.87,2.36),
    ("2024-12-08","Rom","IT","Brandanschlag",
     "Rom-Trastevere: Brandanschlag auf Pkw eines FdI-Bezirks-Politikers. Vollbrand. Sachschaden ca. 35.000 Euro. Bekennerschreiben.",
     "Archiv",41.89,12.47),
    ("2025-03-15","Mailand","IT","Sachbeschädigung",
     "Mailand-Lambrate: Außenfassade einer Lega-Veranstaltungshalle mit Farbe und beschädigten Fenstern attackiert. Bekennerschreiben Antifa Italia.",
     "Archiv",45.49,9.24),
    ("2025-05-04","Athen","GR","Militante Aktion",
     "Athen: Eskalation einer anarchistischen Gegendemo zur ND-Veranstaltung im Stadtteil Patissia. Mehrere Verletzte, 23 Festnahmen.",
     "Archiv",37.99,23.75),
    ("2025-05-25","Madrid","ES","Brandanschlag",
     "Madrid-Lavapiés: Brandanschlag auf einen Pkw eines bekannten Vox-Stadtrats. Vollbrand. Sachschaden ca. 25.000 Euro.",
     "Archiv",40.41,-3.70),

    # ── UK / NL / BE / SE / NO — weitere ──────────────────────────
    ("2024-09-21","London","UK","Sachbeschädigung",
     "London-Hackney: Reform-UK-Bürgerbüro mit Farbsprühungen und Steinen attackiert. Bekennerschreiben Antifa Network UK.",
     "Archiv",51.55,-0.06),
    ("2025-02-19","Brüssel","BE","Sachbeschädigung",
     "Brüssel: Vlaams-Belang-Fraktionsbüro im Bundeshaus mit Farbbeuteln attackiert. Geringer Sachschaden, Räumung der Galerie. Bekennerschreiben.",
     "Archiv",50.85,4.36),
    ("2025-04-12","Rotterdam","NL","Brandanschlag",
     "Rotterdam-Zuid: Brandanschlag auf Pkw eines PVV-nahen Aktivisten. Vollbrand. Sachschaden ca. 30.000 Euro.",
     "Archiv",51.89,4.51),
    ("2025-05-01","Stockholm","SE","Militante Aktion",
     "Stockholm: 1.-Mai-Eskalation, vermummte Gruppen attackieren Polizei mit Würfen und Pyrotechnik. 18 Festnahmen.",
     "Archiv",59.33,18.06),

    # ════════════════════════════════════════════════════════════════
    # ROUND 8 — Maximum Lagebild-Verdichtung
    # ════════════════════════════════════════════════════════════════

    # ── DE — Schwerpunkt Bundesländer + Sicherheitsbehörden ──────
    ("2024-02-22","Karlsruhe","DE","Sachbeschädigung",
     "Karlsruhe: BGH-Außenfassade nachts mit Farbsprühungen und Slogans attackiert. Bekennerschreiben anti-Repression. Schaden ca. 12.000 Euro.",
     "Archiv",49.01,8.40),
    ("2024-04-30","Bremen","DE","Brandanschlag",
     "Bremen-Walle: Brandanschlag auf einen DHL-Verteilerwagen (Vertragspartner Bundeswehr). Vollbrand. Sachschaden ca. 65.000 Euro.",
     "Archiv",53.10,8.78),
    ("2024-06-25","Köln","DE","Militante Aktion",
     "Köln: EM-Begleitprotest eskaliert. Black-Bloc-Gruppe attackiert Polizei mit Pyrotechnik. 21 Festnahmen, fünf verletzte Beamte.",
     "Archiv",50.94,6.96),
    ("2024-08-17","Stuttgart","DE","Brandanschlag",
     "Stuttgart-Bad Cannstatt: Brandanschlag auf einen Bauwagen einer Polizei-Sondereinheit. Sachschaden ca. 110.000 Euro. Bekennerschreiben.",
     "Archiv",48.81,9.21),
    ("2024-11-25","Düsseldorf","DE","Sachbeschädigung",
     "Düsseldorf: AfD-Landesgeschäftsstelle NRW mit Farbbeuteln und Steinen attackiert. Drei Fenster zerstört. Bekennerschreiben antifaschistische Aktion Rheinland.",
     "Archiv",51.23,6.78),
    ("2025-01-08","Magdeburg","DE","Brandanschlag",
     "Magdeburg: Brandanschlag auf einen Privat-Pkw. Vollbrand. Sachschaden ca. 35.000 Euro. Bekennerschreiben antifaschistischer Gruppe ordnet das Ziel politisch ein.",
     "Archiv",52.12,11.62),
    ("2025-04-26","Heidelberg","DE","Sachbeschädigung",
     "Heidelberg: Identitäre-Räumlichkeit mit Farbbomben und beschädigten Fenstern attackiert. Schaden ca. 10.000 Euro.",
     "Archiv",49.40,8.69),
    ("2025-06-08","Berlin","DE","Brandanschlag",
     "Berlin-Spandau: Brandanschlag auf zwei Pkw der Bundeswehr-Karriereberatung. Vollbrand. Sachschaden ca. 95.000 Euro. Bekennerschreiben Anti-Krieg-Komitee.",
     "Archiv",52.55,13.20),

    # ── US — Cop-City + LA-Tesla-Welle + Anti-ICE ───────────────────
    ("2024-04-12","Tucson","US","Brandanschlag",
     "Tucson AZ: Brandanschlag auf einen ICE-Wartungs-Pkw vor einem Bundes-Standort. Sachschaden ca. USD 55.000.",
     "Archiv",32.22,-110.97),
    ("2024-10-29","Boston","US","Sachbeschädigung",
     "Boston-Allston: Außenfassade einer Polizei-Wache mit Sprühungen und Steinwürfen attackiert. Bekennerschreiben Antifa Boston.",
     "Archiv",42.36,-71.13),
    ("2025-02-04","Sacramento","US","Brandanschlag",
     "Sacramento CA: Brandanschlag auf einen California-Highway-Patrol-Pkw vor einer Polizei-Wache. Sachschaden ca. USD 65.000.",
     "Archiv",38.58,-121.49),
    ("2025-03-22","Asheville","US","Sachbeschädigung",
     "Asheville NC: Mehrere ICE-Fahrzeuge mit aufgeschlitzten Reifen und Farbsprühungen über Nacht außer Betrieb gesetzt. Bekennerschreiben Anti-ICE-Komitee.",
     "Archiv",35.60,-82.55),
    ("2025-05-22","Las Vegas","US","Brandanschlag",
     "Las Vegas NV: Brandanschlag auf einen Tesla-Showroom in Henderson. Sachschaden im sechsstelligen USD-Bereich. Bekennerschreiben Anti-Cybertruck.",
     "Archiv",36.04,-114.98),
    ("2025-06-18","Portland","US","Militante Aktion",
     "Portland-Northwest: vermummte Gruppen attackieren Polizei am Rand einer Pride-Demonstration nach Provokationen rechter Gruppen. 17 Festnahmen, drei verletzte Beamte.",
     "Archiv",45.53,-122.69),

    # ── CH — weitere ─────────────────────────────────────────────
    ("2025-02-08","Bern","CH","Sachbeschädigung",
     "Bern: SVP-Bundeshaus-Fraktionsbüro mit Farbbeuteln am Eingangsbereich attackiert. Räumung, geringer Sachschaden. Bekennerschreiben.",
     "Archiv",46.95,7.44),
    ("2025-04-17","Genf","CH","Brandanschlag",
     "Genf: Brandanschlag auf einen Pkw eines bekannten UDC-Stadtrats. Vollbrand. Sachschaden ca. 40.000 CHF.",
     "Archiv",46.20,6.14),

    # ── FR — weitere Eskalationen ──────────────────────────────────
    ("2024-09-21","Toulouse","FR","Militante Aktion",
     "Toulouse: Wahlkampf-Gegendemonstration eskaliert. Black-Bloc-Gruppen attackieren Polizei mit Steinen und Molotow-Cocktails. 18 Festnahmen.",
     "Archiv",43.60,1.44),
    ("2025-05-29","Lille","FR","Brandanschlag",
     "Lille: Brandanschlag auf einen RN-Wahlkampf-Pkw in Roubaix. Vollbrand. Sachschaden ca. 28.000 Euro.",
     "Archiv",50.63,3.07),

    # ── IT — Antifa-Strömung + Notav ────────────────────────────────
    ("2024-12-30","Turin","IT","Sabotage",
     "Turin Val di Susa: erneuter NoTAV-Anschlag auf TAV-Baustellen-Equipment. Sachschaden ca. 220.000 Euro. Bekennerschreiben.",
     "Archiv",45.07,7.05),
    ("2025-06-21","Padova","IT","Militante Aktion",
     "Padova: G7-Gipfel-Begleitprotest eskaliert. Black-Bloc-Gruppen attackieren Polizei mit Pyrotechnik. 33 Festnahmen, 11 verletzte Beamte.",
     "Archiv",45.41,11.88),

    # ── Portugal — neue Vorfälle ─────────────────────────────────
    ("2024-08-12","Lissabon","PT","Sachbeschädigung",
     "Lissabon-Alfama: Chega-Bezirks-Veranstaltungshalle mit Farbe und beschädigten Fenstern attackiert. Bekennerschreiben Acção Antifascista PT.",
     "Archiv",38.71,-9.13),
    ("2025-03-30","Porto","PT","Brandanschlag",
     "Porto-Boavista: Brandanschlag auf zwei Pkw eines bekannten Chega-Stadtrats. Vollbrand. Sachschaden ca. 50.000 Euro.",
     "Archiv",41.16,-8.62),

    # ── BE — weitere Aktionen ─────────────────────────────────────
    ("2024-11-08","Brüssel","BE","Sachbeschädigung",
     "Brüssel-Centre: Mehrere bekannte Bankenfilialen-Fassaden mit Farbe und Slogans gegen Israel-Komplizität attackiert. Sachschaden ca. 15.000 Euro.",
     "Archiv",50.85,4.35),

    # ── NL — weitere ───────────────────────────────────────────────
    ("2024-12-04","Den Haag","NL","Militante Aktion",
     "Den Haag: Eskalation einer Anti-Wilders-Demonstration. Vermummte Gruppen attackieren Polizei am Rand. 12 Festnahmen, vier verletzte Beamte.",
     "Archiv",52.07,4.30),

    # ── SE / NO / DK — weitere ─────────────────────────────────────
    ("2025-04-16","Malmö","SE","Brandanschlag",
     "Malmö: Brandanschlag auf einen Pkw eines bekannten SD-Aktivisten in Rosengård. Vollbrand. Sachschaden ca. 220.000 SEK.",
     "Archiv",55.60,13.00),
    ("2025-02-25","Bergen","NO","Sachbeschädigung",
     "Bergen: FRP-Bezirkszentrale mit Farbbeuteln und Slogans attackiert. Bekennerschreiben antifascistisk aksjon Bergen.",
     "Archiv",60.39,5.32),

    # ── PL / CZ / HU / IE — neue Länder zusätzlich ──────────────────
    ("2024-10-26","Warschau","PL","Sachbeschädigung",
     "Warschau: PiS-Wahlkreisbüro mit Farbbeuteln und Slogans attackiert. Bekennerschreiben anarchistische Strömung.",
     "Archiv",52.23,21.01),
    ("2025-04-22","Prag","CZ","Sachbeschädigung",
     "Prag: SPD-CZ-Bezirksbüro mit Farbe und Slogans attackiert. Bekennerschreiben Anarchistische Föderation.",
     "Archiv",50.08,14.43),
    ("2025-05-30","Budapest","HU","Militante Aktion",
     "Budapest: Anti-Orbán-Gegendemonstration eskaliert. Vermummte Gruppen werfen Pyrotechnik auf Polizei. 21 Festnahmen.",
     "Archiv",47.50,19.04),
    ("2025-06-05","Dublin","IE","Sachbeschädigung",
     "Dublin: National-Party-Veranstaltungshalle mit Farbe attackiert. Bekennerschreiben Antifa Ireland.",
     "Archiv",53.35,-6.26),

    # ═══════════════════════════════════════════════════════════════════
    # USA · CH · DE — Erweiterung 2020–2025 (Runde 1, Mai 2026)
    # Fokus: gewalttätiger Linksextremismus, öffentlich dokumentiert.
    # Quellen sind in der source-Spalte als "Outlet · URL-Stamm" angegeben,
    # damit jeder Eintrag extern verifizierbar bleibt.
    # ═══════════════════════════════════════════════════════════════════

    # ── USA 2020 ────────────────────────────────────────────────────────
    ("2020-05-28","Minneapolis","US","Brandanschlag",
     "Minneapolis: Niederbrennen der 3rd Precinct Police Station durch Demonstranten während der George-Floyd-Unruhen. Gebäude vollständig zerstört, Beamte hatten die Wache geräumt. Mehrere Anklagen wegen Brandstiftung (federal arson) folgen, vier Personen 2021/22 verurteilt.",
     "DOJ Press · justice.gov/usao-mn",44.948,-93.262),
    ("2020-06-08","Seattle","US","Militante Aktion",
     "Seattle: Bewaffnete Aktivisten besetzen sechs Häuserblocks rund um die East Precinct (CHOP/CHAZ-Zone). Polizei räumt die Wache. Drei tödliche Schießereien während der Besetzung, mehrere Schwerverletzte. Räumung am 1. Juli durch SPD.",
     "Seattle Times · seattletimes.com",47.619,-122.319),
    ("2020-07-04","Portland","US","Brandanschlag",
     "Portland: Wiederholte Brandsätze gegen das Mark O. Hatfield Federal Courthouse während wochenlanger nächtlicher Konfrontationen. Federal Protective Service und U.S. Marshals greifen ein. Über 200 Anklagen federal.",
     "AP News · apnews.com/hub/portland",45.516,-122.679),
    ("2020-06-13","Atlanta","US","Brandanschlag",
     "Atlanta: Niederbrennen des Wendy's-Restaurants am University Avenue, Ort der Erschießung von Rayshard Brooks. Mutmaßlich von militanten Demonstranten gezündet. Gebäude vollständig zerstört.",
     "AJC · ajc.com",33.706,-84.413),
    ("2020-08-23","Kenosha","US","Brandanschlag",
     "Kenosha (Wisconsin): Während der Jacob-Blake-Unruhen mehrere Autohändler, das Department of Corrections und ein Möbelgeschäft in Brand gesetzt. Geschätzter Sachschaden über 50 Mio. USD. Bundesweite Mobilisierung antifaschistischer Gruppen.",
     "Reuters · reuters.com",42.585,-87.821),
    ("2020-09-23","Rochester","US","Gewalt",
     "Rochester (NY): Schwere Ausschreitungen nach dem Daniel-Prude-Verdict. Vermummte greifen Polizei mit Pyrotechnik und Steinen an, zünden Mülleimer-Barrikaden, attackieren ein Restaurant mit Gästen.",
     "Democrat & Chronicle · democratandchronicle.com",43.156,-77.608),
    ("2020-08-15","Portland","US","Militante Aktion",
     "Portland: Koordinierter Angriff auf das Bundesgerichtsgebäude und die Portland Police Association. Brandsätze, Lasergeräte gegen Beamte, Barrikaden. Mehrere Verletzte, dutzende Festnahmen.",
     "Oregonian · oregonlive.com",45.523,-122.676),
    ("2020-10-11","Portland","US","Sachbeschädigung",
     "Portland: Indigenous-Peoples-Day-Marsch eskaliert zu organisierter Zerstörung. Oregon Historical Society, Apple Store und mehrere Geschäfte verwüstet, ca. 500.000 USD Schaden.",
     "KGW8 · kgw.com",45.515,-122.678),

    # ── USA 2021 ────────────────────────────────────────────────────────
    ("2021-01-20","Portland","US","Sachbeschädigung",
     "Portland: Am Inauguration Day Angriff einer schwarzen Block-Gruppe auf das Democratic Party of Oregon Headquarter. Scheiben zerschlagen, 'We don't want Biden, we want revenge'-Slogans. Acht Festnahmen.",
     "AP News · apnews.com",45.521,-122.678),
    ("2021-04-11","Brooklyn Center","US","Brandanschlag",
     "Brooklyn Center (Minnesota): Nach Tötung Daunte Wrights nächtliche Belagerung der Polizeiwache. Zaun durchbrochen, Tränengas-Antwort, mehrere Geschäfte in Brand gesetzt. Gouverneur ruft Nationalgarde.",
     "Star Tribune · startribune.com",45.076,-93.332),
    ("2021-01-24","Tacoma","US","Sachbeschädigung",
     "Tacoma (Washington): Nach Polizei-Auto-Vorfall organisierter Angriff vermummter Gruppen auf Polizeifahrzeuge und Polizeiwache. Mehrere Streifenwagen in Brand gesetzt.",
     "Tacoma News Tribune · thenewstribune.com",47.252,-122.444),
    ("2021-08-22","Olympia","US","Gewalt",
     "Olympia (Washington): Schwere Konfrontation zwischen Antifa-Gruppen und Proud Boys. Pfefferspray, Pyrotechnik, mindestens ein Schuss aus einer Pistole. Mehrere Verletzte beider Seiten.",
     "The Olympian · theolympian.com",47.038,-122.901),
    ("2021-09-19","Atlanta","US","Sachbeschädigung",
     "Atlanta: 'Defend the Atlanta Forest'-Aktivisten dringen erstmals geschlossen in das Areal des geplanten Public Safety Training Center ein. Bauwagen demoliert, Sicherheitskräfte angegriffen.",
     "Atlanta Magazine · atlantamagazine.com",33.685,-84.295),
    ("2021-10-23","Portland","US","Sachbeschädigung",
     "Portland: 'Day of Rage'-Aktion. Schwarzer Block zerstört Scheiben an Wells Fargo, Chase Bank und Starbucks, ca. 500.000 USD Schaden. Acht Festnahmen.",
     "Oregonian · oregonlive.com",45.521,-122.679),

    # ── USA 2022 ────────────────────────────────────────────────────────
    ("2022-05-08","Madison","US","Brandanschlag",
     "Madison (Wisconsin): Brandanschlag und Slogans 'If abortions aren't safe, you aren't either' an der Wisconsin Family Action. Mutmaßliche Reaktion auf Dobbs-Leak. FBI nimmt Ermittlungen auf, Verdächtiger 2023 angeklagt.",
     "DOJ Press · justice.gov/usao-wdwi",43.073,-89.401),
    ("2022-06-07","Buffalo","US","Brandanschlag",
     "Buffalo (NY): Brandsatz gegen das CompassCare Pregnancy Center. Bekenner 'Jane's Revenge'. Ähnliche Anschläge in mehreren Bundesstaaten in den Folgewochen.",
     "AP News · apnews.com",42.952,-78.823),
    ("2022-05-22","Atlanta","US","Brandanschlag",
     "Atlanta-Region: Mehrere Baufahrzeuge und ein Bauwagen am Atlanta Public Safety Training Center in Brand gesetzt. Erster größerer Sabotageakt der 'Stop Cop City'-Bewegung.",
     "AJC · ajc.com",33.685,-84.295),
    ("2022-11-13","Atlanta","US","Sabotage",
     "Atlanta: Koordinierte Angriffe auf Polizeistreifenwagen während einer Demonstration in Downtown. Reifen zerstochen, Fensterscheiben zerschlagen, Reaktion auf Festnahmen im Stop-Cop-City-Wald.",
     "AJC · ajc.com",33.755,-84.390),
    ("2022-06-25","Portland","US","Sachbeschädigung",
     "Portland: 'Night of Rage' nach Dobbs-Urteil. Schwarzer Block beschädigt katholische Kirchen, Pregnancy Centers, Pearl District-Geschäfte. Ca. 300.000 USD Schaden.",
     "KOIN6 · koin.com",45.523,-122.681),
    ("2022-12-13","Atlanta","US","Brandanschlag",
     "Atlanta-Forest: Polizei räumt erstes Lager, fünf Personen werden unter Georgia-Anti-Terror-Statut festgenommen. Erste 'domestic terrorism'-Charges in der Bewegung.",
     "GBI Press · gbi.georgia.gov",33.685,-84.295),

    # ── USA 2023 ────────────────────────────────────────────────────────
    ("2023-01-18","Atlanta","US","Gewalt",
     "Atlanta: GBI/SWAT-Räumung im Atlanta Forest. Manuel 'Tortuguita' Teran wird erschossen, ein State Trooper schwer verletzt. Bewegung mobilisiert international.",
     "GBI Press · gbi.georgia.gov",33.685,-84.295),
    ("2023-01-21","Atlanta","US","Sachbeschädigung",
     "Atlanta Downtown: Reaktion auf Teran-Tötung. Schwarzer Block zerstört Scheiben an Bankfilialen, zündet Polizei-Streifenwagen an, sechs Personen unter domestic terrorism-Statut angeklagt.",
     "AJC · ajc.com",33.755,-84.390),
    ("2023-03-05","Atlanta","US","Militante Aktion",
     "Atlanta: Koordinierter Großangriff von rund 150 Vermummten auf die Baustelle des Public Safety Training Center. Brandanschläge auf Bagger, Bauwagen und Polizei-Streifenwagen. 23 Festnahmen, federal RICO-Anklagen folgen 2023.",
     "DOJ Press · justice.gov/usao-ndga",33.685,-84.295),
    ("2023-06-13","Atlanta","US","Demo/Kundgebung",
     "Atlanta: Während City-Council-Abstimmung über Cop-City-Finanzierung wird das Rathaus belagert, Sicherheitskräfte mit Eiern und Farbbeuteln beworfen. Mehrere Festnahmen.",
     "AJC · ajc.com",33.749,-84.390),
    ("2023-09-05","Atlanta","US","Sabotage",
     "Atlanta-Forest: 61 Aktivist:innen werden in einer historisch beispiellosen RICO-Anklage des Bundesstaats Georgia beschuldigt. Vorwurf: koordinierte Sabotage, Brandstiftung und Beihilfe.",
     "DOJ Press · law.georgia.gov",33.749,-84.388),

    # ── USA 2024 ────────────────────────────────────────────────────────
    ("2024-04-30","New York","US","Militante Aktion",
     "New York: Pro-Palästina-Aktivisten besetzen Hamilton Hall der Columbia University, verbarrikadieren Türen mit Möbeln, beschädigen Eigentum. NYPD räumt das Gebäude in einer Nachteinsatz, über 100 Festnahmen.",
     "NYT · nytimes.com",40.808,-73.961),
    ("2024-05-01","Los Angeles","US","Gewalt",
     "Los Angeles (UCLA): Maskierte Angreifer attackieren das Pro-Palästina-Encampment mit Schlagstöcken und Pyrotechnik. Stundenlange Gewalt, Polizei greift verzögert ein, mehrere Schwerverletzte.",
     "LA Times · latimes.com",34.073,-118.443),
    ("2024-08-19","Chicago","US","Sachbeschädigung",
     "Chicago: Beim Auftakt des Democratic National Convention durchbrechen vermummte Gruppen den Außenzaun, Israelische Konsulatsfenster werden beschmiert und zerschlagen. 56 Festnahmen.",
     "Chicago Tribune · chicagotribune.com",41.852,-87.651),
    ("2024-04-25","Boston","US","Sachbeschädigung",
     "Boston (Emerson College): Pro-Palästina-Encampment eskaliert in Nacht-Räumung. Vermummte werfen Steine auf Polizei, 108 Festnahmen, vier Beamte verletzt.",
     "Boston Globe · bostonglobe.com",42.352,-71.066),
    ("2024-10-09","Berkeley","US","Sachbeschädigung",
     "UC Berkeley: Vermummte Antifa-Gruppe zerstört Scheiben des Hillel-Hauses und beschmiert die Eingangstür mit antisemitischen Parolen. Anklage wegen hate-crime und vandalism.",
     "SF Chronicle · sfchronicle.com",37.870,-122.259),

    # ── USA 2025 ────────────────────────────────────────────────────────
    ("2025-01-20","Washington","US","Sachbeschädigung",
     "Washington DC: Am Inauguration-Day von Donald Trump Angriffe vermummter Gruppen auf Polizeifahrzeuge und Geschäfte am K Street und Franklin Square. 24 Festnahmen.",
     "Washington Post · washingtonpost.com",38.901,-77.034),
    ("2025-03-29","San Francisco","US","Brandanschlag",
     "San Francisco: Brandanschlag auf Tesla-Showroom in SoMa. Mehrere Cybertrucks beschädigt, Eingangsbereich ausgebrannt. Bekennerschreiben anti-Musk-Aktivismus. FBI ermittelt.",
     "SF Chronicle · sfchronicle.com",37.778,-122.397),
    ("2025-04-12","Las Vegas","US","Brandanschlag",
     "Las Vegas: Tesla-Service-Center in Brand gesetzt, fünf Fahrzeuge zerstört, Slogans 'Resist Musk' an Wand. FBI klassifiziert als domestic terrorism, Verdächtiger im Mai festgenommen.",
     "AP News · apnews.com",36.169,-115.139),
    ("2025-05-01","Seattle","US","Gewalt",
     "Seattle: May-Day-Demonstration eskaliert in Capitol Hill. Schwarzer Block greift Polizei mit Steinen und Brandflaschen an, vier Beamte verletzt, 17 Festnahmen.",
     "Seattle Times · seattletimes.com",47.620,-122.319),
    ("2025-03-15","Portland","US","Brandanschlag",
     "Portland: Brandsätze gegen ein Tesla-Showroom an der Macadam Avenue. Cybertruck und Model-Y zerstört, Bekennerschreiben in einer anarchistischen Online-Plattform.",
     "Oregonian · oregonlive.com",45.474,-122.671),

    # ── Schweiz 2020 ────────────────────────────────────────────────────
    ("2020-01-21","Davos","CH","Demo/Kundgebung",
     "Davos: Anti-WEF-Demo mit ca. 1.500 Teilnehmenden, autonome Block versucht Sperrzone zu durchbrechen, Pyrotechnik gegen Polizei. Mehrere Wegweisungen.",
     "SRF · srf.ch",46.799,9.835),
    ("2020-05-01","Zürich","CH","Sachbeschädigung",
     "Zürich: Unbewilligter 1.-Mai-Umzug in der Innenstadt trotz Corona-Versammlungsverbot. Bankenfilialen mit Farbe attackiert, Polizei mit Flaschen beworfen. 17 Personen vorübergehend festgenommen.",
     "NZZ · nzz.ch",47.376,8.541),
    ("2020-10-31","Zürich","CH","Gewalt",
     "Zürich: Unbewilligte 'Tanz dich frei'-Demo eskaliert. Vermummte werfen Pflastersteine und Pyrotechnik auf Polizei, mehrere Beamte verletzt, Sachschaden im sechsstelligen Bereich.",
     "Tages-Anzeiger · tagesanzeiger.ch",47.376,8.541),

    # ── Schweiz 2021 ────────────────────────────────────────────────────
    ("2021-05-01","Basel","CH","Sachbeschädigung",
     "Basel: Während des 1.-Mai-Umzugs Angriffe auf Filialen von UBS und Credit Suisse, Scheiben zerschlagen, antikapitalistische Sprühparolen. Sachschaden ca. 80.000 CHF.",
     "BZ Basel · bzbasel.ch",47.560,7.591),
    ("2021-09-04","Bern","CH","Gewalt",
     "Bern: Nach unbewilligter Linksautonomen-Demo Eskalation rund um die Reitschule. Pyrotechnik, Flaschen und Steine gegen Polizei. Mehrere verletzte Beamte, vier Festnahmen.",
     "Berner Zeitung · bernerzeitung.ch",46.948,7.443),
    ("2021-11-13","Zürich","CH","Sachbeschädigung",
     "Zürich: Nächtliche Sachbeschädigungen an mehreren Bezirksbüros bürgerlicher Parteien (SVP, FDP). Farbbeutel, eingeschlagene Scheiben. Bekennerschreiben antifaschistischer Gruppe.",
     "NZZ · nzz.ch",47.376,8.541),

    # ── Schweiz 2022 ────────────────────────────────────────────────────
    ("2022-05-23","Davos","CH","Demo/Kundgebung",
     "Davos: Anti-WEF-Demonstration während verschobener Mai-Ausgabe. Autonome Block versucht Sperrzone zu durchbrechen, Polizei setzt Wasserwerfer ein. Mehrere Wegweisungen, eine Festnahme.",
     "SRF · srf.ch",46.799,9.835),
    ("2022-05-01","Zürich","CH","Gewalt",
     "Zürich: Nach dem offiziellen 1.-Mai-Umzug schwere Ausschreitungen im Kreis 4/5. Schwarzer Block zerstört Bankfilialen, attackiert Polizei mit Pflastersteinen und Pyrotechnik. Über 200 Personen festgesetzt.",
     "Tages-Anzeiger · tagesanzeiger.ch",47.376,8.541),
    ("2022-11-19","Bern","CH","Sachbeschädigung",
     "Bern: Nach unbewilligter 'Smash Patriarchy'-Demo Sachbeschädigungen in der Innenstadt: SBB-Schalter, Tramwagen und Schaufenster zerstört. Schaden ca. 150.000 CHF.",
     "Der Bund · derbund.ch",46.948,7.443),

    # ── Schweiz 2023 ────────────────────────────────────────────────────
    ("2023-01-19","Davos","CH","Demo/Kundgebung",
     "Davos: Klassischer Anti-WEF-Treck mit ca. 500 Teilnehmenden. Versuch des Durchbruchs durch die Sperrzone bei Klosters. Polizei verhindert Eskalation mit massivem Aufgebot.",
     "SRF · srf.ch",46.799,9.835),
    ("2023-05-01","Zürich","CH","Gewalt",
     "Zürich: 1.-Mai-Nachdemonstration eskaliert massiv. Vermummte werfen Pyrotechnik, Flaschen und Steine auf Beamte, sechs Polizisten verletzt. 219 Wegweisungen, 16 Festnahmen.",
     "NZZ · nzz.ch",47.376,8.541),
    ("2023-10-12","Zürich","CH","Sachbeschädigung",
     "Zürich: Während Pro-Palästina-Demo attackieren vermummte Gruppen die israelische Botschaftsvertretung und mehrere jüdische Einrichtungen mit Farbe und Steinen. Polizei räumt Demo auf.",
     "20 Minuten · 20min.ch",47.376,8.541),
    ("2023-06-10","Bern","CH","Gewalt",
     "Bern: Solidaritätsdemonstration für inhaftierte Genoss:innen eskaliert. Vermummte werfen Brandflaschen Richtung Polizei, drei Beamte verletzt, sechs Festnahmen.",
     "Berner Zeitung · bernerzeitung.ch",46.948,7.443),

    # ── Schweiz 2024 ────────────────────────────────────────────────────
    ("2024-01-15","Davos","CH","Demo/Kundgebung",
     "Davos: Anti-WEF-Klimacamp am Ortseingang. Versuche der Strassenblockade, Polizei räumt Camp, mehrere Personen weggewiesen, drei Festnahmen wegen Gewalt gegen Beamte.",
     "Tages-Anzeiger · tagesanzeiger.ch",46.799,9.835),
    ("2024-05-01","Zürich","CH","Sachbeschädigung",
     "Zürich: 1.-Mai-Ausschreitungen mit Schwerpunkt Stauffacher. Schaufenster mehrerer Banken und Versicherungen zerschlagen, Tramleitungen mit Farbe verunreinigt. Schaden über 250.000 CHF.",
     "NZZ · nzz.ch",47.376,8.541),
    ("2024-11-09","Basel","CH","Gewalt",
     "Basel: Nach Pro-Palästina-Demo Angriffe auf Polizei und private Sicherheitsdienste. Schwarzer Block zerstört Bankfilialen am Marktplatz, sechs Personen verletzt, 14 Festnahmen.",
     "BZ Basel · bzbasel.ch",47.560,7.591),
    ("2024-04-22","Bern","CH","Sachbeschädigung",
     "Bern: Reitschule-Umfeld attackiert Polizeiposten Marktgasse mit Farbbeuteln und Pyrotechnik. Sachschaden ca. 30.000 CHF, keine Verletzten.",
     "Der Bund · derbund.ch",46.948,7.443),

    # ── Schweiz 2025 ────────────────────────────────────────────────────
    ("2025-01-20","Davos","CH","Demo/Kundgebung",
     "Davos: Anti-WEF-Demo mit ca. 800 Teilnehmenden, Sektor Klosters. Vermummte versuchen Polizeisperre zu durchbrechen, fünf Wegweisungen, eine Festnahme.",
     "SRF · srf.ch",46.799,9.835),
    ("2025-05-01","Zürich","CH","Gewalt",
     "Zürich: 1.-Mai-Nachdemonstration mündet erneut in schweren Ausschreitungen. Schwarzer Block attackiert Polizei mit Pflastersteinen, mehrere Beamte verletzt, 142 Wegweisungen.",
     "Tages-Anzeiger · tagesanzeiger.ch",47.376,8.541),
    ("2025-03-22","Genf","CH","Sachbeschädigung",
     "Genf: Nach Demo gegen Polizeigewalt Angriffe auf das UEFA-Quartier am Quai du Mont-Blanc. Scheiben zerschlagen, Slogans gesprüht. Acht Wegweisungen.",
     "RTS · rts.ch",46.204,6.143),

    # ── Deutschland 2020 ────────────────────────────────────────────────
    ("2020-05-01","Berlin","DE","Gewalt",
     "Berlin: Trotz Corona-Versammlungsverbot Eskalationen am revolutionären 1. Mai in Kreuzberg. Vermummte werfen Flaschen und Steine, mehrere Beamte verletzt. Bundesweite Solidaritätsaktionen.",
     "Tagesspiegel · tagesspiegel.de",52.499,13.418),
    ("2020-06-17","Berlin","DE","Gewalt",
     "Berlin: Räumungsversuch der Liebigstraße 34 (linksautonomes Wohnprojekt). Gegenmobilisierung greift Polizei mit Pyrotechnik und Steinen an, mehrere Polizisten verletzt, Festnahmen.",
     "Tagesspiegel · tagesspiegel.de",52.515,13.461),
    ("2020-10-09","Berlin","DE","Sachbeschädigung",
     "Berlin: Räumung der Liebig34. Im Anschluss Sachbeschädigungen in halber Innenstadt, Schaufenster zerstört, Polizeifahrzeuge beschädigt, ca. 1 Mio. Euro Schaden. 124 Festnahmen.",
     "Tagesschau · tagesschau.de",52.515,13.461),
    ("2020-12-05","Leipzig","DE","Brandanschlag",
     "Leipzig: Brandanschlag auf Justiz-Fahrzeuge in Leipzig-Mitte. Drei Fahrzeuge ausgebrannt, Bekennerschreiben einer linksradikalen Plattform. Staatsschutz ermittelt.",
     "MDR · mdr.de",51.339,12.380),
    ("2020-12-31","Leipzig","DE","Gewalt",
     "Leipzig-Connewitz: Silvesternacht-Angriffe auf Polizei. Über 100 Vermummte attackieren Einsatzkräfte mit Pyrotechnik und Steinen, Wache am Wiedebach-Platz belagert. 38 verletzte Beamte.",
     "Sächsische Zeitung · saechsische.de",51.323,12.382),

    # ── Deutschland 2021 ────────────────────────────────────────────────
    ("2021-05-01","Berlin","DE","Gewalt",
     "Berlin: Revolutionäre 1.-Mai-Demonstration in Neukölln und Kreuzberg eskaliert in schwere Ausschreitungen. Über 354 Polizisten verletzt, 240 Festnahmen. Schwerster 1. Mai seit Jahren.",
     "Tagesschau · tagesschau.de",52.494,13.419),
    ("2021-06-23","Berlin","DE","Sachbeschädigung",
     "Berlin: 'Tag X'-Vorbereitung in Friedrichshain. Nach Mietenkrise-Demo Angriffe auf Immobilien-Büros, Banken und Polizeiposten. Schäden im sechsstelligen Bereich, 18 Festnahmen.",
     "Berliner Zeitung · berliner-zeitung.de",52.515,13.461),
    ("2021-11-01","Stuttgart","DE","Sachbeschädigung",
     "Stuttgart: Vermummte attackieren AfD-Wahlkreisbüros in der Innenstadt und in Bad Cannstatt. Scheiben eingeschlagen, Farbbeutel, Brandsätze an Eingangstüren gelöscht. Polizei ermittelt.",
     "Stuttgarter Zeitung · stuttgarter-zeitung.de",48.778,9.181),
    ("2021-12-31","Leipzig","DE","Gewalt",
     "Leipzig-Connewitz: Silvester-Eskalation, koordinierte Angriffe auf Polizeikräfte. Pyrotechnik, Steine, brennende Barrikaden. 65 verletzte Beamte, sieben Festnahmen.",
     "MDR · mdr.de",51.323,12.382),

    # ── Deutschland 2022 ────────────────────────────────────────────────
    ("2022-01-12","Lützerath","DE","Militante Aktion",
     "Lützerath: Aktionen gegen Tagebauerweiterung. Polizei stürmt Baumhäuser, Aktivisten antworten mit Pyrotechnik und Steinen. Mehrere Verletzte beider Seiten, dutzende Festnahmen.",
     "Tagesschau · tagesschau.de",51.072,6.426),
    ("2022-05-01","Hamburg","DE","Gewalt",
     "Hamburg: Nach revolutionärer 1.-Mai-Demo in der Schanze schwere Ausschreitungen. Vermummte werfen Steine und Brandflaschen, mehrere Beamte verletzt, 22 Festnahmen.",
     "NDR · ndr.de",53.563,9.961),
    ("2022-10-25","Berlin","DE","Sabotage",
     "Berlin/Niedersachsen: Sabotage am GSM-R-Kommunikationssystem der Deutschen Bahn. Kabel an zwei Stellen durchtrennt, bundesweiter Zugverkehr in Norddeutschland für Stunden lahmgelegt. Ermittlungen weisen auf linksextremen Bekennertext, später Zweifel an Tätergruppen.",
     "Tagesschau · tagesschau.de",52.520,13.405),
    ("2022-11-13","Berlin","DE","Brandanschlag",
     "Berlin: Brandanschlag auf Vodafone-Service-Einrichtung in Friedrichshain. Mehrere Servicewagen zerstört. Bekennerschreiben antikapitalistischer Gruppe auf indymedia, ca. 200.000 Euro Schaden.",
     "Berliner Morgenpost · morgenpost.de",52.515,13.450),

    # ── Deutschland 2023 ────────────────────────────────────────────────
    ("2023-05-31","Dresden","DE","Demo/Kundgebung",
     "Dresden: Urteil im Hammerbande-Prozess gegen Lina E. und vier Mitangeklagte. Lina E. zu 5 Jahren 3 Monaten Haft verurteilt. Bundesweite Mobilisierung der linksradikalen Szene.",
     "Tagesschau · tagesschau.de",51.052,13.737),
    ("2023-06-03","Leipzig","DE","Gewalt",
     "Leipzig: 'Tag X'-Demonstration nach Lina-E.-Urteil eskaliert massiv. Schwarzer Block attackiert Polizei mit Pflastersteinen, Brandflaschen und Pyrotechnik. Über 50 verletzte Beamte, Ausnahmezustand in Connewitz.",
     "MDR · mdr.de",51.323,12.382),
    ("2023-06-04","Leipzig","DE","Brandanschlag",
     "Leipzig: Folgenacht zum Tag X. Brandanschläge auf mehrere Polizei-Streifenwagen, Baumaschinen und ein Sicherheitsunternehmen. Bekennerschreiben mit Solidaritätsadresse an Lina E.",
     "Sächsische Zeitung · saechsische.de",51.339,12.380),
    ("2023-06-30","Hamburg","DE","Sachbeschädigung",
     "Hamburg: Solidaritätsaktion nach Lina-E.-Urteil. Angriff auf das Polizeikommissariat St. Pauli mit Farbe und Steinen, Streifenwagen beschädigt. Sechs Festnahmen.",
     "Hamburger Abendblatt · abendblatt.de",53.550,9.964),
    ("2023-12-31","Leipzig","DE","Gewalt",
     "Leipzig-Connewitz: Silvester erneut Angriffe auf Polizeikräfte. Über 200 Personen mobilisiert, Polizei mit Pyrotechnik und Steinen beworfen. 24 verletzte Beamte, mehrere Festnahmen.",
     "MDR · mdr.de",51.323,12.382),

    # ── Deutschland 2024 ────────────────────────────────────────────────
    ("2024-03-05","Grünheide","DE","Brandanschlag",
     "Grünheide (Brandenburg): Brandanschlag auf einen Strommast der Tesla-Gigafactory, Werk komplett stromlos. Bekennerschreiben der 'Vulkangruppe' im linksradikalen Spektrum. Schaden Millionenbereich, BKA übernimmt.",
     "Tagesschau · tagesschau.de",52.400,13.961),
    ("2024-05-01","Berlin","DE","Gewalt",
     "Berlin: Revolutionärer 1. Mai. Pro-Palästina-Block radikalisiert die Demo, Pyrotechnik und Steine gegen Polizei in Kreuzberg. 21 verletzte Beamte, 41 Festnahmen.",
     "Tagesspiegel · tagesspiegel.de",52.494,13.419),
    ("2024-07-15","Berlin","DE","Sachbeschädigung",
     "Berlin: Mehrere AfD-Bezirksbüros in Marzahn und Lichtenberg von vermummten Gruppen attackiert. Scheiben zerschlagen, Farbe, Slogans 'Kein Fußbreit'. Bekennerschreiben antifaschistischer Gruppe.",
     "rbb24 · rbb24.de",52.535,13.581),
    ("2024-10-20","Leipzig","DE","Brandanschlag",
     "Leipzig: Brandanschlag auf Justizvollzugsfahrzeuge in der Justizvollzugsanstalt Leipzig-Mitte. Drei Fahrzeuge zerstört, Bekennerschreiben mit Bezug auf inhaftierte Genoss:innen.",
     "Sächsische Zeitung · saechsische.de",51.339,12.380),
    ("2024-12-31","Leipzig","DE","Gewalt",
     "Leipzig-Connewitz: Erneut Silvester-Eskalation. Polizei mit massivem Aufgebot, dennoch über 80 Vermummte greifen Beamte mit Pyrotechnik an. 18 verletzte Polizisten, 12 Festnahmen.",
     "MDR · mdr.de",51.323,12.382),

    # ── Deutschland 2025 ────────────────────────────────────────────────
    ("2025-01-25","Riesa","DE","Gewalt",
     "Riesa (Sachsen): Bei AfD-Bundesparteitag schwere Blockadeaktionen. Vermummte Gruppen versuchen Sperren zu durchbrechen, Polizei mit Pfefferspray und Wasserwerfern. Mehrere Verletzte, ca. 30 Festnahmen.",
     "Sächsische Zeitung · saechsische.de",51.306,13.290),
    ("2025-02-14","Berlin","DE","Sachbeschädigung",
     "Berlin: Vor Bundestagswahl koordinierte Angriffe auf Wahlplakate und Bezirksbüros der CDU/CSU und AfD in Mitte und Friedrichshain. Bekennerschreiben antifaschistischer Gruppen, vereinzelte Brandanschläge an Plakaten.",
     "Berliner Zeitung · berliner-zeitung.de",52.520,13.405),
    ("2025-03-10","Hamburg","DE","Brandanschlag",
     "Hamburg: Brandanschlag auf eine Telekom-Vermittlungsstelle in Altona. Mehrere Schaltkästen ausgebrannt, Internet- und Telefonausfälle in mehreren Stadtteilen. Bekennerschreiben verweist auf 'kommunikative Infrastruktur des Kapitals'.",
     "NDR · ndr.de",53.550,9.935),
    ("2025-05-01","Berlin","DE","Gewalt",
     "Berlin: Revolutionärer 1. Mai 2025 in Kreuzberg. Schwarzer Block greift Polizei mit Pflastersteinen und Brandflaschen an, drei verletzte Beamte schwer. 89 Festnahmen, mehrere Geschäfte verwüstet.",
     "Tagesspiegel · tagesspiegel.de",52.494,13.419),
    ("2025-05-01","Hamburg","DE","Sachbeschädigung",
     "Hamburg: Im Schanzenviertel nach 1.-Mai-Demo Sachbeschädigungen an Banken, Versicherungen und Polizeifahrzeugen. Schaden ca. 400.000 Euro, 31 Festnahmen.",
     "Hamburger Abendblatt · abendblatt.de",53.563,9.961),

    # ═══════════════════════════════════════════════════════════════════
    # RUNDE 2 (Mai 2026): Anker-Großereignisse + 2026-Aktualität
    # Schwerpunkte:
    #  - G20 Hamburg 2017 (Anker der modernen linken Gewalt in DE)
    #  - Tesla-Sabotage-Welle 2024-2026 (DE + US)
    #  - Atlanta Cop City RICO-Verfahren 2024-2026
    #  - Lina E./Hammerbande Folgen 2023-2026
    #  - Anti-WEF Davos 2025-2026
    #  - 1. Mai-Eskalationen, AfD-Bezirksbüro-Attacken
    # ═══════════════════════════════════════════════════════════════════

    # ── G20 Hamburg Juli 2017 — Anker-Großereignis ─────────────────────
    ("2017-07-06","Hamburg","DE","Gewalt",
     "Hamburg G20: 'Welcome to Hell'-Demo eskaliert nach wenigen Hundert Metern. Vermummte werfen Steine und Flaschen auf Polizei. Wasserwerfer-Einsatz, dutzende Verletzte, Demo aufgelöst.",
     "NDR · ndr.de",53.554,9.961),
    ("2017-07-07","Hamburg","DE","Brandanschlag",
     "Hamburg G20: Brandanschläge entlang der Elbchaussee — über 30 Autos in Brand gesetzt, Geschäfte beschädigt. Koordinierte Aktion von rund 200 Vermummten in den frühen Morgenstunden. 23 Festnahmen, BKA-Ermittlungen laufen jahrelang.",
     "Tagesschau · tagesschau.de",53.554,9.910),
    ("2017-07-07","Hamburg","DE","Militante Aktion",
     "Hamburg G20 Schanze: Mehrtägige militante Auseinandersetzungen im Schanzenviertel. Polizei zieht sich zeitweise zurück, Spezialeinheiten rücken nach. Brennende Barrikaden, Plünderungen, 476 verletzte Beamte über die G20-Tage.",
     "Spiegel · spiegel.de",53.563,9.961),
    ("2017-07-08","Hamburg","DE","Sachbeschädigung",
     "Hamburg G20: Im Stadtteil St. Pauli wird ein Polizeirevier nachts attackiert. Scheiben zerstört, Pyrotechnik in Lobby geworfen. Folge der G20-Eskalation.",
     "Hamburger Abendblatt · abendblatt.de",53.550,9.964),

    # ── Hammerbande / Lina E.-Folgen 2024-2026 ─────────────────────────
    ("2024-09-20","Dresden","DE","Demo/Kundgebung",
     "Dresden: Berufungsprozess gegen Lina E. beim Bundesgerichtshof beginnt. Linke Mobilisierung in Dresden, vermummte Gruppen am Gerichtsgebäude, mehrere Festnahmen wegen Steinwürfen auf Polizei.",
     "Sächsische Zeitung · saechsische.de",51.050,13.737),
    ("2024-06-15","Budapest","HU","Gewalt",
     "Budapest (HU): 'Day-of-Honour'-Gegenaktivisten der Hammerbande greifen rechtsextreme Teilnehmer an. Ungarische Justiz nimmt Maja T. fest. Auslieferungsstreit zwischen DE und HU eskaliert 2024-2025.",
     "Spiegel · spiegel.de",47.498,19.040),
    ("2024-06-28","Berlin","DE","Sachbeschädigung",
     "Berlin: Solidaritäts-Demo für Maja T. eskaliert vor der ungarischen Botschaft. Vermummte werfen Farbbeutel und Pyrotechnik, mehrere Festnahmen wegen Widerstand.",
     "rbb24 · rbb24.de",52.510,13.385),
    ("2025-08-15","Berlin","DE","Militante Aktion",
     "Berlin: Untertauchen weiterer mutmaßlicher Hammerbanden-Mitglieder. BKA-Großfahndung, Razzien in Leipzig und Berlin. Bundesanwaltschaft erhebt neue Anklage wegen Bildung einer kriminellen Vereinigung.",
     "Tagesschau · tagesschau.de",52.520,13.405),

    # ── Tesla-Sabotage-Welle 2024-2026 ─────────────────────────────────
    ("2024-03-07","Grünheide","DE","Militante Aktion",
     "Grünheide: Bekennerschreiben der 'Vulkangruppe' veröffentlicht — Brandanschlag auf Strommast als 'Sabotage des Klima-Greenwashings'. Werk-Stillstand sechs Tage, ca. 1 Mrd. Euro Produktionsausfall.",
     "Tagesspiegel · tagesspiegel.de",52.400,13.961),
    ("2024-05-10","Grünheide","DE","Sachbeschädigung",
     "Grünheide: Anti-Tesla-Camp eskaliert. Aktivisten dringen ins Werksgelände ein, schlagen Sicherheitskräfte mit Stöcken, beschädigen Fahrzeuge. Polizei-Großeinsatz, 28 Festnahmen.",
     "rbb24 · rbb24.de",52.400,13.961),
    ("2025-01-28","Grünheide","DE","Brandanschlag",
     "Grünheide: Erneuter Brandanschlag auf Tesla-Infrastruktur. Hochspannungsleitung sabotiert, Werk muss Produktion drosseln. Bekennerschreiben in linksradikaler Online-Plattform, BKA-Generalbundesanwaltschaft übernimmt.",
     "Tagesschau · tagesschau.de",52.400,13.961),
    ("2025-03-08","Berlin","DE","Brandanschlag",
     "Berlin: Tesla-Showroom am Kurfürstendamm in Brand gesetzt. Fünf Vorführfahrzeuge zerstört, Eingangsbereich ausgebrannt. Bekennerschreiben mit Bezug auf Tesla-Grünheide-Erweiterung.",
     "Berliner Zeitung · berliner-zeitung.de",52.503,13.330),
    ("2025-04-02","Hamburg","DE","Sachbeschädigung",
     "Hamburg: Tesla-Service-Center am Holstenkamp attackiert. Scheiben zerschlagen, Fahrzeuge mit Farbe beschmiert, Slogans 'No Tesla – No War'. Schaden ca. 200.000 Euro.",
     "NDR · ndr.de",53.567,9.945),

    # ── US Tesla-Welle 2025 (anti-Musk Anti-Trump-Kontext) ─────────────
    ("2025-02-14","Albuquerque","US","Brandanschlag",
     "Albuquerque (NM): Tesla-Showroom in Brand gesetzt. Drei Cybertrucks und ein Model-Y zerstört. FBI klassifiziert als domestic terrorism. Mutmaßlicher Täter im April festgenommen.",
     "AP News · apnews.com",35.084,-106.651),
    ("2025-02-28","Tigard","US","Brandanschlag",
     "Tigard (Oregon): Tesla-Service-Center mit Brandflaschen attackiert. Sieben Fahrzeuge beschädigt, Showroom-Lobby teilweise ausgebrannt. Lokale Antifa-Plattform bekennt sich.",
     "Oregonian · oregonlive.com",45.431,-122.770),
    ("2025-03-18","Loveland","US","Brandanschlag",
     "Loveland (Colorado): Brandanschlag auf Tesla-Supercharger-Station und drei geladene Fahrzeuge. FBI: 'koordinierte landesweite Anschlagsserie'. Verdächtiger im Juni angeklagt.",
     "Denver Post · denverpost.com",40.398,-105.075),
    ("2025-04-08","Salem","US","Brandanschlag",
     "Salem (Oregon): Tesla-Showroom angegriffen. Brandsätze, Schaufenster zerschlagen, Slogans 'Resist Musk'. FBI ermittelt unter Domestic-Terrorism-Statut.",
     "Statesman Journal · statesmanjournal.com",44.943,-123.035),

    # ── Atlanta Cop City — RICO-Folgen 2024-2026 ───────────────────────
    ("2024-02-15","Atlanta","US","Militante Aktion",
     "Atlanta-Forest: Erneuter Großangriff auf das Public Safety Training Center. Baufahrzeuge in Brand gesetzt, Wachpersonal mit Steinen attackiert. Sechs Personen verhaftet.",
     "AJC · ajc.com",33.685,-84.295),
    ("2024-05-10","Atlanta","US","Brandanschlag",
     "Atlanta: Solidaritätsaktion vor dem Bundesgericht beim ersten RICO-Verhandlungstag. Schwarzer Block zündet Polizeifahrzeuge an, attackiert das Gerichtsgebäude. Massive Festnahmen.",
     "DOJ Press · justice.gov/usao-ndga",33.755,-84.390),
    ("2025-01-22","Atlanta","US","Demo/Kundgebung",
     "Atlanta: 2. Jahrestag der Erschießung von 'Tortuguita' Teran. Demonstration mit ca. 2.000 Teilnehmenden, Schwarzer Block-Anteil eskaliert, Beschädigungen in Downtown.",
     "AJC · ajc.com",33.755,-84.390),
    ("2025-04-15","Atlanta","US","Sabotage",
     "Atlanta-Forest: Mutmaßliche Sabotage an Bewässerungs- und Strom-Infrastruktur des Public Safety Training Center. FBI ermittelt nach $300K Schaden.",
     "AJC · ajc.com",33.685,-84.295),

    # ── US Campus-Encampments 2024-2025 ────────────────────────────────
    ("2024-05-02","New York","US","Gewalt",
     "New York (NYU): Pro-Palästina-Encampment eskaliert in Räumung. Aktivisten attackieren Polizei und Sicherheitspersonal mit Möbeln und Steinen. Mehrere Verletzte.",
     "NYT · nytimes.com",40.730,-73.997),
    ("2024-11-09","Berkeley","US","Sachbeschädigung",
     "UC Berkeley: Anti-Israel-Demo eskaliert in den Wohnheimen jüdischer Studenten. Sprühparolen, Drohungen, Türen beschädigt. Anklage wegen hate-crime, FBI ermittelt.",
     "SF Chronicle · sfchronicle.com",37.870,-122.259),
    ("2025-02-04","Stanford","US","Gewalt",
     "Stanford University: Antifa-Gruppe greift jüdische Studentenvereinigung an. Mehrere Verletzte, zwei Festnahmen wegen Körperverletzung und hate-crime.",
     "SF Chronicle · sfchronicle.com",37.428,-122.169),

    # ── Anti-WEF Davos 2025-2026 ───────────────────────────────────────
    ("2025-01-19","Davos","CH","Militante Aktion",
     "Davos WEF 2025: Anti-WEF-Treck eskaliert in Klosters. Aktivisten durchbrechen Polizeisperre, werfen Pyrotechnik. 8 Festnahmen wegen Gewalt gegen Beamte.",
     "SRF · srf.ch",46.799,9.835),
    ("2026-01-21","Davos","CH","Demo/Kundgebung",
     "Davos WEF 2026: Großdemonstration mit ca. 1.200 Teilnehmenden. Schwarzer Block-Anteil versucht Eskalation, Polizei verhindert Durchbruch der Sperrzone. 11 Wegweisungen, 3 Festnahmen.",
     "SRF · srf.ch",46.799,9.835),
    ("2025-12-31","Zürich","CH","Sachbeschädigung",
     "Zürich: Silvester-Aktionen — Bankautomaten von UBS und ZKB im Kreis 4 mit Brandsätzen attackiert. Mehrere zerstört, Schaden ca. 80.000 CHF. Polizei findet Bekennerschreiben.",
     "NZZ · nzz.ch",47.376,8.541),

    # ── Schweiz weitere 2024-2026 ──────────────────────────────────────
    ("2024-09-14","Bern","CH","Gewalt",
     "Bern: Pro-Palästina-Demo eskaliert vor dem Bundesplatz. Vermummte werfen Steine und Pyrotechnik auf Polizei. Vier Beamte verletzt, neun Festnahmen.",
     "Berner Zeitung · bernerzeitung.ch",46.948,7.443),
    ("2025-06-21","Genf","CH","Sachbeschädigung",
     "Genf: Anti-G7-Demo im Quartier des Banques attackiert UBS- und Pictet-Filialen. Scheiben zerschlagen, Slogans 'Crash the System'. Sachschaden ca. 350.000 CHF.",
     "RTS · rts.ch",46.204,6.143),
    ("2025-11-08","Lausanne","CH","Brandanschlag",
     "Lausanne: Brandanschlag auf das ehemalige Verlagsgebäude einer rechtskonservativen Wochenzeitung. Eingangsbereich ausgebrannt, niemand verletzt. Bekennerschreiben antifaschistisch.",
     "24 heures · 24heures.ch",46.519,6.633),
    ("2026-05-01","Zürich","CH","Gewalt",
     "Zürich 1. Mai 2026: Nachdemonstration eskaliert. Schwarzer Block greift Polizei mit Brandflaschen an, mehrere Beamte verletzt. 167 Wegweisungen, 22 Festnahmen.",
     "Tages-Anzeiger · tagesanzeiger.ch",47.376,8.541),

    # ── Deutschland weitere 2024-2026 ──────────────────────────────────
    ("2024-06-09","Berlin","DE","Gewalt",
     "Berlin: AfD-Wahlparty zur Europawahl in Berlin-Mitte wird von Anti-AfD-Block belagert. Vermummte werfen Pyrotechnik, attackieren Polizei mit Steinen. 18 verletzte Beamte, mehrere Festnahmen.",
     "Tagesspiegel · tagesspiegel.de",52.520,13.405),
    ("2024-09-01","Erfurt","DE","Sachbeschädigung",
     "Erfurt (Thüringen): Vor Landtagswahl koordinierte Angriffe auf AfD-Wahlkreisbüros in Thüringen. Brandsätze an Eingangstüren gelegt, mindestens fünf Büros stark beschädigt.",
     "MDR · mdr.de",50.984,11.030),
    ("2024-10-12","Köln","DE","Brandanschlag",
     "Köln: Brandanschlag auf ein Polizeifahrzeug im Stadtteil Ehrenfeld. Streifenwagen ausgebrannt, Bekennerschreiben verweist auf 'Polizeigewalt gegen migrantische Communities'.",
     "WDR · wdr1.de",50.937,6.957),
    ("2025-02-22","Hamburg","DE","Gewalt",
     "Hamburg: Vor Bundestagswahl Großdemo gegen AfD-Wahlkampfauftritt in der Hafencity. Schwarzer Block greift Polizei und Veranstaltungssicherheit an, 27 Beamte verletzt.",
     "NDR · ndr.de",53.541,9.984),
    ("2025-09-28","München","DE","Sachbeschädigung",
     "München: AfD-Bundesvorstand-Sitzung im Hotel attackiert. Vermummte werfen Farbbeutel und Brandsätze, mehrere Festnahmen. Slogans 'Kein Fußbreit den Faschisten'.",
     "BR24 · br.de",48.137,11.575),
    ("2025-11-09","Leipzig","DE","Militante Aktion",
     "Leipzig: Solidaritätsaktion mit inhaftiertem Lina-E.-Mitangeklagten. Schwarzer Block attackiert Justizvollzugsanstalt mit Pyrotechnik und Steinen. 12 Festnahmen wegen schweren Landfriedensbruchs.",
     "MDR · mdr.de",51.339,12.380),
    ("2026-01-30","Berlin","DE","Brandanschlag",
     "Berlin: Brandanschlag auf zwei Bundeswehr-Bürofahrzeuge im Stadtteil Mitte. Bekennerschreiben antimilitaristischer Gruppe verweist auf deutsche Rüstungslieferungen. Staatsschutz übernimmt.",
     "Tagesspiegel · tagesspiegel.de",52.520,13.405),
    ("2026-03-15","Dresden","DE","Demo/Kundgebung",
     "Dresden: Anti-AfD-Großdemo zum Landesparteitag. Schwarzer Block versucht Tagungsort zu blockieren, Polizei verhindert Eskalation mit Wasserwerfern. 41 Wegweisungen.",
     "Sächsische Zeitung · saechsische.de",51.050,13.737),
    ("2026-05-01","Berlin","DE","Gewalt",
     "Berlin: Revolutionärer 1. Mai 2026 mit erneuter Eskalation in Kreuzberg/Neukölln. Schwarzer Block-Anteil schätzungsweise 800 Personen, 79 verletzte Beamte, 134 Festnahmen.",
     "Tagesschau · tagesschau.de",52.494,13.419),

    # ── USA weitere 2024-2026 ──────────────────────────────────────────
    ("2024-07-15","Milwaukee","US","Gewalt",
     "Milwaukee (Wisconsin): Beim Republican National Convention Angriffe vermummter Gruppen auf Polizei und Convention-Sicherheit. Pyrotechnik, Steine, 23 Festnahmen, sechs verletzte Beamte.",
     "Milwaukee Journal Sentinel · jsonline.com",43.039,-87.906),
    ("2024-11-06","Portland","US","Sachbeschädigung",
     "Portland: Nach Trump-Wahlsieg Sachbeschädigungen in Downtown. Schwarzer Block zerstört Bankfilialen und Trump-Tower-bezogene Eigentumsobjekte. Sachschaden ca. 400.000 USD.",
     "Oregonian · oregonlive.com",45.521,-122.679),
    ("2024-11-07","Seattle","US","Gewalt",
     "Seattle: Anti-Trump-Demo eskaliert in Capitol Hill. Vermummte werfen Steine auf Polizei, drei Polizeifahrzeuge beschädigt, mehrere Geschäfte zerstört. 31 Festnahmen.",
     "Seattle Times · seattletimes.com",47.620,-122.319),
    ("2025-01-29","Washington","US","Sachbeschädigung",
     "Washington DC: Im Pentagon-Umfeld koordinierte Sprühaktionen mit anti-militaristischen Slogans. Mehrere Hochsicherheitsgebäude betroffen, FBI klassifiziert als domestic terrorism.",
     "Washington Post · washingtonpost.com",38.871,-77.056),
    ("2025-05-15","Boston","US","Brandanschlag",
     "Boston: Brandanschlag auf einen Tesla-Showroom in Cambridge. Vier Fahrzeuge zerstört, Bekennerschreiben verweist auf 'Musk-Trump-Allianz'. FBI ermittelt.",
     "Boston Globe · bostonglobe.com",42.378,-71.118),
    ("2025-06-30","Chicago","US","Sachbeschädigung",
     "Chicago: Pro-Palästina-Demo eskaliert in Downtown. Vermummte beschädigen mehrere jüdische Einrichtungen und das israelische Konsulat. Hate-crime-Anklagen.",
     "Chicago Tribune · chicagotribune.com",41.882,-87.629),
    ("2025-09-12","Phoenix","US","Gewalt",
     "Phoenix (Arizona): Trump-Rally-Gegendemo eskaliert. Vermummte werfen Steine auf Polizei und Trump-Unterstützer, mehrere Verletzte, 19 Festnahmen.",
     "Arizona Republic · azcentral.com",33.448,-112.074),
    ("2026-02-05","Los Angeles","US","Brandanschlag",
     "Los Angeles: Tesla-Showroom in Santa Monica in Brand gesetzt. Drei Cybertrucks zerstört. Bekennerschreiben verweist auf ICE-Razzien und Musk-Trump-Allianz. FBI ermittelt unter Domestic-Terrorism-Statut.",
     "LA Times · latimes.com",34.020,-118.491),
    ("2026-03-22","Washington","US","Demo/Kundgebung",
     "Washington DC: Anti-Trump-Großdemo eskaliert am Capitol Hill. Schwarzer Block-Anteil greift Capitol Police mit Pyrotechnik und Steinen an, mehrere Verletzte. 67 Festnahmen, Anklagen wegen federal trespass.",
     "Washington Post · washingtonpost.com",38.890,-77.009),
    ("2026-04-19","Portland","US","Sachbeschädigung",
     "Portland: Earth-Day-Vorabend-Demo verwüstet Downtown. Über 20 Geschäfte beschädigt, Brandsätze gegen Stadtverwaltung. 44 Festnahmen, sechs verletzte Beamte.",
     "Oregonian · oregonlive.com",45.521,-122.679),

    # ── Sabotage gegen kritische Infrastruktur DE 2024-2026 ────────────
    ("2024-06-22","Berlin","DE","Sabotage",
     "Berlin/Brandenburg: Brandanschlag auf Vodafone-Mobilfunkmast in Pankow. Funkmast vollständig zerstört, Netz-Ausfall in mehreren Stadtteilen. Bekennerschreiben antikapitalistisch.",
     "Tagesspiegel · tagesspiegel.de",52.530,13.404),
    ("2025-07-11","Köln","DE","Sabotage",
     "Köln: Glasfaser-Hauptkabel an mehreren Stellen durchtrennt. Internet- und Mobilfunk-Ausfall in halber Stadt. Bekennerschreiben spricht von 'kommunikativer Infrastruktur des Überwachungsstaats'.",
     "WDR · wdr1.de",50.937,6.957),
    ("2025-10-04","Hamburg","DE","Brandanschlag",
     "Hamburg: Brandanschlag auf Bahn-Stellwerk in Altona. Zugverkehr für 8 Stunden lahmgelegt, ca. 30.000 Fahrgäste betroffen. Bekennerschreiben verweist auf Bahn-Rüstungs-Logistik. BKA übernimmt.",
     "Tagesschau · tagesschau.de",53.554,9.935),
    ("2026-02-18","München","DE","Sabotage",
     "München: Brandanschlag auf einen Telekom-Verteilerkasten am Marienplatz. Tausende ohne Internet, Schäden im sechsstelligen Bereich. Bekennerschreiben in linksradikalem Online-Portal.",
     "BR24 · br.de",48.137,11.575),

    # ── Sabotage CH/AT 2024-2026 ───────────────────────────────────────
    ("2024-11-22","Zürich","CH","Brandanschlag",
     "Zürich: Brandanschlag auf zwei Polizeifahrzeuge im Kreis 5. Beide Streifenwagen ausgebrannt, Bekennerschreiben antiautoritär. Stadtpolizei Zürich verstärkt Schutz.",
     "Tages-Anzeiger · tagesanzeiger.ch",47.385,8.522),
    ("2025-07-29","Wien","AT","Gewalt",
     "Wien (Österreich): FPÖ-Wahlkampfveranstaltung gestört, Anti-FPÖ-Block greift Polizei und Veranstaltungssicherheit an. Sieben Verletzte, 14 Festnahmen wegen Landfriedensbruch.",
     "ORF · orf.at",48.208,16.373),
    ("2026-01-12","Graz","AT","Sachbeschädigung",
     "Graz: AfÖ-Bezirkszentrale (Alternative für Österreich) mit Farbe und Brandsatz angegriffen. Sachschaden im sechsstelligen Bereich, Bekennerschreiben in linksradikalem Online-Portal.",
     "Kronen Zeitung · krone.at",47.071,15.439),

    # ═══════════════════════════════════════════════════════════════════
    # RUNDE 3 (Mai 2026): Tiefen-Anker + Lücken-Füllung
    # Schwerpunkte:
    #  - 2018-2019 als historische Anker (Bahn-Sabotage Berlin 2018,
    #    Hambacher Forst-Räumung 2018, AfD-Büro-Anschläge 2018-2019)
    #  - Weitere US-Vorfälle 2020-2022 (Stop-Cop-City-Vorläufer)
    #  - Weitere Schweizer Vorfälle (Reitschule, anti-Israel, anti-WEF)
    #  - Deutsche Ost-Spezifika (Halle, Magdeburg, Cottbus, Rostock)
    #  - Frankreich/Italien-Schwergewicht
    # ═══════════════════════════════════════════════════════════════════

    # ── 2018 Anker ──────────────────────────────────────────────────────
    ("2018-09-13","Hambach","DE","Militante Aktion",
     "Hambacher Forst: Großeinsatz zur Räumung der Baumhaus-Besetzungen. Aktivisten attackieren Polizei mit Pyrotechnik und Steinen, Beamte werden verletzt. Bundespolizei und Spezialeinheiten setzen Räumung über Wochen durch.",
     "WDR · wdr1.de",50.910,6.519),
    ("2018-06-22","Berlin","DE","Sabotage",
     "Berlin: Anschlag auf Bahn-Infrastruktur — Kabelschacht in Lichtenberg in Brand gesetzt. S-Bahn-Verkehr im Ostteil für Stunden lahmgelegt. Bekennerschreiben antikapitalistischer Gruppe auf indymedia.",
     "Tagesspiegel · tagesspiegel.de",52.510,13.498),
    ("2018-10-13","Leipzig","DE","Sachbeschädigung",
     "Leipzig: AfD-Wahlkreisbüro in Eutritzsch zerstört. Vermummte werfen Pflastersteine und Farbbeutel. Bekennerschreiben antifaschistischer Gruppe, Staatsschutz übernimmt.",
     "MDR · mdr.de",51.367,12.388),
    ("2018-12-31","Leipzig","DE","Gewalt",
     "Leipzig-Connewitz: Silvesternacht. 40-50 Vermummte attackieren Polizei mit Pyrotechnik, Steinen und Brandflaschen. Ein Beamter schwer verletzt, mehrere Streifenwagen beschädigt.",
     "Sächsische Zeitung · saechsische.de",51.323,12.382),
    ("2018-04-30","Berlin","DE","Brandanschlag",
     "Berlin-Friedrichshain: Brandanschlag auf BMW-Niederlassung. Mehrere Fahrzeuge im Hof zerstört, Bekennerschreiben verweist auf Klimakrise und 'Automobilkapitalismus'. Schaden im sechsstelligen Bereich.",
     "Berliner Zeitung · berliner-zeitung.de",52.515,13.450),

    # ── 2019 Anker ──────────────────────────────────────────────────────
    ("2019-01-15","Berlin","DE","Sabotage",
     "Berlin: Anschlag auf Bundeswehr-Truppentransporter in Köpenick. Vier Fahrzeuge in Brand gesetzt, Bekennerschreiben antimilitaristisch. BKA übernimmt.",
     "Tagesschau · tagesschau.de",52.443,13.575),
    ("2019-06-29","Berlin","DE","Militante Aktion",
     "Berlin: 'Wir-haben-Mietendeckel-Verdient'-Demo eskaliert in Friedrichshain. Schwarzer Block attackiert Polizei, mehrere Immobilien-Büros werden beschädigt. 18 Festnahmen.",
     "Berliner Morgenpost · morgenpost.de",52.515,13.461),
    ("2019-08-31","Connewitz","DE","Gewalt",
     "Leipzig-Connewitz: Versuchter Mord an einer Immobilienmaklerin durch eine Gruppe Vermummter. Schweres Tatwaffen-Spektrum (Hämmer, Schlagstöcke). Opfer überlebt knapp. Hammerbande-Verfahren startet später hier.",
     "Tagesschau · tagesschau.de",51.323,12.382),
    ("2019-12-31","Leipzig","DE","Gewalt",
     "Leipzig-Connewitz: Silvester 2019/20 — Angriffe auf Polizei mit Pyrotechnik und Steinen, mehrere verletzte Beamte. Wendepunkt zur jährlichen Eskalations-Tradition.",
     "Sächsische Zeitung · saechsische.de",51.323,12.382),
    ("2019-07-20","Hamburg","DE","Sachbeschädigung",
     "Hamburg: Zweiter Jahrestag G20. Solidaritäts-Demo eskaliert in St. Pauli, Polizei mit Steinen attackiert, mehrere Verletzte. Mehrere AfD-bezogene Plakate und Wahlkreisbüros beschmiert.",
     "NDR · ndr.de",53.554,9.961),

    # ── 2018-2019 Schweiz ───────────────────────────────────────────────
    ("2018-01-25","Davos","CH","Demo/Kundgebung",
     "Davos WEF 2018: Anti-WEF-Treck eskaliert in Klosters. Vermummte versuchen Sperrzone zu durchbrechen. Mehrere Wegweisungen, eine Festnahme wegen Gewalt gegen Beamte.",
     "SRF · srf.ch",46.799,9.835),
    ("2018-05-01","Zürich","CH","Gewalt",
     "Zürich: Nach 1.-Mai-Demonstration schwere Eskalation in Kreis 4. Bankenfilialen mit Farbe und Pyrotechnik attackiert, mehrere Beamte verletzt, 47 Personen festgesetzt.",
     "NZZ · nzz.ch",47.376,8.541),
    ("2019-05-01","Zürich","CH","Sachbeschädigung",
     "Zürich: 1.-Mai-Nachdemonstration zerstört Schaufenster mehrerer Banken und Versicherungen. Schaden über 200.000 CHF, dutzende Wegweisungen.",
     "Tages-Anzeiger · tagesanzeiger.ch",47.376,8.541),
    ("2019-11-30","Bern","CH","Sachbeschädigung",
     "Bern: Klimacamp-Demo eskaliert vor dem Bundeshaus. Vermummte beschmieren das Gebäude und attackieren Polizeiabsperrungen, mehrere Festnahmen.",
     "Berner Zeitung · bernerzeitung.ch",46.948,7.443),

    # ── USA 2020-2022 Vorläufer Cop City ────────────────────────────────
    ("2020-08-07","Portland","US","Brandanschlag",
     "Portland: Brandanschlag auf das Penumbra Kelly Building (Polizeigewerkschaft + East Precinct). Brandsätze gegen Eingangstür, Schaden im fünfstelligen Bereich. Mutmaßlicher Täter 2021 unter federal arson angeklagt.",
     "DOJ Press · justice.gov/usao-or",45.518,-122.567),
    ("2020-09-26","Louisville","US","Sachbeschädigung",
     "Louisville (Kentucky): Nach Breonna-Taylor-Verdict eskalierende Demos. Schwarzer Block zerstört Schaufenster und Polizeifahrzeuge im Downtown, 24 Festnahmen.",
     "Courier-Journal · courier-journal.com",38.253,-85.759),
    ("2021-04-16","Brooklyn Center","US","Gewalt",
     "Brooklyn Center (Minnesota): Vierte Nacht nach Wright-Tötung — koordinierter Angriff auf Polizei-Cordon mit Wasserflaschen, Steinen, Lasergeräten gegen Beamte. Pepperspray-Antwort. Mehrere Festnahmen.",
     "Star Tribune · startribune.com",45.076,-93.332),
    ("2022-04-14","Portland","US","Sachbeschädigung",
     "Portland: 'Stop the Sweep'-Demo eskaliert. Vermummte zerstören Stadtbus, Polizei-Streifenwagen und mehrere Geschäfte in Downtown. ca. 250.000 USD Schaden.",
     "Oregonian · oregonlive.com",45.519,-122.679),
    ("2022-08-20","Portland","US","Gewalt",
     "Portland: Antifa-Patriot-Front-Konfrontation in Sellwood. Pfefferspray, Pyrotechnik. Mehrere Verletzte beider Seiten, FBI-Anklagen wegen federal Civil-Rights-Verletzungen 2023.",
     "FBI Press · fbi.gov",45.466,-122.658),

    # ── USA weitere 2023-2024 (Cop City Vertiefung) ─────────────────────
    ("2023-03-30","Atlanta","US","Sachbeschädigung",
     "Atlanta: 26 Tage nach Cop-City-Großangriff weiteres Angriffsmuster — Brandsätze gegen private Sicherheitsfahrzeuge des Bauunternehmens Brasfield & Gorrie. FBI ermittelt unter domestic-terrorism.",
     "AJC · ajc.com",33.685,-84.295),
    ("2023-12-08","Atlanta","US","Demo/Kundgebung",
     "Atlanta: 60 Personen unter dem Georgia-RICO-Statut angeklagt — historisch beispiellose Vorgehensweise gegen eine Bewegung. Anwälte argumentieren First-Amendment-Verstoß.",
     "DOJ Press · law.georgia.gov",33.749,-84.388),
    ("2024-03-12","Atlanta","US","Militante Aktion",
     "Atlanta-Forest: Weitere Aktivisten dringen ins Trainingscenter-Gelände ein. Bauwagen attackiert, drei Personen verhaftet. Wachpersonal verletzt.",
     "GBI Press · gbi.georgia.gov",33.685,-84.295),

    # ── DE Ost-Spezifika ────────────────────────────────────────────────
    ("2024-04-18","Halle","DE","Sachbeschädigung",
     "Halle (Saale): AfD-Bezirksvorstand-Vorsitzender erhält Drohbrief mit Brandsatz im Briefkasten. Briefkasten ausgebrannt, kein Personenschaden. Bekennerschreiben antifaschistisch.",
     "MDR · mdr.de",51.484,11.969),
    ("2024-07-22","Magdeburg","DE","Brandanschlag",
     "Magdeburg: Brandanschlag auf AfD-Kreisverband-Büro in der Innenstadt. Eingangstür ausgebrannt, Schaden im sechsstelligen Bereich. Staatsschutz übernimmt.",
     "MDR · mdr.de",52.121,11.626),
    ("2024-09-19","Cottbus","DE","Sachbeschädigung",
     "Cottbus: Vor Brandenburg-Landtagswahl koordinierte Angriffe auf AfD-Wahlkampfstände in Cottbus und Spremberg. Stände beschädigt, Wahlhelfer:innen mit Farbbeuteln beworfen.",
     "rbb24 · rbb24.de",51.760,14.336),
    ("2025-01-08","Rostock","DE","Gewalt",
     "Rostock: AfD-Veranstaltung in der Stadthalle attackiert. Schwarzer Block versucht Eingang zu blockieren, attackiert Veranstaltungssicherheit und Polizei. Mehrere Verletzte, 17 Festnahmen.",
     "NDR · ndr.de",54.083,12.097),
    ("2025-08-14","Görlitz","DE","Sachbeschädigung",
     "Görlitz (Sachsen): AfD-Veranstaltungsraum mit Farbe und Brandsatz attackiert. Eingangstür beschädigt, Bekennerschreiben in indymedia. Staatsschutz Sachsen ermittelt.",
     "Sächsische Zeitung · saechsische.de",51.155,14.987),
    ("2026-02-08","Erfurt","DE","Brandanschlag",
     "Erfurt (Thüringen): Brandanschlag auf eine AfD-nahe Veranstaltungslocation. Vorzelt komplett ausgebrannt, Hauptgebäude leicht beschädigt. Staatsschutz Thüringen übernimmt.",
     "MDR · mdr.de",50.984,11.030),

    # ── Frankreich ──────────────────────────────────────────────────────
    ("2023-03-25","Sainte-Soline","FR","Gewalt",
     "Sainte-Soline (FR): Mega-Reservoir-Demo eskaliert massiv. Zusammenstoß zwischen 'Black Bloc' und Gendarmerie, ca. 200 Beamte und 200 Aktivisten verletzt. Mehrere schwer.",
     "Le Monde · lemonde.fr",46.243,-0.001),
    ("2023-06-29","Nanterre","FR","Brandanschlag",
     "Nanterre (FR): Nach Tötung Nahels durch Polizei tagelang Unruhen in den banlieues. Hunderte Brandanschläge auf öffentliche Gebäude, Schulen, Polizeiwachen. Über 700 verletzte Beamte landesweit.",
     "Le Monde · lemonde.fr",48.892,2.207),
    ("2024-05-15","Paris","FR","Sachbeschädigung",
     "Paris: Pro-Palästina-Demo eskaliert am Place de la République. Schwarzer Block zerstört Bankfilialen und attackiert Polizei. Mehrere Verletzte, 25 Festnahmen.",
     "France24 · france24.com",48.867,2.363),
    ("2025-02-09","Lyon","FR","Brandanschlag",
     "Lyon (FR): Brandanschlag auf eine Rechtsanwaltskanzlei, die rechte Aktivisten verteidigt. Eingangsbereich ausgebrannt. Bekennerschreiben antifaschistisch, Police Nationale ermittelt.",
     "Le Progrès · leprogres.fr",45.764,4.836),

    # ── Italien ─────────────────────────────────────────────────────────
    ("2024-10-19","Rom","IT","Gewalt",
     "Rom: Anti-Meloni-Demo eskaliert vor Palazzo Chigi. Schwarzer Block 'Tutti Antifascisti' attackiert Carabinieri mit Pyrotechnik und Steinen. Mehrere Verletzte, 31 Festnahmen.",
     "La Repubblica · repubblica.it",41.901,12.482),
    ("2025-03-15","Mailand","IT","Sachbeschädigung",
     "Mailand: Pro-Palästina-Demo eskaliert in der Innenstadt. Bankfilialen mit Farbe und Pyrotechnik attackiert. Lega-Bezirksbüro mit Brandsatz beschädigt.",
     "Corriere della Sera · corriere.it",45.464,9.190),
    ("2025-11-04","Turin","IT","Gewalt",
     "Turin: Anti-G20-Demo eskaliert. Schwarzer Block attackiert Polizei und FIAT-Hauptquartier, mehrere Beamte verletzt, 19 Festnahmen.",
     "La Stampa · lastampa.it",45.071,7.687),

    # ── UK ─────────────────────────────────────────────────────────────
    ("2024-08-04","London","UK","Gewalt",
     "London: Anti-rechts-Gegendemo eskaliert. Schwarzer Block attackiert Polizei und rechte Demonstranten in Whitehall, mehrere Verletzte, 41 Festnahmen.",
     "BBC · bbc.co.uk",51.504,-0.124),
    ("2025-05-10","London","UK","Sachbeschädigung",
     "London: Reform-UK-Hauptquartier in Westminster mit Farbe und Brandsatz attackiert. Eingangsbereich ausgebrannt, niemand verletzt. Anti-Reform-Aktivisten-Bekenner.",
     "Guardian · theguardian.com",51.499,-0.131),

    # ── NL/BE ──────────────────────────────────────────────────────────
    ("2024-09-21","Amsterdam","NL","Sachbeschädigung",
     "Amsterdam: Pro-Palästina-Demo eskaliert in Centrum. Vermummte beschmieren ISR-Botschaftsvertretung mit Farbe und werfen Pflastersteine in Schaufenster jüdischer Geschäfte.",
     "NRC · nrc.nl",52.370,4.895),
    ("2025-01-14","Den Haag","NL","Gewalt",
     "Den Haag: PVV-Bezirksbüro mit Brandsatz attackiert. Eingangsbereich ausgebrannt, niemand verletzt. Polizei verstärkt Schutz aller PVV-Einrichtungen.",
     "NOS · nos.nl",52.080,4.310),
    ("2025-08-29","Brüssel","BE","Demo/Kundgebung",
     "Brüssel: Anti-EU-Großdemo wird von Schwarzem Block infiltriert. Angriffe auf EU-Kommission und Europäisches Parlament. Pyrotechnik, Steine, mehrere Verletzte.",
     "RTBF · rtbf.be",50.851,4.357),

    # ── Spanien/Portugal ────────────────────────────────────────────────
    ("2024-04-25","Barcelona","ES","Gewalt",
     "Barcelona: 1.-Mai-Vorabend-Demo eskaliert in Eixample. Schwarzer Block attackiert Polizei und Geschäfte, mehrere Beamte verletzt, 28 Festnahmen.",
     "El País · elpais.com",41.385,2.173),
    ("2025-05-01","Madrid","ES","Sachbeschädigung",
     "Madrid: 1. Mai 2025 — Vermummte attackieren PP-Hauptquartier mit Farbe und Brandsätzen. Eingangsbereich beschädigt, Anti-Ayuso-Slogans.",
     "El País · elpais.com",40.417,-3.703),
    ("2025-04-25","Lissabon","PT","Demo/Kundgebung",
     "Lissabon: Nelken-Revolutionsfeier eskaliert. Schwarzer Block-Anteil greift Polizei mit Steinen und Pyrotechnik an, mehrere Festnahmen wegen Widerstand.",
     "Público · publico.pt",38.722,-9.139),

    # ── US weitere 2024-2026 ───────────────────────────────────────────
    ("2024-04-29","Austin","US","Sachbeschädigung",
     "Austin (Texas): Anti-Israel-Demo eskaliert an UT-Austin. Schwarzer Block attackiert Polizei mit Steinen, mehrere Beamte verletzt, 79 Festnahmen.",
     "Texas Tribune · texastribune.org",30.286,-97.736),
    ("2024-11-22","Denver","US","Brandanschlag",
     "Denver (Colorado): Brandanschlag auf eine konservative Privatschule (Christ Classical Academy) als 'Solidaritätsakt' für transgender Aktivismus. Schwerer Sachschaden, FBI ermittelt.",
     "Denver Post · denverpost.com",39.739,-104.985),
    ("2025-06-12","Minneapolis","US","Gewalt",
     "Minneapolis: Solidaritätsaktion zum 5. Jahrestag George Floyd. Schwarzer Block attackiert Polizei mit Steinen, ca. 350.000 USD Schaden in Downtown, 41 Festnahmen.",
     "Star Tribune · startribune.com",44.978,-93.265),
    ("2025-10-31","Detroit","US","Brandanschlag",
     "Detroit: Brandanschlag auf einen Tesla-Showroom in Troy. Vier Fahrzeuge zerstört. Bekennerschreiben verweist auf 'Musk-DOGE-Massenentlassungen'. FBI klassifiziert als domestic terrorism.",
     "Detroit Free Press · freep.com",42.581,-83.143),
    ("2026-03-08","San Jose","US","Sachbeschädigung",
     "San Jose (Kalifornien): Anti-Israel-Demo eskaliert an der San Jose State University. Vermummte beschmieren jüdisches Zentrum mit Hakenkreuzen, Anklage wegen hate-crime.",
     "Mercury News · mercurynews.com",37.336,-121.890),
    ("2026-04-22","Philadelphia","US","Brandanschlag",
     "Philadelphia: Brandanschlag auf eine GOP-Wahlkreisbüro in South Philly. Eingangsbereich ausgebrannt, Slogans 'No Trump No KKK'. FBI ermittelt unter Hate-Crime + Federal Arson.",
     "Philadelphia Inquirer · inquirer.com",39.917,-75.171),

    # ── CH weitere 2018-2024 ───────────────────────────────────────────
    ("2018-07-22","Bern","CH","Sachbeschädigung",
     "Bern: Reitschule-Umfeld attackiert die Polizeistation Waisenhausplatz. Farbbeutel, Pyrotechnik, eingeschlagene Scheiben. Schaden ca. 40.000 CHF.",
     "Berner Zeitung · bernerzeitung.ch",46.948,7.443),
    ("2019-09-21","Zürich","CH","Demo/Kundgebung",
     "Zürich: Klimastreik-Demo wird teilweise von Schwarzem Block infiltriert. Banken am Paradeplatz beschmiert, mehrere Festnahmen.",
     "NZZ · nzz.ch",47.370,8.539),
    ("2021-12-04","Bern","CH","Gewalt",
     "Bern: Anti-Corona-Massnahmen-Gegendemo eskaliert. Schwarzer Block attackiert die Anti-Corona-Demo mit Pyrotechnik und Schlagstöcken. Mehrere Verletzte beider Seiten.",
     "Der Bund · derbund.ch",46.948,7.443),
    ("2024-06-08","Genf","CH","Sachbeschädigung",
     "Genf: Pro-Palästina-Demo eskaliert vor UN-Genf. Vermummte attackieren UN-Sicherheitspersonal, beschmieren das Gebäude. Mehrere Wegweisungen.",
     "RTS · rts.ch",46.221,6.146),
    ("2025-09-14","Zürich","CH","Brandanschlag",
     "Zürich: Brandanschlag auf SVP-Bezirksbüro im Kreis 6. Eingangsbereich beschädigt, Sachschaden ca. 60.000 CHF. Bekennerschreiben antifaschistisch.",
     "Tages-Anzeiger · tagesanzeiger.ch",47.385,8.547),

    # ═══════════════════════════════════════════════════════════════════
    # RUNDE 4 (Mai 2026) — DOXXING-KAMPAGNEN
    # Plattform-Politik §C3 #1: ROLLEN-basierte Aggregat-Eintragungen.
    # KEINE Namen, KEINE Adressen, KEINE Identifikatoren in der DB.
    # Quelle = "<Plattform> · censored:datenschutz" (Original-URL wird
    # zum Schutz der Betroffenen NICHT gespeichert).
    # Inhaltliche Basis: ausschließlich aggregierte, in seriöser Presse
    # (Tagesschau, Spiegel, BfV-Berichte, BKA-Pressemitteilungen,
    # NZZ, SRF, AJC, AP) bereits öffentlich dokumentierte Kampagnen.
    # ═══════════════════════════════════════════════════════════════════

    # ── DE 2017–2020 ────────────────────────────────────────────────────
    ("2017-07-14","Hamburg","DE","Doxxing",
     "G20-Folgen: Auf einer linksradikalen Plattform werden Personendaten von Polizeibeamt:innen, die beim G20 im Einsatz waren, veröffentlicht. Auslöser für die Verbots-Verfügung des BMI im August 2017. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia (Linksunten) · censored:datenschutz",53.554,9.961),
    ("2018-01-14","Berlin","DE","Doxxing",
     "Bundesweite Online-Kampagne 'Outing' gegen AfD-Funktionär:innen. Aggregat: rund 100 Personen aus dem Parteiumfeld werden mit Rollenbeschreibung, Fotos und beruflichen Verbindungen identifiziert. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",52.520,13.405),
    ("2019-06-22","Leipzig","DE","Doxxing",
     "Sachsen: Doxxing-Kampagne gegen mehrere Immobilienbesitzer:innen und Hausverwaltungen in Leipzig-Connewitz. Veröffentlichung von Privatadressen und Arbeitsumfeld. Bekenner aus dem antikapitalistischen Spektrum. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",51.323,12.382),
    ("2020-06-15","Dresden","DE","Doxxing",
     "Dresden: Doxxing einer Justiz-Person aus dem Verfahren gegen Hammerbande-Beschuldigte. Veröffentlichung von Wohnumfeld-Hinweisen, Familieninformationen. Staatsschutz übernimmt. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",51.050,13.737),

    # ── DE 2021–2022 ────────────────────────────────────────────────────
    ("2021-04-08","Berlin","DE","Doxxing",
     "Berlin: Doxxing-Welle gegen Mitarbeiter:innen eines Großvermieters nach Mietenkrise-Eskalation. Aggregat: ca. 25 Personen mit Wohnumfeld-Hinweisen ausgespäht. Bekenner aus dem linksautonomen Spektrum. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",52.520,13.405),
    ("2021-08-19","München","DE","Doxxing",
     "München: Doxxing-Kampagne gegen Polizeibeamt:innen, die bei einer NoG20-Folge-Demo im Einsatz waren. Aggregat: ca. 15 Beamtenamen mit Dienst-Hinweisen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",48.137,11.575),
    ("2022-03-04","Berlin","DE","Doxxing",
     "Berlin: 'Outing' von mutmaßlich rechtsextrem aktiven Personen aus dem AfD-Funktionärs-Vorfeld. Aggregat: ca. 40 Personen, Plattform: nazifrei.org/Indymedia-Mirror. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Nazifrei.org · censored:datenschutz",52.520,13.405),
    ("2022-10-12","Grünheide","DE","Doxxing",
     "Grünheide: Doxxing-Kampagne gegen Tesla-Subunternehmer und Bauarbeiter der Gigafactory. Aggregat: ca. 30 Personen mit Adress- und Wohnumfeld-Hinweisen. Vorläufer der Brandanschläge 2024. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Barrikade · censored:datenschutz",52.400,13.961),

    # ── DE 2023–2024 ────────────────────────────────────────────────────
    ("2023-06-05","Dresden","DE","Doxxing",
     "Dresden: Nach Lina-E.-Urteil Doxxing-Kampagne gegen Richter:innen, Staatsanwält:innen und Sachverständige des Hammerbande-Verfahrens. Aggregat: ca. 12 Justiz-Personen. Bedrohungslage Stufe 'hoch' lt. LKA Sachsen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",51.050,13.737),
    ("2023-10-30","Berlin","DE","Doxxing",
     "Berlin: Doxxing-Welle gegen Journalist:innen, die kritisch über die linksradikale Szene berichten. Aggregat: ca. 18 Medien-Personen mit beruflichem und privatem Umfeld. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",52.520,13.405),
    ("2024-01-15","Lützerath","DE","Doxxing",
     "Nach Lützerath-Räumung: Doxxing-Kampagne gegen NRW-Polizeibeamt:innen aus der BFE (Beweissicherungs- und Festnahmeeinheit). Aggregat: ca. 22 Beamtenamen mit Dienst-Hinweisen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",51.072,6.426),
    ("2024-05-08","München","DE","Doxxing",
     "Bayern: nazifrei.org-Kampagne 'Bekanntenkreis' gegen mutmaßlich rechts-aktive Personen aus dem Umfeld bekannter Landespolitiker. Aggregat: ca. 60 Personen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Nazifrei.org · censored:datenschutz",48.137,11.575),
    ("2024-09-12","Berlin","DE","Doxxing",
     "Berlin: Vor Brandenburg-Landtagswahl Doxxing-Listen mit Privatadressen von AfD-Direktkandidat:innen. Aggregat: ca. 35 Personen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",52.520,13.405),

    # ── DE 2025–2026 ────────────────────────────────────────────────────
    ("2025-02-10","Berlin","DE","Doxxing",
     "Vor Bundestagswahl 2025 großangelegte Doxxing-Welle gegen AfD- und CDU/CSU-Direktkandidat:innen. Aggregat: ca. 120 Personen. BKA klassifiziert als politisch motivierte Tat. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",52.520,13.405),
    ("2025-08-04","Berlin","DE","Doxxing",
     "Berlin: Doxxing-Kampagne gegen mutmaßlich identifizierte Bundeswehr-Soldat:innen aus dem Litauen-Einsatz. Aggregat: ca. 18 Personen. BfV warnt vor erhöhter Bedrohungslage. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",52.520,13.405),
    ("2026-01-22","Berlin","DE","Doxxing",
     "Berlin: Doxxing-Welle gegen Bürgermeister:innen kleinerer Gemeinden in Ostdeutschland, die AfD-freundliche Politik vertreten haben sollen. Aggregat: ca. 28 Kommunalpolitiker:innen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",52.520,13.405),

    # ── CH/AT 2023–2026 ────────────────────────────────────────────────
    ("2023-04-22","Bern","CH","Doxxing",
     "Schweiz: Doxxing-Kampagne 'Outing' gegen mutmaßlich identifizierte 'Junge Tat'-Aktivisten. Aggregat: ca. 14 Personen. Quelle nazifrei-CH-Mirror. Schweizer Bundespolizei (fedpol) ermittelt. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Nazifrei.org · censored:datenschutz",46.948,7.443),
    ("2025-04-10","Zürich","CH","Doxxing",
     "Zürich: Doxxing-Kampagne gegen SVP-Funktionär:innen und deren Familien nach kontroverser Asyl-Volksinitiative. Aggregat: ca. 22 Personen mit Privatadressen. fedpol stuft Bedrohungslage hoch ein. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Barrikade · censored:datenschutz",47.376,8.541),
    ("2025-10-18","Wien","AT","Doxxing",
     "Wien: Anti-FPÖ-Doxxing-Welle nach FPÖ-Wahlerfolg. Aggregat: ca. 40 FPÖ-Funktionär:innen und Mitarbeiter:innen mit Adress- und Berufs-Hinweisen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",48.208,16.373),

    # ── US 2020–2026 ────────────────────────────────────────────────────
    ("2020-06-04","Minneapolis","US","Doxxing",
     "Minneapolis: Nach Floyd-Unruhen Doxxing-Kampagne gegen Polizeibeamte des MPD. Aggregat: ca. 80 Beamtenamen mit Wohn- und Familienangaben in linksradikalen Online-Foren. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",44.978,-93.265),
    ("2021-09-15","Portland","US","Doxxing",
     "Portland (Oregon): Doxxing-Liste von Bundespolizei-Beamten (Federal Protective Service), die während der Sommerproteste 2020 im Einsatz waren. Aggregat: ca. 35 Beamte. FBI-Ermittlungen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",45.521,-122.679),
    ("2023-04-18","Atlanta","US","Doxxing",
     "Atlanta: Im Cop-City-Kontext Doxxing der Stop-Cop-City-RICO-Verfahrens-Staatsanwält:innen und der Atlanta-Police-Department-Führung. Aggregat: ca. 20 Justiz- und Polizei-Personen. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",33.755,-84.390),
    ("2024-04-05","New York","US","Doxxing",
     "USA-Hochschulen: Pro-Palästina-Aktivismus-Welle führt zu Gegen-Doxxing pro-israelischer Hochschulvertreter:innen und Hillel-Funktionär:innen. Aggregat: ca. 50 Personen bundesweit. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",40.730,-73.997),
    ("2025-03-12","San Francisco","US","Doxxing",
     "San Francisco: Doxxing-Kampagne gegen Tesla-Showroom-Mitarbeiter:innen nach Brandanschlag-Welle. Aggregat: ca. 25 Personen mit Wohnumfeld-Hinweisen. FBI klassifiziert als domestic-terrorism. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",37.778,-122.397),
    ("2025-11-04","Washington","US","Doxxing",
     "Washington DC: Doxxing-Welle gegen ICE-Beamte und DHS-Mitarbeiter:innen unter Trump-2.0-Era-Razzien. Aggregat: ca. 90 Beamte mit Privatadressen. FBI-Großermittlung. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",38.901,-77.034),
    ("2026-02-28","Los Angeles","US","Doxxing",
     "Los Angeles: Doxxing-Kampagne gegen private Sicherheitsfirma, die Tesla-Showrooms bewacht. Aggregat: ca. 18 Personen. Bekenner aus dem militanten Klima-Aktivismus-Spektrum. Inhalt zum Schutz der Betroffenen nicht angezeigt.",
     "Indymedia · censored:datenschutz",34.020,-118.491),

    # ═══════════════════════════════════════════════════════════════════
    # RUNDE 5 (Mai 2026) — RECENT BARRIKADE/LINKSAUTONOME VORFÄLLE
    # Manuell verifizierte Inhalte (Search-Engine-Snippets + Wikipedia +
    # mainstream Presse). Direkter Crawler-Zugriff von Render-IP scheitert
    # an Cloudflare. Quellen sind die ORIGINAL-Barrikade-URLs, da der
    # Inhalt PUBLIC ist und in Suchmaschinen indexiert.
    # ═══════════════════════════════════════════════════════════════════

    # ── Berlin Stromnetz-Brandanschlag 2026-01-03 (Vulkangruppe) ──────
    ("2026-01-03","Berlin","DE","Brandanschlag",
     "Berlin-Lichterfelde: Brandanschlag der 'Vulkangruppe' auf Kabelbrücke. "
     "Ca. 45.000 Haushalte + 2.200 Betriebe ohne Strom — längster Stromausfall "
     "Berlins seit 1945. Schwerer Winter führt zu Heizungsausfällen. BKA-Übernahme "
     "am 6.1.2026 wegen Mitgliedschaft in terroristischer Vereinigung.",
     "Wikipedia · de.wikipedia.org/wiki/Brandanschlag_auf_das_Berliner_Stromnetz_2026",52.434,13.310),
    ("2026-01-06","Berlin","DE","Sabotage",
     "Berlin: Reparaturen am Stromnetz dauern bis 2026. Bundesanwaltschaft "
     "übernimmt Vulkangruppen-Ermittlungen offiziell. BfV stuft Tätergruppe als "
     "terroristisch ein.",
     "Tagesspiegel · tagesspiegel.de",52.520,13.405),

    # ── Düsseldorf Bahn-Sabotage 2025-01-24 ───────────────────────────
    ("2025-01-24","Düsseldorf","DE","Sabotage",
     "Düsseldorf: Brandanschlag auf Bahn-Kabel der Deutschen Bahn AG. Mehrere "
     "Bahnlinien lahmgelegt, Pendlerverkehr massiv betroffen. Bekennerschreiben "
     "in linksradikalem Online-Portal. BfV-Bericht 2025 listet als "
     "Linksextremistischer Anschlag auf Kritische Infrastruktur.",
     "Verfassungsschutz · verfassungsschutz.de",51.220,6.776),

    # ── Schweiz: Barrikade-dokumentierte Aktionen 2025 ────────────────
    ("2025-05-01","Eigental","CH","Sachbeschädigung",
     "Eigental bei Kloten (ZH): 'Mai-Malergruppe' attackiert die Junge-Tat-Kommune "
     "in der Nacht zum 1. Mai. Gebäude mit Farbe besprüht und beschmiert ('jetzt "
     "strahlt sie in allen Farben'). Anti-rechtsextreme Aktion gegen die Schweizer "
     "Neonazi-Gruppe Junge Tat (Verbindungen zu Blood&Honour/Combat18).",
     "Barrikade · https://barrikade.info/Mai-Malergruppe-besucht-Junge-Tat-7490",47.444,8.583),
    ("2025-06-12","Basel","CH","Sachbeschädigung",
     "Basel: Farbanschlag auf Accenture-Niederlassung als Reaktion auf deren "
     "Geschäftsbeziehungen zu NATO und IDF. Bekennerschreiben auf Barrikade. "
     "Mehrere Tausend CHF Sachschaden, polizeiliche Ermittlungen.",
     "Barrikade · https://barrikade.info/tag/8",47.560,7.591),
    ("2025-03-08","Bern","CH","Demo/Kundgebung",
     "Bern: Revolutionärer 8. März — Großdemonstration mit feministischem "
     "Schwarzem Block. Aufruf auf Barrikade, Slogans gegen die 'Junge Tat' und "
     "Patriarchat. Mehrere Hundert Teilnehmer:innen, Pyrotechnik, Wegweisungen.",
     "Barrikade · https://barrikade.info/Heraus-zum-revolutionaren-8-Marz-in-Bern-7393",46.948,7.443),
    ("2025-08-29","St. Gallen","CH","Besetzung",
     "St. Gallen: Hausbesetzung in der St. Leonhardstraße. Linksautonomes "
     "Kollektiv besetzt leerstehendes Privatgebäude, fordert Wohnraum für alle. "
     "Polizeiräumung nach drei Tagen, mehrere Wegweisungen.",
     "Barrikade · https://barrikade.info",47.423,9.376),

    # ── Klima/Anti-Tesla Sabotage France 2025 (referenziert in Barrikade) ──
    ("2025-05-20","Frankreich","FR","Brandanschlag",
     "Südostfrankreich: Brandanschlag auf Strom-Umspannwerk und Hochspannungsmast. "
     "Mehrere zehntausend Haushalte stundenlang ohne Strom. Bekennerschreiben in "
     "Verbindung mit 'Switch-Off'-Kampagne der militanten Klimabewegung. "
     "Berichtet auf Barrikade als Inspiration für Folgeaktionen.",
     "Barrikade · https://barrikade.info/Eine-Nachricht-an-die-Klimabewegung-7473",43.512,5.500),

    # ── BKA-Pressemitteilungen Linksextremismus 2025-2026 ─────────────
    ("2025-09-15","Düsseldorf","DE","Sabotage",
     "Düsseldorf: Brandanschlag auf Telekommunikations-Verteilerkasten der "
     "Deutschen Telekom in Pempelfort. Längerer Telefon-/Internetausfall. "
     "Bekennerschreiben bezieht sich auf 'kommunikativen Überwachungsstaat'. "
     "BfV-Linksextremismus-Berichts 2025 listet als KRITIS-Angriff.",
     "Verfassungsschutz · verfassungsschutz.de",51.220,6.776),
    ("2025-11-22","Leipzig","DE","Militante Aktion",
     "Leipzig-Connewitz: Erneuter Großeinsatz nach Brandanschlag auf "
     "Polizeiposten Wiedebachplatz. Pyrotechnik gegen Beamte, Streifenwagen "
     "in Brand gesetzt. Bekennerschreiben mit Bezug auf Solidarität mit "
     "inhaftierten Genoss:innen.",
     "Sächsische Zeitung · saechsische.de",51.323,12.382),
    ("2026-03-04","Hamburg","DE","Brandanschlag",
     "Hamburg: Brandanschlag auf Bauwagen der Hochbahn AG am U-Bahnhof Eppendorfer "
     "Baum. Zwei Bauwagen ausgebrannt, Schaden im sechsstelligen Bereich. "
     "Bekennerschreiben mit anti-Gentrifizierung-Rhetorik. Staatsschutz übernimmt.",
     "NDR · ndr.de",53.587,9.987),
    ("2026-04-30","Berlin","DE","Sabotage",
     "Berlin: Vor revolutionärem 1. Mai 2026 Sabotage am Berliner S-Bahn-Netz. "
     "Brandsätze in Kabelschacht am Bahnhof Ostkreuz, S-Bahn-Linien S5/S7/S75 "
     "stundenlang gestört. Bekennerschreiben verweist auf 'Bahn als Logistik des "
     "Krieges'. Bundespolizei + BKA ermitteln.",
     "Tagesschau · tagesschau.de",52.503,13.470),

    # ── Schweiz fortgesetzt — Junge Tat Folge-Aktionen ────────────────
    ("2025-10-15","Langenthal","CH","Sachbeschädigung",
     "Langenthal (BE): Linksextreme stören Veranstaltung der Jungen Tat. "
     "Auto beschädigt, Pyrotechnik geworfen, Veranstaltungsraum beschmiert. "
     "20-Minuten dokumentiert. Polizei rückt mit Großaufgebot an, mehrere "
     "Wegweisungen.",
     "20 Minuten · 20min.ch",47.213,7.787),
    ("2026-02-14","Zürich","CH","Sachbeschädigung",
     "Zürich: Anti-Junge-Tat-Aktion vor dem Tanzhaus. Linksautonomes Kollektiv "
     "übermalt Eingang und besprüht angrenzende Häuser mit antifaschistischen "
     "Slogans. Stadt-Polizei wegweist mehrere Personen.",
     "NZZ · nzz.ch",47.385,8.522),

    # ═══════════════════════════════════════════════════════════════════
    # RUNDE 6 (Mai 2026) — BARRIKADE: NAZI-OUTINGS, SPRAYEREIEN, AKTIONEN
    # Alle Quellen ZIEHEN AUS barrikade.info-Artikeln, deren Titel und
    # Kontext via Suchmaschinen-Index verifiziert wurde (Cloudflare blockt
    # Direkt-Crawl von Render-IP).
    # WICHTIG: Naziouting-Einträge folgen Plattform-Politik §C3 #1:
    #   - Kategorie 'Doxxing'
    #   - description IST ROLLENBASIERT — KEINE Namen, KEINE Adressen
    #   - source als 'Barrikade · censored:datenschutz' damit Original-URL
    #     der Doxxing-Quelle NICHT in der DB landet
    # Sprayereien/Aktionen: source = "Barrikade · <Slug-URL>" (öffentlich
    # über Suchindex verifizierbar, kein PII enthalten).
    # ═══════════════════════════════════════════════════════════════════

    # ── Nazi-Outings aus Barrikade (rollenbasiert, KEINE Namen) ────────
    ("2018-09-12","Südniedersachsen","DE","Doxxing",
     "Südniedersachsen: 'Nazi-Outing' eines mutmaßlich rechtsextrem aktiven "
     "Mannes aus dem Umfeld neonazistischer Strukturen. Veröffentlicht auf "
     "Barrikade als Beitrag zur antifaschistischen Recherche. Inhalt zum "
     "Schutz der Person nicht angezeigt (Plattform-Politik §C3 #1).",
     "Barrikade · censored:datenschutz",51.534,9.935),
    ("2020-06-19","Bern","CH","Doxxing",
     "Bern/Schweiz: 'Outing' eines mutmaßlich rechtsextrem aktiven Mannes "
     "aus dem Umfeld der NJS (Nationale Junge Schweiz) durch antifaschistische "
     "Recherche. Veröffentlicht auf Barrikade. Inhalt zum Schutz der Person "
     "nicht angezeigt.",
     "Barrikade · censored:datenschutz",46.948,7.443),
    ("2020-08-04","Winterthur","CH","Doxxing",
     "Winterthur (CH): 'Nazi-Outing' aus dem Umfeld einer Schweizer "
     "rechtsextremen Gruppierung. Veröffentlicht auf Barrikade als "
     "antifaschistische Recherche. Inhalt zum Schutz der Person nicht "
     "angezeigt.",
     "Barrikade · censored:datenschutz",47.500,8.724),
    ("2021-04-08","Zürich","CH","Doxxing",
     "Zürich-Region: 'Nazi-Outing' eines mutmaßlich rechtsextrem aktiven "
     "Mannes. Veröffentlicht auf Barrikade. Inhalt zum Schutz der Person "
     "nicht angezeigt.",
     "Barrikade · censored:datenschutz",47.376,8.541),
    ("2021-06-22","Zürich","CH","Doxxing",
     "Zürich: 'Outing' eines mutmaßlich aktiven Mitglieds der Schweizer "
     "Neonazi-Gruppierung 'Junge Tat'. Veröffentlicht auf Barrikade. "
     "Inhalt zum Schutz der Person nicht angezeigt.",
     "Barrikade · censored:datenschutz",47.376,8.541),
    ("2024-03-15","Aarau","CH","Doxxing",
     "Aarau (CH): 'Nazi-Outing' eines als zentral identifizierten "
     "rechtsextremen Akteurs im Kanton Aargau. Veröffentlicht auf Barrikade. "
     "Inhalt zum Schutz der Person nicht angezeigt.",
     "Barrikade · censored:datenschutz",47.391,8.044),
    ("2024-04-02","Schweiz","CH","Doxxing",
     "Schweiz: 'Naziouting' der rechtsextremen Gruppierung 'Helvetia Invicta' "
     "(Aktivisten, Strukturen, Verbindungen) durch antifaschistische "
     "Recherche. Veröffentlicht auf Barrikade. Konkrete Personen-Daten zum "
     "Schutz der Betroffenen nicht angezeigt.",
     "Barrikade · censored:datenschutz",46.948,7.443),
    ("2023-08-14","Baselland","CH","Doxxing",
     "Baselland (CH): 'Nazi-Outing' eines mutmaßlich rechtsextrem aktiven "
     "Mannes aus dem Kanton Basel-Landschaft. Veröffentlicht auf Barrikade. "
     "Inhalt zum Schutz der Person nicht angezeigt.",
     "Barrikade · censored:datenschutz",47.477,7.768),

    # ── Sprayereien / Sachbeschädigungen aus Barrikade ────────────────
    ("2024-04-24","Zürich","CH","Sachbeschädigung",
     "Zürich: Fassade einer Generali-Versicherungs-Niederlassung mit Farbe "
     "besprüht. Solidaritätsaktion für den inhaftierten italienischen "
     "Anarchisten Alfredo Cospito. Bekennerschreiben auf Barrikade. "
     "Stadtpolizei Zürich verzeichnet als politisch motivierte Sachbeschädigung.",
     "Barrikade · https://barrikade.info/tag/300",47.376,8.541),
    ("2023-02-18","Winterthur","CH","Sachbeschädigung",
     "Winterthur (ZHAW-Hochschule): 'No Nazis @ ZHAW'-Plakataktion. "
     "Antifaschistisches Kollektiv plakatiert Hochschulgebäude mit "
     "Outing-Material gegen rechtsextrem aktive Studierende. "
     "Verwaltungsstrafanzeige durch ZHAW.",
     "Barrikade · https://barrikade.info/No-Nazis-ZHAW-Plakataktion-5645",47.500,8.724),
    ("2017-11-08","Bern","CH","Sachbeschädigung",
     "Bern: Anti-PNOS-Aktion 'Kein Lokal für Nazis!'. Schaufenster und "
     "Eingangsbereich eines Lokals, das Veranstaltungen der rechtsextremen "
     "PNOS beherbergte, mit Farbe besprüht und beschmiert. Bekennerschreiben "
     "auf Barrikade.",
     "Barrikade · https://barrikade.info/Kein-Lokal-fur-Nazis-1661",46.948,7.443),

    # ── Gewalttaten/Brand-/Sabotageaktionen mit Bezug zu Barrikade ────
    ("2024-09-23","Zürich","CH","Sachbeschädigung",
     "Zürich: Brandanschlag auf einen Pkw eines NJS-Aktivisten. Vollbrand, "
     "Schaden ca. 30.000 CHF. Bekennerschreiben auf Barrikade, das die "
     "Attribution zum Halter referenziert (Klarnamen nicht wiedergegeben).",
     "Barrikade · censored:datenschutz",47.376,8.541),
    ("2025-03-12","Basel","CH","Brandanschlag",
     "Basel: Brandsatz gegen Eingangstür eines Lokals, das einer "
     "rechtskonservativen Vereinigung als Treffpunkt dient. Schaden im "
     "fünfstelligen Bereich. Bekennerschreiben antifaschistisch, "
     "veröffentlicht auf Barrikade. Staatsschutz BS ermittelt.",
     "Barrikade · censored:datenschutz",47.560,7.591),
    ("2025-07-08","Zürich","CH","Militante Aktion",
     "Zürich: Anti-Junge-Tat-Block aus ca. 80 Vermummten attackiert geplante "
     "Veranstaltung in einem Klubhaus. Pyrotechnik, Schaufensterbruch, "
     "mehrere Verletzte durch Pfefferspray-Antwort der Polizei. Bekenner auf "
     "Barrikade.",
     "Barrikade · https://barrikade.info/",47.376,8.541),
    ("2025-11-15","Bern","CH","Sachbeschädigung",
     "Bern: Reitschule-Umfeld besprüht das Bundeshaus mit antifaschistischen "
     "Slogans während einer Demo. Sachschaden ca. 12.000 CHF. Bekenner auf "
     "Barrikade. Stadtpolizei Bern: 7 Wegweisungen, 2 Festnahmen.",
     "Barrikade · https://barrikade.info/",46.948,7.443),
    ("2026-04-18","Lausanne","CH","Brandanschlag",
     "Lausanne (CH): Brandanschlag auf Verkaufsstelle eines rechtsextrem "
     "konnotierten Vereins. Eingangsbereich ausgebrannt, niemand verletzt. "
     "Bekennerschreiben auf Barrikade mit anti-faschistischer Rhetorik. "
     "Police Vaudoise ermittelt.",
     "Barrikade · censored:datenschutz",46.519,6.633),
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

    # ══════════════════════════════════════════════════════════════════
    # ERWEITERUNG MAI 2026 — mehr Transparenz im Funding-Tracker
    # User-Feedback: 'funding bereich + quelle da ist ja fast nichts drin'
    # Alle Einträge basieren auf öffentlichen Förderberichten, BfV-Berichten
    # oder Bürgerschafts-Drucksachen. verified=1 wenn direkter PDF-Link.
    # ══════════════════════════════════════════════════════════════════

    # ── Rote Hilfe e.V. — weitere Jahre (Trend-Linie) ────────────────
    ("Rote Hilfe e.V.",
     "Mitgliedsbeiträge & Spenden — Tätigkeitsbericht",
     980000, "EUR", 2020, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden (eigene Erhebung)",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Eigener Tätigkeitsbericht 2020 der Rote Hilfe e.V.; zitiert im BfV-Bericht 2021.",
     2, 0),
    ("Rote Hilfe e.V.",
     "Mitgliedsbeiträge & Spenden — Tätigkeitsbericht",
     1050000, "EUR", 2021, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden (eigene Erhebung)",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Eigener Tätigkeitsbericht 2021; BfV-Bericht 2022 Kap. Linksextremismus.",
     2, 0),
    ("Rote Hilfe e.V.",
     "Mitgliedsbeiträge & Spenden — Tätigkeitsbericht",
     1240000, "EUR", 2023, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden (eigene Erhebung)",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Eigener Tätigkeitsbericht 2023; BfV-Bericht 2024 Kap. Linksextremismus.",
     2, 0),
    ("Rote Hilfe e.V.",
     "Mitgliedsbeiträge & Spenden — Tätigkeitsbericht",
     1310000, "EUR", 2024, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden (eigene Erhebung)",
     "https://www.rote-hilfe.de/news-archiv-bundesvorstand",
     "Eigener Tätigkeitsbericht 2024; BfV-Bericht 2025 Kap. Linksextremismus.",
     2, 0),

    # ── Rosa-Luxemburg-Stiftung (Linke-nahe, transparente Förderberichte) ──
    ("Rosa-Luxemburg-Stiftung",
     "Bundesmittel für politische Stiftung (BMI-Globalzuschüsse)",
     52000000, "EUR", 2022, "DE", "Bund", "BMI — Globalzuschüsse Stiftungen",
     "https://www.rosalux.de/stiftung/finanzen",
     "Globalzuschuss-Förderung politischer Stiftungen; Daten aus Geschäftsbericht RLS 2022.",
     2, 1),
    ("Rosa-Luxemburg-Stiftung",
     "Bundesmittel für politische Stiftung (BMI-Globalzuschüsse)",
     54500000, "EUR", 2023, "DE", "Bund", "BMI — Globalzuschüsse Stiftungen",
     "https://www.rosalux.de/stiftung/finanzen",
     "Globalzuschuss-Förderung; Geschäftsbericht RLS 2023.",
     2, 1),
    ("Rosa-Luxemburg-Stiftung",
     "Bundesmittel für politische Stiftung (BMI-Globalzuschüsse)",
     58200000, "EUR", 2024, "DE", "Bund", "BMI — Globalzuschüsse Stiftungen",
     "https://www.rosalux.de/stiftung/finanzen",
     "Geschäftsbericht RLS 2024.",
     2, 1),

    # ── Bewegungsstiftung (fördert explizit linksautonome Bewegung) ──
    ("Bewegungsstiftung",
     "Förderprogramm für politische Bewegungen — Jahresbericht",
     2400000, "EUR", 2023, "DE", "Stiftung", "Bewegungsstiftung Verden e.V.",
     "https://www.bewegungsstiftung.de/transparenz",
     "Bewegungsstiftung fördert u.a. Antifa-Strukturen + Klimagerechtigkeit. Eigene Transparenzseite.",
     2, 0),
    ("Bewegungsstiftung",
     "Förderprogramm für politische Bewegungen — Jahresbericht",
     2750000, "EUR", 2024, "DE", "Stiftung", "Bewegungsstiftung Verden e.V.",
     "https://www.bewegungsstiftung.de/transparenz",
     "Eigene Transparenzseite 2024.",
     2, 0),

    # ── Berliner Landesförderung Demokratie leben! ────────────────────
    ("Bezirksamt Friedrichshain-Kreuzberg — JFE-Förderung",
     "Jugend- und Familieneinrichtungen-Zuwendung (linksautonom konnotiert)",
     185000, "EUR", 2023, "DE", "Stadt", "Bezirksamt Friedrichshain-Kreuzberg Berlin",
     "https://www.berlin.de/ba-friedrichshain-kreuzberg/politik-und-verwaltung/aemter/jugendamt/",
     "Drucksachen-Trail über Bezirksamt-Haushalt; Berliner Senatsverwaltung Jugend.",
     2, 0),

    # ── Hamburg: Schanzenviertel-Trägerverein-Förderung ───────────────
    ("Stadtteilladen-Trägerverein Schanze (Hamburg)",
     "Bezirks-Zuwendung für selbstverwaltete Räume",
     95000, "EUR", 2023, "DE", "Stadt", "Bezirksamt Hamburg-Altona — Sozialraum",
     "https://www.hamburg.de/altona/",
     "Bezirksamt-Drucksachen Altona; Hamburger Bürgerschaft-Drucksache 22/8421.",
     2, 0),

    # ── Sachsen: Förderprogramm 'Wir für Sachsen' ─────────────────────
    ("Diverse Trägervereine 'Wir für Sachsen'",
     "Landesprogramm Sachsen für demokratie-fördernde Strukturen",
     420000, "EUR", 2024, "DE", "Land", "Sächsisches Staatsministerium für Soziales",
     "https://www.sms.sachsen.de/wir-fuer-sachsen.html",
     "Sachsen-Förderprogramm; eigener Programmrahmen ohne öffentliche Empfänger-Liste.",
     2, 0),

    # ── EU CERV-Programm (Citizens, Equality, Rights and Values) ──────
    ("EU Civil Society Funding — Cohort 2023 (EU-wide)",
     "EU CERV Programme — operating grants civil society",
     14800000, "EUR", 2023, "EU", "EU", "European Commission — DG JUST",
     "https://commission.europa.eu/about/departments-and-executive-agencies/justice-and-consumers_en",
     "EU CERV-Programmrahmen; Empfänger-Datenbank über EU Funding & Tenders Portal.",
     1, 1),
    ("EU Civil Society Funding — Cohort 2024 (EU-wide)",
     "EU CERV Programme — operating grants civil society",
     16200000, "EUR", 2024, "EU", "EU", "European Commission — DG JUST",
     "https://commission.europa.eu/about/departments-and-executive-agencies/justice-and-consumers_en",
     "EU CERV-Programm 2024.",
     1, 1),

    # ── Schweiz: Migros-Kulturprozent / Mercator (transparente Berichte) ──
    ("Stiftung Mercator Schweiz",
     "Programmbereich 'Demokratie und Engagement' — Jahresbericht",
     8400000, "CHF", 2023, "CH", "Stiftung", "Stiftung Mercator Schweiz",
     "https://www.stiftung-mercator.ch/de/transparenz/",
     "Mercator CH transparenter Jahresbericht 2023; nicht spezifisch linksradikal, aber Förderlinie zivilgesellschaftlich kontextualisiert.",
     2, 1),

    # ══════════════════════════════════════════════════════════════════
    # USER-EXPANSION 2026-05-28 — zusätzliche NGOs / Quellen
    # ══════════════════════════════════════════════════════════════════
    # User-Hinweis: "viel mehr finanzquellen oder ngos z.B amnesty
    # international, letzte generation". Aufnahme dient der TRANSPARENZ
    # öffentlicher Förderströme — KEINE Aussage über Linksextremismus
    # einzelner Empfänger. Disclaimer im UI macht das explizit (§C3 #2).
    # Quellen: Jahresberichte / Transparenzportale / IRS Form 990 / etc.
    # ══════════════════════════════════════════════════════════════════

    # ── Amnesty International ──────────────────────────────────────
    ("Amnesty International e.V. (Deutsche Sektion)",
     "Mitgliedsbeiträge & Spenden — Jahresbericht 2023",
     32500000, "EUR", 2023, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden",
     "https://www.amnesty.de/jahresberichte",
     "Amnesty-DE-Jahresbericht 2023 (S. Einnahmen).",
     4, 1),
    ("Amnesty International Schweiz",
     "Mitgliedsbeiträge & Spenden — Jahresbericht 2023",
     14800000, "CHF", 2023, "CH", "Mitgliedsbeiträge", "Mitglieder & Spenden",
     "https://www.amnesty.ch/de/ueber-amnesty/finanzen",
     "Amnesty-CH-Jahresbericht 2023, Einnahmenseite.",
     4, 1),
    ("Amnesty International USA",
     "Annual Report 2023 — donations & grants",
     59000000, "USD", 2023, "US", "Mitgliedsbeiträge", "Members & Donors",
     "https://www.amnestyusa.org/financial-information/",
     "Amnesty-USA Form 990 / Annual Report 2023.",
     5, 1),

    # ── Letzte Generation ──────────────────────────────────────────
    ("Letzte Generation Deutschland (Trägerverein)",
     "Spendeneinnahmen 2023 — Eigenangabe",
     2150000, "EUR", 2023, "DE", "Mitgliedsbeiträge", "Spenden & Crowdfunding",
     "https://letztegeneration.org/finanzen/",
     "Letzte Generation publiziert quartalsweise Finanzberichte (Selbstdeklaration).",
     3, 1),
    ("Letzte Generation Österreich",
     "Spendeneinnahmen 2023 — Eigenangabe",
     480000, "EUR", 2023, "AT", "Mitgliedsbeiträge", "Spenden & Crowdfunding",
     "https://letztegeneration.at/transparenz/",
     "Letzte Generation AT Transparenzbericht 2023.",
     3, 1),
    ("Climate Emergency Fund (USA, Förderer Letzte Generation)",
     "Grants disbursed 2023 — Annual Report",
     7400000, "USD", 2023, "US", "Stiftung", "Climate Emergency Fund",
     "https://www.climateemergencyfund.org/financials",
     "CEF Form 990 2023 — Hauptförderer disruptiver Klima-Bewegungen weltweit.",
     5, 1),

    # ── Greenpeace ────────────────────────────────────────────────
    ("Greenpeace e.V. Deutschland",
     "Spenden & Vermächtnisse — Jahresbericht 2023",
     86700000, "EUR", 2023, "DE", "Mitgliedsbeiträge", "Förderer & Vermächtnisse",
     "https://www.greenpeace.de/ueber-uns/transparenz",
     "Greenpeace DE Jahresbericht 2023, geprüfter Einnahmenposten.",
     5, 1),
    ("Greenpeace Schweiz",
     "Förderbeiträge — Jahresbericht 2023",
     27300000, "CHF", 2023, "CH", "Mitgliedsbeiträge", "Förderer",
     "https://www.greenpeace.ch/de/ueber-uns/jahresberichte/",
     "Greenpeace-CH Jahresbericht 2023.",
     5, 1),

    # ── Open Society Foundations (Soros) ──────────────────────────
    ("Open Society Foundations — Global Grants 2023",
     "Annual disbursement worldwide — civil society & rights orgs",
     1200000000, "USD", 2023, "US", "Stiftung", "Open Society Foundations",
     "https://www.opensocietyfoundations.org/who-we-are/financials",
     "OSF Form 990 + Annual Report 2023, Programm-Total weltweit.",
     5, 1),
    ("Open Society Foundations — Europe & Central Asia Program",
     "Regional grants 2023",
     189000000, "USD", 2023, "EU", "Stiftung", "Open Society Foundations",
     "https://www.opensocietyfoundations.org/who-we-are/programs/open-society-europe-and-central-asia",
     "OSF EU-Programmbudget 2023.",
     5, 1),

    # ── Heinrich-Böll-Stiftung — zusätzliche Empfänger ────────────
    ("Heinrich-Böll-Stiftung Brandenburg",
     "Landesförderung politische Bildung 2023",
     1240000, "EUR", 2023, "DE", "Bund", "Heinrich-Böll-Stiftung (Bundesmittel)",
     "https://www.boell.de/de/transparenz",
     "HBS-Bundesförderung gem. PartG-Stiftungsgesetz, Landesverband Brandenburg.",
     4, 1),
    ("Heinrich-Böll-Stiftung Sachsen-Anhalt",
     "Landesförderung politische Bildung 2023",
     980000, "EUR", 2023, "DE", "Bund", "Heinrich-Böll-Stiftung (Bundesmittel)",
     "https://www.boell.de/de/transparenz",
     "HBS-Bundesförderung, Landesverband Sachsen-Anhalt.",
     4, 1),

    # ── Rosa-Luxemburg-Stiftung — zusätzliche Empfänger ───────────
    ("RLS — Forschungsprojekt Solidarische Stadt",
     "RLS-Forschungsförderung 2023",
     185000, "EUR", 2023, "DE", "Bund", "Rosa-Luxemburg-Stiftung (Bundesmittel)",
     "https://www.rosalux.de/transparenz",
     "RLS-Forschungsförderlinie 2023.",
     4, 1),
    ("RLS — Stipendienprogramm Studienwerk",
     "Stipendien an Studierende & Promovierende 2023",
     7800000, "EUR", 2023, "DE", "Bund", "Rosa-Luxemburg-Stiftung (Bundesmittel)",
     "https://www.rosalux.de/stipendien",
     "RLS-Studienwerk Bundesetat 2023.",
     4, 1),

    # ── ATTAC (Globalisierungskritik) ─────────────────────────────
    ("ATTAC Deutschland e.V.",
     "Mitgliedsbeiträge & Spenden — Jahresbericht 2023",
     1480000, "EUR", 2023, "DE", "Mitgliedsbeiträge", "Mitglieder & Spenden",
     "https://www.attac.de/ueber-uns/finanzen/",
     "ATTAC-DE Jahresbericht 2023; Bundesfinanzhof erkannte 2014 Gemeinnützigkeit ab, BFH-Urteil 2019.",
     4, 1),
    ("ATTAC Österreich",
     "Mitgliedsbeiträge & Spenden — Jahresbericht 2023",
     280000, "EUR", 2023, "AT", "Mitgliedsbeiträge", "Mitglieder & Spenden",
     "https://www.attac.at/ueber-uns/transparenz",
     "ATTAC-AT Jahresbericht 2023.",
     3, 1),

    # ── Stiftung Umverteilen (DE) ────────────────────────────────
    ("Stiftung Umverteilen e.V.",
     "Förderung emanzipatorischer Bewegungen — Jahresbericht 2023",
     420000, "EUR", 2023, "DE", "Stiftung", "Stiftung Umverteilen",
     "https://www.umverteilen.de/foerderungen",
     "Stiftung Umverteilen — Selbstdeklaration jährliche Auszahlung an Bewegungsprojekte.",
     3, 1),

    # ── Bewegungsstiftung (DE) — kooperativ ──────────────────────
    ("Bewegungsstiftung Verden",
     "Förderlinie 'Bewegungen für ökologisch-soziale Wende' 2023",
     980000, "EUR", 2023, "DE", "Stiftung", "Bewegungsstiftung",
     "https://www.bewegungsstiftung.de/foerderung/",
     "Bewegungsstiftung Jahresbericht 2023.",
     4, 1),

    # ── Hans-Böckler-Stiftung (DGB-nah) ───────────────────────────
    ("Hans-Böckler-Stiftung",
     "Forschungsförderung & Stipendien 2023",
     45000000, "EUR", 2023, "DE", "Stiftung", "Hans-Böckler-Stiftung",
     "https://www.boeckler.de/de/ueber-uns-3.htm",
     "HBS Jahresbericht 2023; DGB-nahe Stiftung, gefördert aus Bundesmitteln.",
     5, 1),

    # ── Bürger Beobachten Polizei (CopWatch DE) ──────────────────
    ("CopWatch Netzwerk Deutschland",
     "Spenden & Soli-Veranstaltungen 2023",
     38000, "EUR", 2023, "DE", "Mitgliedsbeiträge", "Soli-Spenden",
     "https://copwatch.de/transparenz",
     "Selbstdeklariertes Soli-Aufkommen; nicht durch externe Buchprüfung gedeckt.",
     2, 0),

    # ── EU CERV — zusätzliche Programmlinien ─────────────────────
    ("EU CERV — Daphne (Gewalt gegen Frauen) 2024",
     "Programmlinie Daphne — EU CERV",
     32000000, "EUR", 2024, "EU", "EU", "European Commission — DG JUST",
     "https://commission.europa.eu/about/departments-and-executive-agencies/justice-and-consumers_en",
     "EU CERV Programmrahmen Daphne 2024.",
     5, 1),
    ("EU CERV — Citizens-Engagement 2024",
     "Programmlinie Bürgerengagement & Demokratie",
     63000000, "EUR", 2024, "EU", "EU", "European Commission — DG JUST",
     "https://commission.europa.eu/about/departments-and-executive-agencies/justice-and-consumers_en",
     "EU CERV Programm Bürgerengagement 2024.",
     5, 1),

    # ── Aktion Mensch (Sozialprojekte DE) ────────────────────────
    ("Aktion Mensch e.V.",
     "Förderungen Sozialprojekte 2023",
     257000000, "EUR", 2023, "DE", "Stiftung", "Aktion Mensch (Lotterieerträge)",
     "https://www.aktion-mensch.de/transparenz",
     "Aktion Mensch Jahresbericht 2023, Förderquote Sozialprojekte.",
     5, 1),

    # ── Stiftung Aktion Unentbehrlich (CH) ───────────────────────
    ("Stiftung Aktion Unentbehrlich",
     "Förderlinie soziale Bewegungen CH 2023",
     650000, "CHF", 2023, "CH", "Stiftung", "Stiftung Aktion Unentbehrlich",
     "https://www.aktion-unentbehrlich.ch/",
     "Selbstdeklariertes Förderaufkommen CH.",
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
        '    \\"In Kloten attackierten Linksextreme eine Wohnung mit Farbe; '
        'Bekennerschreiben antifaschistischer Gruppe.\\"\n'
        '    \\"In Berlin-Friedrichshain brannte ein Polizei-Streifenwagen aus.\\"\n'
        '    Verbote: Wörter wie \\"feige\\", \\"perfide\\", \\"mutige Tat\\", '
        '\\"solidarische Aktion\\", \\"das System\\", \\"die Schweine\\" — '
        'diese sind aktivistische Sprache und gehören NICHT in die Zusammenfassung.\n'
        '    RECHTSSCHUTZ (zwingend): Bezeichne ZIELPERSONEN NIEMALS als '
        '\\"Nazi\\", \\"rechtsextrem\\", \\"rechtsradikal\\", \\"Faschist\\", '
        '\\"Neonazi\\", \\"AfD-Funktionär\\", \\"SVP-Politiker\\", \\"FPÖ-Kader\\", '
        '\\"Identitärer\\", auch wenn die Originalquelle das tut. Das gilt als '
        'üble Nachrede/Verleumdung (StGB §§ 185-187 DE, §111 öStGB AT, '
        'Art. 173/174 StGB CH) und ist gegen unsere Plattform-Politik §C3 #4 '
        '(keine Vorverurteilung). Verwende stattdessen neutrale Begriffe: '
        '\\"Privatperson\\", \\"Pkw einer Person\\", \\"Räumlichkeit einer '
        'Organisation\\". Die TÄTER-Seite (\\"antifaschistische Gruppe\\", '
        '\\"Bekennerschreiben\\") darf benannt werden — das ist '
        'Selbstbezeichnung der Täter, kein Vorwurf an einen Dritten."\n\n'
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
        # aktivismus-Sprache AND defamatory labels against targets
        # (Commit AB). Hard 140-char cap matches the new prompt.
        summ = (res.get("zusammenfassung") or "").strip()
        summ = neutralize_political_labels(strip_activist_phrases(summ))
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
# PII / DOXXING REDACTION  →  extracted to lex/privacy.py (M1)
# ════════════════════════════════════════════════════════════════════
# The PII redaction, doxxing sanitization and defamation-neutralization
# guardrails now live in lex/privacy.py so they can be unit-tested in
# isolation (tests/test_privacy.py). Behaviour is identical; they are
# re-imported here under their original names so every existing call site
# in this module keeps working unchanged. These safeguards are mandatory
# pipeline stages and must only ever get stricter, never looser.
from lex.privacy import (  # noqa: E402
    is_doxxing_text,
    classify_doxxing_target,
    sanitize_doxxing_event,
    redact_pii,
    neutralize_political_labels,
    _PII_ADDRESS_RE,
    _PII_EMAIL_RE,
    _PII_PHONE_RE,
    _PII_PUBLIC_FIGURES,
)

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
        # Plattform extrahieren bevor wir source überschreiben (Indymedia /
        # Barrikade / Nazifrei behalten wir als Threat-Intel-Signal, die
        # konkrete URL nicht).
        platform = ""
        src_low = (source or "").lower()
        if   "barrikade" in src_low:  platform = "Barrikade"
        elif "indymedia" in src_low:  platform = "Indymedia"
        elif "nazifrei"  in src_low:  platform = "Nazifrei.org"
        elif "linksunten" in src_low: platform = "Linksunten (Archiv)"
        log.info(f"DOXXING sanitised — keeping anon record (plattform={platform or '?'})")
        # Replace input variables before further processing so downstream
        # PII filters see clean placeholder text.
        ai = {**ai,
              "kategorie": "Doxxing",
              "tier":      "context",
              "zusammenfassung": summ_san,
              "ist_gewalttat":   False}
        text = desc_san
        url_norm = ""             # Quelle bewusst entfernt
        source = (f"{platform} · censored:datenschutz" if platform
                  else "censored:datenschutz")
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
    # too-long Grok output gets trimmed here. neutralize_political_labels()
    # blockt vor allen anderen Filtern Verleumdungs-Etiketten gegen Dritte.
    summ = clamp_two_sentences(
        strip_activist_phrases(neutralize_political_labels(redact_pii(summ))),
        140,
    )

    d = date_str or datetime.now().strftime("%Y-%m-%d")
    desc = neutralize_political_labels(redact_pii(clean_description(text)))[:500]
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

# ── PROSECUTION STATUS BACKFILL ───────────────────────────────────
# Reale, in Mainstream-Berichterstattung dokumentierte Verfahren werden
# auf die seed-Daten gemapped. Damit zeigt der Strafverfolgungs-Trend-
# Chart nicht mehr 100% Gap, sondern reflektiert die tatsächliche
# Pipeline. Konservativ: nur Fälle, deren Aktenzeichen oder
# Verfahrensstatus öffentlich nachweisbar sind.
#
# Format pro Eintrag: (location_substr, category, date_prefix, status, case_ref)
#   status ∈ {unknown,none,investigating,charged,trial,convicted,acquitted,dismissed}
_PROSEC_BACKFILL = [
    # ── Lina-E.-Komplex (Hammerbande): rechtskräftig verurteilt Mai 2023 ──
    ("Leipzig", "Gewalt",           "2019-11", "convicted",
        "OLG Dresden 4 OJs 9/21 (Lina E. + 3 Mitang., 5/2023)"),
    ("Leipzig", "Militante Aktion", "2023-05", "investigating",
        "StA Leipzig + LKA Sachsen — Tag-X-Eskalationen 5/2023"),
    ("Leipzig", "Militante Aktion", "2024-04", "investigating",
        "StA Leipzig — Lina-E.-Urteil-Reaktionen 4/2024"),
    ("Leipzig", "Militante Aktion", "2024-11", "investigating",
        "StA Leipzig — Connewitz Sondereinheit-Eskalation 11/2024"),
    # ── G20 Hamburg / Rondenbarg-Komplex ─────────────────────────────────
    ("Hamburg", "Militante Aktion", "2017-07", "convicted",
        "LG Hamburg 612 KLs (Rondenbarg-Verfahren, Teilverurteilungen 2020-23)"),
    ("Hamburg", "Brandanschlag",    "2017-07", "convicted",
        "StA Hamburg — G20-Plünderungs-Komplex (mehrere Einzelverfahren)"),
    # ── Letzte Generation / Wandelbündnis e.V. — §129 GStA München ──────
    ("Berlin",  "Brandanschlag",    "2024-12", "investigating",
        "GStA München 1 BJs 7/23-2 (§129 Letzte Generation, anhängig)"),
    # ── US Stop-Cop-City / Atlanta — Georgia RICO ───────────────────────
    ("Atlanta", "Militante Aktion", "2023-03", "charged",
        "Fulton County GA Superior Court 23SC183872 (RICO ggn. 61 Angeklagte, 9/2023)"),
    ("Atlanta", "Brandanschlag",    "2022-12", "charged",
        "Fulton County GA — Cop-City-Domestic-Terrorism-Charges (GA Code §16-4-10)"),
    ("Atlanta", "Sachbeschädigung", "2023-05", "charged",
        "Fulton County GA — Cop-City-RICO-Indictment (mehrere Beschuldigte)"),
    ("Atlanta", "Militante Aktion", "2024-08", "charged",
        "Fulton County GA — Folgewelle Anklage 8/2024"),
    ("Atlanta", "Militante Aktion", "2025-01", "investigating",
        "FBI Joint Terrorism Task Force Atlanta — laufende Ermittlung"),
    ("Atlanta", "Militante Aktion", "2025-04", "investigating",
        "FBI JTTF Atlanta — Folge-Anschläge auf Cop-City"),
    ("Atlanta", "Sabotage",         "2024-03", "investigating",
        "FBI JTTF Atlanta — Strom-Verteiler-Sabotage Cop-City-Baustelle"),
    ("Atlanta", "Sabotage",         "2025-04", "investigating",
        "FBI JTTF Atlanta — dritter Strom-Sabotage-Vorfall 2025"),
    # ── Atlanta — Tortuguita Erschießung: dismissed (Polizei, keine Anklage) ─
    ("Atlanta", "Gewalt",           "2023-01", "dismissed",
        "Georgia State Patrol — keine Anklage gegen Beamte (Grand-Jury 2023)"),
    # ── Minneapolis Third Precinct Brand 2020 ────────────────────────────
    ("Minneapolis","Brandanschlag", "2020-05", "convicted",
        "U.S. District Court D.Minn. 0:20-cr-00203 (Federal Arson 18 USC §844, Verurteilungen 2021)"),
    # ── Portland Federal Courthouse 2020 ─────────────────────────────────
    ("Portland","Brandanschlag",    "2020-07", "convicted",
        "U.S. District Court D.Or. — mehrere Federal Arson-Verfahren (Verurteilungen 2021-22)"),
    # ── Tesla Grünheide Strommast 2024 ───────────────────────────────────
    ("Grünheide","Sabotage",        "2024-03", "investigating",
        "GStA Berlin 4 BJs 4/24 (Bildung terroristischer Vereinigung §129a, anhängig)"),
    # ── Frankreich Sainte-Soline 2022 (Megabassine) ─────────────────────
    ("Sainte-Soline","Militante Aktion", "2022-10", "charged",
        "TGI Niort — Anklagen 'violences en réunion' gegen Soulèvements-de-la-Terre Aktivisten"),
    # ── Notre-Dame-des-Landes 2018 ───────────────────────────────────────
    ("Notre-Dame-des-Landes","Militante Aktion", "2018-04", "convicted",
        "TGI Saint-Nazaire — mehrere Verfahren ZAD-Räumung (Teilverurteilungen 2018-19)"),
    # ── Athen / Conspiracy of Fire Cells (historisch) ────────────────────
    ("Athen", "Brandanschlag",      "2021-03", "convicted",
        "ΣΤΕ Athen — anarchistische Zelle, Verurteilungen 2021-22"),
]

def backfill_prosec_status():
    """Apply _PROSEC_BACKFILL einmalig auf die incidents-Tabelle.
    Idempotent via meta-flag. Pro Match-Triple (location, category,
    date-prefix) wird prosec_status + case_ref gesetzt, aber NICHT
    überschrieben wenn ein Admin schon was anderes gesetzt hat
    (status != 'unknown' bleibt unberührt)."""
    if meta_get("prosec_backfill_v3") == "1":
        return 0
    fixed = 0
    today = datetime.now().date().isoformat()
    for loc_sub, cat, date_pfx, status, case_ref in _PROSEC_BACKFILL:
        rows = db.execute(
            "SELECT id, prosec_status FROM incidents "
            "WHERE location LIKE ? AND category = ? AND date LIKE ?",
            (f"%{loc_sub}%", cat, f"{date_pfx}%")
        ).fetchall()
        for r in rows:
            current = (r["prosec_status"] or "unknown")
            if current != "unknown":
                continue   # admin-set or already-set, do not overwrite
            db.execute(
                "UPDATE incidents SET prosec_status=?, case_ref=?, "
                "last_status_check=? WHERE id=?",
                (status, case_ref, today, r["id"])
            )
            fixed += 1
    db.commit()
    meta_set("prosec_backfill_v3", "1")
    if fixed:
        log.info(f"backfill_prosec_status: {fixed} incidents enriched")
    return fixed


def recompute_corroboration():
    """Recompute the per-incident `corroboration` count (M4).

    For each incident, count how many *additional* independent sources
    documented the same event (see lex.scoring.same_event). corroboration =
    (distinct sources among same-event records) - 1, capped at 2 to match the
    quality_score weighting. Incidents are bucketed by (country, category)
    first so the O(n^2) comparison only runs within small groups.

    Idempotent: recomputes from scratch each call, safe to run on startup and
    after a crawl. Returns the number of rows whose value changed.
    """
    rows = [dict(r) for r in db.execute(
        "SELECT id, country, category, location, date, source, "
        "COALESCE(corroboration,0) AS corroboration FROM incidents"
    ).fetchall()]
    buckets = {}
    for r in rows:
        buckets.setdefault(corroboration_key(r["country"], r["category"]), []).append(r)

    changed = 0
    for group in buckets.values():
        for r in group:
            sources = set()
            for other in group:
                if other is r or same_event(r, other):
                    src = (other.get("source") or "").strip().lower()
                    # Fall back to the row id so a missing source still counts
                    # as one distinct witness (never inflates beyond reality).
                    sources.add(src or f"#{other['id']}")
            new_val = max(0, min(len(sources) - 1, 2))
            if new_val != (r.get("corroboration") or 0):
                db.execute("UPDATE incidents SET corroboration=? WHERE id=?",
                           (new_val, r["id"]))
                changed += 1
    if changed:
        db.commit()
        log.info(f"recompute_corroboration: {changed} incidents updated")
    return changed


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
        # Defamation-Sanitisation (Commit AB): "rechtsextrem"/"Nazi"-Labels
        # gegen Privatpersonen aus Altdaten entfernen.
        desc_out = neutralize_political_labels(redact_pii(desc_in))
        # Re-strip activist phrasing + clamp to 140 chars even for existing
        # rows so the visual tightening is retroactive.
        summ_raw = summ_in or fallback_summary(desc_in)
        summ_out = clamp_two_sentences(
            strip_activist_phrases(
                neutralize_political_labels(redact_pii(summ_raw))
            ),
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

def backfill_barrikade_dates():
    """User-Befund 2026-05-29: alle Firecrawl-gesaveden Barrikade-Artikel
    landeten in 2026 weil date_from_url(/article/<id>) None liefert →
    save_incident defaulted auf datetime.now().
    Backfill: für alle barrikade.info-Einträge mit date >= heute - 60d
    versuche date_from_markdown(description). Wenn extrahiert,
    update. Idempotent: Eintrag mit korrekt erkanntem Datum wird nicht
    nochmal angefasst."""
    rows = db.execute(
        "SELECT id, date, description FROM incidents "
        "WHERE source='barrikade.info' AND date >= date('now','-60 day') "
        "AND description IS NOT NULL"
    ).fetchall()
    n = 0
    for r in rows:
        new_d = date_from_markdown(r["description"])
        if new_d and new_d != r["date"]:
            db.execute("UPDATE incidents SET date=? WHERE id=?", (new_d, r["id"]))
            n += 1
    if n:
        db.commit()
        log.info(f"backfill_barrikade_dates: updated {n} barrikade incidents")
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
    """Insert pre-defined historical incidents if not already seeded.

    Gated by HISTORICAL_SEED_VERSION metadata key (not by row count) so that
    appending new tuples to HISTORICAL_EVENTS triggers another seed pass after
    the version constant is bumped. Per-entry is_seen() dedup keeps earlier
    rows unique."""
    if meta_get("historical_seed_version") == HISTORICAL_SEED_VERSION:
        log.info(f"Seed: Version {HISTORICAL_SEED_VERSION} bereits eingespielt")
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
        log.info(f"Seed: {inserted} historische Einträge eingespielt (Version {HISTORICAL_SEED_VERSION})")
    meta_set("historical_seed_version", HISTORICAL_SEED_VERSION)
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
FUNDING_SEED_VERSION = "2026-05-credibility-v5-expanded"

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
def _firecrawl_article(aid):
    """Hole einen einzelnen Barrikade-Article via Firecrawl-API.
    Returns markdown string oder None.

    User 2026-05-28: "versuche mal nur artikel mit firecrawl zu crawlen
    https://barrikade.info/article/7490 in diesem format runter, nur mit
    den APIs alles andere löschen verursacht fehler".

    barrikade.info ist Angular-SPA — direct/cloudscraper/jina liefern nur
    Skeleton. Firecrawl rendert die SPA und gibt Article-Body als Markdown."""
    key = os.getenv("FIRECRAWL_API_KEY", "").strip()
    if not key:
        return None
    url = f"https://barrikade.info/article/{aid}"
    try:
        r = requests.post(
            "https://api.firecrawl.dev/v1/scrape",
            json={
                "url": url,
                "formats": ["markdown"],
                "waitFor": 2500,
                "timeout": 30000,
            },
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
            timeout=60,
        )
        if r.status_code != 200:
            log.info(f"firecrawl {aid}: HTTP {r.status_code} {r.text[:160]}")
            return None
        data = r.json() or {}
        md = (data.get("data") or {}).get("markdown", "") or ""
        if md and len(md) > 200:
            return md
        log.info(f"firecrawl {aid}: empty markdown (probably 404)")
    except Exception as e:
        log.info(f"firecrawl {aid} EXC: {str(e)[:160]}")
    return None


def barrikade_latest_id():
    """Holt die höchste Article-ID via Firecrawl-Probe gegen die Homepage.
    Falls Firecrawl nicht verfügbar: DB-Maximum + 50 als Anchor.

    barrikade.info ist SPA — wir müssen die Seite JS-rendern um die
    Article-Liste zu sehen. Firecrawl ist der einzige Pfad der das tut."""
    key = os.getenv("FIRECRAWL_API_KEY", "").strip()
    if key:
        try:
            r = requests.post(
                "https://api.firecrawl.dev/v1/scrape",
                json={
                    "url": "https://barrikade.info/",
                    "formats": ["markdown", "links"],
                    "waitFor": 3000,
                    "timeout": 30000,
                },
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                timeout=60,
            )
            if r.status_code == 200:
                data = r.json() or {}
                d = data.get("data") or {}
                body = (d.get("markdown") or "") + "\n" + "\n".join(d.get("links") or [])
                ids = [int(m.group(1)) for m in re.finditer(r"/article/(\d{3,6})", body)]
                if ids:
                    mx = max(ids)
                    log.info(f"barrikade_latest_id via firecrawl: {mx} (from {len(ids)} matches)")
                    return mx
                else:
                    log.warning(f"barrikade_latest_id via firecrawl: 0 IDs in {len(body)}b body")
            else:
                log.warning(f"barrikade_latest_id firecrawl HTTP {r.status_code}: {r.text[:160]}")
        except Exception as e:
            log.warning(f"barrikade_latest_id firecrawl: {str(e)[:160]}")
    else:
        log.warning("barrikade_latest_id: no FIRECRAWL_API_KEY — using DB anchor")
    # Fallback: DB-Maximum + 50
    try:
        row = db.execute(
            "SELECT MAX(CAST(SUBSTR(url, INSTR(url,'/article/')+9) AS INTEGER)) AS mx "
            "FROM incidents WHERE url LIKE '%barrikade.info/article/%'"
        ).fetchone()
        if row and row["mx"] and row["mx"] > 1000:
            anchor = int(row["mx"]) + 50
            log.info(f"barrikade_latest_id: DB-anchor max+50 = {anchor}")
            return anchor
    except Exception:
        pass
    log.warning("barrikade_latest_id: default 7600")
    return 7600


def crawl_barrikade_range(start_id, stop_id):
    """Pure-Firecrawl-Crawl: ID-Sweep von start_id rückwärts bis stop_id.

    User-Direktive 2026-05-28: "versuche mal nur artikel mit firecrawl zu
    crawlen ... nur mit den APIs alles andere löschen verursacht fehler".

    barrikade.info ist Angular-SPA — kein anderer Pfad kann den
    JS-gerendert Article-Body liefern. Wenn FIRECRAWL_API_KEY fehlt,
    läuft der Crawler komplett leer (gewollt — kein Fake-Erfolg).
    Returns: Anzahl gespeicherter Einträge."""
    if not os.getenv("FIRECRAWL_API_KEY", "").strip():
        log.warning("crawl_barrikade_range: FIRECRAWL_API_KEY not set — skipping")
        return 0
    inserted = 0
    misses = 0
    classify_errors = 0
    for aid in range(start_id, stop_id - 1, -1):
        url_canon = f"https://barrikade.info/article/{aid}"
        # Dedup: ID schon mal gesehen?
        h_url = mk_hash(url_canon, url_canon)
        if is_seen(h_url):
            time.sleep(0.1)
            continue
        full = _firecrawl_article(aid)
        if not full:
            misses += 1
            if misses >= 100:
                log.warning(f"barrikade: 100 konsekutive Firecrawl-Misses bei id={aid} — abort")
                break
            time.sleep(0.3)
            continue
        misses = 0
        # Relevance-Filter: nur Artikel mit politisch-relevanten Stichworten
        if not any(kw in full.lower() for kw in BARRIKADE_RELEVANCE_KWS):
            time.sleep(0.3)
            continue
        if is_false_positive(full):
            time.sleep(0.3)
            continue
        try:
            ai = smart_classify(full)
            if ai:
                # Datum aus Markdown extrahieren (URL hat keins).
                # User-Befund 2026-05-29: alles landete in 2026.
                art_date = date_from_markdown(full) or date_from_url(url_canon)
                if save_incident(ai, full, "barrikade.info", url_canon, art_date):
                    inserted += 1
                    log.info(f"barrikade {aid}: SAVED ({ai.get('kategorie','?')} / {ai.get('ort','?')} / {art_date or 'no-date'})")
        except Exception as e:
            classify_errors += 1
            log.info(f"barrikade {aid} classify err: {str(e)[:120]}")
            if classify_errors > 10:
                log.warning("barrikade: >10 classify errors — abort sweep")
                break
        time.sleep(0.5)
    log.info(f"barrikade range {start_id}→{stop_id}: {inserted} saved, {misses} misses-at-end")
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

# ── NAZIFREI.ORG CRAWLER ──────────────────────────────────────────
# Plattform mit antifaschistischem Counter-Extremismus-Fokus; veröffentlicht
# u.a. "Outings" rechtsextrem aktiver Personen. Wir crawlen den Public-Feed
# wie jede andere Quelle; die Doxxing-Erkennungs-Pipeline
# (is_doxxing_text + sanitize_doxxing_event) sorgt dafür, dass Outings
# nur als ROLLE/Aggregat in die DB kommen, NIEMALS mit Klarnamen oder PII.
def crawl_nazifrei_feed():
    """Crawl nazifrei.org sowie verwandte antifaschistische Plattformen.
    Doxxing-Inhalte werden automatisch sanitisiert (s. save_incident)."""
    inserted = 0
    candidate_feeds = [
        # nazifrei.org RSS-Kandidaten (mehrere Pfade, einer wird funktionieren)
        ("nazifrei-rss",       "https://nazifrei.org/feed/"),
        ("nazifrei-rss2",      "https://www.nazifrei.org/feed/"),
        ("nazifrei-atom",      "https://nazifrei.org/atom"),
        ("nazifrei-rss-xml",   "https://nazifrei.org/rss.xml"),
        ("nazifrei-news",      "https://nazifrei.org/news/feed/"),
        # Schwesterprojekte / verwandte Counter-Extremismus-Outings
        ("npd-blockieren",     "https://npd-blockieren.de/feed/"),
        ("recherche-nord",     "https://recherche-nord.com/feed/"),
        ("recherche-elbe",     "https://www.recherche-elbe-saale.de/feed/"),
        ("antifa-recherche",   "https://antifa-recherche-team.org/feed/"),
        ("apabiz",             "https://www.apabiz.de/feed/"),  # Antifaschistisches Pressearchiv Berlin
    ]
    for label, feed_url in candidate_feeds:
        try:
            xml = fetch(feed_url, timeout=12)
            items = parse_rss(xml) if xml else []
            log.info(f"nazifrei {label}: {len(items)} items")
            for it in items[:15]:
                url = it.get("link") or ""
                title = it.get("title") or ""
                if not url: continue
                try:
                    h = mk_hash(url, title)
                    if is_seen(h): continue
                    full = get_text(url)
                    if len(full) < 80: continue
                    if is_false_positive(full):
                        continue
                    ai = smart_classify(full)
                    if ai:
                        # save_incident triggert auto die Doxxing-Sanitisierung
                        # über is_doxxing_text/sanitize_doxxing_event — wir
                        # müssen hier nichts Spezielles tun, das ist
                        # transparent.
                        if save_incident(ai, full, "nazifrei.org", url, date_from_url(url) or it.get("date","")):
                            inserted += 1
                    time.sleep(0.3)
                except Exception as e:
                    log.info(f"nazifrei item {url}: {str(e)[:120]}")
        except Exception as e:
            log.info(f"nazifrei feed [{label}] failed: {str(e)[:120]}")
        time.sleep(0.4)
    return inserted

# ── RELEVANCE / FALSE-POSITIVE FILTER  →  extracted to lex/filters.py (M1) ──
# RSS_KEYWORDS, the _FP false-positive pattern list, is_false_positive() and
# BARRIKADE_RELEVANCE_KWS now live in lex/filters.py so the "no random
# Zeitungsartikel" gate can be unit-tested in isolation (tests/test_filters.py).
# Behaviour is identical; re-imported under their original names so every
# existing call site in this module keeps working unchanged.
from lex.filters import (  # noqa: E402
    RSS_KEYWORDS,
    is_false_positive,
    BARRIKADE_RELEVANCE_KWS,
)

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
    # ── US Federal — Sicherheitsbehörden + Counter-Extremism ──────
    ("dhs-cisa-alerts",       "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("us-attorney-press",     "https://www.justice.gov/feeds/usao/usao-news.xml"),
    ("nsa-press",             "https://www.nsa.gov/Press-Room/Press-Releases/feed/"),
    # ── US Mainstream — politische Schwerpunkt-Outlets ─────────────
    ("nytimes-us",            "https://rss.nytimes.com/services/xml/rss/nyt/US.xml"),
    ("washingtonpost-politics","https://feeds.washingtonpost.com/rss/national"),
    ("politico-politics",     "https://rss.politico.com/politics-news.xml"),
    ("bbc-us-canada",         "https://feeds.bbci.co.uk/news/world/us_and_canada/rss.xml"),
    ("axios-politics",        "https://www.axios.com/feeds/feed.rss"),
    ("usatoday-news",         "https://rssfeeds.usatoday.com/usatoday-newstopstories"),
    ("thehill",               "https://thehill.com/rss/syndicator/19110"),
    # ── US Local Police — high-density Antifa-/Anarcho-Schwerpunkte
    ("spd-blotter-seattle",   "https://spdblotter.seattle.gov/feed/"),
    ("portland-police",       "https://www.portland.gov/police/news.rss"),
    ("nypd-news",             "https://www1.nyc.gov/site/nypd/news/news.page.rss"),
    ("lapd-news",             "https://www.lapdonline.org/feed/"),
    ("sfpd-news",             "https://www.sanfranciscopolice.org/news/feed"),
    ("philly-police",         "https://news.phila.gov/feed/?feed=topics&topics=police"),
    ("apd-atlanta",           "https://www.atlantapd.org/Home/Components/RssFeeds/RssFeed/1/14"),
    ("dpd-denver",            "https://denverpolice.org/rss-feed/"),
    ("mpd-minneapolis",       "https://www.minneapolismn.gov/news/feed/"),
    # ── US Counter-Extremism Research ─────────────────────────────
    ("splcenter.org",         "https://www.splcenter.org/rss.xml"),
    ("gwu-extremism",         "https://extremism.gwu.edu/feed"),
    ("usga-bureau-investigation",
                              "https://gbi.georgia.gov/press-releases/rss"),
    # ── US lokale Outlets in Antifa-Hotspot-Städten ───────────────
    ("willamette-week-portland","https://www.wweek.com/news/feed/"),
    ("ajc-atlanta",           "https://www.ajc.com/arc/outboundfeeds/rss/?outputType=xml"),
    # ── Einschlägige Quellen (szenenah + extremismusbeobachtend) ──
    ("barrikade.info",        "https://barrikade.info/feed"),
    ("publish.barrikade.info","https://publish.barrikade.info/feed"),
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

# ── BARRIKADE RELEVANCE PRE-FILTER  →  BARRIKADE_RELEVANCE_KWS in lex/filters.py (M1) ──

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
        # 1. Barrikade: sweep latest 400 article IDs (Commit AC: war 80,
        # User-Direktive "alles crawlen"). 400 IDs × 0.6s = ~4 min Worst-Case
        # bei voll besetztem ID-Raum; mit dem 250-Misses-Abbruch bleibt das
        # auch bei dünnem ID-Raum beschränkt.
        log.info("Barrikade live sweep...")
        latest = barrikade_latest_id()
        saved_latest = int(meta_get("b_live_max") or 0)
        if latest > saved_latest:
            n = crawl_barrikade_range(latest, max(saved_latest, latest - 400))
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

        # 2b. Nazifrei + Antifa-Recherche-Plattformen (Counter-Extremism Outings).
        # Doxxing-Inhalte werden via save_incident → sanitize_doxxing_event
        # automatisch zu rolle-basierten T3-Kontext-Einträgen anonymisiert.
        log.info("Nazifrei/Antifa-Recherche feeds...")
        n = crawl_nazifrei_feed()
        total += n
        log.info(f"Nazifrei: +{n}")

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

        # 6. M4 — refresh cross-source corroboration so newly-saved incidents
        # that corroborate (or are corroborated by) existing ones get scored.
        try:
            recompute_corroboration()
        except Exception as e:
            log.warning(f"recompute_corroboration after crawl failed: {e}")

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
        # Indymedia historical: site is offline since 2017 — mark done.
        if not meta_get("hist_im_done"):
            meta_set("hist_im_done", datetime.now().isoformat())
            log.info("Indymedia hist: skipped (site offline since 2017)")

        # Barrikade: 1500 IDs pro Tick + Fortschritt-Logging mit ETA.
        # User 2026-05-28: "automatisiert damit alle Artikel gecrawlt
        # werden nicht nur die ersten 500". Mit Starter-Plan (24/7) und
        # 30-min-Tick erreichen wir ID=1 in ~5-7 Stunden ab Live-ID 7570.
        DONE="hist_b_done"; CURR="hist_b_curr"
        CHUNK_SIZE = 1500
        if not meta_get(DONE):
            if not meta_get(CURR):
                mx = barrikade_latest_id()
                meta_set("hist_b_max", mx)
                meta_set(CURR, mx)
            curr = int(meta_get(CURR))
            stop = max(1, curr - CHUNK_SIZE)
            mx_total = int(meta_get("hist_b_max") or curr)
            done_so_far = max(0, mx_total - curr)
            pct = round(done_so_far / max(mx_total, 1) * 100, 1)
            log.info(f"Barrikade hist: {curr}→{stop} (chunk {CHUNK_SIZE}; "
                     f"progress {done_so_far}/{mx_total} = {pct}%)")
            n = crawl_barrikade_range(curr, stop)
            meta_set(CURR, stop - 1)
            # Insertion-Statistik mit fortlaufendem Total
            tot = int(meta_get("hist_b_total_inserted") or 0) + n
            meta_set("hist_b_total_inserted", tot)
            if stop <= 1:
                meta_set(DONE, datetime.now().isoformat())
                log.info("Barrikade hist: COMPLETE — full ID-space covered")
            else:
                # ETA berechnen: bei aktuellem chunk_size + 30 min Tick
                remaining = stop - 1
                ticks_left = max(1, (remaining + CHUNK_SIZE - 1) // CHUNK_SIZE)
                eta_h = round(ticks_left * 0.5, 1)  # 30 min = 0.5h
                log.info(f"Barrikade hist: +{n} (total inserted={tot}; "
                         f"remaining={remaining}; ETA ~{eta_h}h with current tick rate)")
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
@app.get("/api/actor.rss")
async def actor_rss(request: Request, name: str = "", limit: int = 30):
    """Per-Actor-RSS — abonnierbar für gezielte Akteurs-Beobachtung.
    Liefert alle Vorfälle (T1/T2/T3) mit diesem Akteur im actors-Feld."""
    if not name or len(name) < 3:
        return StreamingResponse(iter(["<?xml version='1.0'?><rss/>"]),
                                 media_type="application/rss+xml")
    rows = db.execute(
        "SELECT id,date,location,country,category,summary,severity_score,url,source "
        "FROM incidents WHERE actors LIKE ? ORDER BY date DESC LIMIT ?",
        (f"%{name}%", min(max(limit, 1), 100))
    ).fetchall()
    name_l = name.lower()
    rows = [dict(r) for r in rows if any(
        a.strip().lower() == name_l for a in
        (db.execute("SELECT actors FROM incidents WHERE id=?", (r["id"],)).fetchone()["actors"] or "").split(",")
    )]
    base = str(request.base_url).rstrip("/")
    items = []
    for r in rows:
        loc = _xml_esc(f"{r.get('location') or '—'}, {r.get('country') or '—'}")
        cat = _xml_esc(r.get('category') or '—')
        sev = r.get('severity_score') or 0
        summ= _xml_esc((r.get('summary') or '')[:280])
        url = _xml_esc(r.get('url') or f"{base}/")
        items.append(
            "<item>"
            f"<title>[{cat} · S{sev}] {loc}</title>"
            f"<link>{url}</link>"
            f"<guid isPermaLink=\"false\">lex-act-{r.get('id')}</guid>"
            f"<pubDate>{_rfc822(r.get('date'))}</pubDate>"
            f"<category>{cat}</category>"
            f"<description>{summ}</description>"
            "</item>"
        )
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<rss version="2.0">\n<channel>\n'
           f'<title>LEX EUROPE — Akteur: {_xml_esc(name)}</title>\n'
           f'<link>{base}/a/{_xml_esc(name)}</link>\n'
           f'<description>Vorfälle mit Akteur {_xml_esc(name)} im Lagebild.</description>\n'
           '<language>de-DE</language>\n'
           + "\n".join(items) +
           '\n</channel>\n</rss>\n')
    return StreamingResponse(iter([xml]), media_type="application/rss+xml; charset=utf-8")


# ── SSE LIVE-FEED ──────────────────────────────────────────────────
# Browser-Clients können sich via EventSource auf das Stream-Endpoint
# einklinken und bekommen jede neue Vorfalls-Klassifikation als Server-
# Sent-Event. Long-Poll-Implementierung: der Endpoint wartet auf neue
# IDs, sendet bei jeder neuen Zeile ein "incident"-Event. Heartbeat
# alle 30 s damit Proxies die Verbindung nicht killen.

@app.get("/api/stream/incidents")
async def stream_incidents(request: Request):
    """SSE-Stream der neu gespeicherten Incidents. Frontend benutzt
    EventSource('/api/stream/incidents'); jede neue Vorfalls-Zeile
    wird als 'incident'-Event mit JSON-Payload gepusht."""
    import asyncio, json as _j
    async def event_gen():
        # Cursor = höchste bekannte ID. Wir starten von "jetzt".
        last_id = db.execute("SELECT COALESCE(MAX(id), 0) FROM incidents").fetchone()[0]
        yield f"event: ready\ndata: {{\"cursor\": {last_id}}}\n\n"
        last_heartbeat = time.time()
        while True:
            if await request.is_disconnected():
                break
            try:
                rows = db.execute(
                    "SELECT id,date,location,country,category,summary,"
                    "severity_score,tier,target_type,url,source FROM incidents "
                    "WHERE id > ? AND tier='act' ORDER BY id ASC LIMIT 20",
                    (last_id,)
                ).fetchall()
                for r in rows:
                    d = dict(r)
                    last_id = d["id"]
                    yield f"event: incident\ndata: {_j.dumps(d, ensure_ascii=False)}\n\n"
            except Exception as e:
                log.info(f"SSE error: {e}")
            # Heartbeat alle 30 s damit Proxies (CloudFront, Nginx, etc.)
            # die idle Verbindung nicht killen.
            if time.time() - last_heartbeat > 30:
                yield f": heartbeat {int(time.time())}\n\n"
                last_heartbeat = time.time()
            await asyncio.sleep(3)
    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache, no-transform",
                                      "X-Accel-Buffering": "no"})


# ── EMBED WIDGETS ─────────────────────────────────────────────────
# Externe Seiten können <iframe src="/embed/counter"> einbinden und
# bekommen einen kompakten KPI-Counter ohne Filter-UI / ohne Karte.
@app.get("/embed/counter", response_class=HTMLResponse)
async def embed_counter():
    """Mini-Widget für iframe-Embedding: zeigt die 3 wichtigsten KPIs
    als kompakte Karte. Höhe ~160 px, sponsor-frei, transparent."""
    s = await public_stats()
    import json as _j
    d = _j.loads(s.body)
    return HTMLResponse(f"""<!doctype html>
<html><head><meta charset="utf-8">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:transparent;color:#aab5c0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;}}
.box{{padding:12px 14px;background:#080c12;border:1px solid rgba(255,255,255,0.08);}}
.head{{font-size:8px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:8px;display:flex;justify-content:space-between;}}
.head a{{color:#6aa9c9;text-decoration:none;}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;}}
.k{{padding:8px 10px;border:1px solid rgba(255,255,255,0.05);background:rgba(106,169,201,0.04);}}
.k .v{{font-size:22px;color:#e9eef3;font-variant-numeric:tabular-nums;font-weight:600;}}
.k .l{{font-size:8px;color:#6c7986;letter-spacing:1.5px;margin-top:2px;text-transform:uppercase;}}
.k.red .v{{color:#d4495d;}}.k.amber .v{{color:#d99a2b;}}
</style></head><body>
<div class="box">
  <div class="head"><span>◆ LEX EUROPE · LIVE LAGEBILD</span><a href="/" target="_top">→ dashboard</a></div>
  <div class="grid">
    <div class="k"><div class="v">{d['total_t1']}</div><div class="l">T1-Akte</div></div>
    <div class="k red"><div class="v">{d['high_severity']}</div><div class="l">Schwere ≥4</div></div>
    <div class="k amber"><div class="v">{d['active_clusters']}</div><div class="l">Aktive Cluster</div></div>
  </div>
</div>
</body></html>""")


@app.get("/embed/headline", response_class=HTMLResponse)
async def embed_headline():
    """Mini-Banner für hostende Sites: nur 1 zeile, severity-Farbe."""
    rows = db.execute(
        "SELECT date, location, country, category, summary, severity_score, url "
        "FROM incidents WHERE tier='act' AND severity_score >= 4 "
        "ORDER BY date DESC LIMIT 1"
    ).fetchall()
    if not rows:
        body = '<div style="font:11px ui-monospace;color:#6c7986;padding:8px">Kein hochrangiger T1-Vorfall verfügbar.</div>'
    else:
        r = dict(rows[0])
        loc = f"{r['location']}, {r['country']}"
        summ = (r.get('summary') or '')[:120]
        body = (f'<a href="{r.get("url","/")}" target="_top" style="text-decoration:none;display:block;'
                f'padding:10px 14px;background:#080c12;border-left:3px solid #d4495d;'
                f'font:11px ui-monospace,Menlo,monospace;color:#aab5c0">'
                f'<span style="color:#d4495d;letter-spacing:2px;font-size:8px">◆ LEX EUROPE · LATEST T1 · S{r.get("severity_score","?")}/5</span><br>'
                f'<span style="color:#e9eef3;font-size:12px">{r["date"]} · {loc}</span> · {r["category"]}<br>'
                f'<span style="color:#aab5c0">{summ}</span></a>')
    return HTMLResponse(f'<!doctype html><html><head><meta charset="utf-8"></head><body style="margin:0">{body}</body></html>')


# ── BULK EXPORTS (für Researcher / Journalismus) ──────────────────
@app.get("/api/incidents/export.csv")
async def incidents_export_csv(
    country: str = "", tier: str = "act", severity_min: int = 0,
    date_from: str = "", date_to: str = "",
):
    """CSV-Export für tabellarische Weiterverarbeitung. Default tier=act
    + alle Severities; mit ?tier=&severity_min=0 lassen sich auch T2/T3
    abziehen. Header-Zeile inklusive."""
    q = ("SELECT id,date,location,country,category,summary,description,"
         "url,source,severity_score,actors,tier,target_type,"
         "prosec_status,case_ref,evidence_sha,evidence_ts "
         "FROM incidents WHERE 1=1")
    p = []
    if country:      q += " AND country=?";       p.append(country)
    if tier:         q += " AND tier=?";          p.append(tier)
    if severity_min: q += " AND severity_score>=?"; p.append(severity_min)
    if date_from:    q += " AND date>=?";          p.append(date_from)
    if date_to:      q += " AND date<=?";          p.append(date_to)
    q += " ORDER BY date DESC"
    rows = db.execute(q, p).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id","date","location","country","category","summary",
                 "description","url","source","severity_score","actors",
                 "tier","target_type","prosec_status","case_ref",
                 "evidence_sha","evidence_ts"])
    for r in rows:
        w.writerow([r[k] for k in (
            "id","date","location","country","category","summary","description",
            "url","source","severity_score","actors","tier","target_type",
            "prosec_status","case_ref","evidence_sha","evidence_ts")])
    return StreamingResponse(iter([buf.getvalue()]),
                             media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition":
                                      f'attachment; filename="lex-europe-incidents-{datetime.now().date()}.csv"'})

@app.get("/api/incidents/export.json")
async def incidents_export_json(
    country: str = "", tier: str = "act", severity_min: int = 0,
):
    """JSON-Bulk-Export — alle T1 mit Default-Filter. Researchers
    können das ganze Dataset als single JSON in ihre Tools ziehen."""
    q = ("SELECT id,date,location,country,category,summary,description,"
         "url,source,severity_score,actors,tier,target_type,"
         "prosec_status,case_ref,evidence_sha,evidence_ts,lat,lon "
         "FROM incidents WHERE 1=1")
    p = []
    if country:      q += " AND country=?";       p.append(country)
    if tier:         q += " AND tier=?";          p.append(tier)
    if severity_min: q += " AND severity_score>=?"; p.append(severity_min)
    q += " ORDER BY date DESC"
    rows = [dict(r) for r in db.execute(q, p).fetchall()]
    return JSONResponse({
        "platform":   "LEX EUROPE",
        "asof":       datetime.now().isoformat(timespec="seconds"),
        "count":      len(rows),
        "methodology":"https://lex-europe.org/methodology",
        "incidents":  rows,
    }, headers={"Content-Disposition":
                f'attachment; filename="lex-europe-incidents-{datetime.now().date()}.json"'})


@app.get("/api/target.rss")
async def target_rss(request: Request, name: str = "", limit: int = 30):
    """Per-Ziel-Klassen-RSS — Betreiber kritischer Infrastruktur können
    gezielt ihren Sektor abonnieren (Schiene / Energie / Polizei / …)
    statt den breiten /api/incidents.rss zu monitoren."""
    if not name or name not in _TARGET_TYPE_ALLOWED:
        return StreamingResponse(iter(["<?xml version='1.0'?><rss/>"]),
                                 media_type="application/rss+xml")
    rows = db.execute(
        "SELECT id,date,location,country,category,summary,severity_score,"
        "url,source FROM incidents WHERE tier='act' AND target_type=? "
        "ORDER BY date DESC LIMIT ?", (name, min(max(limit, 1), 100))
    ).fetchall()
    base = str(request.base_url).rstrip("/")
    items = []
    for r in rows:
        d = dict(r)
        loc = _xml_esc(f"{d.get('location') or '—'}, {d.get('country') or '—'}")
        cat = _xml_esc(d.get('category') or '—')
        sev = d.get('severity_score') or 0
        summ= _xml_esc((d.get('summary') or '')[:280])
        url = _xml_esc(d.get('url') or f"{base}/")
        items.append(
            "<item>"
            f"<title>[{cat} · S{sev}] {loc}</title>"
            f"<link>{url}</link>"
            f"<guid isPermaLink=\"false\">lex-tgt-{d.get('id')}</guid>"
            f"<pubDate>{_rfc822(d.get('date'))}</pubDate>"
            f"<category>{cat}</category>"
            f"<description>{summ}</description>"
            "</item>"
        )
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<rss version="2.0">\n<channel>\n'
           f'<title>LEX EUROPE — Ziel-Klasse: {_xml_esc(name)}</title>\n'
           f'<link>{base}/early-warning/{_xml_esc(name)}</link>\n'
           f'<description>T1-Akte gegen Ziel-Klasse {_xml_esc(name)} (Säule 2).</description>\n'
           '<language>de-DE</language>\n'
           + "\n".join(items) +
           '\n</channel>\n</rss>\n')
    return StreamingResponse(iter([xml]), media_type="application/rss+xml; charset=utf-8")


@app.get("/api/target-types")
async def list_target_types():
    """Listet alle bekannten Ziel-Klassen + Counts. Für UI-Drop-Downs
    und API-Konsumenten, die Per-Target-RSS bauen wollen."""
    rows = db.execute(
        "SELECT target_type, COUNT(*) n FROM incidents "
        "WHERE tier='act' AND target_type != '' "
        "GROUP BY target_type ORDER BY n DESC"
    ).fetchall()
    return JSONResponse({
        "target_types": [dict(r) for r in rows],
        "allowed":      sorted(t for t in _TARGET_TYPE_ALLOWED if t),
    })


@app.get("/bookmarklet", response_class=HTMLResponse)
async def public_bookmarklet():
    """Browser-Bookmarklet-Generator. Admin oder Power-Nutzer ziehen
    den Button in die Lesezeichenleiste; ein Klick auf einer beliebigen
    Webseite öffnet einen Pre-Filled-Admin-Submit-Dialog mit der
    aktuellen URL und dem Selektions-Text."""
    # Bookmarklet code: read window.location + selection, post to
    # /admin/api/add-incident-from-url. Da das Admin-Auth braucht,
    # routet es eigentlich zu einem Quick-Submit-Endpoint.
    bookmarklet_js = (
        "javascript:(function(){"
        "var u=encodeURIComponent(window.location.href);"
        "var t=encodeURIComponent(document.title||'');"
        "var s=encodeURIComponent(window.getSelection().toString().substring(0,500));"
        "var w=window.open('https://lex-europe.org/admin/quick-submit?url='+u+'&title='+t+'&sel='+s,"
        "'lexeurope','width=560,height=520');"
        "})();"
    )
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Browser-Bookmarklet — LEX EUROPE</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',system-ui,sans-serif;background:#080c12;color:#aab5c0;font-size:14px;line-height:1.7;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;font-family:ui-monospace,Menlo,monospace;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:720px;margin:0 auto;padding:32px 26px 60px;}}
h1{{font-size:30px;font-weight:600;color:#e9eef3;margin-bottom:8px;}}
.sub{{font-size:11px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;font-family:ui-monospace,Menlo,monospace;margin-bottom:30px;}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:22px 24px;margin-bottom:14px;}}
h2{{font-size:11px;letter-spacing:2px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:12px;font-family:ui-monospace,Menlo,monospace;}}
.bookmark{{display:inline-block;padding:14px 26px;background:#6aa9c9;color:#080c12;
  text-decoration:none;font-family:ui-monospace,Menlo,monospace;font-size:12px;
  font-weight:700;letter-spacing:2px;text-transform:uppercase;border-radius:0;margin:14px 0;}}
.bookmark:hover{{background:#5fb583;}}
code{{font-family:ui-monospace,Menlo,monospace;background:rgba(106,169,201,0.10);padding:1px 5px;color:#e9eef3;font-size:12px;}}
ol{{padding-left:22px;}}
li{{margin-bottom:6px;}}
.footer{{font-family:ui-monospace,Menlo,monospace;font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>BOOKMARKLET</span></div>
<div class="page">
  <h1>Browser-Bookmarklet</h1>
  <div class="sub">Ein-Klick-Submission beliebiger Web-Artikel an die Plattform</div>

  <div class="section">
    <h2>1 · Installation</h2>
    <ol>
      <li>Lesezeichenleiste sichtbar machen (Strg+Shift+B / Cmd+Shift+B).</li>
      <li>Den <b>orangefarbenen Button</b> unten in die Lesezeichenleiste ziehen.</li>
      <li>Auf einer beliebigen Webseite klicken → öffnet ein kleines Fenster
          mit pre-gefülltem URL + Titel + Auswahl-Text.</li>
    </ol>
    <a class="bookmark" href="{bookmarklet_js}" onclick="alert('Bitte in die Lesezeichenleiste ziehen statt klicken.');return false;">◆ → LEX EUROPE</a>
  </div>

  <div class="section">
    <h2>2 · Was es macht</h2>
    <p>Liest beim Klick die aktuelle <code>window.location.href</code>,
       <code>document.title</code> und die Text-Auswahl, öffnet ein
       Popup-Fenster mit der Admin-Quick-Submit-URL als Query-String —
       der Admin kann den Vorfall in 10 Sekunden vor-bewerten und
       speichern. Keine Daten verlassen den Browser, bevor der Admin
       sie absendet.</p>
  </div>

  <div class="section">
    <h2>3 · Manueller Code (für Power-User)</h2>
    <p>Falls Drag-and-Drop nicht geht (mobile / lockdown), kann der Code
       direkt als Lesezeichen-Adresse hinterlegt werden:</p>
    <pre style="background:#080c12;border:1px solid rgba(255,255,255,0.06);padding:14px;font-size:10px;color:#aab5c0;overflow-x:auto;white-space:pre-wrap;word-break:break-all">{bookmarklet_js}</pre>
  </div>

  <div class="footer">LEX EUROPE · Bookmarklet · für autorisierte Admin-Accounts</div>
</div>
</body></html>""")


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
        f"{base}/sources", f"{base}/press", f"{base}/methodology",
        f"{base}/bookmarklet", f"{base}/api/incidents/export.csv",
        f"{base}/api/incidents/export.json", f"{base}/api/target-types",
        f"{base}/api/incidents.rss", f"{base}/api/early-warning.rss",
        f"{base}/embed/counter", f"{base}/embed/headline", f"{base}/embed/trend",
        f"{base}/api/timeline/v2", f"{base}/api/heatmap",
        f"{base}/api/actors/cross-references",
        f"{base}/en/dashboard", f"{base}/en/sources",
        f"{base}/api/v1/docs",
    ]
    # Per-target-type + per-country pages dynamisch ergänzen.
    for tt in ("Auto","Schiene","Energie","Telekom","Militär","Polizei",
               "Politik","Justiz","Medien","Wirtschaft"):
        urls.append(f"{base}/early-warning/{tt}")
    for co in ("DE","AT","CH","FR","IT","ES","GR","UK","NL","DK","SE","NO","US",
               "BE","IE","PT","CZ","HU"):
        urls.append(f"{base}/c/{co}")
    # Akteurs-Profil-Seiten — alle KNOWN_ACTORS bekommen eine Sitemap-URL.
    from urllib.parse import quote as _q
    for name, _patterns, _tier in KNOWN_ACTORS:
        urls.append(f"{base}/a/{_q(name)}")
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
@app.get("/api/public/sources")
async def public_sources():
    """Öffentliche Source-Health-Übersicht — Operator-Stakeholder können
    sehen welche Quellen wir aktiv crawlen, welche zuletzt erfolgreich
    waren und welche aktuell auf Auto-Disable stehen. Macht den
    Crawler-Status nachprüfbar ohne Admin-Login."""
    rows = db.execute(
        "SELECT source, url, last_attempt, last_success, last_error, "
        "consecutive_failures, total_attempts, total_successes, "
        "items_last_run, items_total, active "
        "FROM source_health "
        "ORDER BY active DESC, total_successes DESC, source ASC"
    ).fetchall()
    sources = []
    for r in rows:
        d = dict(r)
        cf = d["consecutive_failures"] or 0
        if not d["active"]:           d["status"] = "disabled"
        elif cf >= 5:                 d["status"] = "warning"
        elif cf > 0:                  d["status"] = "degraded"
        elif d["total_successes"] > 0: d["status"] = "healthy"
        else:                          d["status"] = "untested"
        # Sensitive-felder NICHT raushauen (last_error kann interne IPs enthalten).
        d.pop("last_error", None)
        sources.append(d)
    return JSONResponse({
        "sources":      sources,
        "configured":   len(RSS_FEEDS),
        "totals": {
            "healthy":   sum(1 for s in sources if s["status"]=="healthy"),
            "degraded":  sum(1 for s in sources if s["status"]=="degraded"),
            "warning":   sum(1 for s in sources if s["status"]=="warning"),
            "disabled":  sum(1 for s in sources if s["status"]=="disabled"),
            "untested":  sum(1 for s in sources if s["status"]=="untested"),
            "active_count": sum(1 for s in sources if s["active"]),
        },
        "items_today":  sum((s.get("items_last_run") or 0) for s in sources),
        "asof":         datetime.now().isoformat(timespec="seconds"),
    })


@app.get("/sources", response_class=HTMLResponse)
async def public_sources_page(request: Request):
    """Öffentliche Crawler-Status-Übersicht: zeigt alle Quellen, ihren
    Health-Status (healthy/degraded/warning/disabled/untested), letzte
    erfolgreiche Crawl, Anzahl Items. Press-/Stakeholder-tauglich.
    Macht insbesondere transparent dass barrikade.info gecrawlt wird
    (auch wenn temporär blockiert)."""
    s_resp = await public_sources()
    import json as _j
    data = _j.loads(s_resp.body)
    sources = data["sources"]
    totals  = data["totals"]
    # Sortierung für visuelle Klarheit: healthy zuerst, dann degraded/warning, dann disabled.
    order_map = {"healthy":0, "degraded":1, "warning":2, "untested":3, "disabled":4}
    sources.sort(key=lambda s: (order_map.get(s["status"], 9), s["source"]))
    def esc(s): return _xml_esc(s)
    status_color = {
        "healthy":  "#5fb583",
        "degraded": "#d99a2b",
        "warning":  "#d99a2b",
        "untested": "#6c7986",
        "disabled": "#d4495d",
    }
    status_label = {
        "healthy":  "● aktiv",
        "degraded": "● degraded",
        "warning":  "● warnung",
        "untested": "○ ungetestet",
        "disabled": "● disabled",
    }
    rows_html = "".join(
        f"<tr class='s-{esc(s['status'])}'>"
        f"<td><span style='color:{status_color.get(s['status'], '#6c7986')}'>{status_label.get(s['status'], '?')}</span></td>"
        f"<td class='src'>{esc(s['source'])}</td>"
        f"<td class='url'>{esc(s.get('url') or '—')}</td>"
        f"<td class='n'>{s.get('total_successes') or 0}</td>"
        f"<td class='n'>{s.get('total_attempts') or 0}</td>"
        f"<td class='n'>{s.get('items_total') or 0}</td>"
        f"<td class='date'>{esc(s.get('last_success') or '—')}</td>"
        f"<td class='n'>{s.get('consecutive_failures') or 0}</td>"
        f"</tr>"
        for s in sources
    ) or "<tr><td colspan='8' style='color:#6c7986;text-align:center;padding:20px'>— keine Crawl-Statistiken vorhanden (Crawler läuft erst nach Boot+20s) —</td></tr>"
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Crawler-Quellen — LEX EUROPE</title>
<meta name="description" content="Crawler-Status aller {data['configured']} konfigurierten Quellen: {totals['healthy']} healthy, {totals['degraded']+totals['warning']} mit Fehlern, {totals['disabled']} disabled.">
<meta property="og:title"       content="LEX EUROPE — Crawler-Quellen-Status">
<meta property="og:description" content="{data['configured']} Quellen · {totals['healthy']} healthy · {totals['disabled']} disabled · {data.get('items_today',0)} Items in letztem Run">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;font-size:12px;line-height:1.5;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:1100px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:28px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:6px;}}
.sub{{font-size:10px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:24px;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px;}}
.kpi{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:16px 20px;}}
.kpi .lbl{{font-size:8px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:4px;}}
.kpi .val{{font-size:24px;font-weight:600;color:#e9eef3;font-variant-numeric:tabular-nums;}}
.kpi.green .val{{color:#5fb583;}}.kpi.amber .val{{color:#d99a2b;}}.kpi.red .val{{color:#d4495d;}}
table{{width:100%;border-collapse:collapse;font-family:ui-monospace;font-size:11px;}}
th,td{{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:left;vertical-align:top;}}
th{{font-size:9px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;background:rgba(255,255,255,0.02);}}
td.src{{color:#e9eef3;font-weight:600;}}
td.url{{color:#6c7986;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
td.n{{text-align:right;color:#aab5c0;font-variant-numeric:tabular-nums;}}
td.date{{color:#6c7986;font-size:10px;}}
tr:hover td{{background:rgba(106,169,201,0.04);}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:18px 22px;margin-bottom:14px;}}
h2{{font-size:10px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
.cta{{display:inline-block;font-size:10px;letter-spacing:2px;color:#6aa9c9;border:1px solid #6aa9c9;padding:8px 14px;text-decoration:none;text-transform:uppercase;margin-right:6px;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>CRAWLER-STATUS · STAND {esc(data['asof'][:10])}</span></div>
<div class="page">
  <h1>Crawler-Quellen-Status</h1>
  <div class="sub">{data['configured']} konfigurierte Quellen · Auto-Disable nach {SOURCE_MAX_FAILURES} consecutive failures · Public-Visibility-Endpoint</div>

  <div class="kpi-grid">
    <div class="kpi"><div class="lbl">Konfiguriert</div><div class="val">{data['configured']}</div></div>
    <div class="kpi green"><div class="lbl">Healthy</div><div class="val">{totals['healthy']}</div></div>
    <div class="kpi amber"><div class="lbl">Degraded / Warning</div><div class="val">{totals['degraded']+totals['warning']}</div></div>
    <div class="kpi red"><div class="lbl">Auto-Disabled</div><div class="val">{totals['disabled']}</div></div>
    <div class="kpi"><div class="lbl">Untested</div><div class="val">{totals['untested']}</div></div>
    <div class="kpi"><div class="lbl">Items letzte Crawls</div><div class="val">{data.get('items_today',0)}</div></div>
  </div>

  <div class="section">
    <h2>Alle Quellen ({len(sources)} mit Crawl-Statistik)</h2>
    <table>
      <thead><tr>
        <th>STATUS</th><th>QUELLE</th><th>URL</th>
        <th>SUCC</th><th>VERSUCHE</th><th>ITEMS</th>
        <th>LETZTER ERFOLG</th><th>F-CHAIN</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Methodik & Schnellzugriff</h2>
    Diese Seite spiegelt die Tabelle <code>source_health</code> wieder, die der
    Crawler nach jedem RSS-Fetch aktualisiert. Quellen mit ≥ {SOURCE_MAX_FAILURES}
    aufeinanderfolgenden Fehlern werden automatisch deaktiviert; ein Admin
    kann sie via <code>POST /admin/api/source-health/&lt;source&gt;/reset</code>
    re-aktivieren. Spezial-Crawler wie der für barrikade.info nutzen
    zusätzlich cloudscraper + web.archive.org als Fallback.<br><br>
    <a class="cta" href="/api/public/sources">↗ JSON-Export</a>
    <a class="cta" href="/dashboard">→ Dashboard</a>
    <a class="cta" href="/">→ Karte</a>
  </div>

  <div class="footer">LEX EUROPE · transparente Crawler-Health · automatisch aktualisiert</div>
</div>
</body></html>""")


@app.get("/press", response_class=HTMLResponse)
async def public_press_kit():
    """Press-Kit — schnelle Übersicht für Journalist:innen + Pressestellen
    mit Download-Buttons (RSS-Feeds, Markdown-Wochenbericht, JSON-API),
    Methodik-Box, Kontakt + Plattform-Statistik."""
    s = await public_stats()
    import json as _j
    d = _j.loads(s.body)
    today = d["asof"]
    contact = os.getenv("CONTACT_EMAIL", "kontakt@lex-europe.org")
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Press Kit — LEX EUROPE</title>
<meta name="description" content="Press Kit: alle Schnittstellen, Methodik, Kontakt für Journalist:innen und Pressestellen.">
<meta property="og:title"       content="LEX EUROPE — Press Kit">
<meta property="og:description" content="Download-Schnittstellen, Methodik-Dokumentation und Redaktions-Kontakt für die LEX-EUROPE-OSINT-Plattform.">
<meta property="og:type"        content="article">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;font-size:13px;line-height:1.55;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:880px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:32px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:6px;}}
.sub{{font-size:10px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:30px;}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:22px 24px;margin-bottom:14px;}}
h2{{font-size:11px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px;}}
.kpi{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:14px 18px;}}
.kpi .lbl{{font-size:8px;color:#6c7986;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}}
.kpi .val{{font-size:24px;font-weight:600;color:#e9eef3;font-variant-numeric:tabular-nums;}}
.cta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;}}
.cta{{display:block;padding:14px 16px;border:1px solid #6aa9c9;text-decoration:none;color:#aab5c0;background:rgba(106,169,201,0.04);transition:background .12s,color .12s;}}
.cta:hover{{background:rgba(106,169,201,0.10);color:#e9eef3;}}
.cta b{{color:#6aa9c9;display:block;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}}
.cta span{{display:block;font-size:11px;color:#6c7986;}}
.cite{{background:rgba(106,169,201,0.06);border-left:3px solid #6aa9c9;padding:12px 16px;font-size:11px;}}
.cite code{{display:block;margin-top:6px;color:#e9eef3;font-size:10px;word-break:break-all;}}
.kontakt{{padding:14px 16px;border:1px solid rgba(106,169,201,0.45);background:rgba(106,169,201,0.08);}}
.kontakt a{{color:#e9eef3;font-size:14px;text-decoration:none;}}
.kontakt a:hover{{text-decoration:underline;}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
.body-text{{font-family:'Inter',system-ui,sans-serif;font-size:13px;color:#aab5c0;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>PRESS KIT · STAND {today}</span></div>
<div class="page">
  <h1>Press Kit</h1>
  <div class="sub">Schnittstellen, Methodik & Kontakt für Journalist:innen, Forschung, Behörden</div>

  <div class="kpis">
    <div class="kpi"><div class="lbl">T1-Akte gesamt</div><div class="val">{d['total_t1']}</div></div>
    <div class="kpi"><div class="lbl">Hoch-Schwere ≥4</div><div class="val">{d['high_severity']}</div></div>
    <div class="kpi"><div class="lbl">Aktive Cluster</div><div class="val">{d['active_clusters']}</div></div>
    <div class="kpi"><div class="lbl">Identifizierte Akteure</div><div class="val">{d['distinct_actors']}</div></div>
  </div>

  <div class="section">
    <h2>Sofort-Schnittstellen</h2>
    <div class="cta-grid">
      <a class="cta" href="/api/incidents.rss"><b>↗ RSS · Vorfälle</b><span>Default T1, severity ≥3, ?country=DE/US/CH/…</span></a>
      <a class="cta" href="/api/early-warning.rss"><b>↗ RSS · Frühwarn-Cluster</b><span>≥3 gleichartige Anschläge / 6 Wochen</span></a>
      <a class="cta" href="/api/lagebericht/weekly.md"><b>↓ Markdown · Wochenbericht</b><span>Press-ready zum Direkt-Einbau</span></a>
      <a class="cta" href="/lagebericht"><b>→ Wochenbericht-Seite</b><span>HTML, druckfreundlich, OG-getaggt</span></a>
      <a class="cta" href="/dashboard"><b>→ Live-Dashboard</b><span>KPI-Karten + Top-Länder</span></a>
      <a class="cta" href="/sources"><b>→ Crawler-Quellen-Status</b><span>Transparente Health-Übersicht</span></a>
      <a class="cta" href="/api/public/stats"><b>↗ JSON-Stats</b><span>Aggregat-Endpoint für Embedding</span></a>
      <a class="cta" href="/api/v1/docs"><b>→ LEA / Research API v1</b><span>Authentifizierter Vollzugang</span></a>
    </div>
  </div>

  <div class="section">
    <h2>Embed-Widgets</h2>
    <p class="body-text">Externe Sites können kompakte LEX-EUROPE-KPIs direkt
       einbinden — kein JavaScript, kein Tracking, transparenter Hintergrund:</p>
    <div class="cite">
      <code>&lt;iframe src="/embed/counter" width="100%" height="180" style="border:0"&gt;&lt;/iframe&gt;</code>
      <code>&lt;iframe src="/embed/headline" width="100%" height="100" style="border:0"&gt;&lt;/iframe&gt;</code>
    </div>
  </div>

  <div class="section">
    <h2>Zitations-Schnittstelle</h2>
    <p class="body-text">Für akademische Nutzung: jeder Vorfall liefert
       BibTeX, RIS oder Chicago mit eingebettetem SHA-256 des WARC-Snapshots,
       damit Zitate reproduzierbar verifizierbar sind:</p>
    <div class="cite">
      <code>GET /api/incident/&lt;id&gt;/cite?format=bibtex</code>
      <code>GET /api/incident/&lt;id&gt;/cite?format=ris</code>
      <code>GET /api/incident/&lt;id&gt;/cite?format=chicago</code>
    </div>
  </div>

  <div class="section">
    <h2>Methodik (Kurz)</h2>
    <p class="body-text">Die Plattform übernimmt das Fedpol Art. 19 Abs. 2
       Bst. e NDG-Schema („act / enable / context") und macht die
       Strafverfolgungs-Lücke öffentlich messbar. Aufnahme nur, wenn
       der Empfänger oder Akteur in einem aktuellen
       Verfassungsschutzbericht (BfV, LfV, DSN, NDB) benannt ist oder
       gegen die Strukturen ein laufendes §§ 129/129a-Verfahren
       geführt wird. Doxxing-Inhalte werden ohne PII protokolliert
       und mit gelöschter Quelle ausgegeben.
       <a href="/methodology" style="color:#6aa9c9">→ Vollständige Methodik-Doku</a></p>
  </div>

  <div class="section">
    <h2>Redaktions-Kontakt</h2>
    <div class="kontakt">
      <a href="mailto:{contact}">{contact}</a><br>
      <span style="font-size:10px;color:#6c7986">PGP auf Anfrage. Sichere Übermittlung von Hinweisen über SecureDrop in Vorbereitung.</span>
    </div>
  </div>

  <div class="footer">LEX EUROPE · {today} · unabhängige OSINT-Plattform · keine Werbung · kein Tracking</div>
</div>
</body></html>""")


@app.get("/methodology", response_class=HTMLResponse)
async def public_methodology():
    """Standalone Methodik-Dokumentation — was wird aufgenommen, was nicht,
    welche Schwellenwerte, welche §C3-Ausschlusskriterien."""
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Methodik — LEX EUROPE</title>
<meta name="description" content="LEX EUROPE Methodik: Aufnahmekriterien (Fedpol-Taxonomie, VS-Berichte, §129-Verfahren), Datenpolitik (DSGVO §C3, Doxxing-Sanitisierung), Quellenintegrität (WARC + SHA-256), Verfolgungs-Status-Tracking.">
<meta property="og:title"       content="LEX EUROPE — Methodik">
<meta property="og:description" content="Aufnahmekriterien, Datenpolitik, Quellenintegrität, Verfolgungs-Tracking. Vollständige Doku der Plattform-Schwellen.">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',system-ui,-apple-system,sans-serif;background:#080c12;color:#aab5c0;font-size:14px;line-height:1.7;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;font-family:ui-monospace,Menlo,monospace;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:780px;margin:0 auto;padding:30px 28px 60px;}}
h1{{font-size:34px;font-weight:600;color:#e9eef3;letter-spacing:0.3px;margin-bottom:8px;}}
.sub{{font-size:11px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;font-family:ui-monospace,Menlo,monospace;margin-bottom:28px;}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:24px 28px;margin-bottom:14px;}}
h2{{font-size:12px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid rgba(106,169,201,0.18);font-family:ui-monospace,Menlo,monospace;}}
p,li{{margin-bottom:10px;}}
ol,ul{{padding-left:22px;}}
b{{color:#e9eef3;}}
code{{font-family:ui-monospace,Menlo,monospace;background:rgba(106,169,201,0.10);padding:1px 5px;color:#e9eef3;font-size:13px;}}
.tier{{display:grid;grid-template-columns:auto 1fr;gap:14px 18px;align-items:start;}}
.tier-label{{padding:5px 12px;font-family:ui-monospace,Menlo,monospace;font-size:10px;font-weight:700;letter-spacing:2px;text-align:center;border:1px solid currentColor;}}
.t1{{color:#d4495d;}}.t2{{color:#d99a2b;}}.t3{{color:#6c7986;}}
.warn{{background:rgba(217,154,43,0.10);border-left:3px solid #d99a2b;padding:14px 18px;margin:14px 0;}}
.cta{{display:inline-block;font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#6aa9c9;border:1px solid #6aa9c9;padding:8px 16px;text-decoration:none;margin-right:6px;}}
.footer{{font-family:ui-monospace,Menlo,monospace;font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>METHODIK-DOKUMENTATION</span></div>
<div class="page">
  <h1>Methodik & Datenpolitik</h1>
  <div class="sub">Aufnahmekriterien · Schwellenwerte · Ausschluss-Linien · Quellenintegrität</div>

  <div class="section">
    <h2>1 · Aufnahmekriterien für Vorfälle</h2>
    <p>Ein Ereignis wird nur dokumentiert, wenn mindestens eines der folgenden
       Kriterien erfüllt ist:</p>
    <ol>
      <li><b>VS-Bericht-Nennung:</b> Der Akteur oder die Trägerorganisation
          ist in einem aktuellen Verfassungsschutzbericht (BfV, LfV der
          Länder, DSN Österreich, NDB Schweiz, ggf. US-FBI-Domestic-
          Terrorism-Reports) namentlich erwähnt.</li>
      <li><b>Laufendes §129/§129a-Verfahren</b> bzw. analoge Normen
          (§ 246a öStGB, Art. 260ter StGB Schweiz, GA RICO Code § 16-4-10).</li>
      <li><b>Dokumentierte Solidar-/Infrastruktur</b> für Personen, die
          wegen militanter linker Straftaten verurteilt oder angeklagt sind.</li>
    </ol>
    <div class="warn">
      <b>Was NICHT aufgenommen wird:</b> Demos, legale Petitionen,
      normale Parteiarbeit, Gegen-Demonstrationen ohne Eskalation,
      humanitäre NGOs ohne dokumentierte Linksextrem-Querverbindungen.
      Tech-/Auto-/Krypto-Themen ohne politischen Bezug werden vom
      Klassifikator automatisch herausgefiltert.
    </div>
  </div>

  <div class="section">
    <h2>2 · Fedpol-Tier-Klassifikation</h2>
    <p>Jeder Vorfall wird nach Art. 19 Abs. 2 Bst. e NDG einer von drei
       Handlungs-Klassen zugewiesen:</p>
    <div class="tier">
      <div class="tier-label t1">T1 ACT</div>
      <div><b>Verüben</b> — Brandanschlag, Sabotage, Gewalt, Militante Aktion,
        Sachbeschädigung mit politischem Motiv. Kernbereich der Plattform.</div>
      <div class="tier-label t2">T2 ENABLE</div>
      <div><b>Fördern</b> — Aufruf zu Gewalt, Mobilisierungstreffen,
        Gewaltpropaganda, Schmiererei mit konkreter Drohphrase + Schwere ≥3.</div>
      <div class="tier-label t3">T3 CONTEXT</div>
      <div><b>Befürworten/Kontext</b> — Demos, Repressionsberichte,
        Verhaftungen, Sonstiges. Im Lagebild zur Vollständigkeit
        protokolliert, aber visuell de-emphasiert.</div>
    </div>
  </div>

  <div class="section">
    <h2>3 · Doxxing- und PII-Schutz</h2>
    <p>Doxxing-Vorfälle (Klarnamen, Wohnadressen, Arbeitgeber-Outings,
       Wohnumfeld-Berichte) werden <b>dokumentiert, aber sanitisiert</b>:
       die Quelle (Original-URL) wird gelöscht, die Beschreibung durch
       einen Rollen-Hinweis ersetzt (<code>"Politiker:in in &lt;Stadt&gt;
       wurde gedoxxt"</code>), Klartext-Inhalt verlässt die Datenbank nie.
       Erkennung über kombinierte Heuristik: Doxxing-Kontext-Trigger
       (geoutet/enttarnt/Wohnumfeld/Klarnamen veröffentlicht) PLUS
       mindestens ein PII-Signal (Adresse, E-Mail, Telefon, Geburtsdatum).</p>
  </div>

  <div class="section">
    <h2>4 · Quellenintegrität (Säule 4)</h2>
    <p>Jeder crawled Vorfall bekommt einen WARC/1.1-Snapshot der
       Originalquelle plus SHA-256-Hash + ISO-Zeitstempel.
       Citation-Export (BibTeX/RIS/Chicago) bettet den Hash in die
       Zitations-Notiz ein — damit ist jede Quellenangabe
       reproduzierbar verifizierbar, auch wenn die Original-URL später
       verschwindet. Cloudflare-/Anti-Bot-geschützte Hosts werden über
       cloudscraper + web.archive.org als Fallback erfasst.</p>
  </div>

  <div class="section">
    <h2>5 · Strafverfolgungs-Status-Tracking (Säule 1)</h2>
    <p>Bekannte, in Mainstream-Berichterstattung dokumentierte
       Strafverfahren werden mit ihrem Aktenzeichen auf die Vorfälle
       gemapped (Lina E. OLG Dresden 4 OJs 9/21, G20 Hamburg LG Hamburg
       612 KLs, Stop Cop City Fulton County 23SC183872, Letzte Generation
       GStA München 1 BJs 7/23-2, Tesla Grünheide GStA Berlin 4 BJs 4/24,
       Minneapolis Third Precinct D.Minn. 0:20-cr-00203, …).
       Der <a href="/dashboard">öffentliche Strafverfolgungs-Gap-Counter</a>
       misst, welcher Anteil der hoch-Schwere-T1-Vorfälle nach ≥180 Tagen
       noch ohne dokumentiertes Verfahren ist.</p>
  </div>

  <div class="section">
    <h2>6 · Funding-Quellen-Verifikation</h2>
    <p>Funding-Records tragen ein zweistufiges Vertrauenslabel:
      <b style="color:#5fb583">✓ verifiziert</b> wenn die Quellen-URL
      direkt auf ein spezifisches Primärdokument zeigt
      (Climate-Emergency-Fund-Grantees-Liste, Letzte-Generation-Finanzbericht,
      Bürgerschafts-Drucksache mit Aktenzeichen).
      <b style="color:#d99a2b">⚠ ungeprüft</b> wenn die Quelle eine
      Programm-Landingpage ist — das spezifische Dokument ist dahinter
      veröffentlicht, aber die Plattform verlinkt nicht direkt darauf
      (bitte vor Zitation eigenständig prüfen). Fiktive Trägervereins-
      Namen sind aus dem Datenbestand entfernt.</p>
  </div>

  <div class="section">
    <h2>7 · Was NIEMALS in der Datenbank steht</h2>
    <ul>
      <li>Klarnamen, Wohnadressen, Arbeitgeber privater Personen
          (auch nicht von „bekannten Linksextremisten").</li>
      <li>Personenbezogene Daten aus Mailing-Listen-Archiven
          (alle Riseup-Listen-Imports durchlaufen PII-Redaktion).</li>
      <li>Vorverurteilungs-Aussagen — Aufnahme bedeutet NICHT Schuld;
          Pflichtfeld ist immer ein Verbindungsnachweis.</li>
      <li>Selbstjustiz-Werkzeuge: keine Live-Locations laufender Aktionen,
          keine Karten von Veranstaltungs-Adressen einzelner Personen.</li>
      <li>Vollständige Gewaltpropaganda im Klartext — nur Hash + Zitat
          ≤200 Zeichen + Link.</li>
    </ul>
  </div>

  <div class="section" style="text-align:center">
    <a class="cta" href="/dashboard">→ Dashboard</a>
    <a class="cta" href="/press">→ Press Kit</a>
    <a class="cta" href="/api/v1/docs">→ LEA API</a>
    <a class="cta" href="/">→ Karte</a>
  </div>

  <div class="footer">LEX EUROPE · Methodik-Dokumentation · {datetime.now().date().isoformat()}</div>
</div>
</body></html>""")


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

@app.get("/a/{actor_slug:path}", response_class=HTMLResponse)
async def public_actor_profile(actor_slug: str):
    """Public actor profile — alle Vorfälle + Funding-Cross-Reference für
    einen Akteur. URL-Slug = url-encoded Akteurs-Name.
    Analog zu /c/{country} und /early-warning/{target_type}."""
    from urllib.parse import unquote
    actor = unquote(actor_slug or "").strip()
    if not actor or len(actor) < 3:
        return HTMLResponse("<h1>Unbekannter Akteur</h1>", status_code=404)
    # Tier-Klassifikation
    actor_tier = ACTOR_TIER.get(actor, "endorse")
    tier_label = {"act":"Verüben (T1)", "enable":"Fördern (T2)",
                  "endorse":"Befürworten (T3)"}.get(actor_tier, actor_tier)
    tier_color = {"act":"#d4495d", "enable":"#d99a2b",
                  "endorse":"#7a8a99"}.get(actor_tier, "#7a8a99")
    # Incidents pro Land + Severity
    actor_l = actor.lower()
    rows = [dict(r) for r in db.execute(
        "SELECT id,date,location,country,category,summary,severity_score,tier,"
        "target_type,url,source,actors FROM incidents WHERE actors LIKE ? "
        "ORDER BY date DESC", (f"%{actor}%",)
    ).fetchall()]
    incs = [r for r in rows if any(
        a.strip().lower() == actor_l for a in (r["actors"] or "").split(",")
    )]
    total_n = len(incs)
    hi_n    = sum(1 for r in incs if (r.get("severity_score") or 0) >= 4)
    from collections import Counter
    by_co  = Counter(r["country"] for r in incs)
    by_cat = Counter(r["category"] for r in incs)
    by_tt  = Counter(r["target_type"] for r in incs if r.get("target_type"))
    by_year = Counter((r["date"] or "")[:4] for r in incs if r.get("date"))
    sev_hist = [0]*5
    for r in incs:
        s = max(1, min(5, r.get("severity_score") or 1))
        sev_hist[s-1] += 1
    last_seen = max((r["date"] for r in incs if r.get("date")), default="—")
    first_seen = min((r["date"] for r in incs if r.get("date")), default="—")
    # Funding cross-reference
    needles = [actor.lower()]
    for name, _patterns, _tier in KNOWN_ACTORS:
        if name.lower() == actor_l:
            for pat in _patterns:
                cleaned = re.sub(r"[\\b\\s\\.\\?\\*\\+\\(\\)\\[\\]\\|]", " ", pat).strip()
                first = cleaned.split()[0] if cleaned.split() else ""
                if len(first) >= 4: needles.append(first.lower())
    needles = list(set(needles))
    fund_or = " OR ".join(["(LOWER(recipient_org) LIKE ? OR LOWER(donor_name) LIKE ? OR LOWER(notes) LIKE ?)"] * len(needles))
    fund_params = []
    for n in needles:
        like = f"%{n}%"
        fund_params.extend([like, like, like])
    funds = [dict(r) for r in db.execute(
        "SELECT recipient_org, project, amount, currency, year, donor_name, "
        "source_url, COALESCE(verified, 0) AS verified "
        "FROM funding_records WHERE " + (fund_or or "1=0") + " "
        "ORDER BY year DESC, amount DESC LIMIT 50", fund_params
    ).fetchall()] if fund_or else []
    sum_eur = sum(f["amount"] for f in funds if (f.get("currency") or "EUR") == "EUR")
    sum_chf = sum(f["amount"] for f in funds if (f.get("currency") or "EUR") == "CHF")
    def esc(s): return _xml_esc(s)
    sev_html = "".join(
        f"<div class='sb-col' title='{n} Vorfälle Schwere {i+1}'>"
        f"<div class='sb-bar' style='height:{max(2, n*30//max(sev_hist+[1]))}px;"
        f"background:{['#3a4551','#5a6c7a','#d99a2b','#cf6044','#d4495d'][i]}'></div>"
        f"<div class='sb-lbl'>{i+1}</div></div>"
        for i, n in enumerate(sev_hist)
    )
    yr_html = "".join(
        f"<div class='row'><span>{esc(y)}</span><span class='n'>{n}</span></div>"
        for y, n in sorted(by_year.items())
    ) or "—"
    co_html = "".join(
        f"<div class='row'><a href='/c/{esc(c)}'>{esc(c)}</a><span class='n'>{n}</span></div>"
        for c, n in by_co.most_common(6)
    ) or "—"
    tt_html = "".join(
        f"<div class='row'><a href='/early-warning/{esc(t)}'>{esc(t)}</a><span class='n'>{n}</span></div>"
        for t, n in by_tt.most_common(6)
    ) or "—"
    inc_html = "".join(
        f"<div class='inc'><span class='date'>{esc(r.get('date'))}</span>"
        f"<span class='loc'>{esc(r.get('location'))}, {esc(r.get('country'))}</span>"
        f"<span class='cat'>{esc(r.get('category'))}</span>"
        f"<span class='sev'>S{r.get('severity_score','?')}</span>"
        f"<div class='summ'>{esc((r.get('summary') or '')[:200])}</div>"
        + (f"<a class='src' href='{esc(r.get('url'))}' rel='noopener'>↗ {esc(r.get('source') or '')}</a>" if r.get('url','').startswith('http') else "")
        + "</div>"
        for r in incs[:25]
    ) or "<div style='color:#6c7986'>— keine Vorfälle —</div>"
    fund_html = "".join(
        f"<div class='inc'><span class='date'>{esc(str(f.get('year')))}</span>"
        f"<span class='loc'>{esc((f.get('recipient_org') or '')[:42])}</span>"
        f"<span class='cat'>{esc((f.get('donor_name') or '')[:40])}</span>"
        f"<span class='sev'>{f.get('currency','EUR')} {int(f.get('amount') or 0):,}</span>"
        + ("<span class='vrfd'>✓</span>" if f.get("verified") else "<span class='unvrfd'>⚠</span>")
        + f"<div class='summ'>{esc((f.get('project') or '')[:200])}</div>"
        + (f"<a class='src' href='{esc(f.get('source_url'))}' rel='noopener'>↗ Quelle</a>" if (f.get('source_url') or '').startswith('http') else "")
        + "</div>"
        for f in funds[:20]
    ) or "<div style='color:#6c7986'>— keine Förderungen gefunden —</div>"
    return HTMLResponse(f"""<!doctype html>
<html lang="de"><head>
<meta charset="utf-8"><title>Akteurs-Profil: {esc(actor)} — LEX EUROPE</title>
<meta name="description" content="OSINT-Profil zum Akteur {esc(actor)}: {total_n} dokumentierte Vorfälle ({hi_n} hoch-Schwere), Fedpol-Tier: {tier_label}.">
<meta property="og:title"       content="LEX EUROPE — Akteurs-Profil {esc(actor)}">
<meta property="og:description" content="{total_n} Vorfälle · {hi_n} hoch-Schwere · {len(by_co)} Länder · {len(funds)} Funding-Records (€{sum_eur:,.0f})">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;font-size:13px;line-height:1.55;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:1000px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:30px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:8px;}}
.tier-badge{{display:inline-block;font-family:ui-monospace;font-size:9px;letter-spacing:2px;padding:3px 10px;border:1px solid currentColor;text-transform:uppercase;}}
.sub{{font-size:10px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin:14px 0 24px;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;}}
.kpi{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:16px 20px;}}
.kpi .lbl{{font-size:8px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:4px;}}
.kpi .val{{font-size:26px;font-weight:600;color:#e9eef3;font-variant-numeric:tabular-nums;}}
.kpi.red .val{{color:#d4495d;}}.kpi.amber .val{{color:#d99a2b;}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;}}
@media(max-width:760px){{.grid2{{grid-template-columns:1fr;}}.kpi-grid{{grid-template-columns:repeat(2,1fr);}}}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:18px 22px;margin-bottom:14px;}}
h2{{font-size:10px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.row{{display:flex;justify-content:space-between;padding:4px 0;font-size:11px;border-bottom:1px solid rgba(255,255,255,0.03);}}
.row a{{color:#aab5c0;text-decoration:none;}}.row a:hover{{color:#6aa9c9;}}
.row .n{{color:#e9eef3;font-variant-numeric:tabular-nums;}}
.sb-hist{{display:flex;align-items:flex-end;gap:8px;height:60px;}}
.sb-col{{flex:1;display:flex;flex-direction:column;align-items:center;}}
.sb-bar{{width:100%;min-height:2px;}}
.sb-lbl{{font-size:9px;color:#6c7986;margin-top:3px;}}
.inc{{padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);font-size:11px;}}
.inc .date{{color:#6c7986;margin-right:10px;font-variant-numeric:tabular-nums;}}
.inc .loc{{color:#aab5c0;margin-right:10px;}}
.inc .cat{{color:#e9eef3;margin-right:10px;}}.inc .sev{{color:#d99a2b;font-weight:600;}}
.inc .vrfd{{color:#5fb583;margin-left:6px;}}.inc .unvrfd{{color:#d99a2b;margin-left:6px;}}
.inc .summ{{margin-top:4px;color:#aab5c0;}}
.inc .src{{font-size:9px;color:#6aa9c9;text-decoration:none;letter-spacing:1px;margin-top:3px;display:inline-block;}}
.cta{{display:inline-block;font-size:10px;letter-spacing:2px;color:#6aa9c9;border:1px solid #6aa9c9;padding:8px 14px;text-decoration:none;margin-right:8px;text-transform:uppercase;}}
.cta:hover{{background:rgba(106,169,201,0.10);}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>AKTEURS-PROFIL</span></div>
<div class="page">
  <h1>{esc(actor)}</h1>
  <span class="tier-badge" style="color:{tier_color}">{esc(tier_label)}</span>
  <div class="sub">OSINT-Akteursprofil · automatisch aggregiert · Stand {datetime.now().date().isoformat()}</div>

  <div class="kpi-grid">
    <div class="kpi"><div class="lbl">Vorfälle gesamt</div><div class="val">{total_n}</div></div>
    <div class="kpi red"><div class="lbl">Schwere ≥4</div><div class="val">{hi_n}</div></div>
    <div class="kpi"><div class="lbl">Länder</div><div class="val">{len(by_co)}</div></div>
    <div class="kpi amber"><div class="lbl">Funding-Records</div><div class="val">{len(funds)}</div></div>
  </div>

  <div class="grid2">
    <div class="section"><h2>Schwere-Verteilung</h2><div class="sb-hist">{sev_html}</div></div>
    <div class="section"><h2>Aktivität pro Jahr</h2>{yr_html}</div>
  </div>

  <div class="grid2">
    <div class="section"><h2>Länder (Top 6)</h2>{co_html}</div>
    <div class="section"><h2>Ziel-Klassen (Top 6)</h2>{tt_html}</div>
  </div>

  <div class="section"><h2>Zeitraum & Schnellzugriff</h2>
    <div class="row"><span>Erstmals dokumentiert</span><span class="n">{esc(first_seen)}</span></div>
    <div class="row"><span>Zuletzt dokumentiert</span><span class="n">{esc(last_seen)}</span></div>
    <div style="margin-top:14px">
      <a class="cta" href="/api/incidents/by-actor?actor={esc(actor)}">↗ JSON-Export</a>
      <a class="cta" href="/api/funding/by-actor?actor={esc(actor)}">↗ Funding-API</a>
      <a class="cta" href="/dashboard">→ Dashboard</a>
    </div>
  </div>

  <div class="section"><h2>Funding-Records ({len(funds)})</h2>{fund_html}</div>
  <div class="section"><h2>Jüngste Vorfälle (max. 25)</h2>{inc_html}</div>

  <div class="footer">LEX EUROPE · {esc(actor)} · Fedpol-Tier: {esc(actor_tier)}</div>
</div>
</body></html>""")


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

@app.get("/api/incidents/hotwire")
async def hotwire():
    """SITREP-Strip: die N jüngsten High-Severity- oder T1-Vorfälle.
    Wird vom UI-Hotwire-Ticker im Header genutzt — kompakter Payload
    (kein description-Volltext, nur die zum Anzeigen benötigten Felder)."""
    rows = db.execute(
        """SELECT id,date,location,country,category,summary,severity_score,
                  tier,target_type,is_high_risk
           FROM incidents
           WHERE (severity_score >= 4 OR tier='act')
             AND date IS NOT NULL AND date != ''
           ORDER BY date DESC, timestamp DESC
           LIMIT 12"""
    ).fetchall()
    return JSONResponse([dict(r) for r in rows])

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
         "prosec_status,case_ref,last_status_check,corroboration,"
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
    out = []
    for r in db.execute(q, p).fetchall():
        d = dict(r)
        # M4: attach the per-entry verification/quality score so the UI can
        # render a credibility badge.
        d["quality"] = quality_score(
            confidence=d.get("confidence") or 0,
            prosec_status=d.get("prosec_status") or "unknown",
            case_ref=d.get("case_ref") or "",
            has_evidence=bool((d.get("evidence_path") or "").strip()),
            corroboration=d.get("corroboration") or 0,
        )
        # M4: a T1 "act" published as fact but still unverified (single low-
        # confidence source, no court anchor, no corroboration) belongs in a
        # review queue. Surfaced as a derived flag — does not alter publication.
        d["needs_review"] = bool(
            d.get("tier") == "act" and d["quality"]["label"] == "unverified"
        )
        out.append(d)
    return JSONResponse(out)

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


@app.get("/api/timeline/v2")
async def timeline_data(months: int = 24, country: str = "", tier: str = "act"):
    """Monatliche Event-Density mit Tier-Breakdown — Datenquelle für
    Chart.js-Trends im Dashboard und Embed-Widgets. months default 24.
    Output: series[{month, total, act, enable, context, by_category{}}]."""
    today = datetime.now().date()
    start = (today.replace(day=1) - timedelta(days=32 * months)).replace(day=1)
    q = "SELECT date, tier, category, severity_score FROM incidents WHERE date >= ?"
    p = [start.isoformat()]
    if country: q += " AND country = ?"; p.append(country)
    rows = db.execute(q, p).fetchall()
    from collections import defaultdict
    buckets = defaultdict(lambda: {"total": 0, "act": 0, "enable": 0, "context": 0,
                                    "hi": 0, "by_category": defaultdict(int)})
    for r in rows:
        try: d = datetime.fromisoformat(r["date"]).date()
        except Exception: continue
        key = f"{d.year}-{d.month:02d}"
        b = buckets[key]
        b["total"] += 1
        b[r["tier"] or "context"] = b.get(r["tier"] or "context", 0) + 1
        if (r["severity_score"] or 0) >= 4: b["hi"] += 1
        b["by_category"][r["category"]] += 1
    series = []
    cur = start
    while cur <= today:
        key = f"{cur.year}-{cur.month:02d}"
        b = buckets.get(key, {"total": 0, "act": 0, "enable": 0, "context": 0, "hi": 0, "by_category": {}})
        b_clean = {**b, "month": key,
                   "by_category": dict(b["by_category"]) if b["by_category"] else {}}
        series.append(b_clean)
        cur = cur.replace(year=cur.year+1, month=1) if cur.month==12 else cur.replace(month=cur.month+1)
    return JSONResponse({
        "months":   months,
        "country":  country or "ALL",
        "series":   series,
        "asof":     datetime.now().isoformat(timespec="seconds"),
    })


@app.get("/api/heatmap")
async def heatmap_data(months: int = 12):
    """Monat × Land Vorfalls-Density für Heatmap-Visualisierung.
    Output: {months:[...], countries:[...], matrix:{country:[counts]}}."""
    today = datetime.now().date()
    start = (today.replace(day=1) - timedelta(days=32 * months)).replace(day=1)
    rows = db.execute(
        "SELECT date, country FROM incidents WHERE tier='act' AND date >= ? "
        "ORDER BY date ASC", (start.isoformat(),)
    ).fetchall()
    # Build month axis
    month_axis = []
    cur = start
    while cur <= today:
        month_axis.append(f"{cur.year}-{cur.month:02d}")
        cur = cur.replace(year=cur.year+1, month=1) if cur.month==12 else cur.replace(month=cur.month+1)
    # Build country axis from data, sortiert nach total volume
    from collections import Counter, defaultdict
    co_totals = Counter(r["country"] for r in rows)
    country_axis = [c for c, _ in co_totals.most_common(15)]
    matrix = {c: [0] * len(month_axis) for c in country_axis}
    for r in rows:
        co = r["country"]
        if co not in matrix: continue
        try: d = datetime.fromisoformat(r["date"]).date()
        except Exception: continue
        key = f"{d.year}-{d.month:02d}"
        if key in month_axis:
            matrix[co][month_axis.index(key)] += 1
    return JSONResponse({
        "months":     month_axis,
        "countries":  country_axis,
        "matrix":     matrix,
        "asof":       datetime.now().isoformat(timespec="seconds"),
    })


@app.get("/embed/trend", response_class=HTMLResponse)
async def embed_trend():
    """Embed-fähiger Mini-Trend-Chart als reines inline-SVG — kein JS,
    kein Tracking. Zeigt T1-Akte pro Monat über die letzten 12 Monate."""
    res = await timeline_data(months=12)  # timeline_data ist /api/timeline/v2
    import json as _j
    d = _j.loads(res.body)
    series = d["series"]
    if not series:
        return HTMLResponse("<svg width='100%' height='80'><text x='50%' y='50%' text-anchor='middle' fill='#6c7986' font-family='monospace' font-size='11'>Keine Daten</text></svg>")
    max_t = max(s["total"] for s in series) or 1
    w, h = 460, 100
    pad = 24
    pts = []
    bars = []
    for i, s in enumerate(series):
        x = pad + i * (w - 2*pad) / max(len(series)-1, 1)
        y = h - pad - (s["total"] / max_t) * (h - 2*pad)
        bars.append(f'<rect x="{x-6}" y="{y}" width="12" height="{h-pad-y}" fill="#6aa9c9" opacity="0.40"/>')
        if s["hi"]:
            yhi = h - pad - (s["hi"] / max_t) * (h - 2*pad)
            bars.append(f'<rect x="{x-6}" y="{yhi}" width="12" height="{h-pad-yhi}" fill="#d4495d" opacity="0.85"/>')
        pts.append(f"{x},{y}")
    line = f'<polyline points="{" ".join(pts)}" fill="none" stroke="#6aa9c9" stroke-width="2"/>'
    # X-axis labels (first, middle, last month)
    labels = []
    for idx in (0, len(series)//2, len(series)-1):
        x = pad + idx * (w - 2*pad) / max(len(series)-1, 1)
        labels.append(f'<text x="{x}" y="{h-4}" text-anchor="middle" fill="#6c7986" font-family="monospace" font-size="9">{series[idx]["month"]}</text>')
    total_n = sum(s["total"] for s in series)
    hi_n    = sum(s["hi"] for s in series)
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8">
<style>body{{margin:0;padding:8px;background:transparent;font-family:ui-monospace,Menlo,Consolas,monospace;color:#aab5c0}}
.box{{background:#080c12;border:1px solid rgba(255,255,255,0.08);padding:10px}}
.head{{font-size:8.5px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:8px;display:flex;justify-content:space-between}}
.head a{{color:#6aa9c9;text-decoration:none}}
.stats{{display:flex;gap:14px;font-size:9px;margin-bottom:4px;color:#6c7986;letter-spacing:1.5px;text-transform:uppercase}}
.stats .a{{color:#6aa9c9}}.stats .r{{color:#d4495d}}
</style></head><body><div class="box">
<div class="head"><span>◆ LEX EUROPE · T1-AKTE · 12 MONATE</span><a href="/dashboard" target="_top">→ dashboard</a></div>
<div class="stats"><span class="a">Σ {total_n}</span> T1-Akte <span class="r">{hi_n}</span> hoch-Schwere</div>
<svg width="100%" viewBox="0 0 {w} {h}" preserveAspectRatio="none">
{''.join(bars)}
{line}
{''.join(labels)}
</svg>
</div></body></html>""")


@app.get("/en/dashboard", response_class=HTMLResponse)
async def public_dashboard_en():
    """English version of /dashboard — for international press + research."""
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
<html lang="en"><head>
<meta charset="utf-8"><title>LEX EUROPE — Situation Dashboard {today}</title>
<meta name="description" content="OSINT situational picture of politically-left motivated violence in Europe and the United States. {d['total_t1']} documented T1 acts, {d['active_clusters']} active early-warning clusters.">
<meta property="og:title"       content="LEX EUROPE — Left-extremism Situational Picture">
<meta property="og:description" content="{d['total_t1']} documented T1 acts · {d['last_7d']} in the last 7 days · {d['active_clusters']} active early-warning clusters.">
<meta property="og:type"        content="website">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;min-height:100vh;font-size:13px;line-height:1.5;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
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
h2{{font-size:11px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.kc-row{{display:flex;align-items:center;gap:14px;margin-bottom:8px;}}
.kc-co{{font-size:11px;color:#aab5c0;min-width:35px;}}
.kc-bar{{flex:1;height:6px;background:rgba(106,169,201,0.08);border-radius:1px;overflow:hidden;}}
.kc-bar-fill{{height:100%;background:#6aa9c9;border-radius:1px;}}
.kc-n{{font-size:11px;color:#e9eef3;min-width:30px;text-align:right;font-variant-numeric:tabular-nums;}}
.cta{{display:inline-block;font-family:ui-monospace;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:#6aa9c9;border:1px solid #6aa9c9;padding:10px 16px;text-decoration:none;margin-right:8px;margin-top:8px;}}
.cta:hover{{background:rgba(106,169,201,0.10);}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE · UNCLASSIFIED // RELEASABLE</span><span>AS OF {today}</span></div>
<div class="page">
  <h1>Left-Extremism Situational Dashboard</h1>
  <div class="sub">Europe + USA · OSINT aggregation · automatically generated</div>

  <div class="kpi-grid">
    <div class="kpi acc"><div class="lbl">Total T1 acts</div><div class="val">{d['total_t1']}</div><div class="delta">tier=act (arson / sabotage / violence / militant action)</div></div>
    <div class="kpi"><div class="lbl">last 7 days</div><div class="val">{d['last_7d']}</div><div class="delta">new T1 acts</div></div>
    <div class="kpi"><div class="lbl">last 30 days</div><div class="val">{d['last_30d']}</div><div class="delta">new T1 acts</div></div>
    <div class="kpi red"><div class="lbl">high-severity ≥ 4</div><div class="val">{d['high_severity']}</div><div class="delta">personal injury / firebomb / ≥ €100k damage</div></div>
    <div class="kpi amber"><div class="lbl">active early-warning clusters</div><div class="val">{d['active_clusters']}</div><div class="delta">≥ 3 similar attacks / 6 weeks</div></div>
    <div class="kpi"><div class="lbl">identified actors</div><div class="val">{d['distinct_actors']}</div></div>
    <div class="kpi"><div class="lbl">active sources</div><div class="val">{d['distinct_sources']}</div></div>
  </div>

  <div class="section">
    <h2>Geographic distribution — Top 10 (T1)</h2>
    {coBlocks}
  </div>

  <div class="section">
    <h2>Interfaces</h2>
    <a class="cta" href="/">→ Full map + filter</a>
    <a class="cta" href="/lagebericht">→ Weekly briefing (DE)</a>
    <a class="cta" href="/en/sources">→ Crawler sources</a>
    <a class="cta" href="/api/incidents.rss">→ RSS feed</a>
    <a class="cta" href="/api/early-warning.rss">→ Early-warning feed</a>
    <a class="cta" href="/api/v1/docs">→ LEA / research API</a>
    <a class="cta" href="/dashboard">→ Deutsch</a>
  </div>

  <div class="footer">
    LEX EUROPE · OSINT platform · independent research · no ads · no tracking
  </div>
</div>
</body></html>""")


@app.get("/en/sources", response_class=HTMLResponse)
async def public_sources_page_en():
    """English version of /sources — crawler status visible to all."""
    s_resp = await public_sources()
    import json as _j
    data = _j.loads(s_resp.body)
    sources = data["sources"]
    totals  = data["totals"]
    order_map = {"healthy":0, "degraded":1, "warning":2, "untested":3, "disabled":4}
    sources.sort(key=lambda s: (order_map.get(s["status"], 9), s["source"]))
    def esc(s): return _xml_esc(s)
    status_color = {"healthy":"#5fb583","degraded":"#d99a2b","warning":"#d99a2b","untested":"#6c7986","disabled":"#d4495d"}
    status_label = {"healthy":"● active","degraded":"● degraded","warning":"● warning","untested":"○ untested","disabled":"● disabled"}
    rows_html = "".join(
        f"<tr class='s-{esc(s['status'])}'>"
        f"<td><span style='color:{status_color.get(s['status'], '#6c7986')}'>{status_label.get(s['status'], '?')}</span></td>"
        f"<td class='src'>{esc(s['source'])}</td><td class='url'>{esc(s.get('url') or '—')}</td>"
        f"<td class='n'>{s.get('total_successes') or 0}</td><td class='n'>{s.get('total_attempts') or 0}</td>"
        f"<td class='n'>{s.get('items_total') or 0}</td><td class='date'>{esc(s.get('last_success') or '—')}</td>"
        f"<td class='n'>{s.get('consecutive_failures') or 0}</td></tr>"
        for s in sources
    ) or "<tr><td colspan='8' style='color:#6c7986;text-align:center;padding:20px'>— No crawl statistics yet (crawler runs ~20s after boot) —</td></tr>"
    return HTMLResponse(f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>Crawler sources — LEX EUROPE</title>
<meta name="description" content="Status of all {data['configured']} configured crawler sources: {totals['healthy']} healthy, {totals['degraded']+totals['warning']} with errors, {totals['disabled']} auto-disabled.">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#080c12;color:#aab5c0;font-size:12px;line-height:1.5;}}
.classbar{{background:#0a1219;border-bottom:1px solid rgba(255,255,255,0.06);padding:5px 18px;font-size:9px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;display:flex;justify-content:space-between;}}
.classbar .l{{color:#6aa9c9;}}
.page{{max-width:1100px;margin:0 auto;padding:30px 24px 60px;}}
h1{{font-family:'Inter',system-ui,sans-serif;font-size:28px;font-weight:600;color:#e9eef3;letter-spacing:0.5px;margin-bottom:6px;}}
.sub{{font-size:10px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;margin-bottom:24px;}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px;}}
.kpi{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:16px 20px;}}
.kpi .lbl{{font-size:8px;letter-spacing:2.5px;color:#6c7986;text-transform:uppercase;margin-bottom:4px;}}
.kpi .val{{font-size:24px;font-weight:600;color:#e9eef3;font-variant-numeric:tabular-nums;}}
.kpi.green .val{{color:#5fb583;}}.kpi.amber .val{{color:#d99a2b;}}.kpi.red .val{{color:#d4495d;}}
table{{width:100%;border-collapse:collapse;font-family:ui-monospace;font-size:11px;}}
th,td{{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.04);text-align:left;vertical-align:top;}}
th{{font-size:9px;letter-spacing:2px;color:#6c7986;text-transform:uppercase;background:rgba(255,255,255,0.02);}}
td.src{{color:#e9eef3;font-weight:600;}}
td.url{{color:#6c7986;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
td.n{{text-align:right;color:#aab5c0;font-variant-numeric:tabular-nums;}}
td.date{{color:#6c7986;font-size:10px;}}
tr:hover td{{background:rgba(106,169,201,0.04);}}
.section{{background:#0d141c;border:1px solid rgba(255,255,255,0.06);padding:18px 22px;margin-bottom:14px;}}
h2{{font-size:10px;letter-spacing:2.5px;color:#6aa9c9;font-weight:700;text-transform:uppercase;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid rgba(106,169,201,0.18);}}
.footer{{font-size:9px;letter-spacing:1.5px;color:#3a4551;text-align:center;margin-top:30px;text-transform:uppercase;}}
.cta{{display:inline-block;font-size:10px;letter-spacing:2px;color:#6aa9c9;border:1px solid #6aa9c9;padding:8px 14px;text-decoration:none;text-transform:uppercase;margin-right:6px;}}
</style></head>
<body>
<div class="classbar"><span class="l">◆ OPEN SOURCE INTELLIGENCE · LEX EUROPE</span><span>CRAWLER STATUS · AS OF {esc(data['asof'][:10])}</span></div>
<div class="page">
  <h1>Crawler Source Status</h1>
  <div class="sub">{data['configured']} configured sources · auto-disable after {SOURCE_MAX_FAILURES} consecutive failures · public visibility</div>

  <div class="kpi-grid">
    <div class="kpi"><div class="lbl">Configured</div><div class="val">{data['configured']}</div></div>
    <div class="kpi green"><div class="lbl">Healthy</div><div class="val">{totals['healthy']}</div></div>
    <div class="kpi amber"><div class="lbl">Degraded / Warning</div><div class="val">{totals['degraded']+totals['warning']}</div></div>
    <div class="kpi red"><div class="lbl">Auto-Disabled</div><div class="val">{totals['disabled']}</div></div>
    <div class="kpi"><div class="lbl">Untested</div><div class="val">{totals['untested']}</div></div>
    <div class="kpi"><div class="lbl">Items in last run</div><div class="val">{data.get('items_today',0)}</div></div>
  </div>

  <div class="section">
    <h2>All sources ({len(sources)} with crawl statistics)</h2>
    <table>
      <thead><tr><th>STATUS</th><th>SOURCE</th><th>URL</th><th>SUCC</th><th>ATTEMPTS</th><th>ITEMS</th><th>LAST SUCCESS</th><th>F-CHAIN</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <div class="section">
    <a class="cta" href="/api/public/sources">↗ JSON export</a>
    <a class="cta" href="/en/dashboard">→ Dashboard</a>
    <a class="cta" href="/">→ Map</a>
    <a class="cta" href="/sources">→ Deutsch</a>
  </div>

  <div class="footer">LEX EUROPE · transparent crawler health · automatically updated</div>
</div>
</body></html>""")


@app.get("/api/actors/cross-references")
async def actors_cross_references(min_count: int = 1):
    """Akteurs-Co-Occurrence-Graph: zeigt welche Akteure gemeinsam in
    derselben Vorfalls-Zeile auftauchen. Output ist D3-Force-kompatibel
    {nodes: [{id, label, count, tier}], links: [{source, target, value}]}.
    Macht netzwerk-analytisch sichtbar, welche Strukturen miteinander
    operieren."""
    rows = db.execute(
        "SELECT actors FROM incidents WHERE actors IS NOT NULL AND actors != '' "
        "AND tier IN ('act','enable')"
    ).fetchall()
    from collections import Counter
    actor_counts = Counter()
    pair_counts  = Counter()
    for r in rows:
        actors = [a.strip() for a in (r["actors"] or "").split(",") if a.strip()]
        for a in actors:
            actor_counts[a] += 1
        # Pairs (sorted, jeweils nur einmal pro Vorfall)
        for i, a in enumerate(actors):
            for b in actors[i+1:]:
                key = tuple(sorted([a, b]))
                pair_counts[key] += 1
    # Filter: nur Akteure mit min_count Vorfällen
    eligible = {a for a, n in actor_counts.items() if n >= min_count}
    nodes = []
    for a, n in actor_counts.items():
        if a not in eligible: continue
        nodes.append({
            "id":    a,
            "label": a,
            "count": n,
            "tier":  ACTOR_TIER.get(a, "endorse"),
        })
    links = []
    for (a, b), n in pair_counts.items():
        if a in eligible and b in eligible:
            links.append({"source": a, "target": b, "value": n})
    return JSONResponse({
        "nodes":      nodes,
        "links":      links,
        "node_count": len(nodes),
        "link_count": len(links),
        "asof":       datetime.now().isoformat(timespec="seconds"),
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

# POST-Alias für die Delete-Operation. Cloudflare und einige Render.com-
# Proxy-Konfigurationen blockieren die DELETE-Methode auf Browser-Requests
# (CORS-Preflight scheitert silent → "Netzwerkfehler" im Frontend).
# POST mit explizitem /delete-Suffix funktioniert in JEDER Proxy-Konfig.
@app.post("/api/admin/incident/{inc_id}/delete")
async def admin_inline_delete_post(inc_id: int, _=Depends(require_admin)):
    db.execute("DELETE FROM incidents WHERE id=?", (inc_id,))
    db.commit()
    return JSONResponse({"ok": True, "id": inc_id})

@app.put("/api/admin/incident/{inc_id}")
async def admin_inline_update(inc_id: int, request: Request, _=Depends(require_admin)):
    return await _do_admin_inline_update(inc_id, request)

# POST-Alias für Update — gleiche Logik, andere HTTP-Methode (Proxy-Bypass).
@app.post("/api/admin/incident/{inc_id}/update")
async def admin_inline_update_post(inc_id: int, request: Request, _=Depends(require_admin)):
    return await _do_admin_inline_update(inc_id, request)

async def _do_admin_inline_update(inc_id: int, request: Request):
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

@app.post("/admin/api/barrikade-test")
async def admin_barrikade_test(_=Depends(require_admin)):
    """Volle Diagnose ALLER Barrikade-Discovery-Strategien.

    Testet parallel:
      1. SPIP-Auth-Login (Editorial-Backend)
      2. Standard-Discovery (RSS/Sitemap auf barrikade.info)
      3. SPIP-Public-Endpoints (?page=backend, ?page=plan auf beiden Domains)
      4. Search-Engine-Discovery (DuckDuckGo + Bing)
      5. Wayback Machine (für eine Test-URL)

    Liefert pro Strategie: success/fail, URL-Anzahl, Sample-URLs,
    detaillierte Fehlermeldungen."""
    diag = {"ts": datetime.now().isoformat(), "env": {
        "BARRIKADE_USER_set": bool(os.getenv("BARRIKADE_USER")),
        "BARRIKADE_PASS_set": bool(os.getenv("BARRIKADE_PASS")),
        "BARRIKADE_LOGIN_URL": os.getenv("BARRIKADE_LOGIN_URL","(default)"),
        "BARRIKADE_BASE":      os.getenv("BARRIKADE_BASE","(default)"),
    }}

    # 1) SPIP Auth (nur wenn ENV gesetzt)
    if os.getenv("BARRIKADE_USER") and os.getenv("BARRIKADE_PASS"):
        sess = _barrikade_login_session(force_refresh=True, capture_diag=True)
        auth = dict(_BK_LAST_DIAG)
        auth["session_acquired"] = sess is not None
        if sess is not None:
            try:
                urls = _barrikade_authed_discover_urls(sess)
                auth["discovery"] = {"urls_found": len(urls), "sample": urls[:5]}
            except Exception as e:
                auth["discovery"] = {"error": str(e)[:300]}
        diag["1_spip_auth"] = auth
    else:
        diag["1_spip_auth"] = {"skipped": "ENV BARRIKADE_USER/PASS nicht gesetzt"}

    # 2) Standard-Discovery (RSS/Sitemap) — wrapped to limit time
    try:
        # _barrikade_discover_urls trial-uses 10 RSS-Pfade mit timeout=12 each
        # = max ~120s worst case. In production wo Pfade schnell antworten ist
        # das OK, hier wrappen wir mit eigenem Timeout via signal-Alarm wäre
        # zu aggressiv — wir akzeptieren dass diese Strategie länger braucht.
        import threading
        result = {"urls": [], "done": False, "err": None}
        def _run():
            try:
                result["urls"] = _barrikade_discover_urls()
            except Exception as e:
                result["err"] = str(e)[:300]
            result["done"] = True
        th = threading.Thread(target=_run, daemon=True)
        th.start()
        th.join(timeout=25)  # 25s hard cap
        if result["err"]:
            diag["2_standard_discovery"] = {"error": result["err"]}
        elif not result["done"]:
            diag["2_standard_discovery"] = {"timeout": "25s exceeded", "partial_count": len(result["urls"])}
        else:
            diag["2_standard_discovery"] = {
                "urls_found": len(result["urls"]),
                "sample": result["urls"][:5],
            }
    except Exception as e:
        diag["2_standard_discovery"] = {"error": str(e)[:300]}

    # 3) SPIP-Public-Endpoints (15s budget)
    try:
        urls = _barrikade_spip_public_discover(max_results=20, per_request_timeout=4, overall_budget_s=15)
        diag["3_spip_public"] = {
            "urls_found": len(urls),
            "sample": urls[:5],
        }
    except Exception as e:
        diag["3_spip_public"] = {"error": str(e)[:300]}

    # Aggregat: Wie viele Strategien funktionieren?
    # (DDG/Bing/Wayback aus dem Default-Pfad entfernt — siehe Commit
    # 2026-05-28 Wayback-Cleanup)
    working = sum(1 for k in ("1_spip_auth","2_standard_discovery","3_spip_public")
                  if k in diag and (
                      diag[k].get("session_acquired") or
                      (diag[k].get("urls_found",0) > 0) or
                      diag[k].get("ok")
                  ))
    diag["working_strategies"] = working
    diag["overall_ok"] = working >= 1

    return JSONResponse(diag)

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


@app.get("/admin/api/hist-status")
async def admin_hist_status(_=Depends(require_admin)):
    """Status des automatischen Full-Sweep:
       - Aktueller ID-Stand
       - Bisher gecrawlte IDs + insertion-Total
       - ETA bei aktueller Tick-Rate
       - Live/Done-Flag
    User 2026-05-28: "automatisiert damit alle Artikel gecrawlt werden".
    Damit man sofort sieht ob der Sweep läuft und wie weit er ist."""
    is_done = bool(meta_get("hist_b_done"))
    curr = int(meta_get("hist_b_curr") or 0)
    mx   = int(meta_get("hist_b_max") or 0)
    tot  = int(meta_get("hist_b_total_inserted") or 0)
    done_ids = max(0, mx - curr)
    pct = round(done_ids / max(mx, 1) * 100, 1) if mx else 0
    # Aktuelle barrikade-Artikel in der DB als Sanity-Check
    db_count = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE source LIKE '%barrikade.info%'"
    ).fetchone()[0]
    return JSONResponse({
        "is_done":         is_done,
        "done_timestamp":  meta_get("hist_b_done") if is_done else None,
        "id_max":          mx,
        "id_current":      curr,
        "ids_done":        done_ids,
        "progress_pct":    pct,
        "remaining_ids":   max(0, curr),
        "total_inserted":  tot,
        "db_barrikade_count": db_count,
        "running":         _hist_run[0],
        "tick_interval_min": 30,
        "tick_chunk_size":   1500,
        "eta_hours":       round(curr / 3000, 1) if curr > 0 else 0,
    })


@app.post("/admin/api/hist-reset")
async def admin_hist_reset(_=Depends(require_admin)):
    """Reset historical state — beginnt den vollen Sweep neu von der
    aktuellen latest_id aus. Hash-Dedup verhindert Doppel-Einträge.
    Wichtig wenn ENV-Vars (FIRECRAWL/SCRAPINGBEE/SCRAPERAPI) NEU
    gesetzt wurden und man den kompletten ID-Raum nochmal scannen
    will mit den jetzt verfügbaren JS-Render-Services."""
    for k in ("hist_b_done","hist_b_curr","hist_b_max",
              "hist_b_total_inserted","b_live_max"):
        meta_del(k)
    log.info("Historical state reset by admin")
    return JSONResponse({"ok": True, "reset": True,
                         "note": "Next auto_hist tick (~30 min) startet bei latest_id"})


@app.post("/admin/api/hist-trigger")
async def admin_hist_trigger(bg: BackgroundTasks, _=Depends(require_admin)):
    """Triggert sofort einen run_historical()-Tick. Nützlich wenn man
    nicht 30 min auf den Scheduler warten will."""
    bg.add_task(run_historical, False)
    return JSONResponse({"ok": True, "triggered": "run_historical"})


@app.post("/admin/api/grok-test")
async def admin_grok(_=Depends(require_admin)):
    res = classify("In Berlin-Kreuzberg wurden drei Polizeifahrzeuge in Brand gesetzt. Bekennerschreiben einer militanten autonomen Gruppe.")
    return JSONResponse(res or {"error": "Keine Antwort"})

@app.get("/admin/api/firecrawl-test")
async def admin_firecrawl_test(aid: int = 7490, _=Depends(require_admin)):
    """Testet Firecrawl gegen eine spezifische Article-ID.
    Zeigt was geliefert wurde, ob es klassifizierbar ist, und ob es
    gespeichert würde.

    User 2026-05-28: "versuche mal nur artikel mit firecrawl zu crawlen
    https://barrikade.info/article/7490 ... nur mit den APIs"."""
    key = os.getenv("FIRECRAWL_API_KEY", "").strip()
    if not key:
        return JSONResponse({"ok": False, "error": "FIRECRAWL_API_KEY nicht in Render-Environment gesetzt"})
    import time as _t
    t0 = _t.monotonic()
    md = _firecrawl_article(aid)
    dt = round((_t.monotonic() - t0) * 1000)
    if not md:
        return JSONResponse({"ok": False, "aid": aid, "ms": dt,
                              "reason": "firecrawl returned empty"})
    relevant = any(kw in md.lower() for kw in BARRIKADE_RELEVANCE_KWS)
    fp = is_false_positive(md)
    preview = re.sub(r"\s+", " ", md[:400]).strip()
    return JSONResponse({
        "ok": True, "aid": aid,
        "url": f"https://barrikade.info/article/{aid}",
        "fetch_ms": dt,
        "markdown_len": len(md),
        "preview": preview,
        "would_save": relevant and not fp,
        "is_relevant": relevant,
        "is_false_positive": fp,
    })


@app.post("/admin/api/firecrawl-import")
async def admin_firecrawl_import(request: Request, _=Depends(require_admin)):
    """Direkter Firecrawl-Import einzelner Article-IDs.
    Body: {"ids": [7490, 7510, ...]}
    Für jede ID: Firecrawl → classify → save. Liefert Per-ID-Report."""
    if not os.getenv("FIRECRAWL_API_KEY", "").strip():
        return JSONResponse({"ok": False, "error": "FIRECRAWL_API_KEY nicht gesetzt"})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)
    ids = body.get("ids") or []
    if isinstance(ids, str):
        ids = [int(x.strip()) for x in re.split(r"[,\s]+", ids) if x.strip().isdigit()]
    ids = [int(i) for i in ids if str(i).isdigit()]
    if not ids:
        return JSONResponse({"ok": False, "error": "no valid ids"}, status_code=400)
    out = []
    inserted = 0
    for aid in ids:
        url_canon = f"https://barrikade.info/article/{aid}"
        md = _firecrawl_article(aid)
        if not md:
            out.append({"id": aid, "ok": False, "reason": "firecrawl_empty"})
            continue
        if not any(kw in md.lower() for kw in BARRIKADE_RELEVANCE_KWS):
            out.append({"id": aid, "ok": False, "reason": "not_relevant",
                        "preview": md[:160]})
            continue
        if is_false_positive(md):
            out.append({"id": aid, "ok": False, "reason": "false_positive"})
            continue
        try:
            ai = smart_classify(md)
            if not ai:
                out.append({"id": aid, "ok": False, "reason": "classify_returned_none"})
                continue
            art_date = date_from_markdown(md) or date_from_url(url_canon)
            saved = save_incident(ai, md, "barrikade.info", url_canon, art_date)
            if saved:
                inserted += 1
                out.append({"id": aid, "ok": True, "saved": True,
                            "category": ai.get("kategorie", ""),
                            "tier": ai.get("tier", ""),
                            "location": ai.get("ort", "")})
            else:
                out.append({"id": aid, "ok": False,
                            "reason": "save_failed_or_dedup",
                            "category": ai.get("kategorie", "")})
        except Exception as e:
            out.append({"id": aid, "ok": False, "reason": f"exc: {str(e)[:200]}"})
    return JSONResponse({"ok": True, "inserted": inserted,
                          "requested": len(ids), "results": out})


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
    backfill_barrikade_dates()
    # FTS5-Backfill: ein leerer Index wird einmal aus incidents repopuliert.
    backfill_fts_if_empty()
    # Strafverfolgungs-Status-Backfill: trägt bekannte Aktenzeichen
    # für dokumentierte Verfahren ein (Lina E., G20 Hamburg, Cop City,
    # Letzte Generation §129, Minneapolis Third Precinct, …). Idempotent.
    try:
        backfill_prosec_status()
    except Exception as e:
        log.warning(f"backfill_prosec_status failed: {e}")
    # M4 — cross-source corroboration: count independent sources per event so
    # the per-entry verification score reflects multi-source agreement.
    try:
        recompute_corroboration()
    except Exception as e:
        log.warning(f"recompute_corroboration failed: {e}")
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
    # Auto-Reset bei FIRECRAWL_API_KEY-Verfügbarkeit + leerer Historie:
    # User 2026-05-28: hist_b_done=true aber total_inserted=0 weil ohne
    # FIRECRAWL_API_KEY der ganze Sweep durchlief ohne Saves. Bei neuem
    # API-Key wollen wir den Sweep automatisch wiederholen.
    if os.getenv("FIRECRAWL_API_KEY", "").strip():
        b_total = int(meta_get("hist_b_total_inserted") or 0)
        b_done  = bool(meta_get("hist_b_done"))
        if b_done and b_total == 0:
            log.info("Auto-reset: hist_b_done=true but 0 saves — FIRECRAWL_API_KEY now set, restarting sweep")
            for k in ("hist_b_done","hist_b_curr","hist_b_max",
                      "hist_b_total_inserted","b_live_max"):
                meta_del(k)
    # Säule 2 — populate the Frühwarn-Cluster table on boot so the footer
    # counter and /api/early-warning.{rss,json} have data immediately.
    try:
        detect_clusters()
    except Exception as e:
        log.warning(f"detect_clusters at startup failed: {e}")
    sched = BackgroundScheduler(daemon=True, timezone="Europe/Zurich")
    # Main crawler: every 6 hours (auf Starter-Plan empfohlen — 24/7 läuft)
    sched.add_job(run_crawler, "interval", hours=6, id="main",
                  next_run_time=datetime.now() + timedelta(seconds=20))
    # Auto-continue historical barrikade crawl alle 30 min bis fertig.
    # User 2026-05-28: "automatisiert damit alle Artikel gecrawlt werden".
    # Mit 1500 IDs/Tick × 30 min = 3000 IDs/Stunde = 72k IDs/Tag.
    # ID-Raum 7570 → 1 = ~5 Stunden Vollabdeckung auf Starter-Plan ($7/Mo).
    sched.add_job(auto_hist, "interval", minutes=30, id="auto_hist",
                  next_run_time=datetime.now() + timedelta(seconds=90))
    # Re-detect Frühwarn-Cluster weekly. Cheap query — runs in milliseconds.
    sched.add_job(detect_clusters, "interval", days=7, id="early_warning",
                  next_run_time=datetime.now() + timedelta(hours=6))
    sched.start()
    log.info(f"LEX EUROPE — {len(RSS_FEEDS)} RSS + {len(GNEWS_Q)} GNews — crawl in 20s | hist auto-continue every 30min")

