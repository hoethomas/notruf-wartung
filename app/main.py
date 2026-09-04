import base64
import collections
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.pdfgen import canvas

BASE = Path(__file__).resolve().parent.parent
DB = BASE / "notruf.db"
MASTER_DATA = BASE / "master_data.json"
PROTOCOL_DIR = BASE / "protocols"
PROTOCOL_DIR.mkdir(exist_ok=True)
TEMPLATES = Jinja2Templates(directory=str(BASE / "app" / "templates"))

app = FastAPI(title="Notrufanlagen Wartung")
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", "change-this-secret"))

CHECKS = [
    ("zt", "ZT", ["OK", "NOK"]),
    ("zl", "ZL", ["OK", "NOK"]),
    ("rt_b1", "RT B1", ["OK", "NOK", "NF"]),
    ("rt_b2", "RT B2", ["OK", "NOK", "NF"]),
    ("rt_b3", "RT B3", ["OK", "NOK", "NF"]),
    ("rt", "RT", ["OK", "NOK", "NF"]),
    ("pt_bad", "PT Bad", ["OK", "NOK", "NF"]),
    ("rt_bad", "RT Bad", ["OK", "NOK", "NF"]),
    ("zt_bad", "ZT Bad", ["OK", "NOK", "NF"]),
    ("at_bad", "AT Bad", ["OK", "NOK", "NF"]),
]
CHECK_KEYS = [c[0] for c in CHECKS]


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return "pbkdf2_sha256$210000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt_b64, digest_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(rounds))
        return hmac.compare_digest(digest, base64.b64decode(digest_b64))
    except Exception:
        return False


def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'technician'
    );
    CREATE TABLE IF NOT EXISTS maintenances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hauscode TEXT NOT NULL,
        station TEXT NOT NULL,
        technician_id INTEGER NOT NULL,
        inspector_name TEXT,
        inspection_year INTEGER,
        inspection_type TEXT,
        email_address TEXT,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL,
        completed_at TEXT,
        signature TEXT,
        email_sent_at TEXT,
        email_error TEXT,
        pdf_path TEXT,
        FOREIGN KEY(technician_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS imported_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        config_name TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS config_stations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config_id INTEGER NOT NULL,
        hauscode TEXT NOT NULL,
        house_display TEXT NOT NULL,
        stationsbezeichnung TEXT NOT NULL,
        station_id TEXT,
        station_system_id TEXT,
        station_type TEXT,
        room_count INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(config_id) REFERENCES imported_configs(id)
    );
    CREATE TABLE IF NOT EXISTS config_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config_id INTEGER NOT NULL,
        hauscode TEXT NOT NULL,
        house_display TEXT NOT NULL,
        stationsbezeichnung TEXT NOT NULL,
        station_id TEXT,
        station_system_id TEXT,
        zimmerbezeichnung TEXT NOT NULL,
        FOREIGN KEY(config_id) REFERENCES imported_configs(id)
    );
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        maintenance_id INTEGER NOT NULL,
        room_name TEXT NOT NULL,
        manual INTEGER NOT NULL DEFAULT 0,
        zt TEXT, zl TEXT, rt_b1 TEXT, rt_b2 TEXT, rt_b3 TEXT, rt TEXT,
        rt_bad TEXT, pt_bad TEXT, zt_bad TEXT, at_bad TEXT,
        issue_details TEXT,
        FOREIGN KEY(maintenance_id) REFERENCES maintenances(id)
    );
    """)
    def add_col(table, col, definition):
        cols = {row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
        if col not in cols:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")
    add_col("config_stations", "station_id", "TEXT")
    add_col("config_stations", "station_system_id", "TEXT")
    add_col("config_records", "station_id", "TEXT")
    add_col("config_records", "station_system_id", "TEXT")
    add_col("maintenances", "station_id", "TEXT")
    add_col("users", "role", "TEXT NOT NULL DEFAULT 'technician'")
    for col, definition in [
        ("inspector_name", "TEXT"), ("inspection_year", "INTEGER"), ("inspection_type", "TEXT"), ("email_address", "TEXT"),
        ("email_sent_at", "TEXT"), ("email_error", "TEXT"), ("pdf_path", "TEXT")]:
        add_col("maintenances", col, definition)
    add_col("results", "manual", "INTEGER NOT NULL DEFAULT 0")
    add_col("results", "rt", "TEXT")
    add_col("results", "issue_details", "TEXT")
    user = c.execute("SELECT id FROM users LIMIT 1").fetchone()
    if not user:
        c.execute("INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)",
                  ("admin", hash_password("admin123"), "Administrator", "admin"))
    # Standard-Technikerkonten für den ersten Einsatz/Test anlegen, falls sie noch nicht existieren.
    for username, password, display_name in [
        ("Test1", "1234", "Test1"),
        ("Test2", "1234", "Test2"),
        ("Test3", "1234", "Test3"),
    ]:
        exists = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not exists:
            c.execute("INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)",
                      (username, hash_password(password), display_name, "technician"))
    c.commit(); c.close()


init_db()


def current_user(request):
    uid = request.session.get("user_id")
    if not uid:
        return None
    c = db(); u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone(); c.close()
    return u


def require_user(request):
    return current_user(request)


def load_master_data():
    # Legacy fallback retained only for compatibility with older deployments.
    if not MASTER_DATA.exists(): return []
    try:
        raw=json.loads(MASTER_DATA.read_text(encoding="utf-8")); clean=[]
        for r in raw:
            if not r.get("hauscode") or not r.get("stationsbezeichnung") or not r.get("zimmerbezeichnung"): continue
            clean.append({"hauscode":str(r["hauscode"]).strip(),"house_display":str(r.get("house_display") or r["hauscode"]).strip(),"stationsbezeichnung":str(r["stationsbezeichnung"]).strip(),"zimmerbezeichnung":str(r["zimmerbezeichnung"]).strip()})
        return clean
    except Exception: return []

def is_admin(request):
    u=current_user(request)
    return bool(u and u["role"] == "admin")

def get_active_config_id(request):
    cid=request.session.get("config_id")
    if not cid: return None
    c=db(); row=c.execute("SELECT id FROM imported_configs WHERE id=? AND user_id=?",(cid,request.session.get("user_id"))).fetchone(); c.close()
    return row["id"] if row else None

def active_records(request):
    cid=get_active_config_id(request)
    if not cid: return []
    c=db(); rows=c.execute("SELECT hauscode,house_display,stationsbezeichnung,zimmerbezeichnung FROM config_records WHERE config_id=?",(cid,)).fetchall(); c.close()
    return [dict(r) for r in rows]

def active_houses(request):
    seen={}
    cid=get_active_config_id(request)
    if cid:
        c=db(); rows=c.execute("SELECT hauscode,house_display FROM config_stations WHERE config_id=?",(cid,)).fetchall(); c.close()
        for r in rows: seen[r["hauscode"]]=r["house_display"]
    if not seen:
        for r in active_records(request): seen[r["hauscode"]]=r["house_display"]
    return sorted([(k,v) for k,v in seen.items()], key=lambda x:x[1].lower())

def active_stations(request, hauscode):
    cid=get_active_config_id(request)
    if not cid: return []
    c=db(); rows=c.execute("SELECT station_id,station_system_id,stationsbezeichnung,station_type,room_count FROM config_stations WHERE config_id=? AND hauscode=? ORDER BY stationsbezeichnung, CAST(COALESCE(station_system_id,'0') AS INTEGER)",(cid,hauscode)).fetchall(); c.close()
    if rows:
        data=[dict(r) for r in rows]
        counts=collections.Counter(x["stationsbezeichnung"] for x in data)
        for x in data:
            x["label"]=x["stationsbezeichnung"] + (f" (ID {x['station_system_id']})" if counts[x["stationsbezeichnung"]]>1 and x.get("station_system_id") else "")
        return data
    return []

def _element_full_name(node):
    """Return the object's own _name/_full, including inherited base objects."""
    if node is None:
        return ""
    name = node.find("./_name/_full")
    if name is not None and name.text and name.text.strip():
        return name.text.strip()
    for base in node.findall("./base"):
        found = _element_full_name(base)
        if found:
            return found
    return ""


def _resolve_ref(node, by_refid):
    """Resolve a ref/refid node while protecting against broken/cyclic references."""
    seen = set()
    cur = node
    while cur is not None:
        rid = cur.attrib.get("refid")
        ref = cur.attrib.get("ref")
        if rid and rid in by_refid and rid not in seen:
            seen.add(rid)
            cur = by_refid[rid]
            continue
        if ref and ref in by_refid and ref not in seen:
            seen.add(ref)
            cur = by_refid[ref]
            continue
        return cur
    return None


def _find_descendant(node, tag):
    """Find a property through base chains, not arbitrary nested room/device data."""
    direct = node.find(f"./{tag}")
    if direct is not None:
        return direct
    for base in node.findall("./base"):
        found = _find_descendant(base, tag)
        if found is not None:
            return found
    return None


def _get_rooms_node(ward):
    return _find_descendant(ward, "_rooms")


def _collect_room_objects(rooms_node, by_refid, seen_objects=None):
    """Recursively collect actual room objects from inline entries and references."""
    if seen_objects is None:
        seen_objects = set()
    result = []
    if rooms_node is None:
        return result
    for child in list(rooms_node):
        obj = _resolve_ref(child, by_refid)
        if obj is None:
            continue
        rid = obj.attrib.get("refid") or child.attrib.get("ref") or child.attrib.get("refid")
        key = rid or id(obj)
        if key in seen_objects:
            continue
        seen_objects.add(key)

        # A real room object has a _name/_full. Do not descend into its
        # technical substructures, otherwise device names become rooms.
        if _element_full_name(obj):
            result.append(obj)
            continue

        # Some VCIP versions wrap room groups/lists. Resolve those recursively.
        nested = _find_descendant(obj, "_rooms")
        if nested is not None:
            result.extend(_collect_room_objects(nested, by_refid, seen_objects))
    return result


def _collect_ward_entries(wards_node, by_refid):
    """Resolve every ward entry in the logicalConfig._wards list exactly once."""
    result = []
    seen = set()
    for entry in list(wards_node) if wards_node is not None else []:
        ward = _resolve_ref(entry, by_refid)
        if ward is None:
            continue
        # Walk base inheritance: e.g. Billroth 1 is typeid 176 with base typeid 7.
        name = _element_full_name(ward) or _element_full_name(_find_descendant(ward, "base") or ward)
        if not name:
            continue
        rid = ward.attrib.get("refid") or entry.attrib.get("ref") or entry.attrib.get("refid")
        key = rid or (ward.attrib.get("typeid"), name)
        if key in seen:
            continue
        seen.add(key)
        result.append(ward)
    return result


def parse_vcip_bytes(data: bytes):
    """Parse VCIP using the actual logical hierarchy: project -> wards -> rooms.

    Areas are intentionally ignored. References and inherited Ward structures are
    resolved before deduplication so a station such as Fellinger 2 cannot appear twice.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            bad = z.testzip()
            if bad:
                raise ValueError(f"Beschädigte VCIP-Datei (fehlerhaftes ZIP-Element: {bad}).")
            names = z.namelist()
            xml_name = "data/data.xml" if "data/data.xml" in names else next((n for n in names if n.lower().endswith(".xml")), None)
            if not xml_name:
                raise ValueError("Keine XML-Daten in der VCIP-Datei gefunden.")
            root = ET.fromstring(z.read(xml_name))
    except zipfile.BadZipFile as e:
        raise ValueError("Die VCIP-Datei ist keine gültige ZIP/VCIP-Datei oder ist beschädigt.") from e
    except ET.ParseError as e:
        raise ValueError("Die XML-Daten der VCIP-Datei sind beschädigt oder ungültig.") from e

    logical = next((e for e in root.iter() if e.tag == "_logicalConfig"), None)
    if logical is None:
        raise ValueError("Keine logische VCIP-Konfiguration (_logicalConfig) gefunden.")

    config_name = ""
    name_node = logical.find("./_name")
    if name_node is not None and name_node.text and name_node.text.strip():
        config_name = name_node.text.strip()
    if not config_name:
        config_name = _element_full_name(logical)
    if not config_name:
        raise ValueError("Kein Projekt-/Hausname in der VCIP-Konfiguration gefunden.")

    by_refid = {x.attrib.get("refid"): x for x in root.iter() if x.attrib.get("refid")}
    wards_node = logical.find("./_wards")
    wards = _collect_ward_entries(wards_node, by_refid)
    if not wards:
        raise ValueError("Die VCIP-Datei enthält keine erkennbaren Stationen.")

    station_objects = []
    station_seen = set()
    for ward in wards:
        station = _element_full_name(ward)
        if not station:
            continue
        station_id = ward.attrib.get("refid") or station
        if station_id in station_seen:
            continue
        station_seen.add(station_id)
        base_type = ward.attrib.get("typeid") or ""
        if base_type != "7":
            for base in ward.iter("base"):
                if base.attrib.get("typeid") == "7":
                    base_type = "7"
                    break
        system_id_node = ward.find("./_id")
        system_id = (system_id_node.text or "").strip() if system_id_node is not None else ""
        station_objects.append({"id":station_id,"system_id":system_id,"name":station,"typeid":base_type,"ward":ward})

    # KWP-style projects use a three-character house code at the start of
    # practically every station name. Other learned configurations use the
    # exact logical project name as the house. Detect that structural pattern
    # instead of hard-coding customer/project names.
    import re
    coded = [w["name"].split()[0] for w in station_objects if re.match(r"^[A-Z0-9]{3}$", w["name"].split()[0] if w["name"].split() else "")]
    use_station_prefix_house = bool(station_objects) and len(coded) / len(station_objects) >= 0.80
    records = []
    station_meta = []
    for info in station_objects:
        station = info["name"]
        first = station.split()[0] if station.split() else station
        house = first if use_station_prefix_house else config_name
        rooms_node = _get_rooms_node(info["ward"])
        rooms = _collect_room_objects(rooms_node, by_refid)
        station_meta.append({"station_id":info["id"],"station_system_id":info.get("system_id",""),"hauscode":house,"house_display":house,"stationsbezeichnung":station,"station_type":({"7":"VCIP","176":"VCIP","163":"VC+ Hybrid","170":"VC+ Hybrid"}.get(info["typeid"],"Unbekannt")),"room_count":len(rooms)})
        room_seen = set()
        for room in rooms:
            room_name = _element_full_name(room)
            if not room_name:
                continue
            room_id = room.attrib.get("refid") or room_name
            if room_id in room_seen:
                continue
            room_seen.add(room_id)
            records.append({
                "station_id": info["id"],
                "station_system_id": info.get("system_id",""),
                "hauscode": house,
                "house_display": house,
                "stationsbezeichnung": station,
                "zimmerbezeichnung": room_name,
            })

    if not records and not station_meta:
        raise ValueError("Die VCIP-Datei enthält keine erkennbaren Stationen/Zimmer.")

    # IMPORTANT: identical visible station names can be different Systembau stations.
    # Their stable station identity is the VCIP refid, while _id is the Systembau station ID.
    # Never merge two different station IDs just because the visible name is identical.
    merged_stations = {}
    for st in station_meta:
        key = (st["hauscode"], st.get("station_id") or (st["stationsbezeichnung"], st.get("station_system_id","")))
        if key not in merged_stations:
            merged_stations[key] = dict(st)
        else:
            merged_stations[key]["room_count"] += st.get("room_count", 0)
    station_meta = list(merged_stations.values())

    # Final defensive deduplication by semantic hierarchy.
    unique = []
    seen = set()
    for r in records:
        key = (r["hauscode"], r.get("station_id") or r["stationsbezeichnung"], r["zimmerbezeichnung"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return config_name, unique, station_meta

def save_import_for_user(request, filename, config_name, records, station_meta):
    u=current_user(request); now=datetime.now().isoformat(timespec="seconds")
    c=db()
    old=request.session.get("config_id")
    if old:
        c.execute("DELETE FROM config_records WHERE config_id=?",(old,)); c.execute("DELETE FROM config_stations WHERE config_id=?",(old,)); c.execute("DELETE FROM imported_configs WHERE id=? AND user_id=?",(old,u["id"]))
    cur=c.execute("INSERT INTO imported_configs(user_id,filename,config_name,created_at) VALUES(?,?,?,?)",(u["id"],filename,config_name,now)); cid=cur.lastrowid
    c.executemany("INSERT INTO config_stations(config_id,hauscode,house_display,stationsbezeichnung,station_id,station_system_id,station_type,room_count) VALUES(?,?,?,?,?,?,?,?)",[(cid,s["hauscode"],s["house_display"],s["stationsbezeichnung"],s.get("station_id",""),s.get("station_system_id",""),s.get("station_type",""),s.get("room_count",0)) for s in station_meta])
    c.executemany("INSERT INTO config_records(config_id,hauscode,house_display,stationsbezeichnung,station_id,station_system_id,zimmerbezeichnung) VALUES(?,?,?,?,?,?,?)",[(cid,r["hauscode"],r["house_display"],r["stationsbezeichnung"],r.get("station_id",""),r.get("station_system_id",""),r["zimmerbezeichnung"]) for r in records])
    c.commit();c.close();request.session["config_id"]=cid
    return cid

def get_rooms(hauscode, station, request=None, station_id=None):
    if request is not None:
        cid=get_active_config_id(request)
        if cid and station_id:
            c=db(); rows=c.execute("SELECT zimmerbezeichnung FROM config_records WHERE config_id=? AND hauscode=? AND station_id=? ORDER BY id",(cid,hauscode,station_id)).fetchall(); c.close()
            return [r["zimmerbezeichnung"] for r in rows]
        return sorted({r["zimmerbezeichnung"] for r in active_records(request) if r["hauscode"]==hauscode and r["stationsbezeichnung"]==station})
    return []

def is_room_checked(row):
    return all((row[k] or "") in ("OK", "NOK", "NF") for k in CHECK_KEYS)


def save_results_from_form(c, mid, form):
    for row in c.execute("SELECT id FROM results WHERE maintenance_id=?", (mid,)).fetchall():
        rid = row["id"]
        vals = [form.get(f"{key}_{rid}") for key, _, _ in CHECKS]
        details = {}
        raw = form.get(f"details_{rid}", "") or ""
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict): details = obj
        except Exception: pass
        details = {k: str(v).strip() for k,v in details.items() if k in CHECK_KEYS and vals[CHECK_KEYS.index(k)] == "NOK" and str(v).strip()}
        c.execute("""UPDATE results SET zt=?,zl=?,rt_b1=?,rt_b2=?,rt_b3=?,rt=?,pt_bad=?,rt_bad=?,zt_bad=?,at_bad=?,issue_details=? WHERE id=?""",
                  (*vals, json.dumps(details, ensure_ascii=False), rid))


class NumberedCanvas(canvas.Canvas):
    """Canvas that writes the final page count after the document is built."""
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 7)
        self.drawRightString(198*mm, 9*mm, f"Seite {self._pageNumber}/{page_count}")
        self.restoreState()


def format_date_de(value):
    if not value:
        return ""
    try:
        return datetime.fromisoformat(str(value)).strftime("%d.%m.%Y")
    except Exception:
        return str(value)[:10]


INSPECTION_TITLES = {
    "Inspektion": "Zusammenfassung der Rufanlageninspektion",
    "Wartung": "Zusammenfassung der Rufanlagenwartung",
    "Instandhaltung": "Zusammenfassung der Rufanlageninstandhaltung",
}


def make_pdf(mid):
    c = db()
    m = c.execute("SELECT m.*,u.display_name FROM maintenances m JOIN users u ON u.id=m.technician_id WHERE m.id=?", (mid,)).fetchone()
    rows = c.execute("SELECT * FROM results WHERE maintenance_id=? ORDER BY room_name", (mid,)).fetchall()
    c.close()
    if not m: raise ValueError("Wartung nicht gefunden")
    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=7*mm, leftMargin=7*mm, topMargin=6*mm, bottomMargin=6*mm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=13, leading=15, alignment=1)
    subtitle = ParagraphStyle("subtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=6.2, leading=7, alignment=1, spaceBefore=1)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=6.5, leading=7.5)
    center = ParagraphStyle("center", parent=small, alignment=1)
    issue_style = ParagraphStyle("issue", parent=small, fontSize=7, leading=8)

    inspection_type = m["inspection_type"] or "Wartung"
    pdf_title = INSPECTION_TITLES.get(inspection_type, INSPECTION_TITLES["Wartung"])
    title_block = [Paragraph(pdf_title, title), Paragraph("Dieses Dokument ist eine Zusammenfassung und ersetzt nicht das offizielle Wartungsprotokoll. Das offizielle Wartungsprotokoll erhalten Sie separat.", subtitle)]
    header = Table([
        [title_block, ""],
        [Paragraph(f"<b>Haus:</b> {m['hauscode']}", center), Paragraph(f"<b>Station:</b> {m['station']}", center)],
        [Paragraph(f"<b>Überprüfung für das Jahr:</b> {m['inspection_year'] or ''}", center), Paragraph(f"<b>Art der Überprüfung:</b> {inspection_type}", center)],
    ], colWidths=[99*mm,99*mm], rowHeights=[13*mm,8*mm,8*mm])
    header.setStyle(TableStyle([("SPAN",(0,0),(-1,0)),("GRID",(0,0),(-1,-1),0.6,colors.black),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))

    data = [["Bezeichnung"] + [x[1] for x in CHECKS]]; noks=[]
    for r in rows:
        line=[Paragraph(str(r["room_name"]), small)]
        try: details=json.loads(r["issue_details"] or "{}"); details=details if isinstance(details,dict) else {}
        except Exception: details={}
        for key,label,_ in CHECKS:
            val=r[key]
            if val == "OK":
                line.append(Paragraph("<font color='#16a34a'><b>✓</b></font>", ParagraphStyle("okp", parent=center, fontSize=11, leading=12)))
            elif val == "NOK":
                line.append(Paragraph("<font color='#dc2626'><b>!</b></font>", ParagraphStyle("nokp", parent=center, fontSize=11, leading=12)))
            elif val == "NF":
                line.append(Paragraph("<font color='#64748b'><b>—</b></font>", ParagraphStyle("nfp", parent=center, fontSize=11, leading=12)))
            else:
                line.append(Paragraph("", center))
            if val=="NOK": noks.append((r["room_name"],label,details.get(key,"")))
        data.append(line)
    widths=[46*mm]+[15.2*mm]*len(CHECKS)
    table=Table(data,repeatRows=1,colWidths=widths,hAlign="CENTER")
    table.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.45,colors.black),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eeeeee")),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),6.1),("FONTSIZE",(1,1),(-1,-1),6.4),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(0,0),(-1,-1),"CENTER"),("ALIGN",(0,1),(0,-1),"LEFT"),("TOPPADDING",(0,0),(-1,-1),3.5),("BOTTOMPADDING",(0,0),(-1,-1),3.5)]))
    story=[header,Spacer(1,2*mm),table,Spacer(1,3*mm)]
    if noks:
        issue_data=[[Paragraph("Zusammenfassung der Mängel", ParagraphStyle("ih",parent=small,fontName="Helvetica-Bold"))]]
        for room,label,detail in noks:
            txt=f"<b>{room}</b> – {label} – <b>NOK</b>"
            if detail: txt += f"<br/>Details: {detail}"
            issue_data.append([Paragraph(txt,issue_style)])
        issues=Table(issue_data,colWidths=[198*mm]); issues.setStyle(TableStyle([("BOX",(0,0),(-1,-1),0.6,colors.black),("INNERGRID",(0,0),(-1,-1),0.35,colors.black),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eeeeee")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
        story.extend([issues,Spacer(1,3*mm)])
    else:
        story.extend([Paragraph("<b>Zusammenfassung der Mängel:</b> Keine Beanstandungen.",small),Spacer(1,3*mm)])

    legend_title=Paragraph("<b>Legende</b>", ParagraphStyle("legendtitle", parent=small, fontName="Helvetica-Bold", fontSize=7.2, leading=8))
    legend_cells=[
        [Paragraph("<font color='#16a34a'><b>✓</b></font>", ParagraphStyle("lgok", parent=center, fontSize=11, leading=11)), Paragraph("<b>OK</b> – Prüfung in Ordnung", small)],
        [Paragraph("<font color='#dc2626'><b>!</b></font>", ParagraphStyle("lgnok", parent=center, fontSize=11, leading=11)), Paragraph("<b>NOK</b> – Mangel festgestellt", small)],
        [Paragraph("<font color='#64748b'><b>—</b></font>", ParagraphStyle("lgnf", parent=center, fontSize=11, leading=11)), Paragraph("<b>nicht ausgeführt</b>", small)],
    ]
    legend_table=Table(legend_cells, colWidths=[12*mm,76*mm])
    legend_table.setStyle(TableStyle([
        ("BOX",(0,0),(-1,-1),0.6,colors.black),("INNERGRID",(0,0),(-1,-1),0.3,colors.black),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(0,0),(0,-1),"CENTER"),
        ("BACKGROUND",(0,0),(0,0),colors.HexColor("#dcfce7")),("BACKGROUND",(0,1),(0,1),colors.HexColor("#fee2e2")),("BACKGROUND",(0,2),(0,2),colors.HexColor("#e2e8f0")),
        ("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),2.5),("BOTTOMPADDING",(0,0),(-1,-1),2.5)
    ]))

    abbrev_cells=[
        [Paragraph("<b>ZT:</b>",small), Paragraph("Zimmerterminal",small)],
        [Paragraph("<b>ZL:</b>",small), Paragraph("Zimmerlampe",small)],
        [Paragraph("<b>RT B1:</b>",small), Paragraph("Ruftaster Bett 1",small)],
        [Paragraph("<b>RT B2:</b>",small), Paragraph("Ruftaster Bett 2",small)],
        [Paragraph("<b>RT B3:</b>",small), Paragraph("Ruftaster Bett 3",small)],
        [Paragraph("<b>RT:</b>",small), Paragraph("Ruftaster",small)],
        [Paragraph("<b>PT Bad:</b>",small), Paragraph("Pneumatischer Taster im Bad",small)],
        [Paragraph("<b>RT Bad:</b>",small), Paragraph("Ruftaster Bad",small)],
        [Paragraph("<b>ZT Bad:</b>",small), Paragraph("Zugtaster Bad",small)],
        [Paragraph("<b>AT Bad:</b>",small), Paragraph("Abstelltaster Bad",small)],
    ]
    abbrev_table=Table(abbrev_cells, colWidths=[25*mm,63*mm])
    abbrev_table.setStyle(TableStyle([
        ("BOX",(0,0),(-1,-1),0.6,colors.black),("INNERGRID",(0,0),(-1,-1),0.3,colors.black),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2)
    ]))
    legend_left=Table([[legend_title],[legend_table]],colWidths=[94*mm])
    legend_left.setStyle(TableStyle([("BOX",(0,0),(-1,-1),0.6,colors.black),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eeeeee")),("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
    abbrev_title=Paragraph("<b>Abkürzungen</b>", ParagraphStyle("abbrevtitle", parent=small, fontName="Helvetica-Bold", fontSize=7.2, leading=8))
    legend_right=Table([[abbrev_title],[abbrev_table]],colWidths=[94*mm])
    legend_right.setStyle(TableStyle([("BOX",(0,0),(-1,-1),0.6,colors.black),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eeeeee")),("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
    combined_legend=Table([[legend_left,legend_right]],colWidths=[96*mm,96*mm])
    combined_legend.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),0),("RIGHTPADDING",(0,0),(-1,-1),0),("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0)]))
    story.append(combined_legend); story.append(Spacer(1,3*mm))

    sig_img=""
    if m["signature"] and m["signature"].startswith("data:image"):
        try:
            raw=base64.b64decode(m["signature"].split(",",1)[1]); sig_img=Image(io.BytesIO(raw),width=55*mm,height=18*mm)
        except Exception: pass
    completed=format_date_de(m["completed_at"])
    notes=Table([
        [Paragraph("<b>Unterschrift:</b>",small),sig_img],
        [Paragraph(f"<b>Name des Prüfers:</b> {m['inspector_name'] or m['display_name'] or ''}",small),Paragraph(f"<b>Abschlussdatum:</b> {completed}",small)],
    ],colWidths=[99*mm,99*mm],rowHeights=[22*mm,12*mm])
    notes.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.6,colors.black),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3)])); story.append(notes)
    doc.build(story, canvasmaker=NumberedCanvas); out.seek(0); return out



@app.get("/import", response_class=HTMLResponse)
def import_page(request: Request):
    u=current_user(request)
    if not u: return RedirectResponse("/login",303)
    c=db(); cfg=None
    cid=get_active_config_id(request)
    if cid: cfg=c.execute("SELECT * FROM imported_configs WHERE id=?",(cid,)).fetchone()
    c.close()
    return TEMPLATES.TemplateResponse("import.html", {"request":request,"user":u,"config":cfg,"record_count":len(active_records(request)),"station_count":len(active_stations(request, active_houses(request)[0][0])) if active_houses(request) else 0})

@app.post("/import/vcip-file")
async def import_vcip_file(request: Request, file_upload: UploadFile = File(...)):
    u=current_user(request)
    if not u: return RedirectResponse("/login",303)
    data=await file_upload.read()
    try:
        config_name,records,station_meta=parse_vcip_bytes(data)
        save_import_for_user(request,file_upload.filename or "config.vcip",config_name,records,station_meta)
        return RedirectResponse(f"/import?success={len(records)}",303)
    except Exception as e:
        return RedirectResponse("/import?error="+str(e).replace(" ","+"),303)

@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    u=current_user(request)
    if not u: return RedirectResponse("/login",303)
    if u["role"] != "admin": return RedirectResponse("/",303)
    c=db(); users=c.execute("SELECT id,username,display_name,role FROM users ORDER BY username").fetchall(); c.close()
    return TEMPLATES.TemplateResponse("users.html", {"request":request,"user":u,"users":users})

@app.post("/users/create")
def users_create(request: Request, username:str=Form(...), display_name:str=Form(...), password:str=Form(...), role:str=Form("technician")):
    u=current_user(request)
    if not u or u["role"] != "admin": return RedirectResponse("/",303)
    username=username.strip(); display_name=display_name.strip(); role=role if role in ("admin","technician") else "technician"
    if not username or not display_name or not password: return RedirectResponse("/users?error=Bitte+alle+Felder+ausfüllen",303)
    c=db()
    try:
        c.execute("INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)",(username,hash_password(password),display_name,role)); c.commit()
    except sqlite3.IntegrityError:
        c.close(); return RedirectResponse("/users?error=Benutzername+bereits+vorhanden",303)
    c.close(); return RedirectResponse("/users?success=Benutzer+angelegt",303)

@app.post("/users/{uid}/delete")
def users_delete(request: Request, uid:int):
    u=current_user(request)
    if not u or u["role"] != "admin": return RedirectResponse("/",303)
    if uid == u["id"]: return RedirectResponse("/users?error=Eigener+Benutzer+kann+nicht+gelöscht+werden",303)
    c=db(); c.execute("DELETE FROM users WHERE id=?",(uid,)); c.commit(); c.close(); return RedirectResponse("/users?success=Benutzer+gelöscht",303)

@app.get("/api/houses")
def api_houses(request: Request):
    if not require_user(request): return {"error":"unauthorized"}
    return [{"code":code,"label":label} for code,label in active_houses(request)]

@app.get("/api/stations/{hauscode}")
def api_stations(request: Request, hauscode: str):
    if not require_user(request): return {"error":"unauthorized"}
    return active_stations(request, hauscode)

@app.get("/api/rooms/{hauscode}/{station_id}")
def api_rooms(request: Request, hauscode: str, station_id: str):
    if not require_user(request): return {"error":"unauthorized"}
    c=db(); row=c.execute("SELECT stationsbezeichnung FROM config_stations WHERE config_id=? AND hauscode=? AND station_id=?",(get_active_config_id(request),hauscode,station_id)).fetchone(); c.close()
    if not row: return []
    return get_rooms(hauscode,row["stationsbezeichnung"],request,station_id)

@app.get("/",response_class=HTMLResponse)
def home(request: Request):
    u=current_user(request)
    if not u:return RedirectResponse("/login",303)
    c=db(); maint=c.execute("""SELECT m.*,u.display_name,
        COUNT(res.id) AS total_rooms,
        SUM(CASE WHEN res.zt IS NOT NULL AND res.zl IS NOT NULL AND res.rt_b1 IS NOT NULL AND res.rt_b2 IS NOT NULL AND res.rt_b3 IS NOT NULL AND res.rt IS NOT NULL AND res.pt_bad IS NOT NULL AND res.rt_bad IS NOT NULL AND res.zt_bad IS NOT NULL AND res.at_bad IS NOT NULL THEN 1 ELSE 0 END) AS checked_rooms,
        SUM(CASE WHEN res.zt='NOK' OR res.zl='NOK' OR res.rt_b1='NOK' OR res.rt_b2='NOK' OR res.rt_b3='NOK' OR res.rt='NOK' OR res.rt_bad='NOK' OR res.pt_bad='NOK' OR res.zt_bad='NOK' OR res.at_bad='NOK' THEN 1 ELSE 0 END) AS nok_rooms
        FROM maintenances m JOIN users u ON u.id=m.technician_id LEFT JOIN results res ON res.maintenance_id=m.id
        GROUP BY m.id ORDER BY m.id DESC LIMIT 30""").fetchall(); c.close()
    houses=active_houses(request)
    return TEMPLATES.TemplateResponse("dashboard.html",{"request":request,"user":u,"maintenances":maint,"houses":houses,"house_count":len(houses),"is_admin":u["role"]=="admin","has_config":bool(get_active_config_id(request))})

@app.get("/login",response_class=HTMLResponse)
def login_page(request: Request): return TEMPLATES.TemplateResponse("login.html",{"request":request})

@app.post("/login")
def login(request: Request,username:str=Form(...),password:str=Form(...)):
    c=db();u=c.execute("SELECT * FROM users WHERE username=?",(username.strip(),)).fetchone();c.close()
    if not u or not verify_password(password,u["password_hash"]): return TEMPLATES.TemplateResponse("login.html",{"request":request,"error":"Benutzername oder Passwort falsch."})
    request.session.clear(); request.session["user_id"]=u["id"]; return RedirectResponse("/",303)

@app.get("/logout")
def logout(request: Request): request.session.clear();return RedirectResponse("/login",303)

@app.post("/maintenance/start")
def maintenance_start(request: Request,hauscode:str=Form(...),station_id:str=Form(...),inspection_year:int=Form(...),inspection_type:str=Form(...)):
    if not require_user(request):return RedirectResponse("/login",303)
    if not get_active_config_id(request): return RedirectResponse("/import?error=Bitte+zuerst+eine+VCIP-Datei+hochladen",303)
    c=db(); st=c.execute("SELECT stationsbezeichnung FROM config_stations WHERE config_id=? AND hauscode=? AND station_id=?",(get_active_config_id(request),hauscode.strip(),station_id.strip())).fetchone()
    c.close()
    if not st:return RedirectResponse("/?error=Station+nicht+gefunden",303)
    station=st["stationsbezeichnung"]
    rooms=get_rooms(hauscode.strip(),station,request,station_id.strip())
    if not rooms:return RedirectResponse("/?error=Keine+Zimmer+gefunden",303)
    if inspection_type not in INSPECTION_TITLES: return RedirectResponse("/?error=Ungültige+Art+der+Überprüfung",303)
    c=db(); now=datetime.now().isoformat(timespec="seconds"); u=current_user(request)
    cur=c.execute("INSERT INTO maintenances(hauscode,station,station_id,technician_id,inspector_name,inspection_year,inspection_type,created_at) VALUES(?,?,?,?,?,?,?,?)",(hauscode.strip(),station,station_id.strip(),u["id"],u["display_name"],inspection_year,inspection_type,now));mid=cur.lastrowid
    c.executemany("INSERT INTO results(maintenance_id,room_name,manual) VALUES(?,?,0)",[(mid,r) for r in rooms]);c.commit();c.close();return RedirectResponse(f"/maintenance/{mid}",303)

@app.get("/maintenance/{mid}",response_class=HTMLResponse)
def maintenance(request:Request,mid:int):
    if not require_user(request):return RedirectResponse("/login",303)
    c=db();m=c.execute("SELECT m.*,u.display_name FROM maintenances m JOIN users u ON u.id=m.technician_id WHERE m.id=?",(mid,)).fetchone()
    if not m:c.close();return RedirectResponse("/",303)
    rows=c.execute("SELECT * FROM results WHERE maintenance_id=? ORDER BY manual,room_name",(mid,)).fetchall();c.close()
    return TEMPLATES.TemplateResponse("maintenance.html",{"request":request,"user":current_user(request),"m":m,"rows":rows,"checks":CHECKS,"years":list(range(2026,2041))})

@app.post("/maintenance/{mid}/save")
async def maintenance_save(request:Request,mid:int):
    if not require_user(request):return RedirectResponse("/login",303)
    form=await request.form();c=db();exists=c.execute("SELECT id FROM maintenances WHERE id=?",(mid,)).fetchone()
    if not exists:c.close();return RedirectResponse("/",303)
    save_results_from_form(c,mid,form)
    inspector=(form.get("inspector_name") or "").strip();year=form.get("inspection_year") or None; inspection_type=(form.get("inspection_type") or "").strip()
    if inspection_type not in INSPECTION_TITLES: inspection_type="Wartung"
    c.execute("UPDATE maintenances SET inspector_name=?,inspection_year=?,inspection_type=? WHERE id=?",(inspector,year,inspection_type,mid));c.commit();c.close();return RedirectResponse(f"/maintenance/{mid}",303)

@app.post("/maintenance/{mid}/add-room")
def add_room(request:Request,mid:int,room_name:str=Form(...)):
    if not require_user(request):return RedirectResponse("/login",303)
    room_name=room_name.strip()
    if room_name:
        c=db();c.execute("INSERT INTO results(maintenance_id,room_name,manual) VALUES(?,?,1)",(mid,room_name));c.commit();c.close()
    return RedirectResponse(f"/maintenance/{mid}",303)

@app.post("/maintenance/{mid}/complete")
async def maintenance_complete(request:Request,mid:int):
    if not require_user(request):return RedirectResponse("/login",303)
    form=await request.form();sig=(form.get("signature") or "").strip();inspector=(form.get("inspector_name") or "").strip();year=form.get("inspection_year") or None; inspection_type=(form.get("inspection_type") or "").strip()
    if not sig or not sig.startswith("data:image"):
        return RedirectResponse(f"/maintenance/{mid}?error=Bitte+Unterschrift+setzen",303)
    c=db();exists=c.execute("SELECT id FROM maintenances WHERE id=?",(mid,)).fetchone()
    if not exists:c.close();return RedirectResponse("/",303)
    save_results_from_form(c,mid,form)
    completed=datetime.now().isoformat(timespec="seconds")
    if inspection_type not in INSPECTION_TITLES: inspection_type="Wartung"
    c.execute("UPDATE maintenances SET inspector_name=?,inspection_year=?,inspection_type=?,status='completed',completed_at=?,signature=? WHERE id=?",(inspector,year,inspection_type,completed,sig,mid));c.commit();c.close()
    pdf=make_pdf(mid);pdf_bytes=pdf.getvalue();filename=f"Zusammenfassung_Rufanlagenwartung_{mid}.pdf";path=PROTOCOL_DIR/filename;path.write_bytes(pdf_bytes)
    c=db();c.execute("UPDATE maintenances SET pdf_path=? WHERE id=?",(str(path),mid));c.commit();c.close()
    return RedirectResponse(f"/maintenance/{mid}/completed",303)

@app.get("/maintenance/{mid}/completed",response_class=HTMLResponse)
def maintenance_completed(request:Request,mid:int):
    if not require_user(request):return RedirectResponse("/login",303)
    c=db();m=c.execute("SELECT m.*,u.display_name FROM maintenances m JOIN users u ON u.id=m.technician_id WHERE m.id=?",(mid,)).fetchone();c.close()
    if not m:return RedirectResponse("/",303)
    return TEMPLATES.TemplateResponse("completed.html",{"request":request,"user":current_user(request),"m":m,"completed_date":format_date_de(m["completed_at"])})

@app.get("/maintenance/{mid}/pdf")
def maintenance_pdf(request:Request,mid:int):
    if not require_user(request):return RedirectResponse("/login",303)
    pdf=make_pdf(mid);return StreamingResponse(pdf,media_type="application/pdf",headers={"Content-Disposition":f'inline; filename="Zusammenfassung_Rufanlagenwartung_{mid}.pdf"'})
