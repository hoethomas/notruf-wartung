import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

BASE = Path(__file__).resolve().parent.parent
DB = BASE / "notruf.db"
MASTER_DATA = BASE / "master_data.json"
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
        display_name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS maintenances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hauscode TEXT NOT NULL,
        station TEXT NOT NULL,
        technician_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL,
        completed_at TEXT,
        signature TEXT,
        FOREIGN KEY(technician_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        maintenance_id INTEGER NOT NULL,
        room_name TEXT NOT NULL,
        zt TEXT, zl TEXT, rt_b1 TEXT, rt_b2 TEXT, rt_b3 TEXT, rt TEXT,
        rt_bad TEXT, pt_bad TEXT, zt_bad TEXT, at_bad TEXT,
        FOREIGN KEY(maintenance_id) REFERENCES maintenances(id)
    );
    """)
    # Migration für bestehende Test-Datenbanken
    cols = {row[1] for row in c.execute("PRAGMA table_info(results)").fetchall()}
    if "rt" not in cols:
        c.execute("ALTER TABLE results ADD COLUMN rt TEXT")
    user = c.execute("SELECT id FROM users LIMIT 1").fetchone()
    if not user:
        c.execute("INSERT INTO users(username,password_hash,display_name) VALUES(?,?,?)",
                  ("admin", hash_password("admin123"), "Administrator"))
    c.commit()
    c.close()


init_db()


def current_user(request):
    uid = request.session.get("user_id")
    if not uid:
        return None
    c = db()
    u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    c.close()
    return u


def require_user(request):
    return current_user(request)


def load_master_data():
    if not MASTER_DATA.exists():
        return []
    try:
        raw = json.loads(MASTER_DATA.read_text(encoding="utf-8"))
        clean = []
        for r in raw:
            if not r.get("hauscode") or not r.get("stationsbezeichnung") or not r.get("zimmerbezeichnung"):
                continue
            clean.append({
                "hauscode": str(r["hauscode"]).strip(),
                "stationsbezeichnung": str(r["stationsbezeichnung"]).strip(),
                "zimmerbezeichnung": str(r["zimmerbezeichnung"]).strip(),
            })
        return clean
    except Exception:
        return []


def get_rooms(hauscode, station):
    return sorted({r["zimmerbezeichnung"] for r in load_master_data()
                   if r["hauscode"] == hauscode and r["stationsbezeichnung"] == station})


@app.get("/api/houses")
def api_houses(request: Request):
    if not require_user(request):
        return {"error": "unauthorized"}
    return sorted({r["hauscode"] for r in load_master_data()})


@app.get("/api/stations/{hauscode}")
def api_stations(request: Request, hauscode: str):
    if not require_user(request):
        return {"error": "unauthorized"}
    return sorted({r["stationsbezeichnung"] for r in load_master_data() if r["hauscode"] == hauscode})


@app.get("/api/rooms/{hauscode}/{station}")
def api_rooms(request: Request, hauscode: str, station: str):
    if not require_user(request):
        return {"error": "unauthorized"}
    return get_rooms(hauscode, station)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", 303)
    c = db()
    maint = c.execute("""
        SELECT m.*, u.display_name,
               COUNT(res.id) AS room_count,
               SUM(CASE WHEN res.zt='NOK' OR res.zl='NOK' OR res.rt_b1='NOK' OR res.rt_b2='NOK'
                         OR res.rt_b3='NOK' OR res.rt='NOK' OR res.rt_bad='NOK' OR res.pt_bad='NOK'
                         OR res.zt_bad='NOK' OR res.at_bad='NOK' THEN 1 ELSE 0 END) AS nok_rooms
        FROM maintenances m
        JOIN users u ON u.id=m.technician_id
        LEFT JOIN results res ON res.maintenance_id=m.id
        GROUP BY m.id
        ORDER BY m.id DESC LIMIT 30
    """).fetchall()
    c.close()
    return TEMPLATES.TemplateResponse("dashboard.html", {
        "request": request, "user": u, "maintenances": maint,
        "houses": sorted({r["hauscode"] for r in load_master_data()}),
        "house_count": len({r["hauscode"] for r in load_master_data()}),
    })


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return TEMPLATES.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    c = db()
    u = c.execute("SELECT * FROM users WHERE username=?", (username.strip(),)).fetchone()
    c.close()
    if not u or not verify_password(password, u["password_hash"]):
        return TEMPLATES.TemplateResponse("login.html", {"request": request, "error": "Benutzername oder Passwort falsch."})
    request.session["user_id"] = u["id"]
    return RedirectResponse("/", 303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", 303)


@app.post("/maintenance/start")
def maintenance_start(request: Request, hauscode: str = Form(...), station: str = Form(...)):
    if not require_user(request):
        return RedirectResponse("/login", 303)
    hauscode = hauscode.strip()
    station = station.strip()
    rooms = get_rooms(hauscode, station)
    if not rooms:
        return RedirectResponse("/?error=Keine+Zimmer+gefunden", 303)
    c = db()
    cur = c.execute("""
        INSERT INTO maintenances(hauscode,station,technician_id,created_at)
        VALUES(?,?,?,?)
    """, (hauscode, station, current_user(request)["id"], datetime.now().isoformat(timespec="seconds")))
    mid = cur.lastrowid
    c.executemany("INSERT INTO results(maintenance_id,room_name) VALUES(?,?)", [(mid, r) for r in rooms])
    c.commit(); c.close()
    return RedirectResponse(f"/maintenance/{mid}", 303)


@app.get("/maintenance/{mid}", response_class=HTMLResponse)
def maintenance(request: Request, mid: int):
    if not require_user(request):
        return RedirectResponse("/login", 303)
    c = db()
    m = c.execute("""SELECT m.*,u.display_name FROM maintenances m
                     JOIN users u ON u.id=m.technician_id WHERE m.id=?""", (mid,)).fetchone()
    if not m:
        c.close()
        return RedirectResponse("/", 303)
    rows = c.execute("SELECT * FROM results WHERE maintenance_id=? ORDER BY room_name", (mid,)).fetchall()
    c.close()
    return TEMPLATES.TemplateResponse("maintenance.html", {
        "request": request, "user": current_user(request), "m": m, "rows": rows, "checks": CHECKS
    })


@app.post("/maintenance/{mid}/save")
async def maintenance_save(request: Request, mid: int):
    if not require_user(request):
        return RedirectResponse("/login", 303)
    form = await request.form()
    c = db()
    exists = c.execute("SELECT id FROM maintenances WHERE id=?", (mid,)).fetchone()
    if not exists:
        c.close(); return RedirectResponse("/", 303)
    for row in c.execute("SELECT id FROM results WHERE maintenance_id=?", (mid,)).fetchall():
        rid = row["id"]
        vals = [form.get(f"{key}_{rid}") for key, _, _ in CHECKS]
        c.execute("""UPDATE results SET zt=?,zl=?,rt_b1=?,rt_b2=?,rt_b3=?,rt=?,pt_bad=?,rt_bad=?,zt_bad=?,at_bad=? WHERE id=?""",
                  (*vals, rid))
    c.commit(); c.close()
    return RedirectResponse(f"/maintenance/{mid}", 303)


@app.post("/maintenance/{mid}/complete")
async def maintenance_complete(request: Request, mid: int):
    if not require_user(request):
        return RedirectResponse("/login", 303)
    form = await request.form()
    sig = form.get("signature", "")
    c = db()
    c.execute("UPDATE maintenances SET status='completed', completed_at=?, signature=? WHERE id=?",
              (datetime.now().isoformat(timespec="seconds"), sig, mid))
    c.commit(); c.close()
    return RedirectResponse(f"/maintenance/{mid}/pdf", 303)


def room_applicable(room_name: str, key: str) -> bool:
    """Abbild der grauen/nicht relevanten Felder aus dem VDE-Muster."""
    name = (room_name or "").strip().lower()
    if "dienstzimmer" in name:
        return key in {"zt", "zl"}
    if "stationsbad" in name:
        return key in {"zt", "zl", "pt_bad", "rt_bad", "zt_bad"}
    # Standard: Patienten-/Bettenzimmer
    return key not in {"rt_b3", "pt_bad"}


def make_pdf(mid):
    c = db()
    m = c.execute("""SELECT m.*,u.display_name FROM maintenances m
                     JOIN users u ON u.id=m.technician_id WHERE m.id=?""", (mid,)).fetchone()
    rows = c.execute("SELECT * FROM results WHERE maintenance_id=? ORDER BY room_name", (mid,)).fetchall()
    c.close()
    if not m:
        raise ValueError("Wartung nicht gefunden")

    out = io.BytesIO()
    # Das Originalmuster ist ein einseitiges Hochformat-A4-Formular.
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=10*mm, leftMargin=10*mm,
                            topMargin=8*mm, bottomMargin=8*mm)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("protocol_title", parent=styles["Normal"], fontName="Helvetica-Bold",
                           fontSize=12, leading=14, alignment=1, spaceAfter=0)
    small = ParagraphStyle("protocol_small", parent=styles["Normal"], fontSize=6.5, leading=7.5)
    tiny = ParagraphStyle("protocol_tiny", parent=styles["Normal"], fontSize=6, leading=6.8)
    center = ParagraphStyle("protocol_center", parent=small, alignment=1)

    # Kopfzeile wie im Muster: links Hauscode, rechts Station.
    header = Table([
        [Paragraph("Inspektion von Rufanlagen nach DIN VDE 0834 Ziffer 11.2", title), ""],
        [Paragraph(f"<b>{m['hauscode']}</b>", center), Paragraph(f"<b>Station:</b> {m['station']}", center)],
    ], colWidths=[90*mm, 90*mm], rowHeights=[10*mm, 10*mm])
    header.setStyle(TableStyle([
        ("SPAN", (0,0), (-1,0)),
        ("GRID", (0,0), (-1,-1), 0.6, colors.black),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))

    headers = ["Raum Nr.", "Bezeichnung"] + [x[1] for x in CHECKS] + ["o.k."]
    data = [headers]
    noks = []
    for idx, r in enumerate(rows, start=1):
        line = [str(idx), r["room_name"]]
        row_has_nok = False
        for key, label, _ in CHECKS:
            val = r[key]
            if not room_applicable(r["room_name"], key):
                line.append("")
            else:
                line.append("✓" if val == "OK" else ("NOK" if val == "NOK" else ("n.a." if val == "NF" else "")))
                if val == "NOK":
                    row_has_nok = True
                    noks.append(f"{idx} – {r['room_name']} – {label}")
        line.append("NOK" if row_has_nok else ("✓" if all((not room_applicable(r['room_name'], k) or r[k] == "OK") for k,_,_ in CHECKS) else ""))
        data.append(line)

    col_widths = [14*mm, 37*mm] + [11.5*mm]*len(CHECKS) + [10*mm]
    table = Table(data, repeatRows=1, colWidths=col_widths, hAlign="CENTER")
    ts = [
        ("GRID", (0,0), (-1,-1), 0.45, colors.black),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eeeeee")),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 6.2),
        ("FONTSIZE", (0,1), (-1,-1), 6.2),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("ALIGN", (1,1), (1,-1), "LEFT"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.white]),
    ]
    # Graue/nicht auszuführende Felder wie im Muster.
    for row_i, r in enumerate(rows, start=1):
        for check_i, (key, _, _) in enumerate(CHECKS, start=2):
            if not room_applicable(r["room_name"], key):
                ts.append(("BACKGROUND", (check_i,row_i), (check_i,row_i), colors.HexColor("#bdbdbd")))
    table.setStyle(TableStyle(ts))

    # Legende und Unterschriftsbereich entsprechend dem Muster.
    legend = Table([[Paragraph(
        "ZT = Zimmerterminal, ZL = Zimmerleuchte, RT B1 = Ruftaster Bett 1, "
        "RT B2 = Ruftaster Bett 2, RT B3 = Ruftaster Bett 3, RT = Ruftaster, "
        "PT Bad = Pneumatischer Taster, RT Bad = Ruftaster im Bad, "
        "ZT Bad = Zugtaster im Bad, AT Bad = Abstelltaster im Bad, o.k. = ohne Beanstandung",
        tiny)]], colWidths=[180*mm])
    legend.setStyle(TableStyle([("BOX",(0,0),(-1,-1),0.6,colors.black),("LEFTPADDING",(0,0),(-1,-1),2),("RIGHTPADDING",(0,0),(-1,-1),2)]))

    notes = Table([
        [Paragraph("<b>Name des Prüfers:</b>", small), Paragraph("<b>Datum und Unterschrift:</b>", small)],
        [Paragraph("*1 mech. defekt &nbsp;&nbsp;&nbsp;&nbsp; *6 Ruf löst nicht aus &nbsp;&nbsp;&nbsp;&nbsp; *11 keine Sprechverbind.<br/>"
                   "*2 Taste klemmt &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *7 rote Leuchte defekt &nbsp;&nbsp;&nbsp;&nbsp; *12 ZT-Schnur fehlerhaft<br/>"
                   "*3 AW Anzeige defekt &nbsp;&nbsp; *8 grüne Leuchte defekt<br/>"
                   "*4 BL defekt &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *9 weiße Leuchte defekt<br/>"
                   "*5 Rufnachsendung &nbsp;&nbsp;&nbsp;&nbsp; *10 gelbe Leuchte defekt", tiny), ""]
    ], colWidths=[110*mm, 70*mm], rowHeights=[7*mm, 23*mm])
    notes.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),0.6,colors.black),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("LEFTPADDING",(0,0),(-1,-1),2), ("TOPPADDING",(0,0),(-1,-1),2)
    ]))

    story = [header, Spacer(1, 2*mm), table, Spacer(1, 2*mm), legend, Spacer(1, 2*mm)]
    if noks:
        story.append(Paragraph("<b>Beanstandungen:</b> " + " | ".join(noks), tiny))
        story.append(Spacer(1, 1*mm))
    if m["signature"] and m["signature"].startswith("data:image"):
        try:
            raw = base64.b64decode(m["signature"].split(",",1)[1])
            sig_img = Image(io.BytesIO(raw), width=45*mm, height=15*mm)
            notes._cellvalues[1][1] = sig_img
        except Exception:
            pass
    story.append(notes)
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph(f"Wartung begonnen: {m['created_at']} &nbsp;&nbsp;&nbsp; abgeschlossen: {m['completed_at'] or ''} &nbsp;&nbsp;&nbsp; Prüfer: {m['display_name']}", tiny))
    doc.build(story)
    out.seek(0)
    return out


@app.get("/maintenance/{mid}/pdf")
def maintenance_pdf(request: Request, mid: int):
    if not require_user(request):
        return RedirectResponse("/login", 303)
    pdf = make_pdf(mid)
    return StreamingResponse(pdf, media_type="application/pdf",
                             headers={"Content-Disposition": f'inline; filename="Wartungsprotokoll_{mid}.pdf"'})
