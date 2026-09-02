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
    ("rt_bad", "RT Bad", ["OK", "NOK", "NF"]),
    ("pt_bad", "PT Bad", ["OK", "NOK", "NF"]),
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
        zt TEXT, zl TEXT, rt_b1 TEXT, rt_b2 TEXT, rt_b3 TEXT,
        rt_bad TEXT, pt_bad TEXT, zt_bad TEXT, at_bad TEXT,
        FOREIGN KEY(maintenance_id) REFERENCES maintenances(id)
    );
    """)
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
                         OR res.rt_b3='NOK' OR res.rt_bad='NOK' OR res.pt_bad='NOK'
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
        c.execute("""UPDATE results SET zt=?,zl=?,rt_b1=?,rt_b2=?,rt_b3=?,rt_bad=?,pt_bad=?,zt_bad=?,at_bad=? WHERE id=?""",
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


def make_pdf(mid):
    c = db()
    m = c.execute("""SELECT m.*,u.display_name FROM maintenances m
                     JOIN users u ON u.id=m.technician_id WHERE m.id=?""", (mid,)).fetchone()
    rows = c.execute("SELECT * FROM results WHERE maintenance_id=? ORDER BY room_name", (mid,)).fetchall()
    c.close()
    if not m:
        raise ValueError("Wartung nicht gefunden")

    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=landscape(A4), rightMargin=8*mm,leftMargin=8*mm,topMargin=8*mm,bottomMargin=8*mm)
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=7, leading=8)
    story = [
        Paragraph("WARTUNGSPROTOKOLL – NOTRUFANLAGE", styles["Title"]),
        Paragraph(f"<b>Haus:</b> {m['hauscode']} &nbsp;&nbsp; <b>Station:</b> {m['station']}", styles["Normal"]),
        Paragraph(f"<b>Techniker:</b> {m['display_name']} &nbsp;&nbsp; <b>Wartungsbeginn:</b> {m['created_at']} &nbsp;&nbsp; <b>Status:</b> {m['status']}", styles["Normal"]),
        Spacer(1, 5*mm)
    ]
    headers = ["Zimmer"] + [x[1] for x in CHECKS]
    data = [headers]
    labels = {"OK":"OK", "NOK":"NOK", "NF":"nicht ausgeführt", None:""}
    noks=[]
    for r in rows:
        line=[r["room_name"]]
        for key,label,_ in CHECKS:
            val=r[key]
            line.append(labels.get(val,val or ""))
            if val=="NOK":
                noks.append(f"Zimmer {r['room_name']} – {label}")
        data.append(line)
    table = Table(data, repeatRows=1, colWidths=[40*mm]+[21*mm]*len(CHECKS))
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1f2937")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),6),
        ("GRID",(0,0),(-1,-1),0.3,colors.grey),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("ALIGN",(1,1),(-1,-1),"CENTER"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    story.append(table)
    story.append(Spacer(1,5*mm))
    story.append(Paragraph(f"<b>Beanstandungen (NOK):</b> {len(noks)}", styles["Heading2"]))
    for n in noks:
        story.append(Paragraph("• " + n, small))
    story.append(Spacer(1,5*mm))
    story.append(Paragraph("Techniker-Unterschrift:", styles["Heading2"]))
    if m["signature"] and m["signature"].startswith("data:image"):
        try:
            raw = base64.b64decode(m["signature"].split(",",1)[1])
            story.append(Image(io.BytesIO(raw), width=55*mm, height=20*mm))
        except Exception:
            story.append(Paragraph("Unterschrift konnte nicht eingebettet werden.", small))
    story.append(Paragraph(f"Erstellt/abgeschlossen: {m['completed_at'] or ''}", small))
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
