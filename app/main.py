import base64
import io
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from passlib.hash import bcrypt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image

BASE = Path(__file__).resolve().parent.parent
DB = BASE / "notruf.db"
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

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS facilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        number TEXT UNIQUE NOT NULL,
        house_name TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS stations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        facility_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        FOREIGN KEY(facility_id) REFERENCES facilities(id)
    );
    CREATE TABLE IF NOT EXISTS rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        station_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        FOREIGN KEY(station_id) REFERENCES stations(id)
    );
    CREATE TABLE IF NOT EXISTS maintenances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        facility_id INTEGER NOT NULL,
        technician_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL,
        completed_at TEXT,
        signature TEXT,
        FOREIGN KEY(facility_id) REFERENCES facilities(id),
        FOREIGN KEY(technician_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        maintenance_id INTEGER NOT NULL,
        room_id INTEGER NOT NULL,
        zt TEXT, zl TEXT, rt_b1 TEXT, rt_b2 TEXT, rt_b3 TEXT,
        rt_bad TEXT, pt_bad TEXT, zt_bad TEXT, at_bad TEXT,
        FOREIGN KEY(maintenance_id) REFERENCES maintenances(id),
        FOREIGN KEY(room_id) REFERENCES rooms(id)
    );
    """)
    user = c.execute("SELECT id FROM users LIMIT 1").fetchone()
    if not user:
        c.execute("INSERT INTO users(username,password_hash,display_name) VALUES(?,?,?)",
                  ("admin", bcrypt.hash("admin123"), "Administrator"))
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

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    u = current_user(request)
    if not u:
        return RedirectResponse("/login", 303)
    c = db()
    facilities = c.execute("""
        SELECT f.*, COUNT(DISTINCT m.id) AS maintenance_count
        FROM facilities f LEFT JOIN maintenances m ON m.facility_id=f.id
        GROUP BY f.id ORDER BY f.house_name
    """).fetchall()
    maint = c.execute("""
        SELECT m.*, f.number, f.house_name, u.display_name
        FROM maintenances m JOIN facilities f ON f.id=m.facility_id
        JOIN users u ON u.id=m.technician_id
        ORDER BY m.id DESC LIMIT 20
    """).fetchall()
    c.close()
    return TEMPLATES.TemplateResponse("dashboard.html", {"request": request, "user": u, "facilities": facilities, "maintenances": maint})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return TEMPLATES.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    c = db()
    u = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    c.close()
    if not u or not bcrypt.verify(password, u["password_hash"]):
        return TEMPLATES.TemplateResponse("login.html", {"request": request, "error": "Benutzername oder Passwort falsch."})
    request.session["user_id"] = u["id"]
    return RedirectResponse("/", 303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", 303)

@app.get("/facility/new", response_class=HTMLResponse)
def facility_new(request: Request):
    if not require_user(request): return RedirectResponse("/login", 303)
    return TEMPLATES.TemplateResponse("facility_new.html", {"request": request, "user": current_user(request)})

@app.post("/facility/new")
def facility_create(request: Request, number: str = Form(...), house_name: str = Form(...), station_name: str = Form(...)):
    if not require_user(request): return RedirectResponse("/login", 303)
    c = db()
    try:
        cur = c.execute("INSERT INTO facilities(number,house_name,created_at) VALUES(?,?,?)",
                         (number.strip(), house_name.strip(), datetime.now().isoformat(timespec="seconds")))
        fid = cur.lastrowid
        c.execute("INSERT INTO stations(facility_id,name) VALUES(?,?)", (fid, station_name.strip()))
        c.commit()
    except sqlite3.IntegrityError:
        c.close()
        return TEMPLATES.TemplateResponse("facility_new.html", {"request": request, "user": current_user(request), "error": "Diese Anlagennummer existiert bereits."})
    c.close()
    return RedirectResponse(f"/facility/{fid}", 303)

@app.get("/facility/{fid}", response_class=HTMLResponse)
def facility_detail(request: Request, fid: int):
    if not require_user(request): return RedirectResponse("/login", 303)
    c = db()
    f = c.execute("SELECT * FROM facilities WHERE id=?", (fid,)).fetchone()
    stations = c.execute("SELECT * FROM stations WHERE facility_id=? ORDER BY name", (fid,)).fetchall()
    rooms = c.execute("""SELECT r.*, s.name station_name FROM rooms r JOIN stations s ON s.id=r.station_id
                         WHERE s.facility_id=? ORDER BY s.name,r.name""", (fid,)).fetchall()
    c.close()
    return TEMPLATES.TemplateResponse("facility.html", {"request": request, "user": current_user(request), "facility": f, "stations": stations, "rooms": rooms})

@app.post("/station/{sid}/room")
def room_create(request: Request, sid: int, name: str = Form(...)):
    if not require_user(request): return RedirectResponse("/login", 303)
    c = db()
    c.execute("INSERT INTO rooms(station_id,name) VALUES(?,?)", (sid, name.strip()))
    c.commit()
    fid = c.execute("SELECT facility_id FROM stations WHERE id=?", (sid,)).fetchone()["facility_id"]
    c.close()
    return RedirectResponse(f"/facility/{fid}", 303)

@app.post("/station")
def station_create(request: Request, facility_id: int = Form(...), name: str = Form(...)):
    if not require_user(request): return RedirectResponse("/login", 303)
    c = db()
    c.execute("INSERT INTO stations(facility_id,name) VALUES(?,?)", (facility_id, name.strip()))
    c.commit(); c.close()
    return RedirectResponse(f"/facility/{facility_id}", 303)

@app.get("/maintenance/new/{fid}")
def maintenance_new(request: Request, fid: int):
    if not require_user(request): return RedirectResponse("/login", 303)
    c = db()
    m = c.execute("INSERT INTO maintenances(facility_id,technician_id,created_at) VALUES(?,?,?)",
                  (fid, current_user(request)["id"], datetime.now().isoformat(timespec="seconds"))).lastrowid
    c.execute("""INSERT INTO results(maintenance_id,room_id) SELECT ?,r.id
                 FROM rooms r JOIN stations s ON s.id=r.station_id WHERE s.facility_id=?""", (m, fid))
    c.commit(); c.close()
    return RedirectResponse(f"/maintenance/{m}", 303)

@app.get("/maintenance/{mid}", response_class=HTMLResponse)
def maintenance(request: Request, mid: int):
    if not require_user(request): return RedirectResponse("/login", 303)
    c = db()
    m = c.execute("""SELECT m.*, f.number,f.house_name,u.display_name
                     FROM maintenances m JOIN facilities f ON f.id=m.facility_id
                     JOIN users u ON u.id=m.technician_id WHERE m.id=?""", (mid,)).fetchone()
    rows = c.execute("""SELECT r.id room_id,r.name room_name,s.name station_name,res.*
                        FROM results res JOIN rooms r ON r.id=res.room_id
                        JOIN stations s ON s.id=r.station_id
                        WHERE res.maintenance_id=? ORDER BY s.name,r.name""", (mid,)).fetchall()
    c.close()
    return TEMPLATES.TemplateResponse("maintenance.html", {"request": request, "user": current_user(request), "m": m, "rows": rows, "checks": CHECKS})

@app.post("/maintenance/{mid}/save")
async def maintenance_save(request: Request, mid: int):
    if not require_user(request): return RedirectResponse("/login", 303)
    form = await request.form()
    c = db()
    for row in c.execute("SELECT id FROM results WHERE maintenance_id=?", (mid,)).fetchall():
        rid = row["id"]
        vals = [form.get(f"{key}_{rid}") for key,_,_ in CHECKS]
        c.execute("""UPDATE results SET zt=?,zl=?,rt_b1=?,rt_b2=?,rt_b3=?,rt_bad=?,pt_bad=?,zt_bad=?,at_bad=? WHERE id=?""",
                  (*vals, rid))
    c.commit(); c.close()
    return RedirectResponse(f"/maintenance/{mid}", 303)

@app.post("/maintenance/{mid}/complete")
async def maintenance_complete(request: Request, mid: int):
    if not require_user(request): return RedirectResponse("/login", 303)
    form = await request.form()
    sig = form.get("signature", "")
    c = db()
    c.execute("UPDATE maintenances SET status='completed', completed_at=?, signature=? WHERE id=?",
              (datetime.now().isoformat(timespec="seconds"), sig, mid))
    c.commit(); c.close()
    return RedirectResponse(f"/maintenance/{mid}/pdf", 303)

def make_pdf(mid):
    c = db()
    m = c.execute("""SELECT m.*,f.number,f.house_name,u.display_name FROM maintenances m
                     JOIN facilities f ON f.id=m.facility_id JOIN users u ON u.id=m.technician_id
                     WHERE m.id=?""", (mid,)).fetchone()
    rows = c.execute("""SELECT r.name room_name,s.name station_name,res.* FROM results res
                        JOIN rooms r ON r.id=res.room_id JOIN stations s ON s.id=r.station_id
                        WHERE res.maintenance_id=? ORDER BY s.name,r.name""", (mid,)).fetchall()
    c.close()

    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=landscape(A4), rightMargin=8*mm,leftMargin=8*mm,topMargin=8*mm,bottomMargin=8*mm)
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=7, leading=8)
    story = [
        Paragraph("WARTUNGSPROTOKOLL – NOTRUFANLAGE", styles["Title"]),
        Paragraph(f"<b>Anlagennummer:</b> {m['number']} &nbsp;&nbsp; <b>Haus:</b> {m['house_name']}", styles["Normal"]),
        Paragraph(f"<b>Techniker:</b> {m['display_name']} &nbsp;&nbsp; <b>Wartungsbeginn:</b> {m['created_at']} &nbsp;&nbsp; <b>Status:</b> {m['status']}", styles["Normal"]),
        Spacer(1, 5*mm)
    ]
    headers = ["Station","Zimmer"] + [x[1] for x in CHECKS]
    data = [headers]
    labels = {"OK":"OK","NOK":"NOK","NF":"n. ausgeführt",None:""}
    noks=[]
    for r in rows:
        line=[r["station_name"], r["room_name"]]
        for key,label,_ in CHECKS:
            val=r[key]
            line.append(labels.get(val,val or ""))
            if val=="NOK":
                noks.append(f"{r['station_name']} / Zimmer {r['room_name']} – {label}")
        data.append(line)
    table = Table(data, repeatRows=1, colWidths=[28*mm,22*mm]+[21*mm]*len(CHECKS))
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1f2937")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),6),
        ("GRID",(0,0),(-1,-1),0.3,colors.grey),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("ALIGN",(2,1),(-1,-1),"CENTER"),
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
            img = Image(io.BytesIO(raw), width=55*mm, height=20*mm)
            story.append(img)
        except Exception:
            story.append(Paragraph("Unterschrift konnte nicht eingebettet werden.", small))
    story.append(Paragraph(f"Erstellt/abgeschlossen: {m['completed_at'] or ''}", small))
    doc.build(story)
    out.seek(0)
    return out

@app.get("/maintenance/{mid}/pdf")
def maintenance_pdf(request: Request, mid: int):
    if not require_user(request): return RedirectResponse("/login", 303)
    pdf = make_pdf(mid)
    return StreamingResponse(pdf, media_type="application/pdf",
                             headers={"Content-Disposition": f'inline; filename="Wartungsprotokoll_{mid}.pdf"'})
