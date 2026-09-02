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

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

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
        display_name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS maintenances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hauscode TEXT NOT NULL,
        station TEXT NOT NULL,
        technician_id INTEGER NOT NULL,
        inspector_name TEXT,
        inspection_year INTEGER,
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
    for col, definition in [
        ("inspector_name", "TEXT"), ("inspection_year", "INTEGER"), ("email_address", "TEXT"),
        ("email_sent_at", "TEXT"), ("email_error", "TEXT"), ("pdf_path", "TEXT")]:
        add_col("maintenances", col, definition)
    add_col("results", "manual", "INTEGER NOT NULL DEFAULT 0")
    add_col("results", "rt", "TEXT")
    add_col("results", "issue_details", "TEXT")
    user = c.execute("SELECT id FROM users LIMIT 1").fetchone()
    if not user:
        c.execute("INSERT INTO users(username,password_hash,display_name) VALUES(?,?,?)",
                  ("admin", hash_password("admin123"), "Administrator"))
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
    if not MASTER_DATA.exists(): return []
    try:
        raw = json.loads(MASTER_DATA.read_text(encoding="utf-8")); clean=[]
        for r in raw:
            if not r.get("hauscode") or not r.get("stationsbezeichnung") or not r.get("zimmerbezeichnung"): continue
            clean.append({"hauscode": str(r["hauscode"]).strip(), "stationsbezeichnung": str(r["stationsbezeichnung"]).strip(), "zimmerbezeichnung": str(r["zimmerbezeichnung"]).strip()})
        return clean
    except Exception:
        return []


def get_rooms(hauscode, station):
    return sorted({r["zimmerbezeichnung"] for r in load_master_data() if r["hauscode"] == hauscode and r["stationsbezeichnung"] == station})


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

    title_block = [Paragraph("Zusammenfassung der Rufanlagenwartung", title), Paragraph("Dies ist nicht das offizielle Wartungsprotokoll. Das Wartungsprotokoll erhalten Sie separat.", subtitle)]
    header = Table([
        [title_block, ""],
        [Paragraph(f"<b>Haus:</b> {m['hauscode']}", center), Paragraph(f"<b>Station:</b> {m['station']}", center)],
        [Paragraph(f"<b>Überprüfung für das Jahr:</b> {m['inspection_year'] or ''}", center), Paragraph(f"<b>Prüfer:</b> {m['inspector_name'] or m['display_name'] or ''}", center)],
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
        [Paragraph("<font color='#64748b'><b>—</b></font>", ParagraphStyle("lgnf", parent=center, fontSize=11, leading=11)), Paragraph("<b>nicht ausgeführt</b> – Prüfung nicht durchgeführt", small)],
    ]
    legend_table=Table(legend_cells, colWidths=[12*mm,186*mm])
    legend_table.setStyle(TableStyle([
        ("BOX",(0,0),(-1,-1),0.6,colors.black),("INNERGRID",(0,0),(-1,-1),0.3,colors.black),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(0,0),(0,-1),"CENTER"),
        ("BACKGROUND",(0,0),(0,0),colors.HexColor("#dcfce7")),
        ("BACKGROUND",(0,1),(0,1),colors.HexColor("#fee2e2")),
        ("BACKGROUND",(0,2),(0,2),colors.HexColor("#e2e8f0")),
        ("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),2.5),("BOTTOMPADDING",(0,0),(-1,-1),2.5)
    ]))
    legend_box=Table([[legend_title],[legend_table]],colWidths=[198*mm])
    legend_box.setStyle(TableStyle([("BOX",(0,0),(-1,-1),0.6,colors.black),("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eeeeee")),("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
    story.append(legend_box); story.append(Spacer(1,3*mm))

    sig_img=""
    if m["signature"] and m["signature"].startswith("data:image"):
        try:
            raw=base64.b64decode(m["signature"].split(",",1)[1]); sig_img=Image(io.BytesIO(raw),width=55*mm,height=18*mm)
        except Exception: pass
    completed=m["completed_at"] or ""
    notes=Table([
        [Paragraph("<b>Name des Prüfers:</b>",small),Paragraph("<b>Unterschrift:</b>",small)],
        [Paragraph(str(m["inspector_name"] or m["display_name"] or ""),small),sig_img],
        [Paragraph(f"<b>Abschlussdatum:</b> {completed}",small),Paragraph("",small)],
    ],colWidths=[99*mm,99*mm],rowHeights=[7*mm,22*mm,12*mm])
    notes.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.6,colors.black),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3)])); story.append(notes)
    doc.build(story); out.seek(0); return out



@app.get("/api/houses")
def api_houses(request: Request):
    if not require_user(request): return {"error":"unauthorized"}
    return sorted({r["hauscode"] for r in load_master_data()})

@app.get("/api/stations/{hauscode}")
def api_stations(request: Request, hauscode: str):
    if not require_user(request): return {"error":"unauthorized"}
    return sorted({r["stationsbezeichnung"] for r in load_master_data() if r["hauscode"]==hauscode})

@app.get("/api/rooms/{hauscode}/{station}")
def api_rooms(request: Request, hauscode: str, station: str):
    if not require_user(request): return {"error":"unauthorized"}
    return get_rooms(hauscode,station)

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
    return TEMPLATES.TemplateResponse("dashboard.html",{"request":request,"user":u,"maintenances":maint,"houses":sorted({r["hauscode"] for r in load_master_data()}),"house_count":len({r["hauscode"] for r in load_master_data()})})

@app.get("/login",response_class=HTMLResponse)
def login_page(request: Request): return TEMPLATES.TemplateResponse("login.html",{"request":request})

@app.post("/login")
def login(request: Request,username:str=Form(...),password:str=Form(...)):
    c=db();u=c.execute("SELECT * FROM users WHERE username=?",(username.strip(),)).fetchone();c.close()
    if not u or not verify_password(password,u["password_hash"]): return TEMPLATES.TemplateResponse("login.html",{"request":request,"error":"Benutzername oder Passwort falsch."})
    request.session["user_id"]=u["id"];return RedirectResponse("/",303)

@app.get("/logout")
def logout(request: Request): request.session.clear();return RedirectResponse("/login",303)

@app.post("/maintenance/start")
def maintenance_start(request: Request,hauscode:str=Form(...),station:str=Form(...),inspection_year:int=Form(...)):
    if not require_user(request):return RedirectResponse("/login",303)
    rooms=get_rooms(hauscode.strip(),station.strip())
    if not rooms:return RedirectResponse("/?error=Keine+Zimmer+gefunden",303)
    c=db(); now=datetime.now().isoformat(timespec="seconds"); u=current_user(request)
    cur=c.execute("INSERT INTO maintenances(hauscode,station,technician_id,inspector_name,inspection_year,created_at) VALUES(?,?,?,?,?,?)",(hauscode.strip(),station.strip(),u["id"],u["display_name"],inspection_year,now));mid=cur.lastrowid
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
    inspector=(form.get("inspector_name") or "").strip();year=form.get("inspection_year") or None
    c.execute("UPDATE maintenances SET inspector_name=?,inspection_year=? WHERE id=?",(inspector,year,mid));c.commit();c.close();return RedirectResponse(f"/maintenance/{mid}",303)

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
    form=await request.form();sig=(form.get("signature") or "").strip();inspector=(form.get("inspector_name") or "").strip();year=form.get("inspection_year") or None
    if not sig or not sig.startswith("data:image"):
        return RedirectResponse(f"/maintenance/{mid}?error=Bitte+Unterschrift+setzen",303)
    c=db();exists=c.execute("SELECT id FROM maintenances WHERE id=?",(mid,)).fetchone()
    if not exists:c.close();return RedirectResponse("/",303)
    save_results_from_form(c,mid,form)
    completed=datetime.now().isoformat(timespec="seconds")
    c.execute("UPDATE maintenances SET inspector_name=?,inspection_year=?,status='completed',completed_at=?,signature=? WHERE id=?",(inspector,year,completed,sig,mid));c.commit();c.close()
    pdf=make_pdf(mid);pdf_bytes=pdf.getvalue();filename=f"Zusammenfassung_Rufanlagenwartung_{mid}.pdf";path=PROTOCOL_DIR/filename;path.write_bytes(pdf_bytes)
    c=db();c.execute("UPDATE maintenances SET pdf_path=? WHERE id=?",(str(path),mid));c.commit();c.close()
    return RedirectResponse(f"/maintenance/{mid}/completed",303)

@app.get("/maintenance/{mid}/completed",response_class=HTMLResponse)
def maintenance_completed(request:Request,mid:int):
    if not require_user(request):return RedirectResponse("/login",303)
    c=db();m=c.execute("SELECT m.*,u.display_name FROM maintenances m JOIN users u ON u.id=m.technician_id WHERE m.id=?",(mid,)).fetchone();c.close()
    if not m:return RedirectResponse("/",303)
    return TEMPLATES.TemplateResponse("completed.html",{"request":request,"user":current_user(request),"m":m})

@app.get("/maintenance/{mid}/pdf")
def maintenance_pdf(request:Request,mid:int):
    if not require_user(request):return RedirectResponse("/login",303)
    pdf=make_pdf(mid);return StreamingResponse(pdf,media_type="application/pdf",headers={"Content-Disposition":f'inline; filename="Zusammenfassung_Rufanlagenwartung_{mid}.pdf"'})
