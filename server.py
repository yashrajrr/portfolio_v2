import os, json, sqlite3, secrets, hashlib, time, base64, functools, re, io, tempfile
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from pydantic import BaseModel, Field, ConfigDict, ValidationError, field_validator
from typing import Literal
from blob_storage import enabled as blob_enabled, connect_blob, get_blob, put_blob, StorageConflict

ROOT = Path(__file__).parent
DATA = Path(os.environ.get("PORTFOLIO_DATA_DIR", str(ROOT / "data")))
MEDIA = DATA / "media"
MEDIA.mkdir(exist_ok=True)
DB = DATA / "portfolio.sqlite"
OWNER = os.environ.get("PORTFOLIO_OWNER_ID", "8e5be353-bde4-4aba-9155-0b0526029d6e")
REQUIRE_OWNER = os.environ.get("REQUIRE_PROMPTQL_OWNER", "true") == "true"
ADMIN_RESET_TOKEN = os.environ.get("ADMIN_RESET_TOKEN", "")
COOKIE = "__Host-portfolio-session"
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=12000)

def safe_link(v):
    if v and (not v.startswith(("https://", "http://")) or not urlparse(v).netloc):
        raise ValueError("Use a complete http or https URL")
    return v

class Profile(Strict):
    name: str = Field(min_length=1, max_length=100)
    fullName: str
    role: str
    location: str
    email: str
    linkedin: str
    github: str
    heroLead: str
    heroSecond: str
    intro: str
    aboutTitle: str
    about: str
    availability: str
    languages: str
    portrait: str
    resume: str
    resumeLabel: str
    contactTitle: str
    contactText: str
    _links = field_validator("linkedin", "github")(safe_link)
    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        if not re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", v): raise ValueError("Enter a valid email")
        return v
    @field_validator("portrait", "resume")
    @classmethod
    def local_media(cls, v):
        if v and not re.fullmatch(r"/media/[a-zA-Z0-9_.-]+", v): raise ValueError("Use an uploaded media file")
        return v

class Design(Strict):
    accent: str
    font: Literal["editorial", "sans"]
    defaultTheme: Literal["light", "dark"]
    animations: bool
    showPortrait: bool
    showContactForm: bool
    showEducation: bool
    showCredentials: bool
    @field_validator("accent")
    @classmethod
    def valid_color(cls, v):
        if not re.fullmatch(r"#[0-9a-fA-F]{6}",v): raise ValueError("Invalid color")
        return v

class Project(Strict):
    id: str = Field(min_length=1, max_length=100)
    title: str
    name: str
    category: str
    period: str
    summary: str
    description: str
    bullets: list[str] = Field(max_length=30)
    tags: list[str] = Field(max_length=30)
    visual: Literal["pipeline", "search", "agents"]
    url: str
    repo: str
    _links = field_validator("url", "repo")(safe_link)
class Skill(Strict):
    title: str
    description: str
    items: list[str] = Field(max_length=60)
class Experience(Strict):
    title: str
    organization: str
    period: str
    description: str
class Education(Strict):
    title: str
    organization: str
    period: str
    result: str
class Credential(Strict):
    title: str
    organization: str
    period: str
    type: str
class Content(Strict):
    profile: Profile
    design: Design
    projects: list[Project] = Field(max_length=30)
    skills: list[Skill] = Field(max_length=20)
    experience: list[Experience] = Field(max_length=30)
    education: list[Education] = Field(max_length=20)
    credentials: list[Credential] = Field(max_length=40)

def connect():
    if blob_enabled():
        if "database" not in g:
            g.database = connect_blob()
        return g.database
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

@app.teardown_appcontext
def close_database(_error):
    database = g.pop("database", None)
    if database is not None:
        database.close()

def init():
    with connect() as c:
        c.executescript("""
        PRAGMA journal_mode=MEMORY;
        CREATE TABLE IF NOT EXISTS content (id INTEGER PRIMARY KEY CHECK(id=1),published TEXT NOT NULL,draft TEXT NOT NULL,updated REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1),email TEXT NOT NULL,password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY,expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY,content TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY,name TEXT,email TEXT,message TEXT,created REAL,read INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY,count INTEGER,reset REAL);
        """)
        if not c.execute("SELECT id FROM content").fetchone():
            seed = Content.model_validate_json((DATA / "seed.json").read_text()).model_dump_json()
            c.execute("INSERT INTO content VALUES(1,?,?,?)",(seed,seed,time.time()))
    if not blob_enabled():
        os.chmod(DB, 0o600)

def visitor_id():
    token = request.headers.get("X-PromptQL-Visitor-Token","")
    try:
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==="))
        if float(payload.get("exp",0)) < time.time(): return None
        return payload.get("sub")
    except (ValueError, IndexError, TypeError): return None

def owner_allowed():
    return not REQUIRE_OWNER or visitor_id() == OWNER

def session_ok():
    if not owner_allowed(): return False
    token = request.cookies.get(COOKIE,"")
    if not token: return False
    with connect() as c:
        return bool(c.execute("SELECT 1 FROM sessions WHERE token=? AND expires>?",(hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone())

def auth(fn):
    @functools.wraps(fn)
    def wrap(*args,**kwargs):
        if not session_ok(): return jsonify(error="Sign in as the portfolio owner to continue."),401
        return fn(*args,**kwargs)
    return wrap

def limited(key, maximum, window):
    now=time.time()
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        r=c.execute("SELECT count,reset FROM rate_limits WHERE key=?",(key,)).fetchone()
        if r and r["reset"]>now:
            if r["count"] >= maximum: return True
            c.execute("UPDATE rate_limits SET count=count+1 WHERE key=?",(key,))
        else:
            c.execute("INSERT OR REPLACE INTO rate_limits VALUES(?,1,?)",(key,now+window))
    return False

@app.before_request
def guard():
    if request.method not in ("GET","HEAD","OPTIONS") and request.path.startswith("/api/"):
        if request.headers.get("X-CSRF-Protection") != "1" or request.headers.get("Sec-Fetch-Site") == "cross-site":
            return jsonify(error="Request verification failed. Refresh and try again."),403

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"]="nosniff"
    r.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    r.headers["Cache-Control"]="no-store"
    r.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
    return r

@app.errorhandler(HTTPException)
def http_error(e):
    return jsonify(error=e.description),e.code

@app.errorhandler(StorageConflict)
def storage_conflict(e):
    return jsonify(error=str(e)),409

@app.get("/readyz")
def ready():
    with connect() as c: c.execute("SELECT id FROM content").fetchone()
    return "",204

@app.get("/api/content")
def get_content():
    with connect() as c: row=c.execute("SELECT published FROM content WHERE id=1").fetchone()
    return jsonify(json.loads(row["published"]))

@app.get("/api/auth/status")
def status():
    with connect() as c: configured=bool(c.execute("SELECT id FROM admin").fetchone())
    return jsonify(configured=configured,owner=owner_allowed(),authenticated=session_ok())

def login_response():
    token=secrets.token_urlsafe(48)
    with connect() as c:
        c.execute("DELETE FROM sessions WHERE expires<?",(time.time(),))
        c.execute("INSERT INTO sessions VALUES(?,?)",(hashlib.sha256(token.encode()).hexdigest(),time.time()+8*3600))
    r=jsonify(ok=True)
    r.set_cookie(COOKIE,token,secure=True,httponly=True,samesite="None",partitioned=True,max_age=8*3600,path="/")
    return r

@app.post("/api/auth/setup")
def setup():
    if not owner_allowed(): return jsonify(error="Only the portfolio owner can create the admin account."),403
    data=request.get_json() or {}
    email=str(data.get("email","")).strip().lower()
    password=str(data.get("password",""))
    if len(password)<12 or len(password)>256 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email):
        return jsonify(error="Use a valid email and a password of 12–256 characters."),400
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        if c.execute("SELECT id FROM admin").fetchone(): return jsonify(error="Admin account already exists. Please sign in."),409
        c.execute("INSERT INTO admin VALUES(1,?,?)",(email,generate_password_hash(password)))
    return login_response()

@app.post("/api/auth/login")
def login():
    if not owner_allowed(): return jsonify(error="Open this app using the portfolio owner's PromptQL account."),403
    if limited("login",8,900): return jsonify(error="Too many attempts. Try again in 15 minutes."),429
    data=request.get_json() or {}
    with connect() as c: a=c.execute("SELECT email,password FROM admin WHERE id=1").fetchone()
    if not a or not secrets.compare_digest(str(data.get("email","")).strip().lower(),a["email"]) or not check_password_hash(a["password"],str(data.get("password",""))[:256]):
        return jsonify(error="Email or password is incorrect."),401
    with connect() as c: c.execute("DELETE FROM rate_limits WHERE key='login'")
    return login_response()

@app.post("/api/auth/reset")
def reset_password():
    data = request.get_json() or {}
    reset_token = str(data.get("token", ""))
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not ADMIN_RESET_TOKEN or not secrets.compare_digest(reset_token, ADMIN_RESET_TOKEN):
        return jsonify(error="Password reset is not enabled or the reset token is invalid."), 403
    if len(password) < 12 or len(password) > 256 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify(error="Use a valid email and a password of 12–256 characters."), 400
    with connect() as c:
        admin = c.execute("SELECT id FROM admin WHERE id=1").fetchone()
        if not admin:
            return jsonify(error="Admin account has not been configured yet."), 404
        c.execute("UPDATE admin SET email=?, password=? WHERE id=1", (email, generate_password_hash(password)))
        c.execute("DELETE FROM sessions")
    return jsonify(ok=True)

@app.post("/api/auth/logout")
@auth
def logout():
    with connect() as c: c.execute("DELETE FROM sessions WHERE token=?",(hashlib.sha256(request.cookies.get(COOKIE,"").encode()).hexdigest(),))
    r=jsonify(ok=True);r.delete_cookie(COOKIE,secure=True,httponly=True,samesite="None",partitioned=True,path="/")
    return r

@app.post("/api/auth/password")
@auth
def change_password():
    data=request.get_json() or {}
    password=str(data.get("password",""))
    if not 12<=len(password)<=256: return jsonify(error="Choose a password of 12–256 characters."),400
    with connect() as c:
        a=c.execute("SELECT password FROM admin").fetchone()
        if not check_password_hash(a["password"],str(data.get("current",""))[:256]): return jsonify(error="Current password is incorrect."),400
        c.execute("UPDATE admin SET password=?",(generate_password_hash(password),))
        c.execute("DELETE FROM sessions")
    return login_response()

@app.get("/api/admin/content")
@auth
def admin_content():
    with connect() as c: row=c.execute("SELECT draft,updated FROM content WHERE id=1").fetchone()
    return jsonify(content=json.loads(row["draft"]),updated=row["updated"])

@app.post("/api/admin/validate")
@auth
def validate_import():
    try:
        content = Content.model_validate(request.get_json()).model_dump()
        return jsonify(content)
    except ValidationError as e:
        return jsonify(error="Invalid content file: " + str(e.errors(include_url=False, include_context=False)[0]["msg"])), 400

@app.put("/api/admin/content")
@auth
def save():
    data=request.get_json() or {}
    try: content=Content.model_validate(data.get("content")).model_dump_json()
    except ValidationError as e: return jsonify(error="Check your content: "+str(e.errors(include_url=False,include_context=False)[0]["msg"])),400
    if len(content)>300000: return jsonify(error="Content is too large."),400
    publish=data.get("publish") is True
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        row=c.execute("SELECT updated,published FROM content WHERE id=1").fetchone()
        if data.get("version")!=row["updated"]: return jsonify(error="This draft changed in another tab. Reload before saving."),409
        stamp=time.time()
        if publish:
            c.execute("INSERT INTO history(content,created) VALUES(?,?)",(row["published"],stamp))
            c.execute("DELETE FROM history WHERE id NOT IN(SELECT id FROM history ORDER BY id DESC LIMIT 10)")
            c.execute("UPDATE content SET draft=?,published=?,updated=? WHERE id=1",(content,content,stamp))
        else: c.execute("UPDATE content SET draft=?,updated=? WHERE id=1",(content,stamp))
    return jsonify(ok=True,updated=stamp)

@app.get("/api/admin/history")
@auth
def history():
    with connect() as c: rows=c.execute("SELECT id,created FROM history ORDER BY id DESC LIMIT 10").fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/admin/history/<int:version>")
@auth
def history_item(version):
    with connect() as c: r=c.execute("SELECT content FROM history WHERE id=?",(version,)).fetchone()
    if not r:return jsonify(error="Version not found."),404
    return jsonify(json.loads(r["content"]))

@app.post("/api/admin/upload")
@auth
def upload():
    import pymupdf
    f=request.files.get("file");kind=request.form.get("kind")
    if not f or kind not in ["portrait","resume"]:return jsonify(error="Choose an image or PDF."),400
    raw=f.read()
    if len(raw)>10*1024*1024:return jsonify(error="Maximum file size is 10 MB."),400
    try:
        if kind=="resume":
            doc=pymupdf.open(stream=raw,filetype="pdf")
            if not 1<=len(doc)<=20 or doc.is_encrypted: raise ValueError()
            # Rebuild PDF pages to discard document scripts and attachments.
            out=pymupdf.open()
            out.insert_pdf(doc,links=False,annots=False)
            filename=secrets.token_hex(12)+".pdf"
            target = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
            target.close()
            out.save(target.name,garbage=4,deflate=True)
            cleaned = Path(target.name).read_bytes()
            Path(target.name).unlink(missing_ok=True)
        else:
            pix=pymupdf.Pixmap(raw)
            if pix.width*pix.height>16000000:raise ValueError()
            if pix.colorspace.n not in (1,3):pix=pymupdf.Pixmap(pymupdf.csRGB,pix)
            filename=secrets.token_hex(12)+".png"
            target = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
            target.close()
            pix.save(target.name)
            cleaned = Path(target.name).read_bytes()
            Path(target.name).unlink(missing_ok=True)
        if blob_enabled():
            put_blob("media/"+filename, cleaned)
        else:
            (MEDIA/filename).write_bytes(cleaned)
    except Exception:return jsonify(error="The file could not be read. Use a valid image or an unencrypted PDF (up to 20 pages)."),400
    return jsonify(path="/media/"+filename)

@app.post("/api/contact")
def contact():
    d=request.get_json() or {}
    if d.get("website"):return jsonify(ok=True)
    key="contact:"+str(visitor_id() or request.headers.get("X-Forwarded-For",request.remote_addr)).split(",")[0]
    if limited(key,5,3600):return jsonify(error="Message limit reached. Please email me directly."),429
    name=str(d.get("name","")).strip();email=str(d.get("email","")).strip();message=str(d.get("message","")).strip()
    if not 1<=len(name)<=100 or not re.fullmatch(r"[^@\s<>]{1,100}@[^@\s<>]{1,100}\.[^@\s<>]{1,30}",email) or not 10<=len(message)<=4000:
        return jsonify(error="Add your name, a valid email, and a message of 10–4,000 characters."),400
    with connect() as c:c.execute("INSERT INTO messages(name,email,message,created) VALUES(?,?,?,?)",(name,email,message,time.time()))
    return jsonify(ok=True),201

@app.get("/api/admin/messages")
@auth
def messages():
    with connect() as c:rows=c.execute("SELECT id,name,email,message,created,read FROM messages ORDER BY id DESC LIMIT 500").fetchall()
    return jsonify([dict(r) for r in rows])

@app.patch("/api/admin/messages/<int:mid>")
@auth
def message_read(mid):
    with connect() as c:c.execute("UPDATE messages SET read=1 WHERE id=?",(mid,))
    return jsonify(ok=True)

@app.delete("/api/admin/messages/<int:mid>")
@auth
def message_delete(mid):
    with connect() as c:c.execute("DELETE FROM messages WHERE id=?",(mid,))
    return jsonify(ok=True)

@app.get("/media/<path:filename>")
def media(filename):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+",filename):return "",404
    if blob_enabled():
        raw, _, info = get_blob("media/"+filename)
        if raw is None:return "",404
        content_type = "application/pdf" if filename.endswith(".pdf") else "image/png" if filename.endswith(".png") else "image/jpeg"
        return send_file(io.BytesIO(raw),mimetype=content_type,as_attachment=filename.endswith(".pdf"),download_name="Yashraj-Rathor-Resume.pdf" if filename.endswith(".pdf") else filename)
    return send_from_directory(MEDIA,filename,as_attachment=filename.endswith(".pdf"),download_name="Yashraj-Rathor-Resume.pdf" if filename.endswith(".pdf") else None)

@app.get("/")
@app.get("/admin")
@app.get("/admin/")
def index():
    return send_from_directory(ROOT/"dist","index.html")

@app.get("/<path:filename>")
def assets(filename):
    return send_from_directory(ROOT/"dist",filename)

with app.app_context():
    init()