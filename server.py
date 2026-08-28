import os, secrets, string, calendar, hashlib, hmac, time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import psycopg
from psycopg import errors
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel

DATABASE_URL = os.getenv("DATABASE_URL","").strip()
APP_ENV = os.getenv("APP_ENV","production")
ADMIN_SECRET = os.getenv("ADMIN_SECRET","")
CLIENT_VERSION = os.getenv("CLIENT_VERSION","10.0.0")
CLIENT_DOWNLOAD_URL = os.getenv("CLIENT_DOWNLOAD_URL","")
CLIENT_RELEASE_NOTES = os.getenv("CLIENT_RELEASE_NOTES","Latest Resource Hub client.")
SESSION_DAYS = int(os.getenv("SESSION_DAYS","30"))
ONLINE_WINDOW = 90
RATE = {}

app = FastAPI(title="Resource Hub License Server", version="10.0.0")

def now(): return datetime.now(timezone.utc)
def iso(v): return v.isoformat()
def dt(v):
    try: return datetime.fromisoformat(v) if v else None
    except: return None
def remain(v):
    d=dt(v); return max(0,int((d-now()).total_seconds())) if d else 0

def require_database_url():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured. Add your PostgreSQL connection URL "
            "to the Render service environment."
        )

def conn():
    require_database_url()
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10,
    )

def database_label():
    if not DATABASE_URL:
        return "PostgreSQL (not configured)"
    try:
        host=urlparse(DATABASE_URL).hostname or "PostgreSQL"
        if "neon" in host.lower():
            return "PostgreSQL / Neon"
        if "render" in host.lower():
            return "PostgreSQL / Render"
        if "supabase" in host.lower():
            return "PostgreSQL / Supabase"
        return "PostgreSQL"
    except Exception:
        return "PostgreSQL"

def database_size_bytes():
    c=conn()
    try:
        row=c.execute(
            "SELECT pg_database_size(current_database()) AS size_bytes"
        ).fetchone()
        return int(row["size_bytes"]) if row else 0
    finally:
        c.close()

def online(v):
    d=dt(v); return bool(d and (now()-d).total_seconds() <= ONLINE_WINDOW)

def setup():
    c=conn()
    try:
        q=c.cursor()

        q.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id BIGSERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT,
                last_seen_at TEXT,
                disabled INTEGER NOT NULL DEFAULT 0
            )
        """)

        q.execute("""
            CREATE TABLE IF NOT EXISTS sessions(
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            )
        """)

        q.execute("""
            CREATE TABLE IF NOT EXISTS licenses(
                license_key TEXT PRIMARY KEY,
                duration_type TEXT NOT NULL,
                duration_amount INTEGER NOT NULL,
                activated INTEGER NOT NULL DEFAULT 0,
                bound_hwid TEXT,
                activated_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                owner_username TEXT
            )
        """)

        q.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs(
                id BIGSERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                action TEXT NOT NULL,
                username TEXT,
                license_key TEXT,
                details TEXT
            )
        """)

        q.execute("""
            CREATE TABLE IF NOT EXISTS settings(
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )
        """)

        # Safe schema upgrades for older databases.
        upgrades = [
            ("users","disabled","INTEGER NOT NULL DEFAULT 0"),
            ("users","last_login_at","TEXT"),
            ("users","last_seen_at","TEXT"),
            ("sessions","last_seen_at","TEXT"),
            ("licenses","owner_username","TEXT"),
            ("licenses","bound_hwid","TEXT"),
            ("licenses","activated_at","TEXT"),
            ("licenses","expires_at","TEXT"),
            ("licenses","revoked","INTEGER NOT NULL DEFAULT 0"),
        ]

        for table,column,definition in upgrades:
            q.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN IF NOT EXISTS {column} {definition}"
            )

        q.execute(
            """
            INSERT INTO settings(k,v)
            VALUES('maintenance','0')
            ON CONFLICT (k) DO NOTHING
            """
        )

        q.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_last_seen "
            "ON users(last_seen_at)"
        )
        q.execute(
            "CREATE INDEX IF NOT EXISTS idx_licenses_owner "
            "ON licenses(owner_username)"
        )
        q.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_created "
            "ON audit_logs(created_at DESC)"
        )
        q.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_license "
            "ON audit_logs(license_key)"
        )

        c.commit()
    finally:
        c.close()

@app.on_event("startup")
def boot():
    setup()

def maintenance():
    c=conn(); r=c.execute("SELECT v FROM settings WHERE k='maintenance'").fetchone(); c.close()
    return bool(r and r["v"]=="1")

def audit(action,username=None,key=None,details=""):
    c=conn(); c.execute("INSERT INTO audit_logs(created_at,action,username,license_key,details) VALUES(%s,%s,%s,%s,%s)",(iso(now()),action,username,key,str(details)[:500])); c.commit(); c.close()

def pw_hash(p,salt=None):
    salt=salt or secrets.token_bytes(16).hex()
    d=hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(salt),200000).hex()
    return d,salt
def pw_ok(p,h,s): return hmac.compare_digest(pw_hash(p,s)[0],h)
def th(t): return hashlib.sha256(t.encode()).hexdigest()

def new_session(user):
    t=secrets.token_urlsafe(48); n=now(); e=n+timedelta(days=SESSION_DAYS)
    c=conn(); c.execute("INSERT INTO sessions VALUES(%s,%s,%s,%s,%s)",(th(t),user,iso(n),iso(e),iso(n))); c.commit(); c.close(); return t

def user_from_auth(auth):
    if not auth: raise HTTPException(401,"Login required.")
    t=auth[7:].strip() if auth.startswith("Bearer ") else auth
    c=conn(); r=c.execute("SELECT * FROM sessions WHERE token_hash=%s",(th(t),)).fetchone()
    if not r: c.close(); raise HTTPException(401,"Session expired. Please sign in again.")
    if now() >= dt(r["expires_at"]):
        c.execute("DELETE FROM sessions WHERE token_hash=%s",(th(t),)); c.commit(); c.close()
        raise HTTPException(401,"Session expired. Please sign in again.")
    u=c.execute("SELECT disabled FROM users WHERE username=%s",(r["username"],)).fetchone()
    if not u or u["disabled"]: c.close(); raise HTTPException(403,"Account disabled.")
    seen=iso(now()); c.execute("UPDATE sessions SET last_seen_at=%s WHERE token_hash=%s",(seen,th(t))); c.execute("UPDATE users SET last_seen_at=%s WHERE username=%s",(seen,r["username"])); c.commit(); c.close()
    return r["username"]

def admin(secret):
    if not ADMIN_SECRET: raise HTTPException(500,"ADMIN_SECRET is not configured on the server.")
    if not secret or not hmac.compare_digest(secret,ADMIN_SECRET): raise HTTPException(403,"Invalid admin authorization.")

def rate(request,name,window=300,limit=10):
    ip=request.client.host if request.client else "unknown"; k=f"{name}:{ip}"; t=time.time()
    a=[x for x in RATE.get(k,[]) if t-x<window]
    if len(a)>=limit: raise HTTPException(429,"Too many attempts. Please wait a few minutes.")
    a.append(t); RATE[k]=a

def gen_key():
    a="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(a) for _ in range(5)) for _ in range(4))
def add_duration(base,kind,n):
    kind=kind.lower()
    if kind=="minutes": return base+timedelta(minutes=n)
    if kind=="hours": return base+timedelta(hours=n)
    if kind=="days": return base+timedelta(days=n)
    if kind=="months":
        m=base.month-1+n; y=base.year+m//12; mo=m%12+1
        d=min(base.day,calendar.monthrange(y,mo)[1]); return base.replace(year=y,month=mo,day=d)
    raise ValueError("Invalid duration type.")
def lic_status(r):
    if r["revoked"]: return "revoked"
    if not r["activated"]: return "not_activated"
    e=dt(r["expires_at"])
    return "expired" if not e or now()>=e else "active"
def lic_dict(r):
    return dict(r) | {"activated":bool(r["activated"]),"revoked":bool(r["revoked"]),"status":lic_status(r),"seconds_remaining":remain(r["expires_at"])}

def reconcile_license_owners(c=None):
    own_connection = c is None
    if own_connection:
        c = conn()

    changed = 0
    rows = c.execute(
        "SELECT license_key FROM licenses WHERE owner_username IS NULL OR TRIM(owner_username)=''"
    ).fetchall()

    for row in rows:
        hit = c.execute(
            """
            SELECT username
            FROM audit_logs
            WHERE license_key=%s
              AND action='LICENSE_ACTIVATED'
              AND username IS NOT NULL
              AND TRIM(username)!=''
            ORDER BY id DESC
            LIMIT 1
            """,
            (row["license_key"],),
        ).fetchone()

        if hit:
            c.execute(
                "UPDATE licenses SET owner_username=%s WHERE license_key=%s",
                (hit["username"], row["license_key"]),
            )
            changed += 1

    if changed:
        c.commit()

    if own_connection:
        c.close()

    return changed

def enriched_license(c, r):
    data = lic_dict(r)
    owner = data.get("owner_username")

    data["assigned"] = bool(owner)
    data["owner_online"] = False
    data["owner_last_login_at"] = None
    data["owner_last_seen_at"] = None
    data["owner_disabled"] = False

    if owner:
        user = c.execute(
            "SELECT username,last_login_at,last_seen_at,disabled FROM users WHERE username=%s",
            (owner,),
        ).fetchone()

        if user:
            data["owner_online"] = online(user["last_seen_at"])
            data["owner_last_login_at"] = user["last_login_at"]
            data["owner_last_seen_at"] = user["last_seen_at"]
            data["owner_disabled"] = bool(user["disabled"])

    return data

class Auth(BaseModel): username:str; password:str
class Gen(BaseModel): duration_type:str; duration_amount:int
class LicenseReq(BaseModel): license_key:str; hwid:str
class KeyReq(BaseModel): license_key:str
class Extend(BaseModel): duration_type:str; duration_amount:int
class Toggle(BaseModel): disabled:bool
class ResetPW(BaseModel): new_password:str
class Maint(BaseModel): enabled:bool

@app.get("/")
def root(): return {"success":True,"message":"Resource Hub license server is online.","version":VERSION,"environment":APP_ENV,"server_time":iso(now())}

VERSION="10.0.0"

@app.get("/health")
def health():
    c=conn(); c.execute("SELECT 1").fetchone(); c.close()
    return {"success":True,"status":"online","database":"ready","environment":APP_ENV,"maintenance":maintenance(),"server_time":iso(now())}

@app.get("/api/client/version")
def version():
    return {"success":True,"client_version":CLIENT_VERSION,"download_url":CLIENT_DOWNLOAD_URL,"release_notes":CLIENT_RELEASE_NOTES,"maintenance":maintenance()}

@app.post("/api/auth/register")
def register(request:Request,b:Auth):
    rate(request,"register",limit=8)
    if maintenance(): raise HTTPException(503,"The service is currently in maintenance mode.")
    u=b.username.strip()
    if not (3<=len(u)<=32) or not u.replace("_","").isalnum(): raise HTTPException(400,"Username must be 3-32 characters and use letters, numbers, or underscores.")
    if len(b.password)<6: raise HTTPException(400,"Password must be at least 6 characters.")
    h,s=pw_hash(b.password); c=conn()
    try: c.execute("INSERT INTO users(username,password_hash,salt,created_at) VALUES(%s,%s,%s,%s)",(u,h,s,iso(now()))); c.commit()
    except errors.UniqueViolation: c.close(); raise HTTPException(409,"Username already exists.")
    c.close(); audit("USER_REGISTERED",u); return {"success":True,"username":u,"token":new_session(u)}

@app.post("/api/auth/login")
def login(request:Request,b:Auth):
    rate(request,"login",limit=8)
    if maintenance(): raise HTTPException(503,"The service is currently in maintenance mode.")
    c=conn(); r=c.execute("SELECT * FROM users WHERE username=%s",(b.username.strip(),)).fetchone(); c.close()
    if not r or r["disabled"] or not pw_ok(b.password,r["password_hash"],r["salt"]): raise HTTPException(401,"Invalid username or password.")
    seen=iso(now()); c=conn(); c.execute("UPDATE users SET last_login_at=%s,last_seen_at=%s WHERE username=%s",(seen,seen,r["username"])); c.commit(); c.close(); audit("USER_LOGIN",r["username"]); return {"success":True,"username":r["username"],"token":new_session(r["username"])}

@app.post("/api/auth/logout")
def logout(auth:str|None=Header(default=None, alias="Authorization")):
    if auth:
        t=auth[7:].strip() if auth.startswith("Bearer ") else auth; u=user_from_auth(auth)
        c=conn(); c.execute("DELETE FROM sessions WHERE token_hash=%s",(th(t),)); c.commit(); c.close(); audit("USER_LOGOUT",u)
    return {"success":True}

@app.post("/api/auth/heartbeat")
def heartbeat(auth:str|None=Header(default=None, alias="Authorization")): return {"success":True,"username":user_from_auth(auth),"server_time":iso(now())}

@app.get("/api/auth/me")
def me(auth:str|None=Header(default=None, alias="Authorization")):
    u=user_from_auth(auth); c=conn()
    user=c.execute("SELECT username,created_at,last_login_at,last_seen_at,disabled FROM users WHERE username=%s",(u,)).fetchone()
    lic=c.execute("SELECT * FROM licenses WHERE owner_username=%s ORDER BY activated_at DESC,created_at DESC LIMIT 1",(u,)).fetchone()
    c.close()
    return {"success":True,"account":dict(user)|{"online":online(user["last_seen_at"]),"disabled":bool(user["disabled"]),"license":lic_dict(lic) if lic else None}}

@app.post("/api/license/activate")
def activate(request:Request,b:LicenseReq,auth:str|None=Header(default=None, alias="Authorization")):
    rate(request,"activate",limit=12); u=user_from_auth(auth); key=b.license_key.strip().upper()
    c=conn(); r=c.execute("SELECT * FROM licenses WHERE license_key=%s",(key,)).fetchone()
    if not r: c.close(); raise HTTPException(404,"Invalid license key.")
    if r["revoked"]: c.close(); raise HTTPException(403,"This license has been revoked.")
    if not r["activated"]:
        a=now(); e=add_duration(a,r["duration_type"],r["duration_amount"])
        c.execute("UPDATE licenses SET activated=1,bound_hwid=%s,activated_at=%s,expires_at=%s,owner_username=%s WHERE license_key=%s",(b.hwid,iso(a),iso(e),u,key)); c.commit(); c.close()
        audit("LICENSE_ACTIVATED",u,key,"Account and HWID bound."); return {"success":True,"message":"License activated successfully.","seconds_remaining":remain(iso(e)),"expires_at":iso(e)}
    if r["bound_hwid"]!=b.hwid: c.close(); raise HTTPException(403,"HWID mismatch. This license is bound to another device.")
    if r["owner_username"] and r["owner_username"]!=u: c.close(); raise HTTPException(403,"This license belongs to another account.")
    left=remain(r["expires_at"]); c.close()
    if left<=0: raise HTTPException(403,"This license has expired.")
    return {"success":True,"message":"License is valid.","seconds_remaining":left,"expires_at":r["expires_at"]}

@app.post("/api/license/validate")
def validate(b:LicenseReq,auth:str|None=Header(default=None, alias="Authorization")):
    u=user_from_auth(auth); c=conn(); r=c.execute("SELECT * FROM licenses WHERE license_key=%s",(b.license_key.strip().upper(),)).fetchone(); c.close()
    if not r: raise HTTPException(404,"Invalid license key.")
    if r["revoked"]: raise HTTPException(403,"This license has been revoked.")
    if not r["activated"]: raise HTTPException(403,"This license is not activated.")
    if r["bound_hwid"]!=b.hwid: raise HTTPException(403,"HWID mismatch.")
    if r["owner_username"] and r["owner_username"]!=u: raise HTTPException(403,"This license belongs to another account.")
    left=remain(r["expires_at"])
    if left<=0: raise HTTPException(403,"This license has expired.")
    return {"success":True,"valid":True,"seconds_remaining":left,"expires_at":r["expires_at"]}

@app.post("/api/admin/generate")
def admin_generate(b:Gen,x: str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    if b.duration_type.lower() not in {"minutes","hours","days","months"} or b.duration_amount<1: raise HTTPException(400,"Invalid duration.")
    c=conn()
    while True:
        k=gen_key()
        if not c.execute("SELECT 1 FROM licenses WHERE license_key=%s",(k,)).fetchone(): break
    c.execute("INSERT INTO licenses(license_key,duration_type,duration_amount,created_at) VALUES(%s,%s,%s,%s)",(k,b.duration_type.lower(),b.duration_amount,iso(now()))); c.commit(); c.close()
    audit("LICENSE_GENERATED",key=k,details=f"{b.duration_amount} {b.duration_type}"); return {"success":True,"license_key":k}

@app.get("/api/admin/licenses")
def licenses(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    c=conn()
    reconcile_license_owners(c)
    rows=c.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    result=[enriched_license(c,r) for r in rows]
    c.close()
    return {"success":True,"count":len(result),"licenses":result}

@app.get("/api/admin/license/{key}")
def license_detail(key:str,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    c=conn()
    reconcile_license_owners(c)
    r=c.execute("SELECT * FROM licenses WHERE license_key=%s",(key.upper(),)).fetchone()
    if not r:
        c.close()
        raise HTTPException(404,"License not found.")
    result=enriched_license(c,r)
    c.close()
    return {"success":True,"license":result}

@app.post("/api/admin/license/{key}/extend")
def extend(key:str,b:Extend,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); r=c.execute("SELECT * FROM licenses WHERE license_key=%s",(key.upper(),)).fetchone()
    if not r: c.close(); raise HTTPException(404,"License not found.")
    base=dt(r["expires_at"]) or now(); e=add_duration(max(base,now()),b.duration_type,b.duration_amount)
    c.execute("UPDATE licenses SET expires_at=%s,activated=1 WHERE license_key=%s",(iso(e),key.upper())); c.commit(); c.close()
    audit("LICENSE_EXTENDED",r["owner_username"],key.upper(),f"Added {b.duration_amount} {b.duration_type}"); return {"success":True,"expires_at":iso(e),"seconds_remaining":remain(iso(e))}

@app.post("/api/admin/revoke")
def revoke(b:KeyReq,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); r=c.execute("SELECT owner_username FROM licenses WHERE license_key=%s",(b.license_key.upper(),)).fetchone(); cur=c.execute("UPDATE licenses SET revoked=1 WHERE license_key=%s",(b.license_key.upper(),)); c.commit(); c.close()
    if cur.rowcount==0: raise HTTPException(404,"License not found.")
    if r and r["owner_username"]:
        c=conn(); c.execute("DELETE FROM sessions WHERE username=%s",(r["owner_username"],)); c.commit(); c.close()
    audit("LICENSE_REVOKED",r["owner_username"] if r else None,b.license_key.upper()); return {"success":True}

@app.post("/api/admin/unrevoke")
def unrevoke(b:KeyReq,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); cur=c.execute("UPDATE licenses SET revoked=0 WHERE license_key=%s",(b.license_key.upper(),)); c.commit(); c.close()
    if cur.rowcount==0: raise HTTPException(404,"License not found.")
    audit("LICENSE_RESTORED",key=b.license_key.upper()); return {"success":True}

@app.post("/api/admin/reset-hwid")
def reset_hwid(b:KeyReq,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); r=c.execute("SELECT owner_username FROM licenses WHERE license_key=%s",(b.license_key.upper(),)).fetchone(); cur=c.execute("UPDATE licenses SET activated=0,bound_hwid=NULL,activated_at=NULL,expires_at=NULL,owner_username=NULL WHERE license_key=%s",(b.license_key.upper(),)); c.commit(); c.close()
    if cur.rowcount==0: raise HTTPException(404,"License not found.")
    if r and r["owner_username"]:
        c=conn(); c.execute("DELETE FROM sessions WHERE username=%s",(r["owner_username"],)); c.commit(); c.close()
    audit("LICENSE_HWID_RESET",r["owner_username"] if r else None,b.license_key.upper()); return {"success":True}

@app.get("/api/admin/users")
def users(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    c=conn()
    reconcile_license_owners(c)
    us=c.execute(
        "SELECT id,username,created_at,last_login_at,last_seen_at,disabled FROM users ORDER BY created_at DESC"
    ).fetchall()

    out=[]
    for u in us:
        ls=c.execute(
            "SELECT * FROM licenses WHERE owner_username=%s ORDER BY activated_at DESC,created_at DESC",
            (u["username"],),
        ).fetchall()

        licenses_for_user=[enriched_license(c,r) for r in ls]
        current=next(
            (item for item in licenses_for_user if item["status"]=="active"),
            licenses_for_user[0] if licenses_for_user else None,
        )

        out.append({
            "id":u["id"],
            "username":u["username"],
            "created_at":u["created_at"],
            "last_login_at":u["last_login_at"],
            "last_seen_at":u["last_seen_at"],
            "online":online(u["last_seen_at"]),
            "disabled":bool(u["disabled"]),
            "license_count":len(licenses_for_user),
            "current_license":current,
            "licenses":licenses_for_user,
        })

    unassigned_row=c.execute(
        "SELECT COUNT(*) AS count FROM licenses "
        "WHERE owner_username IS NULL OR TRIM(owner_username)=''"
    ).fetchone()
    unassigned=int(unassigned_row["count"])
    c.close()

    return {
        "success":True,
        "count":len(out),
        "unassigned_licenses":unassigned,
        "users":out,
    }

@app.get("/api/admin/user/{username}")
def user_detail(username:str,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    c=conn()
    reconcile_license_owners(c)

    u=c.execute(
        "SELECT id,username,created_at,last_login_at,last_seen_at,disabled FROM users WHERE username=%s",
        (username,),
    ).fetchone()

    if not u:
        c.close()
        raise HTTPException(404,"User not found.")

    ls=c.execute(
        "SELECT * FROM licenses WHERE owner_username=%s ORDER BY activated_at DESC,created_at DESC",
        (username,),
    ).fetchall()

    licenses_for_user=[enriched_license(c,r) for r in ls]
    current=next(
        (item for item in licenses_for_user if item["status"]=="active"),
        licenses_for_user[0] if licenses_for_user else None,
    )

    result={
        "id":u["id"],
        "username":u["username"],
        "created_at":u["created_at"],
        "last_login_at":u["last_login_at"],
        "last_seen_at":u["last_seen_at"],
        "online":online(u["last_seen_at"]),
        "disabled":bool(u["disabled"]),
        "license_count":len(licenses_for_user),
        "current_license":current,
        "licenses":licenses_for_user,
    }

    c.close()
    return {"success":True,"user":result}

@app.get("/api/admin/overview")
def admin_overview(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    c=conn()
    reconciled=reconcile_license_owners(c)

    license_rows=c.execute(
        "SELECT * FROM licenses ORDER BY created_at DESC"
    ).fetchall()
    licenses_out=[enriched_license(c,r) for r in license_rows]

    user_rows=c.execute(
        "SELECT id,username,created_at,last_login_at,last_seen_at,disabled FROM users ORDER BY created_at DESC"
    ).fetchall()

    users_out=[]
    for u in user_rows:
        owned=[item for item in licenses_out if item.get("owner_username")==u["username"]]
        current=next(
            (item for item in owned if item["status"]=="active"),
            owned[0] if owned else None,
        )
        users_out.append({
            "id":u["id"],
            "username":u["username"],
            "created_at":u["created_at"],
            "last_login_at":u["last_login_at"],
            "last_seen_at":u["last_seen_at"],
            "online":online(u["last_seen_at"]),
            "disabled":bool(u["disabled"]),
            "license_count":len(owned),
            "current_license":current,
            "licenses":owned,
        })

    c.close()

    return {
        "success":True,
        "reconciled":reconciled,
        "users":users_out,
        "licenses":licenses_out,
        "counts":{
            "users":len(users_out),
            "licenses":len(licenses_out),
            "assigned":sum(bool(item.get("owner_username")) for item in licenses_out),
            "unassigned":sum(not bool(item.get("owner_username")) for item in licenses_out),
            "online_users":sum(bool(item.get("online")) for item in users_out),
        },
    }

@app.post("/api/admin/reconcile")
def reconcile_admin_data(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    changed=reconcile_license_owners()
    if changed:
        audit("LICENSE_OWNER_RECONCILE",details=f"Recovered {changed} license owner mapping(s) from audit history.")
    return {"success":True,"reconciled":changed}

@app.post("/api/admin/user/{username}/disable")
def disable(username:str,b:Toggle,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); cur=c.execute("UPDATE users SET disabled=%s WHERE username=%s",(int(b.disabled),username)); c.commit(); c.close()
    if cur.rowcount==0: raise HTTPException(404,"User not found.")
    if b.disabled:
        c=conn(); c.execute("DELETE FROM sessions WHERE username=%s",(username,)); c.commit(); c.close()
    audit("USER_DISABLED" if b.disabled else "USER_ENABLED",username); return {"success":True,"disabled":b.disabled}

@app.post("/api/admin/user/{username}/reset-password")
def reset_password(username:str,b:ResetPW,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    if len(b.new_password)<6: raise HTTPException(400,"Password must be at least 6 characters.")
    h,s=pw_hash(b.new_password); c=conn(); cur=c.execute("UPDATE users SET password_hash=%s,salt=%s WHERE username=%s",(h,s,username)); c.commit(); c.close()
    if cur.rowcount==0: raise HTTPException(404,"User not found.")
    c=conn(); c.execute("DELETE FROM sessions WHERE username=%s",(username,)); c.commit(); c.close(); audit("USER_PASSWORD_RESET",username); return {"success":True}

@app.post("/api/admin/user/{username}/force-logout")
def force_logout(username:str,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); c.execute("DELETE FROM sessions WHERE username=%s",(username,)); c.commit(); c.close(); audit("USER_FORCE_LOGOUT",username); return {"success":True}

@app.get("/api/admin/activity")
def activity(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); u=c.execute("SELECT username,last_login_at,last_seen_at FROM users ORDER BY last_seen_at DESC LIMIT 100").fetchall(); a=c.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200").fetchall(); c.close()
    return {"success":True,"users":[dict(r)|{"online":online(r["last_seen_at"])} for r in u],"audit":[dict(r) for r in a]}

@app.get("/api/admin/audit")
def audit_api(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); r=c.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500").fetchall(); c.close()
    return {"success":True,"logs":[dict(v) for v in r]}

@app.get("/api/admin/stats")
def stats(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    c=conn()
    reconcile_license_owners(c)
    rows=c.execute("SELECT * FROM licenses").fetchall()
    users=c.execute("SELECT last_seen_at FROM users WHERE disabled=0").fetchall()
    count=int(c.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"])
    assigned=int(c.execute(
        "SELECT COUNT(*) AS count FROM licenses "
        "WHERE owner_username IS NOT NULL AND TRIM(owner_username)!=''"
    ).fetchone()["count"])
    c.close()
    active=sum(lic_status(r)=="active" for r in rows)
    unused=sum(lic_status(r)=="not_activated" for r in rows)
    revoked=sum(lic_status(r)=="revoked" for r in rows)
    expired=sum(lic_status(r)=="expired" for r in rows)
    return {
        "success":True,
        "total_keys":len(rows),
        "activated_keys":active,
        "unused_keys":unused,
        "revoked_keys":revoked,
        "expired_keys":expired,
        "assigned_keys":assigned,
        "unassigned_keys":len(rows)-assigned,
        "users":count,
        "online_users":sum(online(r["last_seen_at"]) for r in users),
        "environment":APP_ENV,
        "maintenance":maintenance(),
        "database_path":database_label(),
    }

@app.get("/api/admin/settings")
def settings(x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x)
    try:
        size=database_size_bytes()
        exists=True
    except Exception:
        size=0
        exists=False
    return {
        "success":True,
        "maintenance":maintenance(),
        "environment":APP_ENV,
        "client_version":CLIENT_VERSION,
        # These old field names are intentionally kept so the current
        # KeySystem UI continues working without any redesign.
        "database_path":database_label(),
        "database_exists":exists,
        "database_size":size,
        "database_type":"postgresql",
    }

@app.post("/api/admin/maintenance")
def set_maintenance(b:Maint,x:str|None=Header(default=None,alias="X-Admin-Secret")):
    admin(x); c=conn(); c.execute("UPDATE settings SET v=%s WHERE k='maintenance'",("1" if b.enabled else "0",)); c.commit(); c.close(); audit("MAINTENANCE_ON" if b.enabled else "MAINTENANCE_OFF"); return {"success":True,"maintenance":b.enabled}
