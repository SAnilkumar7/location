#!/usr/bin/env python3
"""
SafeTrace Backend — Google OAuth + User Tracking + Admin Dashboard
- Google Sign-In: verifies ID tokens via Google tokeninfo API
- User store: tracks signups, session counts, last login per Google account
- /api/auth/google    — verify Google ID token, return user profile
- /api/auth/me        — get current user by session token
- /api/admin/users    — admin-only: list all users + stats
- /api/admin/stats    — admin-only: aggregate platform stats
- All existing session/location/SSE routes preserved

Run dev:  python3 server.py
Run prod: gunicorn -w 1 -k gevent --worker-connections 2000 -b 0.0.0.0:8000 server:app
Env vars:
  GOOGLE_CLIENT_ID  — your Google OAuth client ID (required for auth)
  ADMIN_SECRET      — secret key to access /admin dashboard (default: changeme)
  BASE_URL          — public base URL for generated links
"""

import json, math, secrets, time, threading, uuid, os, queue, urllib.request, urllib.error
from collections import deque
from flask import Flask, request, jsonify, Response, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="")
BASE_URL          = os.environ.get("BASE_URL", "").rstrip("/")
GOOGLE_CLIENT_ID  = os.environ.get("GOOGLE_CLIENT_ID", "")
ADMIN_SECRET      = os.environ.get("ADMIN_SECRET", "changeme")

def get_base_url():
    return BASE_URL if BASE_URL else request.host_url.rstrip("/")

# ─────────────────────────────────────────────────────────────────────────────
# USER STORE  (in-memory; swap for SQLite/Postgres for persistence)
# ─────────────────────────────────────────────────────────────────────────────
_users_lock  = threading.Lock()
users        = {}   # google_id → user dict
auth_tokens  = {}   # auth_token → google_id  (short-lived session tokens)

def _upsert_user(google_id, email, name, picture):
    with _users_lock:
        if google_id in users:
            u = users[google_id]
            u["last_login"]  = now_ts()
            u["login_count"] += 1
            u["name"]        = name       # refresh in case changed
            u["picture"]     = picture
        else:
            u = {
                "google_id":    google_id,
                "email":        email,
                "name":         name,
                "picture":      picture,
                "created_at":   now_ts(),
                "last_login":   now_ts(),
                "login_count":  1,
                "session_count": 0,       # incremented on each /create call
            }
            users[google_id] = u
        token = secrets.token_urlsafe(32)
        auth_tokens[token] = google_id
        # Expire old tokens for this user (keep last 5 only)
        owned = [t for t,g in auth_tokens.items() if g == google_id]
        if len(owned) > 5:
            for old in owned[:-5]:
                auth_tokens.pop(old, None)
        return u, token

def _get_user_by_token(token):
    with _users_lock:
        gid = auth_tokens.get(token)
        return users.get(gid) if gid else None

def _user_snapshot(u):
    return {k: v for k, v in u.items() if k != "google_id"}

# ─────────────────────────────────────────────────────────────────────────────
# SESSION STORE
# ─────────────────────────────────────────────────────────────────────────────
_registry_lock = threading.Lock()
sessions       = {}
sse_queues     = {}

COMPASS = ["N","NNE","NE","ENE","E","ESE","SE","SSE","S","SSW","SW","WSW","W","WNW","NW","NNW"]

def compass(d):   return COMPASS[round(d/22.5)%16] if d is not None else None
def now_ts():     return time.time()
def mask_ip(ip):
    if not ip: return None
    p = ip.split(".")
    return f"{p[0]}.{p[1]}.{p[2]}.0" if len(p)==4 else ip
def get_ip():
    fwd = request.headers.get("X-Forwarded-For")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "unknown"
def haversine(lat1,lon1,lat2,lon2):
    R=6_371_000
    f1,f2=math.radians(lat1),math.radians(lat2)
    df,dl=math.radians(lat2-lat1),math.radians(lon2-lon1)
    a=math.sin(df/2)**2+math.cos(f1)*math.cos(f2)*math.sin(dl/2)**2
    return R*2*math.atan2(math.sqrt(a),math.sqrt(1-a))

def create_session(watcher_name, duration_minutes, google_id=None):
    token = secrets.token_urlsafe(32)
    s = {
        "lock": threading.RLock(),
        "token": token,
        "created_at": now_ts(),
        "expires_at": now_ts() + duration_minutes*60,
        "duration_minutes": duration_minutes,
        "is_active": True,
        "watcher_name": watcher_name or "Parent",
        "google_id": google_id,          # ties session to a user account
        "emergency_mode": True,
        "sharer": None,
        "stats": {
            "total_distance":0.0,"max_speed":0.0,
            "_speed_sum":0.0,"_speed_count":0,
            "avg_speed":0.0,"best_accuracy":None,
            "max_altitude":None,"update_count":0,
        },
    }
    with _registry_lock:
        sessions[token]   = s
        sse_queues[token] = []
    # Increment user session counter
    if google_id:
        with _users_lock:
            if google_id in users:
                users[google_id]["session_count"] += 1
    return s

def is_expired(s): return not s["is_active"] or now_ts() > s["expires_at"]
def _make_sharer(name):
    return {"name":name,"consented":True,"is_sharing":True,
            "logs":deque(maxlen=2000),"joined_at":now_ts(),"last_seen":now_ts()}

# ─────────────────────────────────────────────────────────────────────────────
# SSE
# ─────────────────────────────────────────────────────────────────────────────
def _push_sse(token, event, data):
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    with _registry_lock:
        qs = list(sse_queues.get(token, []))
    dead = []
    for q in qs:
        try:   q.put_nowait(msg)
        except queue.Full: dead.append(q)
    if dead:
        with _registry_lock:
            bucket = sse_queues.get(token,[])
            for q in dead:
                try: bucket.remove(q)
                except ValueError: pass

def session_snapshot(token):
    with _registry_lock:
        s = sessions.get(token)
    if not s: return None
    with s["lock"]:
        sh     = s["sharer"]
        latest = sh["logs"][-1] if sh and sh["logs"] else None
        stats  = {k:v for k,v in s["stats"].items() if not k.startswith("_")}
        return {
            "token":token,"is_active":s["is_active"] and not is_expired(s),
            "expires_at":s["expires_at"],"duration_minutes":s["duration_minutes"],
            "watcher_name":s["watcher_name"],"emergency_mode":True,
            "sharer":{
                "name":sh["name"],"consented":sh["consented"],
                "is_sharing":sh["is_sharing"],"log_count":len(sh["logs"]),
                "latest":latest,"joined_at":sh["joined_at"],
            } if sh else None,
            "stats":stats,
        }

# ─────────────────────────────────────────────────────────────────────────────
# LOCATION
# ─────────────────────────────────────────────────────────────────────────────
def add_location(token,lat,lng,accuracy,altitude,speed,heading):
    with _registry_lock:
        s = sessions.get(token)
    if not s: return None,"Session not found"
    with s["lock"]:
        if is_expired(s): return None,"Session expired"
        sh = s["sharer"]
        if not sh: return None,"Not joined"
        if not sh.get("consented"):
            sh["consented"]=True; sh["is_sharing"]=True
        logs=sh["logs"]; stats=s["stats"]; prev=logs[-1] if logs else None
        dist=0.0; derived_speed=None
        if prev:
            dist=haversine(prev["lat"],prev["lng"],lat,lng)
            dt=now_ts()-prev["ts"]
            if speed is None and dt>0.5: derived_speed=dist/dt
            stats["total_distance"]+=dist
        eff=speed if speed is not None else (derived_speed or 0.0)
        if eff>stats["max_speed"]: stats["max_speed"]=eff
        stats["_speed_sum"]+=eff; stats["_speed_count"]+=1
        stats["avg_speed"]=stats["_speed_sum"]/stats["_speed_count"]
        stats["update_count"]+=1
        if accuracy is not None and (stats["best_accuracy"] is None or accuracy<stats["best_accuracy"]):
            stats["best_accuracy"]=accuracy
        if altitude is not None and (stats["max_altitude"] is None or altitude>stats["max_altitude"]):
            stats["max_altitude"]=altitude
        entry={
            "id":uuid.uuid4().hex[:8],"lat":round(lat,8),"lng":round(lng,8),
            "accuracy":    round(accuracy,2)      if accuracy      is not None else None,
            "altitude":    round(altitude,2)      if altitude      is not None else None,
            "speed":       round(speed,3)         if speed         is not None else None,
            "derived_speed":round(derived_speed,3)if derived_speed is not None else None,
            "heading":     round(heading,1)       if heading       is not None else None,
            "heading_label":compass(heading),"dist_from_prev":round(dist,2),
            "ip":mask_ip(get_ip()),"ts":now_ts(),
        }
        logs.append(entry); sh["last_seen"]=now_ts()
        push={
            "lat":entry["lat"],"lng":entry["lng"],"accuracy":entry["accuracy"],
            "altitude":entry["altitude"],"speed":entry["speed"],
            "derived_speed":entry["derived_speed"],"heading":entry["heading"],
            "heading_label":entry["heading_label"],"dist_from_prev":entry["dist_from_prev"],
            "ts":entry["ts"],"log_count":len(logs),"sharer_name":sh["name"],
            "stats":{k:v for k,v in stats.items() if not k.startswith("_")},
        }
        _push_sse(token,"location_update",push)
        return entry,None

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
def _cleanup_loop():
    while True:
        time.sleep(120)
        cutoff=now_ts()-600
        with _registry_lock:
            dead=[t for t,s in sessions.items() if s["expires_at"]<cutoff]
        for t in dead:
            with _registry_lock:
                sessions.pop(t,None); sse_queues.pop(t,None)
        # Also expire old auth tokens (older than 30 days)
        token_cutoff = now_ts() - 30*86400
        with _users_lock:
            dead_tokens = []
            for tok, gid in auth_tokens.items():
                u = users.get(gid)
                if u and u.get("last_login",0) < token_cutoff:
                    dead_tokens.append(tok)
            for tok in dead_tokens:
                auth_tokens.pop(tok, None)

threading.Thread(target=_cleanup_loop, daemon=True).start()

# ─────────────────────────────────────────────────────────────────────────────
# CORS + helpers
# ─────────────────────────────────────────────────────────────────────────────
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return resp

@app.route("/api/<path:p>", methods=["OPTIONS"])
def options(p): return "",204

def _get_auth_user():
    """Extract user from Authorization: Bearer <token> header."""
    hdr = request.headers.get("Authorization","")
    if not hdr.startswith("Bearer "): return None
    return _get_user_by_token(hdr[7:].strip())

def _require_admin():
    secret = request.headers.get("X-Admin-Secret","") or request.args.get("secret","")
    return secret == ADMIN_SECRET

# ─────────────────────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/auth/google", methods=["POST"])
def auth_google():
    """
    Verify a Google ID token sent from the frontend GSI library.
    Returns a SafeTrace auth token + user profile.
    """
    body     = request.get_json(silent=True) or {}
    id_token = body.get("id_token","").strip()
    if not id_token:
        return jsonify({"error":"id_token required"}),400

    # Verify with Google's tokeninfo endpoint (no extra library needed)
    try:
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return jsonify({"error":"Invalid Google token"}),401
    except Exception as e:
        return jsonify({"error":"Token verification failed"}),500

    # Validate audience matches our client ID (skip if GOOGLE_CLIENT_ID not set — dev mode)
    if GOOGLE_CLIENT_ID and payload.get("aud") != GOOGLE_CLIENT_ID:
        return jsonify({"error":"Token audience mismatch"}),401

    google_id = payload.get("sub")
    email     = payload.get("email","")
    name      = payload.get("name","")
    picture   = payload.get("picture","")

    if not google_id:
        return jsonify({"error":"Could not extract user from token"}),401

    user, auth_token = _upsert_user(google_id, email, name, picture)
    return jsonify({
        "auth_token": auth_token,
        "user": {
            "name":    user["name"],
            "email":   user["email"],
            "picture": user["picture"],
            "session_count": user["session_count"],
            "created_at":    user["created_at"],
        }
    }), 200

@app.route("/api/auth/me")
def auth_me():
    user = _get_auth_user()
    if not user:
        return jsonify({"error":"Unauthorized"}),401
    return jsonify({"user": _user_snapshot(user)})

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    hdr = request.headers.get("Authorization","")
    if hdr.startswith("Bearer "):
        tok = hdr[7:].strip()
        with _users_lock:
            auth_tokens.pop(tok, None)
    return jsonify({"success":True})

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/admin/stats")
def admin_stats():
    if not _require_admin():
        return jsonify({"error":"Forbidden"}),403
    with _users_lock:
        total_users       = len(users)
        total_logins      = sum(u["login_count"] for u in users.values())
        total_sessions    = sum(u["session_count"] for u in users.values())
        new_today         = sum(1 for u in users.values()
                                if now_ts()-u["created_at"] < 86400)
        active_today      = sum(1 for u in users.values()
                                if now_ts()-u["last_login"] < 86400)
    with _registry_lock:
        live_sessions     = sum(1 for s in sessions.values() if not is_expired(s))
        total_sse_conns   = sum(len(q) for q in sse_queues.values())
    return jsonify({
        "total_users":    total_users,
        "new_today":      new_today,
        "active_today":   active_today,
        "total_logins":   total_logins,
        "total_sessions_created": total_sessions,
        "live_sessions":  live_sessions,
        "sse_connections":total_sse_conns,
        "ts": now_ts(),
    })

@app.route("/api/admin/users")
def admin_users():
    if not _require_admin():
        return jsonify({"error":"Forbidden"}),403
    page     = max(1, int(request.args.get("page",1)))
    per_page = min(100, int(request.args.get("per_page",50)))
    sort_by  = request.args.get("sort","last_login")   # last_login|created_at|session_count
    with _users_lock:
        all_users = list(users.values())
    all_users.sort(key=lambda u: u.get(sort_by,0), reverse=True)
    total  = len(all_users)
    start  = (page-1)*per_page
    page_u = all_users[start:start+per_page]
    return jsonify({
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "users": [{
            "name":          u["name"],
            "email":         u["email"],
            "picture":       u["picture"],
            "created_at":    u["created_at"],
            "last_login":    u["last_login"],
            "login_count":   u["login_count"],
            "session_count": u["session_count"],
        } for u in page_u],
    })

@app.route("/admin")
def admin_page():
    return send_from_directory("static","admin.html")

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    with _registry_lock:
        total  = len(sessions)
        active = sum(1 for s in sessions.values() if not is_expired(s))
        conns  = sum(len(q) for q in sse_queues.values())
    with _users_lock:
        u_total = len(users)
    return jsonify({"status":"ok","sessions_total":total,"sessions_active":active,
                    "sse_connections":conns,"registered_users":u_total,"ts":now_ts()})

# ─────────────────────────────────────────────────────────────────────────────
# EMERGENCY ROUTES (unchanged logic, google_id attached to sessions now)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/emergency/create", methods=["POST"])
def emergency_create():
    body     = request.get_json(silent=True) or {}
    name     = str(body.get("watcher_name","Parent"))[:30]
    duration = max(15,min(480,int(body.get("duration_minutes",120))))
    # Try to attach to logged-in user (optional — works without login too)
    user = _get_auth_user()
    google_id = user["google_id"] if user else None
    if user: name = user["name"]  # use their real Google name
    s    = create_session(name, duration, google_id)
    base = get_base_url()
    return jsonify({
        "token":s["token"],
        "track_url":f"{base}/track/{s['token']}",
        "watch_url": f"{base}/watch/{s['token']}",
        "expires_at":s["expires_at"],
        "duration_minutes":s["duration_minutes"],
        "watcher_name":s["watcher_name"],
        "emergency_mode":True,
    }),201

@app.route("/api/emergency/activate/<token>", methods=["POST"])
def emergency_activate(token):
    with _registry_lock: s=sessions.get(token)
    if not s or is_expired(s): return jsonify({"error":"Session not found or expired"}),404
    body=request.get_json(silent=True) or {}
    sharer_name=str(body.get("sharer_name","Child"))[:30]
    with s["lock"]:
        if not s["sharer"]: s["sharer"]=_make_sharer(sharer_name)
        else:
            s["sharer"]["consented"]=True; s["sharer"]["is_sharing"]=True
        name=s["sharer"]["name"]
    _push_sse(token,"sharer_active",{"name":name})
    _push_sse(token,"sharer_consented",{"name":name})
    return jsonify({"token":token,"sharer_name":name,
                    "watcher_name":s["watcher_name"],"expires_at":s["expires_at"]}),200

@app.route("/api/emergency/join/<token>", methods=["POST"])
def emergency_join(token):
    with _registry_lock: s=sessions.get(token)
    if not s or is_expired(s): return jsonify({"error":"Session not found or expired"}),404
    body=request.get_json(silent=True) or {}
    sharer_name=str(body.get("sharer_name","Child"))[:30]
    with s["lock"]:
        if not s["sharer"]: s["sharer"]=_make_sharer(sharer_name)
        name=s["sharer"]["name"]
    _push_sse(token,"sharer_active",{"name":name})
    return jsonify({"token":token,"sharer_name":name,
                    "watcher_name":s["watcher_name"],"expires_at":s["expires_at"]}),201

@app.route("/api/emergency/consent/<token>", methods=["POST"])
def emergency_consent(token):
    with _registry_lock: s=sessions.get(token)
    if not s or is_expired(s): return jsonify({"error":"Session expired"}),410
    with s["lock"]:
        if not s["sharer"]: return jsonify({"error":"Must join first"}),400
        s["sharer"]["consented"]=True; s["sharer"]["is_sharing"]=True
        name=s["sharer"]["name"]
    _push_sse(token,"sharer_consented",{"name":name})
    return jsonify({"success":True})

@app.route("/api/emergency/location/<token>", methods=["POST"])
def emergency_location(token):
    body=request.get_json(silent=True) or {}
    lat,lng=body.get("lat"),body.get("lng")
    if lat is None or lng is None: return jsonify({"error":"lat and lng required"}),422
    try:
        lat,lng=float(lat),float(lng)
        if not(-90<=lat<=90 and -180<=lng<=180): return jsonify({"error":"Out of range"}),422
    except(TypeError,ValueError): return jsonify({"error":"Invalid coordinates"}),422
    def _f(k): v=body.get(k); return float(v) if v is not None else None
    entry,err=add_location(token,lat,lng,_f("accuracy"),_f("altitude"),_f("speed"),_f("heading"))
    if err: return jsonify({"error":err}),410
    return jsonify({"success":True,"ts":entry["ts"],"id":entry["id"]}),201

@app.route("/api/emergency/status/<token>")
def emergency_status(token):
    snap=session_snapshot(token)
    if not snap: return jsonify({"error":"Session not found"}),404
    return jsonify(snap)

@app.route("/api/emergency/logs/<token>")
def emergency_logs(token):
    with _registry_lock: s=sessions.get(token)
    if not s: return jsonify({"error":"Not found"}),404
    with s["lock"]:
        logs=list(s["sharer"]["logs"]) if s["sharer"] else []
        stats={k:v for k,v in s["stats"].items() if not k.startswith("_")}
    return jsonify({"logs":logs,"count":len(logs),"stats":stats})

@app.route("/api/emergency/stream/<token>")
def emergency_stream(token):
    with _registry_lock: s=sessions.get(token)
    if not s: return jsonify({"error":"Not found"}),404
    my_q=queue.Queue(maxsize=64)
    with _registry_lock: sse_queues.setdefault(token,[]).append(my_q)
    snap=session_snapshot(token)
    my_q.put_nowait(f"event: init\ndata: {json.dumps(snap)}\n\n")
    def generate():
        try:
            while True:
                try:    yield my_q.get(timeout=25)
                except queue.Empty:
                    yield f"event: ping\ndata: {json.dumps({'ts':now_ts()})}\n\n"
        except GeneratorExit: pass
        finally:
            with _registry_lock:
                bucket=sse_queues.get(token,[])
                try: bucket.remove(my_q)
                except ValueError: pass
    return Response(generate(),mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"})

@app.route("/api/emergency/end/<token>", methods=["DELETE"])
def emergency_end(token):
    with _registry_lock: s=sessions.get(token)
    if s:
        with s["lock"]: s["is_active"]=False
        _push_sse(token,"session_ended",{"message":"Session ended."})
    return jsonify({"success":True})

@app.route("/api/emergency/leave/<token>", methods=["DELETE"])
def emergency_leave(token):
    name="Child"
    with _registry_lock: s=sessions.get(token)
    if s:
        with s["lock"]:
            if s["sharer"]:
                name=s["sharer"]["name"]
                s["sharer"]["is_sharing"]=False; s["sharer"]["consented"]=False
        _push_sse(token,"sharer_stopped",{"message":f"{name} stopped sharing."})
    return jsonify({"success":True})

@app.route("/api/emergency/extend/<token>", methods=["POST"])
def emergency_extend(token):
    with _registry_lock: s=sessions.get(token)
    if not s: return jsonify({"error":"Session not found"}),404
    body=request.get_json(silent=True) or {}
    extra=max(15,min(120,int(body.get("extra_minutes",30))))
    with s["lock"]:
        if is_expired(s): return jsonify({"error":"Session already expired"}),410
        s["expires_at"]+=extra*60; s["duration_minutes"]+=extra
        exp,dur=s["expires_at"],s["duration_minutes"]
    _push_sse(token,"session_extended",{"expires_at":exp,"extra_minutes":extra,"duration_minutes":dur})
    return jsonify({"success":True,"expires_at":exp,"extra_minutes":extra})

# Legacy aliases
@app.route("/api/create",          methods=["POST"])
def lc(): return emergency_create()
@app.route("/api/join/<t>",        methods=["POST"])
def lj(t): return emergency_join(t)
@app.route("/api/consent/<t>",     methods=["POST"])
def lcn(t): return emergency_consent(t)
@app.route("/api/location/<t>",    methods=["POST"])
def ll(t): return emergency_location(t)
@app.route("/api/status/<t>")
def ls(t): return emergency_status(t)
@app.route("/api/logs/<t>")
def llg(t): return emergency_logs(t)
@app.route("/api/stream/<t>")
def lst(t): return emergency_stream(t)
@app.route("/api/end/<t>",         methods=["DELETE"])
def le(t): return emergency_end(t)
@app.route("/api/leave/<t>",       methods=["DELETE"])
def llv(t): return emergency_leave(t)

# ─────────────────────────────────────────────────────────────────────────────
# FRONTEND
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
@app.route("/watch/<token>")
@app.route("/track/<token>")
def frontend(token=None): return send_from_directory("static","index.html")

if __name__=="__main__":
    port=int(os.environ.get("PORT",8000))
    print(f"\n✅  SafeTrace → http://localhost:{port}")
    if not GOOGLE_CLIENT_ID:
        print("⚠️   GOOGLE_CLIENT_ID not set — auth runs in dev mode (no token verification)")
    print(f"🔐  Admin dashboard → http://localhost:{port}/admin  (secret: {ADMIN_SECRET})")
    print(f"\n⚡  Production: gunicorn -w 1 -k gevent --worker-connections 2000 -b 0.0.0.0:{port} server:app\n")
    app.run(host="0.0.0.0",port=port,threaded=True)
