"""TanchTV — web UI for TVs/boxes on HDMI capture cards: live video + remote control.

Auth: own login page + cookie sessions (SQLite in /data), optional Google sign-in.
Roles: admin (everything) and viewer (video only; remote only if an admin allows it).
The built-in "admin" account can't be disabled/demoted/deleted from the UI — only via cli.py.

Ports: each capture card ("port") has its own video streams (go2rtc p<id>, p<id>_sd) and its own remote driver
(remotes.py: Android TV / Fire TV / Apple TV). Admins manage ports in Settings -> Ports; the go2rtc config is
generated from the ports table (ports.py) and applied through go2rtc's API.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import time
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

import aiohttp
from aiohttp import WSMsgType, web
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from db import DB, hash_password, verify_password, db_path
from ports import build_go2rtc_yaml, list_capture_devices, stream_names
from remotes import APPS, KEYS, KINDS, RemoteError, Remotes

log = logging.getLogger("tanchtv")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

GO2RTC = os.environ.get("GO2RTC_URL", "http://127.0.0.1:1984").rstrip("/")
GO2RTC_RTSP = os.environ.get("GO2RTC_RTSP", "rtsp://127.0.0.1:18554").rstrip("/")
DATA = Path(os.environ.get("DATA_DIR", "/data"))
PORT = int(os.environ.get("PORT", "8095"))
STATIC = Path(__file__).parent / "static"
COOKIE = "tvr_session"

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"

# ======================================================================================
# Helpers
# ======================================================================================
def db_(request) -> DB:
    return request.app["db"]


def remotes(request) -> Remotes:
    return request.app["remotes"]


def first_port_id(db: DB):
    ps = db.ports()
    return ps[0]["id"] if ps else None


def req_port(request, from_query=False):
    """The port named in the URL (/{pid}/) or ?port=; None if it doesn't exist."""
    raw = request.query.get("port") if from_query else request.match_info.get("pid")
    db = db_(request)
    if raw in (None, ""):
        pid = first_port_id(db)
    else:
        try:
            pid = int(raw)
        except ValueError:
            return None
    return db.port(pid) if pid is not None else None


def client_ip(request) -> str:
    return (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Real-IP")
        or (request.headers.get("X-Forwarded-For", "").split(",")[0].strip())
        or (request.remote or "")
    )


def is_https(request) -> bool:
    return request.headers.get("X-Forwarded-Proto", request.scheme) == "https"


def base_url(request) -> str:
    configured = db_(request).get("public_url").rstrip("/")
    if configured:
        return configured
    return f"{'https' if is_https(request) else 'http'}://{request.host}"


def is_admin(u) -> bool:
    return bool(u) and u["role"] == "admin"


def can_control(u) -> bool:
    return bool(u) and (u["role"] == "admin" or bool(u["can_control"]))


def public_user(u) -> dict:
    return {
        "id": u["id"], "username": u["username"], "display_name": u["display_name"] or u["username"],
        "email": u["email"], "role": u["role"], "can_control": can_control(u), "is_root": bool(u["is_root"]),
        "has_password": bool(u["password_hash"]), "google": bool(u["google_sub"]),
    }


def jerr(msg: str, status: int = 400):
    return web.json_response({"error": msg}, status=status)


async def body(request) -> dict:
    try:
        d = await request.json()
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def set_session_cookie(request, resp, token: str) -> None:
    resp.set_cookie(COOKIE, token, max_age=30 * 86400, httponly=True, samesite="Lax", secure=is_https(request), path="/")


def google_enabled(db: DB) -> bool:
    return db.get("google_enabled") == "1" and bool(db.get("google_client_id")) and bool(db.get("google_client_secret"))


# Simple per-IP login throttle: 8 failures / 15 min.
_fails: dict[str, list[float]] = {}


def throttled(ip: str) -> bool:
    now = time.time()
    _fails[ip] = [t for t in _fails.get(ip, []) if now - t < 900]
    return len(_fails[ip]) >= 8


def note_fail(ip: str) -> None:
    _fails.setdefault(ip, []).append(time.time())


# ======================================================================================
# Middleware: session + CSRF
# ======================================================================================
# /vlc/<token>/... is public by design: VLC can't log in, the secret token in the URL is the credential.
PUBLIC_PATHS = {"/login", "/healthz", "/api/login", "/api/auth/config", "/api/invite/info",
                "/api/passkeys/login/options", "/api/passkeys/login/verify",
                "/auth/google/start", "/auth/google/callback", "/favicon.ico"}


@web.middleware
async def auth_mw(request: web.Request, handler):
    request["user"] = db_(request).session_user(request.cookies.get(COOKIE, ""))
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc != request.host:
            return jerr("Cross-site request blocked", 403)
    p = request.path
    if p in PUBLIC_PATHS or p.startswith("/static/") or p.startswith("/invite/") or p.startswith("/vlc/"):
        return await handler(request)
    if not request["user"]:
        if p.startswith("/api/") or p.endswith(".js"):
            return jerr("Not signed in", 401)
        raise web.HTTPFound("/login" + ("?next=" + quote(p) if p != "/" else ""))
    return await handler(request)


def admin_only(fn):
    async def wrapper(request):
        if not is_admin(request["user"]):
            return jerr("Admins only", 403)
        return await fn(request)
    return wrapper


def control_only(fn):
    async def wrapper(request):
        if not can_control(request["user"]):
            return jerr("You don't have permission to use the remote. Ask an admin.", 403)
        return await fn(request)
    return wrapper


routes = web.RouteTableDef()


# ======================================================================================
# Pages
# ======================================================================================
@routes.get("/healthz")
async def healthz(_):
    return web.Response(text="ok")


@routes.get("/favicon.ico")
async def favicon(_):
    return web.FileResponse(STATIC / "favicon-32.png", headers={"Content-Type": "image/png", "Cache-Control": "max-age=86400"})


@routes.get("/")
@routes.get("/remote")
async def index(_):
    return web.FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


@routes.get("/login")
async def login_page(request):
    if request["user"]:
        raise web.HTTPFound("/")
    return web.FileResponse(STATIC / "login.html", headers={"Cache-Control": "no-cache"})


@routes.get("/invite/{token}")
async def invite_page(_):
    return web.FileResponse(STATIC / "login.html", headers={"Cache-Control": "no-cache"})


# ======================================================================================
# Auth API
# ======================================================================================
@routes.get("/api/auth/config")
async def auth_config(request):
    return web.json_response({"google": google_enabled(db_(request))})


@routes.post("/api/login")
async def api_login(request):
    ip = client_ip(request)
    if throttled(ip):
        return jerr("Too many attempts. Try again in a few minutes.", 429)
    d = await body(request)
    u = db_(request).user_by_name(str(d.get("username", "")))
    ok = verify_password(str(d.get("password", "")), u["password_hash"] if u else None)
    if not u or not ok or u["disabled"]:
        note_fail(ip)
        return jerr("Wrong username or password." if not (u and ok) else "This account is disabled.", 401)
    token = db_(request).create_session(u["id"], ip, request.headers.get("User-Agent", ""))
    resp = web.json_response({"ok": True})
    set_session_cookie(request, resp, token)
    return resp


@routes.post("/api/logout")
async def api_logout(request):
    db_(request).delete_session(request.cookies.get(COOKIE, ""))
    resp = web.json_response({"ok": True})
    resp.del_cookie(COOKIE, path="/")
    return resp


@routes.get("/api/me")
async def api_me(request):
    u = request["user"]
    return web.json_response({"user": public_user(u)})


@routes.post("/api/me/password")
async def api_me_password(request):
    u, d = request["user"], await body(request)
    new = str(d.get("new", ""))
    if not u["password_hash"]:
        return jerr("This account signs in with Google.", 403)
    if not verify_password(str(d.get("current", "")), u["password_hash"]):
        return jerr("Current password is wrong.")
    if len(new) < 8:
        return jerr("Use at least 8 characters.")
    db_(request).run("UPDATE users SET password_hash=? WHERE id=?", hash_password(new), u["id"])
    return web.json_response({"ok": True})


# ---- Passkeys (WebAuthn) ----
# Discoverable credentials ("passkeys"): sign-in needs no username. RP ID = the host the browser is on,
# so passkeys made on your public https name work there (browsers only allow them over https).
_pk_flows: dict[str, dict] = {}


def _pk_flow_put(data: dict) -> str:
    now = time.time()
    for k in [k for k, v in _pk_flows.items() if now - v["t"] > 300]:
        _pk_flows.pop(k, None)
    fid = secrets.token_urlsafe(16)
    _pk_flows[fid] = {"t": now, **data}
    return fid


def _pk_rp(request):
    host = request.host.split(":")[0]
    origin = f"{'https' if is_https(request) else 'http'}://{request.host}"
    if not is_https(request) and host not in ("localhost", "127.0.0.1"):
        raise web.HTTPBadRequest(text=json.dumps({"error": f"Passkeys only work over https. Open {base_url(request)} instead."}),
                                 content_type="application/json")
    return host, origin


@routes.get("/api/passkeys")
async def passkeys_list(request):
    rows = db_(request).all("SELECT id,name,created_at,last_used FROM passkeys WHERE user_id=? ORDER BY created_at",
                            request["user"]["id"])
    return web.json_response(rows)


@routes.delete("/api/passkeys/{id}")
async def passkeys_delete(request):
    n = db_(request).run("DELETE FROM passkeys WHERE id=? AND user_id=?", int(request.match_info["id"]), request["user"]["id"])
    return web.json_response({"ok": bool(n)})


@routes.post("/api/passkeys/register/options")
async def passkeys_register_options(request):
    u = request["user"]
    rp_id, origin = _pk_rp(request)
    existing = db_(request).all("SELECT credential_id FROM passkeys WHERE user_id=?", u["id"])
    opts = generate_registration_options(
        rp_id=rp_id, rp_name="TanchTV", user_id=f"tanchtv-user-{u['id']}".encode(),
        user_name=u["email"] or u["username"], user_display_name=u["display_name"] or u["username"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.PREFERRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in existing],
    )
    fid = _pk_flow_put({"challenge": opts.challenge, "uid": u["id"], "rp_id": rp_id, "origin": origin})
    return web.json_response({"flow": fid, "options": json.loads(options_to_json(opts))})


@routes.post("/api/passkeys/register/verify")
async def passkeys_register_verify(request):
    d, u = await body(request), request["user"]
    flow = _pk_flows.pop(str(d.get("flow", "")), None)
    if not flow or flow["uid"] != u["id"]:
        return jerr("That took too long. Try again.")
    cred = d.get("credential") or {}
    try:
        v = verify_registration_response(credential=cred, expected_challenge=flow["challenge"],
                                         expected_rp_id=flow["rp_id"], expected_origin=flow["origin"])
    except Exception as e:  # noqa: BLE001
        log.warning("passkey registration failed: %s", e)
        return jerr("The passkey couldn't be verified. Try again.")
    transports = (cred.get("response") or {}).get("transports") or []
    name = str(d.get("name", "")).strip()[:60] or "Passkey"
    db_(request).run(
        "INSERT INTO passkeys(user_id,credential_id,public_key,sign_count,transports,name,created_at) VALUES(?,?,?,?,?,?,?)",
        u["id"], bytes_to_base64url(v.credential_id), bytes_to_base64url(v.credential_public_key), v.sign_count,
        json.dumps(transports), name, int(time.time()))
    return web.json_response({"ok": True})


@routes.post("/api/passkeys/login/options")
async def passkeys_login_options(request):
    rp_id, origin = _pk_rp(request)
    opts = generate_authentication_options(rp_id=rp_id, user_verification=UserVerificationRequirement.PREFERRED)
    fid = _pk_flow_put({"challenge": opts.challenge, "rp_id": rp_id, "origin": origin})
    return web.json_response({"flow": fid, "options": json.loads(options_to_json(opts))})


@routes.post("/api/passkeys/login/verify")
async def passkeys_login_verify(request):
    ip = client_ip(request)
    if throttled(ip):
        return jerr("Too many attempts. Try again in a few minutes.", 429)
    d = await body(request)
    flow = _pk_flows.pop(str(d.get("flow", "")), None)
    if not flow:
        return jerr("That took too long. Try again.")
    cred = d.get("credential") or {}
    db = db_(request)
    pk = db.one("SELECT * FROM passkeys WHERE credential_id=?", str(cred.get("id", "")))
    if not pk:
        note_fail(ip)
        return jerr("This passkey isn't registered here (it may have been removed).", 401)
    try:
        v = verify_authentication_response(
            credential=cred, expected_challenge=flow["challenge"], expected_rp_id=flow["rp_id"],
            expected_origin=flow["origin"], credential_public_key=base64url_to_bytes(pk["public_key"]),
            credential_current_sign_count=pk["sign_count"])
    except Exception as e:  # noqa: BLE001
        log.warning("passkey sign-in failed: %s", e)
        note_fail(ip)
        return jerr("The passkey couldn't be verified.", 401)
    u = db.user(pk["user_id"])
    if not u or u["disabled"]:
        return jerr("This account is disabled.", 401)
    db.run("UPDATE passkeys SET sign_count=?, last_used=? WHERE id=?", v.new_sign_count, int(time.time()), pk["id"])
    token = db.create_session(u["id"], ip, request.headers.get("User-Agent", ""))
    resp = web.json_response({"ok": True})
    set_session_cookie(request, resp, token)
    return resp


# ---- invites (public side) ----
# Invited people can ONLY join with Google (no self-made username/password accounts).
# Accounts are created in google_callback, and only when a valid invite comes with the sign-in.
@routes.get("/api/invite/info")
async def invite_info(request):
    inv = db_(request).valid_invite(request.query.get("token", ""))
    if not inv:
        return jerr("This invite link is invalid, expired or already used.", 404)
    if not google_enabled(db_(request)):
        return jerr("This invite can't be used yet: Google sign-in isn't set up. Ask the admin.", 503)
    return web.json_response({"role": inv["role"], "can_control": bool(inv["can_control"]), "email": inv["email"]})


# ---- Google SSO ----
_oauth_states: dict[str, dict] = {}


@routes.get("/auth/google/start")
async def google_start(request):
    db = db_(request)
    if not google_enabled(db):
        raise web.HTTPFound("/login?error=" + quote("Google sign-in isn't set up."))
    now = time.time()
    for k in [k for k, v in _oauth_states.items() if now - v["t"] > 600]:
        _oauth_states.pop(k, None)
    state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    nxt = request.query.get("next", "/")
    _oauth_states[state] = {"t": now, "verifier": verifier, "invite": request.query.get("invite", ""),
                            "next": nxt if nxt.startswith("/") and not nxt.startswith("//") else "/"}
    params = {
        "client_id": db.get("google_client_id"), "redirect_uri": base_url(request) + "/auth/google/callback",
        "response_type": "code", "scope": "openid email profile", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account",
    }
    raise web.HTTPFound(GOOGLE_AUTH + "?" + urlencode(params))


@routes.get("/auth/google/callback")
async def google_callback(request):
    db = db_(request)

    def fail(msg, invite=""):
        target = f"/invite/{invite}" if invite else "/login"
        return web.HTTPFound(f"{target}?error=" + quote(msg))

    st = _oauth_states.pop(request.query.get("state", ""), None)
    if not st or time.time() - st["t"] > 600:
        raise fail("Sign-in expired. Try again.")
    if request.query.get("error") or not request.query.get("code"):
        raise fail("Google sign-in was cancelled.", st["invite"])
    http = request.app["http"]
    async with http.post(GOOGLE_TOKEN, data={
        "code": request.query["code"], "client_id": db.get("google_client_id"),
        "client_secret": db.get("google_client_secret"), "redirect_uri": base_url(request) + "/auth/google/callback",
        "grant_type": "authorization_code", "code_verifier": st["verifier"],
    }) as r:
        tok = await r.json(content_type=None)
    if "access_token" not in tok:
        log.warning("Google token exchange failed: %s", tok)
        raise fail("Google sign-in failed (check the client ID/secret and redirect URI).", st["invite"])
    async with http.get(GOOGLE_USERINFO, headers={"Authorization": f"Bearer {tok['access_token']}"}) as r:
        info = await r.json(content_type=None)
    sub, email = info.get("sub"), (info.get("email") or "").lower()
    if not sub or not email or not info.get("email_verified"):
        raise fail("Google didn't return a verified email.", st["invite"])

    user = db.one("SELECT * FROM users WHERE google_sub=?", sub) or db.one("SELECT * FROM users WHERE lower(email)=?", email)
    if st["invite"]:
        inv = db.valid_invite(st["invite"])
        if not inv:
            raise fail("This invite link is invalid, expired or already used.")
        if inv["email"] and inv["email"].lower() != email:
            raise fail(f"This invite is for {inv['email']}, but you signed in as {email}.", st["invite"])
        if user:
            raise fail(f"{email} already has an account. Use “Sign in” instead.")
        uid = db.create_user(db.unique_username(email.split("@")[0]), (info.get("name") or "")[:60], inv["role"],
                             inv["can_control"], email=email, google_sub=sub)
        db.use_invite(inv["id"], uid)
        user = db.user(uid)
    elif not user:
        raise fail(f"There's no account for {email}. Ask an admin for an invite.")
    if user["disabled"]:
        raise fail("This account is disabled.")
    if not user["google_sub"]:
        db.run("UPDATE users SET google_sub=? WHERE id=?", sub, user["id"])
    if not user["email"]:
        db.run("UPDATE users SET email=? WHERE id=?", email, user["id"])
    token = db.create_session(user["id"], client_ip(request), request.headers.get("User-Agent", ""))
    resp = web.HTTPFound(st["next"])
    set_session_cookie(request, resp, token)
    raise resp


# ======================================================================================
# Admin API
# ======================================================================================
@routes.get("/api/admin/users")
@admin_only
async def admin_users(request):
    rows = db_(request).all("SELECT * FROM users ORDER BY is_root DESC, role, username")
    return web.json_response([
        {**public_user(u), "disabled": bool(u["disabled"]), "raw_can_control": bool(u["can_control"]),
         "last_login": u["last_login"], "created_at": u["created_at"]} for u in rows
    ])


@routes.post("/api/admin/users/{id}")
@admin_only
async def admin_user_update(request):
    db, me, d = db_(request), request["user"], await body(request)
    u = db.user(int(request.match_info["id"]))
    if not u:
        return jerr("No such user", 404)
    if u["is_root"]:
        return jerr("The built-in admin can only be changed from the command line.", 403)
    if u["id"] == me["id"] and ("role" in d or "disabled" in d):
        return jerr("You can't change your own role or disable yourself.", 403)
    if "role" in d:
        if d["role"] not in ("admin", "viewer"):
            return jerr("Bad role")
        db.run("UPDATE users SET role=? WHERE id=?", d["role"], u["id"])
    if "can_control" in d:
        db.run("UPDATE users SET can_control=? WHERE id=?", 1 if d["can_control"] else 0, u["id"])
    if "disabled" in d:
        db.run("UPDATE users SET disabled=? WHERE id=?", 1 if d["disabled"] else 0, u["id"])
        if d["disabled"]:
            db.delete_user_sessions(u["id"])
    if "display_name" in d:
        db.run("UPDATE users SET display_name=? WHERE id=?", str(d["display_name"])[:60], u["id"])
    return web.json_response({"ok": True})


@routes.delete("/api/admin/users/{id}")
@admin_only
async def admin_user_delete(request):
    db = db_(request)
    u = db.user(int(request.match_info["id"]))
    if not u:
        return jerr("No such user", 404)
    if u["is_root"]:
        return jerr("The built-in admin can't be deleted.", 403)
    if u["id"] == request["user"]["id"]:
        return jerr("You can't delete yourself.", 403)
    db.run("DELETE FROM users WHERE id=?", u["id"])
    return web.json_response({"ok": True})


@routes.get("/api/admin/invites")
@admin_only
async def admin_invites(request):
    rows = db_(request).all(
        "SELECT i.id,i.role,i.can_control,i.email,i.note,i.created_at,i.expires_at,i.used_at,"
        " c.username AS created_by, u.username AS used_by FROM invites i"
        " LEFT JOIN users c ON c.id=i.created_by LEFT JOIN users u ON u.id=i.used_by"
        " WHERE i.used_at IS NOT NULL OR i.expires_at > ? ORDER BY i.created_at DESC LIMIT 100", int(time.time()) - 7 * 86400)
    return web.json_response(rows)


@routes.post("/api/admin/invites")
@admin_only
async def admin_invite_create(request):
    d = await body(request)
    if not google_enabled(db_(request)):
        return jerr("Turn on Google sign-in first: invited people can only join with Google.")
    role = d.get("role", "viewer")
    if role not in ("admin", "viewer"):
        return jerr("Bad role")
    email =str(d.get("email", "")).strip().lower()
    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jerr("That email doesn't look right.")
    days = max(1, min(int(d.get("days", 7) or 7), 90))
    token = db_(request).create_invite(role, bool(d.get("can_control")) or role == "admin", email or None,
                                       str(d.get("note", ""))[:80], days, request["user"]["id"])
    return web.json_response({"ok": True, "link": f"{base_url(request)}/invite/{token}"})


@routes.delete("/api/admin/invites/{id}")
@admin_only
async def admin_invite_delete(request):
    db_(request).run("DELETE FROM invites WHERE id=? AND used_at IS NULL", int(request.match_info["id"]))
    return web.json_response({"ok": True})


# ---- VLC / external player links (admin) ----
def stream_url(request, token: str) -> str:
    return f"{base_url(request)}/vlc/{token}/stream.ts"


@routes.get("/api/admin/streamlinks")
@admin_only
async def admin_streamlinks(request):
    rows = db_(request).all(
        "SELECT l.id,l.name,l.created_at,l.expires_at,l.last_used,l.last_ip,u.username AS created_by,"
        " l.port_id, p.name AS port_name"
        " FROM stream_links l LEFT JOIN users u ON u.id=l.created_by LEFT JOIN ports p ON p.id=l.port_id"
        " ORDER BY l.created_at DESC")
    return web.json_response(rows)


@routes.post("/api/admin/streamlinks")
@admin_only
async def admin_streamlink_create(request):
    d = await body(request)
    db = db_(request)
    days = int(d.get("days", 0) or 0)
    try:
        port_id = int(d.get("port") or first_port_id(db) or 0)
    except (TypeError, ValueError):
        port_id = 0
    if not db.port(port_id):
        return jerr("Pick a port for the link (add one in Settings → Ports first).")
    token = secrets.token_urlsafe(24)
    now = int(time.time())
    db.run(
        "INSERT INTO stream_links(token_hash,name,created_by,created_at,expires_at,port_id) VALUES(?,?,?,?,?,?)",
        hashlib.sha256(token.encode()).hexdigest(), str(d.get("name", "")).strip()[:60] or "VLC",
        request["user"]["id"], now, now + days * 86400 if days > 0 else None, port_id)
    return web.json_response({"ok": True, "url": stream_url(request, token)})


@routes.delete("/api/admin/streamlinks/{id}")
@admin_only
async def admin_streamlink_delete(request):
    db_(request).run("DELETE FROM stream_links WHERE id=?", int(request.match_info["id"]))
    return web.json_response({"ok": True})


@routes.get("/vlc/{token}/stream.ts")
@routes.get("/vlc/{token}")
async def vlc_stream(request):
    """MPEG-TS (H.264 + AAC) over plain HTTP for VLC and other players."""
    db = db_(request)
    link = db.one("SELECT * FROM stream_links WHERE token_hash=?",
                  hashlib.sha256(request.match_info["token"].encode()).hexdigest())
    if not link or (link["expires_at"] and link["expires_at"] < time.time()):
        return web.Response(status=404, text="This stream link is invalid, expired or revoked.\n")
    port = db.port(link["port_id"]) if link["port_id"] else None
    if port is None:
        ps = db.ports()
        port = ps[0] if ps else None
    if port is None:
        return web.Response(status=404, text="This stream link's port no longer exists.\n")
    db.run("UPDATE stream_links SET last_used=?, last_ip=? WHERE id=?", int(time.time()), client_ip(request), link["id"])
    sid = "vlc-" + secrets.token_hex(4)
    v = viewers.get_or_create(sid, request, kind="vlc", label=f"VLC link: {link['name']}")
    v["path"], v["quality"], v["task"], v["port_id"] = "VLC link", "hd", asyncio.current_task(), port["id"]
    resp = web.StreamResponse(headers={"Content-Type": "video/mp2t", "Cache-Control": "no-store",
                                       "X-Accel-Buffering": "no"})
    await resp.prepare(request)
    # MPEG-TS made by ffmpeg from go2rtc's RTSP so it carries a proper PCR clock every 20 ms. go2rtc's own
    # /api/stream.ts has no PCR: VLC then improvises a clock and keeps drifting further behind live.
    # Video is copied (no re-encode). Audio: go2rtc's RTSP announces the AAC track but sends no packets on it
    # (ffmpeg then waits 10 s and outputs no sound), so take the Opus track and convert it to AAC.
    proc = await asyncio.create_subprocess_exec(
        "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error",
        "-fflags", "nobuffer", "-analyzeduration", "500000", "-probesize", "500000",
        "-rtsp_transport", "tcp", "-i", f"{GO2RTC_RTSP}/{stream_names(port['id'])[0]}?video=h264&audio=opus",
        "-map", "0:v", "-map", "0:a", "-c:v", "copy", "-c:a", "aac", "-b:a", "160k",
        "-f", "mpegts", "-pcr_period", "20", "-muxdelay", "0", "-muxpreload", "0",
        "-flush_packets", "1", "pipe:1",
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        checked = time.monotonic()
        while True:
            chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=30)
            if not chunk:
                break
            await resp.write(chunk)                     # blocks while the player isn't reading (paused)
            v["bytes"] += len(chunk)
            v["last_progress"] = v["last_seen"] = time.time()
            # Every 5 s: revoking a link also cuts a VLC session that's already playing.
            if time.monotonic() - checked > 5:
                checked = time.monotonic()
                if not db.one("SELECT 1 FROM stream_links WHERE id=?", link["id"]):
                    break
    except (ConnectionResetError, asyncio.CancelledError, asyncio.TimeoutError, aiohttp.ClientError):
        pass
    finally:
        viewers.s.pop(sid, None)
        if proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except Exception:  # noqa: BLE001
                pass
    return resp


@routes.get("/api/admin/settings")
@admin_only
async def admin_settings(request):
    db = db_(request)
    return web.json_response({
        "google_enabled": db.get("google_enabled") == "1",
        "google_client_id": db.get("google_client_id"),
        "google_client_secret_set": bool(db.get("google_client_secret")),
        "public_url": db.get("public_url"),
        "redirect_uri": base_url(request) + "/auth/google/callback",
    })


@routes.post("/api/admin/settings")
@admin_only
async def admin_settings_save(request):
    db, d = db_(request), await body(request)
    # Validate everything first, then write — a rejected save never leaves half-saved values.
    new: dict[str, str] = {}
    if "public_url" in d:
        url = str(d["public_url"]).strip().rstrip("/")
        if url and not re.match(r"^https?://[^/\s]+$", url):
            return jerr("Public URL must look like https://shield.example.com (no path).")
        new["public_url"] = url
    if "google_client_id" in d:
        cid = str(d["google_client_id"]).strip()
        if cid and not cid.endswith(".apps.googleusercontent.com"):
            return jerr("The client ID should end with .apps.googleusercontent.com")
        new["google_client_id"] = cid
    if str(d.get("google_client_secret") or "").strip():
        new["google_client_secret"] = str(d["google_client_secret"]).strip()
    if d.get("google_client_secret_clear"):
        new["google_client_secret"] = ""
    if "google_enabled" in d:
        cid = new.get("google_client_id", db.get("google_client_id"))
        sec = new.get("google_client_secret", db.get("google_client_secret"))
        if d["google_enabled"] and not cid:
            return jerr("Enter the client ID before turning on Google sign-in.")
        if d["google_enabled"] and not sec:
            return jerr("Enter the client secret before turning on Google sign-in.")
        new["google_enabled"] = "1" if d["google_enabled"] else "0"
    for k, v in new.items():
        db.set(k, v)
    return web.json_response({"ok": True})


# ======================================================================================
# Ports: capture card + device + remote driver
# ======================================================================================
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")
USB_RE = re.compile(r"^\d+-[\d.]+$")


def port_view(request, p, admin: bool) -> dict:
    drv = remotes(request).get(p["id"])
    hd, sd = stream_names(p["id"])
    d = {"id": p["id"], "name": p["name"], "kind": p["kind"], "kind_label": KINDS.get(p["kind"], p["kind"]),
         "apps": [{"id": k, "name": v["name"]} for k, v in APPS.items()],
         "unsupported": sorted(drv.unsupported) if drv else [], "remote": drv.state if drv else "error"}
    if admin:
        d.update(usb=p["usb"], host=p["host"], adb_enabled=bool(p["adb_enabled"]), streams=[hd, sd],
                 pairing_help=drv.pairing_help if drv else "", remote_error=drv.error if drv else "")
    return d


async def sync_go2rtc(app) -> bool:
    """Write the go2rtc config for the current ports and restart go2rtc if anything changed."""
    want = build_go2rtc_yaml(app["db"].ports())
    http = app["http"]
    try:
        async with http.get(f"{GO2RTC}/api/config", timeout=aiohttp.ClientTimeout(total=10)) as r:
            have = await r.text()
    except Exception as e:  # noqa: BLE001
        log.warning("go2rtc config read failed: %s", e)
        have = ""
    if have.strip() == want.strip():
        return False
    async with http.post(f"{GO2RTC}/api/config", data=want.encode(), timeout=aiohttp.ClientTimeout(total=10)) as r:
        if r.status >= 300:
            raise RuntimeError(f"go2rtc rejected the config ({r.status}): {(await r.text())[:200]}")
    try:
        async with http.post(f"{GO2RTC}/api/restart", timeout=aiohttp.ClientTimeout(total=5)) as r:
            log.info("go2rtc restart -> %s", r.status)
    except Exception:  # noqa: BLE001  (the connection drops while it restarts)
        pass
    for _ in range(40):                                   # wait until it's back
        await asyncio.sleep(0.5)
        try:
            async with http.get(f"{GO2RTC}/api", timeout=aiohttp.ClientTimeout(total=2)) as r:
                if r.status == 200:
                    break
        except Exception:  # noqa: BLE001
            pass
    log.info("go2rtc config updated for %d port(s)", len(app["db"].ports()))
    return True


@routes.get("/api/ports")
async def ports_list(request):
    u = request["user"]
    return web.json_response([port_view(request, p, is_admin(u)) for p in db_(request).ports()])


@routes.get("/api/ports/{pid}/status")
async def port_status(request):
    u, p = request["user"], req_port(request)
    if not p:
        return jerr("No such port", 404)
    sig = signals.get(p["id"])
    if not can_control(u):
        return web.json_response({"kind": p["kind"], **sig})
    drv = remotes(request).get(p["id"])
    return web.json_response({**(drv.status(is_admin(u)) if drv else {"remote": "error"}), **sig})


async def _drv_call(request, fn):
    p = req_port(request)
    if not p:
        return jerr("No such port", 404)
    drv = remotes(request).get(p["id"])
    if not drv:
        return jerr("This port has no remote.", 503)
    try:
        via = await fn(drv)
    except RemoteError as e:
        return jerr(str(e), 503)
    except Exception as e:  # noqa: BLE001
        log.warning("remote call failed on port %s: %s", p["id"], e)
        return jerr(f"{type(e).__name__}: {e}", 503)
    return web.json_response({"ok": True, "via": via})


def parse_key(d) -> tuple[str, str] | None:
    k = str(d.get("key", "")).upper().removeprefix("KEYCODE_")
    direction = str(d.get("direction", "SHORT")).upper()
    if k not in KEYS or direction not in ("SHORT", "START_LONG", "END_LONG"):
        return None
    return k, direction


@routes.post("/api/ports/{pid}/key")
@control_only
async def port_key(request):
    parsed = parse_key(await body(request))
    if not parsed:
        return jerr("bad key")
    k, direction = parsed
    return await _drv_call(request, lambda drv: drv.key(k, direction))


@routes.post("/api/ports/{pid}/text")
@control_only
async def port_text(request):
    t = str((await body(request)).get("text", ""))[:500]
    if not t:
        return jerr("empty")
    return await _drv_call(request, lambda drv: drv.text(t))


@routes.post("/api/ports/{pid}/app")
@control_only
async def port_app(request):
    app_id = str((await body(request)).get("app", ""))
    if app_id not in APPS:
        return jerr("Unknown app")
    return await _drv_call(request, lambda drv: drv.launch(app_id))


# ---- admin: devices + ports ----
@routes.get("/api/admin/devices")
@admin_only
async def admin_devices(request):
    used = {p["usb"]: p for p in db_(request).ports()}
    out = []
    for dev in list_capture_devices():
        p = used.get(dev["usb"])
        out.append({**dev, "port_id": p["id"] if p else None, "port_name": p["name"] if p else None})
    return web.json_response({"devices": out, "kinds": KINDS})


def _validate_port(d, partial=False):
    out = {}
    if "name" in d or not partial:
        name = str(d.get("name", "")).strip()[:40]
        if not name:
            return out, "Give the port a name (e.g. Living room Shield)."
        out["name"] = name
    if "usb" in d or not partial:
        usb = str(d.get("usb", "")).strip()
        if not USB_RE.match(usb):
            return out, "Pick a capture device."
        out["usb"] = usb
    if "kind" in d or not partial:
        kind = str(d.get("kind", ""))
        if kind not in KINDS:
            return out, "Pick the device type."
        out["kind"] = kind
    if "host" in d or not partial:
        host = str(d.get("host", "")).strip()
        if host and not HOST_RE.match(host):
            return out, "The device address should be an IP or hostname."
        out["host"] = host
    if "adb_enabled" in d:
        out["adb_enabled"] = 1 if d["adb_enabled"] else 0
    return out, None


async def _apply_port_change(request, pid, restream: bool):
    p = db_(request).port(pid)
    if p:
        await remotes(request).add(p)
    else:
        await remotes(request).remove(pid)
    if restream:
        try:
            await sync_go2rtc(request.app)
        except Exception as e:  # noqa: BLE001
            log.warning("go2rtc sync failed: %s", e)
            return str(e)
    return None


@routes.post("/api/admin/ports")
@admin_only
async def admin_port_create(request):
    fields, err = _validate_port(await body(request))
    if err:
        return jerr(err)
    db = db_(request)
    if db.one("SELECT 1 FROM ports WHERE usb=?", fields["usb"]):
        return jerr("That capture device is already used by another port.")
    nxt = (db.one("SELECT COALESCE(MAX(sort),0)+1 AS n FROM ports") or {"n": 1})["n"]
    pid = db.run("INSERT INTO ports(name,usb,kind,host,adb_enabled,sort,created_at) VALUES(?,?,?,?,?,?,?)",
                 fields["name"], fields["usb"], fields["kind"], fields["host"], fields.get("adb_enabled", 0),
                 nxt, int(time.time()))
    warn = await _apply_port_change(request, pid, restream=True)
    return web.json_response({"ok": True, "id": pid, "warning": warn})


@routes.post("/api/admin/ports/{pid}")
@admin_only
async def admin_port_update(request):
    p = req_port(request)
    if not p:
        return jerr("No such port", 404)
    fields, err = _validate_port(await body(request), partial=True)
    if err:
        return jerr(err)
    db = db_(request)
    if "usb" in fields and fields["usb"] != p["usb"] and db.one("SELECT 1 FROM ports WHERE usb=?", fields["usb"]):
        return jerr("That capture device is already used by another port.")
    if fields.get("kind", p["kind"]) != p["kind"]:
        fields["creds"] = "{}"                     # different device type: the old pairing is useless
        shutil.rmtree(DATA / "ports" / str(p["id"]), ignore_errors=True)
    for k, v in fields.items():                    # k comes from a fixed whitelist (_validate_port)
        db.run(f"UPDATE ports SET {k}=? WHERE id=?", v, p["id"])
    warn = await _apply_port_change(request, p["id"], restream="usb" in fields and fields["usb"] != p["usb"])
    return web.json_response({"ok": True, "warning": warn})


@routes.delete("/api/admin/ports/{pid}")
@admin_only
async def admin_port_delete(request):
    p = req_port(request)
    if not p:
        return jerr("No such port", 404)
    db = db_(request)
    db.run("DELETE FROM ports WHERE id=?", p["id"])
    db.run("UPDATE stream_links SET port_id=NULL WHERE port_id=?", p["id"])
    shutil.rmtree(DATA / "ports" / str(p["id"]), ignore_errors=True)
    for v in [x for x in viewers.s.values() if x.get("port_id") == p["id"]]:
        await viewers.kill(v["sid"], "admin")
    warn = await _apply_port_change(request, p["id"], restream=True)
    return web.json_response({"ok": True, "warning": warn})


@routes.post("/api/admin/ports/{pid}/pair/start")
@admin_only
async def admin_port_pair_start(request):
    p = req_port(request)
    drv = remotes(request).get(p["id"]) if p else None
    if not drv:
        return jerr("No such port", 404)
    try:
        return web.json_response({"ok": True, **(await drv.pair_start())})
    except RemoteError as e:
        return jerr(str(e), 503)
    except Exception as e:  # noqa: BLE001
        return jerr(f"{type(e).__name__}: {e}", 503)


@routes.post("/api/admin/ports/{pid}/pair/finish")
@admin_only
async def admin_port_pair_finish(request):
    p = req_port(request)
    drv = remotes(request).get(p["id"]) if p else None
    if not drv:
        return jerr("No such port", 404)
    code = str((await body(request)).get("code", ""))
    try:
        return web.json_response({"ok": True, **(await drv.pair_finish(code))})
    except RemoteError as e:
        return jerr(str(e))
    except Exception as e:  # noqa: BLE001
        return jerr(f"{type(e).__name__}: {e}")


@routes.post("/api/admin/ports/{pid}/adb/connect")
@admin_only
async def admin_port_adb(request):
    p = req_port(request)
    drv = remotes(request).get(p["id"]) if p else None
    if not drv or not hasattr(drv, "adb_connect"):
        return jerr("This port has no ADB.", 404)
    asyncio.create_task(_quiet(drv.adb_connect()))
    return web.json_response({"ok": True})


async def _quiet(coro):
    try:
        await coro
    except Exception:  # noqa: BLE001
        pass


# ======================================================================================
# go2rtc passthrough
# ======================================================================================
async def _get_upstream(request, path, ctype):
    async with request.app["http"].get(f"{GO2RTC}{path}") as r:
        return web.Response(body=await r.read(), status=r.status, content_type=ctype, headers={"Cache-Control": "no-cache"})


@routes.get("/video-rtc.js")
async def vr_js(request):
    return await _get_upstream(request, "/video-rtc.js", "application/javascript")


@routes.get("/api/hls/{tail:.+}")
async def hls_proxy(request):
    """HLS playlists/segments for iPhone Safari (native HLS). Signed-in users only (middleware)."""
    tail = request.match_info["tail"]
    if ".." in tail or tail.startswith("/"):
        return jerr("bad path", 400)
    url = f"{GO2RTC}/api/hls/{tail}"
    if request.query_string:
        url += "?" + request.query_string
    async with request.app["http"].get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
        return web.Response(body=await r.read(), status=r.status, content_type=r.content_type,
                            headers={"Cache-Control": "no-cache"})


@routes.get("/api/frame.jpeg")
async def frame(request):
    p = req_port(request, from_query=True)
    if not p:
        return jerr("No such port", 404)
    return await _get_upstream(request, f"/api/frame.jpeg?src={stream_names(p['id'])[0]}", "image/jpeg")


# ======================================================================================
# Viewer sessions: admin "Streams" view, kill, and the idle reaper
# ======================================================================================
# Every open player page has a session id (sid) and a small control WebSocket (/api/session) over which it
# reports {visible, playing, path} every 5 s, and through which the server can tell it to stop. The video
# itself may go through the app (MSE, /api/ws?sid=...) or directly from go2rtc (WebRTC); VLC links are
# sessions too. Anything paused (not playing) or not reporting for IDLE_KILL_S seconds is killed; a page that
# keeps playing in the background (other tab, minimized, behind a window, being screen-shared) is kept.
IDLE_KILL_S = int(os.environ.get("IDLE_KILL_SECONDS", "120"))
SID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")


def device_name(ua: str) -> str:
    ua = ua or ""
    if "VLC" in ua or "LibVLC" in ua:
        return "VLC"
    os_ = ("iPhone" if "iPhone" in ua else "iPad" if "iPad" in ua else "Android" if "Android" in ua
           else "Mac" if "Mac OS X" in ua else "Windows" if "Windows" in ua else "Linux" if "Linux" in ua else "")
    br = ("Edge" if "Edg/" in ua else "Firefox" if "Firefox/" in ua else "Chrome" if ("Chrome/" in ua or "CriOS" in ua)
          else "Safari" if "Safari/" in ua else "")
    return " · ".join(x for x in (os_, br) if x) or (ua[:30] or "unknown")


class Viewers:
    def __init__(self):
        self.s: dict[str, dict] = {}

    def get_or_create(self, sid, request, kind="web", user=None, label=""):
        v = self.s.get(sid)
        if v is None:
            now = time.time()
            ua = request.headers.get("User-Agent", "")
            v = {"sid": sid, "kind": kind, "user_id": user["id"] if user else None,
                 "user": (user["display_name"] or user["username"]) if user else label, "username": user["username"] if user else None,
                 "ip": client_ip(request), "device": device_name(ua), "started": now, "last_seen": now,
                 "visible": True, "playing": False, "path": "", "quality": "", "idle_since": now,
                 "killed": None, "killed_at": None, "control": None, "proxies": set(), "task": None,
                 "bytes": 0, "last_progress": now, "port_id": None,
                 "mode": "watch", "follow_sent": "", "keylock": asyncio.Lock()}
            self.s[sid] = v
        elif user and v["user_id"] not in (None, user["id"]):
            return None   # someone else's sid
        return v

    def drop_if_unused(self, sid):
        v = self.s.get(sid)
        if v and v["kind"] == "web" and v["control"] is None and not v["proxies"]:
            self.s.pop(sid, None)

    async def kill(self, sid, reason):
        v = self.s.get(sid)
        if not v:
            return False
        v["killed"], v["killed_at"] = reason, time.time()
        log.info("killing stream %s (%s, %s, %s): %s", sid, v["user"], v["device"], v["kind"], reason)
        ctl = v["control"]
        if ctl is not None and not ctl.closed:
            try:
                await ctl.send_json({"type": "kill", "reason": reason})
            except Exception:  # noqa: BLE001
                pass
        for ws in list(v["proxies"]):
            try:
                await ws.close(code=4001, message=b"stream stopped")
            except Exception:  # noqa: BLE001
                pass
        if v["task"] is not None:
            v["task"].cancel()
        if v["kind"] != "web":
            self.s.pop(sid, None)
        return True

    async def reaper(self):
        while True:
            await asyncio.sleep(5)
            now = time.time()
            for sid, v in list(self.s.items()):
                try:
                    if v["kind"] == "vlc":
                        if now - v["last_progress"] > IDLE_KILL_S:      # player paused / not reading
                            await self.kill(sid, "idle")
                        continue
                    if v["killed"]:
                        if v["control"] is None and now - v["killed_at"] > 60:
                            self.s.pop(sid, None)
                        continue
                    stale = now - v["last_seen"] > IDLE_KILL_S        # page stopped reporting (closed/asleep)
                    if v.get("mode") == "remote":                    # controller only, no video to stop
                        if stale and v["control"] is None:
                            self.s.pop(sid, None)
                        continue
                    idle = v["idle_since"] is not None and now - v["idle_since"] > IDLE_KILL_S
                    if stale or idle:
                        await self.kill(sid, "idle")
                except Exception as e:  # noqa: BLE001
                    log.warning("reaper: %s", e)


viewers = Viewers()


# ======================================================================================
# No-signal detection. With no HDMI input (box asleep/off/unplugged) the MS2109 keeps sending
# frames, but they are one flat colour (black: Y=7, U=V=128 everywhere). Every few seconds we take a
# small snapshot of each port and measure how flat it is; a card that's unplugged or a stream that
# gives no picture also counts as "no signal". The page shows the TanchTV test card on top.
# ======================================================================================
SIGNAL_EVERY = 4          # seconds between checks
SIGNAL_LOST_AFTER = 2     # this many flat/failed checks in a row = no signal (~8 s)
FLAT = 3                  # flat colour = every RGB channel of the 8x8 thumbnail within FLAT*4 levels


def no_signal_pattern(raw: bytes) -> str | None:
    """Look at an 8x8 RGB thumbnail. Capture cards with no HDMI input send either one flat colour
    (the MS2109 on USB 3-2: black) or their own colour bars (the one on USB 3-3: white, yellow, cyan,
    green, magenta, red, blue, black). Returns 'flat', 'bars' or None (a real picture)."""
    if len(raw) != 8 * 8 * 3:
        return None
    px = [[tuple(raw[(r * 8 + c) * 3:(r * 8 + c) * 3 + 3]) for c in range(8)] for r in range(8)]
    flat_px = [p for row in px for p in row]
    if all(max(p[i] for p in flat_px) - min(p[i] for p in flat_px) <= FLAT * 4 for i in range(3)):
        return "flat"
    cols = []
    for c in range(8):
        col = [px[r][c] for r in range(8)]
        if any(max(p[i] for p in col) - min(p[i] for p in col) > 24 for i in range(3)):
            return None                      # columns aren't solid: a real picture
        cols.append(tuple(sum(p[i] for p in col) / 8 for i in range(3)))
    hi, lo = (lambda v: v > 170), (lambda v: v < 90)
    want = ["111", "110", "011", "010", "101", "100", "001", "000"]   # R G B on/off per bar
    for (r, g, b), w in zip(cols, want):
        for v, bit in zip((r, g, b), w):
            if not (hi(v) if bit == "1" else lo(v)):
                return None
    return "bars"


class SignalWatch:
    def __init__(self):
        self.s = {}       # port id -> {"signal": bool, "since": ts, "reason": str, "bad": int}

    def get(self, pid) -> dict:
        st = self.s.get(pid)
        if not st:
            return {"signal": True}
        return {"signal": st["signal"], "signal_since": st["since"], **({"signal_reason": st["reason"]} if not st["signal"] else {})}

    async def _flat(self, http, pid) -> str | None:
        """Return why this port has no picture ('flat', 'no video') or None when it looks fine."""
        try:
            async with http.get(f"{GO2RTC}/api/frame.jpeg", params={"src": stream_names(pid)[0]},
                                timeout=aiohttp.ClientTimeout(total=6)) as r:
                if r.status != 200:
                    return "no video"
                jpg = await r.read()
        except Exception:  # noqa: BLE001
            return "no video"
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-v", "error", "-f", "image2pipe", "-i", "pipe:0",
            "-vf", "format=rgb24,scale=8:8:flags=area", "-pix_fmt", "rgb24", "-f", "rawvideo", "-",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            raw, _ = await asyncio.wait_for(proc.communicate(jpg), 10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None                      # can't tell: don't flip anything
        return no_signal_pattern(raw)

    async def check(self, app):
        ports = app["db"].ports()
        plugged = {d["usb"] for d in list_capture_devices()}
        now = time.time()
        for pid in list(self.s):
            if pid not in {p["id"] for p in ports}:
                del self.s[pid]
        for p in ports:
            reason = "unplugged" if p["usb"] not in plugged else await self._flat(app["http"], p["id"])
            st = self.s.setdefault(p["id"], {"signal": True, "since": now, "reason": "", "bad": 0})
            if reason:
                st["bad"] += 1
                if st["signal"] and (st["bad"] >= SIGNAL_LOST_AFTER or reason == "unplugged"):
                    st.update(signal=False, since=now, reason=reason)
                    log.info("port %s: no signal (%s)", p["id"], reason)
            else:
                st["bad"] = 0
                if not st["signal"]:
                    st.update(signal=True, since=now, reason="")
                    log.info("port %s: signal back", p["id"])

    async def run(self, app):
        while True:
            try:
                await self.check(app)
            except Exception as e:  # noqa: BLE001
                log.warning("signal check: %s", e)
            await asyncio.sleep(SIGNAL_EVERY)


signals = SignalWatch()


def viewer_state(v, now):
    if v["killed"]:
        return "stopped", 0
    if v["kind"] == "vlc":
        return ("watching", 0) if now - v["last_progress"] < 10 else ("paused", int(now - v["last_progress"]))
    if now - v["last_seen"] > 75:          # background tabs may report only once a minute
        return "not reporting", int(now - v["last_seen"])
    if v.get("mode") == "remote":
        return "remote control", 0
    if v["playing"]:
        return ("watching" if v["visible"] else "playing in background"), 0
    return "paused", int(now - (v["idle_since"] or now))


@routes.get("/api/session")
async def session_ws(request):
    sid = request.query.get("sid", "")
    if not SID_RE.match(sid):
        return jerr("bad sid")
    v = viewers.get_or_create(sid, request, user=request["user"])
    if v is None:
        return jerr("forbidden", 403)
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    old = v["control"]
    v["control"], v["last_seen"] = ws, time.time()
    if old is not None and not old.closed:
        await old.close()
    await ws.send_json({"type": "hello", "idle_kill": IDLE_KILL_S, "killed": v["killed"]})
    try:
        async for m in ws:
            if m.type != WSMsgType.TEXT:
                break
            try:
                d = json.loads(m.data)
            except ValueError:
                continue
            now = time.time()
            v["last_seen"] = now
            if d.get("type") == "key":
                asyncio.create_task(_socket_key(request.app, v, ws, d))
                continue
            if d.get("type") == "switch":
                await switch_followed(v, d.get("port"))
                continue
            if d.get("type") == "status":
                mode = "remote" if d.get("mode") == "remote" else "watch"
                changed = mode != v.get("mode") or d.get("port") != v.get("port_id") or bool(d.get("playing")) != v["playing"]
                v["mode"] = mode
                v["visible"], v["playing"] = bool(d.get("visible")), bool(d.get("playing"))
                v["path"], v["quality"] = str(d.get("path", ""))[:40], str(d.get("quality", ""))[:4]
                if isinstance(d.get("port"), int):
                    v["port_id"] = d["port"]
                if v["playing"] or mode == "remote":    # hidden/minimized/other tab but playing = still watched
                    v["idle_since"] = None
                elif v["idle_since"] is None:
                    v["idle_since"] = now
                if changed or mode == "remote":
                    await push_follow(v["user_id"])
            elif d.get("type") == "resume":
                v["killed"] = v["killed_at"] = None
                v["idle_since"] = now          # gets cleared by the next "playing" status
                await ws.send_json({"type": "resumed"})
    finally:
        if v["control"] is ws:
            v["control"] = None
        viewers.drop_if_unused(sid)
        await push_follow(v["user_id"])
    return ws


async def _socket_key(app, v, ws, d):
    """A remote key sent over the session socket (lower latency than one HTTP request per press).
    Keys from one page run in order; each gets an ack so the page can report errors."""
    seq = d.get("seq")
    err = None
    try:
        u = app["db"].user(v["user_id"]) if v["user_id"] else None
        parsed = parse_key(d)
        pid = d.get("port")
        drv = app["remotes"].get(pid) if isinstance(pid, int) else None
        if not u or u.get("disabled"):
            err = "Signed out."
        elif not can_control(u):
            err = "You don't have permission to use the remote. Ask an admin."
        elif not parsed:
            err = "bad key"
        elif not drv:
            err = "This port has no remote."
        else:
            async with v["keylock"]:
                await drv.key(*parsed)
    except RemoteError as e:
        err = str(e)
    except Exception as e:  # noqa: BLE001
        log.warning("socket key failed: %s", e)
        err = f"{type(e).__name__}: {e}"
    if seq is not None and not ws.closed:
        try:
            await ws.send_json({"type": "keyack", "seq": seq, "ok": err is None, **({"error": err} if err else {})})
        except Exception:  # noqa: BLE001
            pass


def follow_target(user_id):
    """The port this user is watching on another device right now (most recent playing session)."""
    now = time.time()
    best = None
    for v in viewers.s.values():
        if (v["user_id"] != user_id or v["kind"] != "web" or v.get("mode") == "remote" or v["killed"]
                or not v["playing"] or v["port_id"] is None or now - v["last_seen"] > 75):
            continue
        if best is None or v["started"] > best["started"]:
            best = v
    return best


async def push_follow(user_id):
    """Tell this user's remote-mode phones which port to control (or that nothing is playing)."""
    if user_id is None:
        return
    t = follow_target(user_id)
    msg = {"type": "follow", "port": t["port_id"] if t else None, "device": t["device"] if t else ""}
    key = f'{msg["port"]}|{msg["device"]}'
    for v in list(viewers.s.values()):
        if v["user_id"] != user_id or v.get("mode") != "remote" or v["control"] is None or v["control"].closed:
            continue
        if v.get("follow_sent") == key:
            continue
        v["follow_sent"] = key
        try:
            await v["control"].send_json(msg)
        except Exception:  # noqa: BLE001
            pass


async def switch_followed(v, port):
    """A remote-mode page picked another port while following: switch the screen it follows to it too."""
    if v.get("mode") != "remote" or not isinstance(port, int):
        return
    t = follow_target(v["user_id"])
    if not t or t["port_id"] == port or t["control"] is None or t["control"].closed:
        return
    try:
        await t["control"].send_json({"type": "setport", "port": port, "by": v["device"]})
    except Exception:  # noqa: BLE001
        pass


@routes.get("/api/admin/streams")
@admin_only
async def admin_streams(request):
    now = time.time()
    me = request.query.get("me", "")
    names = {p["id"]: p["name"] for p in db_(request).ports()}
    rows = []
    for v in sorted(viewers.s.values(), key=lambda x: x["started"]):
        state, secs = viewer_state(v, now)
        rows.append({"sid": v["sid"], "kind": v["kind"], "user": v["user"], "username": v["username"],
                     "port": names.get(v.get("port_id"), ""),
                     "device": v["device"], "ip": v["ip"], "path": v["path"], "quality": v["quality"],
                     "started": int(v["started"]), "state": state, "state_secs": secs, "mine": v["sid"] == me,
                     "bytes": v["bytes"], "can_signout": bool(v["user_id"])})
    # what go2rtc itself is serving (cross-check), excluding the always-on preload
    server = {}
    try:
        async with request.app["http"].get(f"{GO2RTC}/api/streams", timeout=aiohttp.ClientTimeout(total=5)) as r:
            for name, st in (await r.json(content_type=None) or {}).items():
                cons = [c.get("format_name", "?") for c in (st or {}).get("consumers") or [] if c.get("format_name") != "preload"]
                server[name] = {"running": bool((st or {}).get("producers")), "consumers": cons}
    except Exception as e:  # noqa: BLE001
        server = {"error": str(e)}
    return web.json_response({"idle_kill": IDLE_KILL_S, "streams": rows, "server": server})


@routes.post("/api/admin/streams/{sid}/kill")
@admin_only
async def admin_stream_kill(request):
    sid, d = request.match_info["sid"], await body(request)
    v = viewers.s.get(sid)
    if not v:
        return jerr("That stream is already gone.", 404)
    if d.get("signout") and v["user_id"]:
        target = db_(request).user(v["user_id"])
        if target and target["is_root"] and request["user"]["id"] != target["id"]:
            return jerr("The built-in admin can't be signed out from here.", 403)
        db_(request).delete_user_sessions(v["user_id"])
        for other in [x["sid"] for x in viewers.s.values() if x["user_id"] == v["user_id"]]:
            await viewers.kill(other, "signout")
        return web.json_response({"ok": True})
    await viewers.kill(sid, "admin")
    return web.json_response({"ok": True})


@routes.post("/api/admin/streams/kill-all")
@admin_only
async def admin_stream_kill_all(request):
    keep = str((await body(request)).get("keep", ""))
    n = 0
    for sid, v in list(viewers.s.items()):
        if sid != keep and not v["killed"]:
            n += await viewers.kill(sid, "admin")
    return web.json_response({"ok": True, "killed": n})


@routes.get("/api/ws")
async def ws_proxy(request):
    sid = request.query.get("sid", "")
    if not SID_RE.match(sid):
        sid = "legacy-" + secrets.token_hex(4)     # old cached page without a sid: still tracked
    v = viewers.get_or_create(sid, request, user=request["user"])
    client = web.WebSocketResponse(max_msg_size=0, heartbeat=20)
    await client.prepare(request)
    if v is None or v["killed"]:
        await client.close(code=4001, message=b"stream stopped")
        return client
    p = req_port(request, from_query=True)
    if p is None:
        await client.close(code=4004, message=b"no such port")
        return client
    v["proxies"].add(client)
    v["port_id"] = p["id"]
    hd, sd = stream_names(p["id"])
    src = sd if request.query.get("q") == "sd" else hd          # 720p light stream for phones
    try:
        async with request.app["http"].ws_connect(f"{GO2RTC}/api/ws?src={src}", max_msg_size=0) as up:
            async def pump(src, dst, count=False):
                async for m in src:
                    if m.type == WSMsgType.TEXT:
                        await dst.send_str(m.data)
                    elif m.type == WSMsgType.BINARY:
                        await dst.send_bytes(m.data)
                        if count:
                            v["bytes"] += len(m.data)
                    else:
                        break

            tasks = [asyncio.create_task(pump(client, up)), asyncio.create_task(pump(up, client, True))]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
    except aiohttp.ClientError as e:
        log.warning("go2rtc ws: %s", e)
    finally:
        v["proxies"].discard(client)
        viewers.drop_if_unused(sid)
    await client.close()
    return client


async def _startup_sync(app):
    """Push the ports' config to go2rtc. Both containers start together, so go2rtc's API may not be
    up yet: keep trying (a fresh install has no streams at all until this succeeds)."""
    for attempt in range(60):
        try:
            await sync_go2rtc(app)
            if attempt:
                log.info("go2rtc config synced after %d retries", attempt)
            return
        except Exception as e:  # noqa: BLE001
            if attempt in (0, 5, 20):
                log.warning("go2rtc not ready yet (%s); retrying", e)
            await asyncio.sleep(5)
    log.error("could not reach go2rtc at %s for 5 minutes; ports won't stream until the app restarts", GO2RTC)


async def on_startup(app):
    app["http"] = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, sock_connect=10))
    db = app["db"]

    def store(pid, fields):
        if "creds" in fields:
            db.run("UPDATE ports SET creds=? WHERE id=?", fields["creds"], pid)

    app["remotes"] = Remotes(DATA / "ports", store)
    for p in db.ports():
        await app["remotes"].add(p)
    app["go2rtc_sync"] = asyncio.create_task(_startup_sync(app))
    app["reaper"] = asyncio.create_task(viewers.reaper())
    app["signals"] = asyncio.create_task(signals.run(app))


async def on_cleanup(app):
    await app["http"].close()


def main():
    db = DB(db_path(DATA))
    generated = db.ensure_root(os.environ.get("TVR_PASSWORD", ""))
    if generated:
        log.warning("Created built-in admin. Username: admin  Password: %s  (change it in the app or with cli.py)", generated)
    app = web.Application(middlewares=[auth_mw])
    app["db"] = db
    app.add_routes(routes)
    app.router.add_static("/static", STATIC)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    web.run_app(app, host="0.0.0.0", port=PORT, access_log=None)


if __name__ == "__main__":
    main()
