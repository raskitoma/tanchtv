"""SQLite storage for TanchTV: users, sessions, invites, settings, ports."""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

ROOT_USERNAME = "admin"
SESSION_TTL = 30 * 86400
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL DEFAULT '',
  email         TEXT UNIQUE,
  password_hash TEXT,
  google_sub    TEXT UNIQUE,
  role          TEXT NOT NULL CHECK (role IN ('admin','viewer')),
  can_control   INTEGER NOT NULL DEFAULT 0,
  disabled      INTEGER NOT NULL DEFAULT 0,
  is_root       INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_login    INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  ip          TEXT,
  user_agent  TEXT
);
CREATE TABLE IF NOT EXISTS invites (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash  TEXT NOT NULL UNIQUE,
  role        TEXT NOT NULL CHECK (role IN ('admin','viewer')),
  can_control INTEGER NOT NULL DEFAULT 0,
  email       TEXT,
  note        TEXT NOT NULL DEFAULT '',
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
  used_at     INTEGER
);
CREATE TABLE IF NOT EXISTS stream_links (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash  TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL DEFAULT '',
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER,              -- NULL = never
  last_used   INTEGER,
  last_ip     TEXT
);
CREATE TABLE IF NOT EXISTS passkeys (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,   -- base64url
  public_key    TEXT NOT NULL,          -- base64url COSE key
  sign_count    INTEGER NOT NULL DEFAULT 0,
  transports    TEXT NOT NULL DEFAULT '[]',
  name          TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  last_used     INTEGER
);
CREATE TABLE IF NOT EXISTS ports (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL,
  usb          TEXT NOT NULL UNIQUE,      -- USB port path of the capture card, e.g. "3-2"
  kind         TEXT NOT NULL CHECK (kind IN ('androidtv','firetv','appletv')),
  host         TEXT NOT NULL DEFAULT '',  -- IP / hostname of the device, for the remote
  adb_enabled  INTEGER NOT NULL DEFAULT 0,
  creds        TEXT NOT NULL DEFAULT '{}',
  sort         INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    n, r, p = 2**14, 8, 1
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str | None) -> bool:
    if not stored:
        # constant-ish time even for users without a password
        hashlib.scrypt(pw.encode(), salt=b"0" * 16, n=2**14, r=8, p=1, dklen=32)
        return False
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:  # noqa: BLE001
        return False


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(stream_links)")}
            if "port_id" not in cols:   # VLC links belong to a port (older links: first port)
                self.conn.execute("ALTER TABLE stream_links ADD COLUMN port_id INTEGER")

    # ---- low level ----
    def all(self, sql, *a) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, a).fetchall()]

    def one(self, sql, *a) -> dict | None:
        with self.lock:
            r = self.conn.execute(sql, a).fetchone()
            return dict(r) if r else None

    def run(self, sql, *a) -> int:
        with self.lock:
            cur = self.conn.execute(sql, a)
            return cur.lastrowid if sql.lstrip().upper().startswith("INSERT") else cur.rowcount

    # ---- settings ----
    def get(self, key: str, default: str = "") -> str:
        r = self.one("SELECT value FROM settings WHERE key=?", key)
        return r["value"] if r else default

    def set(self, key: str, value: str) -> None:
        self.run("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)

    # ---- ports ----
    def ports(self) -> list[dict]:
        return self.all("SELECT * FROM ports ORDER BY sort, id")

    def port(self, pid) -> dict | None:
        return self.one("SELECT * FROM ports WHERE id=?", pid)

    # ---- users ----
    def ensure_root(self, bootstrap_password: str) -> str | None:
        """Create the built-in admin if missing. Returns a generated password if one was made."""
        if self.one("SELECT id FROM users WHERE is_root=1"):
            return None
        generated = None
        pw = bootstrap_password
        if not pw:
            pw = generated = secrets.token_urlsafe(12)
        self.run(
            "INSERT INTO users(username,display_name,password_hash,role,can_control,is_root,created_at) VALUES(?,?,?,?,?,?,?)",
            ROOT_USERNAME, "Administrator", hash_password(pw), "admin", 1, 1, int(time.time()),
        )
        return generated

    def user(self, uid: int) -> dict | None:
        return self.one("SELECT * FROM users WHERE id=?", uid)

    def user_by_name(self, username: str) -> dict | None:
        return self.one("SELECT * FROM users WHERE username=?", username.strip().lower())

    def unique_username(self, base: str) -> str:
        base = re.sub(r"[^a-z0-9._-]", "", base.lower())[:24] or "user"
        if len(base) < 3:
            base = (base + "user")[:8]
        name, i = base, 1
        while self.user_by_name(name):
            i += 1
            name = f"{base}{i}"
        return name

    def create_user(self, username, display_name, role, can_control, email=None, password=None, google_sub=None) -> int:
        return self.run(
            "INSERT INTO users(username,display_name,email,password_hash,google_sub,role,can_control,created_at) VALUES(?,?,?,?,?,?,?,?)",
            username, display_name, email, hash_password(password) if password else None, google_sub,
            role, 1 if can_control else 0, int(time.time()),
        )

    # ---- sessions ----
    def create_session(self, uid: int, ip: str, ua: str) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        self.run(
            "INSERT INTO sessions(token_hash,user_id,created_at,expires_at,ip,user_agent) VALUES(?,?,?,?,?,?)",
            sha256(token), uid, now, now + SESSION_TTL, ip, ua[:200],
        )
        self.run("UPDATE users SET last_login=? WHERE id=?", now, uid)
        self.run("DELETE FROM sessions WHERE expires_at<?", now)
        return token

    def session_user(self, token: str) -> dict | None:
        if not token:
            return None
        now = int(time.time())
        row = self.one(
            "SELECT u.*, s.expires_at AS s_exp FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?",
            sha256(token), now,
        )
        if not row or row["disabled"]:
            return None
        if row["s_exp"] - now < SESSION_TTL - 86400:  # slide at most once a day
            self.run("UPDATE sessions SET expires_at=? WHERE token_hash=?", now + SESSION_TTL, sha256(token))
        return row

    def delete_session(self, token: str) -> None:
        self.run("DELETE FROM sessions WHERE token_hash=?", sha256(token))

    def delete_user_sessions(self, uid: int) -> None:
        self.run("DELETE FROM sessions WHERE user_id=?", uid)

    # ---- invites ----
    def create_invite(self, role, can_control, email, note, days, created_by) -> str:
        token = secrets.token_urlsafe(24)
        now = int(time.time())
        self.run(
            "INSERT INTO invites(token_hash,role,can_control,email,note,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
            sha256(token), role, 1 if can_control else 0, email or None, note, created_by, now, now + days * 86400,
        )
        return token

    def valid_invite(self, token: str) -> dict | None:
        if not token:
            return None
        return self.one(
            "SELECT * FROM invites WHERE token_hash=? AND used_at IS NULL AND expires_at>?", sha256(token), int(time.time())
        )

    def use_invite(self, invite_id: int, uid: int) -> None:
        self.run("UPDATE invites SET used_by=?, used_at=? WHERE id=?", uid, int(time.time()), invite_id)


def db_path(data_dir) -> "Path":
    """tanchtv.db in the data dir (installs from before the rename keep their tvremoter.db)."""
    from pathlib import Path
    d = Path(data_dir)
    legacy = d / "tvremoter.db"
    return legacy if legacy.exists() and not (d / "tanchtv.db").exists() else d / "tanchtv.db"
