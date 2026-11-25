"""TanchTV admin CLI. The built-in 'admin' account can only be disabled/re-enabled here.

Run inside the container:
  docker exec -it tanchtv-app python cli.py admin password            # prompt for a new password
  docker exec -it tanchtv-app python cli.py admin password --random   # generate and print one
  docker exec -it tanchtv-app python cli.py admin disable | enable
  docker exec -it tanchtv-app python cli.py users
  docker exec -it tanchtv-app python cli.py logout-all
"""

import argparse
import getpass
import os
import secrets
import sys
import time
from pathlib import Path

from db import DB, hash_password, db_path

db = DB(db_path(Path(os.environ.get("DATA_DIR", "/data"))))


def root():
    r = db.one("SELECT * FROM users WHERE is_root=1")
    if not r:
        sys.exit("The built-in admin doesn't exist yet: start the app once first.")
    return r


def main():
    p = argparse.ArgumentParser(prog="cli.py", description="TanchTV admin CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("admin", help="manage the built-in admin account")
    a.add_argument("action", choices=["password", "disable", "enable"])
    a.add_argument("--random", action="store_true", help="generate a random password and print it")
    sub.add_parser("users", help="list users")
    sub.add_parser("logout-all", help="sign everyone out")
    args = p.parse_args()

    if args.cmd == "admin":
        r = root()
        if args.action == "password":
            if args.random:
                pw = secrets.token_urlsafe(12)
            else:
                pw = getpass.getpass("New password for 'admin': ")
                if pw != getpass.getpass("Repeat: "):
                    sys.exit("Passwords don't match.")
            if len(pw) < 8:
                sys.exit("Use at least 8 characters.")
            db.run("UPDATE users SET password_hash=? WHERE id=?", hash_password(pw), r["id"])
            db.delete_user_sessions(r["id"])
            print(f"Password changed. New password: {pw}" if args.random else "Password changed.")
        else:
            off = args.action == "disable"
            db.run("UPDATE users SET disabled=? WHERE id=?", 1 if off else 0, r["id"])
            if off:
                db.delete_user_sessions(r["id"])
            print(f"Built-in admin {'disabled' if off else 'enabled'}.")
    elif args.cmd == "users":
        print(f"{'id':>3}  {'username':<20} {'role':<7} {'remote':<6} {'status':<9} {'login':<6} last login")
        for u in db.all("SELECT * FROM users ORDER BY id"):
            login = "+".join(x for x, y in (("pw", u["password_hash"]), ("google", u["google_sub"])) if y) or "-"
            last = time.strftime("%Y-%m-%d %H:%M", time.localtime(u["last_login"])) if u["last_login"] else "never"
            remote = "yes" if u["role"] == "admin" or u["can_control"] else "no"
            status = "disabled" if u["disabled"] else "active"
            name = u["username"] + (" *" if u["is_root"] else "")
            print(f"{u['id']:>3}  {name:<20} {u['role']:<7} {remote:<6} {status:<9} {login:<6} {last}")
        print("* = built-in admin")
    elif args.cmd == "logout-all":
        n = db.run("DELETE FROM sessions")
        print(f"Signed out {n} session(s).")


if __name__ == "__main__":
    main()
